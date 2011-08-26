/*
 * Software iWARP device driver for Linux
 *
 * Authors: Bernard Metzler <bmt@zurich.ibm.com>
 *          Fredy Neeser <nfd@zurich.ibm.com>
 *
 * Copyright (c) 2008-2011, IBM Corporation
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *   Redistribution and use in source and binary forms, with or
 *   without modification, are permitted provided that the following
 *   conditions are met:
 *
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   - Neither the name of IBM nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/net.h>
#include <linux/scatterlist.h>
#include <linux/highmem.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <net/tcp.h>

#include <rdma/iw_cm.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_umem.h>

#include "siw.h"
#include "siw_obj.h"
#include "siw_cm.h"


/*
 * ----------------------------
 * DDP reassembly for Softiwarp
 * ----------------------------
 * For the ordering of transmitted DDP segments, the relevant iWARP ordering
 * rules are as follows:
 *
 * - RDMAP (RFC 5040): Section 7.5, Rule 17:
 *   "RDMA Read Response Message processing at the Remote Peer (reading
 *    the specified Tagged Buffer) MUST be started only after the RDMA
 *    Read Request Message has been Delivered by the DDP layer (thus,
 *    all previous RDMA Messages have been properly submitted for
 *    ordered Placement)."
 *
 * - DDP (RFC 5041): Section 5.3:
 *   "At the Data Source, DDP:
 *    o MUST transmit DDP Messages in the order they were submitted to
 *      the DDP layer,
 *    o SHOULD transmit DDP Segments within a DDP Message in increasing
 *      MO order for Untagged DDP Messages, and in increasing TO order
 *      for Tagged DDP Messages."
 *
 * Combining these rules implies that, although RDMAP does not provide
 * ordering between operations that are generated from the two ends of an
 * RDMAP stream, DDP *must not* transmit an RDMA Read Response Message before
 * it has finished transmitting SQ operations that were already submitted
 * to the DDP layer. It follows that an iWARP transmitter must fully
 * serialize RDMAP messages belonging to the same QP.
 *
 * Given that a TCP socket receives DDP segments in peer transmit order,
 * we obtain the following ordering of received DDP segments:
 *
 * (i)  the received DDP segments of RDMAP messages for the same QP
 *      cannot be interleaved
 * (ii) the received DDP segments of a single RDMAP message *should*
 *      arrive in order.
 *
 * The Softiwarp transmitter obeys rule #2 in DDP Section 5.3.
 * With this property, the "should" becomes a "must" in (ii) above,
 * which simplifies DDP reassembly considerably.
 * The Softiwarp receiver currently relies on this property
 * and reports an error if DDP segments of the same RDMAP message
 * do not arrive in sequence.
 */

static inline int siw_crc_rxhdr(struct siw_iwarp_rx *ctx)
{
	crypto_hash_init(&ctx->mpa_crc_hd);

	return siw_crc_array(&ctx->mpa_crc_hd, (u8 *)&ctx->hdr,
			     ctx->fpdu_part_rcvd);
}


/*
 * siw_rx_umem_init()
 *
 * Given memory region @mr and tagged offset @t_off within @mr,
 * resolve corresponding ib_umem_chunk memory chunk pointer
 * and update receive context variables to point at receive position.
 * returns 0 on sucess and failure otherwise.
 *
 * NOTE: This function expects virtual addresses.
 * TODO: Function needs generalization to support relative adressing
 *       aka "ZBVA".
 *
 * @rctx:	Receive Context to be updated
 * @mr:		Memory Region
 * @t_off:	Offset within Memory Region
 *
 */
static int siw_rx_umem_init(struct siw_iwarp_rx *rctx, struct siw_mr *mr,
			    u64 t_off)
{
	struct ib_umem_chunk	*chunk;
	u64			off_mr;   /* offset into MR */
	int			psge_idx; /* Index of PSGE */

	off_mr = t_off - (mr->mem.va & PAGE_MASK);
	/*
	 * Equivalent to
	 * off_mr = t_off - mr->mem.va;
	 * off_mr += mr->umem->offset;
	 */

	/* Skip pages not referenced by t_off */
	psge_idx = off_mr >> PAGE_SHIFT;

	list_for_each_entry(chunk, &mr->umem->chunk_list, list) {
		if (psge_idx < chunk->nents)
			break;
		psge_idx -= chunk->nents;
	}
	if (psge_idx >= chunk->nents) {
		dprint(DBG_MM|DBG_ON, "(QP%d): Short chunk list\n",
			RX_QPID(rctx));
		return -EINVAL;
	}
	rctx->pg_idx = psge_idx;
	rctx->pg_off = off_mr & ~PAGE_MASK;
	rctx->umem_chunk = chunk;

	dprint(DBG_MM, "(QP%d): New chunk, idx %d\n", RX_QPID(rctx), psge_idx);
	return 0;
}


/*
 * siw_rx_umem()
 *
 * Receive data of @len into target referenced by @rctx.
 * This function does not check if umem is within bounds requested by
 * @len and @t_off. @umem_ends indicates if routine should
 * not update chunk position pointers after the point it is
 * currently receiving
 *
 * @rctx:	Receive Context
 * @len:	Number of bytes to place
 * @umen_ends:	1, if rctx chunk pointer should not be updated after len.
 */
static int siw_rx_umem(struct siw_iwarp_rx *rctx, int len, int umem_ends)
{
	struct scatterlist	*p_list;
	void			*dest;
	struct ib_umem_chunk    *chunk = rctx->umem_chunk;
	int			pg_off = rctx->pg_off,
				copied = 0,
				bytes,
				rv;

	while (len) {
		bytes  = min(len, (int)PAGE_SIZE - pg_off);
		p_list = &chunk->page_list[rctx->pg_idx];

		dest = kmap_atomic(sg_page(p_list), KM_SOFTIRQ0);

		rv = skb_copy_bits(rctx->skb, rctx->skb_offset, dest + pg_off,
				   bytes);

		dprint(DBG_RX, "(QP%d): Page #%d, "
			"bytes=%u, rv=%d returned by skb_copy_bits()\n",
			RX_QPID(rctx), rctx->pg_idx, bytes, rv);

		if (likely(!rv)) {
			if (rctx->crc_enabled)
				rv = siw_crc_sg(&rctx->mpa_crc_hd, p_list,
						pg_off, bytes);

			rctx->skb_offset += bytes;
			copied += bytes;
			len -= bytes;
			pg_off += bytes;
		}

		kunmap_atomic(dest, KM_SOFTIRQ0);

		if (unlikely(rv)) {
			rctx->skb_copied += copied;
			rctx->skb_new -= copied;
			copied = -EFAULT;

			dprint(DBG_RX|DBG_ON, "(QP%d): failed with %d\n",
				RX_QPID(rctx), rv);

			goto out;
		}
		if (pg_off == PAGE_SIZE) {
			/*
			 * end of page
			 */
			pg_off = 0;
			/*
			 * reference next page chunk if
			 * - all pages in chunk used AND
			 * - current loop fills more into this umem
			 *   OR the next receive will go into this umem
			 *   starting at the position where we are leaving
			 *   the routine.
			 */
			if (++rctx->pg_idx == chunk->nents &&
				(len > 0 || !umem_ends)) {

				rctx->pg_idx = 0;
				chunk = mem_chunk_next(chunk);
			}
		}
	}
	/*
	 * store chunk position for resume
	 */
	rctx->umem_chunk = chunk;
	rctx->pg_off = pg_off;

	rctx->skb_copied += copied;
	rctx->skb_new -= copied;
out:
	return copied;
}

static inline int siw_rx_kva(struct siw_iwarp_rx *rctx, int len, void *kva)
{
	int rv = skb_copy_bits(rctx->skb, rctx->skb_offset, kva, len);

	if (likely(!rv)) {
		rctx->skb_offset += len;
		rctx->skb_copied += len;
		rctx->skb_new -= len;
		if (rctx->crc_enabled) {
			rv = siw_crc_array(&rctx->mpa_crc_hd, kva, len);
			if (rv)
				goto done;
		}
		rv = len;
	}
done:
	return rv;
}

/*
 * siw_rresp_check_ntoh()
 *
 * Check incoming RRESP fragment header against expected
 * header values and update expected values for potential next
 * fragment.
 *
 * NOTE: This function must be called only if a RRESP DDP segment
 *       starts but not for fragmented consecutive pieces of an
 *       already started DDP segement.
 */
static inline int siw_rresp_check_ntoh(struct siw_iwarp_rx *rctx)
{
	struct iwarp_rdma_rresp	*rresp = &rctx->hdr.rresp;
	struct siw_wqe		*wqe = rctx->dest.wqe;

	u32 sink_stag = be32_to_cpu(rresp->sink_stag);
	u64 sink_to   = be64_to_cpu(rresp->sink_to);

	if (rctx->first_ddp_seg) {
		rctx->ddp_stag = wqe->wr.rread.sge[0].lkey;
		rctx->ddp_to   = wqe->wr.rread.sge[0].addr;
	}
	if (rctx->ddp_stag != sink_stag) {
		dprint(DBG_RX|DBG_ON,
			" received STAG=%08x, expected STAG=%08x\n",
			sink_stag, rctx->ddp_stag);
		/*
		 * Verbs: RI_EVENT_QP_LLP_INTEGRITY_ERROR_BAD_FPDU
		 */
		return -EINVAL;
	}
	if (rctx->ddp_to != sink_to) {
		dprint(DBG_RX|DBG_ON,
			" received TO=%016llx, expected TO=%016llx\n",
			(unsigned long long)sink_to,
			(unsigned long long)rctx->ddp_to);
		/*
		 * Verbs: RI_EVENT_QP_LLP_INTEGRITY_ERROR_BAD_FPDU
		 */
		return -EINVAL;
	}
	if (!rctx->more_ddp_segs && (wqe->processed + rctx->fpdu_part_rem
				     != wqe->bytes)) {
		dprint(DBG_RX|DBG_ON,
			" RRESP length does not match RREQ, "
			"peer sent=%d, expected %d\n",
			wqe->processed + rctx->fpdu_part_rem, wqe->bytes);
		return -EINVAL;
	}
	return 0;
}

/*
 * siw_write_check_ntoh()
 *
 * Check incoming WRITE fragment header against expected
 * header values and update expected values for potential next
 * fragment
 *
 * NOTE: This function must be called only if a WRITE DDP segment
 *       starts but not for fragmented consecutive pieces of an
 *       already started DDP segement.
 */
static inline int siw_write_check_ntoh(struct siw_iwarp_rx *rctx)
{
	struct iwarp_rdma_write	*write = &rctx->hdr.rwrite;

	u32 sink_stag = be32_to_cpu(write->sink_stag);
	u64 sink_to   = be64_to_cpu(write->sink_to);

	if (rctx->first_ddp_seg) {
		rctx->ddp_stag = sink_stag;
		rctx->ddp_to   = sink_to;
	} else {
		if (rctx->ddp_stag != sink_stag) {
			dprint(DBG_RX|DBG_ON,
				" received STAG=%08x, expected STAG=%08x\n",
				sink_stag, rctx->ddp_stag);
			/*
			 * Verbs: RI_EVENT_QP_LLP_INTEGRITY_ERROR_BAD_FPDU
			 */
			return -EINVAL;
		}
		if (rctx->ddp_to != sink_to) {
			dprint(DBG_RX|DBG_ON,
				" received TO=%016llx, expected TO=%016llx\n",
				(unsigned long long)sink_to,
				(unsigned long long)rctx->ddp_to);
			/*
			 * Verbs: RI_EVENT_QP_LLP_INTEGRITY_ERROR_BAD_FPDU
			 */
			return -EINVAL;
		}
	}
	return 0;
}

/*
 * siw_send_check_ntoh()
 *
 * Check incoming SEND fragment header against expected
 * header values and update expected MSN if no next
 * fragment expected
 *
 * NOTE: This function must be called only if a SEND DDP segment
 *       starts but not for fragmented consecutive pieces of an
 *       already started DDP segement.
 */
static inline int siw_send_check_ntoh(struct siw_iwarp_rx *rctx)
{
	struct iwarp_send	*send = &rctx->hdr.send;
	struct siw_wqe		*wqe = rctx->dest.wqe;

	u32 ddp_msn = be32_to_cpu(send->ddp_msn);
	u32 ddp_mo  = be32_to_cpu(send->ddp_mo);
	u32 ddp_qn  = be32_to_cpu(send->ddp_qn);

	if (ddp_qn != RDMAP_UNTAGGED_QN_SEND) {
		dprint(DBG_RX|DBG_ON, " Invalid DDP QN %d for SEND\n",
			ddp_qn);
		return -EINVAL;
	}
	if (ddp_msn != rctx->ddp_msn[RDMAP_UNTAGGED_QN_SEND]) {
		dprint(DBG_RX|DBG_ON, " received MSN=%d, expected MSN=%d\n",
			rctx->ddp_msn[RDMAP_UNTAGGED_QN_SEND], ddp_msn);
		/*
		 * TODO: Error handling
		 * async_event= RI_EVENT_QP_RQ_PROTECTION_ERROR_MSN_GAP;
		 * cmpl_status= RI_WC_STATUS_LOCAL_QP_CATASTROPHIC;
		 */
		return -EINVAL;
	}
	if (ddp_mo != wqe->processed) {
		dprint(DBG_RX|DBG_ON, " Received MO=%u, expected MO=%u\n",
			ddp_mo, wqe->processed);
		/*
		 * Verbs: RI_EVENT_QP_LLP_INTEGRITY_ERROR_BAD_FPDU
		 */
		return -EINVAL;
	}
	if (rctx->first_ddp_seg) {
		/* initialize user memory write position */
		rctx->sge_idx = 0;
		rctx->sge_off = 0;
	}
	if (wqe->bytes < wqe->processed + rctx->fpdu_part_rem) {
		dprint(DBG_RX|DBG_ON, " Receive space short: %d < %d\n",
			wqe->bytes - wqe->processed, rctx->fpdu_part_rem);
		wqe->wc_status = IB_WC_LOC_LEN_ERR;
		return -EINVAL;
	}
	return 0;
}


/*
 * siw_srq_fetch_wqe()
 *
 * Get one RQ wqe from SRQ and inform user
 * if SRQ lower watermark reached
 */
static inline struct siw_wqe *siw_srq_fetch_wqe(struct siw_srq *srq)
{
	struct siw_wqe *wqe = NULL;
	int qlen;

	lock_srq(srq);
	if (!list_empty(&srq->rq)) {
		wqe = list_first_wqe(&srq->rq);
		list_del_init(&wqe->list);
		/*
		 * The SRQ wqe is counted for SRQ space until completed.
		 */
		qlen = srq->max_wr - (atomic_read(&srq->space) + 1);
		if (srq->armed && qlen < srq->limit) {
			srq->armed = 0;
			dprint(DBG_RX, " SRQ(%p): SRQ limit event\n", srq);
			siw_srq_event(srq, IB_EVENT_SRQ_LIMIT_REACHED);
		}
	}
	unlock_srq(srq);

	return wqe;
}

static inline struct siw_wqe *siw_get_rqe(struct siw_qp *qp)
{
	struct siw_wqe	*wqe = NULL;

	if (!qp->srq) {
		lock_rq(qp);
		if (!list_empty(&qp->rq)) {
			wqe = list_first_wqe(&qp->rq);
			list_del_init(&wqe->list);
			unlock_rq(qp);
		} else {
			unlock_rq(qp);
			dprint(DBG_RX, " QP(%d): RQ empty!\n", QP_ID(qp));
		}
	} else {
		wqe = siw_srq_fetch_wqe(qp->srq);
		if (wqe) {
			siw_qp_get(qp);
			wqe->qp = qp;
		} else
			dprint(DBG_RX, " QP(%d): SRQ empty!\n", QP_ID(qp));
	}
	return wqe;
}


/*
 * siw_proc_send:
 *
 * Process one incoming SEND and place data into memory referenced by
 * receive wqe.
 *
 * Function supports partially received sends (suspending/resuming
 * current receive wqe processing)
 *
 * return value:
 *	0:       reached the end of a DDP segment
 *	-EAGAIN: to be called again to finish the DDP segment
 */
int siw_proc_send(struct siw_qp *qp, struct siw_iwarp_rx *rctx)
{
	struct siw_wqe	*wqe;
	struct siw_sge	*sge;
	struct siw_mr	*mr;
	u32		data_bytes,	/* all data bytes available */
			rcvd_bytes;	/* sum of data bytes rcvd */
	int		rv = 0;

	if (rctx->first_ddp_seg) {
		WARN_ON(rx_wqe(qp) != NULL);

		wqe = siw_get_rqe(qp);
		if (!wqe)
			return -ENOENT;

		rx_wqe(qp) = wqe;
		wqe->wr_status = SR_WR_INPROGRESS;
	} else  {
		wqe = rx_wqe(qp);
		if (!wqe) {
			/*
			 * this is a siw bug!
			 */
			dprint(DBG_ON, "QP(%d): RQ failure\n", QP_ID(qp));
			return -EPROTO;
		}
	}
	if (rctx->state == SIW_GET_DATA_START) {
		rv = siw_send_check_ntoh(rctx);
		if (rv) {
			siw_qp_event(qp, IB_EVENT_QP_FATAL);
			return rv;
		}
		if (!rctx->fpdu_part_rem) /* zero length SEND */
			return 0;
	}
	data_bytes = min(rctx->fpdu_part_rem, rctx->skb_new);
	rcvd_bytes = 0;

	while (data_bytes) {
		struct siw_pd	*pd;
		u32	sge_bytes;	/* data bytes avail for SGE */

		sge = &wqe->wr.sgl.sge[rctx->sge_idx];

		if (!sge->len) {
			/* just skip empty sge's */
			rctx->sge_idx++;
			rctx->sge_off = 0;
			continue;
		}
		sge_bytes = min(data_bytes, sge->len - rctx->sge_off);

		/*
		 * check with QP's PD if no SRQ present, SRQ's PD otherwise
		 */
		pd = qp->srq == NULL ? qp->pd : qp->srq->pd;

		rv = siw_check_sge(pd, sge, SR_MEM_LWRITE, rctx->sge_off,
				   sge_bytes);
		if (rv) {
			siw_qp_event(qp, IB_EVENT_QP_ACCESS_ERR);
			break;
		}
		mr = siw_mem2mr(sge->mem.obj);

		if (mr->umem) {
			/*
			 * Are we going to finish placing
			 * - the last fragment of the current SGE or
			 * - the last DDP segment (L=1) of the current
			 *   RDMAP message?
			 *
			 * siw_rx_umem() must advance umem page_chunk position
			 * after sucessful receive only, if receive into
			 * current umem does not end.
			 * umem ends, if:
			 *   - current SGE gets completely filled, OR
			 *   - current MPA FPDU is last AND gets consumed now
			 */
			int umem_ends =
				((sge_bytes + rctx->sge_off == sge->len) ||
				  (!rctx->more_ddp_segs &&
				   rctx->fpdu_part_rcvd + sge_bytes ==
				   rctx->fpdu_part_rem)) ? 1 : 0;

			if (rctx->sge_off == 0) {
				/*
				 * started a new sge: update receive pointers
				 */
				rv = siw_rx_umem_init(rctx, mr, sge->addr);
				if (rv)
					break;
			}
			rv = siw_rx_umem(rctx, sge_bytes, umem_ends);
		} else
			rv = siw_rx_kva(rctx, sge_bytes,
					(void *)(sge->addr + rctx->sge_off));
		if (rv != sge_bytes) {
			wqe->processed += rcvd_bytes;
			return -EINVAL;
		}
		rctx->sge_off += rv;

		if (rctx->sge_off == sge->len) {
			rctx->sge_idx++;
			rctx->sge_off = 0;
		}
		data_bytes -= rv;
		rcvd_bytes += rv;

		rctx->fpdu_part_rem -= rv;
		rctx->fpdu_part_rcvd += rv;
	}
	wqe->processed += rcvd_bytes;

	if (!rctx->fpdu_part_rem)
		return 0;

	return (rv < 0) ? rv : -EAGAIN;
}

/*
 * siw_proc_write:
 *
 * Place incoming WRITE after referencing and checking target buffer

 * Function supports partially received WRITEs (suspending/resuming
 * current receive processing)
 *
 * return value:
 *	0:       reached the end of a DDP segment
 *	-EAGAIN: to be called again to finish the DDP segment
 */

int siw_proc_write(struct siw_qp *qp, struct siw_iwarp_rx *rctx)
{
	struct siw_dev		*dev = qp->hdr.sdev;
	struct siw_mem		*mem;
	struct siw_mr		*mr;
	int			bytes,
				rv;

	if (rctx->state == SIW_GET_DATA_START) {

		if (!rctx->fpdu_part_rem) /* zero length WRITE */
			return 0;

		rv = siw_write_check_ntoh(rctx);
		if (rv) {
			siw_qp_event(qp, IB_EVENT_QP_FATAL);
			return rv;
		}
	}
	bytes = min(rctx->fpdu_part_rem, rctx->skb_new);

	/*
	 * NOTE: bytes > 0 is always true, since this routine
	 * gets only called if so.
	 */
	if (rctx->first_ddp_seg) {
		/* DEBUG Code, to be removed */
		if (rx_mem(qp) != NULL) {
			dprint(DBG_RX|DBG_ON, "(QP%d): Stale rctx state!\n",
				QP_ID(qp));
			return -EFAULT;
		}
		rx_mem(qp) = siw_mem_id2obj(dev, rctx->ddp_stag >> 8);
	}
	if (rx_mem(qp) == NULL) {
		dprint(DBG_RX|DBG_ON, "(QP%d): "
			"Sink STag not found or invalid,  STag=0x%08x\n",
			QP_ID(qp), rctx->ddp_stag);
		return -EINVAL;
	}
	mem = rx_mem(qp);
	/*
	 * Rtag not checked against mem's tag again because
	 * hdr check guarantees same tag as before if fragmented
	 */
	rv = siw_check_mem(qp->pd, mem, rctx->ddp_to + rctx->fpdu_part_rcvd,
			   SR_MEM_RWRITE, bytes);
	if (rv) {
		siw_qp_event(qp, IB_EVENT_QP_ACCESS_ERR);
		return rv;
	}
	mr = siw_mem2mr(mem);

	if (mr->umem) {
		/*
		 * Are we going to place the last piece of the last
		 * DDP segment of the current RDMAP message?
		 *
		 * It is last if:
		 * - rctx->fpdu_part_rem <= rctx->skb_new AND
		 * - payload_rem (of current DDP segment) <= rctx->skb_new
		 */
		int last_write = ((rctx->fpdu_part_rem <= rctx->skb_new) &&
				   !rctx->more_ddp_segs) ? 1 : 0;

		if (rctx->first_ddp_seg) {
			rv = siw_rx_umem_init(rctx, mr, rctx->ddp_to);
			if (rv)
				return -EINVAL;

		}
		rv = siw_rx_umem(rctx, bytes, last_write);
	} else
		rv = siw_rx_kva(rctx, bytes,
			       (void *)(rctx->ddp_to +
					rctx->fpdu_part_rcvd));

	if (rv != bytes)
		return -EINVAL;

	rctx->fpdu_part_rem -= rv;
	rctx->fpdu_part_rcvd += rv;

	if (!rctx->fpdu_part_rem) {
		rctx->ddp_to += rctx->fpdu_part_rcvd;
		return 0;
	}

	return (rv < 0) ? rv : -EAGAIN;
}

/*
 * inbound RREQ's cannot carry user data.
 */
int siw_proc_rreq(struct siw_qp *qp, struct siw_iwarp_rx *rctx)
{
	if (!rctx->fpdu_part_rem)
		return 0;

	dprint(DBG_ON|DBG_RX, "(QP%d): RREQ with MPA len %d\n", QP_ID(qp),
		be16_to_cpu(rctx->hdr.ctrl.mpa_len));

	return -EPROTO;
}

static inline struct siw_wqe *siw_get_irqe(struct siw_qp *qp)
{
	struct siw_wqe *wqe = NULL;

	if (atomic_dec_return(&qp->irq_space) >= 0) {
		wqe = siw_freeq_wqe_get(qp);
		if (wqe) {
			INIT_LIST_HEAD(&wqe->list);
			wqe->processed = 0;
			siw_qp_get(qp);
			wqe->qp = qp;
			wr_type(wqe) = SIW_WR_RDMA_READ_RESP;
		} else
			atomic_inc(&qp->irq_space);
	} else
		atomic_inc(&qp->irq_space);

	return wqe;
}

/*
 * siw_init_rresp:
 *
 * Process inbound RDMA READ REQ. Produce a pseudo READ RESPONSE WQE.
 * Put it at the tail of the IRQ, if there is another WQE currently in
 * transmit processing. If not, make it the current WQE to be processed
 * and schedule transmit processing.
 *
 * Can be called from softirq context and from process
 * context (RREAD socket loopback case!)
 *
 * return value:
 *	0:      success,
 *		failure code otherwise
 */

int siw_init_rresp(struct siw_qp *qp, struct siw_iwarp_rx *rctx)
{
	struct siw_wqe *rsp;

	rsp = siw_get_irqe(qp);
	if (rsp) {
		rsp->wr.rresp.sge.len = be32_to_cpu(rctx->hdr.rreq.read_size);
		rsp->bytes = rsp->wr.rresp.sge.len;	/* redundant */

		rsp->wr.rresp.sge.addr = be64_to_cpu(rctx->hdr.rreq.source_to);
		rsp->wr.rresp.num_sge = rsp->bytes ? 1 : 0;

		rsp->wr.rresp.sge.mem.obj = NULL;	/* defer lookup */
		rsp->wr.rresp.sge.lkey =
			be32_to_cpu(rctx->hdr.rreq.source_stag);

		rsp->wr.rresp.raddr = be64_to_cpu(rctx->hdr.rreq.sink_to);
		rsp->wr.rresp.rtag = be32_to_cpu(rctx->hdr.rreq.sink_stag);

	} else {
		dprint(DBG_RX|DBG_ON, "(QP%d): IRD exceeded!\n", QP_ID(qp));
		return -EPROTO;
	}
	rsp->wr_status = SR_WR_QUEUED;

	/*
	 * Insert into IRQ
	 *
	 * TODO: Revisit ordering of genuine SQ WRs and Read Response
	 * pseudo-WRs. RDMAP specifies that there is no ordering among
	 * the two directions of transmission, so there is a degree of
	 * freedom.
	 *
	 * The current logic favours Read Responses over SQ work requests
	 * that are queued but not already in progress.
	 */
	lock_sq(qp);
	if (!tx_wqe(qp)) {
		tx_wqe(qp) = rsp;
		unlock_sq(qp);
		/*
		 * schedule TX work, even if SQ was supended due to
		 * ORD limit: it is always OK (and may even prevent peers
		 * from appl lock) to send RRESPONSE's
		 */
		siw_sq_queue_work(qp);
	} else {
		list_add_tail(&rsp->list, &qp->irq);
		unlock_sq(qp);
	}
	return 0;
}

/*
 * siw_proc_rresp:
 *
 * Place incoming RRESP data into memory referenced by RREQ WQE.
 *
 * Function supports partially received RRESP's (suspending/resuming
 * current receive processing)
 */
int siw_proc_rresp(struct siw_qp *qp, struct siw_iwarp_rx *rctx)
{
	struct siw_wqe	*wqe;
	struct siw_mr	*mr;
	struct siw_sge	*sge;
	int		bytes,
			rv;

	if (rctx->first_ddp_seg) {
		WARN_ON(rx_wqe(qp) != NULL);
		/*
		 * fetch pending RREQ from orq
		 */
		lock_orq(qp);
		if (!list_empty(&qp->orq)) {
			wqe = list_first_entry(&qp->orq, struct siw_wqe, list);
			list_del_init(&wqe->list);
		} else {
			unlock_orq(qp);
			dprint(DBG_RX|DBG_ON, "(QP%d): ORQ empty\n",
				QP_ID(qp));
			/*
			 * TODO: Should generate an async error
			 */
			rv = -ENODATA; /* or -ENOENT ? */
			goto done;
		}
		unlock_orq(qp);

		rx_wqe(qp) = wqe;

		if (wr_type(wqe) != SIW_WR_RDMA_READ_REQ || wqe->processed) {
			WARN_ON(wqe->processed);
			WARN_ON(wr_type(wqe) != SIW_WR_RDMA_READ_REQ);
			rv = -EINVAL;
			goto done;
		}

		wqe->wr_status = SR_WR_INPROGRESS;

		rv = siw_rresp_check_ntoh(rctx);
		if (rv) {
			siw_qp_event(qp, IB_EVENT_QP_FATAL);
			goto done;
		}
	} else {
		wqe = rx_wqe(qp);
		if (!wqe) {
			WARN_ON(1);
			rv = -ENODATA;
			goto done;
		}
	}
	if (!rctx->fpdu_part_rem) /* zero length RRESPONSE */
		return 0;

	bytes = min(rctx->fpdu_part_rem, rctx->skb_new);
	sge = wqe->wr.rread.sge; /* there is only one */

	/*
	 * check target memory which resolves memory on first fragment
	 */
	rv = siw_check_sge(qp->pd, sge, SR_MEM_LWRITE, wqe->processed, bytes);
	if (rv) {
		dprint(DBG_RX|DBG_ON, "(QP%d): siw_check_sge failed: %d\n",
			QP_ID(qp), rv);
		wqe->wc_status = IB_WC_LOC_PROT_ERR;
		siw_qp_event(qp, IB_EVENT_QP_ACCESS_ERR);
		goto done;
	}
	mr = siw_mem2mr(sge->mem.obj);

	if (mr->umem) {
		/*
		 * Are we going to finish placing the last DDP segment (L=1)
		 * of the current RDMAP message?
		 *
		 * NOTE: siw_rresp_check_ntoh() guarantees that the
		 * last inbound RDMAP Read Response message exactly matches
		 * with the RREQ WR.
		 */
		int is_last = (bytes + wqe->processed == wqe->bytes) ? 1 : 0;

		if (rctx->first_ddp_seg) {
			rv = siw_rx_umem_init(rctx, mr, sge->addr);
			if (rv) {
				wqe->wc_status = IB_WC_LOC_PROT_ERR;
				goto done;
			}
		}
		rv = siw_rx_umem(rctx,  bytes, is_last);
	} else
		rv = siw_rx_kva(rctx,  bytes,
				(void *)(sge->addr + wqe->processed));
	if (rv != bytes) {
		wqe->wc_status = IB_WC_GENERAL_ERR;
		rv = -EINVAL;
		goto done;
	}
	rctx->fpdu_part_rem -= rv;
	rctx->fpdu_part_rcvd += rv;

	wqe->processed += rv;

	if (!rctx->fpdu_part_rem) {
		rctx->ddp_to += rctx->fpdu_part_rcvd;
		return 0;
	}
done:
	return (rv < 0) ? rv : -EAGAIN;
}

static void siw_drain_pkt(struct siw_qp *qp, struct siw_iwarp_rx *rctx)
{
	char	buf[128];
	int	len;

	dprint(DBG_ON|DBG_RX, " (QP%d): drain %d bytes\n",
		QP_ID(qp), rctx->fpdu_part_rem);

	while (rctx->fpdu_part_rem) {
		len = min(rctx->fpdu_part_rem, 128);

		skb_copy_bits(rctx->skb, rctx->skb_offset,
				      buf, rctx->fpdu_part_rem);

		rctx->skb_copied += len;
		rctx->skb_offset += len;
		rctx->skb_new -= len;
		rctx->fpdu_part_rem -= len;
		rctx->fpdu_part_rcvd += len;
	}
}

int siw_proc_unsupp(struct siw_qp *qp, struct siw_iwarp_rx *rctx)
{
	WARN_ON(1);
	siw_drain_pkt(qp, rctx);
	return 0;
}


int siw_proc_terminate(struct siw_qp *qp, struct siw_iwarp_rx *rctx)
{
	dprint(DBG_ON, " (QP%d): RX Terminate: type=%d, layer=%d, code=%d\n",
		QP_ID(qp),
		__rdmap_term_etype(&rctx->hdr.terminate),
		__rdmap_term_layer(&rctx->hdr.terminate),
		__rdmap_term_ecode(&rctx->hdr.terminate));

	siw_drain_pkt(qp, rctx);
	return 0;
}


static int siw_get_trailer(struct siw_qp *qp, struct siw_iwarp_rx *rctx)
{
	struct sk_buff	*skb = rctx->skb;
	u8		*tbuf = (u8 *)&rctx->trailer.crc - rctx->pad;
	int		avail;

	avail = min(rctx->skb_new, rctx->fpdu_part_rem);

	skb_copy_bits(skb, rctx->skb_offset,
		      tbuf + rctx->fpdu_part_rcvd, avail);

	rctx->fpdu_part_rcvd += avail;
	rctx->fpdu_part_rem -= avail;

	rctx->skb_new -= avail;
	rctx->skb_offset += avail;
	rctx->skb_copied += avail;

	dprint(DBG_RX, " (QP%d): %d remaining (%d)\n", QP_ID(qp),
		rctx->fpdu_part_rem, avail);

	if (!rctx->fpdu_part_rem) {
		__be32	crc_in, crc_own = 0;
		/*
		 * check crc if required
		 */
		if (!rctx->crc_enabled)
			return 0;

		if (rctx->pad && siw_crc_array(&rctx->mpa_crc_hd,
					       tbuf, rctx->pad) != 0)
			return -EINVAL;

		crypto_hash_final(&rctx->mpa_crc_hd, (u8 *)&crc_own);

		/*
		 * CRC32 is computed, transmitted and received directly in NBO,
		 * so there's never a reason to convert byte order.
		 */
		crc_in = rctx->trailer.crc;

		if (crc_in != crc_own) {
			dprint(DBG_RX|DBG_ON,
				" (QP%d): CRC ERROR in:=%08x, own=%08x\n",
				QP_ID(qp), crc_in, crc_own);
			return -EINVAL;
		}
		return 0;
	}
	return -EAGAIN;
}


static int siw_get_hdr(struct siw_iwarp_rx *rctx)
{
	struct sk_buff		*skb = rctx->skb;
	struct iwarp_ctrl	*c_hdr = &rctx->hdr.ctrl;
	u8			opcode;

	int bytes;

	if (rctx->fpdu_part_rcvd < sizeof(struct iwarp_ctrl)) {
		/*
		 * copy first fix part of iwarp hdr
		 */
		bytes = min_t(int, rctx->skb_new, sizeof(struct iwarp_ctrl)
				- rctx->fpdu_part_rcvd);

		skb_copy_bits(skb, rctx->skb_offset,
			      (char *)c_hdr + rctx->fpdu_part_rcvd, bytes);

		rctx->fpdu_part_rcvd += bytes;

		rctx->skb_new -= bytes;
		rctx->skb_offset += bytes;
		rctx->skb_copied += bytes;

		if (!rctx->skb_new ||
			rctx->fpdu_part_rcvd < sizeof(struct iwarp_ctrl))
			return -EAGAIN;

		if (__ddp_version(c_hdr) != DDP_VERSION) {
			dprint(DBG_RX|DBG_ON, " dversion %d\n",
				__ddp_version(c_hdr));
			return -EINVAL;
		}
		if (__rdmap_version(c_hdr) != RDMAP_VERSION) {
			dprint(DBG_RX|DBG_ON, " rversion %d\n",
				__rdmap_version(c_hdr));
			return -EINVAL;
		}
		opcode = __rdmap_opcode(c_hdr);

		if (opcode > RDMAP_TERMINATE) {
			dprint(DBG_RX|DBG_ON, " opcode %d\n", opcode);
			return -EINVAL;
		}
		dprint(DBG_RX, "(QP%d): New Header, opcode:%d\n",
			RX_QPID(rctx), opcode);
	} else
		opcode = __rdmap_opcode(c_hdr);
	/*
	 * figure out len of current hdr: variable length of
	 * iwarp hdr forces us to copy hdr information
	 */
	bytes = min(rctx->skb_new,
		  iwarp_pktinfo[opcode].hdr_len - rctx->fpdu_part_rcvd);

	skb_copy_bits(skb, rctx->skb_offset,
		      (char *)c_hdr + rctx->fpdu_part_rcvd, bytes);

	rctx->fpdu_part_rcvd += bytes;

	rctx->skb_new -= bytes;
	rctx->skb_offset += bytes;
	rctx->skb_copied += bytes;

	if (rctx->fpdu_part_rcvd == iwarp_pktinfo[opcode].hdr_len) {
		/*
		 * HDR receive completed. Check if the current DDP segment
		 * starts a new RDMAP message or continues a previously
		 * started RDMAP message.
		 *
		 * Note well from the comments on DDP reassembly:
		 * - Support for unordered reception of DDP segments
		 *   (or FPDUs) from different RDMAP messages is not needed.
		 * - Unordered reception of DDP segments of the same
		 *   RDMAP message is not supported. It is probably not
		 *   needed with most peers.
		 */
		siw_dprint_hdr(&rctx->hdr, RX_QPID(rctx), "HDR received");

		if (rctx->more_ddp_segs != 0) {
			rctx->first_ddp_seg = 0;
			if (rctx->prev_rdmap_opcode != opcode) {
				dprint(DBG_ON,
					"packet intersection: %d <> %d\n",
					rctx->prev_rdmap_opcode, opcode);
				return -EPROTO;
			}
		} else {
			rctx->prev_rdmap_opcode = opcode;
			rctx->first_ddp_seg = 1;
		}
		rctx->more_ddp_segs =
			c_hdr->ddp_rdmap_ctrl & DDP_FLAG_LAST ? 0 : 1;

		return 0;
	}
	return -EAGAIN;
}

static inline int siw_fpdu_payload_len(struct siw_iwarp_rx *rctx)
{
	return be16_to_cpu(rctx->hdr.ctrl.mpa_len) - rctx->fpdu_part_rcvd
		+ MPA_HDR_SIZE;
}

static inline int siw_fpdu_trailer_len(struct siw_iwarp_rx *rctx)
{
	int mpa_len = be16_to_cpu(rctx->hdr.ctrl.mpa_len) + MPA_HDR_SIZE;

	return MPA_CRC_SIZE + (-mpa_len & 0x3);
}

/*
 * siw_rreq_complete()
 *
 * Complete the current READ REQUEST after READ RESPONSE processing.
 * It may complete consecutive WQE's which were already SQ
 * processed before but are awaiting completion due to completion
 * ordering (see verbs 8.2.2.2).
 * The READ RESPONSE may also resume SQ processing if it was stalled
 * due to ORD exhaustion (see verbs 8.2.2.18)
 * Function stops completion when next READ REQUEST found or ORQ empty.
 */
static void siw_rreq_complete(struct siw_wqe *wqe, int error)
{
	struct siw_qp		*qp = wqe->qp;
	int			num_wc = 1;
	enum ib_send_flags	flags;
	LIST_HEAD(c_list);

	flags = wr_flags(wqe);

	if (flags & IB_SEND_SIGNALED)
		list_add(&wqe->list, &c_list);
	else {
		atomic_inc(&qp->sq_space);
		siw_wqe_put(wqe);
		num_wc = 0;
	}

	lock_orq(qp);

	/* More WQE's to complete following this RREQ? */
	if (!list_empty(&qp->orq)) {
		struct list_head *pos, *n;
		list_for_each_safe(pos, n, &qp->orq) {
			wqe = list_entry_wqe(pos);
			if (wr_type(wqe) == SIW_WR_RDMA_READ_REQ)
				break;
			flags |= wr_flags(wqe);
			num_wc++;
			dprint(DBG_WR,
				"(QP%d): Resume completion, wr_type %d\n",
				QP_ID(qp), wr_type(wqe));
			list_move_tail(pos, &c_list);
		}
	}
	unlock_orq(qp);

	if (num_wc)
		siw_sq_complete(&c_list, qp, num_wc, flags);

	/*
	 * Check if SQ processing was stalled due to ORD limit
	 */
	lock_sq(qp);

	if (ORD_SUSPEND_SQ(qp)) {

		wqe = siw_next_tx_wqe(qp);

		if (wqe && !tx_wqe(qp)) {
			list_del_init(&wqe->list);
			tx_wqe(qp) = wqe;

			if (wr_type(wqe) == SIW_WR_RDMA_READ_REQ)
				list_add_tail(&wqe->list, &qp->orq);
			else
				atomic_inc(&qp->orq_space);

			unlock_sq(qp);

			dprint(DBG_RX, "(QP%d): SQ resume (%d)\n",
				QP_ID(qp), atomic_read(&qp->sq_space));

			siw_sq_queue_work(qp);
		} else {
			/* only new ORQ space if not next RREQ queued */
			atomic_inc(&qp->orq_space);
			unlock_sq(qp);
		}
	} else {
		unlock_sq(qp);
		atomic_inc(&qp->orq_space);
	}
}

/*
 * siw_rdmap_complete()
 *
 * complete processing of an RDMA message after receiving all
 * DDP segmens
 *
 *   o SENDs + RRESPs will need for completion,
 *   o RREQs need for  READ RESPONSE initialization
 *   o WRITEs need memory dereferencing
 *
 * TODO: Could siw_[s,r]_complete() fail? (CQ full)
 */
static inline int siw_rdmap_complete(struct siw_qp *qp,
				     struct siw_iwarp_rx *rctx)
{
	struct siw_wqe	*wqe;
	u8 opcode = __rdmap_opcode(&rctx->hdr.ctrl);
	int rv = 0;

	switch (opcode) {

	case RDMAP_SEND_SE:
		wr_flags(rx_wqe(qp)) |= IB_SEND_SOLICITED;
	case RDMAP_SEND:
		rctx->ddp_msn[RDMAP_UNTAGGED_QN_SEND]++;

		wqe = rx_wqe(qp);

		wqe->wc_status = IB_WC_SUCCESS;
		wqe->wr_status = SR_WR_DONE;

		siw_rq_complete(wqe, qp);

		break;

	case RDMAP_RDMA_READ_RESP:
		rctx->ddp_msn[RDMAP_UNTAGGED_QN_RDMA_READ]++;

		wqe = rx_wqe(qp);

		wqe->wc_status = IB_WC_SUCCESS;
		wqe->wr_status = SR_WR_DONE;

		siw_rreq_complete(wqe, 0);

		break;

	case RDMAP_RDMA_READ_REQ:
		rv = siw_init_rresp(qp, rctx);

		break;

	case RDMAP_RDMA_WRITE:
		/*
		 * Free References from memory object if
		 * attached to receive context (inbound WRITE)
		 * While a zero-length WRITE is allowed, the
		 * current implementation does not create
		 * a memory reference (it is unclear if memory
		 * rights should be checked in that case!).
		 *
		 * TODO: check zero length WRITE semantics
		 */
		if (rx_mem(qp))
			siw_mem_put(rx_mem(qp));
		break;

	default:
		break;

	}
	rctx->umem_chunk = NULL; /* DEBUG aid, tentatively */
	rx_wqe(qp) = NULL;	/* also clears MEM object for WRITE */

	return rv;
}

/*
 * siw_rdmap_error()
 *
 * Abort processing of RDMAP message after failure.
 * SENDs + RRESPs will need for receive completion, if
 * already started.
 *
 * TODO: WRITE need local error to be surfaced.
 *
 */
static inline void
siw_rdmap_error(struct siw_qp *qp, struct siw_iwarp_rx *rctx, int status)
{
	struct siw_wqe	*wqe;
	u8 opcode = __rdmap_opcode(&rctx->hdr.ctrl);

	switch (opcode) {

	case RDMAP_SEND_SE:
	case RDMAP_SEND:
		rctx->ddp_msn[RDMAP_UNTAGGED_QN_SEND]++;

		wqe = rx_wqe(qp);
		if (!wqe)
			return;

		if (opcode == RDMAP_SEND_SE)
			wr_flags(wqe) |= IB_SEND_SOLICITED;

		if (!wqe->wc_status)
			wqe->wc_status = IB_WC_GENERAL_ERR;

		wqe->wr_status = SR_WR_DONE;
		siw_rq_complete(wqe, qp);

		break;

	case RDMAP_RDMA_READ_RESP:
		/*
		 * A READ RESPONSE may flush consecutive WQE's
		 * which were SQ processed before
		 */
		rctx->ddp_msn[RDMAP_UNTAGGED_QN_RDMA_READ]++;

		if (rctx->state == SIW_GET_HDR || status == -ENODATA)
			/*  eventual RREQ left untouched */
			break;

		wqe = rx_wqe(qp);
		if (wqe) {
			if (status)
				wqe->wc_status = status;
			else
				wqe->wc_status = IB_WC_GENERAL_ERR;

			wqe->wr_status = SR_WR_DONE;
			/*
			 * All errors turn the wqe into signalled.
			 */
			wr_flags(wqe) |= IB_SEND_SIGNALED;
			siw_rreq_complete(wqe, status);
		}
		break;

	case RDMAP_RDMA_WRITE:
		/*
		 * Free References from memory object if
		 * attached to receive context (inbound WRITE)
		 * While a zero-length WRITE is allowed, the
		 * current implementation does not create
		 * a memory reference (it is unclear if memory
		 * rights should be checked in that case!).
		 *
		 * TODO: check zero length WRITE semantics
		 */
		if (rx_mem(qp))
			siw_mem_put(rx_mem(qp));
		break;

	default:
		break;
	}
	rctx->umem_chunk = NULL; /* DEBUG aid, tentatively */
	rx_wqe(qp) = NULL;	/* also clears MEM object for WRITE */
}

/*
 * siw_tcp_rx_data()
 *
 * Main routine to consume inbound TCP payload
 *
 * @rd_desc:	read descriptor
 * @skb:	socket buffer
 * @off:	offset in skb
 * @len:	skb->len - offset : payload in skb
 */
int siw_tcp_rx_data(read_descriptor_t *rd_desc, struct sk_buff *skb,
		    unsigned int off, size_t len)
{
	struct siw_qp		*qp = rd_desc->arg.data;
	struct siw_iwarp_rx	*rctx = &qp->rx_ctx;
	int			rv;

	rctx->skb = skb;
	rctx->skb_new = skb->len - off;
	rctx->skb_offset = off;
	rctx->skb_copied = 0;

	dprint(DBG_RX, "(QP%d): new data %d, rx-state %d\n", QP_ID(qp),
		rctx->skb_new, rctx->state);

	if (unlikely(rctx->rx_suspend == 1 ||
		     qp->attrs.state != SIW_QP_STATE_RTS)) {
		dprint(DBG_RX|DBG_ON, "(QP%d): failed. state rx:%d, qp:%d\n",
			QP_ID(qp), qp->rx_ctx.state, qp->attrs.state);
		return 0;
	}
	while (rctx->skb_new) {

		switch (rctx->state) {

		case SIW_GET_HDR:
			rv = siw_get_hdr(rctx);
			if (!rv) {
				if (rctx->crc_enabled &&
				    siw_crc_rxhdr(rctx) != 0) {
					rv = -EINVAL;
					break;
				}
				rctx->fpdu_part_rem =
					siw_fpdu_payload_len(rctx);

				if (rctx->fpdu_part_rem)
					rctx->pad = -rctx->fpdu_part_rem & 0x3;
				else
					rctx->pad = 0;

				rctx->state = SIW_GET_DATA_START;
				rctx->fpdu_part_rcvd = 0;
			}
			break;

		case SIW_GET_DATA_MORE:
			/*
			 * Another data fragment of the same DDP segment.
			 * Headers will not be checked again by the
			 * opcode-specific data receive function below.
			 * Setting first_ddp_seg = 0 avoids repeating
			 * initializations that may occur only once per
			 * DDP segment.
			 */
			rctx->first_ddp_seg = 0;

		case SIW_GET_DATA_START:
			/*
			 * Headers will be checked by the opcode-specific
			 * data receive function below.
			 */
			rv = siw_rx_data(qp, rctx);
			if (!rv) {
				rctx->fpdu_part_rem =
					siw_fpdu_trailer_len(rctx);
				rctx->fpdu_part_rcvd = 0;
				rctx->state = SIW_GET_TRAILER;
			} else
				rctx->state = SIW_GET_DATA_MORE;

			break;

		case SIW_GET_TRAILER:
			/*
			 * read CRC + any padding
			 */
			rv = siw_get_trailer(qp, rctx);
			if (!rv) {
				/*
				 * FPDU completed.
				 * complete RDMAP message if last fragment
				 */
				rctx->state = SIW_GET_HDR;
				rctx->fpdu_part_rcvd = 0;

				if (!(rctx->hdr.ctrl.ddp_rdmap_ctrl
					& DDP_FLAG_LAST))
					/* more frags */
					break;

				rv = siw_rdmap_complete(qp, rctx);
				if (rv)
					break;
			}
			break;

		default:
			WARN_ON(1);
			rv = -EAGAIN;
		}

		if (unlikely(rv != 0 && rv != -EAGAIN)) {
			/*
			 * TODO: implement graceful error handling including
			 *       generation (and processing) of TERMINATE
			 *       messages.
			 *
			 *	 for now we are left with a bogus rx status
			 *	 unable to receive any further byte.
			 *	 BUT: code must handle difference between
			 *
			 *	 o protocol syntax (FATAL, framing lost)
			 *	 o crc	(FATAL, framing lost since we do not
			 *	        trust packet header (??))
			 *	 o local resource (maybe non fatal, framing
			 *	   not lost)
			 *
			 *	 errors.
			 */
			siw_rdmap_error(qp, rctx, rv);

			dprint(DBG_RX|DBG_ON,
				"(QP%d): RX ERROR %d at RX state %d\n",
				QP_ID(qp), rv, rctx->state);

			siw_dprint_rctx(rctx);
			/*
			 * Calling siw_cm_queue_work() is safe without
			 * releasing qp->state_lock because the QP state
			 * will be transitioned to SIW_QP_STATE_ERROR
			 * by the siw_work_handler() workqueue handler
			 * after we return from siw_qp_llp_data_ready().
			 */
			siw_qp_cm_drop(qp, 1);

			break;
		}
		if (rv) {
			dprint(DBG_RX, "(QP%d): "
				"Misaligned FPDU: State: %d, missing: %d\n",
				QP_ID(qp), rctx->state, rctx->fpdu_part_rem);
			break;
		}
	}
	return rctx->skb_copied;
}

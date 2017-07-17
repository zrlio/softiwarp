/*
 * Software iWARP device driver for Linux
 *
 * Authors: Bernard Metzler <bmt@zurich.ibm.com>
 *          Fredy Neeser <nfd@zurich.ibm.com>
 *
 * Copyright (c) 2008-2016, IBM Corporation
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
	crypto_shash_init(ctx->mpa_crc_hd);

	return siw_crc_array(ctx->mpa_crc_hd, (u8 *)&ctx->hdr,
			     ctx->fpdu_part_rcvd);
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
 * @umem:	siw representation of target memory
 * @dest_addr:	1, if rctx chunk pointer should not be updated after len.
 */
static int siw_rx_umem(struct siw_iwarp_rx *rctx, struct siw_umem *umem,
		       u64 dest_addr, int len)
{
	void	*dest;
	int	pg_off = dest_addr & ~PAGE_MASK,
		copied = 0,
		bytes,
		rv;

	while (len) {
		struct page *p = siw_get_upage(umem, dest_addr);

		if (unlikely(!p)) {
			pr_warn("siw_rx_umem: QP[%d]: bogus addr: %p, %p\n",
				RX_QPID(rctx),
				(void *)dest_addr, (void *)umem->fp_addr);
			/* siw internal error */
			rctx->skb_copied += copied;
			rctx->skb_new -= copied;
			copied = -EFAULT;

			goto out;
		}

		bytes  = min(len, (int)PAGE_SIZE - pg_off);
		dest = kmap_atomic(p);

		rv = skb_copy_bits(rctx->skb, rctx->skb_offset, dest + pg_off,
				   bytes);

		dprint(DBG_RX, "(QP%d): Page %p, "
			"bytes=%u, rv=%d returned by skb_copy_bits()\n",
			RX_QPID(rctx), p, bytes, rv);

		if (likely(!rv)) {
			if (rctx->mpa_crc_hd)
				rv = siw_crc_page(rctx->mpa_crc_hd, p, pg_off,
						  bytes);

			rctx->skb_offset += bytes;
			copied += bytes;
			len -= bytes;
			dest_addr += bytes;
			pg_off = 0;
		}
		kunmap_atomic(dest);

		if (unlikely(rv)) {
			rctx->skb_copied += copied;
			rctx->skb_new -= copied;
			copied = -EFAULT;

			dprint(DBG_RX|DBG_ON, "(QP%d): failed with %d\n",
				RX_QPID(rctx), rv);

			goto out;
		}
	}
	/*
	 * store chunk position for resume
	 */
	rctx->skb_copied += copied;
	rctx->skb_new -= copied;
out:
	return copied;
}

static inline int siw_rx_kva(struct siw_iwarp_rx *rctx, void *kva, int len)
{
	int rv;

	dprint(DBG_RX, "(QP%d): receive %d bytes into %p\n", RX_QPID(rctx),
		len, kva);

	rv = skb_copy_bits(rctx->skb, rctx->skb_offset, kva, len);
	if (likely(!rv)) {
		rctx->skb_offset += len;
		rctx->skb_copied += len;
		rctx->skb_new -= len;
		if (rctx->mpa_crc_hd) {
			rv = siw_crc_array(rctx->mpa_crc_hd, kva, len);
			if (rv)
				goto error;
		}
		return len;
	}
	dprint(DBG_ON, "(QP%d): failed: len %d, addr %p, rv %d\n",
		RX_QPID(rctx), len, kva, rv);
error:
	return rv;
}

static int siw_rx_pbl(struct siw_iwarp_rx *rctx, struct siw_mr *mr,
		      u64 addr, int len)
{
	struct siw_pbl *pbl = mr->pbl;
	u64 offset = addr - mr->mem.va;
	int copied = 0;

	while (len) {
		int bytes;
		u64 buf_addr = siw_pbl_get_buffer(pbl, offset, &bytes,
						  &rctx->pbl_idx);
		if (buf_addr == 0)
			break;
		bytes = min(bytes, len);
		if (siw_rx_kva(rctx, (void *)buf_addr, bytes) == bytes) {
			copied += bytes;
			offset += bytes;
			len -= bytes;
		} else
			break;
	}
	return copied;
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
	struct siw_wqe		*wqe = &rctx->wqe_active;

	u32 sink_stag = be32_to_cpu(rresp->sink_stag);
	u64 sink_to   = be64_to_cpu(rresp->sink_to);

	if (rctx->first_ddp_seg) {
		rctx->ddp_stag = wqe->sqe.sge[0].lkey;
		rctx->ddp_to = wqe->sqe.sge[0].laddr;
		rctx->pbl_idx = 0;
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
		rctx->ddp_to = sink_to;
		rctx->pbl_idx = 0;
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
	struct iwarp_send_inv	*send = &rctx->hdr.send_inv;
	struct siw_wqe		*wqe = &rctx->wqe_active;

	u32 ddp_msn = be32_to_cpu(send->ddp_msn);
	u32 ddp_mo  = be32_to_cpu(send->ddp_mo);
	u32 ddp_qn  = be32_to_cpu(send->ddp_qn);

	if (ddp_qn != RDMAP_UNTAGGED_QN_SEND) {
		dprint(DBG_RX|DBG_ON, " Invalid DDP QN %d for SEND\n",
			ddp_qn);
		return -EINVAL;
	}
	if (unlikely(ddp_msn != rctx->ddp_msn[RDMAP_UNTAGGED_QN_SEND])) {
		dprint(DBG_RX|DBG_ON, " received MSN=%u, expected MSN=%u\n",
			ddp_msn, rctx->ddp_msn[RDMAP_UNTAGGED_QN_SEND]);
		/*
		 * TODO: Error handling
		 * async_event= RI_EVENT_QP_RQ_PROTECTION_ERROR_MSN_GAP;
		 * cmpl_status= RI_WC_STATUS_LOCAL_QP_CATASTROPHIC;
		 */
		return -EINVAL;
	}
	if (unlikely(ddp_mo != wqe->processed)) {
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
		rctx->pbl_idx = 0;
		/* only valid for SEND_INV and SEND_SE_INV operations */
		rctx->inval_stag = be32_to_cpu(send->inval_stag);
	}
	if (unlikely(wqe->bytes < wqe->processed + rctx->fpdu_part_rem)) {
		dprint(DBG_RX|DBG_ON, " Receive space short: (%d - %d) < %d\n",
			wqe->bytes, wqe->processed, rctx->fpdu_part_rem);
		wqe->wc_status = SIW_WC_LOC_LEN_ERR;
		return -EINVAL;
	}
	return 0;
}

static struct siw_wqe *siw_rqe_get(struct siw_qp *qp)
{
	struct siw_rqe *rqe;
	struct siw_srq *srq = qp->srq;
	struct siw_wqe *wqe = NULL;
	unsigned long flags;
	bool srq_used = false;

	if (srq) {
		/*
		 * 'srq_used' usage:
		 * convince gcc we know what we do. testing validity
		 * of 'srq' should be sufficient but gives
		 * "‘flags’ may be used uninitialized ..." later for unlock
		 */
		srq_used = true;
		lock_srq_rxsave(srq, flags);
		rqe = &srq->recvq[srq->rq_get % srq->num_rqe];
	} else
		rqe = &qp->recvq[qp->rq_get % qp->attrs.rq_size];

	if (likely(rqe->flags == SIW_WQE_VALID)) {
		int num_sge = rqe->num_sge;
		if (likely(num_sge <= SIW_MAX_SGE)) {
			int i = 0;

			wqe = rx_wqe(qp);
			wqe->wr_status = SR_WR_INPROGRESS;
			wqe->bytes = 0;
			wqe->processed = 0;

			wqe->rqe.id = rqe->id;
			wqe->rqe.num_sge = num_sge;

			while (i < num_sge) {
				wqe->rqe.sge[i].laddr = rqe->sge[i].laddr;
				wqe->rqe.sge[i].lkey = rqe->sge[i].lkey;
				wqe->rqe.sge[i].length = rqe->sge[i].length;
				wqe->bytes += wqe->rqe.sge[i].length;
				wqe->mem[i].obj = NULL;
				i++;
			}
			/* can be re-used by appl */
			smp_store_mb(rqe->flags, 0);
		} else {
			pr_info("RQE: too many SGE's: %d\n", rqe->num_sge);
			goto out;
		}
		if (srq_used == false)
			qp->rq_get++;
		else {
			if (srq->armed) {
				/* Test SRQ limit */
				u32 off = (srq->rq_get + srq->limit) %
					  srq->num_rqe;
				struct siw_rqe *rqe2 = &srq->recvq[off];

				if (!(rqe2->flags & SIW_WQE_VALID)) {
					srq->armed = 0;
					siw_srq_event(srq,
						IB_EVENT_SRQ_LIMIT_REACHED);
				}
			}
			srq->rq_get++;
		}
	} 
out:
	if (srq_used)
		unlock_srq_rxsave(srq, flags);

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
	struct siw_wqe		*wqe;
	struct siw_sge		*sge;
	u32			data_bytes,	/* all data bytes available */
				rcvd_bytes;	/* sum of data bytes rcvd */
	int rv = 0;

	if (rctx->first_ddp_seg) {
		wqe = siw_rqe_get(qp);
		if (unlikely(!wqe))
			return -ENOENT;
	} else  {
		wqe = rx_wqe(qp);
		if (unlikely(wqe->wr_status != SR_WR_INPROGRESS)) {
			/*
			 * this is a siw bug!
			 */
			dprint(DBG_ON, "QP(%d): RQ failure\n", QP_ID(qp));
			return -EPROTO;
		}
	}
	if (rctx->state == SIW_GET_DATA_START) {
		rv = siw_send_check_ntoh(rctx);
		if (unlikely(rv)) {
			siw_qp_event(qp, IB_EVENT_QP_FATAL);
			return rv;
		}
		if (!rctx->fpdu_part_rem) /* zero length SEND */
			return 0;
	}
	data_bytes = min(rctx->fpdu_part_rem, rctx->skb_new);
	rcvd_bytes = 0;

	/* A zero length SEND will skip below loop */
	while (data_bytes) {
		struct siw_pd *pd;
		struct siw_mr *mr;
		union siw_mem_resolved *mem;
		u32 sge_bytes;	/* data bytes avail for SGE */

		sge = &wqe->rqe.sge[rctx->sge_idx];

		if (!sge->length) {
			/* just skip empty sge's */
			rctx->sge_idx++;
			rctx->sge_off = 0;
			rctx->pbl_idx = 0;
			continue;
		}
		sge_bytes = min(data_bytes, sge->length - rctx->sge_off);
		mem = &wqe->mem[rctx->sge_idx];

		/*
		 * check with QP's PD if no SRQ present, SRQ's PD otherwise
		 */
		pd = qp->srq == NULL ? qp->pd : qp->srq->pd;

		rv = siw_check_sge(pd, sge, mem, SR_MEM_LWRITE, rctx->sge_off,
				   sge_bytes);
		if (unlikely(rv)) {
			siw_qp_event(qp, IB_EVENT_QP_ACCESS_ERR);
			break;
		}
		mr = siw_mem2mr(mem->obj);
		if (mr->mem_obj == NULL)
			rv = siw_rx_kva(rctx,
					(void *)(sge->laddr + rctx->sge_off),
					sge_bytes);
		else if (!mr->mem.is_pbl)
			rv = siw_rx_umem(rctx, mr->umem,
					 sge->laddr + rctx->sge_off, sge_bytes);
		else
			rv = siw_rx_pbl(rctx, mr,
					sge->laddr + rctx->sge_off, sge_bytes);

		if (unlikely(rv != sge_bytes)) {
			wqe->processed += rcvd_bytes;
			return -EINVAL;
		}
		rctx->sge_off += rv;

		if (rctx->sge_off == sge->length) {
			rctx->sge_idx++;
			rctx->sge_off = 0;
			rctx->pbl_idx = 0;
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
		if (unlikely(rv)) {
			siw_qp_event(qp, IB_EVENT_QP_FATAL);
			return rv;
		}
	}
	bytes = min(rctx->fpdu_part_rem, rctx->skb_new);

	if (rctx->first_ddp_seg) {
		/* DEBUG Code, to be removed */
		if (rx_mem(qp) != NULL) {
			dprint(DBG_RX|DBG_ON, "(QP%d): Stale rctx state!\n",
				QP_ID(qp));
			return -EFAULT;
		}
		rx_mem(qp) = siw_mem_id2obj(dev, rctx->ddp_stag >> 8);
		rx_wqe(qp)->wr_status = SR_WR_INPROGRESS;
	}
	if (unlikely(!rx_mem(qp))) {
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
	if (unlikely(rv)) {
		siw_qp_event(qp, IB_EVENT_QP_ACCESS_ERR);
		return rv;
	}

	mr = siw_mem2mr(mem);
	if (mr->mem_obj == NULL)
		rv = siw_rx_kva(rctx,
				(void *)(rctx->ddp_to + rctx->fpdu_part_rcvd),
				bytes);
	else if (!mr->mem.is_pbl)
		rv = siw_rx_umem(rctx, mr->umem,
				 rctx->ddp_to + rctx->fpdu_part_rcvd, bytes);
	else
		rv = siw_rx_pbl(rctx, mr,
				rctx->ddp_to + rctx->fpdu_part_rcvd, bytes);

	if (unlikely(rv != bytes))
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

static int siw_init_rresp(struct siw_qp *qp, struct siw_iwarp_rx *rctx)
{
	struct siw_wqe *tx_work = tx_wqe(qp);
	struct siw_sqe *resp;

	uint64_t	raddr	= be64_to_cpu(rctx->hdr.rreq.sink_to),
			laddr	= be64_to_cpu(rctx->hdr.rreq.source_to);
	uint32_t	length	= be32_to_cpu(rctx->hdr.rreq.read_size),
			lkey	= be32_to_cpu(rctx->hdr.rreq.source_stag),
			rkey	= be32_to_cpu(rctx->hdr.rreq.sink_stag);
	int run_sq = 1, rv = 0;
	unsigned long flags;

	lock_sq_rxsave(qp, flags);

	if (tx_work->wr_status == SR_WR_IDLE) {
		/*
		 * immediately schedule READ response w/o
		 * consuming IRQ entry: IRQ must be empty.
		 */
		tx_work->processed = 0;
		tx_work->mem[0].obj = NULL;
		tx_work->wr_status = SR_WR_QUEUED;
		resp = &tx_work->sqe;
	} else {
		resp = irq_alloc_free(qp);
		run_sq = 0;
	}
	if (likely(resp)) {
		resp->opcode = SIW_OP_READ_RESPONSE;

		resp->sge[0].length = length;
		resp->sge[0].laddr = laddr;
		resp->sge[0].lkey = lkey;

		resp->raddr = raddr;
		resp->rkey = rkey;
		resp->num_sge = length ? 1 : 0;

		smp_store_mb(resp->flags, SIW_WQE_VALID);
	} else {
		dprint(DBG_RX|DBG_ON, ": QP[%d]: IRQ %d exceeded %d!\n",
			QP_ID(qp), qp->irq_put % qp->attrs.irq_size,
			qp->attrs.irq_size);
		rv = -EPROTO;
	}

	unlock_sq_rxsave(qp, flags);

	if (run_sq)
		siw_sq_queue_work(qp);

	return rv;
}

/*
 * Only called at start of Read.Resonse processing.
 * Fetch pending Read from ORQ, but keep it valid until
 * Read.Response processing done. No Queue locking needed.
 */
static struct siw_wqe *siw_orqe_get(struct siw_qp *qp)
{
	struct siw_sqe *orqe;
	struct siw_wqe *wqe = NULL;

	smp_mb();

	orqe = orq_get_current(qp);
	if (_load_shared(orqe->flags) & SIW_WQE_VALID) {
		wqe = rx_wqe(qp);
		wqe->sqe.id = orqe->id;
		wqe->sqe.opcode = orqe->opcode;
		wqe->sqe.sge[0].laddr = orqe->sge[0].laddr;
		wqe->sqe.sge[0].lkey = orqe->sge[0].lkey;
		wqe->sqe.sge[0].length = orqe->sge[0].length;
		wqe->sqe.flags = orqe->flags;
		wqe->sqe.num_sge = 1;
		wqe->bytes = orqe->sge[0].length;
		wqe->processed = 0;
		wqe->mem[0].obj = NULL;
		wqe->wr_status = SR_WR_INPROGRESS;
		smp_wmb();
	}
	return wqe;
}


/*
 * siw_proc_rresp:
 *
 * Place incoming RRESP data into memory referenced by RREQ WQE
 * which is at the tip of the ORQ
 *
 * Function supports partially received RRESP's (suspending/resuming
 * current receive processing)
 */
int siw_proc_rresp(struct siw_qp *qp, struct siw_iwarp_rx *rctx)
{
	struct siw_wqe		*wqe;
	union siw_mem_resolved	*mem;
	struct siw_sge		*sge;
	struct siw_mr		*mr;
	int			bytes,
				rv;

	if (rctx->first_ddp_seg) {
		if (unlikely(rx_wqe(qp)->wr_status != SR_WR_IDLE)) {
			pr_warn("QP[%d]: Start RRESP: RX status %d, op %d\n",
				QP_ID(qp), rx_wqe(qp)->wr_status,
				rx_wqe(qp)->sqe.opcode);
			rv = -EPROTO;
			goto done;
		}
		/*
		 * fetch pending RREQ from orq
		 */
		wqe = siw_orqe_get(qp);
		if (unlikely(!wqe)) {
			dprint(DBG_RX|DBG_ON, "(QP%d): ORQ empty at idx %d\n",
				QP_ID(qp),
				qp->orq_get % qp->attrs.orq_size);
			rv = -EPROTO;
			goto done;
		}
		rv = siw_rresp_check_ntoh(rctx);
		if (unlikely(rv)) {
			siw_qp_event(qp, IB_EVENT_QP_FATAL);
			goto done;
		}
	} else {
		wqe = rx_wqe(qp);
		if (unlikely(wqe->wr_status != SR_WR_INPROGRESS)) {
			pr_warn("QP[%d]: Resume RRESP: status %d\n",
				QP_ID(qp), rx_wqe(qp)->wr_status);
			rv = -EPROTO;
			goto done;
		}
	}
	if (!rctx->fpdu_part_rem) /* zero length RRESPONSE */
		return 0;

	sge = wqe->sqe.sge; /* there is only one */
	mem = &wqe->mem[0];

	if (mem->obj == NULL) {
		/*
		 * check target memory which resolves memory on first fragment
		 */
		rv = siw_check_sge(qp->pd, sge, mem, SR_MEM_LWRITE, 0,
				   wqe->bytes);
		if (rv) {
			dprint(DBG_RX|DBG_ON, "(QP%d): siw_check_sge: %d\n",
				QP_ID(qp), rv);
			wqe->wc_status = SIW_WC_LOC_PROT_ERR;
			siw_qp_event(qp, IB_EVENT_QP_ACCESS_ERR);
			goto done;
		}
	}
	bytes = min(rctx->fpdu_part_rem, rctx->skb_new);

	mr = siw_mem2mr(mem->obj);
	if (mr->mem_obj == NULL)
		rv = siw_rx_kva(rctx, (void *)(sge->laddr + wqe->processed),
				bytes);
	else if (!mr->mem.is_pbl)
		rv = siw_rx_umem(rctx, mr->umem, sge->laddr + wqe->processed,
				 bytes);
	else
		rv = siw_rx_pbl(rctx, mr, sge->laddr + wqe->processed,
				 bytes);
	if (rv != bytes) {
		wqe->wc_status = SIW_WC_GENERAL_ERR;
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


int siw_proc_unsupp(struct siw_qp *qp, struct siw_iwarp_rx *rctx)
{
	return -ECONNRESET;
}


int siw_proc_terminate(struct siw_qp *qp, struct siw_iwarp_rx *rctx)
{
	dprint(DBG_ON, " (QP%d): RX Terminate: type=%d, layer=%d, code=%d\n",
		QP_ID(qp),
		__rdmap_term_etype(&rctx->hdr.terminate),
		__rdmap_term_layer(&rctx->hdr.terminate),
		__rdmap_term_ecode(&rctx->hdr.terminate));

	return -ECONNRESET;
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
		if (!rctx->mpa_crc_hd)
			return 0;

		if (rctx->pad && siw_crc_array(rctx->mpa_crc_hd,
					       tbuf, rctx->pad) != 0)
			return -EINVAL;

		crypto_shash_final(rctx->mpa_crc_hd, (u8 *)&crc_own);

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



static void siw_check_tx_fence(struct siw_qp *qp)
{
	struct siw_wqe *tx_waiting = tx_wqe(qp);
	struct siw_sqe *rreq;
	int resume_tx = 0;
	unsigned long flags;

	lock_orq_rxsave(qp, flags);

	/* free current orq entry */
	rreq = orq_get_current(qp);
	smp_store_mb(rreq->flags, 0);

	if (qp->tx_ctx.orq_fence) {
		if (unlikely(tx_waiting->wr_status != SR_WR_QUEUED)) {
			pr_warn("QP[%d]: Resume from fence: status %d wrong\n",
				QP_ID(qp), tx_waiting->wr_status);
			goto out;
		}
		/* resume SQ processing */
		if (tx_waiting->sqe.opcode == SIW_OP_READ ||
		    tx_waiting->sqe.opcode == SIW_OP_READ_LOCAL_INV) {

			rreq = orq_get_tail(qp);
			if (unlikely(!rreq)) {
				pr_warn("QP[%d]: no ORQ\n", QP_ID(qp)); 
				goto out;
			}
			siw_read_to_orq(rreq, &tx_waiting->sqe);

			qp->orq_put++;
			qp->tx_ctx.orq_fence = 0;
			resume_tx = 1;

		} else if (siw_orq_empty(qp)) {

			qp->tx_ctx.orq_fence = 0;
			resume_tx = 1;
		} else
			pr_warn("QP[%d]:  Resume from fence: error: %d:%d\n",
				QP_ID(qp), qp->orq_get, qp->orq_put);
	}
	qp->orq_get++;
out:
	unlock_orq_rxsave(qp, flags);

	if (resume_tx)
		siw_sq_queue_work(qp);
}

/*
 * siw_rdmap_complete()
 *
 * Complete processing of an RDMA message after receiving all
 * DDP segmens or ABort processing after encountering error case.
 *
 *   o SENDs + RRESPs will need for completion,
 *   o RREQs need for  READ RESPONSE initialization
 *   o WRITEs need memory dereferencing
 *
 * TODO: Failed WRITEs need local error to be surfaced.
 */

static inline int
siw_rdmap_complete(struct siw_qp *qp, int error)
{
	struct siw_iwarp_rx	*rctx = &qp->rx_ctx;
	struct siw_wqe		*wqe = rx_wqe(qp);
	enum siw_wc_status	wc_status = wqe->wc_status;

	u8 opcode = __rdmap_opcode(&rctx->hdr.ctrl);
	int rv = 0;

	switch (opcode) {

	case RDMAP_SEND_SE:
	case RDMAP_SEND_SE_INVAL:
		wqe->rqe.flags |= SIW_WQE_SOLICITED;
	case RDMAP_SEND:
	case RDMAP_SEND_INVAL:
		if (wqe->wr_status == SR_WR_IDLE)
			break;

		rctx->ddp_msn[RDMAP_UNTAGGED_QN_SEND]++;

		if (error != 0 && wc_status == SIW_WC_SUCCESS)
			wc_status = SIW_WC_GENERAL_ERR;

		/*
		 * Handle STag invalidation request
		 */
		if (wc_status == SIW_WC_SUCCESS &&
		    (opcode == RDMAP_SEND_INVAL ||
		     opcode == RDMAP_SEND_SE_INVAL)) {
			rv = siw_invalidate_stag(qp->pd, rctx->inval_stag);
			if (rv)
				wc_status = SIW_WC_REM_INV_REQ_ERR;
		}
		rv = siw_rqe_complete(qp, &wqe->rqe, wqe->processed,
				      wc_status);
		siw_wqe_put_mem(wqe, SIW_OP_RECEIVE);

		break;

	case RDMAP_RDMA_READ_RESP:
		if (wqe->wr_status == SR_WR_IDLE)
			break;

		rctx->ddp_msn[RDMAP_UNTAGGED_QN_RDMA_READ]++;
		if (error != 0) {
			if  (rctx->state == SIW_GET_HDR || error == -ENODATA)
				/*  eventual RREQ in ORQ left untouched */
				break;

			if (wc_status == SIW_WC_SUCCESS)
				wc_status = SIW_WC_GENERAL_ERR;
		} else if (qp->kernel_verbs) {
			/*
			 * Handle any STag invalidation request
			 */
			if (opcode == SIW_OP_READ_LOCAL_INV) {
				rv = siw_invalidate_stag(qp->pd,
							 wqe->sqe.sge[0].lkey);
				if (rv && wc_status == SIW_WC_SUCCESS) {
					wc_status = SIW_WC_GENERAL_ERR;
					error = rv;
				}
			}
		}
		/*
		 * All errors turn the wqe into signalled.
		 */
		if ((wqe->sqe.flags & SIW_WQE_SIGNALLED) || error != 0)
			rv = siw_sqe_complete(qp, &wqe->sqe, wqe->processed,
					      wc_status);
		siw_wqe_put_mem(wqe, SIW_OP_READ);

		if (error == 0)
			siw_check_tx_fence(qp);
		break;

	case RDMAP_RDMA_READ_REQ:
		if (error == 0)
			rv = siw_init_rresp(qp, rctx);

		break;

	case RDMAP_RDMA_WRITE:
		if (wqe->wr_status == SR_WR_IDLE)
			break;

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
		if (rx_mem(qp)) {
			siw_mem_put(rx_mem(qp));
			rx_mem(qp) = NULL;
		}
		break;

	default:
		break;
	}
	wqe->wr_status = SR_WR_IDLE;

	return rv;
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

	dprint(DBG_RX, "(QP%d): new data %d\n",
		QP_ID(qp), rctx->skb_new);

	while (rctx->skb_new) {
		int run_completion = 1;

		if (unlikely(rctx->rx_suspend)) {
			/* Do not process any more data */
			rctx->skb_copied += rctx->skb_new;
			break;
		}
		switch (rctx->state) {

		case SIW_GET_HDR:
			rv = siw_get_hdr(rctx);
			if (!rv) {
				if (rctx->mpa_crc_hd &&
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
			} else {
				if (unlikely(rv == -ECONNRESET))
					run_completion = 0;
				else
					rctx->state = SIW_GET_DATA_MORE;
			}
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

				rv = siw_rdmap_complete(qp, 0);
				run_completion = 0;
			}
			break;

		default:
			pr_warn("QP[%d]: RX out of state\n", QP_ID(qp));
			rv = -EPROTO;
			run_completion = 0;
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
			 *	 errors:
			 *
			 *	 o protocol syntax (FATAL, framing lost)
			 *	 o crc	(FATAL, framing lost since we do not
			 *	        trust packet header (??))
			 *	 o local resource (maybe non fatal, framing
			 *	   not lost)
			 *
			 */
			if (rctx->state > SIW_GET_HDR && run_completion)
				siw_rdmap_complete(qp, rv);

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

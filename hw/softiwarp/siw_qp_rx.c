/*
 * Software iWARP device driver for Linux
 *
 * Authors: Bernard Metzler <bmt@zurich.ibm.com>
 *          Fredy Neeser <nfd@zurich.ibm.com>
 *
 * Copyright (c) 2008-2010, IBM Corporation
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
#include "siw_socket.h"
#include "siw_utils.h"


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

static void siw_print_rctx(struct siw_iwarp_rx *rctx)
{
	if (!(DPRINT_MASK & DBG_ON))
		return;
	printk(KERN_INFO "RECEIVE CONTEXT*************************\n");
	printk(KERN_INFO "QP: %d\n", RX_QPID(rctx));
	printk(KERN_INFO "skb: %p\n", rctx->skb);
	printk(KERN_INFO "HDR: (%d)\n", rctx->hdr.ctrl.opcode);
	printk(KERN_INFO "WQE/UMEM = %p\n", rctx->dest.wqe);
	printk(KERN_INFO "STAG = %x (MEM%x)\n", rctx->ddp_stag,
		rctx->ddp_stag>>8);
	printk(KERN_INFO "DDP_TO: %016llx\n",
		(unsigned long long)rctx->ddp_to);
	printk(KERN_INFO "fpdu_part_rcvd: %d\n", rctx->fpdu_part_rcvd);
	printk(KERN_INFO "fpdu_part_rem: %d\n", rctx->fpdu_part_rem);
	printk(KERN_INFO "skb_new: %d\n", rctx->skb_new);
	printk(KERN_INFO "skb_offset: %d\n", rctx->skb_offset);
	printk(KERN_INFO "skb_copied: %d\n", rctx->skb_copied);
	printk(KERN_INFO "sge_idx: %d\n", rctx->sge_idx);
	printk(KERN_INFO "sge_off: %d\n", rctx->sge_off);
	printk(KERN_INFO "umem_chunk: %p\n", rctx->umem_chunk);
	printk(KERN_INFO "pg_idx: %d\n", rctx->pg_idx);
	printk(KERN_INFO "pg_off: %d\n", rctx->pg_off);
	printk(KERN_INFO "state: %d\n", rctx->state);
	printk(KERN_INFO "crc_enabled: %d\n", rctx->crc_enabled);
	printk(KERN_INFO "pad: %d\n", rctx->pad);
	printk(KERN_INFO "prev_ddp_opcode: %d\n", rctx->prev_ddp_opcode);
	printk(KERN_INFO "more_ddp_segs: %d\n", rctx->more_ddp_segs);
	printk(KERN_INFO "first_ddp_seg: %d\n", rctx->first_ddp_seg);
	printk(KERN_INFO "****************************************\n");
}


static inline void siw_crc_rxhdr(struct siw_iwarp_rx *ctx)
{
	crypto_hash_init(&ctx->mpa_crc_hd);
	siw_crc_array(&ctx->mpa_crc_hd, (u8 *)&ctx->hdr,
			ctx->fpdu_part_rcvd);
}


/*
 * siw_qp_rx_umem_init()
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
static int siw_qp_rx_umem_init(struct siw_iwarp_rx *rctx,
			       struct siw_mr *mr, u64 t_off)
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
		dprint(DBG_MM|DBG_ON, "(QP ?): Short chunk list\n");
		return -EINVAL;
	}
	rctx->pg_idx = psge_idx;
	rctx->pg_off = off_mr & ~PAGE_MASK;
	rctx->umem_chunk = chunk;

	dprint(DBG_MM, "(QP%d): New chunk with Page idx %d\n", RX_QPID(rctx),
		psge_idx);
	return 0;
}


/*
 * siw_qp_rx_umem()
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
static int siw_qp_rx_umem(struct siw_iwarp_rx *rctx, int len, int umem_ends)
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
		dest   = kmap_atomic(sg_page(p_list), KM_SOFTIRQ0);

		rv = skb_copy_bits(rctx->skb, rctx->skb_offset, dest + pg_off,
				   bytes);

		dprint(DBG_RX, "(QP%d): Page #%d, "
			"bytes=%u, rv=%d returned by skb_copy_bits()\n",
			RX_QPID(rctx), rctx->pg_idx, bytes, rv);

		if (rv) {
			/*
			 * should be -EFAULT.
			 *
			 * FIXME:
			 * It looks like skb_copy_bits() cannot fail at all
			 * given the way we call it.
			 * But let's at least do the kunmap_atomic() ...
			 * and adjust skb_copied and skb_offset
			 */
			rctx->skb_copied += copied;
			rctx->skb_offset += copied;
			rctx->skb_new -= copied;

			kunmap_atomic(dest, KM_SOFTIRQ0);

			WARN_ON(rv);
			break;
		}
		dprint_mem_irq(DBG_DATA, "Page data received",
				dest + pg_off, bytes, "(QP%d): ",
				RX_QPID(rctx));

		if (rctx->crc_enabled)
			siw_crc_array(&rctx->mpa_crc_hd, dest + pg_off,
					bytes);

		kunmap_atomic(dest, KM_SOFTIRQ0);

		rctx->skb_offset += bytes;
		copied += bytes;
		len -= bytes;

		pg_off += bytes;

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
				chunk = ib_umem_chunk_next(chunk);
			}
		}
	}
	/*
	 * store chunk position for resume
	 */
	rctx->umem_chunk = chunk;
	rctx->pg_off = pg_off;

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
	struct siw_wqe		*wqe = rctx->dest.wqe;

	rresp->sink_stag = be32_to_cpu(rresp->sink_stag);
	rresp->sink_to   = be64_to_cpu(rresp->sink_to);

	if (rctx->first_ddp_seg) {
		rctx->ddp_stag = wqe->wr.rread.sge[0].lkey;
		rctx->ddp_to   = wqe->wr.rread.sge[0].addr;
	}
	if (rctx->ddp_stag != rresp->sink_stag) {
		dprint(DBG_RX|DBG_ON,
			" received STAG=%08x, expected STAG=%08x\n",
			rresp->sink_stag, rctx->ddp_stag);
		/*
		 * Verbs: RI_EVENT_QP_LLP_INTEGRITY_ERROR_BAD_FPDU
		 */
		return -EINVAL;
	}
	if (rctx->ddp_to != rresp->sink_to) {
		dprint(DBG_RX|DBG_ON,
			" received TO=%016llx, expected TO=%016llx\n",
			(unsigned long long)rresp->sink_to,
			(unsigned long long)rctx->ddp_to);
		/*
		 * Verbs: RI_EVENT_QP_LLP_INTEGRITY_ERROR_BAD_FPDU
		 */
		return -EINVAL;
	}
	if (rctx->more_ddp_segs)
		rctx->ddp_to += rctx->fpdu_part_rem;

	else if (wqe->processed + rctx->fpdu_part_rem != wqe->bytes) {
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

	write->sink_stag = be32_to_cpu(write->sink_stag);
	write->sink_to   = be64_to_cpu(write->sink_to);

	if (rctx->first_ddp_seg) {
		rctx->ddp_stag = write->sink_stag;
		rctx->ddp_to   = write->sink_to;
	} else {
		if (rctx->ddp_stag != write->sink_stag) {
			dprint(DBG_RX|DBG_ON,
				"received STAG=%08x, expected STAG=%08x\n",
				write->sink_stag, rctx->ddp_stag);
			/*
			 * Verbs: RI_EVENT_QP_LLP_INTEGRITY_ERROR_BAD_FPDU
			 */
			return -EINVAL;
		}
		if (rctx->ddp_to !=  write->sink_to) {
			dprint(DBG_RX|DBG_ON,
				"received TO=%016llx, expected TO=%016llx\n",
				(unsigned long long)write->sink_to,
				(unsigned long long)rctx->ddp_to);
			/*
			 * Verbs: RI_EVENT_QP_LLP_INTEGRITY_ERROR_BAD_FPDU
			 */
			return -EINVAL;
		}
	}
	/*
	 * Update expected target offset for next incoming DDP segment
	 */
	if (rctx->more_ddp_segs != 0)
		rctx->ddp_to += rctx->fpdu_part_rem;

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

	send->ddp_msn = be32_to_cpu(send->ddp_msn);
	send->ddp_mo  = be32_to_cpu(send->ddp_mo);
	send->ddp_qn  = be32_to_cpu(send->ddp_qn);

	if (send->ddp_qn != RDMAP_UNTAGGED_QN_SEND) {
		dprint(DBG_RX|DBG_ON, "Invalid DDP QN %d for SEND\n",
			send->ddp_qn);
		return -EINVAL;
	}
	if (send->ddp_msn != rctx->ddp_msn[RDMAP_UNTAGGED_QN_SEND]) {
		dprint(DBG_RX|DBG_ON, "received MSN=%d, expected MSN=%d\n",
			rctx->ddp_msn[RDMAP_UNTAGGED_QN_SEND], send->ddp_msn);
		/*
		 * TODO: Error handling
		 * async_event= RI_EVENT_QP_RQ_PROTECTION_ERROR_MSN_GAP;
		 * cmpl_status= RI_WC_STATUS_LOCAL_QP_CATASTROPHIC;
		 */
		return -EINVAL;
	}
	if (send->ddp_mo != wqe->processed) {
		dprint(DBG_RX|DBG_ON, "Received MO=%u, expected MO=%u\n",
			send->ddp_mo, wqe->processed);
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
		dprint(DBG_RX|DBG_ON, "Receive space short: %d < %d\n",
			wqe->bytes - wqe->processed, rctx->fpdu_part_rem);
		wqe->wc_status = IB_WC_LOC_LEN_ERR;
		return -EINVAL;
	}
	return 0;
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

	dprint(DBG_RX, "(QP%d): Enter\n", QP_ID(qp));

	if (rctx->first_ddp_seg) {
		WARN_ON(rx_wqe(qp) != NULL);
		/*
		 * fetch one RECEIVE wqe
		 */
		if (!qp->srq) {
			spin_lock_bh(&qp->rq_lock);
			if (!list_empty(&qp->rq)) {
				wqe = list_first_wqe(&qp->rq);
				list_del_init(&wqe->list);
				spin_unlock_bh(&qp->rq_lock);
			} else {
				spin_unlock_bh(&qp->rq_lock);
				dprint(DBG_RX,
					"QP(%d): RQ empty!\n", QP_ID(qp));
				return -ENOENT;
			}
		} else {
			wqe = siw_srq_fetch_wqe(qp);
			if (!wqe) {
				dprint(DBG_RX, "QP(%d): SRQ empty!\n",
					QP_ID(qp));
				return -ENOENT;
			}
		}
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
			siw_async_ev(qp, NULL, IB_EVENT_QP_FATAL);
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
		int	umem_ends;	/* 1 if umem ends with current rcv */

		sge = &wqe->wr.sgl.sge[rctx->sge_idx];

		if (!sge->len) {
			/* just skip empty sge's */
			rctx->sge_idx++;
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
			siw_async_ev(qp, NULL, IB_EVENT_QP_ACCESS_ERR);
			break;
		}
		mr = siw_mem2mr(sge->mem.obj);

		if (rctx->sge_off == 0) {
			/*
			 * started a new sge: update receive pointers
			 */
			rv = siw_qp_rx_umem_init(rctx, mr, sge->addr);
			if (rv)
				break;
		}
		/*
		 * Are we going to finish placing
		 * - the last fragment of the current SGE or
		 * - the last DDP segment (L=1) of the current RDMAP message?
		 *
		 * siw_qp_rx_umem() must advance umem page_chunk position
		 * after sucessful receive only, if receive into current
		 * umem does not end. umem ends, if:
		 * - current SGE gets completely filled, OR
		 * - current MPA FPDU is last AND gets consumed now
		 */
		umem_ends = ((sge_bytes + rctx->sge_off == sge->len) ||
			      (!rctx->more_ddp_segs &&
			       rctx->fpdu_part_rcvd + sge_bytes ==
					rctx->fpdu_part_rem)) ? 1 : 0;

		rv = siw_qp_rx_umem(rctx, sge_bytes, umem_ends);
		if (rv != sge_bytes) {
			dprint(DBG_RX|DBG_ON, "(QP%d): "
				"siw_qp_rx_umem failed with %d != %d\n",
				QP_ID(qp), rv, sge_bytes);
			/*
			 * siw_qp_rx_umem() must have updated
			 * skb_new and skb_copied
			 */
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
	rctx->skb_new -= rcvd_bytes;
	rctx->skb_copied += rcvd_bytes;

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
	struct siw_dev		*dev = qp->hdr.dev;
	struct iwarp_rdma_write	*write = &rctx->hdr.rwrite;
	struct siw_mem		*mem;
	int			bytes,
				last_write,
				rv;

	dprint(DBG_RX, "(QP%d): Enter\n", QP_ID(qp));

	if (rctx->state == SIW_GET_DATA_START) {

		if (!rctx->fpdu_part_rem) /* zero length WRITE */
			return 0;

		rv = siw_write_check_ntoh(rctx);
		if (rv) {
			siw_async_ev(qp, NULL, IB_EVENT_QP_FATAL);
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
		if (rx_mem(qp) != 0) {
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
	rv = siw_check_mem(qp->pd, mem, write->sink_to + rctx->fpdu_part_rcvd,
			   SR_MEM_RWRITE, bytes);
	if (rv) {
		siw_async_ev(qp, NULL, IB_EVENT_QP_ACCESS_ERR);
		return rv;
	}
	if (rctx->first_ddp_seg) {
		rv = siw_qp_rx_umem_init(rctx, siw_mem2mr(mem), write->sink_to);
		if (rv) {
			dprint(DBG_RX|DBG_ON, "(QP%d): "
				" siw_qp_rx_umem_init!\n", QP_ID(qp));
			return -EINVAL;
		}
	} else if (!rctx->umem_chunk) {
		/*
		 * This should never happen.
		 *
		 * TODO: Remove tentative debug aid.
		 */
		dprint(DBG_RX|DBG_ON, "(QP%d): "
			"Umem chunk not resolved!\n", QP_ID(qp));
		return -EINVAL;
	}
	/*
	 * Are we going to place the last piece of the last
	 * DDP segment of the current RDMAP message?
	 *
	 * It is last if:
	 * - rctx->fpdu_part_rem <= rctx->skb_new AND
	 * - payload_rem (of current DDP segment) <= rctx->skb_new
	 */
	last_write = ((rctx->fpdu_part_rem <= rctx->skb_new) &&
		      !rctx->more_ddp_segs) ? 1 : 0;

	rv = siw_qp_rx_umem(rctx, bytes, last_write);
	if (rv != bytes) {
		dprint(DBG_RX|DBG_ON, "(QP%d): "
			"siw_qp_rx_umem failed with %d != %d\n",
			 QP_ID(qp), rv, bytes);
		return -EINVAL;
	}
	rctx->skb_new -= rv;
	rctx->skb_copied += rv;

	rctx->fpdu_part_rem -= rv;
	rctx->fpdu_part_rcvd += rv;

	if (!rctx->fpdu_part_rem)
		return 0;

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
		rctx->hdr.ctrl.mpa_len);

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

int siw_init_rresp(struct siw_qp *qp, struct siw_iwarp_rx *rctx)
{
	struct siw_wqe 	*rsp;

	dprint(DBG_RX, "(QP%d): Enter\n", QP_ID(qp));

	rsp = siw_wqe_get(qp, SIW_WR_RDMA_READ_RESP);
	if (rsp) {
		rsp->wr.rresp.sge.len = be32_to_cpu(rctx->hdr.rreq.read_size);
		rsp->wr.rresp.sge.addr = be64_to_cpu(rctx->hdr.rreq.source_to);
		rsp->wr.rresp.num_sge = 1;

		rsp->wr.rresp.sge.mem.obj = NULL;	/* defer lookup */
		rsp->wr.rresp.sge.lkey =
			be32_to_cpu(rctx->hdr.rreq.source_stag);

		rsp->wr.rresp.raddr = be64_to_cpu(rctx->hdr.rreq.sink_to);
		rsp->wr.rresp.rtag = rctx->hdr.rreq.sink_stag; /* NBO */

		rsp->bytes = rsp->wr.rresp.sge.len;	/* redundant */
		rsp->processed = 0;
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
	spin_lock_bh(&qp->sq_lock);
	if (!tx_wqe(qp)) {
		tx_wqe(qp) = rsp;
		spin_unlock_bh(&qp->sq_lock);
		/*
		 * schedule TX work, even if SQ was supended due to
		 * ORD limit: it is always OK (and may even prevent peers
		 * from appl lock) to send RRESPONSE's
		 */
		siw_sq_queue_work(qp);
	} else {
		list_add_tail(&rsp->list, &qp->irq);
		spin_unlock_bh(&qp->sq_lock);
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
			is_last,
			rv;

	dprint(DBG_RX, "(QP%d): Enter\n", QP_ID(qp));

	if (rctx->first_ddp_seg) {
		WARN_ON(rx_wqe(qp) != NULL);
		/*
		 * fetch pending RREQ from orq
		 */
		spin_lock_bh(&qp->orq_lock);
		if (!list_empty(&qp->orq)) {
			wqe = list_first_entry(&qp->orq, struct siw_wqe, list);
			list_del_init(&wqe->list);
		} else {
			spin_unlock_bh(&qp->orq_lock);
			dprint(DBG_RX|DBG_ON, "(QP%d): RResp: ORQ empty\n",
				QP_ID(qp));
			/*
			 * TODO: Should generate an async error
			 */
			return -ENODATA; /* or -ENOENT ? */
		}
		spin_unlock_bh(&qp->orq_lock);

		rx_wqe(qp) = wqe;

		WARN_ON(wr_type(wqe) != SIW_WR_RDMA_READ_REQ);
		WARN_ON(wqe->processed);

		wqe->wr_status = SR_WR_INPROGRESS;

		rv = siw_rresp_check_ntoh(rctx);
		if (rv) {
			dprint(DBG_RX|DBG_ON, "(QP%d): "
				"siw_rresp_check_ntoh failed: %d\n",
				QP_ID(qp), rv);
			siw_async_ev(qp, NULL, IB_EVENT_QP_FATAL);
			return rv;
		}
	} else {
		wqe = rx_wqe(qp);
		if (!wqe) {
			WARN_ON(1);
			return -ENODATA;
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
		siw_async_ev(qp, NULL, IB_EVENT_QP_ACCESS_ERR);
		return rv;
	}
	mr = siw_mem2mr(sge->mem.obj);

	if (rctx->first_ddp_seg) {
		rv = siw_qp_rx_umem_init(rctx, mr, sge->addr);
		if (rv) {
			dprint(DBG_RX|DBG_ON, "(QP%d): "
				"siw_qp_rx_umem_init failed: %d\n",
				QP_ID(qp), rv);
			wqe->wc_status = IB_WC_LOC_PROT_ERR;
			return rv;
		}
	} else if (!rctx->umem_chunk) {
		/*
		 * This should never happen.
		 *
		 * TODO: Remove tentative debug aid.
		 */
		dprint(DBG_RX|DBG_ON, "(QP%d): Umem chunk not resolved!\n",
			QP_ID(qp));
		wqe->wc_status = IB_WC_GENERAL_ERR;
		return -EPROTO;
	}
	/*
	 * Are we going to finish placing the last DDP segment (L=1)
	 * of the current RDMAP message?
	 *
	 * NOTE: siw_rresp_check_ntoh() guarantees that the
	 * last inbound RDMAP Read Response message exactly matches
	 * with the RREQ WR.
	 */
	is_last = (bytes + wqe->processed == wqe->bytes) ? 1 : 0;

	rv = siw_qp_rx_umem(rctx,  bytes, is_last);
	if (rv != bytes) {
		dprint(DBG_RX|DBG_ON, "(QP%d): "
			"siw_qp_rx_umem failed with %d != %d\n",
			 QP_ID(qp), rv, bytes);
		wqe->wc_status = IB_WC_GENERAL_ERR;
		return -EINVAL;
	}
	rctx->skb_new -= rv;
	rctx->skb_copied += rv;

	rctx->fpdu_part_rem -= rv;
	rctx->fpdu_part_rcvd += rv;

	wqe->processed += rv;

	if (!rctx->fpdu_part_rem)
		return 0;

	return (rv < 0) ? rv : -EAGAIN;
}

int siw_proc_unsupp(struct siw_qp *qp, struct siw_iwarp_rx *rcx)
{
	WARN_ON(1);
	return __siw_drain_pkt(qp, rcx);
}



static int siw_get_trailer(struct siw_qp *qp, struct siw_iwarp_rx *rctx)
{
	struct sk_buff	*skb = rctx->skb;
	u8		*tbuf = (u8 *)&rctx->trailer.crc - rctx->pad;
	int		avail;

	avail = min(rctx->skb_new, rctx->fpdu_part_rem - rctx->fpdu_part_rcvd);

	skb_copy_bits(skb, rctx->skb_offset,
		      tbuf + rctx->fpdu_part_rcvd, avail);

	rctx->fpdu_part_rcvd += avail;
	rctx->skb_new -= avail;
	rctx->skb_offset += avail;
	rctx->skb_copied += avail;
	rctx->fpdu_part_rem -= avail;

	dprint(DBG_RX, " (QP%d): %d remaining (%d)\n",
		QP_ID(qp), rctx->fpdu_part_rem, avail);

	if (!rctx->fpdu_part_rem) {
		u32	crc_in, crc_own;
		/*
		 * check crc if required
		 */
		if (!rctx->crc_enabled)
			return 0;

		if (rctx->pad)
			siw_crc_array(&rctx->mpa_crc_hd,
				      (u8 *)&rctx->trailer.crc - rctx->pad,
				      rctx->pad);

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

	int bytes;

	if (rctx->fpdu_part_rcvd < sizeof(struct iwarp_ctrl)) {
		/*
		 * copy first fix part of iwarp hdr
		 */
		bytes = min_t(int, rctx->skb_new,
			      sizeof(struct iwarp_ctrl) - rctx->fpdu_part_rcvd);

		skb_copy_bits(skb, rctx->skb_offset,
			      (char *)c_hdr + rctx->fpdu_part_rcvd, bytes);

		rctx->fpdu_part_rcvd += bytes;
		rctx->skb_new    -= bytes;
		rctx->skb_offset += bytes;
		rctx->skb_copied += bytes;

		if (!rctx->skb_new ||
			rctx->fpdu_part_rcvd < sizeof(struct iwarp_ctrl))
			return -EAGAIN;

		if (c_hdr->opcode > RDMAP_TERMINATE) {
			dprint(DBG_RX|DBG_ON, " opcode %d\n", c_hdr->opcode);
			return -EINVAL;
		}
		if (c_hdr->dv != DDP_VERSION) {
			dprint(DBG_RX|DBG_ON, " dversion %d\n", c_hdr->dv);
			return -EINVAL;
		}
		if (c_hdr->rv != RDMAP_VERSION) {
			dprint(DBG_RX|DBG_ON, " rversion %d\n", c_hdr->rv);
			return -EINVAL;
		}
		dprint(DBG_RX, "(QP%d): New Header, opcode:%d\n",
			RX_QPID(rctx), c_hdr->opcode);
	}
	/*
	 * figure out len of current hdr: variable length of
	 * iwarp hdr forces us to copy hdr information
	 */
	bytes = min(rctx->skb_new,
		  iwarp_pktinfo[c_hdr->opcode].hdr_len - rctx->fpdu_part_rcvd);

	skb_copy_bits(skb, rctx->skb_offset,
		      (char *)c_hdr + rctx->fpdu_part_rcvd, bytes);

	rctx->fpdu_part_rcvd += bytes;
	rctx->skb_new -= bytes;
	rctx->skb_offset += bytes;
	rctx->skb_copied += bytes;

	dprint(DBG_RX, " (QP%d): %d remaining (%d)\n", RX_QPID(rctx),
		iwarp_pktinfo[c_hdr->opcode].hdr_len - rctx->fpdu_part_rcvd,
		bytes);

	if (rctx->fpdu_part_rcvd == iwarp_pktinfo[c_hdr->opcode].hdr_len) {
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
		dprint_mem_irq(DBG_RX, "Complete HDR received: ",
				(void *)&rctx->hdr, rctx->fpdu_part_rcvd,
				"(QP%d): ", RX_QPID(rctx));

		if (rctx->more_ddp_segs != 0) {
			rctx->first_ddp_seg = 0;
			if (rctx->prev_ddp_opcode != c_hdr->opcode) {
				dprint(DBG_ON,
				"packet intersection: %d <> %d\n",
				rctx->prev_ddp_opcode, c_hdr->opcode);
				return -EPROTO;
			}
		} else {
			rctx->prev_ddp_opcode = c_hdr->opcode;
			rctx->first_ddp_seg = 1;
		}
		rctx->more_ddp_segs = (c_hdr->l == 0) ? 1 : 0;

		return 0;
	}
	return -EAGAIN;
}

static inline int siw_fpdu_payload_len(struct siw_iwarp_rx *rctx)
{
	return ((int)(rctx->hdr.ctrl.mpa_len) - rctx->fpdu_part_rcvd)
		+ MPA_HDR_SIZE;
}

static inline int siw_fpdu_trailer_len(struct siw_iwarp_rx *rctx)
{
	int mpa_len = (int)rctx->hdr.ctrl.mpa_len + MPA_HDR_SIZE;

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
static void siw_rreq_complete(struct siw_qp *qp, int error)
{
	struct siw_wqe		*wqe = rx_wqe(qp);
	int			c_num = 1;
	enum ib_send_flags	flags;
	LIST_HEAD(c_list);

	if (!wqe) {
		WARN_ON(1);
		return;
	}
	if (!error)
		wqe->wc_status = IB_WC_SUCCESS;
	else if (wqe->wc_status == 0)
		wqe->wc_status = IB_WC_GENERAL_ERR; /* well... */

	wqe->wr_status = SR_WR_DONE;
	flags = wr_flags(wqe);

	list_add(&wqe->list, &c_list);

	spin_lock_bh(&qp->orq_lock);

	/* More WQE's to complete following this RREQ? */
	if (!list_empty(&qp->orq)) {
		struct list_head *pos, *n;
		list_for_each_safe(pos, n, &qp->orq) {
			wqe = list_entry_wqe(pos);
			if (wr_type(wqe) == SIW_WR_RDMA_READ_REQ)
				break;
			flags |= wr_flags(wqe);
			c_num++;
			dprint(DBG_WR|DBG_ON,
				"(QP%d): Resume completion, wr_type %d\n",
				QP_ID(qp), wr_type(wqe));
			list_move_tail(pos, &c_list);
		}
	}
	spin_unlock_bh(&qp->orq_lock);

	siw_sq_complete(&c_list, qp, c_num, flags);

	/*
	 * Check if SQ processing was stalled due to ORD limit
	 */
	if (ORD_SUSPEND_SQ(qp)) {
		spin_lock_bh(&qp->sq_lock);

		wqe = siw_next_tx_wqe(qp);

		if (wqe && !tx_wqe(qp)) {
			WARN_ON(wr_type(wqe) != SIW_WR_RDMA_READ_REQ);
			list_del_init(&wqe->list);
			tx_wqe(qp) = wqe;

			list_add_tail(&wqe->list, &qp->orq);

			spin_unlock_bh(&qp->sq_lock);

			dprint(DBG_RX|DBG_ON, "(QP%d): SQ resume\n",
				QP_ID(qp));

			siw_sq_queue_work(qp);
		} else {
			/* only new ORQ space if not next RREQ queued */
			atomic_inc(&qp->orq_space);
			spin_unlock_bh(&qp->sq_lock);
		}
	} else
		atomic_inc(&qp->orq_space);
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
	int rv = 0;

	switch (rctx->hdr.ctrl.opcode) {

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

		siw_rreq_complete(qp, 0);

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

	switch (rctx->hdr.ctrl.opcode) {

	case RDMAP_SEND_SE:
	case RDMAP_SEND:
		rctx->ddp_msn[RDMAP_UNTAGGED_QN_SEND]++;

		wqe = rx_wqe(qp);
		if (!wqe)
			return;

		if (rctx->hdr.ctrl.opcode == RDMAP_SEND_SE)
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

		siw_rreq_complete(qp, status);

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
	struct siw_iwarp_rx	*rctx = &qp->rx_info;
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
			QP_ID(qp), qp->rx_info.state, qp->attrs.state);
		return 0;
	}
	while (rctx->skb_new) {

		switch (rctx->state) {

		case SIW_GET_HDR:
			rv = siw_get_hdr(rctx);
			if (!rv) {
				if (rctx->crc_enabled)
					siw_crc_rxhdr(rctx);

				rctx->hdr.ctrl.mpa_len =
					ntohs(rctx->hdr.ctrl.mpa_len);

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

				if (!rctx->hdr.ctrl.l)
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

		if (rv != 0 && rv != -EAGAIN) {
			/*
			 * TODO: implement graceful error handling including
			 *       generation (and processing) of TERMINATE
			 *       messages.
			 *
			 *	 for now we are left with a bogus rx status
			 *	 unable to receive any further byte.
			 *	 BUT: code must handle difference between
			 *
			 * 	 o protocol syntax (FATAL, framing lost)
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

			siw_print_rctx(rctx);
			/*
			 * Calling siw_cm_queue_work() is safe without
			 * releasing qp->state_lock because the QP state
			 * will be transitioned to SIW_QP_STATE_ERROR
			 * by the siw_work_handler() workqueue handler
			 * after we return from siw_qp_llp_data_ready().
			 */
			siw_qp_cm_drop(qp, 1, 1);

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

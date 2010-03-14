/*
 * Software iWARP device driver for Linux
 *
 * Authors: Bernard Metzler <bmt@zurich.ibm.com>
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
#include "siw_tcp.h"
#include "siw_utils.h"


static inline void siw_crc_txhdr(struct siw_iwarp_tx *ctx)
{
	crypto_hash_init(&ctx->mpa_crc_hd);
	siw_crc_array(&ctx->mpa_crc_hd, (u8 *)&ctx->hdr,
			ctx->ctrl_len);
}

/*
 * siw_qp_prepare_tx()
 *
 * Prepare tx state for sending out one fpdu.
 * consider opcode specific routines (remove another redundant switch/case
 * statement for efficiency)
 */
static void siw_qp_prepare_tx(struct siw_iwarp_tx *c_tx)
{
	struct siw_wqe		*wqe = c_tx->wqe;
	enum rdma_opcode	op;

	dprint(DBG_TX, "(QP%d):\n", TX_QPID(c_tx));

	switch (wr_type(wqe)) {

	case SIW_WR_SEND:
	case SIW_WR_SEND_WITH_IMM:
		/*
		 * OFA does not support remote invalidation?
		 */
		op = (wr_flags(wqe) & IB_SEND_SOLICITED) ?
			RDMAP_SEND_SE : RDMAP_SEND;

		c_tx->hdr.send.ddp_qn = htonl(iwarp_pktinfo[op].ddp_qn);
		c_tx->hdr.send.ddp_msn =
			htonl(++c_tx->ddp_msn[RDMAP_UNTAGGED_QN_SEND]);
		c_tx->use_sendpage = 0;

		break;

	case SIW_WR_RDMA_WRITE:
	case SIW_WR_RDMA_WRITE_WITH_IMM:
		op = RDMAP_RDMA_WRITE;
		c_tx->hdr.rwrite.sink_stag = htonl(wqe->wr.write.rtag);
		c_tx->hdr.rwrite.sink_to = cpu_to_be64(wqe->wr.write.raddr);
		c_tx->use_sendpage = 0;

		break;

	case SIW_WR_RDMA_READ_REQ:
		op = RDMAP_RDMA_READ_REQ;
		c_tx->hdr.rreq.rsvd = 0;
		c_tx->hdr.rreq.ddp_qn = htonl(iwarp_pktinfo[op].ddp_qn);
		c_tx->hdr.rreq.ddp_msn =
			htonl(++c_tx->ddp_msn[RDMAP_UNTAGGED_QN_RDMA_READ]);
		c_tx->hdr.rreq.ddp_mo = 0;
		c_tx->hdr.rreq.sink_stag = htonl(wqe->wr.rread.sge[0].lkey);
		c_tx->hdr.rreq.sink_to =
			cpu_to_be64(wqe->wr.rread.sge[0].addr); /* abs addr! */
		c_tx->hdr.rreq.source_stag = htonl(wqe->wr.rread.rtag);
		c_tx->hdr.rreq.source_to = cpu_to_be64(wqe->wr.rread.raddr);
		c_tx->hdr.rreq.read_size = htonl(wqe->bytes); /* === sge len */
		c_tx->use_sendpage = 0;

		dprint(DBG_TX, ": RREQ: Sink: %d, 0x%016llx\n",
			wqe->wr.rread.sge[0].lkey, wqe->wr.rread.sge[0].addr);
		break;

	case SIW_WR_RDMA_READ_RESP:
		op = RDMAP_RDMA_READ_RESP;
		/* NBO */
		c_tx->hdr.rresp.sink_stag = wqe->wr.rresp.rtag;
		c_tx->hdr.rresp.sink_to = cpu_to_be64(wqe->wr.rresp.raddr);

		dprint(DBG_TX, ": RRESP: Sink: %d, 0x%016llx\n",
			wqe->wr.rresp.rtag, wqe->wr.rresp.raddr);
		break;

	default:
		dprint(DBG_ON, "Unsupported WQE type %d\n", wr_type(wqe));
		op = RDMAP_NOT_SUPPORTED;
		break;
	}
	/*
	 * Allow direct sending out of user buffer if WR is non signalled
	 * and payload is over threshold and no CRC is enabled.
	 * Per RDMA verbs, the  application should not change the send buffer
	 * until the work completed. In iWarp, work completion is only
	 * local delivery to TCP. TCP may reuse the buffer for 
	 * retransmission or may even did not yet sent the data. Changing
	 * unsent data also breaks the CRC, if applied.
	 */
	if (!(wr_flags(wqe) & IB_SEND_SIGNALED) &&
	    wqe->bytes > SENDPAGE_THRESH && !c_tx->crc_enabled)
		c_tx->use_sendpage = 1;
	else
		c_tx->use_sendpage = 0;
	c_tx->sge_idx = 0;
	c_tx->sge_off = 0;

	memcpy(&c_tx->hdr.ctrl, &iwarp_pktinfo[op].ctrl,
		sizeof(struct iwarp_ctrl));
}


static inline int siw_tx_hdr(struct siw_iwarp_tx *c_tx, struct socket *s)
{
	char	*buf = (char *)&c_tx->hdr;
	int	flags, len, rv;

	/* avoid blocking socket call and inform TCP of more to come */
	flags = MSG_DONTWAIT|MSG_MORE;
	len = c_tx->ctrl_len - c_tx->ctrl_sent;

	rv = ksock_send(s, buf + c_tx->ctrl_sent, len, flags);

	if (rv > 0)
		c_tx->ctrl_sent += rv;

	dprint(DBG_TX, " (QP%d): %d of %d sent (%d)\n",
		TX_QPID(c_tx), c_tx->ctrl_sent, len, rv);

	if (rv == len)
		return 0;

	return -EAGAIN;
}


static inline void siw_prepare_trailer(struct siw_iwarp_tx *c_tx)
{
	u32	crc_out;

	dprint(DBG_TX, "(QP%d):\n", TX_QPID(c_tx));

	c_tx->ctrl_len  = sizeof c_tx->trailer;
	c_tx->ctrl_sent = 4 - c_tx->pad;

	if (c_tx->crc_enabled) {
		if (c_tx->pad)
			siw_crc_array(&c_tx->mpa_crc_hd,
				      (u8 *)&c_tx->trailer.crc - c_tx->pad,
				      c_tx->pad);

		crypto_hash_final(&c_tx->mpa_crc_hd, (u8 *)&crc_out);

		/*
		 * CRC32 is computed, transmitted and received directly in NBO,
		 * so there's never a reason to convert byte order.
		 */
		c_tx->trailer.crc = crc_out;
	} else
		c_tx->trailer.crc = 0;
}

static inline int siw_tx_trailer(struct siw_iwarp_tx *c_tx, struct socket *s)
{
	char	*buf = (char *)&c_tx->trailer;
	int	rv, len, flags;

	dprint(DBG_TX, "(QP%d):\n", TX_QPID(c_tx));

	/*
	 * do not close TCP fragment if more frames will fit
	 */
	if (!c_tx->finish_tcpseg)
		flags = MSG_MORE|MSG_DONTWAIT;
	else
		flags = MSG_DONTWAIT;

	buf += c_tx->ctrl_sent;
	len = sizeof c_tx->trailer - c_tx->ctrl_sent;

	/*
	 * don't break sendpage usage for that packet
	 */
	if (c_tx->use_sendpage)
		rv = s->ops->sendpage(s, virt_to_page(buf),
				      (unsigned long int)buf & ~PAGE_MASK,
				      len, flags);
	else
		rv = ksock_send(s, buf, len, flags);

	if (rv >= 0) {
		c_tx->ctrl_sent += rv;
		dprint(DBG_TX, " (QP%d): %d remaining (%d sent)\n",
			TX_QPID(c_tx),
			(int)(sizeof c_tx->trailer - c_tx->ctrl_sent),
			rv);

		if (c_tx->ctrl_sent == sizeof c_tx->trailer)
			return 0;

		return -EAGAIN;
	}
	return rv;
}

static int siw_tx_data_inline(struct siw_iwarp_tx *c_tx, struct socket *s)
{
	struct siw_wqe	*wqe = c_tx->wqe;
	struct siw_sge	*sge = &wqe->wr.sgl.sge[0];

	int rv = ksock_send(s, sge->mem.buf + c_tx->sge_off, c_tx->ddp_payload,
			    MSG_MORE|MSG_DONTWAIT);

	if (rv > 0) {
		if (c_tx->crc_enabled)
			siw_crc_array(&c_tx->mpa_crc_hd,
				      sge->mem.buf + c_tx->sge_off, rv);

		c_tx->ddp_payload -= rv;
		c_tx->sge_off += rv;
		wqe->processed += rv;

		if (c_tx->ddp_payload > 0)
			return -EAGAIN;
		else
			return 0;
	}
	return rv;
}

/*
 * siw_tx_data()
 *
 * Transmit set of pages out of SGL referenced by transmit context.
 */
static int siw_tx_data(struct siw_iwarp_tx *c_tx, struct socket *s)
{
	struct siw_wqe		*wqe = c_tx->wqe;
	struct siw_sge		*sge = &wqe->wr.sgl.sge[c_tx->sge_idx];
	struct siw_mr		*mr = siw_mem2mr(sge->mem.obj);
	struct ib_umem_chunk 	*chunk = c_tx->umem_chunk;

	struct scatterlist	*p_list;
	int			pg_off,	/* Page offset within page to send */
				bytes,
				rv = 0;

	dprint(DBG_TX, "(QP%d):\n", TX_QPID(c_tx));

	pg_off = (sge->addr + c_tx->sge_off) & ~PAGE_MASK;

	while (c_tx->ddp_payload) {
		p_list =  &chunk->page_list[c_tx->pg_idx];
		bytes = min(c_tx->ddp_payload, (int)PAGE_SIZE - pg_off);
		bytes = min(bytes, (int)sge->len);

		dprint(DBG_TX, "(QP%d): "
			"MR Base: 0x%016llx UMEM Off: %llu\n", TX_QPID(c_tx),
			(unsigned long long)mr->mem.va,
			(unsigned long long)mr->umem->offset);
		dprint(DBG_TX, "(QP%d): PAGE idx: %d "
			"SGE idx: %d SGE off: %u Bytes: %d\n",
			TX_QPID(c_tx), c_tx->pg_idx, c_tx->sge_idx,
			c_tx->sge_off, bytes);

		if (c_tx->use_sendpage)
			rv = s->ops->sendpage(s, sg_page(p_list), pg_off,
					      bytes, MSG_MORE|MSG_DONTWAIT);
		else
			rv = sock_no_sendpage(s, sg_page(p_list), pg_off,
					      bytes, MSG_MORE|MSG_DONTWAIT);

		if (rv > 0) {
			c_tx->ddp_payload -= rv;
			wqe->processed += rv;

			/* update MPA CRC computation */
			if (c_tx->crc_enabled)
				siw_crc_sg(&c_tx->mpa_crc_hd, p_list,
					     pg_off, rv);

			/* Update memory reference only if more to send */
			if (wqe->processed < wqe->bytes) {
				if (c_tx->sge_off + rv == sge->len) {
					/*
					 * SGE ends
					 */
					c_tx->sge_idx++;
					c_tx->sge_off = 0;
					sge++;

					mr = siw_mem2mr(sge->mem.obj);

					chunk = siw_qp_umem_chunk_get(mr,
							sge->addr,
							&c_tx->pg_idx);
					if (!chunk)
						return -EINVAL;

					pg_off = sge->addr & ~PAGE_MASK;

				} else if (pg_off + rv == PAGE_SIZE) {
					/*
					 * Page ends
					 */
					if (++c_tx->pg_idx == chunk->nents) {
						/*
						 * End of chunk, too
						 */
						c_tx->pg_idx = 0;
						chunk =
						    ib_umem_chunk_next(chunk);
					}
					c_tx->sge_off += rv;
					pg_off = 0;

				} else  {
					/*
					 * Within same page and SGE
					 */
					pg_off += rv;
					c_tx->sge_off += rv;
				}
			}
			if (rv != bytes) {
				/*
				 * sent some but not all requested bytes out
				 * of current page: socket queue full.
				 */
				dprint(DBG_TX, "(QP%d): todo=%d, sent=%d\n",
					TX_QPID(c_tx), bytes, rv);
				rv = -EAGAIN;
				break;
			}
			rv = 0;
		} else {
			if (rv == 0)
				rv = -EAGAIN;
			break;
		}
	}
	/*
	 * Store current chunk pointer in transmit context
	 */
	c_tx->umem_chunk = chunk;

	return rv;
}


/*
 * siw_unseg_txlen()
 *
 * Compute complete tcp payload len if packet would not
 * get fragmented
 */
static inline int siw_unseg_txlen(struct siw_iwarp_tx *c_tx)
{
	int pad = c_tx->ddp_payload ? -c_tx->ddp_payload & 0x3 : 0;

	return c_tx->ddp_payload + c_tx->ctrl_len + pad + MPA_CRC_SIZE;
}


/*
 * siw_prepare_fpdu()
 *
 * Prepares transmit context to send out one FPDU.
 * Checks and locks involved memory segments of data to be sent.
 * Computes maximum FPDU length to fill up TCP MSS if possible.
 *
 * @qp:		QP from which to transmit
 * @wqe:	Current WQE causing transmission
 * @ddp_start:	1, if first DDP segement
 *
 * TODO: Take into account real available sendspace on socket
 *       to avoid header misalignment due to send pausing within
 *       fpdu transmission
 */
int siw_prepare_fpdu(struct siw_qp *qp, struct siw_wqe *wqe,
		     int ddp_start)
{
	struct siw_iwarp_tx	*c_tx  = &qp->tx_info;
	struct socket		*s = qp->attrs.llp_stream_handle;
	int			rreq_len,
				rv;

	dprint(DBG_TX, "(QP%d)\n", QP_ID(qp));

	/*
	 * TODO: TCP Fragmentation dynamics needs for further investigation.
	 * 	 Resuming SQ processing may start with full-sized packet
	 *	 or short packet which resets MSG_MORE and thus helps
	 *	 to synchronize.
	 *	 This version resmues with short packet.
	 */
	if (wr_type(wqe) == SIW_WR_RDMA_READ_REQ)
		rreq_len = sizeof(struct iwarp_rdma_rreq) + MPA_CRC_SIZE;
	else
		rreq_len = 0;

	c_tx->ctrl_len = iwarp_pktinfo[c_tx->hdr.ctrl.opcode].hdr_len;
	c_tx->ctrl_sent = 0;

	/*
	 * Update target buffer offset if any
	 */
	if (!c_tx->hdr.ctrl.t) {
		/* Untagged message */
		c_tx->hdr.c_untagged.ddp_mo = cpu_to_be32(wqe->processed);

		if (rreq_len)
			c_tx->hdr.rreq.sink_to =
				cpu_to_be64(wqe->wr.sgl.sge[0].addr);
	} else {
		/* Tagged message */
		if (wr_type(wqe) == SIW_WR_RDMA_READ_RESP) {
			c_tx->hdr.c_tagged.ddp_to =
			    cpu_to_be64(wqe->wr.rresp.raddr + wqe->processed);
		} else {
			c_tx->hdr.c_tagged.ddp_to =
			    cpu_to_be64(wqe->wr.write.raddr + wqe->processed);
		}
	}
	if (!s->sk->sk_wmem_queued)
		c_tx->tcp_seglen = get_tcp_mss(s->sk);

	if (rreq_len) {
		c_tx->tcp_seglen -= rreq_len;
		c_tx->ddp_payload = 0;
	} else {
		/* First guess: one big unsegmented DDP segment */
		c_tx->ddp_payload = wqe->bytes - wqe->processed;
		c_tx->tcp_seglen -= siw_unseg_txlen(c_tx);
	}
	if (c_tx->tcp_seglen >= 0) {
		/* Whole DDP segment fits into current TCP segment */
		c_tx->hdr.ctrl.l = 1;
	} else {
		/* Trim DDP payload to fit into current TCP segment */
		c_tx->ddp_payload += c_tx->tcp_seglen;
		c_tx->hdr.ctrl.l = 0;
	}
	c_tx->pad = -c_tx->ddp_payload & 0x3;

	if (c_tx->tcp_seglen < (int)MPA_MIN_FRAG || c_tx->use_sendpage ||
		(TX_QUEUE_EMPTY(qp) && c_tx->hdr.ctrl.l == 1)) {
		/*
		 * End current TCP segment with this DDP segment, since
		 * 1. not much space left in current TCP segment, or
		 * 2. probably not more to send within this SQ run
		 *    NOTE: User may push further WQEs simultaneously
		 * 3. sendpage gets used in the current segment
		 *
		 * may get refined with checking next wqe's
		 * wire length which may be within MPA_MIN_FRAG
		 */
		c_tx->finish_tcpseg = 1;
		c_tx->tcp_seglen = get_tcp_mss(s->sk);
	} else  {
		c_tx->finish_tcpseg = 0;
		/* Sub any padding from remaining TCP segment space */
		c_tx->tcp_seglen -= c_tx->pad;
	}
	c_tx->hdr.ctrl.mpa_len =
		htons(c_tx->ctrl_len + c_tx->ddp_payload - MPA_HDR_SIZE);
	/*
	 * Init MPA CRC computation
	 */
	if (c_tx->crc_enabled)
		siw_crc_txhdr(c_tx);

	if (c_tx->ddp_payload && !SIW_INLINED_DATA(wqe)) {
		struct siw_sge	*sge = &wqe->wr.sgl.sge[c_tx->sge_idx];
		/*
		 * Reference memory to be tx'd
		 */
		BUG_ON(c_tx->sge_idx > wqe->wr.sgl.num_sge - 1);

		if (wr_type(wqe) != SIW_WR_RDMA_READ_RESP)
			rv = siw_check_sgl(qp->pd, sge, SR_MEM_LREAD,
					   c_tx->sge_off, c_tx->ddp_payload);
		else
			rv = siw_check_sge(qp->pd, sge, SR_MEM_RREAD,
					   c_tx->sge_off, c_tx->ddp_payload);
		if (rv)
			return rv;
		/*
		 * Initialize memory tx pointers
		 */
		if (ddp_start) {
			c_tx->umem_chunk =
				siw_qp_umem_chunk_get(siw_mem2mr(sge->mem.obj),
						      sge->addr,
						      &c_tx->pg_idx);

			if (c_tx->umem_chunk == NULL)
				return -EINVAL;

			c_tx->sge_idx = 0;
			c_tx->sge_off = 0;
		}
	}
	return 0;
}

/*
 * siw_qp_sq_proc_tx()
 *
 * Process one WQE which needs transmission on the wire.
 * Return with:
 *	-EAGAIN, if handover to tcp remained incomplete
 *	0,	 if handover to tcp complete
 *	< 0,	 if other errors happend.
 *
 * @qp:		QP to send from
 * @wqe:	WQE causing transmission
 */
static int siw_qp_sq_proc_tx(struct siw_qp *qp, struct siw_wqe *wqe)
{
	struct siw_iwarp_tx	*c_tx = &qp->tx_info;
	struct socket	 	*s = qp->attrs.llp_stream_handle;
	int			rv = 0;

	if (wqe->wr_status == SR_WR_QUEUED) {
		if (c_tx->tx_suspend)
			return -EPIPE;

		siw_qp_prepare_tx(&qp->tx_info);

		wqe->wr_status = SR_WR_INPROGRESS;
		c_tx->state = SIW_SEND_HDR;

		rv = siw_prepare_fpdu(qp, wqe, 1);
		if (rv)
			return rv;
	}
next_segment:

	switch (c_tx->state) {

	case SIW_SEND_HDR:
		rv = siw_tx_hdr(c_tx, s);
		if (rv)
			break;

		if (c_tx->ddp_payload) {
			if (likely(!SIW_INLINED_DATA(wqe)))
				rv = siw_tx_data(c_tx, s);
			else
				rv = siw_tx_data_inline(c_tx, s);
			if (rv) {
				c_tx->state = SIW_SEND_DATA;
				break;
			}
		}
		c_tx->state = SIW_SEND_TRAILER;
		siw_prepare_trailer(c_tx);
		rv = siw_tx_trailer(c_tx, s);

		break;

	case SIW_SEND_DATA:
		if (likely(!SIW_INLINED_DATA(wqe)))
			rv = siw_tx_data(c_tx, s);
		else
			rv = siw_tx_data_inline(c_tx, s);
		if (rv)
			break;

		c_tx->state = SIW_SEND_TRAILER;
		siw_prepare_trailer(c_tx);
		/*
		 * fall through to sendig trailer
		 */
	case SIW_SEND_TRAILER:
		rv = siw_tx_trailer(c_tx, s);

		break;
	}
	if (c_tx->state == SIW_SEND_TRAILER && rv >= 0) {
		/*
		 * One segment sent. Processing completed if last segment.
		 * Do next segment otherwise. Stop if tx error.
		 */
		if (c_tx->hdr.ctrl.l == 1) {
			dprint(DBG_TX, "(QP%d): WR completed\n", QP_ID(qp));
			return 0;
		}
		/* Verbs, 6.4.: Try stopping sending after a full DDP segment
		 * if the connection goes down (== peer halfclose)
		 */
		if (c_tx->tx_suspend)
			return -EPIPE;

		c_tx->state = SIW_SEND_HDR;

		rv = siw_prepare_fpdu(qp, wqe, 0);
		if (!rv)
			goto next_segment;
	}
	return rv;
}


/*
 * siw_wqe_sq_processed()
 *
 * Called after WQE processing completed.
 * If WQE is not of signalled typ, it can be released.
 * If the ORQ is empty, a signalled WQE is attached to the CQ.
 * Otherwise, it is appended to the end of the ORQ for later
 * completion. To keep WQE ordering, the ORQ is always consumed FIFO.
 */
static void siw_wqe_sq_processed(struct siw_wqe *wqe, struct siw_qp *qp)
{
	LIST_HEAD(c_list);

	if (!(wr_flags(wqe) & IB_SEND_SIGNALED)) {
		atomic_inc(&qp->sq_space);
		siw_wqe_put(wqe);
		return;
	}
	spin_lock_bh(&qp->orq_lock);

	if (ORQ_EMPTY(qp)) {
		spin_unlock_bh(&qp->orq_lock);
		dprint(DBG_WR|DBG_TX,
			"(QP%d): Immediate completion, wr_type %d\n",
			QP_ID(qp), wr_type(wqe));
		list_add_tail(&wqe->list, &c_list);
		siw_sq_complete(&c_list, qp, 1, wr_flags(wqe));
	} else {
		list_add_tail(&wqe->list, &qp->orq);
		spin_unlock_bh(&qp->orq_lock);
		dprint(DBG_WR|DBG_TX|DBG_ON,
			"(QP%d): Defer completion, wr_type %d\n",
			QP_ID(qp), wr_type(wqe));
	}
}

int siw_qp_sq_proc_local(struct siw_qp *qp, struct siw_wqe *wqe)
{
	printk(KERN_ERR "local WR's not yet implemented\n");
	BUG();
	return 0;
}


/*
 * siw_qp_sq_process()
 *
 * Core TX path routine for RDMAP/DDP/MPA using a TCP kernel socket.
 * Sends RDMAP payload for the current SQ WR @wqe of @qp in one or more
 * MPA FPDUs, each containing a DDP segment.
 *
 * SQ processing may occur in user context as a result of posting
 * new WQE's or from siw_sq_work_handler() context.
 *
 * SQ processing may get paused anytime, possibly in the middle of a WR
 * or FPDU, if insufficient send space is available. SQ processing
 * gets resumed from siw_sq_work_handler(), if send space becomes
 * available again.
 *
 * Must be called with the QP state read-locked.
 *
 * TODO:
 * To be solved more seriously: an outbound RREQ can be satisfied
 * by the corresponding RRESP _before_ it gets assigned to the ORQ.
 * This happens regularly in RDMA READ via loopback case. Since both
 * outbound RREQ and inbound RRESP can be handled by the same CPU
 * locking the ORQ is dead-lock prone and thus not an option.
 * Tentatively, the RREQ gets assigned to the ORQ _before_ being
 * sent (and pulled back in case of send failure).
 */
int siw_qp_sq_process(struct siw_qp *qp, int user_ctx)
{
	struct siw_wqe		*wqe;
	enum siw_wr_opcode	tx_type;
	int			rv;

	dprint(DBG_WR|DBG_TX, "(QP%d): Enter\n", QP_ID(qp));

	rv = atomic_inc_return(&qp->tx_info.in_use);
	if (rv != 1) {
		dprint(DBG_WR|DBG_TX|DBG_ON,
			"(QP%d): SQ concurrency 1 (%d)\n", QP_ID(qp), user_ctx);
		return 0;
	}

	wqe = tx_wqe(qp);

	BUG_ON(wqe == NULL);

next_wqe:
	if (qp->tx_info.tx_suspend) {
		dprint(DBG_WR|DBG_TX, "(QP%d): tx suspend\n", QP_ID(qp));
		return -ECONNRESET;
	}
	tx_type = wr_type(wqe);

	dprint(DBG_WR|DBG_TX,
		" QP(%d): WR type %d, state %d, data %u, sent %u, id %llu\n",
		QP_ID(qp), wr_type(wqe), wqe->wr_status, wqe->bytes,
		wqe->processed, (unsigned long long)wr_id(wqe));

	if (SIW_WQE_IS_TX(wqe))
		rv = siw_qp_sq_proc_tx(qp, wqe);
	else
		rv = siw_qp_sq_proc_local(qp, wqe);

	if (!rv) {
		/*
		 * WQE processing done
		 */
		switch (tx_type) {

		case SIW_WR_SEND:
		case SIW_WR_RDMA_WRITE:

			wqe->wc_status = IB_WC_SUCCESS;
			wqe->wr_status = SR_WR_DONE;
			siw_wqe_sq_processed(wqe, qp);
			break;

		case SIW_WR_RDMA_READ_REQ:
			/*
			 * already enqueued to ORQ queue
			 */
			break;

		case SIW_WR_RDMA_READ_RESP:
			/*
			 * silently recyclye wqe
			 */
			/* XXX DEBUG AID, please remove */
			wqe->wr_status = SR_WR_DONE;
			siw_wqe_put(wqe);
			break;
		default:
			BUG();
		}
		spin_lock_bh(&qp->sq_lock);

		wqe = siw_next_tx_wqe(qp);
		if (!wqe) {
			tx_wqe(qp) = NULL;
			rv = atomic_dec_return(&qp->tx_info.in_use);
			if (rv != 0) {
				dprint(DBG_WR|DBG_TX|DBG_ON,
					"(QP%d): SQ concurrency 2 (%d)\n",
					QP_ID(qp), user_ctx);
				atomic_dec(&qp->tx_info.in_use);
			}
			spin_unlock_bh(&qp->sq_lock);
			return 0;
		}
		if (wr_type(wqe) == SIW_WR_RDMA_READ_REQ) {
			if (ORD_SUSPEND_SQ(qp)) {
				tx_wqe(qp) = NULL;
				if (!atomic_dec_and_test(&qp->tx_info.in_use))
					atomic_dec(&qp->tx_info.in_use);
				spin_unlock_bh(&qp->sq_lock);
				dprint(DBG_WR|DBG_TX|DBG_ON,
					" QP%d PAUSE SQ: ORD limit\n",
					QP_ID(qp));
				return 0;
			} else {
				tx_wqe(qp) = wqe;
				siw_rreq_queue(wqe, qp);
			}
		} else  {
			list_del_init(&wqe->list);
			tx_wqe(qp) = wqe;
		}
		spin_unlock_bh(&qp->sq_lock);

		goto next_wqe;

	} else if (rv == -EAGAIN) {
		dprint(DBG_WR|DBG_TX,
			"(QP%d): SQ paused: hd/tr %d of %d, data %d\n",
			QP_ID(qp), qp->tx_info.ctrl_sent, qp->tx_info.ctrl_len,
			qp->tx_info.ddp_payload);

		if (!atomic_dec_and_test(&qp->tx_info.in_use)) {
			dprint(DBG_WR|DBG_TX|DBG_ON,
				"(QP%d): SQ concurrency 3 (%d)\n",
				QP_ID(qp), user_ctx);
			goto next_wqe;
		}
		return 0;
	} else {
		/*
		 * WQE processing failed.
		 * Verbs 8.3.2:
		 * o It turns any WQE into a signalled WQE.
		 * o Local catastrophic error must be surfaced
		 * o QP must be moved into Terminate state: done by code
		 *   doing socket state change processing
		 *
		 * o TODO: Termination message must be sent.
		 * o TODO: Implement more precise work completion errors,
		 *         see enum ib_wc_status in ib_verbs.h
		 */

		spin_lock_bh(&qp->sq_lock);
		/*
		 * RREQ may have already been completed by inbound RRESP!
		 */
		if (tx_type == RDMAP_RDMA_READ_REQ) {
			spin_lock(&qp->orq_lock);
			if (!ORQ_EMPTY(qp) &&
			    wqe == list_entry_wqe(qp->orq.prev)) {
				/*
				 * wqe still on the ORQ
				 * TODO: fix a potential race condition if the
				 * rx path is currently referencing the wqe(!)
				 */
				dprint(DBG_ON, "(QP%d): Bad RREQ in ORQ\n",
					QP_ID(qp));
				list_del_init(&wqe->list);
				spin_unlock(&qp->orq_lock);
			} else {
				/*
				 * already completed by inbound RRESP
				 */
				dprint(DBG_ON,
					"(QP%d): Bad RREQ already Completed\n",
					QP_ID(qp));
				spin_unlock(&qp->orq_lock);
				tx_wqe(qp) = NULL;
				spin_unlock_bh(&qp->sq_lock);
				if (!atomic_dec_and_test(&qp->tx_info.in_use)) {
					dprint(DBG_WR|DBG_TX|DBG_ON,
						"(QP%d): "
						"SQ concurrency 4 (%d)\n",
						QP_ID(qp), user_ctx);
					atomic_dec(&qp->tx_info.in_use);
				}
				return rv;
			}
		}
		tx_wqe(qp) = NULL;
		spin_unlock_bh(&qp->sq_lock);
		/*
		 * immediately suspends further TX processing
		 */
		if (!qp->tx_info.tx_suspend)
			siw_qp_cm_drop(qp, 0, 1);

		switch (tx_type) {

		case SIW_WR_SEND:
		case SIW_WR_RDMA_WRITE:
		case SIW_WR_RDMA_READ_REQ:
			wqe->wr_status = SR_WR_DONE;
			wqe->wc_status = IB_WC_LOC_QP_OP_ERR;
			wqe->error = rv;
			wr_flags(wqe) |= IB_SEND_SIGNALED;
			if (tx_type != SIW_WR_RDMA_READ_REQ)
				/*
				 * RREQ already enqueued to ORQ queue
				 */
				siw_wqe_sq_processed(wqe, qp);

			siw_async_ev(qp, NULL, IB_EVENT_QP_FATAL);

			break;

		case SIW_WR_RDMA_READ_RESP:
			/*
			 * Recyclye wqe
			 */
			dprint(DBG_WR|DBG_TX|DBG_ON, "(QP%d): "
				   "Processing RRESPONSE failed with %d\n",
				    QP_ID(qp), rv);

			siw_async_ev(qp, NULL, IB_EVENT_QP_REQ_ERR);

			siw_wqe_put(wqe);
			break;

		default:
			BUG();
		}
	}
	if (!atomic_dec_and_test(&qp->tx_info.in_use)) {
		dprint(DBG_WR|DBG_TX|DBG_ON, "(QP%d): "
			"SQ concurrency 5 (%d)\n", QP_ID(qp), user_ctx);
		atomic_dec(&qp->tx_info.in_use);
	}
	return rv;
}

static struct workqueue_struct *siw_sq_wq;

int __init siw_sq_worker_init(void)
{
	siw_sq_wq = create_workqueue("siw_sq_wq");
	if (!siw_sq_wq)
		return -ENOMEM;

	dprint(DBG_TX|DBG_OBJ, " Init WQ\n");
	return 0;
}


void __exit siw_sq_worker_exit(void)
{
	dprint(DBG_TX|DBG_OBJ, " Destroy WQ\n");
	if (siw_sq_wq) {
		flush_workqueue(siw_sq_wq);
		destroy_workqueue(siw_sq_wq);
	}
}


/*
 * siw_sq_work_handler()
 *
 * Scheduled by siw_qp_llp_write_space() socket callback if socket
 * send space became available again. This function resumes SQ
 * processing.
 */
static void siw_sq_work_handler(struct work_struct *w)
{
	struct siw_sq_work	*this_work;
	struct siw_qp		*qp;
	int			rv;

	this_work = container_of(w, struct siw_sq_work, work);
	qp = this_work->qp;

	dprint(DBG_TX|DBG_OBJ, "(QP%d)\n", QP_ID(qp));

	/*
	 * This work is currently being executed. Another parallel
	 * work scheduling attempt must schedule the other work item.
	 * This is safe since the other item can be scheduled only
	 * from executing our work which will be done next.
	 */
	qp->sq_work = this_work;

	if (down_read_trylock(&qp->state_lock)) {
		if (qp->attrs.state == SIW_QP_STATE_RTS &&
			qp->tx_info.tx_suspend == 0) {

			rv = siw_qp_sq_process(qp, 0);
			up_read(&qp->state_lock);

			if (rv < 0) {
				dprint(DBG_ON|DBG_TX, "(QP%d): failed: %d\n",
					QP_ID(qp), rv);

				if (!qp->tx_info.tx_suspend)
					siw_qp_cm_drop(qp, 0, 1);
			}
		} else {
			dprint(DBG_ON|DBG_TX, "(QP%d): state: %d %d\n",
				QP_ID(qp), qp->attrs.state,
					qp->tx_info.tx_suspend);
			up_read(&qp->state_lock);
		}
	} else {
		dprint(DBG_ON|DBG_TX, "(QP%d): QP locked\n", QP_ID(qp));
	}
	siw_qp_put(qp);
}


void siw_sq_queue_work(struct siw_qp *qp)
{
	struct siw_sq_work	*new_work;

	dprint(DBG_TX|DBG_OBJ, "(QP%d)\n", QP_ID(qp));

	if (!tx_wqe(qp)) {
		WARN_ON(1);
		return;
	}
	siw_qp_get(qp);

	/*
	 * Take the free work item to schedule our work since
	 * we can be within executing the other work item.
	 */
	new_work = (qp->sq_work == &qp->work1) ? &qp->work2 : &qp->work1;

	INIT_WORK(&new_work->work, siw_sq_work_handler);

	qp->sq_work = new_work;

	/*
	 * TODO: To improve locality, shall we schedule the work
	 *       on a certain CPU - given the unknown SQ content...?
	 */
#ifdef TX_FROM_APPL_CPU
	queue_work_on(qp->cpu, siw_sq_wq, &new_work->work);
#else
	queue_work(siw_sq_wq, &new_work->work);
#endif
}

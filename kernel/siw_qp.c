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
#include <linux/file.h>
#include <linux/scatterlist.h>
#include <linux/highmem.h>
#include <linux/vmalloc.h>
#include <asm/barrier.h>
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


#if DPRINT_MASK > 0
static char siw_qp_state_to_string[SIW_QP_STATE_COUNT][sizeof "TERMINATE"] = {
	[SIW_QP_STATE_IDLE]		= "IDLE",
	[SIW_QP_STATE_RTR]		= "RTR",
	[SIW_QP_STATE_RTS]		= "RTS",
	[SIW_QP_STATE_CLOSING]		= "CLOSING",
	[SIW_QP_STATE_TERMINATE]	= "TERMINATE",
	[SIW_QP_STATE_ERROR]		= "ERROR",
	[SIW_QP_STATE_MORIBUND]		= "MORIBUND",
	[SIW_QP_STATE_UNDEF]		= "UNDEF"
};
#endif

/*
 * iWARP (RDMAP, DDP and MPA) parameters as well as Softiwarp settings on a
 * per-RDMAP message basis. Please keep order of initializer. All MPA len
 * is initialized to minimum packet size.
 */
struct iwarp_msg_info iwarp_pktinfo[RDMAP_TERMINATE + 1] = { {
	/* RDMAP_RDMA_WRITE */
	.hdr_len = sizeof(struct iwarp_rdma_write),
	.ctrl.mpa_len = htons(sizeof(struct iwarp_rdma_write) - 2),
	.ctrl.ddp_rdmap_ctrl = DDP_FLAG_TAGGED | DDP_FLAG_LAST
		| cpu_to_be16(DDP_VERSION << 8)
		| cpu_to_be16(RDMAP_VERSION << 6)
		| cpu_to_be16(RDMAP_RDMA_WRITE),
	.proc_data = siw_proc_write
},
{	/* RDMAP_RDMA_READ_REQ */
	.hdr_len = sizeof(struct iwarp_rdma_rreq),
	.ctrl.mpa_len = htons(sizeof(struct iwarp_rdma_rreq) - 2),
	.ctrl.ddp_rdmap_ctrl = DDP_FLAG_LAST
		| cpu_to_be16(DDP_VERSION << 8)
		| cpu_to_be16(RDMAP_VERSION << 6)
		| cpu_to_be16(RDMAP_RDMA_READ_REQ),
	.proc_data = siw_proc_rreq
},
{	/* RDMAP_RDMA_READ_RESP */
	.hdr_len = sizeof(struct iwarp_rdma_rresp),
	.ctrl.mpa_len = htons(sizeof(struct iwarp_rdma_rresp) - 2),
	.ctrl.ddp_rdmap_ctrl = DDP_FLAG_TAGGED | DDP_FLAG_LAST
		| cpu_to_be16(DDP_VERSION << 8)
		| cpu_to_be16(RDMAP_VERSION << 6)
		| cpu_to_be16(RDMAP_RDMA_READ_RESP),
	.proc_data = siw_proc_rresp
},
{	/* RDMAP_SEND */
	.hdr_len = sizeof(struct iwarp_send),
	.ctrl.mpa_len = htons(sizeof(struct iwarp_send) - 2),
	.ctrl.ddp_rdmap_ctrl = DDP_FLAG_LAST
		| cpu_to_be16(DDP_VERSION << 8)
		| cpu_to_be16(RDMAP_VERSION << 6)
		| cpu_to_be16(RDMAP_SEND),
	.proc_data = siw_proc_send
},
{	/* RDMAP_SEND_INVAL */
	.hdr_len = sizeof(struct iwarp_send_inv),
	.ctrl.mpa_len = htons(sizeof(struct iwarp_send_inv) - 2),
	.ctrl.ddp_rdmap_ctrl = DDP_FLAG_LAST
		| cpu_to_be16(DDP_VERSION << 8)
		| cpu_to_be16(RDMAP_VERSION << 6)
		| cpu_to_be16(RDMAP_SEND_INVAL),
	.proc_data = siw_proc_send
},
{	/* RDMAP_SEND_SE */
	.hdr_len = sizeof(struct iwarp_send),
	.ctrl.mpa_len = htons(sizeof(struct iwarp_send) - 2),
	.ctrl.ddp_rdmap_ctrl = DDP_FLAG_LAST
		| cpu_to_be16(DDP_VERSION << 8)
		| cpu_to_be16(RDMAP_VERSION << 6)
		| cpu_to_be16(RDMAP_SEND_SE),
	.proc_data = siw_proc_send
},
{	/* RDMAP_SEND_SE_INVAL */
	.hdr_len = sizeof(struct iwarp_send_inv),
	.ctrl.mpa_len = htons(sizeof(struct iwarp_send_inv) - 2),
	.ctrl.ddp_rdmap_ctrl = DDP_FLAG_LAST
		| cpu_to_be16(DDP_VERSION << 8)
		| cpu_to_be16(RDMAP_VERSION << 6)
		| cpu_to_be16(RDMAP_SEND_SE_INVAL),
	.proc_data = siw_proc_send
},
{	/* RDMAP_TERMINATE */
	.hdr_len = sizeof(struct iwarp_terminate),
	.ctrl.mpa_len = htons(sizeof(struct iwarp_terminate) - 2),
	.ctrl.ddp_rdmap_ctrl = DDP_FLAG_LAST
		| cpu_to_be16(DDP_VERSION << 8)
		| cpu_to_be16(RDMAP_VERSION << 6)
		| cpu_to_be16(RDMAP_TERMINATE),
	.proc_data = siw_proc_terminate
} };

void siw_qp_llp_data_ready(struct sock *sk)
{
	struct siw_qp		*qp;

	read_lock(&sk->sk_callback_lock);

	if (unlikely(!sk->sk_user_data || !sk_to_qp(sk))) {
		dprint(DBG_ON, " No QP: %p\n", sk->sk_user_data);
		goto done;
	}
	qp = sk_to_qp(sk);

	if (likely(!qp->rx_ctx.rx_suspend &&
		   down_read_trylock(&qp->state_lock))) {
		read_descriptor_t rd_desc = {.arg.data = qp, .count = 1};

		dprint(DBG_SK|DBG_RX, "(QP%d): state (before read_sock)=%d\n",
			QP_ID(qp), qp->attrs.state);

		if (likely(qp->attrs.state == SIW_QP_STATE_RTS))
			/*
			 * Implements data receive operation during
			 * socket callback. TCP gracefully catches
			 * the case where there is nothing to receive
			 * (not calling siw_tcp_rx_data() then).
			 */
			tcp_read_sock(sk, &rd_desc, siw_tcp_rx_data);

		dprint(DBG_SK|DBG_RX, "(QP%d): state (after read_sock)=%d\n",
			QP_ID(qp), qp->attrs.state);

		up_read(&qp->state_lock);
	} else {
		dprint(DBG_SK|DBG_RX, "(QP%d): Unable to RX: rx_suspend: %d\n",
			QP_ID(qp), qp->rx_ctx.rx_suspend);
	}
done:
	read_unlock(&sk->sk_callback_lock);
}


void siw_qp_llp_close(struct siw_qp *qp)
{
	dprint(DBG_CM, "(QP%d): Enter: SIW QP state = %s, cep=0x%p\n",
		QP_ID(qp), siw_qp_state_to_string[qp->attrs.state],
		qp->cep);

	down_write(&qp->state_lock);

	dprint(DBG_CM, "(QP%d): state locked\n", QP_ID(qp));

	qp->rx_ctx.rx_suspend = 1;
	qp->tx_ctx.tx_suspend = 1;
	qp->attrs.llp_stream_handle = NULL;

	switch (qp->attrs.state) {

	case SIW_QP_STATE_RTS:
	case SIW_QP_STATE_RTR:
	case SIW_QP_STATE_IDLE:
	case SIW_QP_STATE_TERMINATE:

		qp->attrs.state = SIW_QP_STATE_ERROR;

		break;
	/*
	 * SIW_QP_STATE_CLOSING:
	 *
	 * This is a forced close. shall the QP be moved to
	 * ERROR or IDLE ?
	 */
	case SIW_QP_STATE_CLOSING:
		if (tx_wqe(qp)->wr_status == SR_WR_IDLE)
			qp->attrs.state = SIW_QP_STATE_ERROR;
		else
			qp->attrs.state = SIW_QP_STATE_IDLE;

		break;

	default:
		dprint(DBG_CM, " No state transition needed: %d\n",
			qp->attrs.state);
		break;
	}
	siw_sq_flush(qp);
	siw_rq_flush(qp);

	/*
	 * dereference closing CEP
	 */
	if (qp->cep) {
		siw_cep_put(qp->cep);
		qp->cep = NULL;
	}

	up_write(&qp->state_lock);
	dprint(DBG_CM, "(QP%d): Exit: SIW QP state = %s, cep=0x%p\n",
		QP_ID(qp), siw_qp_state_to_string[qp->attrs.state],
		qp->cep);
}


/*
 * socket callback routine informing about newly available send space.
 * Function schedules SQ work for processing SQ items.
 */
void siw_qp_llp_write_space(struct sock *sk)
{
	struct siw_cep	*cep = sk_to_cep(sk);

	/*
	 * TODO:
	 * Resemble sk_stream_write_space() logic for iWARP constraints:
	 * Clear SOCK_NOSPACE only if sendspace may hold some reasonable
	 * sized FPDU.
	 */
#ifdef SIW_TX_FULLSEGS
	struct socket *sock = sk->sk_socket;

	if (sk_stream_wspace(sk) >= (int)cep->qp.tx_ctx.fpdu_len && sock) {
		clear_bit(SOCK_NOSPACE, &sock->flags);
		siw_sq_start(cep->qp);
	}
#else
	cep->sk_write_space(sk);

	if (!test_bit(SOCK_NOSPACE, &sk->sk_socket->flags))
		siw_sq_start(cep->qp);
#endif
}

static int siw_qp_readq_init(struct siw_qp *qp, int irq_size, int orq_size)
{
	dprint(DBG_CM|DBG_WR, "(QP%d): %d %d\n", QP_ID(qp), irq_size, orq_size);

	if (!irq_size)
		irq_size = 1;
	if (!orq_size)
		orq_size = 1;

	qp->attrs.irq_size = irq_size;
	qp->attrs.orq_size = orq_size;

	qp->irq = vmalloc(irq_size * sizeof(struct siw_sqe));
	if (!qp->irq) {
		dprint(DBG_ON, "(QP%d): Failed\n", QP_ID(qp));
		qp->attrs.irq_size = 0;
		return -ENOMEM;
	}
	qp->orq = vmalloc(orq_size * sizeof(struct siw_sqe));
	if (!qp->orq) {
		dprint(DBG_ON, "(QP%d): Failed\n", QP_ID(qp));
		qp->attrs.orq_size = 0;
		qp->attrs.irq_size = 0;
		vfree(qp->irq);
		return -ENOMEM;
	}
	memset(qp->irq, 0, irq_size * sizeof(struct siw_sqe));
	memset(qp->orq, 0, orq_size * sizeof(struct siw_sqe));

	return 0;
}


static int siw_qp_enable_crc(struct siw_qp *qp)
{
	struct siw_iwarp_rx *c_rx = &qp->rx_ctx;
	struct siw_iwarp_tx *c_tx = &qp->tx_ctx;
	struct crypto_shash *txsh, *rxsh;
	int rv = 0;

	txsh = crypto_alloc_shash("crc32c", 0, 0);
	if (IS_ERR(txsh))
		return -PTR_ERR(txsh);

	rxsh = crypto_alloc_shash("crc32c", 0, 0);
	if (IS_ERR(rxsh)) {
		rv = -PTR_ERR(rxsh);
		rxsh = NULL;
		goto error;
	}

	c_tx->mpa_crc_hd = kzalloc(sizeof(struct shash_desc) +
				   crypto_shash_descsize(txsh),
				   GFP_KERNEL);
	c_rx->mpa_crc_hd = kzalloc(sizeof(struct shash_desc) +
				   crypto_shash_descsize(rxsh),
				   GFP_KERNEL);
	if (!c_tx->mpa_crc_hd || !c_rx->mpa_crc_hd) {
		rv = -ENOMEM;
		goto error;
	}
	c_tx->mpa_crc_hd->tfm = txsh;
	c_rx->mpa_crc_hd->tfm = rxsh;

	return 0;
error:
	dprint(DBG_ON, "(QP%d): Failed loading crc32c: error=%d.",
			QP_ID(qp), rv);

	kfree(c_tx->mpa_crc_hd);
	kfree(c_rx->mpa_crc_hd);

	c_tx->mpa_crc_hd = c_rx->mpa_crc_hd = NULL;

	if (txsh)
		crypto_free_shash(txsh);
	if (rxsh)
		crypto_free_shash(rxsh);

	return rv;
}

/*
 * Send a non signalled READ or WRITE to peer side as negotiated
 * with MPAv2 P2P setup protocol. The work request is only created
 * as a current active WR and does not consume Send Queue space.
 *
 * Caller must hold QP state lock.
 */
int siw_qp_mpa_rts(struct siw_qp *qp, enum mpa_v2_ctrl ctrl)
{
	struct siw_wqe	*wqe = tx_wqe(qp);
	unsigned long flags;
	int rv = 0;

	spin_lock_irqsave(&qp->sq_lock, flags);

	if (unlikely(wqe->wr_status != SR_WR_IDLE)) {
		spin_unlock_irqrestore(&qp->sq_lock, flags);
		return -EIO;
	}
	memset(wqe->mem, 0, sizeof(*wqe->mem) * SIW_MAX_SGE);

	wqe->wr_status = SR_WR_QUEUED;
	wqe->sqe.flags = 0;
	wqe->sqe.num_sge = 1;
	wqe->sqe.sge[0].length = 0;
	wqe->sqe.sge[0].laddr = 0;
	wqe->sqe.sge[0].lkey = 0;
	wqe->sqe.rkey = 0;
	wqe->sqe.raddr = 0;
	wqe->processed = 0;

	if (ctrl & MPA_V2_RDMA_WRITE_RTR)
		wqe->sqe.opcode = SIW_OP_WRITE;
	else if (ctrl & MPA_V2_RDMA_READ_RTR) {
		struct siw_sqe	*rreq;

		wqe->sqe.opcode = SIW_OP_READ;

		spin_lock(&qp->orq_lock);

		rreq = orq_get_free(qp);
		if (rreq) {
			siw_read_to_orq(rreq, &wqe->sqe);
			qp->orq_put++;
		} else
			rv = -EIO;

		spin_unlock(&qp->orq_lock);
	} else
		rv = -EINVAL;

	if (rv)
		wqe->wr_status = SR_WR_IDLE;

	spin_unlock_irqrestore(&qp->sq_lock, flags);

	if (!rv)
		siw_sq_start(qp);

	return rv;
}

/*
 * handle all attrs other than state
 */
static void siw_qp_modify_nonstate(struct siw_qp *qp,
				  struct siw_qp_attrs *attrs,
				  enum siw_qp_attr_mask mask)
{
	if (mask & SIW_QP_ATTR_ACCESS_FLAGS) {
		if (attrs->flags & SIW_RDMA_BIND_ENABLED)
			qp->attrs.flags |= SIW_RDMA_BIND_ENABLED;
		else
			qp->attrs.flags &= ~SIW_RDMA_BIND_ENABLED;

		if (attrs->flags & SIW_RDMA_WRITE_ENABLED)
			qp->attrs.flags |= SIW_RDMA_WRITE_ENABLED;
		else
			qp->attrs.flags &= ~SIW_RDMA_WRITE_ENABLED;

		if (attrs->flags & SIW_RDMA_READ_ENABLED)
			qp->attrs.flags |= SIW_RDMA_READ_ENABLED;
		else
			qp->attrs.flags &= ~SIW_RDMA_READ_ENABLED;
	}
}

/*
 * caller holds qp->state_lock
 */
int siw_qp_modify(struct siw_qp *qp, struct siw_qp_attrs *attrs,
		  enum siw_qp_attr_mask mask)
{
	int	drop_conn = 0, rv = 0;

	if (!mask)
		return 0;

	dprint(DBG_CM, "(QP%d)\n", QP_ID(qp));

	if (mask != SIW_QP_ATTR_STATE)
		siw_qp_modify_nonstate(qp, attrs, mask);

	if (!(mask & SIW_QP_ATTR_STATE))
		return 0;

	dprint(DBG_CM, "(QP%d): SIW QP state: %s => %s\n", QP_ID(qp),
		siw_qp_state_to_string[qp->attrs.state],
		siw_qp_state_to_string[attrs->state]);


	switch (qp->attrs.state) {

	case SIW_QP_STATE_IDLE:
	case SIW_QP_STATE_RTR:

		switch (attrs->state) {

		case SIW_QP_STATE_RTS:

			if (attrs->mpa.crc) {
				rv = siw_qp_enable_crc(qp);
				if (rv)
					break;
			}
			if (!(mask & SIW_QP_ATTR_LLP_HANDLE)) {
				dprint(DBG_ON, "(QP%d): socket?\n", QP_ID(qp));
				rv = -EINVAL;
				break;
			}
			if (!(mask & SIW_QP_ATTR_MPA)) {
				dprint(DBG_ON, "(QP%d): MPA?\n", QP_ID(qp));
				rv = -EINVAL;
				break;
			}
			dprint(DBG_CM, "(QP%d): Enter RTS\n", QP_ID(qp));
			dprint(DBG_CM, " peer 0x%08x, local 0x%08x\n",
				qp->cep->llp.raddr.sin_addr.s_addr,
				qp->cep->llp.laddr.sin_addr.s_addr);
			/*
			 * Initialize global iWARP TX state
			 */
			qp->tx_ctx.ddp_msn[RDMAP_UNTAGGED_QN_SEND] = 0;
			qp->tx_ctx.ddp_msn[RDMAP_UNTAGGED_QN_RDMA_READ] = 0;
			qp->tx_ctx.ddp_msn[RDMAP_UNTAGGED_QN_TERMINATE] = 0;

			/*
			 * Initialize global iWARP RX state
			 */
			qp->rx_ctx.ddp_msn[RDMAP_UNTAGGED_QN_SEND] = 1;
			qp->rx_ctx.ddp_msn[RDMAP_UNTAGGED_QN_RDMA_READ] = 1;
			qp->rx_ctx.ddp_msn[RDMAP_UNTAGGED_QN_TERMINATE] = 1;

			/*
			 * init IRD free queue, caller has already checked
			 * limits.
			 */
			rv = siw_qp_readq_init(qp, attrs->irq_size,
					       attrs->orq_size);
			if (rv)
				break;

			qp->attrs.mpa = attrs->mpa;
			qp->attrs.llp_stream_handle = attrs->llp_stream_handle;

			qp->attrs.state = SIW_QP_STATE_RTS;
			/*
			 * set initial mss
			 */
			qp->tx_ctx.tcp_seglen =
				get_tcp_mss(attrs->llp_stream_handle->sk);

			break;

		case SIW_QP_STATE_ERROR:
			siw_rq_flush(qp);
			qp->attrs.state = SIW_QP_STATE_ERROR;
			if (qp->cep) {
				siw_cep_put(qp->cep);
				qp->cep = NULL;
			}
			break;

		case SIW_QP_STATE_RTR:
			/* ignore */
			break;

		default:
			dprint(DBG_CM,
				" QP state transition undefined: %s => %s\n",
				siw_qp_state_to_string[qp->attrs.state],
				siw_qp_state_to_string[attrs->state]);
			break;
		}
		break;

	case SIW_QP_STATE_RTS:

		switch (attrs->state) {

		case SIW_QP_STATE_CLOSING:
			/*
			 * Verbs: move to IDLE if SQ and ORQ are empty.
			 * Move to ERROR otherwise. But first of all we must
			 * close the connection. So we keep CLOSING or ERROR
			 * as a transient state, schedule connection drop work
			 * and wait for the socket state change upcall to
			 * come back closed.
			 */
			if (tx_wqe(qp)->wr_status == SR_WR_IDLE)
				qp->attrs.state = SIW_QP_STATE_CLOSING;
			else {
				qp->attrs.state = SIW_QP_STATE_ERROR;
				siw_sq_flush(qp);
			}
			siw_rq_flush(qp);

			drop_conn = 1;
			break;

		case SIW_QP_STATE_TERMINATE:
			qp->attrs.state = SIW_QP_STATE_TERMINATE;
			/*
			 * To be extended for flexible error layer,
			 * type and code.
			 */
			siw_send_terminate(qp, RDMAP_ERROR_LAYER_RDMA,
					   RDMAP_ETYPE_CATASTROPHIC,
					   0);
			drop_conn = 1;

			break;

		case SIW_QP_STATE_ERROR:
			/*
			 * This is an emergency close.
			 *
			 * Any in progress transmit operation will get
			 * cancelled.
			 * This will likely result in a protocol failure,
			 * if a TX operation is in transit. The caller
			 * could unconditional wait to give the current
			 * operation a chance to complete.
			 * Esp., how to handle the non-empty IRQ case?
			 * The peer was asking for data transfer at a valid
			 * point in time.
			 */
			siw_sq_flush(qp);
			siw_rq_flush(qp);
			qp->attrs.state = SIW_QP_STATE_ERROR;
			drop_conn = 1;

			break;

		default:
			dprint(DBG_ON,
				" QP state transition undefined: %s => %s\n",
				siw_qp_state_to_string[qp->attrs.state],
				siw_qp_state_to_string[attrs->state]);
			break;
		}
		break;

	case SIW_QP_STATE_TERMINATE:

		switch (attrs->state) {

		case SIW_QP_STATE_ERROR:
			siw_rq_flush(qp);
			qp->attrs.state = SIW_QP_STATE_ERROR;

			if (tx_wqe(qp)->wr_status != SR_WR_IDLE)
				siw_sq_flush(qp);

			break;

		default:
			dprint(DBG_ON,
				" QP state transition undefined: %s => %s\n",
				siw_qp_state_to_string[qp->attrs.state],
				siw_qp_state_to_string[attrs->state]);
		}
		break;

	case SIW_QP_STATE_CLOSING:

		switch (attrs->state) {

		case SIW_QP_STATE_IDLE:
			BUG_ON(tx_wqe(qp)->wr_status != SR_WR_IDLE);
			qp->attrs.state = SIW_QP_STATE_IDLE;

			break;

		case SIW_QP_STATE_CLOSING:
			/*
			 * The LLP may already moved the QP to closing
			 * due to graceful peer close init
			 */
			break;

		case SIW_QP_STATE_ERROR:
			/*
			 * QP was moved to CLOSING by LLP event
			 * not yet seen by user.
			 */
			qp->attrs.state = SIW_QP_STATE_ERROR;

			if (tx_wqe(qp)->wr_status != SR_WR_IDLE)
				siw_sq_flush(qp);

			siw_rq_flush(qp);

			break;

		default:
			dprint(DBG_CM,
				" QP state transition undefined: %s => %s\n",
				siw_qp_state_to_string[qp->attrs.state],
				siw_qp_state_to_string[attrs->state]);
			return -ECONNABORTED;
		}
		break;

	default:
		dprint(DBG_CM, " NOP: State: %d\n", qp->attrs.state);
		break;
	}
	if (drop_conn)
		siw_qp_cm_drop(qp, 0);

	return rv;
}

struct ib_qp *siw_get_ofaqp(struct ib_device *ofa_dev, int id)
{
	struct siw_qp *qp =  siw_qp_id2obj(siw_dev_ofa2siw(ofa_dev), id);

	dprint(DBG_OBJ, ": dev_name: %s, OFA QPID: %d, QP: %p\n",
		ofa_dev->name, id, qp);
	if (qp) {
		/*
		 * siw_qp_id2obj() increments object reference count
		 */
		siw_qp_put(qp);
		dprint(DBG_OBJ, " QPID: %d\n", QP_ID(qp));
		return &qp->ofa_qp;
	}
	return (struct ib_qp *)NULL;
}

/*
 * siw_check_mem()
 *
 * Check protection domain, STAG state, access permissions and
 * address range for memory object.
 *
 * @pd:		Protection Domain memory should belong to
 * @mem:	memory to be checked
 * @addr:	starting addr of mem
 * @perms:	requested access permissions
 * @len:	len of memory interval to be checked
 *
 */
int siw_check_mem(struct siw_pd *pd, struct siw_mem *mem, u64 addr,
		  enum siw_access_flags perms, int len)
{
	if (siw_mem2mr(mem)->pd != pd) {
		dprint(DBG_WR|DBG_ON, "(PD%d): PD mismatch %p : %p\n",
			OBJ_ID(pd),
			siw_mem2mr(mem)->pd, pd);

		return -EINVAL;
	}
	if (mem->stag_valid == 0) {
		dprint(DBG_WR|DBG_ON, "(PD%d): STAG 0x%08x invalid\n",
			OBJ_ID(pd), OBJ_ID(mem));
		return -EPERM;
	}
	/*
	 * check access permissions
	 */
	if ((mem->perms & perms) < perms) {
		dprint(DBG_WR|DBG_ON, "(PD%d): permissions 0x%08x < 0x%08x\n",
			OBJ_ID(pd), mem->perms, perms);
		return -EPERM;
	}
	/*
	 * Check address interval: we relax check to allow memory shrinked
	 * from the start address _after_ placing or fetching len bytes.
	 * TODO: this relaxation is probably overdone
	 */
	if (addr < mem->va || addr + len > mem->va + mem->len) {
		dprint(DBG_WR|DBG_ON, "(PD%d): MEM interval len %d "
			"[0x%016llx, 0x%016llx) out of bounds "
			"[0x%016llx, 0x%016llx) for LKey=0x%08x\n",
			OBJ_ID(pd), len, (unsigned long long)addr,
			(unsigned long long)(addr + len),
			(unsigned long long)mem->va,
			(unsigned long long)(mem->va + mem->len),
			OBJ_ID(mem));

		return -EINVAL;
	}
	return 0;
}

/*
 * siw_check_sge()
 *
 * Check SGE for access rights in given interval
 *
 * @pd:		Protection Domain memory should belong to
 * @sge:	SGE to be checked
 * @mem:	resulting memory reference if successful
 * @perms:	requested access permissions
 * @off:	starting offset in SGE
 * @len:	len of memory interval to be checked
 *
 * NOTE: Function references SGE's memory object (mem->obj)
 * if not yet done. New reference is kept if check went ok and
 * released if check failed. If mem->obj is already valid, no new
 * lookup is being done and mem is not released it check fails.
 */
int
siw_check_sge(struct siw_pd *pd, struct siw_sge *sge,
	      union siw_mem_resolved *mem, enum siw_access_flags perms,
	      u32 off, int len)
{
	struct siw_dev	*sdev = pd->hdr.sdev;
	int		new_ref = 0, rv = 0;

	if (len + off > sge->length) {
		rv = -EPERM;
		goto fail;
	}
	if (mem->obj == NULL) {
		mem->obj = siw_mem_id2obj(sdev, sge->lkey >> 8);
		if (mem->obj == NULL) {
			rv = -EINVAL;
			goto fail;
		}
		new_ref = 1;
	}

	rv = siw_check_mem(pd, mem->obj, sge->laddr + off, perms, len);
	if (rv)
		goto fail;

	return 0;

fail:
	if (new_ref) {
		siw_mem_put(mem->obj);
		mem->obj = NULL;
	}
	return rv;
}

void siw_read_to_orq(struct siw_sqe *rreq, struct siw_sqe *sqe)
{
	rreq->id = sqe->id;
	rreq->opcode = sqe->opcode;
	rreq->sge[0].laddr = sqe->sge[0].laddr;
	rreq->sge[0].length = sqe->sge[0].length;
	rreq->sge[0].lkey = sqe->sge[0].lkey;
	rreq->sge[1].lkey = sqe->sge[1].lkey;
	rreq->flags = sqe->flags | SIW_WQE_VALID;
	rreq->num_sge = 1;
}

/*
 * Must be called with SQ locked
 */
int siw_activate_tx(struct siw_qp *qp)
{
	struct siw_sqe	*sqe;
	struct siw_wqe	*wqe = tx_wqe(qp);
	int rv = 1;

	if (unlikely(wqe->wr_status != SR_WR_IDLE)) {
		WARN_ON(1);
		return -1;
	}
	/*
	 * This codes prefers pending READ Responses over SQ processing
	 */
	sqe = &qp->irq[qp->irq_get % qp->attrs.irq_size];

	if (sqe->flags & SIW_WQE_VALID) {
		memset(wqe->mem, 0, sizeof(*wqe->mem) * SIW_MAX_SGE);
		wqe->wr_status = SR_WR_QUEUED;

		/* start READ RESPONSE */
		wqe->sqe.opcode = SIW_OP_READ_RESPONSE;
		wqe->sqe.flags = 0;
		wqe->sqe.num_sge = 1;
		wqe->sqe.sge[0].length = sqe->sge[0].length;
		wqe->sqe.sge[0].laddr = sqe->sge[0].laddr;
		wqe->sqe.sge[0].lkey = sqe->sge[0].lkey;
		wqe->sqe.rkey = sqe->rkey;
		wqe->sqe.raddr = sqe->raddr;

		wqe->processed = 0;
		qp->irq_get++;
		/* mark current IRQ entry free */
		smp_store_mb(sqe->flags, 0);

		goto out;
	}

	sqe = sq_get_next(qp);
	if (sqe) {
		memset(wqe->mem, 0, sizeof(*wqe->mem) * SIW_MAX_SGE);
		wqe->wr_status = SR_WR_QUEUED;

		/* First copy SQE to kernel private memory */
		memcpy(&wqe->sqe, sqe, sizeof(*sqe));

		if (wqe->sqe.opcode >= SIW_NUM_OPCODES) {
			rv = -EINVAL;
			goto out;
		}

		if (wqe->sqe.flags & SIW_WQE_INLINE) {
			if (wqe->sqe.opcode != SIW_OP_SEND &&
			    wqe->sqe.opcode != SIW_OP_WRITE) {
				rv = -EINVAL;
				goto out;
			}
			if (wqe->sqe.sge[0].length > SIW_MAX_INLINE) {
				rv = -EINVAL;
				goto out;
			}
			wqe->sqe.sge[0].laddr = (u64)&wqe->sqe.sge[1];
			wqe->sqe.sge[0].lkey = 0;
			wqe->sqe.num_sge = 1;
		}

		if (wqe->sqe.flags & SIW_WQE_READ_FENCE) {
			/* A READ cannot be fenced */
			if (unlikely(wqe->sqe.opcode == SIW_OP_READ ||
			    wqe->sqe.opcode == SIW_OP_READ_LOCAL_INV)) {
				pr_info("QP[%d]: cannot fence READ\n",
					QP_ID(qp));
				rv = -EINVAL;
				goto out;
			}
			spin_lock(&qp->orq_lock);

			if (!siw_orq_empty(qp)) {
				qp->tx_ctx.orq_fence = 1;
				rv = 0;
			}
			spin_unlock(&qp->orq_lock);

		} else if (wqe->sqe.opcode == SIW_OP_READ ||
			   wqe->sqe.opcode == SIW_OP_READ_LOCAL_INV) {
			struct siw_sqe	*rreq;

			wqe->sqe.num_sge = 1;

			spin_lock(&qp->orq_lock);

			rreq = orq_get_free(qp);
			if (rreq) {
				/*
				 * Make an immediate copy in ORQ to be ready
				 * to process loopback READ reply
				 */
				siw_read_to_orq(rreq, &wqe->sqe);
				qp->orq_put++;
			} else {
				qp->tx_ctx.orq_fence = 1;
				rv = 0;
			}
			spin_unlock(&qp->orq_lock);
		}

		/* Clear SQE, can be re-used by application */
		smp_store_mb(sqe->flags, 0);
		qp->sq_get++;
	} else
		rv = 0;

out:
	if (unlikely(rv < 0)) {
		pr_warn("QP[%d]: error %d in activate_tx\n", QP_ID(qp), rv);
		wqe->wr_status = SR_WR_IDLE;
	}
	return rv;
}

static void siw_cq_notify(struct siw_cq *cq, u32 flags)
{
	u32 cq_notify;

	if (unlikely(!cq->ofa_cq.comp_handler))
		return;

	cq_notify = _load_shared(*cq->notify);

	if ((cq_notify & SIW_NOTIFY_NEXT_COMPLETION) ||
	    ((cq_notify & SIW_NOTIFY_SOLICITED) &&
	     (flags & SIW_WQE_SOLICITED))) {
		/* de-arm CQ */
		smp_store_mb(*cq->notify, SIW_NOTIFY_NOT);
		(*cq->ofa_cq.comp_handler)(&cq->ofa_cq, cq->ofa_cq.cq_context);
	}
}

int siw_sqe_complete(struct siw_qp *qp, struct siw_sqe *sqe, u32 bytes,
		     enum siw_wc_status status)
{
	struct siw_cq *cq = qp->scq;
	struct siw_cqe *cqe;
	u32 idx;
	int rv = 0;

	if (cq) {
		u32 sqe_flags = sqe->flags;
		unsigned long flags;

		spin_lock_irqsave(&cq->lock, flags);

		idx = cq->cq_put % cq->num_cqe;
		cqe = &cq->queue[idx];

		if (!cqe->flags) {
			cqe->id = sqe->id;
			cqe->opcode = sqe->opcode;
			cqe->status = status;
			cqe->imm_data = 0;
			cqe->bytes = bytes;

			if (cq->kernel_verbs) {
				siw_qp_get(qp);
				cqe->qp = qp;
			} else
				cqe->qp_id = QP_ID(qp);

			/* mark CQE valid for application */
			smp_store_mb(cqe->flags, SIW_WQE_VALID);
			/* recycle SQE */
			smp_store_mb(sqe->flags, 0);

			cq->cq_put++;
			spin_unlock_irqrestore(&cq->lock, flags);
			siw_cq_notify(cq, sqe_flags);
		} else {
			spin_unlock_irqrestore(&cq->lock, flags);
			rv = -ENOMEM;
			siw_cq_event(cq, IB_EVENT_CQ_ERR);
		}
	} else /* recycle SQE */
		smp_store_mb(sqe->flags, 0);

	return rv;
}

int siw_rqe_complete(struct siw_qp *qp, struct siw_rqe *rqe, u32 bytes,
		     enum siw_wc_status status)
{
	struct siw_cq *cq = qp->rcq;
	struct siw_cqe *cqe;
	u32 idx;
	int rv = 0;

	if (cq) {
		u32 rqe_flags = rqe->flags;
		unsigned long flags;

		spin_lock_irqsave(&cq->lock, flags);

		idx = cq->cq_put % cq->num_cqe;
		cqe = &cq->queue[idx];

		if (!cqe->flags) {
			cqe->id = rqe->id;
			cqe->opcode = SIW_OP_RECEIVE;
			cqe->status = status;
			cqe->imm_data = 0;
			cqe->bytes = bytes;

			if (cq->kernel_verbs) {
				siw_qp_get(qp);
				cqe->qp = qp;
			} else
				cqe->qp_id = QP_ID(qp);

			/* mark CQE valid for application */
			smp_store_mb(cqe->flags, SIW_WQE_VALID);
			/* recycle RQE */
			smp_store_mb(rqe->flags, 0);

			cq->cq_put++;
			spin_unlock_irqrestore(&cq->lock, flags);
			siw_cq_notify(cq, rqe_flags);
		} else {
			spin_unlock_irqrestore(&cq->lock, flags);
			rv = -ENOMEM;
			siw_cq_event(cq, IB_EVENT_CQ_ERR);
		}
	} else /* recycle RQE */
		smp_store_mb(rqe->flags, 0);

	return rv;
}

/*
 * siw_sq_flush()
 *
 * Flush SQ and ORRQ entries to CQ.
 * IRRQ entries are silently dropped.
 *
 * TODO: Add termination code for in-progress WQE.
 * TODO: an in-progress WQE may have been partially
 *       processed. It should be enforced, that transmission
 *       of a started DDP segment must be completed if possible
 *       by any chance.
 *
 * Must be called with qp state write lock held.
 * Therefore, SQ and ORQ lock must not be taken.
 */
void siw_sq_flush(struct siw_qp *qp)
{
	struct siw_sqe	*sqe;
	struct siw_wqe	*wqe = tx_wqe(qp);
	int		async_event = 0;

	dprint(DBG_OBJ|DBG_CM|DBG_WR, "(QP%d): Enter\n", QP_ID(qp));
	/*
	 * Start with completing any work currently on the ORQ
	 */
	for (;;) {
		if (qp->attrs.orq_size == 0)
			break;
		sqe = &qp->orq[qp->orq_get % qp->attrs.orq_size];
		if (!sqe->flags)
			break;

		if (siw_sqe_complete(qp, sqe, 0,
				     SIW_WC_WR_FLUSH_ERR) != 0)
			break;

		qp->orq_get++;
	}
	/*
	 * Flush the in-progress wqe, if there.
	 */
	if (wqe->wr_status != SR_WR_IDLE) {
		/*
		 * TODO: Add iWARP Termination code
		 */
		dprint(DBG_WR,
			" (QP%d): Flush current WQE %p, type %d, status %d\n",
			QP_ID(qp), wqe, tx_type(wqe), wqe->wr_status);

		siw_wqe_put_mem(wqe, wqe->sqe.opcode);

		if (wqe->sqe.opcode != SIW_OP_READ_RESPONSE &&
			((wqe->sqe.opcode != SIW_OP_READ &&
			  wqe->sqe.opcode != SIW_OP_READ_LOCAL_INV) ||
			wqe->wr_status == SR_WR_QUEUED))
			/*
			 * An in-progress RREQUEST is already in
			 * the ORQ
			 */
			siw_sqe_complete(qp, &wqe->sqe, wqe->bytes,
					 SIW_WC_WR_FLUSH_ERR);

		wqe->wr_status = SR_WR_IDLE;
	}
	/*
	 * Flush the Send Queue
	 */
	while (qp->attrs.sq_size) {
		sqe = &qp->sendq[qp->sq_get % qp->attrs.sq_size];
		if (!sqe->flags)
			break;

		async_event = 1;
		if (siw_sqe_complete(qp, sqe, 0, SIW_WC_WR_FLUSH_ERR) != 0)
			/* Shall IB_EVENT_SQ_DRAINED be supressed ? */
			break;

		sqe->flags = 0;
		qp->sq_get++;
	}
	if (async_event)
		siw_qp_event(qp, IB_EVENT_SQ_DRAINED);
}

/*
 * siw_rq_flush()
 *
 * Flush recv queue entries to cq. An in-progress WQE may have some bytes
 * processed (wqe->processed).
 *
 * Must be called with qp state write lock held.
 * Therefore, RQ lock must not be taken.
 */
void siw_rq_flush(struct siw_qp *qp)
{
	struct siw_wqe		*wqe = rx_wqe(qp);

	dprint(DBG_OBJ|DBG_CM|DBG_WR, "(QP%d): Enter\n", QP_ID(qp));

	/*
	 * Flush an in-progess WQE if present
	 */
	if (wqe->wr_status != SR_WR_IDLE) {
		if (__rdmap_opcode(&qp->rx_ctx.hdr.ctrl) != RDMAP_RDMA_WRITE) {
			siw_wqe_put_mem(wqe, SIW_OP_RECEIVE);
			siw_rqe_complete(qp, &wqe->rqe, wqe->bytes,
					 SIW_WC_WR_FLUSH_ERR);
		} else
			siw_mem_put(rx_mem(qp));

		wqe->wr_status = SR_WR_IDLE;
	}

	while (qp->recvq && qp->attrs.rq_size) {
		struct siw_rqe *rqe =
			&qp->recvq[qp->rq_get % qp->attrs.rq_size];

		if (!rqe->flags)
			break;

		if (siw_rqe_complete(qp, rqe, 0, SIW_WC_WR_FLUSH_ERR) != 0)
			break;
		rqe->flags = 0;

		qp->rq_get++;
	}
}

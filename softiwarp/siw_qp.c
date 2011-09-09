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
#include <linux/file.h>
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
	.hdr_len = sizeof(struct iwarp_rdma_write),
	.ctrl.mpa_len = htons(sizeof(struct iwarp_rdma_write) - 2),
	.ctrl.ddp_rdmap_ctrl = DDP_FLAG_TAGGED | DDP_FLAG_LAST
		| cpu_to_be16(DDP_VERSION << 8)
		| cpu_to_be16(RDMAP_VERSION << 6)
		| cpu_to_be16(RDMAP_RDMA_WRITE),
	.proc_data = siw_proc_write
},
{
	.hdr_len = sizeof(struct iwarp_rdma_rreq),
	.ctrl.mpa_len = htons(sizeof(struct iwarp_rdma_rreq) - 2),
	.ctrl.ddp_rdmap_ctrl = DDP_FLAG_LAST
		| cpu_to_be16(DDP_VERSION << 8)
		| cpu_to_be16(RDMAP_VERSION << 6)
		| cpu_to_be16(RDMAP_RDMA_READ_REQ),
	.proc_data = siw_proc_rreq
},
{
	.hdr_len = sizeof(struct iwarp_rdma_rresp),
	.ctrl.mpa_len = htons(sizeof(struct iwarp_rdma_rresp) - 2),
	.ctrl.ddp_rdmap_ctrl = DDP_FLAG_TAGGED | DDP_FLAG_LAST
		| cpu_to_be16(DDP_VERSION << 8)
		| cpu_to_be16(RDMAP_VERSION << 6)
		| cpu_to_be16(RDMAP_RDMA_READ_RESP),
	.proc_data = siw_proc_rresp
},
{
	.hdr_len = sizeof(struct iwarp_send),
	.ctrl.mpa_len = htons(sizeof(struct iwarp_send) - 2),
	.ctrl.ddp_rdmap_ctrl = DDP_FLAG_LAST
		| cpu_to_be16(DDP_VERSION << 8)
		| cpu_to_be16(RDMAP_VERSION << 6)
		| cpu_to_be16(RDMAP_SEND),
	.proc_data = siw_proc_send
},
{
	.hdr_len = sizeof(struct iwarp_send_inv),
	.ctrl.mpa_len = htons(sizeof(struct iwarp_send_inv) - 2),
	.ctrl.ddp_rdmap_ctrl = DDP_FLAG_LAST
		| cpu_to_be16(DDP_VERSION << 8)
		| cpu_to_be16(RDMAP_VERSION << 6)
		| cpu_to_be16(RDMAP_SEND_INVAL),
	.proc_data = siw_proc_unsupp
},
{
	.hdr_len = sizeof(struct iwarp_send),
	.ctrl.mpa_len = htons(sizeof(struct iwarp_send) - 2),
	.ctrl.ddp_rdmap_ctrl = DDP_FLAG_LAST
		| cpu_to_be16(DDP_VERSION << 8)
		| cpu_to_be16(RDMAP_VERSION << 6)
		| cpu_to_be16(RDMAP_SEND_SE),
	.proc_data = siw_proc_send
},
{
	.hdr_len = sizeof(struct iwarp_send_inv),
	.ctrl.mpa_len = htons(sizeof(struct iwarp_send_inv) - 2),
	.ctrl.ddp_rdmap_ctrl = DDP_FLAG_LAST
		| cpu_to_be16(DDP_VERSION << 8)
		| cpu_to_be16(RDMAP_VERSION << 6)
		| cpu_to_be16(RDMAP_SEND_SE_INVAL),
	.proc_data = siw_proc_unsupp
},
{
	.hdr_len = sizeof(struct iwarp_terminate),
	.ctrl.mpa_len = htons(sizeof(struct iwarp_terminate) - 2),
	.ctrl.ddp_rdmap_ctrl = DDP_FLAG_LAST
		| cpu_to_be16(DDP_VERSION << 8)
		| cpu_to_be16(RDMAP_VERSION << 6)
		| cpu_to_be16(RDMAP_TERMINATE),
	.proc_data = siw_proc_terminate
} };


static void siw_qp_llp_data_ready(struct sock *sk, int flags)
{
	struct siw_qp		*qp;

	read_lock(&sk->sk_callback_lock);

	if (unlikely(!sk->sk_user_data || !sk_to_qp(sk))) {
		dprint(DBG_ON, " No QP: %p\n", sk->sk_user_data);
		goto done;
	}
	qp = sk_to_qp(sk);

	if (down_read_trylock(&qp->state_lock)) {
		read_descriptor_t	rd_desc = {.arg.data = qp, .count = 1};

		dprint(DBG_SK|DBG_RX, "(QP%d): "
			"state (before tcp_read_sock)=%d, flags=%x\n",
			QP_ID(qp), qp->attrs.state, flags);

		if (likely(qp->attrs.state == SIW_QP_STATE_RTS))
			/*
			 * Implements data receive operation during
			 * socket callback. TCP gracefully catches
			 * the case where there is nothing to receive
			 * (not calling siw_tcp_rx_data() then).
			 */
			tcp_read_sock(sk, &rd_desc, siw_tcp_rx_data);

		dprint(DBG_SK|DBG_RX, "(QP%d): "
			"state (after tcp_read_sock)=%d, flags=%x\n",
			QP_ID(qp), qp->attrs.state, flags);

		up_read(&qp->state_lock);
	} else {
		dprint(DBG_SK|DBG_RX, "(QP%d): "
			"Unable to acquire state_lock\n", QP_ID(qp));
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
		if (!TX_IDLE(qp))
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
}


/*
 * socket callback routine informing about newly available send space.
 * Function schedules SQ work for processing SQ items.
 */
static void siw_qp_llp_write_space(struct sock *sk)
{
	struct siw_qp	*qp = sk_to_qp(sk);

	/*
	 * TODO:
	 * Resemble sk_stream_write_space() logic for iWARP constraints:
	 * Clear SOCK_NOSPACE only if sendspace may hold some reasonable
	 * sized FPDU.
	 */
#ifdef SIW_TX_FULLSEGS
	struct socket *sock = sk->sk_socket;
	if (sk_stream_wspace(sk) >= (int)qp->tx_ctx.fpdu_len && sock) {
		clear_bit(SOCK_NOSPACE, &sock->flags);
		siw_sq_queue_work(qp);
	}
#else
	sk_stream_write_space(sk);

	if (!test_bit(SOCK_NOSPACE, &sk->sk_socket->flags))
		siw_sq_queue_work(qp);
#endif
}

static void siw_qp_socket_assoc(struct socket *s, struct siw_qp *qp)
{
	struct sock *sk = s->sk;

	write_lock_bh(&sk->sk_callback_lock);

	qp->attrs.llp_stream_handle = s;
	s->sk->sk_data_ready = siw_qp_llp_data_ready;
	s->sk->sk_write_space = siw_qp_llp_write_space;

	write_unlock_bh(&sk->sk_callback_lock);
}


static int siw_qp_irq_init(struct siw_qp *qp, int size)
{
	struct siw_wqe *wqe = NULL;
	int i = 0;

	dprint(DBG_CM|DBG_WR, "(QP%d): irq size: %d\n", QP_ID(qp), i);
	if (size <= 0)
		return 0;

	atomic_set(&qp->irq_space, size);

	while (size--) {
		wqe = kzalloc(sizeof(struct siw_wqe), GFP_KERNEL);
		if (!wqe)
			break;

		INIT_LIST_HEAD(&wqe->list);
		list_add(&wqe->list, &qp->freeq);
		i++;
		SIW_INC_STAT_WQE;
	}
	if (!wqe) {
		dprint(DBG_ON, "(QP%d): Failed\n", QP_ID(qp));
		while (i--) {
			wqe = list_first_wqe(&qp->freeq);
			list_del(&wqe->list);
			kfree(wqe);
			SIW_DEC_STAT_WQE;
		}
		atomic_set(&qp->irq_space, 0);
		return -ENOMEM;
	}
	return 0;
}


static void siw_send_terminate(struct siw_qp *qp)
{
	struct iwarp_terminate	pkt;

	memset(&pkt, 0, sizeof pkt);
	/*
	 * TODO: send TERMINATE
	 */
	dprint(DBG_CM, "(QP%d): Todo\n", QP_ID(qp));
}


static int siw_qp_enable_crc(struct siw_qp *qp)
{
	struct siw_iwarp_rx *c_rx = &qp->rx_ctx;
	struct siw_iwarp_tx *c_tx = &qp->tx_ctx;
	int rv = 0;

	c_tx->mpa_crc_hd.tfm = crypto_alloc_hash("crc32c", 0,
						 CRYPTO_ALG_ASYNC);
	if (IS_ERR(c_tx->mpa_crc_hd.tfm)) {
		rv = -PTR_ERR(c_tx->mpa_crc_hd.tfm);
		goto out;
	}
	c_rx->mpa_crc_hd.tfm = crypto_alloc_hash("crc32c", 0,
						 CRYPTO_ALG_ASYNC);
	if (IS_ERR(c_rx->mpa_crc_hd.tfm)) {
		rv = -PTR_ERR(c_rx->mpa_crc_hd.tfm);
		crypto_free_hash(c_tx->mpa_crc_hd.tfm);
	}
out:
	if (rv)
		dprint(DBG_ON, "(QP%d): Failed loading crc32c: error=%d.",
			QP_ID(qp), rv);
	else
		c_tx->crc_enabled = c_rx->crc_enabled = 1;

	return rv;
}


/*
 * caller holds qp->state_lock
 */
int
siw_qp_modify(struct siw_qp *qp, struct siw_qp_attrs *attrs,
	      enum siw_qp_attr_mask mask)
{
	int	drop_conn = 0, rv = 0;

	if (!mask)
		return 0;

	dprint(DBG_CM, "(QP%d)\n", QP_ID(qp));

	if (mask != SIW_QP_ATTR_STATE) {
		/*
		 * changes of qp attributes (maybe state, too)
		 */
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
				qp->attrs.flags &= ~SIW_RDMA_WRITE_ENABLED;

		}
		/*
		 * TODO: what else ??
		 */
	}
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
			dprint(DBG_CM, "(QP%d): Enter RTS: "
				"peer 0x%08x, local 0x%08x\n", QP_ID(qp),
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
			 * init IRD freequeue, caller has already checked
			 * limits. Add one extra entry since after sending
			 * the RResponse it may trigger another peer RRequest
			 * before the RResponse goes back to free queue.
			 */
			++attrs->ird;
			rv = siw_qp_irq_init(qp, attrs->ird);
			if (rv)
				break;

			atomic_set(&qp->orq_space, attrs->ord);

			qp->attrs.ord = attrs->ord;
			qp->attrs.ird = attrs->ird;
			qp->attrs.mpa = attrs->mpa;
			/*
			 * move socket rx and tx under qp's control
			 */
			siw_qp_socket_assoc(attrs->llp_stream_handle, qp);

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
			if (TX_IDLE(qp))
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
			siw_send_terminate(qp);
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

			if (!TX_IDLE(qp))
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
			BUG_ON(!TX_IDLE(qp));
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

			if (!TX_IDLE(qp))
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
	if (mem->stag_state == STAG_INVALID) {
		dprint(DBG_WR|DBG_ON, "(PD%d): STAG 0x%08x invalid\n",
			OBJ_ID(pd), OBJ_ID(mem));
		return -EPERM;
	}
	/*
	 * check access permissions
	 */
	if ((mem->perms & perms) < perms) {
		dprint(DBG_WR|DBG_ON, "(PD%d): "
			"INSUFFICIENT permissions 0x%08x : 0x%08x\n",
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
 * @perms:	requested access permissions
 * @off:	starting offset in SGE
 * @len:	len of memory interval to be checked
 *
 * NOTE: Function references each SGE's memory object (sge->mem)
 * if not yet done. New reference is kept if check went ok and
 * released if check failed. If sge->mem is already valid, no new
 * lookup is being done and mem is not released it check fails.
 */
int
siw_check_sge(struct siw_pd *pd, struct siw_sge *sge,
	      enum siw_access_flags perms, u32 off, int len)
{
	struct siw_dev	*sdev = pd->hdr.sdev;
	struct siw_mem	*mem;
	int		new_ref = 0, rv = 0;

	if (len + off > sge->len) {
		rv = -EPERM;
		goto fail;
	}
	if (sge->mem.obj == NULL) {
		mem = siw_mem_id2obj(sdev, sge->lkey >> 8);
		if (!mem) {
			rv = -EINVAL;
			goto fail;
		}
		sge->mem.obj = mem;
		new_ref = 1;
	} else {
		mem = sge->mem.obj;
		new_ref = 0;
	}
	rv = siw_check_mem(pd, mem, sge->addr + off, perms, len);
	if (rv)
		goto fail;

	return 0;

fail:
	if (new_ref) {
		siw_mem_put(mem);
		sge->mem.obj = NULL;
	}
	return rv;
}


/*
 * siw_check_sgl()
 *
 * Check permissions for a list of SGE's (SGL)
 *
 * @pd:		Protection Domain SGL should belong to
 * @sge:	List of SGE to be checked
 * @perms:	requested access permissions
 * @off:	starting offset in SGL
 * @len:	len of memory interval to be checked
 *
 * Function checks only subinterval of SGL described by bytelen @len,
 * check starts with byte offset @off which must be within
 * the length of the first SGE.
 *
 * The caller is responsible for keeping @len + @off within
 * the total byte len of the SGL.
 */

int siw_check_sgl(struct siw_pd *pd, struct siw_sge *sge,
		  enum siw_access_flags perms, u32 off, int len)
{
	int	rv = 0;

	dprint(DBG_WR, "(PD%d): Enter\n", OBJ_ID(pd));

	BUG_ON(off >= sge->len);

	while (len > 0) {
		dprint(DBG_WR, "(PD%d): sge=%p, perms=0x%x, "
			"len=%d, off=%u, sge->len=%d\n",
			OBJ_ID(pd), sge, perms, len, off, sge->len);
		/*
		 * rdma verbs: do not check stag for a zero length sge
		 */
		if (sge->len == 0) {
			sge++;
			continue;
		}

		rv = siw_check_sge(pd, sge, perms, off, sge->len - off);
		if (rv)
			break;

		len -= sge->len - off;
		off = 0;
		sge++;
	}
	return rv;
}

int siw_crc_array(struct hash_desc *desc, u8 *start, size_t len)
{
	struct scatterlist sg;

	sg_init_one(&sg, start, len);
	return crypto_hash_update(desc, &sg, len);
}

int siw_crc_sg(struct hash_desc *desc, struct scatterlist *sg,
	       int off, int len)
{
	int rv;

	if (off == 0)
		rv = crypto_hash_update(desc, sg, len);
	else {
		struct scatterlist t_sg;

		sg_init_table(&t_sg, 1);
		sg_set_page(&t_sg, sg_page(sg), len, off);
		rv = crypto_hash_update(desc, &t_sg, len);
	}
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
	struct list_head	*pos, *n;
	struct siw_wqe		*wqe = tx_wqe(qp);
	struct siw_cq		*cq = qp->scq;
	int			async_event = 0;

	dprint(DBG_OBJ|DBG_CM|DBG_WR, "(QP%d): Enter\n", QP_ID(qp));

	/*
	 * flush the in-progress wqe, if there.
	 */
	if (wqe) {
		/*
		 * TODO: Add iWARP Termination code
		 */
		tx_wqe(qp) = NULL;

		dprint(DBG_WR,
			" (QP%d): Flush current WQE %p, type %d\n",
			QP_ID(qp), wqe, wr_type(wqe));

		if (wr_type(wqe) == SIW_WR_RDMA_READ_RESP) {
			siw_wqe_put(wqe);
			wqe = NULL;
		} else if (wr_type(wqe) != SIW_WR_RDMA_READ_REQ)
			/*
			 *  A RREQUEST is already on the ORRQ
			 */
			list_add_tail(&wqe->list, &qp->orq);
	}
	if (!list_empty(&qp->irq))
		list_for_each_safe(pos, n, &qp->irq) {
			wqe = list_entry_wqe(pos);
			dprint(DBG_WR,
				" (QP%d): Flush IRQ WQE %p, status %d\n",
				QP_ID(qp), wqe, wqe->wr_status);
			list_del(&wqe->list);
			siw_wqe_put(wqe);
		}

	if (!list_empty(&qp->orq))
		list_for_each_safe(pos, n, &qp->orq) {
			wqe = list_entry_wqe(pos);
			dprint(DBG_WR,
				" (QP%d): Flush ORQ WQE %p, type %d,"
				" status %d\n", QP_ID(qp), wqe, wr_type(wqe),
				wqe->wr_status);
			if (wqe->wr_status != SR_WR_DONE) {
				async_event = 1;
				wqe->wc_status = IB_WC_WR_FLUSH_ERR;
				wqe->wr_status = SR_WR_DONE;
			}
			if (cq) {
				lock_cq(cq);
				list_move_tail(&wqe->list, &cq->queue);
				/* TODO: enforce CQ limits */
				atomic_inc(&cq->qlen);
				unlock_cq(cq);
			} else {
				list_del(&wqe->list);
				siw_wqe_put(wqe);
			}
		}
	if (!list_empty(&qp->sq)) {
		async_event = 1;
		list_for_each_safe(pos, n, &qp->sq) {
			wqe = list_entry_wqe(pos);
			dprint(DBG_WR,
				" (QP%d): Flush SQ WQE %p, type %d\n",
				QP_ID(qp), wqe, wr_type(wqe));
			if (cq) {
				wqe->wc_status = IB_WC_WR_FLUSH_ERR;
				wqe->wr_status = SR_WR_DONE;
				lock_cq(cq);
				list_move_tail(&wqe->list, &cq->queue);
				/* TODO: enforce CQ limits */
				atomic_inc(&cq->qlen);
				unlock_cq(cq);
			} else  {
				list_del(&wqe->list);
				siw_wqe_put(wqe);
			}
		}
	}

	if (wqe != NULL && cq != NULL && cq->ofa_cq.comp_handler != NULL)
		(*cq->ofa_cq.comp_handler)(&cq->ofa_cq, cq->ofa_cq.cq_context);

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
	struct list_head	*pos, *n;
	struct siw_wqe		*wqe;
	struct siw_cq		*cq;

	dprint(DBG_OBJ|DBG_CM|DBG_WR, "(QP%d): Enter\n", QP_ID(qp));

	/*
	 * Flush an in-progess WQE if present
	 */
	if (rx_wqe(qp)) {
		if (__rdmap_opcode(&qp->rx_ctx.hdr.ctrl) != RDMAP_RDMA_WRITE)
			list_add(&rx_wqe(qp)->list, &qp->rq);
		else
			siw_mem_put(rx_mem(qp));

		rx_wqe(qp) = NULL;
	}
	if (list_empty(&qp->rq))
		return;

	cq = qp->rcq;

	list_for_each_safe(pos, n, &qp->rq) {
		wqe = list_entry_wqe(pos);
		list_del_init(&wqe->list);
		if (cq) {
			wqe->wc_status = IB_WC_WR_FLUSH_ERR;
			lock_cq(cq);
			list_add_tail(&wqe->list, &cq->queue);
			/* TODO: enforce CQ limits */
			atomic_inc(&cq->qlen);
			unlock_cq(cq);
		} else
			siw_wqe_put(wqe);
	}

	if (cq != NULL && cq->ofa_cq.comp_handler != NULL)
		(*cq->ofa_cq.comp_handler)(&cq->ofa_cq, cq->ofa_cq.cq_context);
}

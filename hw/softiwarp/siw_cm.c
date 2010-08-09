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

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/net.h>
#include <linux/inetdevice.h>
#include <linux/workqueue.h>
#include <net/sock.h>
#include <net/tcp_states.h>


#include <rdma/iw_cm.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_user_verbs.h>

#include "siw.h"
#include "siw_cm.h"
#include "siw_tcp.h"
#include "siw_utils.h"
#include "siw_obj.h"
#include "siw_socket.h"

static int mpa_crc_enabled;
module_param(mpa_crc_enabled, int, 0644);
MODULE_PARM_DESC(mpa_crc_enabled, "MPA CRC enabled");

static int mpa_markers_enabled; /*  = 0; */
module_param(mpa_markers_enabled, int, 0644);
MODULE_PARM_DESC(mpa_markers_enabled, "MPA markers enabled");

static int mpa_revision = 1;

static void siw_cm_llp_state_change(struct sock *);
static void siw_cm_llp_data_ready(struct sock *, int);
static void siw_cm_llp_write_space(struct sock *);
static void siw_cm_llp_error_report(struct sock *);


static void siw_sk_assign_cm_upcalls(struct sock *sk)
{
	write_lock_bh(&sk->sk_callback_lock);
	sk->sk_state_change = siw_cm_llp_state_change;
	sk->sk_data_ready   = siw_cm_llp_data_ready;
	sk->sk_write_space  = siw_cm_llp_write_space;
	sk->sk_error_report = siw_cm_llp_error_report;
	write_unlock_bh(&sk->sk_callback_lock);
}

static inline int kernel_peername(struct socket *s, struct sockaddr_in *addr)
{
	int unused;
	return s->ops->getname(s, (struct sockaddr *)addr, &unused, 1);
}

static inline int kernel_localname(struct socket *s, struct sockaddr_in *addr)
{
	int unused;
	return s->ops->getname(s, (struct sockaddr *)addr, &unused, 0);
}

static void siw_cep_socket_assoc(struct siw_cep *cep, struct socket *s)
{
	cep->llp.sock = s;
	siw_cep_get(cep);
	s->sk->sk_user_data = cep;

	siw_sk_save_upcalls(s->sk);
	siw_sk_assign_cm_upcalls(s->sk);
}


static struct siw_cep *siw_cep_alloc(void)
{
	struct siw_cep *cep = kzalloc(sizeof *cep, GFP_KERNEL);
	if (cep) {
		INIT_LIST_HEAD(&cep->list);
		INIT_LIST_HEAD(&cep->work_freelist);

		cep->mpa.hdr.params.c = mpa_crc_enabled ? 1 : 0;
		cep->mpa.hdr.params.m = mpa_markers_enabled ? 1 : 0;
		cep->mpa.hdr.params.rev = mpa_revision ? 1 : 0;
		kref_init(&cep->ref);
		cep->state = SIW_EPSTATE_IDLE;
		init_waitqueue_head(&cep->waitq);
		spin_lock_init(&cep->lock);
		dprint(DBG_OBJ|DBG_CM, "(CEP 0x%p): New Object\n", cep);
	}
	return cep;
}

static void siw_cm_free_work(struct siw_cep *cep)
{
	struct list_head	*w, *tmp;
	struct siw_cm_work	*work;

	list_for_each_safe(w, tmp, &cep->work_freelist) {
		work = list_entry(w, struct siw_cm_work, list);
		list_del(&work->list);
		kfree(work);
	}
}

static void siw_put_work(struct siw_cm_work *work)
{
	INIT_LIST_HEAD(&work->list);
	spin_lock_bh(&work->cep->lock);
	list_add(&work->list, &work->cep->work_freelist);
	spin_unlock_bh(&work->cep->lock);
}


static void __siw_cep_dealloc(struct kref *ref)
{
	struct siw_cep *cep = container_of(ref, struct siw_cep, ref);

	dprint(DBG_OBJ|DBG_CM, "(CEP 0x%p): Free Object\n", cep);

	if (cep->listen_cep)
		siw_cep_put(cep->listen_cep);

	/* kfree(NULL) is save */
	kfree(cep->mpa.pdata);
	spin_lock_bh(&cep->lock);
	if (!list_empty(&cep->work_freelist))
		siw_cm_free_work(cep);
	spin_unlock_bh(&cep->lock);

	kfree(cep);
}

static struct siw_cm_work *siw_get_work(struct siw_cep *cep)
{
	struct siw_cm_work	*work = NULL;

	spin_lock_bh(&cep->lock);
	if (!list_empty(&cep->work_freelist)) {
		work = list_entry(cep->work_freelist.next, struct siw_cm_work,
				  list);
		list_del_init(&work->list);
	}
	spin_unlock_bh(&cep->lock);
	return work;
}

static int siw_cm_alloc_work(struct siw_cep *cep, int num)
{
	struct siw_cm_work	*work;

	BUG_ON(!list_empty(&cep->work_freelist));

	while (num--) {
		work = kmalloc(sizeof *work, GFP_KERNEL);
		if (!work) {
			if (!(list_empty(&cep->work_freelist)))
				siw_cm_free_work(cep);
			dprint(DBG_ON, " Failed\n");
			return -ENOMEM;
		}
		work->cep = cep;
		INIT_LIST_HEAD(&work->list);
		list_add(&work->list, &cep->work_freelist);
	}
	return 0;
}

static void siw_cm_release(struct siw_cep *cep)
{
	if (cep->llp.sock) {
		siw_socket_disassoc(cep->llp.sock);
		sock_release(cep->llp.sock);
		cep->llp.sock = NULL;
	}
	if (cep->qp) {
		struct siw_qp *qp = cep->qp;
		cep->qp = NULL;
		siw_qp_put(qp);
	}
	if (cep->cm_id) {
		cep->cm_id->rem_ref(cep->cm_id);
		cep->cm_id = NULL;
		siw_cep_put(cep);
	}
	cep->state = SIW_EPSTATE_CLOSED;
}

/*
 * Test and set CEP into CLOSE pending. After calling
 * this function, the CEP conn_close flag is set. Returns:
 *
 *  1, if CEP is currently in use,
 *  0, if CEP is not in use and not already in CLOSE,
 * -1, if CEP is not in use and already in CLOSE.
 */
int siw_cep_in_close(struct siw_cep *cep)
{
	int rv;

	spin_lock_bh(&cep->lock);

	dprint(DBG_CM, " (CEP 0x%p): close %d, use %d\n",
		cep, cep->conn_close, cep->in_use);

	rv = cep->in_use ? 1 : (cep->conn_close ? -1 : 0);
	cep->conn_close = 1; /* may be redundant */

	spin_unlock_bh(&cep->lock);

	return rv;
}

/*
 * siw_qp_cm_drop()
 *
 * Drops established LLP connection if present and not already
 * scheduled for dropping. Called from user context, SQ workqueue
 * or receive IRQ. Caller signals if socket can be immediately
 * closed (basically, if not in IRQ) and if IWCM should get
 * informed of LLP state change.
 */
void siw_qp_cm_drop(struct siw_qp *qp, int schedule)
{
	struct siw_cep *cep = qp->cep;

	qp->rx_info.rx_suspend = 1;
	qp->tx_info.tx_suspend = 1;

	if (cep && !siw_cep_in_close(cep)) {
		if (schedule) {
			siw_cm_queue_work(cep, SIW_CM_WORK_CLOSE_LLP);
			return;
		}
		/*
		 * Immediately close socket
		 */
		dprint(DBG_CM, "(): immediate close, cep->state=%d\n",
			cep->state);

		if (cep->cm_id) {
			switch (cep->state) {

			case SIW_EPSTATE_AWAIT_MPAREP:
				siw_cm_upcall(cep, IW_CM_EVENT_CONNECT_REPLY,
					      IW_CM_EVENT_STATUS_EINVAL);
				break;

			case SIW_EPSTATE_RDMA_MODE:
				siw_cm_upcall(cep, IW_CM_EVENT_CLOSE,
					      IW_CM_EVENT_STATUS_OK);

				break;

			case SIW_EPSTATE_IDLE:
			case SIW_EPSTATE_LISTENING:
			case SIW_EPSTATE_CONNECTING:
			case SIW_EPSTATE_AWAIT_MPAREQ:
			case SIW_EPSTATE_RECVD_MPAREQ:
			case SIW_EPSTATE_CLOSED:
			default:

				break;
			}
			cep->cm_id->rem_ref(cep->cm_id);
			cep->cm_id = NULL;
			siw_cep_put(cep);
		}
		cep->state = SIW_EPSTATE_CLOSED;

		if (cep->llp.sock) {
			siw_socket_disassoc(cep->llp.sock);
			sock_release(cep->llp.sock);
			cep->llp.sock = NULL;
		}
		cep->qp = NULL;
		siw_qp_put(qp);
	}
}


/*
 * Set CEP in_use flag. Returns:
 *
 *  1, if CEP was not in use and not scheduled for closing,
 *  0, if CEP was not in use but scheduled for closing,
 * -1, if CEP is currently in use.
 */
static int siw_cep_set_inuse(struct siw_cep *cep)
{
	int rv;

	spin_lock_bh(&cep->lock);

	dprint(DBG_CM, " (CEP 0x%p): close %d, use %d\n",
		cep, cep->conn_close, cep->in_use);

	rv = cep->in_use ? -1 : (cep->conn_close ? 0 : 1);
	cep->in_use = 1; /* may be redundant */

	spin_unlock_bh(&cep->lock);

	return rv;
}

/*
 * Clear CEP in_use flag. Returns:
 *
 *  1, if CEP is not scheduled for closing,
 *  0, else.
 */
static int siw_cep_set_free(struct siw_cep *cep)
{
	int rv;

	spin_lock_bh(&cep->lock);

	dprint(DBG_CM, " (CEP 0x%p): close %d, use %d\n",
		cep, cep->conn_close, cep->in_use);

	cep->in_use = 0;
	rv = cep->conn_close ? 0 : 1;

	spin_unlock_bh(&cep->lock);

	wake_up(&cep->waitq);

	return rv;
}


void siw_cep_put(struct siw_cep *cep)
{
	dprint(DBG_OBJ|DBG_CM, "(CEP 0x%p): New refcount: %d\n",
		cep, atomic_read(&cep->ref.refcount) - 1);

	if (!kref_put(&cep->ref, __siw_cep_dealloc))
		wake_up(&cep->waitq);
}

void siw_cep_get(struct siw_cep *cep)
{
	kref_get(&cep->ref);
	dprint(DBG_OBJ|DBG_CM, "(CEP 0x%p): New refcount: %d\n",
		cep, atomic_read(&cep->ref.refcount));
}

static struct workqueue_struct *siw_cm_wq;

/*
 * Receive MPA Request/Reply haeder.
 *
 * Returns 0 if complete MPA Request/Reply haeder including
 * eventual private data was received. Returns -EAGAIN if
 * header was partially received or negative error code otherwise.
 *
 * Context: May be called in process context only
 */
static int siw_recv_mpa_rr(struct siw_cep *cep)
{
	struct mpa_rr	*hdr = &cep->mpa.hdr;
	struct socket	*s = cep->llp.sock;
	int		rcvd, to_rcv;

	if (cep->mpa.bytes_rcvd < sizeof(struct mpa_rr)) {

		rcvd = ksock_recv(s, (char *)hdr + cep->mpa.bytes_rcvd,
				  sizeof(struct mpa_rr) -
				  cep->mpa.bytes_rcvd, 0);

		if (rcvd <= 0)
			return -ECONNABORTED;

		cep->mpa.bytes_rcvd += rcvd;

		if (cep->mpa.bytes_rcvd < sizeof(struct mpa_rr))
			return -EAGAIN;

		hdr->params.pd_len = ntohs(hdr->params.pd_len);

		if (hdr->params.pd_len > MPA_MAX_PRIVDATA)
			return -EPROTO;
	}

	/*
	 * At least the MPA Request/Reply header (frame not including
	 * private data) has been received.
	 * Receive (or continue receiving) any private data.
	 */
	to_rcv = hdr->params.pd_len -
		 (cep->mpa.bytes_rcvd - sizeof(struct mpa_rr));

	if (!to_rcv) {
		/*
		 * We must have hdr->params.pd_len == 0 and thus received a
		 * complete MPA Request/Reply frame.
		 * Check against peer protocol violation.
		 */
		__u32 word;

		rcvd = ksock_recv(s, (char *)&word, sizeof word, MSG_DONTWAIT);
		if (rcvd == -EAGAIN)
			return 0;

		if (rcvd == 0) {
			dprint(DBG_CM, " peer EOF\n");
			return -EPIPE;
		}
		if (rcvd < 0) {
			dprint(DBG_CM, " ERROR: %d: \n", rcvd);
			return rcvd;
		}
		dprint(DBG_CM, " peer sent extra data: %d\n", rcvd);
		return -EPROTO;
	}

	/*
	 * At this point, we must have hdr->params.pd_len != 0.
	 * A private data buffer gets allocated iff hdr->params.pd_len != 0.
	 * Ownership of this buffer will be transferred to the IWCM
	 * when calling siw_cm_upcall().
	 */
	if (!cep->mpa.pdata &&
	    !(cep->mpa.pdata = kmalloc(hdr->params.pd_len + 4, GFP_KERNEL)))
		return -ENOMEM;

	rcvd = ksock_recv(s, cep->mpa.pdata + cep->mpa.bytes_rcvd
			  - sizeof(struct mpa_rr), to_rcv + 4, MSG_DONTWAIT);

	if (rcvd < 0)
		return rcvd;

	if (rcvd > to_rcv)
		return -EPROTO;

	cep->mpa.bytes_rcvd += rcvd;

	if (to_rcv == rcvd) {
		dprint_mem(DBG_CM, "private_data",
				cep->mpa.pdata, hdr->params.pd_len,
				"(): ");
		return 0;
	}
	return -EAGAIN;
}


static void siw_proc_mpareq(struct siw_cep *cep)
{
	int err = siw_recv_mpa_rr(cep);

	if (err)
		goto out;

	if (cep->mpa.hdr.params.rev > MPA_REVISION_1) {
		/* allow for 0 and 1 only */
		err = -EPROTO;
		goto out;
	}

	if (memcmp(cep->mpa.hdr.key, MPA_KEY_REQ, sizeof cep->mpa.hdr.key)) {
		err = -EPROTO;
		goto out;
	}
	cep->state = SIW_EPSTATE_RECVD_MPAREQ;

	if (cep->listen_cep->state == SIW_EPSTATE_LISTENING) {
		/*
		 * Since siw_cm_upcall() called with success, iwcm must hold
		 * a reference to the CEP until the IW_CM_EVENT_CONNECT_REQUEST
		 * has been accepted or rejected.
		 * NOTE: If the iwcm never calls back with accept/reject,
		 * (e.g., the user types ^C instead), the CEP can never be
		 * free'd. It results in a memory hole which should be
		 * fixed by calling siw_reject() in case of application
		 * termination..
		 */
		siw_cep_get(cep);

		err = siw_cm_upcall(cep, IW_CM_EVENT_CONNECT_REQUEST,
				    IW_CM_EVENT_STATUS_OK);
		if (err)
			siw_cep_put(cep);
	} else {
		/*
		 * listener lost: new connection cannot be signalled
		 */
		dprint(DBG_CM|DBG_ON, "(cep=0x%p): Listener lost:!\n", cep);
		err = -EINVAL;
	}
out:
	if (err) {
		dprint(DBG_CM|DBG_ON, "(cep=0x%p): error %d\n", cep, err);

		if (!siw_cep_in_close(cep)) {
			/*
			 * remove reference from listening cep and clear
			 * information on related listener.
			 */
			siw_cep_put(cep->listen_cep);
			cep->listen_cep = NULL;

			siw_socket_disassoc(cep->llp.sock);
			sock_release(cep->llp.sock);
			cep->llp.sock = NULL;

			cep->state = SIW_EPSTATE_CLOSED;
			siw_cep_put(cep);
		}
	}
}


static void siw_proc_mpareply(struct siw_cep *cep)
{
	struct siw_qp_attrs	qp_attrs;
	struct siw_qp		*qp = cep->qp;
	int			rv;

	rv = siw_recv_mpa_rr(cep);
	if (rv == -EAGAIN)
		/* incomplete mpa reply */
		return;

	if (rv)
		goto error;

	if (cep->mpa.hdr.params.rev > MPA_REVISION_1) {
		/* allow for 0 and 1 only */
		rv = -EPROTO;
		goto error;
	}
	if (memcmp(cep->mpa.hdr.key, MPA_KEY_REP, sizeof cep->mpa.hdr.key)) {
		rv = -EPROTO;
		goto error;
	}
	/*
	 * TODO: 1. handle eventual MPA reject (upcall with ECONNREFUSED)
	 *       2. finish mpa parameter check/negotiation
	 */
	memset(&qp_attrs, 0, sizeof qp_attrs);
	qp_attrs.mpa.marker_rcv = 0;
	qp_attrs.mpa.marker_snd = 0;
	qp_attrs.mpa.crc = CONFIG_RDMA_SIW_CRC_ENFORCED;
	qp_attrs.mpa.version = 1;
	qp_attrs.ird = cep->ird;
	qp_attrs.ord = cep->ord;
	qp_attrs.llp_stream_handle = cep->llp.sock;
	qp_attrs.state = SIW_QP_STATE_RTS;

	/* Move socket RX/TX under QP control */
	down_write(&qp->state_lock);
	if (qp->attrs.state > SIW_QP_STATE_RTR) {
		rv = -EINVAL;
		up_write(&qp->state_lock);
		goto error;
	}
	rv = siw_qp_modify(qp, &qp_attrs, SIW_QP_ATTR_STATE|
					       SIW_QP_ATTR_LLP_HANDLE|
					       SIW_QP_ATTR_ORD|
					       SIW_QP_ATTR_IRD|
					       SIW_QP_ATTR_MPA);

	if (!rv) {
		cep->state = SIW_EPSTATE_RDMA_MODE;
		siw_cm_upcall(cep, IW_CM_EVENT_CONNECT_REPLY,
			      IW_CM_EVENT_STATUS_OK);

		up_write(&qp->state_lock);
		return;
	}
	up_write(&qp->state_lock);
error:
	/*
	 * failed socket handover returns responsibility:
	 * inform iwcm and drop connection
	 * TODO: 1. send MPA reject for MPA rev==1
	 *	    if rv != ECONNREFUSED
	 */
	siw_cm_upcall(cep, IW_CM_EVENT_CONNECT_REPLY, rv);

	if (!siw_cep_in_close(cep)) {

		cep->cm_id->rem_ref(cep->cm_id);
		cep->cm_id = NULL;
		siw_cep_put(cep);

		siw_socket_disassoc(cep->llp.sock);
		sock_release(cep->llp.sock);
		cep->llp.sock = NULL;

		cep->qp = NULL;
		siw_qp_put(cep->qp);
	}
	cep->state = SIW_EPSTATE_CLOSED;
}

/*
 * siw_accept_newconn - accept an incoming pending connection
 *
 */
static void siw_accept_newconn(struct siw_cep *cep)
{
	struct socket		*s = cep->llp.sock;
	struct socket		*new_s = NULL;
	struct siw_cep		*new_cep = NULL;
	int			rv = 0; /* debug only. should disappear */

	new_cep = siw_cep_alloc();
	if (!new_cep)
		goto error;

	if (siw_cm_alloc_work(new_cep, 4) != 0)
		goto error;

	/*
	 * Copy saved socket callbacks from listening CEP
	 * and assign new socket with new CEP
	 */
	new_cep->sk_state_change = cep->sk_state_change;
	new_cep->sk_data_ready   = cep->sk_data_ready;
	new_cep->sk_write_space  = cep->sk_write_space;
	new_cep->sk_error_report = cep->sk_error_report;

	rv = kernel_accept(s, &new_s, O_NONBLOCK);
	if (rv != 0) {
		/*
		 * TODO: Already aborted by peer?
		 * Is there anything we should do?
		 */
		dprint(DBG_CM|DBG_ON, "(cep=0x%p): ERROR: "
			"kernel_accept(): rv=%d\n", cep, rv);
		goto error;
	}
	new_cep->llp.sock = new_s;
	siw_cep_get(new_cep);
	new_s->sk->sk_user_data = new_cep;

	dprint(DBG_CM, "(cep=0x%p, s=0x%p, new_s=0x%p): "
		"New LLP connection accepted\n", cep, s, new_s);

	rv = siw_sock_nodelay(new_s);
	if (rv != 0) {
		dprint(DBG_CM|DBG_ON, "(cep=0x%p): ERROR: "
			"siw_sock_nodelay(): rv=%d\n", cep, rv);
		goto error;
	}

	rv = kernel_peername(new_s, &new_cep->llp.raddr);
	if (rv != 0) {
		dprint(DBG_CM|DBG_ON, "(cep=0x%p): ERROR: "
			"kernel_peername(): rv=%d\n", cep, rv);
		goto error;
	}
	rv = kernel_localname(new_s, &new_cep->llp.laddr);
	if (rv != 0) {
		dprint(DBG_CM|DBG_ON, "(cep=0x%p): ERROR: "
			"kernel_localname(): rv=%d\n", cep, rv);
		goto error;
	}

	/*
	 * See siw_proc_mpareq() etc. for the use of new_cep->listen_cep.
	 */
	new_cep->listen_cep = cep;
	siw_cep_get(cep);

	new_cep->state = SIW_EPSTATE_AWAIT_MPAREQ;

	rv = siw_skb_queue_datalen(&new_s->sk->sk_receive_queue);
	if (rv > 0) {
		/*
		 * MPA REQ already queued
		 */
		dprint(DBG_CM, "(cep=0x%p): new sock has %d bytes\n", cep, rv);

		siw_proc_mpareq(new_cep);

	}
	return;

error:
	if (new_cep)
		siw_cep_put(new_cep);

	if (new_s) {
		siw_socket_disassoc(new_s);
		sock_release(new_s);
	}
	dprint(DBG_CM|DBG_ON, "(cep=0x%p): ERROR: rv=%d\n", cep, rv);
}

/*
 * Expects params->pd_len in host byte order
 *
 * TODO: We might want to combine the arguments params and pdata to a single
 * pointer to a struct siw_mpa_info as defined in siw_cm.h.
 * This way, all private data parameters would be in a common struct.
 */
static int siw_send_mpareqrep(struct socket *s, struct mpa_rr_params *params,
				char *key, char *pdata)
{
	struct mpa_rr	hdr;
	struct kvec	iov[2];
	struct msghdr	msg;

	int		rv;
	unsigned short 	pd_len = params->pd_len;

	memset(&msg, 0, sizeof(msg));
	memset(&hdr, 0, sizeof hdr);
	memcpy(hdr.key, key, 16);

	/*
	 * TODO: By adding a union to struct mpa_rr_params, it should be
	 * possible to replace the next 4 statements by one
	 */
	hdr.params.r = params->r;
	hdr.params.c = params->c;
	hdr.params.m = params->m;
	hdr.params.rev = params->rev;

	if (pd_len > MPA_MAX_PRIVDATA)
		return -EINVAL;

	hdr.params.pd_len = htons(pd_len);

	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof hdr;

	if (pd_len) {
		iov[1].iov_base = pdata;
		iov[1].iov_len = pd_len;

		rv =  kernel_sendmsg(s, &msg, iov, 2, pd_len + sizeof hdr);
	} else
		rv =  kernel_sendmsg(s, &msg, iov, 1, sizeof hdr);

	return rv < 0 ? rv : 0;
}

/*
 * siw_cm_upcall()
 *
 * Upcall to IWCM to inform about async connection events
 */
int siw_cm_upcall(struct siw_cep *cep, enum iw_cm_event_type reason,
			    enum iw_cm_event_status status)
{
	struct iw_cm_event	event;
	struct iw_cm_id 	*cm_id;

	memset(&event, 0, sizeof event);
	event.status = status;
	event.event = reason;

	if (cep->mpa.hdr.params.pd_len != 0) {
		/*
		 * hand over MPA private data
		 */
		event.private_data_len = cep->mpa.hdr.params.pd_len;
		event.private_data = cep->mpa.pdata;
		cep->mpa.hdr.params.pd_len = 0;

#ifdef OFED_PRIVATE_DATA_BY_REFERENCE
		/*
		 * The cm_id->event_handler() is called in process
		 * context below. Since we allocated a private data
		 * buffer already, it would make sense to transfer the
		 * ownership of this buffer to cm_id->event_handler()
		 * instead of doing another copy at the iwcm.
		 * This would require a change to
		 * infiniband/drivers/core/iwcm.c::cm_event_handler().
		 */
		cep->mpa.pdata = NULL;
#endif /* OFED_PRIVATE_DATA_BY_REFERENCE */
	}
	if (reason == IW_CM_EVENT_CONNECT_REQUEST ||
	    reason == IW_CM_EVENT_CONNECT_REPLY) {
		event.local_addr = cep->llp.laddr;
		event.remote_addr = cep->llp.raddr;
	}
	if (reason == IW_CM_EVENT_CONNECT_REQUEST) {
		event.provider_data = cep;
		cm_id = cep->listen_cep->cm_id;
	} else
		cm_id = cep->cm_id;

	dprint(DBG_CM, " (QP%d): cep=0x%p, id=0x%p, dev(id)=%s, "
		"reason=%d, status=%d\n",
		cep->qp ? QP_ID(cep->qp) : -1, cep, cm_id,
		cm_id->device->name, reason, status);

	return cm_id->event_handler(cm_id, &event);
}

static void siw_cm_work_handler(struct work_struct *w)
{
	struct siw_cm_work	*work;
	struct siw_cep		*cep;
	int rv;

	work = container_of(w, struct siw_cm_work, work);
	cep = work->cep;

	dprint(DBG_CM, " (QP%d): WORK type: %d, CEP: 0x%p\n",
		cep->qp ? QP_ID(cep->qp) : -1, work->type, cep);

	switch (work->type) {

	case SIW_CM_WORK_ACCEPT:

		rv = siw_cep_set_inuse(cep);
		if (rv > 0) {
			if (cep->state == SIW_EPSTATE_LISTENING)
				siw_accept_newconn(cep);

			if (!siw_cep_set_free(cep)) {
				siw_cm_release(cep);
				siw_cep_put(cep);
			}
			break;
		}
		/*
		 * CEP already scheduled for closing
		 */
		if (!rv) {
			siw_cm_release(cep);
			(void) siw_cep_set_free(cep);
		}
		break;

	case SIW_CM_WORK_READ_MPAHDR:

		rv = siw_cep_set_inuse(cep);
		if (rv > 0) {
			switch (cep->state) {

			case SIW_EPSTATE_AWAIT_MPAREQ:

				siw_proc_mpareq(cep);
				break;

			case SIW_EPSTATE_AWAIT_MPAREP:

				siw_proc_mpareply(cep);
				break;

			default:
				/*
				 * CEP already moved out of MPA handshake.
				 * any connection management already done.
				 * silently ignore the mpa packet.
				 */
				dprint(DBG_CM, "(): CEP not in MPA "
					"handshake state: %d\n", cep->state);
			}
			if (!siw_cep_set_free(cep))
				siw_cm_release(cep);

			break;
		}
		/*
		 * CEP already scheduled for closing
		 */
		if (!rv) {
			siw_cm_release(cep);
			(void) siw_cep_set_free(cep);
		}
		break;

	case SIW_CM_WORK_CLOSE_LLP:
		/*
		 * QP scheduled LLP close
		 */
		dprint(DBG_CM, "(): SIW_CM_WORK_CLOSE_LLP, cep->state=%d\n",
			cep->state);

		cep->state = SIW_EPSTATE_CLOSED;

		if (cep->llp.sock) {
			siw_socket_disassoc(cep->llp.sock);
			sock_release(cep->llp.sock);
			cep->llp.sock = NULL;
		}
		if (cep->qp) {
			siw_qp_llp_close(cep->qp);
			siw_qp_put(cep->qp);
			cep->qp = NULL;
		}
		if (cep->cm_id) {
			siw_cm_upcall(cep, IW_CM_EVENT_CLOSE,
				      IW_CM_EVENT_STATUS_OK);

			cep->cm_id->rem_ref(cep->cm_id);
			cep->cm_id = NULL;
			siw_cep_put(cep);
		}
		break;

	case SIW_CM_WORK_PEER_CLOSE:

		dprint(DBG_CM, "(): SIW_CM_WORK_PEER_CLOSE, "
			"cep->state=%d\n", cep->state);

		if (cep->cm_id) {
			switch (cep->state) {

			case SIW_EPSTATE_AWAIT_MPAREP:
				/*
				 * MPA reply not received, but connection drop
				 */
				siw_cm_upcall(cep, IW_CM_EVENT_CONNECT_REPLY,
						-ECONNRESET);
				break;

			case SIW_EPSTATE_RDMA_MODE:
				/*
				 * NOTE: IW_CM_EVENT_DISCONNECT is given just
				 *       to transition IWCM into CLOSING.
				 *       FIXME: is that needed?
				 */
				siw_cm_upcall(cep, IW_CM_EVENT_DISCONNECT,
					      IW_CM_EVENT_STATUS_OK);
				siw_cm_upcall(cep, IW_CM_EVENT_CLOSE,
					      IW_CM_EVENT_STATUS_OK);

				break;

			default:

				break;
				/*
				 * for these states there is no connection
				 * known to the IWCM. Even not for
				 * SIW_EPSTATE_RECVD_MPAREQ.
				 */
			}
			cep->cm_id->rem_ref(cep->cm_id);
			cep->cm_id = NULL;
			siw_cep_put(cep);
		}
		if (cep->qp) {
			siw_qp_llp_close(cep->qp);
			siw_qp_put(cep->qp);
			cep->qp = NULL;
		}
		if (cep->state != SIW_EPSTATE_CLOSED) {
			cep->state = SIW_EPSTATE_CLOSED;
			siw_socket_disassoc(cep->llp.sock);
			sock_release(cep->llp.sock);
			cep->llp.sock = NULL;
		}

		break;

	default:
		BUG();
	}
	dprint(DBG_CM, " (Exit): WORK type: %d, CEP: 0x%p\n", work->type, cep);
	siw_put_work(work);
	siw_cep_put(cep);
}

int siw_cm_queue_work(struct siw_cep *cep, enum siw_work_type type)
{
	struct siw_cm_work *work = siw_get_work(cep);

	dprint(DBG_CM, " (QP%d): WORK type: %d, CEP: 0x%p\n",
		cep->qp ? QP_ID(cep->qp) : -1, type, cep);

	if (!work) {
		dprint(DBG_ON, " Failed\n");
		return -ENOMEM;
	}
	work->type = type;
	work->cep = cep;

	siw_cep_get(cep);

	INIT_WORK(&work->work, siw_cm_work_handler);
	queue_work(siw_cm_wq, &work->work);

	return 0;
}


static void siw_cm_llp_data_ready(struct sock *sk, int flags)
{
	struct siw_cep	*cep;

	read_lock(&sk->sk_callback_lock);

	cep = sk_to_cep(sk);
	if (!cep) {
		WARN_ON(1);
		goto out;
	}

	if (cep->conn_close)
		goto out;

	dprint(DBG_CM, "(): cep 0x%p, state: %d, flags %x\n", cep,
		cep->state, flags);

	switch (cep->state) {

	case SIW_EPSTATE_RDMA_MODE:
	case SIW_EPSTATE_LISTENING:

		break;

	case SIW_EPSTATE_AWAIT_MPAREQ:
	case SIW_EPSTATE_AWAIT_MPAREP:

		siw_cm_queue_work(cep, SIW_CM_WORK_READ_MPAHDR);
		break;

	default:
		dprint(DBG_CM, "(): Unexpected DATA, state %d\n", cep->state);
		break;
	}
out:
	read_unlock(&sk->sk_callback_lock);
}

static void siw_cm_llp_write_space(struct sock *sk)
{
	struct siw_cep	*cep = sk_to_cep(sk);

	if (cep)
		dprint(DBG_CM, "(): cep: 0x%p, state: %d\n", cep, cep->state);
}

static void siw_cm_llp_error_report(struct sock *sk)
{
	struct siw_cep	*cep = sk_to_cep(sk);

	dprint(DBG_CM, "(): error: %d, state: %d\n", sk->sk_err, sk->sk_state);

	if (cep) {
		cep->sk_error = sk->sk_err;
		dprint(DBG_CM, "(): cep->state: %d\n", cep->state);
		cep->sk_error_report(sk);
	}
}

static void siw_cm_llp_state_change(struct sock *sk)
{
	struct siw_cep	*cep;
	struct socket 	*s;
	void (*orig_state_change)(struct sock *);


	read_lock(&sk->sk_callback_lock);

	cep = sk_to_cep(sk);
	if (!cep) {
		WARN_ON(1);
		read_unlock(&sk->sk_callback_lock);
		return;
	}
	orig_state_change = cep->sk_state_change;

	s = sk->sk_socket;

	dprint(DBG_CM, "(): cep: 0x%p, state: %d\n", cep, cep->state);

	switch (sk->sk_state) {

	case TCP_ESTABLISHED:
		/*
		 * handle accepting socket as special case where only
		 * new connection is possible
		 */
		if (cep->conn_close)
			break;

		if (cep->state == SIW_EPSTATE_LISTENING &&
			siw_cm_queue_work(cep, SIW_CM_WORK_ACCEPT) != 0) {
				dprint(DBG_ON, "Cannot accept\n");
		}
		break;

	case TCP_CLOSE:
	case TCP_CLOSE_WAIT:
		if (cep->state <= SIW_EPSTATE_LISTENING) {
			dprint(DBG_CM, "() Close before accept()\n");
			break;
		}
		if (cep->qp)
			cep->qp->tx_info.tx_suspend = 1;

		if (!siw_cep_in_close(cep))
			siw_cm_queue_work(cep, SIW_CM_WORK_PEER_CLOSE);

		break;

	default:
		dprint(DBG_CM, "Unexpected sock state %d\n", sk->sk_state);
	}
	read_unlock(&sk->sk_callback_lock);
	orig_state_change(sk);
}


static int kernel_bindconnect(struct socket *s,
			      struct sockaddr *laddr, int laddrlen,
			      struct sockaddr *raddr, int raddrlen, int flags)
{
	int err, s_val = 1;
	/*
	 * XXX
	 * Tentative fix. Should not be needed but sometimes iwcm
	 * chooses ports in use
	 */
	err = kernel_setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&s_val,
				sizeof s_val);
	if (err < 0)
		goto done;

	err = s->ops->bind(s, laddr, laddrlen);
	if (err < 0)
		goto done;

	err = s->ops->connect(s, raddr, raddrlen, flags);
	if (err < 0)
		goto done;

	err = s->ops->getname(s, laddr, &s_val, 0);

done:
	return err;
}


int siw_connect(struct iw_cm_id *id, struct iw_cm_conn_param *params)
{
	struct siw_dev	*dev = siw_dev_ofa2siw(id->device);
	struct siw_qp	*qp;
	struct siw_cep	*cep = NULL;
	struct socket 	*s = NULL;
	struct sockaddr	*laddr, *raddr;

	u16		pd_len = params->private_data_len;
	int 		rv, size;

	if (pd_len > MPA_MAX_PRIVDATA)
		return -EINVAL;

	qp = siw_qp_id2obj(dev, params->qpn);
	BUG_ON(!qp);

	dprint(DBG_CM, "(id=0x%p, QP%d): dev(id)=%s, l2dev=%s\n",
		id, QP_ID(qp), dev->ofa_dev.name, dev->l2dev->name);
	dprint(DBG_CM, "(id=0x%p, QP%d): laddr=(0x%x,%d), raddr=(0x%x,%d)\n",
		id, QP_ID(qp),
		ntohl(id->local_addr.sin_addr.s_addr),
		ntohs(id->local_addr.sin_port),
		ntohl(id->remote_addr.sin_addr.s_addr),
		ntohs(id->remote_addr.sin_port));

	down_write(&qp->state_lock);
	if (qp->attrs.state > SIW_QP_STATE_RTR) {
		rv = -EINVAL;
		goto error;
	}

	laddr = (struct sockaddr *)&id->local_addr;
	raddr = (struct sockaddr *)&id->remote_addr;

	rv = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &s);
	if (rv < 0)
		goto error;

	size = SOCKBUFSIZE;
	rv = kernel_setsockopt(s, SOL_SOCKET, SO_SNDBUF, (char *)&size,
			       sizeof size);
	if (rv < 0)
		goto error;

	rv = kernel_setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *)&size,
			       sizeof size);
	if (rv < 0)
		goto error;

	/*
	 * NOTE: For simplification, connect() is called in blocking
	 * mode. Might be reconsidered for async connection setup at
	 * TCP level.
	 */
	rv = kernel_bindconnect(s, laddr, sizeof *laddr, raddr,
				sizeof *raddr, 0);
	if (rv != 0) {
		dprint(DBG_CM, "(id=0x%p, QP%d): kernel_bindconnect: rv=%d\n",
			id, QP_ID(qp), rv);
		goto error;
	}
	rv = siw_sock_nodelay(s);
	if (rv != 0) {
		dprint(DBG_CM, "(id=0x%p, QP%d): siw_sock_nodelay(): rv=%d\n",
			id, QP_ID(qp), rv);
		goto error;
	}
	cep = siw_cep_alloc();
	if (!cep) {
		rv =  -ENOMEM;
		goto error;
	}

	/* Associate QP with CEP */
	siw_cep_get(cep);
	qp->cep = cep;

	/* siw_qp_get(qp) already done by QP lookup */
	cep->qp = qp;

	id->add_ref(id);
	cep->cm_id = id;

	rv = siw_cm_alloc_work(cep, 4);
	if (rv != 0) {
		rv = -ENOMEM;
		goto error;
	}
	cep->mpa.hdr.params.pd_len = pd_len;
	cep->ird = params->ird;
	cep->ord = params->ord;
	cep->state = SIW_EPSTATE_CONNECTING;

	rv = kernel_peername(s, &cep->llp.raddr);
	if (rv)
		goto error;

	rv = kernel_localname(s, &cep->llp.laddr);
	if (rv)
		goto error;

	dprint(DBG_CM, "(id=0x%p, QP%d): pd_len = %u\n", id, QP_ID(qp), pd_len);
	if (pd_len) {
		dprint_mem(DBG_CM, "private_data",
				(unsigned char *)params->private_data, pd_len,
				"(id=0x%p, QP%d): ", id, QP_ID(qp));
	}
	/*
	 * Associate CEP with socket
	 */
	siw_cep_socket_assoc(cep, s);

	cep->state = SIW_EPSTATE_AWAIT_MPAREP;

	rv = siw_send_mpareqrep(cep->llp.sock, &cep->mpa.hdr.params,
				MPA_KEY_REQ, (char *)params->private_data);

	/*
	 * Reset private data len: in case connection drops w/o peer
	 * sending MPA reply we would report stale data pointer during
	 * IW_CM_EVENT_CONNECT_REPLY.
	 */
	cep->mpa.hdr.params.pd_len = 0;

	if (rv >= 0) {
		dprint(DBG_CM, "(id=0x%p, QP%d): Exit\n", id, QP_ID(qp));

		up_write(&qp->state_lock);
		return 0;
	}
error:
	up_write(&qp->state_lock);

	dprint(DBG_ON, " Failed: %d\n", rv);

	if (cep && !siw_cep_in_close(cep)) {

		siw_socket_disassoc(s);
		sock_release(s);
		cep->llp.sock = NULL;

		cep->qp = NULL;

		cep->cm_id = NULL;
		id->rem_ref(id);
		siw_cep_put(cep);

		qp->cep = NULL;
		siw_cep_put(cep);

		cep->state = SIW_EPSTATE_CLOSED;
	} else if (!cep && s)
		sock_release(s);

	siw_qp_put(qp);

	return rv;
}

/*
 * siw_accept - Let SoftiWARP accept an RDMA connection request
 *
 * @id:		New connection management id to be used for accepted
 *		connection request
 * @params:	Connection parameters provided by ULP for accepting connection
 *
 * Transition QP to RTS state, associate new CM id @id with accepted CEP
 * and get prepared for TCP input by installing socket callbacks.
 * Then send MPA Reply and generate the "connection established" event.
 * Socket callbacks must be installed before sending MPA Reply, because
 * the latter may cause a first RDMA message to arrive from the RDMA Initiator
 * side very quickly, at which time the socket callbacks must be ready.
 */
int siw_accept(struct iw_cm_id *id, struct iw_cm_conn_param *params)
{
	struct siw_dev		*dev = siw_dev_ofa2siw(id->device);
	struct siw_cep		*cep = (struct siw_cep *)id->provider_data;
	struct siw_qp		*qp;
	struct siw_qp_attrs	qp_attrs;
	char			*pdata = NULL;
	int 			rv;

retry:
	rv = siw_cep_set_inuse(cep);
	if (rv < 0) {
		dprint(DBG_CM, "(id=0x%p, cep=0x%p): CEP in use\n",
			id, cep);
		wait_event(cep->waitq, !cep->in_use);
		goto retry;
	}
	if (!rv) {
		dprint(DBG_CM, "(id=0x%p, cep=0x%p): CEP in close\n",
			id, cep);
		(void) siw_cep_set_free(cep);
		return -EINVAL;
	}
	if (cep->state != SIW_EPSTATE_RECVD_MPAREQ) {
		if (cep->state == SIW_EPSTATE_CLOSED) {

			dprint(DBG_CM, "(id=0x%p): Out of State\n", id);
			(void) siw_cep_set_free(cep);

			siw_cep_put(cep);
			return -ECONNRESET;
		}
		BUG();
	}
	/* clear iwcm reference to CEP from IW_CM_EVENT_CONNECT_REQUEST */
	siw_cep_put(cep);

	qp = siw_qp_id2obj(dev, params->qpn);
	BUG_ON(!qp); /* The OFA core should prevent this */

	down_write(&qp->state_lock);
	if (qp->attrs.state > SIW_QP_STATE_RTR) {
		rv = -EINVAL;
		goto unlock;
	}

	dprint(DBG_CM, "(id=0x%p, QP%d): dev(id)=%s\n",
		id, QP_ID(qp), dev->ofa_dev.name);

	if (params->ord > qp->attrs.ord || params->ird > qp->attrs.ird) {
		dprint(DBG_CM|DBG_ON, "(id=0x%p, QP%d): "
			"ORD: %d (max: %d), IRD: %d (max: %d)\n",
			id, QP_ID(qp),
			params->ord, qp->attrs.ord,
			params->ird, qp->attrs.ird);
		rv = -EINVAL;
		goto unlock;
	}
	if (params->private_data_len > MPA_MAX_PRIVDATA) {
		dprint(DBG_CM|DBG_ON, "(id=0x%p, QP%d): "
			"Private data too long: %d (max: %d)\n",
			id, QP_ID(qp),
			params->private_data_len, MPA_MAX_PRIVDATA);
		rv =  -EINVAL;
		goto unlock;
	}
	cep->cm_id = id;
	id->add_ref(id);

	memset(&qp_attrs, 0, sizeof qp_attrs);
	qp_attrs.ord = params->ord;
	qp_attrs.ird = params->ird;
	qp_attrs.llp_stream_handle = cep->llp.sock;

	/*
	 * TODO: Add MPA negotiation
	 */
	qp_attrs.mpa.marker_rcv = 0;
	qp_attrs.mpa.marker_snd = 0;
	qp_attrs.mpa.crc = CONFIG_RDMA_SIW_CRC_ENFORCED;
	qp_attrs.mpa.version = 0;
	qp_attrs.state = SIW_QP_STATE_RTS;

	dprint(DBG_CM, "(id=0x%p, QP%d): Moving to RTS\n", id, QP_ID(qp));

	/* Associate QP with CEP */
	siw_cep_get(cep);
	qp->cep = cep;

	/* siw_qp_get(qp) already done by QP lookup */
	cep->qp = qp;

	cep->state = SIW_EPSTATE_RDMA_MODE;

	/* Move socket RX/TX under QP control */
	rv = siw_qp_modify(qp, &qp_attrs, SIW_QP_ATTR_STATE|
					  SIW_QP_ATTR_LLP_HANDLE|
					  SIW_QP_ATTR_ORD|
					  SIW_QP_ATTR_IRD|
					  SIW_QP_ATTR_MPA);
	up_write(&qp->state_lock);

	if (rv)
		goto error;


	/*
	 * TODO: It might be more elegant and concise to check the
	 * private data length cep->mpa.hdr.params.pd_len
	 * inside siw_send_mpareqrep().
	 */
	if (params->private_data_len) {
		pdata = (char *)params->private_data;

		dprint_mem(DBG_CM, "private_data",
				pdata, params->private_data_len,
				"(id=0x%p, QP%d): ", id, QP_ID(qp));
	}
	cep->mpa.hdr.params.pd_len = params->private_data_len;

	dprint(DBG_CM, "(id=0x%p, QP%d): Sending MPA Reply\n", id, QP_ID(qp));

	rv = siw_send_mpareqrep(cep->llp.sock, &cep->mpa.hdr.params,
				MPA_KEY_REP, pdata);
	if (!rv) {
		/*
		 * FIXME: In order to ensure that the first FPDU will be sent
		 * from the RDMA Initiator side, the "connection established"
		 * event should be delayed until Softiwarp has received the
		 * first FPDU from the RDMA Initiator side.
		 * Alternatively, Softiwarp could prevent this side to
		 * send a first FPDU until a first FPDU has been received.
		 *
		 * The two alternatives above will work if
		 * (1) the RDMA application is iWARP standards compliant
		 *     by sending its first RDMA payload from the
		 *     RDMA Initiator side, or
		 * (2) the RDMA Initiator side RNIC inserts an under-cover
		 *     zero-length RDMA operation (negotiated through an
		 *     extended MPA Request/Reply handshake) such as a
		 *     zero-length RDMA Write or Read.
		 * Note that (2) would require an extension of the MPA RFC.
		 *
		 * A third alternative (which may be the easiest for now) is to
		 * return an error to an RDMA application that attempts to send
		 * the first RDMA payload from the RDMA Responder side.
		 */
		siw_cm_upcall(cep, IW_CM_EVENT_ESTABLISHED,
				IW_CM_EVENT_STATUS_OK);

		if (!siw_cep_set_free(cep))
			siw_cm_release(cep);

		dprint(DBG_CM, "(id=0x%p, QP%d): Exit\n", id, QP_ID(qp));
		return 0;
	}

error:
	if (siw_cep_set_free(cep)) {

		siw_socket_disassoc(cep->llp.sock);
		sock_release(cep->llp.sock);
		cep->llp.sock = NULL;

		cep->state = SIW_EPSTATE_CLOSED;

		cep->cm_id->rem_ref(id);
		cep->cm_id = NULL;

		if (qp->cep) {
			siw_cep_put(cep);
			qp->cep = NULL;
		}
		cep->qp = NULL;
		siw_qp_put(qp);
	}
	return rv;
unlock:
	up_write(&qp->state_lock);
	goto error;
}

/*
 * siw_reject()
 *
 * Local connection reject case. Send private data back to peer,
 * close connection and dereference connection id.
 */
int siw_reject(struct iw_cm_id *id, const void *pdata, u8 plen)
{
	struct siw_cep	*cep = (struct siw_cep *)id->provider_data;
	struct siw_dev	*dev = siw_dev_ofa2siw(id->device);

	dprint(DBG_CM, "(id=0x%p): dev(id)=%s, cep->state=%d\n",
		id, dev->ofa_dev.name, cep->state);


	dprint(DBG_CM, " Reject: %s\n", plen ? (char *)pdata:"(no data)");

	if (!siw_cep_in_close(cep)) {

		dprint(DBG_ON, " Sending REJECT not yet implemented\n");

		siw_socket_disassoc(cep->llp.sock);
		sock_release(cep->llp.sock);
		cep->llp.sock = NULL;

		siw_cep_put(cep);
		cep->state = SIW_EPSTATE_CLOSED;
	} else {
		dprint(DBG_CM, " (id=0x%p): Connection lost\n", id);
	}

	/*
	 * clear iwcm reference to CEP from
	 * IW_CM_EVENT_CONNECT_REQUEST
	 */
	siw_cep_put(cep);

	return 0;
}

int siw_listen_address(struct iw_cm_id *id, int backlog, struct sockaddr *laddr)
{
	struct ib_device	*ofa_dev = id->device;
	struct siw_dev		*dev = siw_dev_ofa2siw(ofa_dev);
	struct socket 		*s;
	struct siw_cep		*cep = NULL;
	int 			rv = 0, s_val;

	rv = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &s);
	if (rv < 0) {
		dprint(DBG_CM|DBG_ON, "(id=0x%p): ERROR: "
			"sock_create(): rv=%d\n", id, rv);
		return rv;
	}
#ifdef SIW_ON_BGP
	if (backlog >= 100 && backlog < 4096)
		backlog = 4096;
#endif

	s_val = SOCKBUFSIZE;
	rv = kernel_setsockopt(s, SOL_SOCKET, SO_SNDBUF, (char *)&s_val,
			       sizeof s_val);
	if (rv)
		goto error;

	rv = kernel_setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *)&s_val,
			       sizeof s_val);
	if (rv)
		goto error;

	/*
	 * Probably to be removed later. Allows binding
	 * local port when still in TIME_WAIT from last close.
	 */
	s_val = 1;
	rv = kernel_setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&s_val,
			       sizeof s_val);
	if (rv != 0) {
		dprint(DBG_CM|DBG_ON, "(id=0x%p): ERROR: "
			"kernel_setsockopt(): rv=%d\n", id, rv);
		goto error;
	}

	rv = s->ops->bind(s, laddr, sizeof *laddr);
	if (rv != 0) {
		dprint(DBG_CM|DBG_ON, "(id=0x%p): ERROR: bind(): rv=%d\n",
			id, rv);
		goto error;
	}

	cep = siw_cep_alloc();
	if (!cep) {
		rv = -ENOMEM;
		goto error;
	}
	siw_cep_socket_assoc(cep, s);

	rv = siw_cm_alloc_work(cep, backlog);
	if (rv != 0) {
		dprint(DBG_CM|DBG_ON, "(id=0x%p): ERROR: "
			"siw_cm_alloc_work(backlog=%d): rv=%d\n",
			id, backlog, rv);
		goto error;
	}

	rv = s->ops->listen(s, backlog);
	if (rv != 0) {
		dprint(DBG_CM|DBG_ON, "(id=0x%p): ERROR: listen() rv=%d\n",
			id, rv);
		goto error;
	}

	/*
	 * TODO: Do we really need the copies of local_addr and remote_addr
	 *	 in CEP ???
	 */
	memcpy(&cep->llp.laddr, &id->local_addr, sizeof cep->llp.laddr);
	memcpy(&cep->llp.raddr, &id->remote_addr, sizeof cep->llp.raddr);

	cep->cm_id = id;
	id->add_ref(id);

	/*
	 * In case of a wildcard rdma_listen on a multi-homed device,
	 * a listener's IWCM id is associated with more than one listening CEP.
	 *
	 * We currently use id->provider_data in three different ways:
	 *
	 * o For a listener's IWCM id, id->provider_data points to
	 *   the list_head of the list of listening CEPs.
	 *   Uses: siw_create_listen(), siw_destroy_listen()
	 *
	 * o For a passive-side IWCM id, id->provider_data points to
	 *   the CEP itself. This is a consequence of
	 *   - siw_cm_upcall() setting event.provider_data = cep and
	 *   - the IWCM's cm_conn_req_handler() setting provider_data of the
	 *     new passive-side IWCM id equal to event.provider_data
	 *   Uses: siw_accept(), siw_reject()
	 *
	 * o For an active-side IWCM id, id->provider_data is not used at all.
	 *
	 */
	if (!id->provider_data) {
		id->provider_data = kmalloc(sizeof(struct list_head),
					    GFP_KERNEL);
		if (!id->provider_data) {
			rv = -ENOMEM;
			goto error;
		}
		INIT_LIST_HEAD((struct list_head *)id->provider_data);
	}

	dprint(DBG_CM, "(id=0x%p): dev(id)=%s, l2dev=%s, "
		"id->provider_data=0x%p, cep=0x%p\n",
		id, ofa_dev->name, dev->l2dev->name,
		id->provider_data, cep);

	list_add_tail(&cep->list, (struct list_head *)id->provider_data);
	cep->state = SIW_EPSTATE_LISTENING;
	return 0;

error:
	dprint(DBG_ON, " Failed: %d\n", rv);

	if (cep) {
		cep->llp.sock = NULL;
		siw_socket_disassoc(s);
		cep->state = SIW_EPSTATE_CLOSED;
		siw_cep_put(cep);
	}
	sock_release(s);
	return rv;
}


/*
 * siw_create_listen - Create resources for a listener's IWCM ID @id
 *
 * Listens on the socket addresses id->local_addr and id->remote_addr.
 * We support listening on multi-homed devices, i.e., Softiwarp devices
 * whose underlying net_device is associated with multiple IP addresses.
 * Wildcard listening (listening with zero IP address) is also supported.
 *
 * There are three design options for Softiwarp device management supporting
 * - multiple physical Ethernet ports, i.e., multiple net_device instances, and
 * - multiple IP addresses associated with net_device,
 * as follows:
 *
 *    Option 1: One Softiwarp device per net_device and
 *              IP address associated with the net_device
 *    Option 2: One Softiwarp device per net_device
 *              (and all IP addresses associated with the net_device)
 *    Option 3: Single Softiwarp device for all net_device instances
 *              (and all IP addresses associated with these instances)
 *
 * We currently use Option 2, registering a separate siw_dev for
 * each net_device. Consequently, siw_create_listen() (called separately
 * by the IWCM for each Softiwarp device) handles the associated IP address(es)
 * as follows:
 *
 * - If the listener's @id provides a specific local IP address, at most one
 *   listening socket is created and associated with @id.
 *
 * - If the listener's @id provides the wildcard (zero) local IP address,
 *   a separate listen is performed for each local IP address of the device
 *   by creating a listening socket and binding to that local IP address.
 *   This avoids attempts to bind to the wildcard (zero) IP address
 *   on multiple devices, which fails with -EADDRINUSE on the second and
 *   all subsequent devices.
 *
 *   For the given IWCM and Option 2 above, the alternative approach of doing
 *   a single wildcard listen by creating one listening socket and binding it
 *   to the wildcard IP address is not a good idea if
 *   - there is more than one Softiwarp device (e.g., for lo and eth0), or
 *   - there are non-Softiwarp iWARP devices that cannot cooperate.
 */
int siw_create_listen(struct iw_cm_id *id, int backlog)
{
	struct ib_device	*ofa_dev = id->device;
	struct siw_dev		*dev = siw_dev_ofa2siw(ofa_dev);
	int			rv = 0;

	dprint(DBG_CM, "(id=0x%p): dev(id)=%s, l2dev=%s backlog=%d\n",
		id, ofa_dev->name, dev->l2dev->name, backlog);

#ifdef SIW_ON_BGP
	if (backlog >= 100 && backlog < 8192)
		backlog = 8192;
#endif
	/*
	 * IPv4/v6 design differences regarding multi-homing
	 * propagate up to iWARP:
	 * o For IPv4, use dev->l2dev->ip_ptr
	 * o For IPv6, use dev->l2dev->ipv6_ptr
	 */
	if (id->local_addr.sin_family == AF_INET) {
		/* IPv4 */
		struct sockaddr_in	laddr = id->local_addr;
		u8			*l_ip, *r_ip;
		struct in_device 	*in_dev;

		l_ip = (u8 *) &id->local_addr.sin_addr.s_addr;
		r_ip = (u8 *) &id->remote_addr.sin_addr.s_addr;
		dprint(DBG_CM, "(id=0x%p): "
			"laddr(id)  : ipv4=%d.%d.%d.%d, port=%d; "
			"raddr(id)  : ipv4=%d.%d.%d.%d, port=%d\n",
			id,
			l_ip[0], l_ip[1], l_ip[2], l_ip[3],
			ntohs(id->local_addr.sin_port),
			r_ip[0], r_ip[1], r_ip[2], r_ip[3],
			ntohs(id->remote_addr.sin_port));

		in_dev = in_dev_get(dev->l2dev);
		if (!in_dev) {
			dprint(DBG_CM|DBG_ON, "(id=0x%p): "
				"l2dev has no in_device\n", id);
			return -ENODEV;
		}

		/*
		 * If in_dev is not configured, in_dev->ifa_list may be empty
		 */
		for_ifa(in_dev) {
			/*
			 * Create a listening socket if id->local_addr
			 * contains the wildcard IP address OR
			 * the IP address of the interface.
			 */
#ifdef KERNEL_VERSION_PRE_2_6_26
			if (ZERONET(id->local_addr.sin_addr.s_addr) ||
#else
			if (ipv4_is_zeronet(id->local_addr.sin_addr.s_addr) ||
#endif
					id->local_addr.sin_addr.s_addr ==
					ifa->ifa_address) {
				laddr.sin_addr.s_addr = ifa->ifa_address;

				l_ip = (u8 *) &laddr.sin_addr.s_addr;
				dprint(DBG_CM, "(id=0x%p): "
					"laddr(bind): ipv4=%d.%d.%d.%d,"
					" port=%d\n", id,
					l_ip[0], l_ip[1], l_ip[2],
					l_ip[3], ntohs(laddr.sin_port));

				rv = siw_listen_address(id, backlog,
						(struct sockaddr *)&laddr);
				if (rv)
					break;
			}
		}
		endfor_ifa(in_dev);
		in_dev_put(in_dev);

		if (rv) {
			/*
			 * TODO: Cleanup resources already associated with
			 *	 id->provider_data
			 */
			dprint(DBG_CM|DBG_ON, "(id=0x%p): "
				"TODO: Cleanup resources\n", id);
		}

	} else {
		/* IPv6 */
		dprint(DBG_CM|DBG_ON, "(id=0x%p): TODO: IPv6 support\n", id);
	}
	if (!rv)
		dprint(DBG_CM, "(id=0x%p): Success\n", id);

	return rv;
}


int siw_destroy_listen(struct iw_cm_id *id)
{
	struct ib_device	*ofa_dev = id->device;
	struct siw_dev		*dev = siw_dev_ofa2siw(ofa_dev);
	struct list_head	*p, *tmp;
	struct siw_cep		*cep;

	dprint(DBG_CM, "(id=0x%p): dev(id)=%s, l2dev=%s\n",
		id, ofa_dev->name, dev->l2dev->name);

	if (!id->provider_data) {
		/*
		 * TODO: See if there's a way to avoid getting any
		 *       listener ids without a list of CEPs
		 */
		dprint(DBG_CM, "(id=0x%p): Listener id: no CEP(s)\n", id);
		return 0;
	}

	/*
	 * In case of a wildcard rdma_listen on a multi-homed device,
	 * a listener's IWCM id is associated with more than one listening CEP.
	 */
	list_for_each_safe(p, tmp, (struct list_head *)id->provider_data) {

		cep = list_entry(p, struct siw_cep, list);
		list_del(p);

		if (siw_cep_set_inuse(cep) > 0) {

			cep->conn_close = 1;

			siw_socket_disassoc(cep->llp.sock);
			sock_release(cep->llp.sock);
			cep->llp.sock = NULL;
			id->rem_ref(id);

			cep->state = SIW_EPSTATE_CLOSED;
			/*
			 * Do not set the CEP free again. The CEP is dead.
			 * (void) siw_cep_set_free(cep);
			 */
		} else
			cep->state = SIW_EPSTATE_CLOSED;

		siw_cep_put(cep);
	}
	kfree(id->provider_data);
	id->provider_data = NULL;

	return 0;
}

int __init siw_cm_init(void)
{
	/*
	 * create_single_workqueue for strict ordering
	 */
	siw_cm_wq = create_singlethread_workqueue("siw_cm_wq");
	if (!siw_cm_wq)
		return -ENOMEM;

	return 0;
}

void __exit siw_cm_exit(void)
{
	if (siw_cm_wq) {
		flush_workqueue(siw_cm_wq);
		destroy_workqueue(siw_cm_wq);
	}
}

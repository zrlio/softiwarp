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
#include <linux/inetdevice.h>
#include <linux/workqueue.h>
#include <net/sock.h>
#include <linux/tcp.h>


#include <rdma/iw_cm.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_user_verbs.h>

#include "siw.h"
#include "siw_cm.h"
#include "siw_obj.h"

static bool mpa_crc_strict = 1;
module_param(mpa_crc_strict, bool, 0644);
static bool mpa_crc_required;
module_param(mpa_crc_required, bool, 0644);
static bool tcp_nodelay = 1;
module_param(tcp_nodelay, bool, 0644);

MODULE_PARM_DESC(mpa_crc_required, "MPA CRC required");
MODULE_PARM_DESC(mpa_crc_strict, "MPA CRC off enforced");
MODULE_PARM_DESC(tcp_nodelay, "Set TCP NODELAY");


/*
 * siw_sock_nodelay() - Disable Nagle algorithm
 */
static int siw_sock_nodelay(struct socket *sock)
{
	mm_segment_t oldfs;
	int rv, val = 1;

	val = tcp_nodelay ? 1 : 0;

	oldfs = get_fs();

	set_fs(KERNEL_DS);

	rv = sock->ops->setsockopt(sock, SOL_TCP, TCP_NODELAY,
				    (char __user *)&val, sizeof(val));
	set_fs(oldfs);
	return rv;
}

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

static void siw_sk_save_upcalls(struct sock *sk)
{
	struct siw_cep *cep = sk_to_cep(sk);
	BUG_ON(!cep);

	write_lock_bh(&sk->sk_callback_lock);
	cep->sk_state_change = sk->sk_state_change;
	cep->sk_data_ready   = sk->sk_data_ready;
	cep->sk_write_space  = sk->sk_write_space;
	cep->sk_error_report = sk->sk_error_report;
	write_unlock_bh(&sk->sk_callback_lock);
}

static void siw_sk_restore_upcalls(struct sock *sk, struct siw_cep *cep)
{
	sk->sk_state_change	= cep->sk_state_change;
	sk->sk_data_ready	= cep->sk_data_ready;
	sk->sk_write_space	= cep->sk_write_space;
	sk->sk_error_report	= cep->sk_error_report;
	sk->sk_user_data	= NULL;
	sk->sk_no_check		= 0;
}

static void siw_socket_disassoc(struct socket *s)
{
	struct sock	*sk = s->sk;
	struct siw_cep	*cep;

	if (sk) {
		write_lock_bh(&sk->sk_callback_lock);
		cep = sk_to_cep(sk);
		if (cep) {
			siw_sk_restore_upcalls(sk, cep);
			siw_cep_put(cep);
		}
		write_unlock_bh(&sk->sk_callback_lock);
	}
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


static struct siw_cep *siw_cep_alloc(struct siw_dev  *sdev)
{
	struct siw_cep *cep = kzalloc(sizeof *cep, GFP_KERNEL);
	if (cep) {
		unsigned long flags;

		INIT_LIST_HEAD(&cep->listenq);
		INIT_LIST_HEAD(&cep->devq);
		INIT_LIST_HEAD(&cep->work_freelist);

		kref_init(&cep->ref);
		cep->state = SIW_EPSTATE_IDLE;
		init_waitqueue_head(&cep->waitq);
		spin_lock_init(&cep->lock);
		cep->sdev = sdev;

		spin_lock_irqsave(&sdev->idr_lock, flags);
		list_add_tail(&cep->devq, &sdev->cep_list);
		spin_unlock_irqrestore(&sdev->idr_lock, flags);
		atomic_inc(&sdev->num_cep);

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

static void siw_cancel_mpatimer(struct siw_cep *cep)
{
	spin_lock_bh(&cep->lock);
	if (cep->mpa_timer) {
		if (cancel_delayed_work(&cep->mpa_timer->work)) {
			siw_cep_put(cep);
			kfree(cep->mpa_timer); /* not needed again */
		}
		cep->mpa_timer = NULL;
	}
	spin_unlock_bh(&cep->lock);
}

static void siw_put_work(struct siw_cm_work *work)
{
	INIT_LIST_HEAD(&work->list);
	spin_lock_bh(&work->cep->lock);
	list_add(&work->list, &work->cep->work_freelist);
	spin_unlock_bh(&work->cep->lock);
}

static void siw_cep_set_inuse(struct siw_cep *cep)
{
	unsigned long flags;
	int rv;
retry:
	dprint(DBG_CM, " (CEP 0x%p): use %d\n",
		cep, cep->in_use);

	spin_lock_irqsave(&cep->lock, flags);

	if (cep->in_use) {
		spin_unlock_irqrestore(&cep->lock, flags);
		rv = wait_event_interruptible(cep->waitq, !cep->in_use);
		if (signal_pending(current))
			flush_signals(current);
		goto retry;
	} else {
		cep->in_use = 1;
		spin_unlock_irqrestore(&cep->lock, flags);
	}
}

static void siw_cep_set_free(struct siw_cep *cep)
{
	unsigned long flags;

	dprint(DBG_CM, " (CEP 0x%p): use %d\n",
		cep, cep->in_use);

	spin_lock_irqsave(&cep->lock, flags);
	cep->in_use = 0;
	spin_unlock_irqrestore(&cep->lock, flags);

	wake_up(&cep->waitq);
}


static void __siw_cep_dealloc(struct kref *ref)
{
	struct siw_cep *cep = container_of(ref, struct siw_cep, ref);
	struct siw_dev *sdev = cep->sdev;
	unsigned long flags;

	dprint(DBG_OBJ|DBG_CM, "(CEP 0x%p): Free Object\n", cep);

	WARN_ON(cep->listen_cep);

	/* kfree(NULL) is save */
	kfree(cep->mpa.pdata);
	spin_lock_bh(&cep->lock);
	if (!list_empty(&cep->work_freelist))
		siw_cm_free_work(cep);
	spin_unlock_bh(&cep->lock);

	spin_lock_irqsave(&sdev->idr_lock, flags);
	list_del(&cep->devq);
	spin_unlock_irqrestore(&sdev->idr_lock, flags);
	atomic_dec(&sdev->num_cep);
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

/*
 * siw_cm_upcall()
 *
 * Upcall to IWCM to inform about async connection events
 */
static int siw_cm_upcall(struct siw_cep *cep, enum iw_cm_event_type reason,
			 int status)
{
	struct iw_cm_event	event;
	struct iw_cm_id		*cm_id;
	u16			pd_len;

	memset(&event, 0, sizeof event);
	event.status = status;
	event.event = reason;

	pd_len = be16_to_cpu(cep->mpa.hdr.params.pd_len);
	if (pd_len) {
		/*
		 * hand over MPA private data
		 */
		event.private_data_len = pd_len;
		event.private_data = cep->mpa.pdata;

		cep->mpa.hdr.params.pd_len = 0;
	}
	if (reason == IW_CM_EVENT_CONNECT_REQUEST ||
	    reason == IW_CM_EVENT_CONNECT_REPLY) {
		event.local_addr = cep->llp.laddr;
		event.remote_addr = cep->llp.raddr;
	}
	if (reason == IW_CM_EVENT_CONNECT_REQUEST) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
		event.ird = cep->sdev->attrs.max_ird;
		event.ord = cep->sdev->attrs.max_ord;
#endif
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
/*
 * siw_qp_cm_drop()
 *
 * Drops established LLP connection if present and not already
 * scheduled for dropping. Called from user context, SQ workqueue
 * or receive IRQ. Caller signals if socket can be immediately
 * closed (basically, if not in IRQ).
 */
void siw_qp_cm_drop(struct siw_qp *qp, int schedule)
{
	struct siw_cep *cep = qp->cep;

	qp->rx_ctx.rx_suspend = 1;
	qp->tx_ctx.tx_suspend = 1;

	if (!qp->cep)
		return;

	if (schedule)
		siw_cm_queue_work(cep, SIW_CM_WORK_CLOSE_LLP);
	else {
		siw_cep_set_inuse(cep);

		if (cep->state == SIW_EPSTATE_CLOSED) {
			dprint(DBG_CM, "(): cep=0x%p, already closed\n", cep);
			goto out;
		}
		/*
		 * Immediately close socket
		 */
		dprint(DBG_CM, "(): immediate close, cep=0x%p, state=%d, "
			"id=0x%p, sock=0x%p, QP%d\n", cep, cep->state,
			cep->cm_id, cep->llp.sock,
			cep->qp ? QP_ID(cep->qp) : -1);

		if (cep->cm_id) {
			switch (cep->state) {

			case SIW_EPSTATE_AWAIT_MPAREP:
				siw_cm_upcall(cep, IW_CM_EVENT_CONNECT_REPLY,
					      -EINVAL);
				break;

			case SIW_EPSTATE_RDMA_MODE:
				siw_cm_upcall(cep, IW_CM_EVENT_CLOSE, 0);

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
		if (cep->qp) {
			BUG_ON(qp != cep->qp);
			cep->qp = NULL;
			siw_qp_put(qp);
		}
out:
		siw_cep_set_free(cep);
	}
}


void siw_cep_put(struct siw_cep *cep)
{
	dprint(DBG_OBJ|DBG_CM, "(CEP 0x%p): New refcount: %d\n",
		cep, atomic_read(&cep->ref.refcount) - 1);

	BUG_ON(atomic_read(&cep->ref.refcount) < 1);
	kref_put(&cep->ref, __siw_cep_dealloc);
}

void siw_cep_get(struct siw_cep *cep)
{
	kref_get(&cep->ref);
	dprint(DBG_OBJ|DBG_CM, "(CEP 0x%p): New refcount: %d\n",
		cep, atomic_read(&cep->ref.refcount));
}



static inline int ksock_recv(struct socket *sock, char *buf, size_t size,
			     int flags)
{
	struct kvec iov = {buf, size};
	struct msghdr msg = {.msg_name = NULL, .msg_flags = flags};

	return kernel_recvmsg(sock, &msg, &iov, 1, size, flags);
}

/*
 * Expects params->pd_len in host byte order
 *
 * TODO: We might want to combine the arguments params and pdata to a single
 * pointer to a struct siw_mpa_info as defined in siw_cm.h.
 * This way, all private data parameters would be in a common struct.
 */
static int siw_send_mpareqrep(struct siw_cep *cep, const void *pdata,
			      u8 pd_len)
{
	struct socket	*s = cep->llp.sock;
	struct mpa_rr	*rr = &cep->mpa.hdr;
	struct kvec	iov[2];
	struct msghdr	msg;
	int		rv;

	memset(&msg, 0, sizeof(msg));

	rr->params.pd_len = cpu_to_be16(pd_len);

	iov[0].iov_base = rr;
	iov[0].iov_len = sizeof *rr;

	if (pd_len) {
		iov[1].iov_base = (char *)pdata;
		iov[1].iov_len = pd_len;

		rv =  kernel_sendmsg(s, &msg, iov, 2, pd_len + sizeof *rr);
	} else
		rv =  kernel_sendmsg(s, &msg, iov, 1, sizeof *rr);

	return rv < 0 ? rv : 0;
}

/*
 * Receive MPA Request/Reply header.
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
	u16		pd_len;
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

		if (be16_to_cpu(hdr->params.pd_len) > MPA_MAX_PRIVDATA)
			return -EPROTO;
	}
	pd_len = be16_to_cpu(hdr->params.pd_len);

	/*
	 * At least the MPA Request/Reply header (frame not including
	 * private data) has been received.
	 * Receive (or continue receiving) any private data.
	 */
	to_rcv = pd_len - (cep->mpa.bytes_rcvd - sizeof(struct mpa_rr));

	if (!to_rcv) {
		/*
		 * We must have hdr->params.pd_len == 0 and thus received a
		 * complete MPA Request/Reply frame.
		 * Check against peer protocol violation.
		 */
		u32 word;

		rcvd = ksock_recv(s, (char *)&word, sizeof word, MSG_DONTWAIT);
		if (rcvd == -EAGAIN)
			return 0;

		if (rcvd == 0) {
			dprint(DBG_CM, " peer EOF\n");
			return -EPIPE;
		}
		if (rcvd < 0) {
			dprint(DBG_CM, " ERROR: %d:\n", rcvd);
			return rcvd;
		}
		dprint(DBG_CM, " peer sent extra data: %d\n", rcvd);
		return -EPROTO;
	}

	/*
	 * At this point, we must have hdr->params.pd_len != 0.
	 * A private data buffer gets allocated if hdr->params.pd_len != 0.
	 */
	if (!cep->mpa.pdata) {
		cep->mpa.pdata = kmalloc(pd_len + 4, GFP_KERNEL);
		if (!cep->mpa.pdata)
			return -ENOMEM;
	}
	rcvd = ksock_recv(s, cep->mpa.pdata + cep->mpa.bytes_rcvd
			  - sizeof(struct mpa_rr), to_rcv + 4, MSG_DONTWAIT);

	if (rcvd < 0)
		return rcvd;

	if (rcvd > to_rcv)
		return -EPROTO;

	cep->mpa.bytes_rcvd += rcvd;

	if (to_rcv == rcvd) {
		dprint(DBG_CM, " %d bytes private_data received\n", pd_len);

		return 0;
	}
	return -EAGAIN;
}


/*
 * siw_proc_mpareq()
 *
 * Read MPA Request from socket and signal new connection to IWCM
 * if success. Caller must hold lock on corresponding listening CEP.
 */
static int siw_proc_mpareq(struct siw_cep *cep)
{
	struct mpa_rr	*req;
	int		rv;

	rv = siw_recv_mpa_rr(cep);
	if (rv != -EAGAIN)
		siw_cancel_mpatimer(cep);
	if (rv)
		goto out;

	req = &cep->mpa.hdr;

	if (__mpa_rr_revision(req->params.bits) > MPA_REVISION_1) {
		/* allow for 0 and 1 only */
		rv = -EPROTO;
		goto out;
	}
	if (memcmp(req->key, MPA_KEY_REQ, 16)) {
		rv = -EPROTO;
		goto out;
	}
	/*
	 * Prepare for sending MPA reply
	 */
	memcpy(req->key, MPA_KEY_REP, 16);

	if (req->params.bits & MPA_RR_FLAG_MARKERS
		|| (req->params.bits & MPA_RR_FLAG_CRC
			&& !mpa_crc_required && mpa_crc_strict)) {
		/*
		 * MPA Markers: currently not supported. Marker TX to be added.
		 *
		 * CRC:
		 *    RFC 5044, page 27: CRC MUST be used if peer requests it.
		 *    siw specific: 'mpa_crc_strict' parameter to reject
		 *    connection with CRC if local CRC off enforced by
		 *    'mpa_crc_strict' module parameter.
		 */
		dprint(DBG_CM|DBG_ON, " Reject: CRC %d:%d:%d, M %d:%d\n",
			req->params.bits & MPA_RR_FLAG_CRC ? 1 : 0,
			mpa_crc_required, mpa_crc_strict,
			req->params.bits & MPA_RR_FLAG_MARKERS ? 1 : 0, 0);

		req->params.bits &= ~MPA_RR_FLAG_MARKERS;
		req->params.bits |= MPA_RR_FLAG_REJECT; /* reject */

		if (!mpa_crc_required && mpa_crc_strict)
			req->params.bits &= ~MPA_RR_FLAG_CRC;

		kfree(cep->mpa.pdata);
		cep->mpa.pdata = NULL;

		(void)siw_send_mpareqrep(cep, NULL, 0);
		rv = -EOPNOTSUPP;
		goto out;
	}
	/*
	 * Enable CRC if requested by module initialization
	 */
	if (!(req->params.bits & MPA_RR_FLAG_CRC) && mpa_crc_required)
		req->params.bits |= MPA_RR_FLAG_CRC;
#if 0
	if (!cep->mpa.hdr.params.c && mpa_crc_required)
		cep->mpa.hdr.params.c = 1;
#endif

	cep->state = SIW_EPSTATE_RECVD_MPAREQ;

	/* Keep reference until IWCM accepts/rejects */
	siw_cep_get(cep);
	rv = siw_cm_upcall(cep, IW_CM_EVENT_CONNECT_REQUEST, 0);
	if (rv)
		siw_cep_put(cep);
out:
	return rv;
}


static int siw_proc_mpareply(struct siw_cep *cep)
{
	struct siw_qp_attrs	qp_attrs;
	struct siw_qp		*qp = cep->qp;
	struct mpa_rr		*rep;
	int			rv;

	rv = siw_recv_mpa_rr(cep);
	if (rv != -EAGAIN)
		siw_cancel_mpatimer(cep);
	if (rv)
		goto out_err;

	rep = &cep->mpa.hdr;

	if (__mpa_rr_revision(rep->params.bits) > MPA_REVISION_1) {
		/* allow for 0 and 1 only */
		rv = -EPROTO;
		goto out_err;
	}
	if (memcmp(rep->key, MPA_KEY_REP, 16)) {
		rv = -EPROTO;
		goto out_err;
	}
	if (rep->params.bits & MPA_RR_FLAG_REJECT) {
		dprint(DBG_CM, "(cep=0x%p): Got MPA reject\n", cep);
		(void)siw_cm_upcall(cep, IW_CM_EVENT_CONNECT_REPLY,
				    -ECONNRESET);

		rv = -ECONNRESET;
		goto out;
	}
	if ((rep->params.bits & MPA_RR_FLAG_MARKERS)
		|| (mpa_crc_required && !(rep->params.bits & MPA_RR_FLAG_CRC))
		|| (mpa_crc_strict && !mpa_crc_required
			&& (rep->params.bits & MPA_RR_FLAG_CRC))) {

		dprint(DBG_CM|DBG_ON, " Reply unsupp: CRC %d:%d:%d, M %d:%d\n",
			rep->params.bits & MPA_RR_FLAG_CRC ? 1 : 0,
			mpa_crc_required, mpa_crc_strict,
			rep->params.bits & MPA_RR_FLAG_MARKERS ? 1 : 0, 0);

		(void)siw_cm_upcall(cep, IW_CM_EVENT_CONNECT_REPLY,
				    -ECONNREFUSED);
		rv = -EINVAL;
		goto out;
	}
	memset(&qp_attrs, 0, sizeof qp_attrs);
	qp_attrs.mpa.marker_rcv = 0;
	qp_attrs.mpa.marker_snd = 0;
	qp_attrs.mpa.crc = cep->mpa.hdr.params.bits & MPA_RR_FLAG_CRC ? 1 : 0;
	qp_attrs.ird = cep->ird;
	qp_attrs.ord = cep->ord;
	qp_attrs.llp_stream_handle = cep->llp.sock;
	qp_attrs.state = SIW_QP_STATE_RTS;

	/* Move socket RX/TX under QP control */
	down_write(&qp->state_lock);
	if (qp->attrs.state > SIW_QP_STATE_RTR) {
		rv = -EINVAL;
		up_write(&qp->state_lock);
		goto out_err;
	}
	rv = siw_qp_modify(qp, &qp_attrs, SIW_QP_ATTR_STATE|
					       SIW_QP_ATTR_LLP_HANDLE|
					       SIW_QP_ATTR_ORD|
					       SIW_QP_ATTR_IRD|
					       SIW_QP_ATTR_MPA);

	up_write(&qp->state_lock);

	if (!rv) {
		rv = siw_cm_upcall(cep, IW_CM_EVENT_CONNECT_REPLY, 0);
		if (!rv)
			cep->state = SIW_EPSTATE_RDMA_MODE;

		goto out;
	}

out_err:
	(void)siw_cm_upcall(cep, IW_CM_EVENT_CONNECT_REPLY, -EINVAL);
out:
	return rv;
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

	if (cep->state != SIW_EPSTATE_LISTENING)
		goto error;

	new_cep = siw_cep_alloc(cep->sdev);
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

	new_cep->state = SIW_EPSTATE_AWAIT_MPAREQ;

	rv = siw_cm_queue_work(new_cep, SIW_CM_WORK_MPATIMEOUT);
	if (rv)
		goto error;
	/*
	 * See siw_proc_mpareq() etc. for the use of new_cep->listen_cep.
	 */
	new_cep->listen_cep = cep;
	siw_cep_get(cep);

	if (atomic_read(&new_s->sk->sk_rmem_alloc)) {
		/*
		 * MPA REQ already queued
		 */
		dprint(DBG_CM, "(cep=0x%p): Immediate MPA req.\n", cep);

		siw_cep_set_inuse(new_cep);
		rv = siw_proc_mpareq(new_cep);
		siw_cep_set_free(new_cep);

		if (rv != -EAGAIN) {
			siw_cep_put(cep);
			new_cep->listen_cep = NULL;
			if (rv)
				goto error;
		}
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


static void siw_cm_work_handler(struct work_struct *w)
{
	struct siw_cm_work	*work;
	struct siw_cep		*cep;
	int release_cep = 0, rv = 0;

	work = container_of(w, struct siw_cm_work, work.work);
	cep = work->cep;

	dprint(DBG_CM, " (QP%d): WORK type: %d, CEP: 0x%p, state: %d\n",
		cep->qp ? QP_ID(cep->qp) : -1, work->type, cep, cep->state);

	siw_cep_set_inuse(cep);

	switch (work->type) {

	case SIW_CM_WORK_ACCEPT:

		siw_accept_newconn(cep);
		break;

	case SIW_CM_WORK_READ_MPAHDR:

		switch (cep->state) {

		case SIW_EPSTATE_AWAIT_MPAREQ:

			if (cep->listen_cep) {
				siw_cep_set_inuse(cep->listen_cep);

				if (cep->listen_cep->state ==
				    SIW_EPSTATE_LISTENING)
					rv = siw_proc_mpareq(cep);
				else
					rv = -EFAULT;

				siw_cep_set_free(cep->listen_cep);

				if (rv != -EAGAIN) {
					siw_cep_put(cep->listen_cep);
					cep->listen_cep = NULL;
					if (rv)
						siw_cep_put(cep);
				}
			}
			break;

		case SIW_EPSTATE_AWAIT_MPAREP:

			rv = siw_proc_mpareply(cep);
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
		if (rv && rv != EAGAIN)
			release_cep = 1;

		break;

	case SIW_CM_WORK_CLOSE_LLP:
		/*
		 * QP scheduled LLP close
		 */
		dprint(DBG_CM, "(): SIW_CM_WORK_CLOSE_LLP, cep->state=%d\n",
			cep->state);

		if (cep->cm_id)
			siw_cm_upcall(cep, IW_CM_EVENT_CLOSE, 0);

		release_cep = 1;

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
				siw_cm_upcall(cep, IW_CM_EVENT_DISCONNECT, 0);
				siw_cm_upcall(cep, IW_CM_EVENT_CLOSE, 0);

				break;

			default:

				break;
				/*
				 * for these states there is no connection
				 * known to the IWCM.
				 */
			}
		} else {
			switch (cep->state) {

			case SIW_EPSTATE_RECVD_MPAREQ:
				/*
				 * Wait for the CM to call its accept/reject
				 */
				dprint(DBG_CM, "(): STATE_RECVD_MPAREQ: "
					"wait for CM:\n");
				break;
			case SIW_EPSTATE_AWAIT_MPAREQ:
				/*
				 * Socket close before MPA request received.
				 */
				dprint(DBG_CM,
					"(): STATE_AWAIT_MPAREQ: "
					"unlink from Listener\n");
				siw_cep_put(cep->listen_cep);
				cep->listen_cep = NULL;

				break;

			default:
				break;
			}
		}
		release_cep = 1;

		break;

	case SIW_CM_WORK_MPATIMEOUT:

		cep->mpa_timer = NULL;

		if (cep->state == SIW_EPSTATE_AWAIT_MPAREP) {
			/*
			 * MPA request timed out:
			 * Hide any partially received private data and signal
			 * timeout
			 */
			cep->mpa.hdr.params.pd_len = 0;

			if (cep->cm_id)
				siw_cm_upcall(cep, IW_CM_EVENT_CONNECT_REPLY,
					      -ETIMEDOUT);
			release_cep = 1;

		} else if (cep->state == SIW_EPSTATE_AWAIT_MPAREQ) {
			/*
			 * No MPA request received after peer TCP stream setup.
			 */
			siw_cep_put(cep->listen_cep);
			cep->listen_cep = NULL;
			release_cep = 1;
		}
		break;

	default:
		BUG();
	}

	if (release_cep) {

		dprint(DBG_CM, " (CEP 0x%p): Release: "
			"mpa_timer=%s, sock=0x%p, QP%d, id=0x%p\n",
			cep, cep->mpa_timer ? "y" : "n", cep->llp.sock,
			cep->qp ? QP_ID(cep->qp) : -1, cep->cm_id);

		siw_cancel_mpatimer(cep);

		cep->state = SIW_EPSTATE_CLOSED;

		if (cep->qp) {
			struct siw_qp *qp = cep->qp;
			/*
			 * Serialize a potential race with application
			 * closing the QP and calling siw_qp_cm_drop()
			 */
			siw_qp_get(qp);
			siw_cep_set_free(cep);

			siw_qp_llp_close(qp);
			siw_qp_put(qp);

			siw_cep_set_inuse(cep);
			cep->qp = NULL;
			siw_qp_put(qp);
		}
		if (cep->llp.sock) {
			siw_socket_disassoc(cep->llp.sock);
			sock_release(cep->llp.sock);
			cep->llp.sock = NULL;
		}
		if (cep->cm_id) {
			cep->cm_id->rem_ref(cep->cm_id);
			cep->cm_id = NULL;
			siw_cep_put(cep);
		}
	}

	siw_cep_set_free(cep);

	dprint(DBG_CM, " (Exit): WORK type: %d, CEP: 0x%p\n", work->type, cep);
	siw_put_work(work);
	siw_cep_put(cep);
}

static struct workqueue_struct *siw_cm_wq;

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

	INIT_DELAYED_WORK(&work->work, siw_cm_work_handler);

	if (type == SIW_CM_WORK_MPATIMEOUT) {
		unsigned long delay;
		if (cep->state == SIW_EPSTATE_AWAIT_MPAREQ)
			delay = MPAREQ_TIMEOUT;
		else
			delay = MPAREP_TIMEOUT;
		cep->mpa_timer = work;
		queue_delayed_work(siw_cm_wq, &work->work, delay);
	} else
		queue_delayed_work(siw_cm_wq, &work->work, 0);

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
	struct socket	*s;
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
		siw_cm_queue_work(cep, SIW_CM_WORK_ACCEPT);

		break;

	case TCP_CLOSE:
	case TCP_CLOSE_WAIT:

		if (cep->qp)
			cep->qp->tx_ctx.tx_suspend = 1;
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
	struct siw_dev	*sdev = siw_dev_ofa2siw(id->device);
	struct siw_qp	*qp;
	struct siw_cep	*cep = NULL;
	struct socket	*s = NULL;
	struct sockaddr	*laddr, *raddr;

	u16		pd_len = params->private_data_len;
	int		rv;

	if (pd_len > MPA_MAX_PRIVDATA)
		return -EINVAL;

	qp = siw_qp_id2obj(sdev, params->qpn);
	BUG_ON(!qp);

	dprint(DBG_CM, "(id=0x%p, QP%d): dev(id)=%s, netdev=%s\n",
		id, QP_ID(qp), sdev->ofa_dev.name, sdev->netdev->name);
	dprint(DBG_CM, "(id=0x%p, QP%d): laddr=(0x%x,%d), raddr=(0x%x,%d)\n",
		id, QP_ID(qp),
		ntohl(id->local_addr.sin_addr.s_addr),
		ntohs(id->local_addr.sin_port),
		ntohl(id->remote_addr.sin_addr.s_addr),
		ntohs(id->remote_addr.sin_port));

	laddr = (struct sockaddr *)&id->local_addr;
	raddr = (struct sockaddr *)&id->remote_addr;

	rv = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &s);
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
	cep = siw_cep_alloc(sdev);
	if (!cep) {
		rv =  -ENOMEM;
		goto error;
	}
	siw_cep_set_inuse(cep);

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
	cep->ird = params->ird;
	cep->ord = params->ord;
	cep->state = SIW_EPSTATE_CONNECTING;

	dprint(DBG_CM, " (id=0x%p, QP%d): pd_len = %u\n",
		id, QP_ID(qp), pd_len);

	rv = kernel_peername(s, &cep->llp.raddr);
	if (rv)
		goto error;

	rv = kernel_localname(s, &cep->llp.laddr);
	if (rv)
		goto error;

	/*
	 * Associate CEP with socket
	 */
	siw_cep_socket_assoc(cep, s);

	cep->state = SIW_EPSTATE_AWAIT_MPAREP;

	/*
	 * Set MPA Request bits: CRC if required, no MPA Markers,
	 * MPA Rev. 1, Key 'Request'.
	 */
	cep->mpa.hdr.params.bits = 0;
	__mpa_rr_set_revision(&cep->mpa.hdr.params.bits, MPA_REVISION_1);

	if (mpa_crc_required)
		cep->mpa.hdr.params.bits |= MPA_RR_FLAG_CRC;

	memcpy(cep->mpa.hdr.key, MPA_KEY_REQ, 16);

	rv = siw_send_mpareqrep(cep, params->private_data, pd_len);
	/*
	 * Reset private data.
	 */
	cep->mpa.hdr.params.pd_len = 0;

	if (rv >= 0) {
		rv = siw_cm_queue_work(cep, SIW_CM_WORK_MPATIMEOUT);
		if (!rv) {
			dprint(DBG_CM, "(id=0x%p, cep=0x%p QP%d): Exit\n",
				id, cep, QP_ID(qp));
			siw_cep_set_free(cep);
			return 0;
		}
	}
error:
	dprint(DBG_CM, " Failed: %d\n", rv);

	if (cep) {
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

		siw_cep_set_free(cep);

		siw_cep_put(cep);

	} else if (s)
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
	struct siw_dev		*sdev = siw_dev_ofa2siw(id->device);
	struct siw_cep		*cep = (struct siw_cep *)id->provider_data;
	struct siw_qp		*qp;
	struct siw_qp_attrs	qp_attrs;
	int rv;

	siw_cep_set_inuse(cep);
	siw_cep_put(cep);

	if (cep->state != SIW_EPSTATE_RECVD_MPAREQ) {
		if (cep->state == SIW_EPSTATE_CLOSED) {

			dprint(DBG_CM, "(id=0x%p): Out of State\n", id);

			siw_cep_set_free(cep);
			siw_cep_put(cep);

			return -ECONNRESET;
		}
		BUG();
	}

	qp = siw_qp_id2obj(sdev, params->qpn);
	BUG_ON(!qp); /* The OFA core should prevent this */

	down_write(&qp->state_lock);
	if (qp->attrs.state > SIW_QP_STATE_RTR) {
		rv = -EINVAL;
		up_write(&qp->state_lock);
		goto error;
	}

	dprint(DBG_CM, "(id=0x%p, QP%d): dev(id)=%s\n",
		id, QP_ID(qp), sdev->ofa_dev.name);

	if (params->ord > sdev->attrs.max_ord ||
	    params->ird > sdev->attrs.max_ord) {
		dprint(DBG_CM|DBG_ON, "(id=0x%p, QP%d): "
			"ORD: %d (max: %d), IRD: %d (max: %d)\n",
			id, QP_ID(qp),
			params->ord, qp->attrs.ord,
			params->ird, qp->attrs.ird);
		rv = -EINVAL;
		up_write(&qp->state_lock);
		goto error;
	}
	if (params->private_data_len > MPA_MAX_PRIVDATA) {
		dprint(DBG_CM|DBG_ON, "(id=0x%p, QP%d): "
			"Private data too long: %d (max: %d)\n",
			id, QP_ID(qp),
			params->private_data_len, MPA_MAX_PRIVDATA);
		rv =  -EINVAL;
		up_write(&qp->state_lock);
		goto error;
	}
	cep->cm_id = id;
	id->add_ref(id);

	memset(&qp_attrs, 0, sizeof qp_attrs);
	qp_attrs.ord = params->ord;
	qp_attrs.ird = params->ird;
	qp_attrs.llp_stream_handle = cep->llp.sock;

	/*
	 * Currently no MPA markers support. Consider adding marker TX path.
	 */
	qp_attrs.mpa.marker_rcv = 0;
	qp_attrs.mpa.marker_snd = 0;
	qp_attrs.mpa.crc = cep->mpa.hdr.params.bits & MPA_RR_FLAG_CRC ? 1 : 0;
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

	dprint(DBG_CM, "(id=0x%p, QP%d): %d bytes private_data\n",
			id, QP_ID(qp), params->private_data_len);

	dprint(DBG_CM, "(id=0x%p, QP%d): Sending MPA Reply\n", id, QP_ID(qp));

	rv = siw_send_mpareqrep(cep, params->private_data,
				params->private_data_len);

	if (!rv) {
		rv = siw_cm_upcall(cep, IW_CM_EVENT_ESTABLISHED, 0);
		if (rv)
			goto error;

		siw_cep_set_free(cep);

		dprint(DBG_CM, "(id=0x%p, QP%d): Exit\n", id, QP_ID(qp));
		return 0;
	}

error:
	siw_socket_disassoc(cep->llp.sock);
	sock_release(cep->llp.sock);
	cep->llp.sock = NULL;

	cep->state = SIW_EPSTATE_CLOSED;

	if (cep->cm_id) {
		cep->cm_id->rem_ref(id);
		cep->cm_id = NULL;
	}
	if (qp->cep) {
		siw_cep_put(cep);
		qp->cep = NULL;
	}
	cep->qp = NULL;
	siw_qp_put(qp);

	siw_cep_set_free(cep);
	siw_cep_put(cep);

	return rv;
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

	siw_cep_set_inuse(cep);
	siw_cep_put(cep);

	if (cep->state != SIW_EPSTATE_RECVD_MPAREQ) {
		if (cep->state == SIW_EPSTATE_CLOSED) {

			dprint(DBG_CM, "(id=0x%p): Out of State\n", id);

			siw_cep_set_free(cep);
			siw_cep_put(cep); /* should be last reference */

			return -ECONNRESET;
		}
		BUG();
	}
	dprint(DBG_CM, "(id=0x%p): cep->state=%d\n", id, cep->state);
	dprint(DBG_CM, " Reject: %d: %x\n", plen, plen ? *(char *)pdata : 0);

	if (__mpa_rr_revision(cep->mpa.hdr.params.bits) == MPA_REVISION_1) {
		cep->mpa.hdr.params.bits |= MPA_RR_FLAG_REJECT; /* reject */
		(void)siw_send_mpareqrep(cep, pdata, plen);
	}
	siw_socket_disassoc(cep->llp.sock);
	sock_release(cep->llp.sock);
	cep->llp.sock = NULL;

	cep->state = SIW_EPSTATE_CLOSED;

	siw_cep_set_free(cep);
	siw_cep_put(cep);

	return 0;
}

static int siw_listen_address(struct iw_cm_id *id, int backlog,
			      struct sockaddr *laddr)
{
	struct socket		*s;
	struct siw_cep		*cep = NULL;
	int			rv = 0, s_val;

	rv = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &s);
	if (rv < 0) {
		dprint(DBG_CM|DBG_ON, "(id=0x%p): ERROR: "
			"sock_create(): rv=%d\n", id, rv);
		return rv;
	}

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

	cep = siw_cep_alloc(siw_dev_ofa2siw(id->device));
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

	dprint(DBG_CM, "(id=0x%p): dev(id)=%s, netdev=%s, "
		"id->provider_data=0x%p, cep=0x%p\n",
		id, id->device->name,
		siw_dev_ofa2siw(id->device)->netdev->name,
		id->provider_data, cep);

	list_add_tail(&cep->listenq, (struct list_head *)id->provider_data);
	cep->state = SIW_EPSTATE_LISTENING;

	return 0;

error:
	dprint(DBG_CM, " Failed: %d\n", rv);

	if (cep) {
		siw_cep_set_inuse(cep);

		if (cep->cm_id) {
			cep->cm_id->rem_ref(cep->cm_id);
			cep->cm_id = NULL;
		}
		cep->llp.sock = NULL;
		siw_socket_disassoc(s);
		cep->state = SIW_EPSTATE_CLOSED;

		siw_cep_set_free(cep);
		siw_cep_put(cep);
	}
	sock_release(s);

	return rv;
}

static void siw_drop_listeners(struct iw_cm_id *id)
{
	struct list_head	*p, *tmp;
	/*
	 * In case of a wildcard rdma_listen on a multi-homed device,
	 * a listener's IWCM id is associated with more than one listening CEP.
	 */
	list_for_each_safe(p, tmp, (struct list_head *)id->provider_data) {

		struct siw_cep *cep = list_entry(p, struct siw_cep, listenq);
		list_del(p);

		dprint(DBG_CM, "(id=0x%p): drop CEP 0x%p, state %d\n",
			id, cep, cep->state);
		siw_cep_set_inuse(cep);

		if (cep->cm_id) {
			cep->cm_id->rem_ref(cep->cm_id);
			cep->cm_id = NULL;
		}
		if (cep->llp.sock) {
			siw_socket_disassoc(cep->llp.sock);
			sock_release(cep->llp.sock);
			cep->llp.sock = NULL;
		}
		cep->state = SIW_EPSTATE_CLOSED;
		siw_cep_set_free(cep);
		siw_cep_put(cep);
	}
}

/*
 * siw_create_listen - Create resources for a listener's IWCM ID @id
 *
 * Listens on the socket addresses id->local_addr and id->remote_addr.
 *
 * If the listener's @id provides a specific local IP address, at most one
 * listening socket is created and associated with @id.
 *
 * If the listener's @id provides the wildcard (zero) local IP address,
 * a separate listen is performed for each local IP address of the device
 * by creating a listening socket and binding to that local IP address.
 *
 */
int siw_create_listen(struct iw_cm_id *id, int backlog)
{
	struct ib_device	*ofa_dev = id->device;
	struct siw_dev		*sdev = siw_dev_ofa2siw(ofa_dev);
	int			rv = 0;

	dprint(DBG_CM, "(id=0x%p): dev(id)=%s, netdev=%s backlog=%d\n",
		id, ofa_dev->name, sdev->netdev->name, backlog);

	/*
	 * IPv4/v6 design differences regarding multi-homing
	 * propagate up to iWARP:
	 * o For IPv4, use sdev->netdev->ip_ptr
	 * o For IPv6, use sdev->netdev->ipv6_ptr
	 */
	if (id->local_addr.sin_family == AF_INET) {
		/* IPv4 */
		struct sockaddr_in	laddr = id->local_addr;
		u8			*l_ip, *r_ip;
		struct in_device	*in_dev;

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

		in_dev = in_dev_get(sdev->netdev);
		if (!in_dev) {
			dprint(DBG_CM|DBG_ON, "(id=0x%p): "
				"netdev has no in_device\n", id);
			return -ENODEV;
		}

		for_ifa(in_dev) {
			/*
			 * Create a listening socket if id->local_addr
			 * contains the wildcard IP address OR
			 * the IP address of the interface.
			 */
			if (ipv4_is_zeronet(id->local_addr.sin_addr.s_addr) ||
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

		if (rv && id->provider_data)
			siw_drop_listeners(id);

	} else {
		/* IPv6 */
		rv = -EAFNOSUPPORT;
		dprint(DBG_CM|DBG_ON, "(id=0x%p): TODO: IPv6 support\n", id);
	}
	if (!rv)
		dprint(DBG_CM, "(id=0x%p): Success\n", id);

	return rv;
}


int siw_destroy_listen(struct iw_cm_id *id)
{

	dprint(DBG_CM, "(id=0x%p): dev(id)=%s, netdev=%s\n",
		id, id->device->name,
		siw_dev_ofa2siw(id->device)->netdev->name);

	if (!id->provider_data) {
		/*
		 * TODO: See if there's a way to avoid getting any
		 *       listener ids without a list of CEPs
		 */
		dprint(DBG_CM, "(id=0x%p): Listener id: no CEP(s)\n", id);
		return 0;
	}
	siw_drop_listeners(id);
	kfree(id->provider_data);
	id->provider_data = NULL;

	return 0;
}

int siw_cm_init(void)
{
	/*
	 * create_single_workqueue for strict ordering
	 */
	siw_cm_wq = create_singlethread_workqueue("siw_cm_wq");
	if (!siw_cm_wq)
		return -ENOMEM;

	return 0;
}

void siw_cm_exit(void)
{
	if (siw_cm_wq) {
		flush_workqueue(siw_cm_wq);
		destroy_workqueue(siw_cm_wq);
	}
}

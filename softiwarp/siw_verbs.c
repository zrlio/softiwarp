/*
 * Software iWARP device driver for Linux
 *
 * Authors: Bernard Metzler <bmt@zurich.ibm.com>
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
#include <linux/uaccess.h>

#include <rdma/iw_cm.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_umem.h>

#include "siw.h"
#include "siw_verbs.h"
#include "siw_obj.h"
#include "siw_cm.h"

static int ib_qp_state_to_siw_qp_state[IB_QPS_ERR+1] = {
	[IB_QPS_RESET]	= SIW_QP_STATE_IDLE,
	[IB_QPS_INIT]	= SIW_QP_STATE_IDLE,
	[IB_QPS_RTR]	= SIW_QP_STATE_RTR,
	[IB_QPS_RTS]	= SIW_QP_STATE_RTS,
	[IB_QPS_SQD]	= SIW_QP_STATE_CLOSING,
	[IB_QPS_SQE]	= SIW_QP_STATE_TERMINATE,
	[IB_QPS_ERR]	= SIW_QP_STATE_ERROR
};

static inline struct siw_mr *siw_mr_ofa2siw(struct ib_mr *ofa_mr)
{
	return container_of(ofa_mr, struct siw_mr, ofa_mr);
}

static inline struct siw_pd *siw_pd_ofa2siw(struct ib_pd *ofa_pd)
{
	return container_of(ofa_pd, struct siw_pd, ofa_pd);
}

static inline struct siw_ucontext *siw_ctx_ofa2siw(struct ib_ucontext *ofa_ctx)
{
	return container_of(ofa_ctx, struct siw_ucontext, ib_ucontext);
}

static inline struct siw_qp *siw_qp_ofa2siw(struct ib_qp *ofa_qp)
{
	return container_of(ofa_qp, struct siw_qp, ofa_qp);
}

static inline struct siw_cq *siw_cq_ofa2siw(struct ib_cq *ofa_cq)
{
	return container_of(ofa_cq, struct siw_cq, ofa_cq);
}

static inline struct siw_srq *siw_srq_ofa2siw(struct ib_srq *ofa_srq)
{
	return container_of(ofa_srq, struct siw_srq, ofa_srq);
}

struct ib_ucontext *siw_alloc_ucontext(struct ib_device *ofa_dev,
				       struct ib_udata *udata)
{
	struct siw_ucontext *ctx = NULL;
	struct siw_dev *sdev = siw_dev_ofa2siw(ofa_dev);
	int rv;

	dprint(DBG_CM, "(device=%s)\n", ofa_dev->name);

	if (atomic_inc_return(&sdev->num_ctx) > SIW_MAX_CONTEXT) {
		dprint(DBG_ON, ": Out of CONTEXT's\n");
		rv = -ENOMEM;
		goto err_out;
	}
	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		rv = -ENOMEM;
		goto err_out;
	}
	ctx->sdev = sdev;
	return &ctx->ib_ucontext;

err_out:
	if (ctx)
		kfree(ctx);

	atomic_dec(&sdev->num_ctx);
	return ERR_PTR(rv);
}

int siw_dealloc_ucontext(struct ib_ucontext *ofa_ctx)
{
	struct siw_ucontext *ctx = siw_ctx_ofa2siw(ofa_ctx);

	atomic_dec(&ctx->sdev->num_ctx);
	kfree(ctx);
	return 0;
}

int siw_query_device(struct ib_device *ofa_dev, struct ib_device_attr *attr)
{
	struct siw_dev *sdev = siw_dev_ofa2siw(ofa_dev);
	/*
	 * A process context is needed to report avail memory resources.
	 */
	if (in_interrupt())
		return -EINVAL;

	memset(attr, 0, sizeof *attr);

	attr->max_mr_size = rlimit(RLIMIT_MEMLOCK); /* per process */
	attr->vendor_id = sdev->attrs.vendor_id;
	attr->vendor_part_id = sdev->attrs.vendor_part_id;
	attr->max_qp = sdev->attrs.max_qp;
	attr->max_qp_wr = sdev->attrs.max_qp_wr;

	/*
	 * RDMA Read parameters:
	 * Max. ORD (Outbound Read queue Depth), a.k.a. max_initiator_depth
	 * Max. IRD (Inbound Read queue Depth), a.k.a. max_responder_resources
	 */
	attr->max_qp_rd_atom = sdev->attrs.max_ord;
	attr->max_qp_init_rd_atom = sdev->attrs.max_ird;
	attr->max_res_rd_atom = sdev->attrs.max_qp * sdev->attrs.max_ird;
	attr->device_cap_flags = sdev->attrs.cap_flags;
	attr->max_sge = sdev->attrs.max_sge;
	attr->max_sge_rd = sdev->attrs.max_sge_rd;
	attr->max_cq = sdev->attrs.max_cq;
	attr->max_cqe = sdev->attrs.max_cqe;
	attr->max_mr = sdev->attrs.max_mr;
	attr->max_pd = sdev->attrs.max_pd;
	attr->max_mw = sdev->attrs.max_mw;
	attr->max_fmr = sdev->attrs.max_fmr;
	attr->max_srq = sdev->attrs.max_srq;
	attr->max_srq_wr = sdev->attrs.max_srq_wr;
	attr->max_srq_sge = sdev->attrs.max_srq_sge;

	memcpy(&attr->sys_image_guid, sdev->netdev->dev_addr, 6);

	/*
	 * TODO: understand what of the following should
	 * get useful information
	 *
	 * attr->fw_ver;
	 * attr->max_ah
	 * attr->max_map_per_fmr
	 * attr->max_ee
	 * attr->max_rdd
	 * attr->max_ee_rd_atom;
	 * attr->max_ee_init_rd_atom;
	 * attr->max_raw_ipv6_qp
	 * attr->max_raw_ethy_qp
	 * attr->max_mcast_grp
	 * attr->max_mcast_qp_attach
	 * attr->max_total_mcast_qp_attach
	 * attr->max_pkeys
	 * attr->atomic_cap;
	 * attr->page_size_cap;
	 * attr->hw_ver;
	 * attr->local_ca_ack_delay;
	 */
	return 0;
}

/*
 * Approximate translation of real MTU for IB.
 *
 * TODO: is that needed for RNIC's? We may have a medium
 *       which reports MTU of 64kb and have to degrade to 4k??
 */
static inline enum ib_mtu siw_mtu_net2ofa(unsigned short mtu)
{
	if (mtu >= 4096)
		return IB_MTU_4096;
	if (mtu >= 2048)
		return IB_MTU_2048;
	if (mtu >= 1024)
		return IB_MTU_1024;
	if (mtu >= 512)
		return IB_MTU_512;
	if (mtu >= 256)
		return IB_MTU_256;
	return -1;
}

int siw_query_port(struct ib_device *ofa_dev, u8 port,
		     struct ib_port_attr *attr)
{
	struct siw_dev *sdev = siw_dev_ofa2siw(ofa_dev);

	memset(attr, 0, sizeof *attr);

	attr->state = sdev->state;
	attr->max_mtu = siw_mtu_net2ofa(sdev->netdev->mtu);
	attr->active_mtu = attr->max_mtu;
	attr->gid_tbl_len = 1;
	attr->port_cap_flags = IB_PORT_CM_SUP;	/* ?? */
	attr->port_cap_flags |= IB_PORT_DEVICE_MGMT_SUP;
	attr->max_msg_sz = -1;
	attr->pkey_tbl_len = 1;
	attr->active_width = 2;
	attr->active_speed = 2;
	/*
	 * All zero
	 *
	 * attr->lid = 0;
	 * attr->bad_pkey_cntr = 0;
	 * attr->qkey_viol_cntr = 0;
	 * attr->sm_lid = 0;
	 * attr->lmc = 0;
	 * attr->max_vl_num = 0;
	 * attr->sm_sl = 0;
	 * attr->subnet_timeout = 0;
	 * attr->init_type_repy = 0;
	 * attr->phys_state = 0;
	 */
	return 0;
}

int siw_query_pkey(struct ib_device *ofa_dev, u8 port, u16 idx, u16 *pkey)
{
	*pkey = 0;
	return 0;
}

int siw_query_gid(struct ib_device *ofa_dev, u8 port, int idx,
		   union ib_gid *gid)
{
	struct siw_dev *sdev = siw_dev_ofa2siw(ofa_dev);

	/* subnet_prefix == interface_id == 0; */
	memset(gid, 0, sizeof *gid);
	memcpy(&gid->raw[0], sdev->netdev->dev_addr, 6);

	return 0;
}

struct ib_pd *siw_alloc_pd(struct ib_device *ofa_dev,
			   struct ib_ucontext *context, struct ib_udata *udata)
{
	struct siw_pd	*pd = NULL;
	struct siw_dev	*sdev  = siw_dev_ofa2siw(ofa_dev);
	int rv;

	if (atomic_inc_return(&sdev->num_pd) > SIW_MAX_PD) {
		dprint(DBG_ON, ": Out of PD's\n");
		rv = -ENOMEM;
		goto err_out;
	}
	pd = kmalloc(sizeof *pd, GFP_KERNEL);
	if (!pd) {
		dprint(DBG_ON, ": malloc\n");
		rv = -ENOMEM;
		goto err_out;
	}
	rv = siw_pd_add(sdev, pd);
	if (rv) {
		dprint(DBG_ON, ": siw_pd_add\n");
		rv = -ENOMEM;
		goto err_out;
	}
	if (context) {
		if (ib_copy_to_udata(udata, &pd->hdr.id, sizeof pd->hdr.id)) {
			rv = -EFAULT;
			goto err_out_idr;
		}
	}
	return &pd->ofa_pd;

err_out_idr:
	siw_remove_obj(&sdev->idr_lock, &sdev->pd_idr, &pd->hdr);
err_out:
	kfree(pd);
	atomic_dec(&sdev->num_pd);

	return ERR_PTR(rv);
}

int siw_dealloc_pd(struct ib_pd *ofa_pd)
{
	struct siw_pd	*pd = siw_pd_ofa2siw(ofa_pd);
	struct siw_dev	*sdev = siw_dev_ofa2siw(ofa_pd->device);

	siw_remove_obj(&sdev->idr_lock, &sdev->pd_idr, &pd->hdr);
	siw_pd_put(pd);

	return 0;
}

struct ib_ah *siw_create_ah(struct ib_pd *pd, struct ib_ah_attr *attr)
{
	return ERR_PTR(-ENOSYS);
}

int siw_destroy_ah(struct ib_ah *ah)
{
	return -ENOSYS;
}


void siw_qp_get_ref(struct ib_qp *ofa_qp)
{
	struct siw_qp	*qp = siw_qp_ofa2siw(ofa_qp);

	dprint(DBG_OBJ|DBG_CM, "(QP%d): Get Reference\n", QP_ID(qp));
	siw_qp_get(qp);
}


void siw_qp_put_ref(struct ib_qp *ofa_qp)
{
	struct siw_qp	*qp = siw_qp_ofa2siw(ofa_qp);

	dprint(DBG_OBJ|DBG_CM, "(QP%d): Put Reference\n", QP_ID(qp));
	siw_qp_put(qp);
}

int siw_no_mad(struct ib_device *ofa_dev, int flags, u8 port,
			    struct ib_wc *wc, struct ib_grh *grh,
			    struct ib_mad *in_mad, struct ib_mad *out_mad)
{
	return -ENOSYS;
}


/*
 * siw_create_qp()
 *
 * Create QP of requested size on given device.
 *
 * @ofa_pd:	OFA PD contained in siw PD
 * @attrs:	Initial QP attributes.
 * @udata:	used to provide QP ID, SQ and RQ size back to user.
 */

struct ib_qp *siw_create_qp(struct ib_pd *ofa_pd,
			    struct ib_qp_init_attr *attrs,
			    struct ib_udata *udata)
{
	struct siw_qp			*qp = NULL;
	struct siw_pd			*pd = siw_pd_ofa2siw(ofa_pd);
	struct ib_device		*ofa_dev = ofa_pd->device;
	struct siw_dev			*sdev = siw_dev_ofa2siw(ofa_dev);
	struct siw_cq			*scq = NULL, *rcq = NULL;
	struct siw_uresp_create_qp	uresp;

	unsigned long flags;
	int kernel_verbs = ofa_pd->uobject ? 0 : 1;
	int rv = 0;

	dprint(DBG_OBJ|DBG_CM, ": new QP on device %s\n",
		ofa_dev->name);

	if (atomic_inc_return(&sdev->num_qp) > SIW_MAX_QP) {
		dprint(DBG_ON, ": Out of QP's\n");
		rv = -ENOMEM;
		goto err_out;
	}
	if (attrs->qp_type != IB_QPT_RC) {
		dprint(DBG_ON, ": Only RC QP's supported\n");
		rv = -EINVAL;
		goto err_out;
	}
	if ((attrs->cap.max_send_wr > SIW_MAX_QP_WR) ||
	    (attrs->cap.max_recv_wr > SIW_MAX_QP_WR) ||
	    (attrs->cap.max_send_sge > SIW_MAX_SGE)  ||
	    (attrs->cap.max_recv_sge > SIW_MAX_SGE)) {
		dprint(DBG_ON, ": QP Size!\n");
		rv = -EINVAL;
		goto err_out;
	}
	if (attrs->cap.max_inline_data > SIW_MAX_INLINE) {
		dprint(DBG_ON, ": Max Inline Send %d > %d!\n",
		       attrs->cap.max_inline_data, (int)SIW_MAX_INLINE);
		rv = -EINVAL;
		goto err_out;
	}
	/*
	 * NOTE: we allow for zero element SQ and RQ WQE's SGL's
	 * but not for a QP unable to hold any WQE (SQ + RQ)
	 */
	if (attrs->cap.max_send_wr + attrs->cap.max_recv_wr == 0) {
		rv = -EINVAL;
		goto err_out;
	}

	scq = siw_cq_id2obj(sdev, ((struct siw_cq *)attrs->send_cq)->hdr.id);
	rcq = siw_cq_id2obj(sdev, ((struct siw_cq *)attrs->recv_cq)->hdr.id);

	if (!scq || !rcq) {
		dprint(DBG_OBJ, ": Fail: SCQ: 0x%p, RCQ: 0x%p\n",
			scq, rcq);
		rv = -EINVAL;
		goto err_out;
	}
	qp = kzalloc(sizeof(*qp), GFP_KERNEL);
	if (!qp) {
		dprint(DBG_ON, ": kzalloc\n");
		rv = -ENOMEM;
		goto err_out;
	}

	INIT_LIST_HEAD(&qp->freeq);
	INIT_LIST_HEAD(&qp->sq);
	INIT_LIST_HEAD(&qp->rq);
	INIT_LIST_HEAD(&qp->orq);
	INIT_LIST_HEAD(&qp->irq);

	init_rwsem(&qp->state_lock);
	spin_lock_init(&qp->freeq_lock);
	spin_lock_init(&qp->sq_lock);
	spin_lock_init(&qp->rq_lock);
	spin_lock_init(&qp->orq_lock);

	init_waitqueue_head(&qp->tx_ctx.waitq);

	rv = siw_qp_add(sdev, qp);
	if (rv)
		goto err_out;

	if (kernel_verbs) {
		int num_wqe = attrs->cap.max_send_wr + attrs->cap.max_recv_wr;
		while (num_wqe--) {
			struct siw_wqe *wqe = kzalloc(sizeof *wqe, GFP_KERNEL);
			if (!wqe) {
				rv = -ENOMEM;
				goto err_out_idr;
			}
			SIW_INC_STAT_WQE;
			INIT_LIST_HEAD(&wqe->list);
			list_add(&wqe->list, &qp->freeq);
		}
		qp->attrs.flags |= SIW_KERNEL_VERBS;
	}
	qp->pd  = pd;
	qp->scq = scq;
	qp->rcq = rcq;

	if (attrs->srq) {
		/*
		 * SRQ support.
		 * Verbs 6.3.7: ignore RQ size, if SRQ present
		 * Verbs 6.3.5: do not check PD of SRQ against PD of QP
		 */
		qp->srq = siw_srq_ofa2siw(attrs->srq);
		qp->attrs.rq_size = 0;
		atomic_set(&qp->rq_space, 0);
		dprint(DBG_OBJ, " QP(%d): SRQ(%p) attached\n",
			QP_ID(qp), qp->srq);
	} else {
		qp->srq = NULL;
		qp->attrs.rq_size = attrs->cap.max_recv_wr;
		atomic_set(&qp->rq_space, qp->attrs.rq_size);
	}
	qp->attrs.sq_size = attrs->cap.max_send_wr;
	atomic_set(&qp->sq_space, qp->attrs.sq_size);
	qp->attrs.sq_max_sges = attrs->cap.max_send_sge;
	/*
	 * ofed has no max_send_sge_rdmawrite
	 */
	qp->attrs.sq_max_sges_rdmaw = attrs->cap.max_send_sge;
	qp->attrs.rq_max_sges = attrs->cap.max_recv_sge;

	qp->attrs.state = SIW_QP_STATE_IDLE;

	if (udata) {
		uresp.sq_size = qp->attrs.sq_size;
		uresp.rq_size = qp->attrs.rq_size;
		uresp.qp_id = QP_ID(qp);

		rv = ib_copy_to_udata(udata, &uresp, sizeof uresp);
		if (rv)
			goto err_out_idr;
	}

	atomic_set(&qp->tx_ctx.in_use, 0);

	qp->ofa_qp.qp_num = QP_ID(qp);

	siw_pd_get(pd);

	INIT_LIST_HEAD(&qp->devq);
	spin_lock_irqsave(&sdev->idr_lock, flags);
	list_add_tail(&qp->devq, &sdev->qp_list);
	spin_unlock_irqrestore(&sdev->idr_lock, flags);

	return &qp->ofa_qp;

err_out_idr:
	siw_remove_obj(&sdev->idr_lock, &sdev->qp_idr, &qp->hdr);
err_out:
	if (scq)
		siw_cq_put(scq);
	if (rcq)
		siw_cq_put(rcq);

	if (qp)
		siw_drain_wq(&qp->freeq);

	kfree(qp);
	atomic_dec(&sdev->num_qp);

	return ERR_PTR(rv);
}

/*
 * Minimum siw_query_qp() verb interface.
 *
 * @qp_attr_mask is not used but all available information is provided
 */
int siw_query_qp(struct ib_qp *ofa_qp, struct ib_qp_attr *qp_attr,
		 int qp_attr_mask, struct ib_qp_init_attr *qp_init_attr)
{
	struct siw_qp *qp;
	struct siw_dev *sdev;

	if (ofa_qp && qp_attr && qp_init_attr) {
		qp = siw_qp_ofa2siw(ofa_qp);
		sdev = siw_dev_ofa2siw(ofa_qp->device);
	} else
		return -EINVAL;

	qp_attr->cap.max_inline_data = SIW_MAX_INLINE;
	qp_init_attr->cap.max_inline_data = SIW_MAX_INLINE;

	qp_attr->cap.max_send_wr = qp->attrs.sq_size;
	qp_attr->cap.max_recv_wr = qp->attrs.rq_size;
	qp_attr->cap.max_send_sge = qp->attrs.sq_max_sges;
	qp_attr->cap.max_recv_sge = qp->attrs.rq_max_sges;

	qp_attr->path_mtu = siw_mtu_net2ofa(sdev->netdev->mtu);
	qp_attr->max_rd_atomic = qp->attrs.ird;
	qp_attr->max_dest_rd_atomic = qp->attrs.ord;

	qp_attr->qp_access_flags = IB_ACCESS_LOCAL_WRITE |
			IB_ACCESS_REMOTE_WRITE | IB_ACCESS_REMOTE_READ;

	qp_init_attr->cap = qp_attr->cap;

	return 0;
}

int siw_ofed_modify_qp(struct ib_qp *ofa_qp, struct ib_qp_attr *attr,
		       int attr_mask, struct ib_udata *udata)
{
	struct siw_qp_attrs	new_attrs;
	enum siw_qp_attr_mask	siw_attr_mask = 0;
	struct siw_qp		*qp = siw_qp_ofa2siw(ofa_qp);
	int			rv = 0;

	if (!attr_mask) {
		dprint(DBG_CM, "(QP%d): attr_mask==0 ignored\n", QP_ID(qp));
		goto out;
	}
	siw_dprint_qp_attr_mask(attr_mask);

	memset(&new_attrs, 0, sizeof new_attrs);

	if (attr_mask & IB_QP_ACCESS_FLAGS) {

		siw_attr_mask |= SIW_QP_ATTR_ACCESS_FLAGS;

		if (attr->qp_access_flags & IB_ACCESS_REMOTE_READ)
			new_attrs.flags |= SIW_RDMA_READ_ENABLED;
		if (attr->qp_access_flags & IB_ACCESS_REMOTE_WRITE)
			new_attrs.flags |= SIW_RDMA_WRITE_ENABLED;
		if (attr->qp_access_flags & IB_ACCESS_MW_BIND)
			new_attrs.flags |= SIW_RDMA_BIND_ENABLED;
	}
	if (attr_mask & IB_QP_STATE) {
		dprint(DBG_CM, "(QP%d): Desired IB QP state: %s\n",
			   QP_ID(qp), ib_qp_state_to_string[attr->qp_state]);

		new_attrs.state = ib_qp_state_to_siw_qp_state[attr->qp_state];

		if (new_attrs.state > SIW_QP_STATE_RTS)
			qp->tx_ctx.tx_suspend = 1;

		/* TODO: SIW_QP_STATE_UNDEF is currently not possible ... */
		if (new_attrs.state == SIW_QP_STATE_UNDEF)
			return -EINVAL;

		siw_attr_mask |= SIW_QP_ATTR_STATE;
	}
	if (!attr_mask)
		goto out;

	down_write(&qp->state_lock);

	rv = siw_qp_modify(qp, &new_attrs, siw_attr_mask);

	up_write(&qp->state_lock);

out:
	dprint(DBG_CM, "(QP%d): Exit with %d\n", QP_ID(qp), rv);
	return rv;
}

int siw_destroy_qp(struct ib_qp *ofa_qp)
{
	struct siw_qp		*qp = siw_qp_ofa2siw(ofa_qp);
	struct siw_qp_attrs	qp_attrs;

	dprint(DBG_CM, "(QP%d): SIW QP state=%d, cep=0x%p\n",
		QP_ID(qp), qp->attrs.state, qp->cep);

	/*
	 * Mark QP as in process of destruction to prevent from eventual async
	 * callbacks to OFA core
	 */
	qp->attrs.flags |= SIW_QP_IN_DESTROY;
	qp->rx_ctx.rx_suspend = 1;

	down_write(&qp->state_lock);

	qp_attrs.state = SIW_QP_STATE_ERROR;
	(void)siw_qp_modify(qp, &qp_attrs, SIW_QP_ATTR_STATE);

	if (qp->cep) {
		siw_cep_put(qp->cep);
		qp->cep = NULL;
	}

	up_write(&qp->state_lock);

	if (qp->rx_ctx.crc_enabled)
		crypto_free_hash(qp->rx_ctx.mpa_crc_hd.tfm);
	if (qp->tx_ctx.crc_enabled)
		crypto_free_hash(qp->tx_ctx.mpa_crc_hd.tfm);

	/* Drop references */
	siw_cq_put(qp->scq);
	siw_cq_put(qp->rcq);
	siw_pd_put(qp->pd);
	qp->scq = qp->rcq = NULL;

	siw_qp_put(qp);

	return 0;
}

/*
 * siw_copy_sgl()
 *
 * Copy SGL from user (OFA) representation to local
 * representation.
 * Memory lookup and base+bounds checks must
 * be deferred until wqe gets executed
 */
static int siw_copy_sgl(struct ib_sge *ofa_sge, struct siw_sge *siw_sge,
			int num_sge)
{
	int bytes = 0;

	while (num_sge--) {
		siw_sge->addr = ofa_sge->addr;
		siw_sge->len  = ofa_sge->length;
		siw_sge->lkey = ofa_sge->lkey;
		/*
		 * defer memory lookup to WQE processing
		 */
		siw_sge->mem.obj = NULL;

		bytes += siw_sge->len;
		siw_sge++; ofa_sge++;
	}
	return bytes;
}

/*
 * siw_copy_inline_sgl()
 *
 * Prepare sgl of inlined data for sending. For userland callers
 * function checks if given buffer addresses and len's are within
 * process context bounds.
 * Data from all provided sge's are copied together into the wqe,
 * referenced by a single sge.
 */
static int siw_copy_inline_sgl(struct ib_send_wr *ofa_wr, struct siw_wqe *wqe)
{
	struct ib_sge	*ofa_sge = ofa_wr->sg_list;
	char		*kbuf	 = wqe->wr.inlined_data.data;
	int		num_sge	 = ofa_wr->num_sge,
			bytes	 = 0;

	wqe->wr.inlined_data.sge.mem.buf = NULL;
	wqe->wr.inlined_data.sge.addr = (u64)kbuf;
	wqe->wr.inlined_data.sge.lkey = 0;

	while (num_sge--) {
		if (!ofa_sge->length) {
			ofa_sge++;
			continue;
		}
		bytes += ofa_sge->length;
		if (bytes > SIW_MAX_INLINE) {
			bytes = -EINVAL;
			break;
		}
		if (wqe->qp->attrs.flags & SIW_KERNEL_VERBS)
			memcpy(kbuf,
			       (void *)(uintptr_t)ofa_sge->addr,
			       ofa_sge->length);
		else {
			if (!access_ok(VERIFY_READ,
				       (__user void *)(uintptr_t)ofa_sge->addr,
				       ofa_sge->length)) {
				bytes = -EFAULT;
				break;
			}
			if (__copy_from_user(kbuf, (__user void *)
					     (uintptr_t)ofa_sge->addr,
					     ofa_sge->length)) {
				bytes = -EFAULT;
				break;
			}
		}
		kbuf += ofa_sge->length;
		ofa_sge++;
	}
	wqe->wr.inlined_data.sge.len = bytes > 0 ? bytes : 0;
	wqe->wr.inlined_data.num_sge = bytes > 0 ? 1 : 0;

	dprint(DBG_WR, "(QP%d): Copied inline data: %d\n", QP_ID(wqe->qp),
	       bytes);

	return bytes;
}


/*
 * siw_wqe_alloc()
 *
 * Get new Send or Receive Queue WQE.
 *
 * To avoid blocking operation, kernel level clients get WQE's from
 * QP private freelist. To minimize resource pre-allocation, user
 * level clients get WQE's are kmalloc'ed.
 */
static inline struct siw_wqe *siw_wqe_alloc(struct siw_qp *qp,
					    enum siw_wr_opcode op)
{
	struct siw_wqe	*wqe = NULL;
	atomic_t	*q_space;

	q_space = (op == SIW_WR_RECEIVE) ? &qp->rq_space : &qp->sq_space;

	if (atomic_dec_return(q_space) < 0)
			goto out;

	if (qp->attrs.flags & SIW_KERNEL_VERBS)
		wqe = siw_freeq_wqe_get(qp);
	else {
		wqe = kmalloc(sizeof(struct siw_wqe), GFP_KERNEL);
		SIW_INC_STAT_WQE;
	}
out:
	if (wqe) {
		INIT_LIST_HEAD(&wqe->list);
		wqe->processed = 0;
		wqe->wr.sgl.num_sge = 0;
		siw_qp_get(qp);
		wqe->qp = qp;
	} else {
		atomic_inc(q_space);
		dprint(DBG_WR, " Failed, type:%d\n", op);
	}
	return wqe;
}

/*
 * siw_post_send()
 *
 * Post a list of S-WR's to a SQ.
 *
 * @ofa_qp:	OFA QP contained in siw QP
 * @wr:		Null terminated list of user WR's
 * @bad_wr:	Points to failing WR in case of synchronous failure.
 */
int siw_post_send(struct ib_qp *ofa_qp, struct ib_send_wr *wr,
		  struct ib_send_wr **bad_wr)
{
	struct siw_wqe	*wqe = NULL;
	struct siw_qp	*qp = siw_qp_ofa2siw(ofa_qp);

	unsigned long flags;
	int rv = 0;

	dprint(DBG_WR|DBG_TX, "(QP%d): state=%d\n",
		QP_ID(qp), qp->attrs.state);

	/*
	 * Try to acquire QP state lock. Must be non-blocking
	 * to accommodate kernel clients needs.
	 */
	if (!down_read_trylock(&qp->state_lock)) {
		*bad_wr = wr;
		return -ENOTCONN;
	}

	if (qp->attrs.state != SIW_QP_STATE_RTS) {
		dprint(DBG_WR|DBG_ON, "(QP%d): state=%d\n",
			QP_ID(qp), qp->attrs.state);
		up_read(&qp->state_lock);
		*bad_wr = wr;
		return -ENOTCONN;
	}
	dprint(DBG_WR|DBG_TX, "(QP%d): sq_space(#1)=%d\n",
		QP_ID(qp), atomic_read(&qp->sq_space));

	while (wr) {
		wqe = siw_wqe_alloc(qp, opcode_ofa2siw(wr->opcode));
		if (!wqe) {
			dprint(DBG_ON, " siw_wqe_alloc\n");
			rv = -ENOMEM;
			break;
		}
		wr_type(wqe) = opcode_ofa2siw(wr->opcode);
		wr_flags(wqe) = wr->send_flags;
		wr_id(wqe) = wr->wr_id;

		if (wr->num_sge > qp->attrs.sq_max_sges) {
			/*
			 * NOTE: we allow for zero length wr's here.
			 */
			dprint(DBG_WR, "(QP%d): Num SGE: %d\n",
				QP_ID(qp), wr->num_sge);
			rv = -EINVAL;
			break;
		}

		switch (wr->opcode) {

		case IB_WR_SEND:
			if (!SIW_INLINED_DATA(wqe)) {
				rv = siw_copy_sgl(wr->sg_list,
						  wqe->wr.send.sge,
						  wr->num_sge);
				wqe->wr.send.num_sge = wr->num_sge;
			} else
				rv = siw_copy_inline_sgl(wr, wqe);

			if (rv <= 0) {
				rv = -EINVAL;
				break;
			}
			wqe->bytes = rv;
			break;

		case IB_WR_RDMA_READ:
			/*
			 * OFED WR restricts RREAD sink to SGL containing
			 * 1 SGE only. we could relax to SGL with multiple
			 * elements referring the SAME ltag or even sending
			 * a private per-rreq tag referring to a checked
			 * local sgl with MULTIPLE ltag's. would be easy
			 * to do...
			 */
			if (wr->num_sge != 1) {
				rv = -EINVAL;
				break;
			}
			rv = siw_copy_sgl(wr->sg_list, wqe->wr.rread.sge, 1);
			/*
			 * NOTE: zero length RREAD is allowed!
			 */
			wqe->wr.rread.raddr = wr->wr.rdma.remote_addr;
			wqe->wr.rread.rtag = wr->wr.rdma.rkey;
			wqe->wr.rread.num_sge = 1;
			wqe->bytes = rv;
			break;

		case IB_WR_RDMA_WRITE:
			if (!SIW_INLINED_DATA(wqe)) {
				rv = siw_copy_sgl(wr->sg_list,
						  wqe->wr.send.sge,
						  wr->num_sge);
				wqe->wr.write.num_sge = wr->num_sge;
			} else
				rv = siw_copy_inline_sgl(wr, wqe);
			/*
			 * NOTE: zero length WRITE is allowed!
			 */
			if (rv < 0) {
				rv = -EINVAL;
				break;
			}
			wqe->wr.write.raddr = wr->wr.rdma.remote_addr;
			wqe->wr.write.rtag = wr->wr.rdma.rkey;
			wqe->bytes = rv;
			break;

		default:
			dprint(DBG_WR|DBG_TX|DBG_ON,
				"(QP%d): Opcode %d not yet implemented\n",
				QP_ID(qp), wr->opcode);
			wqe->wr.sgl.num_sge = 0;
			rv = -EINVAL;
			break;
		}
		dprint(DBG_WR|DBG_TX, "(QP%d): opcode %d, bytes %d, "
				"flags 0x%x\n",
				QP_ID(qp), wr_type(wqe), wqe->bytes,
				wr_flags(wqe));
		if (rv < 0)
			break;

		wqe->wr_status = SR_WR_QUEUED;

		lock_sq_rxsave(qp, flags);
		list_add_tail(&wqe->list, &qp->sq);
		unlock_sq_rxsave(qp, flags);

		wr = wr->next;
	}
	/*
	 * Send directly if SQ processing is not in progress.
	 * Eventual immediate errors (rv < 0) do not affect the involved
	 * RI resources (Verbs, 8.3.1) and thus do not prevent from SQ
	 * processing, if new work is already pending. But rv must be passed
	 * to caller.
	 */
	lock_sq_rxsave(qp, flags);
	if (tx_wqe(qp) == NULL) {
		struct siw_wqe	*next = siw_next_tx_wqe(qp);
		if (next != NULL) {
			if (wr_type(next) != SIW_WR_RDMA_READ_REQ ||
			    !ORD_SUSPEND_SQ(qp)) {
				tx_wqe(qp) = next;
				if (wr_type(next) != SIW_WR_RDMA_READ_REQ)
					list_del_init(&next->list);
				else
					siw_rreq_queue(next, qp);

				unlock_sq_rxsave(qp, flags);

				dprint(DBG_WR|DBG_TX,
					"(QP%d): Direct sending...\n",
					QP_ID(qp));

				if (qp->attrs.flags & SIW_KERNEL_VERBS)
					siw_sq_queue_work(qp);
				else if (siw_qp_sq_process(qp, 1) != 0 &&
				    !(qp->tx_ctx.tx_suspend))
					siw_qp_cm_drop(qp, 0);
			} else
				unlock_sq_rxsave(qp, flags);
		} else
			unlock_sq_rxsave(qp, flags);
	} else
		unlock_sq_rxsave(qp, flags);

	up_read(&qp->state_lock);

	dprint(DBG_WR|DBG_TX, "(QP%d): sq_space(#2)=%d\n", QP_ID(qp),
		atomic_read(&qp->sq_space));
	if (rv >= 0)
		return 0;
	/*
	 * Immediate error
	 */
	dprint(DBG_WR|DBG_ON, "(QP%d): error=%d\n", QP_ID(qp), rv);

	if (wqe != NULL)
		siw_wqe_put(wqe);
	*bad_wr = wr;
	return rv;
}

/*
 * siw_post_receive()
 *
 * Post a list of R-WR's to a RQ.
 *
 * @ofa_qp:	OFA QP contained in siw QP
 * @wr:		Null terminated list of user WR's
 * @bad_wr:	Points to failing WR in case of synchronous failure.
 */
int siw_post_receive(struct ib_qp *ofa_qp, struct ib_recv_wr *wr,
		     struct ib_recv_wr **bad_wr)
{
	struct siw_wqe	*wqe = NULL;
	struct siw_qp	*qp = siw_qp_ofa2siw(ofa_qp);
	unsigned long	flags;
	int rv = 0;

	dprint(DBG_WR|DBG_TX, "(QP%d): state=%d\n", QP_ID(qp),
		qp->attrs.state);

	if (qp->srq) {
		*bad_wr = wr;
		return -EOPNOTSUPP; /* what else from errno.h? */
	}
	/*
	 * Try to acquire QP state lock. Must be non-blocking
	 * to accommodate kernel clients needs.
	 */
	if (!down_read_trylock(&qp->state_lock)) {
		*bad_wr = wr;
		return -ENOTCONN;
	}

	if (qp->attrs.state > SIW_QP_STATE_RTS) {
		up_read(&qp->state_lock);
		dprint(DBG_ON, " (QP%d): state=%d\n", QP_ID(qp),
			qp->attrs.state);
		*bad_wr = wr;
		return -EINVAL;
	}
	while (wr) {
		wqe = siw_wqe_alloc(qp, SIW_WR_RECEIVE);
		if (!wqe) {
			rv = -ENOMEM;
			break;
		}
		if (wr->num_sge > qp->attrs.rq_max_sges) {
			dprint(DBG_WR|DBG_ON, "(QP%d): Num SGE: %d\n",
				QP_ID(qp), wr->num_sge);
			rv = -EINVAL;
			break;
		}
		wr_type(wqe) = SIW_WR_RECEIVE;
		wr_id(wqe) = wr->wr_id;

		rv = siw_copy_sgl(wr->sg_list, wqe->wr.recv.sge, wr->num_sge);
		if (rv < 0) {
			/*
			 * XXX tentatively allow zero length receive
			 */
			rv = -EINVAL;
			break;
		}
		wqe->wr.recv.num_sge = wr->num_sge;
		wqe->bytes = rv;
		wqe->wr_status = SR_WR_QUEUED;

		lock_rq_rxsave(qp, flags);
		list_add_tail(&wqe->list, &qp->rq);
		unlock_rq_rxsave(qp, flags);

		wr = wr->next;
	}
	if (rv <= 0) {
		dprint(DBG_WR|DBG_ON, "(QP%d): error=%d\n", QP_ID(qp), rv);
		if (wqe != NULL)
			siw_wqe_put(wqe);
		*bad_wr = wr;
	}
	dprint(DBG_WR|DBG_RX, "(QP%d): rq_space=%d\n", QP_ID(qp),
		atomic_read(&qp->rq_space));

	up_read(&qp->state_lock);

	return rv > 0 ? 0 : rv;
}

int siw_destroy_cq(struct ib_cq *ofa_cq)
{
	struct siw_cq		*cq  = siw_cq_ofa2siw(ofa_cq);
	struct ib_device	*ofa_dev = ofa_cq->device;
	struct siw_dev		*sdev = siw_dev_ofa2siw(ofa_dev);

	siw_cq_flush(cq);

	siw_remove_obj(&sdev->idr_lock, &sdev->cq_idr, &cq->hdr);
	siw_cq_put(cq);

	return 0;
}

/*
 * siw_create_cq()
 *
 * Create CQ of requested size on given device.
 *
 * @ofa_dev:	OFA device contained in siw device
 * @size:	maximum number of CQE's allowed.
 * @ib_context: user context.
 * @udata:	used to provide CQ ID back to user.
 */

struct ib_cq *siw_create_cq(struct ib_device *ofa_dev, int size,
			    int vec /* unused */,
			    struct ib_ucontext *ib_context,
			    struct ib_udata *udata)
{
	struct siw_cq			*cq = NULL;
	struct siw_dev			*sdev = siw_dev_ofa2siw(ofa_dev);
	struct siw_uresp_create_cq	uresp;
	int rv;

	if (atomic_inc_return(&sdev->num_cq) > SIW_MAX_CQ) {
		dprint(DBG_ON, ": Out of CQ's\n");
		rv = -ENOMEM;
		goto err_out;
	}
	if (size < 1 || size > SIW_MAX_CQE) {
		dprint(DBG_ON, ": CQE: %d\n", size);
		rv = -EINVAL;
		goto err_out;
	}
	cq = kmalloc(sizeof *cq, GFP_KERNEL);
	if (!cq) {
		dprint(DBG_ON, ":  kmalloc\n");
		rv = -ENOMEM;
		goto err_out;
	}
	cq->ofa_cq.cqe = size - 1;

	rv = siw_cq_add(sdev, cq);
	if (rv)
		goto err_out_idr;

	INIT_LIST_HEAD(&cq->queue);
	spin_lock_init(&cq->lock);
	atomic_set(&cq->qlen, 0);

	if (ib_context) {
		uresp.cq_id = OBJ_ID(cq);

		rv = ib_copy_to_udata(udata, &uresp, sizeof uresp);
		if (rv)
			goto err_out_idr;
	}
	return &cq->ofa_cq;

err_out_idr:
	siw_remove_obj(&sdev->idr_lock, &sdev->cq_idr, &cq->hdr);
err_out:
	dprint(DBG_OBJ, ": CQ creation failed\n");

	kfree(cq);
	atomic_dec(&sdev->num_cq);

	return ERR_PTR(rv);
}

/*
 * siw_poll_cq()
 *
 * Reap CQ entries if available and copy work completion status into
 * array of WC's provided by caller. Returns number of reaped CQE's.
 *
 * @ofa_cq:	OFA CQ contained in siw CQ.
 * @num_cqe:	Maximum number of CQE's to reap.
 * @wc:		Array of work completions to be filled by siw.
 */
int siw_poll_cq(struct ib_cq *ofa_cq, int num_cqe, struct ib_wc *wc)
{
	struct siw_cq		*cq  = siw_cq_ofa2siw(ofa_cq);
	int			i;

	for (i = 0; i < num_cqe; i++) {
		if (!(siw_reap_cqe(cq, wc)))
			break;
		wc++;
	}
	dprint(DBG_CQ, " CQ%d: reap %d completions (%d left)\n",
		OBJ_ID(cq), i, atomic_read(&cq->qlen));

	return i;
}

/*
 * siw_req_notify_cq()
 *
 * Request notification for new CQE's added to that CQ.
 * Defined flags:
 * o SIW_CQ_NOTIFY_SOLICITED lets siw trigger a notification
 *   event if a WQE with notification flag set enters the CQ
 * o SIW_CQ_NOTIFY_NEXT_COMP lets siw trigger a notification
 *   event if a WQE enters the CQ.
 * o IB_CQ_REPORT_MISSED_EVENTS: return value will provide the
 *   number of not reaped CQE's regardless of its notification
 *   type and current or new CQ notification settings.
 *
 * @ofa_cq:	OFA CQ contained in siw CQ.
 * @flags:	Requested notification flags.
 */
int siw_req_notify_cq(struct ib_cq *ofa_cq, enum ib_cq_notify_flags flags)
{
	struct siw_cq	 *cq  = siw_cq_ofa2siw(ofa_cq);

	dprint(DBG_EH, "(CQ%d:) flags: 0x%8x\n", OBJ_ID(cq), flags);

	if ((flags & IB_CQ_SOLICITED_MASK) == IB_CQ_SOLICITED)
		cq->notify = SIW_CQ_NOTIFY_SOLICITED;
	else
		cq->notify = SIW_CQ_NOTIFY_ALL;

	if (flags & IB_CQ_REPORT_MISSED_EVENTS)
		return atomic_read(&cq->qlen);

	return 0;
}

/*
 * siw_dereg_mr()
 *
 * Release Memory Region.
 *
 * TODO: Update function if Memory Windows are supported by siw:
 *       Is OFED core checking for MW dependencies for current
 *       MR before calling MR deregistration?.
 *
 * @ofa_mr:     OFA MR contained in siw MR.
 */
int siw_dereg_mr(struct ib_mr *ofa_mr)
{
	struct siw_mr	*mr;
	struct siw_dev	*sdev = siw_dev_ofa2siw(ofa_mr->device);

	mr = siw_mr_ofa2siw(ofa_mr);

	dprint(DBG_OBJ|DBG_MM, "(MEM%d): Release UMem %p, #ref's: %d\n",
		mr->mem.hdr.id, mr->umem,
		atomic_read(&mr->mem.hdr.ref.refcount));

	mr->mem.stag_state = STAG_INVALID;

	siw_pd_put(mr->pd);
	siw_remove_obj(&sdev->idr_lock, &sdev->mem_idr, &mr->mem.hdr);
	siw_mem_put(&mr->mem);

	return 0;
}

static struct siw_mr *siw_alloc_mr(struct siw_dev *sdev, struct ib_umem *umem,
				   u64 start, u64 len, int rights)
{
	struct siw_mr *mr = kzalloc(sizeof *mr, GFP_KERNEL);
	if (!mr)
		return NULL;

	mr->mem.stag_state = STAG_INVALID;

	if (siw_mem_add(sdev, &mr->mem) < 0) {
		dprint(DBG_ON, ": siw_mem_add\n");
		kfree(mr);
		return NULL;
	}
	dprint(DBG_OBJ|DBG_MM, "(MEM%d): New Object, UMEM %p\n",
		mr->mem.hdr.id, umem);

	mr->ofa_mr.lkey = mr->ofa_mr.rkey = mr->mem.hdr.id << 8;

	mr->mem.va  = start;
	mr->mem.len = len;
	mr->mem.fbo = 0 ;
	mr->mem.mr  = NULL;
	mr->mem.perms = SR_MEM_LREAD | /* not selectable in OFA */
			(rights & IB_ACCESS_REMOTE_READ  ? SR_MEM_RREAD  : 0) |
			(rights & IB_ACCESS_LOCAL_WRITE  ? SR_MEM_LWRITE : 0) |
			(rights & IB_ACCESS_REMOTE_WRITE ? SR_MEM_RWRITE : 0);

	mr->umem = umem;

	return mr;
}

/*
 * siw_reg_user_mr()
 *
 * Register Memory Region.
 *
 * @ofa_pd:	OFA PD contained in siw PD.
 * @start:	starting address of MR (virtual address)
 * @len:	len of MR
 * @rnic_va:	not used by siw
 * @rights:	MR access rights
 * @udata:	user buffer to communicate STag and Key.
 */
struct ib_mr *siw_reg_user_mr(struct ib_pd *ofa_pd, u64 start, u64 len,
			      u64 rnic_va, int rights, struct ib_udata *udata)
{
	struct siw_mr		*mr = NULL;
	struct siw_pd		*pd = siw_pd_ofa2siw(ofa_pd);
	struct ib_umem		*umem = NULL;
	struct siw_ureq_reg_mr	ureq;
	struct siw_uresp_reg_mr	uresp;
	struct siw_dev		*sdev = pd->hdr.sdev;

	unsigned long mem_limit = rlimit(RLIMIT_MEMLOCK);
	int rv;

	dprint(DBG_MM|DBG_OBJ, " start: 0x%016llx, "
		"va: 0x%016llx, len: %llu, ctx: %p\n",
		(unsigned long long)start,
		(unsigned long long)rnic_va,
		(unsigned long long)len,
		ofa_pd->uobject->context);
	if (atomic_inc_return(&sdev->num_mem) > SIW_MAX_MR) {
		dprint(DBG_ON, ": Out of MRs: %d\n",
			atomic_read(&sdev->num_mem));
		rv = -ENOMEM;
		goto err_out;
	}
	if (!len) {
		rv = -EINVAL;
		goto err_out;
	}
	if (mem_limit != RLIM_INFINITY) {
		unsigned long num_pages =
			(PAGE_ALIGN(len + (start & ~PAGE_MASK))) >> PAGE_SHIFT;
		mem_limit >>= PAGE_SHIFT;

		if (num_pages > mem_limit - current->mm->locked_vm) {
			dprint(DBG_ON|DBG_MM,
				": pages req: %lu, limit: %lu, locked: %lu\n",
				num_pages, mem_limit, current->mm->locked_vm);
			rv = -ENOMEM;
			goto err_out;
		}
	}
	umem = ib_umem_get(ofa_pd->uobject->context, start, len, rights, 0);
	if (IS_ERR(umem)) {
		dprint(DBG_MM, " ib_umem_get:%ld LOCKED:%lu, LIMIT:%lu\n",
			PTR_ERR(umem), current->mm->locked_vm,
			current->signal->rlim[RLIMIT_MEMLOCK].rlim_cur >>
			PAGE_SHIFT);
		rv = PTR_ERR(umem);
		umem = NULL;
		goto err_out;
	}
	mr = siw_alloc_mr(sdev, umem, start, len, rights);
	if (!mr) {
		rv = -ENOMEM;
		goto err_out;
	}

	if (udata) {
		rv = ib_copy_from_udata(&ureq, udata, sizeof ureq);
		if (rv)
			goto err_out_mr;

		mr->ofa_mr.lkey |= ureq.stag_key;
		mr->ofa_mr.rkey |= ureq.stag_key; /* XXX ??? */
		uresp.stag = mr->ofa_mr.lkey;

		rv = ib_copy_to_udata(udata, &uresp, sizeof uresp);
		if (rv)
			goto err_out_mr;
	}
	mr->pd = pd;
	siw_pd_get(pd);

	mr->mem.stag_state = STAG_VALID;

	return &mr->ofa_mr;

err_out_mr:
	siw_remove_obj(&sdev->idr_lock, &sdev->mem_idr, &mr->mem.hdr);
	kfree(mr);

err_out:
	if (umem)
		ib_umem_release(umem);

	atomic_dec(&sdev->num_mem);

	return ERR_PTR(rv);
}


/*
 * siw_get_dma_mr()
 *
 * Create a (empty) DMA memory region, where no umem is attached.
 * All DMA addresses are created via siw_dma_mapping_ops - which
 * will return just kernel virtual addresses, since siw runs on top
 * of TCP kernel sockets.
 */
struct ib_mr *siw_get_dma_mr(struct ib_pd *ofa_pd, int rights)
{
	struct siw_mr	*mr;
	struct siw_pd	*pd = siw_pd_ofa2siw(ofa_pd);
	struct siw_dev	*sdev = pd->hdr.sdev;
	int rv;

	if (atomic_inc_return(&sdev->num_mem) > SIW_MAX_MR) {
		dprint(DBG_ON, ": Out of MRs: %d\n",
			atomic_read(&sdev->num_mem));
		rv = -ENOMEM;
		goto err_out;
	}
	mr = siw_alloc_mr(sdev, NULL, 0, ULONG_MAX, rights);
	if (!mr) {
		rv = -ENOMEM;
		goto err_out;
	}
	mr->mem.stag_state = STAG_VALID;

	mr->pd = pd;
	siw_pd_get(pd);

	return &mr->ofa_mr;

err_out:
	atomic_dec(&sdev->num_mem);

	return ERR_PTR(rv);
}


/*
 * siw_create_srq()
 *
 * Create Shared Receive Queue of attributes @init_attrs
 * within protection domain given by @ofa_pd.
 *
 * @ofa_pd:	OFA PD contained in siw PD.
 * @init_attrs:	SRQ init attributes.
 * @udata:	not used by siw.
 */
struct ib_srq *siw_create_srq(struct ib_pd *ofa_pd,
			      struct ib_srq_init_attr *init_attrs,
			      struct ib_udata *udata)
{
	struct siw_srq		*srq = NULL;
	struct ib_srq_attr	*attrs = &init_attrs->attr;
	struct siw_pd		*pd = siw_pd_ofa2siw(ofa_pd);
	struct siw_dev		*sdev = pd->hdr.sdev;
	struct siw_wqe		*wqe;

	int kernel_verbs = ofa_pd->uobject ? 0 : 1;
	int rv;

	if (atomic_inc_return(&sdev->num_srq) > SIW_MAX_SRQ) {
		dprint(DBG_ON, " Out of SRQ's\n");
		rv = -ENOMEM;
		goto err_out;
	}
	if (attrs->max_wr > SIW_MAX_SRQ_WR || attrs->max_sge > SIW_MAX_SGE ||
	    attrs->srq_limit > attrs->max_wr) {
		rv = -EINVAL;
		goto err_out;
	}

	srq = kzalloc(sizeof *srq, GFP_KERNEL);
	if (!srq) {
		dprint(DBG_ON, " malloc\n");
		rv = -ENOMEM;
		goto err_out;
	}
	INIT_LIST_HEAD(&srq->rq);
	INIT_LIST_HEAD(&srq->freeq);
	srq->max_sge = attrs->max_sge;
	atomic_set(&srq->space, attrs->max_wr);
	srq->limit = attrs->srq_limit;
	srq->max_wr = attrs->max_wr;
	if (srq->limit)
		srq->armed = 1;


	if (kernel_verbs) {
		int num_wqe = attrs->max_wr;
		spin_lock_init(&srq->freeq_lock);
		srq->kernel_verbs = 1;
		while (num_wqe--) {
			wqe = kzalloc(sizeof(struct siw_wqe), GFP_KERNEL);
			if (!wqe) {
				rv = -ENOMEM;
				goto err_out;
			}
			INIT_LIST_HEAD(&wqe->list);
			list_add(&wqe->list, &srq->freeq);
		}
	}
	srq->pd	= pd;
	siw_pd_get(pd);

	spin_lock_init(&srq->lock);

	return &srq->ofa_srq;

err_out:
	if (srq)
		siw_drain_wq(&srq->freeq);

	kfree(srq);
	atomic_dec(&sdev->num_srq);

	return ERR_PTR(rv);
}

/*
 * siw_modify_srq()
 *
 * Modify SRQ. The caller may resize SRQ and/or set/reset notification
 * limit and (re)arm IB_EVENT_SRQ_LIMIT_REACHED notification.
 *
 * NOTE: it is unclear if OFA allows for changing the MAX_SGE
 * parameter. siw_modify_srq() does not check the attrs->max_sge param.
 */
int siw_modify_srq(struct ib_srq *ofa_srq, struct ib_srq_attr *attrs,
		   enum ib_srq_attr_mask attr_mask, struct ib_udata *udata)
{
	struct siw_srq	*srq = siw_srq_ofa2siw(ofa_srq);
	unsigned long	flags;
	int rv = 0;

	lock_srq_rxsave(srq, flags);

	if (attr_mask & IB_SRQ_MAX_WR) {
		/* resize request */
		if (attrs->max_wr > SIW_MAX_SRQ_WR) {
			rv =  -EINVAL;
			goto out;
		}
		if (attrs->max_wr < srq->max_wr) {
			/* shrink */
			if (attrs->max_wr <
			    srq->max_wr - atomic_read(&srq->space)) {
				rv = -EBUSY;
				goto out;
			}
			atomic_sub(srq->max_wr - attrs->max_wr, &srq->space);
		} else /* grow */
			atomic_add(attrs->max_wr - srq->max_wr, &srq->space);
		srq->max_wr = attrs->max_wr;
	}
	if (attr_mask & IB_SRQ_LIMIT) {
		if (attrs->srq_limit) {
			if (attrs->srq_limit > srq->max_wr) {
				rv = -EINVAL;
				/* FIXME: restore old space & max_wr?? */
				goto out;
			}
			srq->armed = 1;
		} else
			srq->armed = 0;

		srq->limit = attrs->srq_limit;
	}
out:
	unlock_srq_rxsave(srq, flags);
	return rv;
}

/*
 * siw_query_srq()
 *
 * Query SRQ attributes.
 */
int siw_query_srq(struct ib_srq *ofa_srq, struct ib_srq_attr *attrs)
{
	struct siw_srq	*srq = siw_srq_ofa2siw(ofa_srq);
	unsigned long	flags;

	lock_srq_rxsave(srq, flags);

	attrs->max_wr = srq->max_wr;
	attrs->max_sge = srq->max_sge;
	attrs->srq_limit = srq->limit;

	unlock_srq_rxsave(srq, flags);

	return 0;
}

/*
 * siw_destroy_srq()
 *
 * Destroy SRQ.
 * It is assumed that the SRQ is not referenced by any
 * QP anymore - the code trusts the OFA environment to keep track
 * of QP references.
 */
int siw_destroy_srq(struct ib_srq *ofa_srq)
{
	struct siw_srq		*srq = siw_srq_ofa2siw(ofa_srq);
	struct siw_dev		*sdev = srq->pd->hdr.sdev;

	siw_drain_wq(&srq->rq);
	siw_drain_wq(&srq->freeq);

	siw_pd_put(srq->pd);

	kfree(srq);
	atomic_dec(&sdev->num_srq);

	return 0;
}

static inline struct siw_wqe *siw_srq_wqe_alloc(struct siw_srq *srq)
{
	struct siw_wqe *wqe = NULL;

	if (atomic_dec_return(&srq->space) < 0)
		goto out;

	if (srq->kernel_verbs) {
		unsigned long flags;
		spin_lock_irqsave(&srq->freeq_lock, flags);
		if (!list_empty(&srq->freeq)) {
			wqe = list_first_wqe(&srq->freeq);
			list_del(&wqe->list);
		}
		spin_unlock_irqrestore(&srq->freeq_lock, flags);
	} else {
		wqe = kzalloc(sizeof(struct siw_wqe), GFP_KERNEL);
		SIW_INC_STAT_WQE;
	}

	dprint(DBG_OBJ|DBG_WR, "(SRQ%p): New WQE p: %p\n", srq, wqe);
out:
	if (wqe) {
		INIT_LIST_HEAD(&wqe->list);
		wqe->processed = 0;
	} else
		atomic_inc(&srq->space);

	return wqe;
}

/*
 * siw_post_srq_recv()
 *
 * Post a list of receive queue elements to SRQ.
 * NOTE: The function does not check or lock a certain SRQ state
 *       during the post operation. The code simply trusts the
 *       OFA environment.
 *
 * @ofa_srq:	OFA SRQ contained in siw SRQ
 * @wr:		List of R-WR's
 * @bad_wr:	Updated to failing WR if posting fails.
 */
int siw_post_srq_recv(struct ib_srq *ofa_srq, struct ib_recv_wr *wr,
		      struct ib_recv_wr **bad_wr)
{
	struct siw_srq	*srq = siw_srq_ofa2siw(ofa_srq);
	struct siw_wqe	*wqe = NULL;
	unsigned long flags;
	int rv = 0;

	while (wr) {
		wqe = siw_srq_wqe_alloc(srq);
		if (!wqe) {
			dprint(DBG_ON, " siw_srq_wqe_alloc\n");
			rv = -ENOMEM;
			break;
		}
		if (!wr->num_sge || wr->num_sge > srq->max_sge) {
			dprint(DBG_WR|DBG_ON,
				"(SRQ%p): Num SGE: %d\n", srq, wr->num_sge);
			rv = -EINVAL;
			break;
		}
		wr_type(wqe) = SIW_WR_RECEIVE;
		wr_id(wqe) = wr->wr_id;
		wqe->wr_status = SR_WR_QUEUED;

		rv = siw_copy_sgl(wr->sg_list, wqe->wr.recv.sge, wr->num_sge);
		if (rv == 0) {
			/*
			 * do not allow zero length receive
			 * XXX correct?
			 */
			rv = -EINVAL;
			break;
		}
		wqe->wr.recv.num_sge = wr->num_sge;
		wqe->bytes = rv;

		lock_srq_rxsave(srq, flags);
		list_add_tail(&wqe->list, &srq->rq);
		unlock_srq_rxsave(srq, flags);

		wr = wr->next;
	}
	if (rv <= 0) {
		dprint(DBG_WR|DBG_ON, "(SRQ %p): error=%d\n",
			srq, rv);

		if (wqe) {
			if (srq->kernel_verbs)
				siw_add_wqe(wqe, &srq->freeq,
					    &srq->freeq_lock);
			else {
				kfree(wqe);
				SIW_DEC_STAT_WQE;
			}
			atomic_inc(&srq->space);
		}
		*bad_wr = wr;
	}
	dprint(DBG_WR|DBG_RX, "(SRQ%p): space=%d\n",
		srq, atomic_read(&srq->space));

	return rv > 0 ? 0 : rv;
}


int siw_mmap(struct ib_ucontext *ctx, struct vm_area_struct *vma)
{
	return -ENOSYS;
}

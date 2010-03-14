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

#include <linux/spinlock.h>
#include <linux/kref.h>

#include "siw.h"
#include "siw_obj.h"
#include "siw_cm.h"


void siw_objhdr_init(struct siw_objhdr *hdr)
{
	kref_init(&hdr->ref);
}

void siw_idr_init(struct siw_dev *dev)
{
	spin_lock_init(&dev->idr_lock);

	idr_init(&dev->qp_idr);
	idr_init(&dev->cq_idr);
	idr_init(&dev->pd_idr);
	idr_init(&dev->mem_idr);
}

void siw_idr_release(struct siw_dev *dev)
{
	idr_destroy(&dev->qp_idr);
	idr_destroy(&dev->cq_idr);
	idr_destroy(&dev->pd_idr);
	idr_destroy(&dev->mem_idr);
}

static inline int siw_add_obj(spinlock_t *lock, struct idr *idr,
			      struct siw_objhdr *obj)
{
	u32		pre_id, id;
	int		rv;

	get_random_bytes(&pre_id, sizeof pre_id);
	pre_id &= 0xffff;
again:
	do {
		if (!(idr_pre_get(idr, GFP_KERNEL)))
			return -ENOMEM;

		spin_lock_bh(lock);
		rv = idr_get_new_above(idr, obj, pre_id, &id);
		spin_unlock_bh(lock);

	} while  (rv == -EAGAIN);

	if (rv == 0) {
		siw_objhdr_init(obj);
		obj->id = id;
		dprint(DBG_OBJ, "(OBJ%d): IDR New Object\n", id);
	} else if (rv == -ENOSPC && pre_id != 1) {
		pre_id = 1;
		goto again;
	} else {
		dprint(DBG_OBJ|DBG_ON, "(OBJ??): IDR New Object failed!\n");
	}
	return rv;
}

static inline struct siw_objhdr *siw_get_obj(struct idr *idr, int id)
{
	struct siw_objhdr *obj;

	obj = idr_find(idr, id);
	if (obj)
		kref_get(&obj->ref);

	return obj;
}

struct siw_cq *siw_cq_id2obj(struct siw_dev *dev, int id)
{
	struct siw_objhdr *obj = siw_get_obj(&dev->cq_idr, id);
	if (obj)
		return container_of(obj, struct siw_cq, hdr);

	return NULL;
}

struct siw_qp *siw_qp_id2obj(struct siw_dev *dev, int id)
{
	struct siw_objhdr *obj = siw_get_obj(&dev->qp_idr, id);
	if (obj)
		return container_of(obj, struct siw_qp, hdr);

	return NULL;
}

/*
 * siw_mem_id2obj()
 *
 * resolves memory from stag given by id. might be called from:
 * o process context before sending out of sgl
 * o or in softirq when resolving target memory
 */
struct siw_mem *siw_mem_id2obj(struct siw_dev *dev, int id)
{
	struct siw_objhdr *obj;

	spin_lock_bh(&dev->idr_lock);
	obj = siw_get_obj(&dev->mem_idr, id);
	spin_unlock_bh(&dev->idr_lock);

	if (obj) {
		dprint(DBG_MM|DBG_OBJ, "(MEM%d): New refcount: %d\n",
		       obj->id, obj->ref.refcount.counter);

		return container_of(obj, struct siw_mem, hdr);
	}
	dprint(DBG_MM|DBG_OBJ|DBG_ON, "(MEM%d): not found!\n", id);

	return NULL;
}

int siw_qp_add(struct siw_dev *dev, struct siw_qp *qp)
{
	int rv = siw_add_obj(&dev->idr_lock, &dev->qp_idr, &qp->hdr);
	if (!rv) {
		dprint(DBG_OBJ, "(QP%d): New Object\n", QP_ID(qp));
		qp->hdr.dev = dev;
	}
	return rv;
}

int siw_cq_add(struct siw_dev *dev, struct siw_cq *cq)
{
	int rv = siw_add_obj(&dev->idr_lock, &dev->cq_idr, &cq->hdr);
	if (!rv) {
		dprint(DBG_OBJ, "(CQ%d): New Object\n", cq->hdr.id);
		cq->hdr.dev = dev;
	}
	return rv;
}

int siw_pd_add(struct siw_dev *dev, struct siw_pd *pd)
{
	int rv = siw_add_obj(&dev->idr_lock, &dev->pd_idr, &pd->hdr);
	if (!rv) {
		dprint(DBG_OBJ, "(PD%d): New Object\n", pd->hdr.id);
		pd->hdr.dev = dev;
	}
	return rv;
}

/*
 * Stag lookup is based on its index part only (24 bits)
 * It is assumed that the idr_get_new_above(,,1,) function will
 * always return a new id within this range (0x1...0xffffff),
 * if one is available.
 * The code avoids special Stag of zero and tries to randomize
 * STag values.
 */
int siw_mem_add(struct siw_dev *dev, struct siw_mem *m)
{
	u32	id, pre_id;
	int	rv;

	do {
		get_random_bytes(&pre_id, sizeof pre_id);
		pre_id &= 0xffff;
	} while (pre_id == 0);
again:
	do {
		if (!(idr_pre_get(&dev->mem_idr, GFP_KERNEL)))
			return -ENOMEM;

		spin_lock_bh(&dev->idr_lock);
		rv = idr_get_new_above(&dev->mem_idr, m, pre_id, &id);
		spin_unlock_bh(&dev->idr_lock);

	} while (rv == -EAGAIN);

	if (rv == -ENOSPC || (rv == 0 && id > SIW_STAG_MAX)) {
		if (rv == 0) {
			spin_lock_bh(&dev->idr_lock);
			idr_remove(&dev->mem_idr, id);
			spin_unlock_bh(&dev->idr_lock);
		}
		if (pre_id == 1) {
			dprint(DBG_OBJ|DBG_MM|DBG_ON,
				"(IDR): New Object failed: %d\n", pre_id);
			return -ENOSPC;
		}
		pre_id = 1;
		goto again;
	} else if (rv) {
		dprint(DBG_OBJ|DBG_MM|DBG_ON,
			"(IDR%d): New Object failed: rv %d\n", id, rv);
		return rv;
	}
	siw_objhdr_init(&m->hdr);
	m->hdr.id = id;
	m->hdr.dev = dev;
	dprint(DBG_OBJ|DBG_MM, "(IDR%d): New Object\n", id);

	return 0;
}

void siw_remove_obj(spinlock_t *lock, struct idr *idr,
		      struct siw_objhdr *hdr)
{
	dprint(DBG_OBJ, "(OBJ%d): IDR Remove Object\n", hdr->id);

	spin_lock_bh(lock);
	idr_remove(idr, hdr->id);
	spin_unlock_bh(lock);
}


/********** routines to put objs back and free if no ref left *****/

static void siw_free_cq(struct kref *ref)
{
	struct siw_cq *cq =
		(container_of(container_of(ref, struct siw_objhdr, ref),
			      struct siw_cq, hdr));

	dprint(DBG_OBJ, "(CQ%d): Free Object\n", cq->hdr.id);

	kfree(cq);
}

static void siw_free_qp(struct kref *ref)
{
	struct siw_qp	*qp =
		container_of(container_of(ref, struct siw_objhdr, ref),
			     struct siw_qp, hdr);

	dprint(DBG_OBJ|DBG_CM|DBG_QP, "(QP%d): Free Object\n", QP_ID(qp));

	if (qp->cep)
		siw_cep_put(qp->cep);

	kfree(qp);
}

static void siw_free_pd(struct kref *ref)
{
	struct siw_pd	*pd =
		container_of(container_of(ref, struct siw_objhdr, ref),
			     struct siw_pd, hdr);

	dprint(DBG_OBJ, "(PD%d): Free Object\n", pd->hdr.id);

	kfree(pd);
}

static void siw_free_mem(struct kref *ref)
{
	struct siw_mem *m;

	m = container_of(container_of(ref, struct siw_objhdr, ref),
			 struct siw_mem, hdr);

	dprint(DBG_MM|DBG_OBJ, "(MEM%d): Free Object\n", OBJ_ID(m));

	if (SIW_MEM_IS_MW(m)) {
		struct siw_mw *mw = container_of(m, struct siw_mw, mem);
		kfree(mw);
	} else {
		struct siw_mr *mr = container_of(m, struct siw_mr, mem);
		dprint(DBG_MM|DBG_OBJ, "(MEM%d): Release UMem\n", OBJ_ID(m));
		ib_umem_release(mr->umem);
		kfree(mr);
	}
}


void siw_cq_put(struct siw_cq *cq)
{
	dprint(DBG_OBJ, "(CQ%d): Old refcount: %d\n",
		OBJ_ID(cq), atomic_read(&cq->hdr.ref.refcount));
	kref_put(&cq->hdr.ref, siw_free_cq);
}

void siw_qp_put(struct siw_qp *qp)
{
	dprint(DBG_OBJ|DBG_QP, "(QP%d): Old refcount: %d\n",
		QP_ID(qp), atomic_read(&qp->hdr.ref.refcount));
	kref_put(&qp->hdr.ref, siw_free_qp);
}

void siw_pd_put(struct siw_pd *pd)
{
	dprint(DBG_OBJ, "(PD%d): Old refcount: %d\n",
		OBJ_ID(pd), atomic_read(&pd->hdr.ref.refcount));
	kref_put(&pd->hdr.ref, siw_free_pd);
}

void siw_mem_put(struct siw_mem *m)
{
	dprint(DBG_MM|DBG_OBJ, "(MEM%d): Old refcount: %d\n",
		OBJ_ID(m), atomic_read(&m->hdr.ref.refcount));
	kref_put(&m->hdr.ref, siw_free_mem);
}


/***** routines for WQE handling ***/

/*
 * siw_wqe_get()
 *
 * Get new WQE. For READ RESPONSE, take it from the free list which
 * has a maximum size of maximum inbound READs. All other WQE are
 * malloc'ed which creates some overhead. Consider change to
 *
 * 1. malloc WR only if it cannot be synchonously completed, or
 * 2. operate own cache of reuseable WQE's.
 *
 * Current code trusts on malloc efficiency.
 */
inline struct siw_wqe *siw_wqe_get(struct siw_qp *qp, enum siw_wr_opcode op)
{
	struct siw_wqe *wqe;

	if (op == SIW_WR_RDMA_READ_RESP) {
		spin_lock_bh(&qp->freelist_lock);
		if (!(list_empty(&qp->wqe_freelist))) {
			wqe = list_entry(qp->wqe_freelist.next,
					 struct siw_wqe, list);
			list_del(&wqe->list);
			spin_unlock_bh(&qp->freelist_lock);
			wqe->processed = 0;
			dprint(DBG_OBJ|DBG_WR,
				"(QP%d): WQE from FreeList p: %p\n",
				QP_ID(qp), wqe);
		} else {
			spin_unlock_bh(&qp->freelist_lock);
			wqe = NULL;
			dprint(DBG_ON|DBG_OBJ|DBG_WR,
				"(QP%d): FreeList empty!\n", QP_ID(qp));
		}
	} else {
		wqe = kzalloc(sizeof(struct siw_wqe), GFP_KERNEL);
		dprint(DBG_OBJ|DBG_WR, "(QP%d): New WQE p: %p\n",
			QP_ID(qp), wqe);
	}
	if (wqe) {
		INIT_LIST_HEAD(&wqe->list);
		siw_qp_get(qp);
		wqe->qp = qp;
	}
	return wqe;
}

inline struct siw_wqe *siw_srq_wqe_get(struct siw_srq *srq)
{
	struct siw_wqe *wqe = kzalloc(sizeof(struct siw_wqe), GFP_KERNEL);

	dprint(DBG_OBJ|DBG_WR, "(SRQ%p): New WQE p: %p\n", srq, wqe);
	if (wqe)
		/* implicite: wqe->qp = NULL; */
		INIT_LIST_HEAD(&wqe->list);

	return wqe;
}

/*
 * siw_srq_fetch_wqe()
 *
 * fetch one RQ wqe from the SRQ and inform user
 * if SRQ lower watermark reached
 */
inline struct siw_wqe *siw_srq_fetch_wqe(struct siw_qp *qp)
{
	struct siw_wqe *wqe;
	struct siw_srq *srq = qp->srq;
	int qlen;

	spin_lock_bh(&srq->lock);
	if (!list_empty(&srq->rq)) {
		wqe = list_first_wqe(&srq->rq);
		list_del_init(&wqe->list);
		qlen = srq->max_wr - atomic_inc_return(&srq->space);
		spin_unlock_bh(&srq->lock);
		wqe->qp = qp;
		if (srq->armed && qlen < srq->limit) {
			srq->armed = 0;
			siw_async_srq_ev(srq, IB_EVENT_SRQ_LIMIT_REACHED);
		}
		return wqe;
	}
	spin_unlock_bh(&srq->lock);
	return NULL;
}

inline void siw_free_inline_sgl(struct siw_sge *sge, int num_sge)
{
	while (num_sge--) {
		kfree(sge->mem.buf); /* kfree handles NULL pointers */
		sge++;
	}
}

inline void siw_unref_mem_sgl(struct siw_sge *sge, int num_sge)
{
	while (num_sge--) {
		if (sge->mem.obj != NULL)
			siw_mem_put(sge->mem.obj);
		sge++;
	}
}


void siw_wqe_put(struct siw_wqe *wqe)
{
	struct siw_qp *qp = wqe->qp;

	dprint(DBG_OBJ|DBG_WR, " WQE: 0x%llu:, type: %d, p: %p\n",
		(unsigned long long)wr_id(wqe), wr_type(wqe), wqe);

	switch (wr_type(wqe)) {

	case SIW_WR_SEND:
	case SIW_WR_RDMA_WRITE:
		if (likely(!SIW_INLINED_DATA(wqe)))
			siw_unref_mem_sgl(wqe->wr.sgl.sge,
					  wqe->wr.sgl.num_sge);
		else
			siw_free_inline_sgl(wqe->wr.sgl.sge,
					    wqe->wr.sgl.num_sge);
		kfree(wqe);
		break;

	case SIW_WR_RECEIVE:
	case SIW_WR_RDMA_READ_REQ:
		siw_unref_mem_sgl(wqe->wr.sgl.sge, wqe->wr.sgl.num_sge);
		kfree(wqe);
		break;

	case SIW_WR_RDMA_READ_RESP:
		siw_unref_mem_sgl(wqe->wr.sgl.sge, 1);
		wqe->wr.sgl.sge[0].mem.obj = NULL;
		/*
		 * freelist can be accessed by tx processing (rresp done)
		 * and rx softirq (get new wqe for rresponse scheduling)
		 */
		INIT_LIST_HEAD(&wqe->list);
		spin_lock_bh(&wqe->qp->freelist_lock);
		list_add_tail(&wqe->list, &wqe->qp->wqe_freelist);
		spin_unlock_bh(&wqe->qp->freelist_lock);
		break;

	default:
		WARN_ON(1);
	}
	siw_qp_put(qp);
}

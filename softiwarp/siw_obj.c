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

#include <linux/spinlock.h>
#include <linux/kref.h>

#include "siw.h"
#include "siw_obj.h"
#include "siw_cm.h"


void siw_objhdr_init(struct siw_objhdr *hdr)
{
	kref_init(&hdr->ref);
}

void siw_idr_init(struct siw_dev *sdev)
{
	spin_lock_init(&sdev->idr_lock);

	idr_init(&sdev->qp_idr);
	idr_init(&sdev->cq_idr);
	idr_init(&sdev->pd_idr);
	idr_init(&sdev->mem_idr);
}

void siw_idr_release(struct siw_dev *sdev)
{
	idr_destroy(&sdev->qp_idr);
	idr_destroy(&sdev->cq_idr);
	idr_destroy(&sdev->pd_idr);
	idr_destroy(&sdev->mem_idr);
}

static inline int siw_add_obj(spinlock_t *lock, struct idr *idr,
			      struct siw_objhdr *obj)
{
	u32		pre_id, id;
	unsigned long	flags;
	int		rv;

	get_random_bytes(&pre_id, sizeof pre_id);
	pre_id &= 0xffff;
again:
	do {
		if (!(idr_pre_get(idr, GFP_KERNEL)))
			return -ENOMEM;

		spin_lock_irqsave(lock, flags);
		rv = idr_get_new_above(idr, obj, pre_id, &id);
		spin_unlock_irqrestore(lock, flags);

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

struct siw_cq *siw_cq_id2obj(struct siw_dev *sdev, int id)
{
	struct siw_objhdr *obj = siw_get_obj(&sdev->cq_idr, id);
	if (obj)
		return container_of(obj, struct siw_cq, hdr);

	return NULL;
}

struct siw_qp *siw_qp_id2obj(struct siw_dev *sdev, int id)
{
	struct siw_objhdr *obj = siw_get_obj(&sdev->qp_idr, id);
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
struct siw_mem *siw_mem_id2obj(struct siw_dev *sdev, int id)
{
	struct siw_objhdr *obj;
	unsigned long flags;

	spin_lock_irqsave(&sdev->idr_lock, flags);
	obj = siw_get_obj(&sdev->mem_idr, id);
	spin_unlock_irqrestore(&sdev->idr_lock, flags);

	if (obj) {
		dprint(DBG_MM|DBG_OBJ, "(MEM%d): New refcount: %d\n",
		       obj->id, obj->ref.refcount.counter);

		return container_of(obj, struct siw_mem, hdr);
	}
	dprint(DBG_MM|DBG_OBJ|DBG_ON, "(MEM%d): not found!\n", id);

	return NULL;
}

int siw_qp_add(struct siw_dev *sdev, struct siw_qp *qp)
{
	int rv = siw_add_obj(&sdev->idr_lock, &sdev->qp_idr, &qp->hdr);
	if (!rv) {
		dprint(DBG_OBJ, "(QP%d): New Object\n", QP_ID(qp));
		qp->hdr.sdev = sdev;
	}
	return rv;
}

int siw_cq_add(struct siw_dev *sdev, struct siw_cq *cq)
{
	int rv = siw_add_obj(&sdev->idr_lock, &sdev->cq_idr, &cq->hdr);
	if (!rv) {
		dprint(DBG_OBJ, "(CQ%d): New Object\n", cq->hdr.id);
		cq->hdr.sdev = sdev;
	}
	return rv;
}

int siw_pd_add(struct siw_dev *sdev, struct siw_pd *pd)
{
	int rv = siw_add_obj(&sdev->idr_lock, &sdev->pd_idr, &pd->hdr);
	if (!rv) {
		dprint(DBG_OBJ, "(PD%d): New Object\n", pd->hdr.id);
		pd->hdr.sdev = sdev;
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
int siw_mem_add(struct siw_dev *sdev, struct siw_mem *m)
{
	u32		id, pre_id;
	unsigned long	flags;
	int		rv;

	do {
		get_random_bytes(&pre_id, sizeof pre_id);
		pre_id &= 0xffff;
	} while (pre_id == 0);
again:
	do {
		if (!(idr_pre_get(&sdev->mem_idr, GFP_KERNEL)))
			return -ENOMEM;

		spin_lock_irqsave(&sdev->idr_lock, flags);
		rv = idr_get_new_above(&sdev->mem_idr, m, pre_id, &id);
		spin_unlock_irqrestore(&sdev->idr_lock, flags);

	} while (rv == -EAGAIN);

	if (rv == -ENOSPC || (rv == 0 && id > SIW_STAG_MAX)) {
		if (rv == 0) {
			spin_lock_irqsave(&sdev->idr_lock, flags);
			idr_remove(&sdev->mem_idr, id);
			spin_unlock_irqrestore(&sdev->idr_lock, flags);
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
	m->hdr.sdev = sdev;
	dprint(DBG_OBJ|DBG_MM, "(IDR%d): New Object\n", id);

	return 0;
}

void siw_remove_obj(spinlock_t *lock, struct idr *idr,
		      struct siw_objhdr *hdr)
{
	unsigned long	flags;

	dprint(DBG_OBJ, "(OBJ%d): IDR Remove Object\n", hdr->id);

	spin_lock_irqsave(lock, flags);
	idr_remove(idr, hdr->id);
	spin_unlock_irqrestore(lock, flags);
}


/********** routines to put objs back and free if no ref left *****/

static void siw_free_cq(struct kref *ref)
{
	struct siw_cq *cq =
		(container_of(container_of(ref, struct siw_objhdr, ref),
			      struct siw_cq, hdr));

	dprint(DBG_OBJ, "(CQ%d): Free Object\n", cq->hdr.id);

	atomic_dec(&cq->hdr.sdev->num_cq);
	kfree(cq);
}

static void siw_free_qp(struct kref *ref)
{
	struct siw_qp	*qp =
		container_of(container_of(ref, struct siw_objhdr, ref),
			     struct siw_qp, hdr);
	struct siw_dev	*sdev = qp->hdr.sdev;
	unsigned long flags;

	dprint(DBG_OBJ|DBG_CM, "(QP%d): Free Object\n", QP_ID(qp));

	if (qp->cep)
		siw_cep_put(qp->cep);

	siw_drain_wq(&qp->freeq);

	siw_remove_obj(&sdev->idr_lock, &sdev->qp_idr, &qp->hdr);

	spin_lock_irqsave(&sdev->idr_lock, flags);
	list_del(&qp->devq);
	spin_unlock_irqrestore(&sdev->idr_lock, flags);

	atomic_dec(&sdev->num_qp);
	kfree(qp);
}

static void siw_free_pd(struct kref *ref)
{
	struct siw_pd	*pd =
		container_of(container_of(ref, struct siw_objhdr, ref),
			     struct siw_pd, hdr);

	dprint(DBG_OBJ, "(PD%d): Free Object\n", pd->hdr.id);

	atomic_dec(&pd->hdr.sdev->num_pd);
	kfree(pd);
}

static void siw_free_mem(struct kref *ref)
{
	struct siw_mem *m;

	m = container_of(container_of(ref, struct siw_objhdr, ref),
			 struct siw_mem, hdr);

	dprint(DBG_MM|DBG_OBJ, "(MEM%d): Free Object\n", OBJ_ID(m));

	atomic_dec(&m->hdr.sdev->num_mem);

	if (SIW_MEM_IS_MW(m)) {
		struct siw_mw *mw = container_of(m, struct siw_mw, mem);
		kfree(mw);
	} else {
		struct siw_mr *mr = container_of(m, struct siw_mr, mem);
		dprint(DBG_MM|DBG_OBJ, "(MEM%d): Release UMem\n", OBJ_ID(m));
		if (mr->umem)
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
	dprint(DBG_OBJ, "(QP%d): Old refcount: %d\n",
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

inline struct siw_wqe *siw_freeq_wqe_get(struct siw_qp *qp)
{
	struct siw_wqe *wqe = NULL;
	unsigned long flags;

	spin_lock_irqsave(&qp->freeq_lock, flags);
	if (!list_empty(&qp->freeq)) {
		wqe = list_first_wqe(&qp->freeq);
		list_del(&wqe->list);
		spin_unlock_irqrestore(&qp->freeq_lock, flags);
		dprint(DBG_OBJ|DBG_WR,
			"(QP%d): WQE from FreeList p: %p\n",
			QP_ID(qp), wqe);
	} else {
		spin_unlock_irqrestore(&qp->freeq_lock, flags);
		dprint(DBG_ON|DBG_OBJ|DBG_WR,
			"(QP%d): FreeList empty!\n", QP_ID(qp));
	}
	return wqe;
}

static inline void siw_unref_mem_sgl(struct siw_sge *sge, int num_sge)
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

	dprint(DBG_OBJ|DBG_WR, " WQE: %llu:, type: %d, p: %p\n",
		(unsigned long long)wr_id(wqe), wr_type(wqe), wqe);

	switch (wr_type(wqe)) {

	case SIW_WR_SEND:
	case SIW_WR_RDMA_WRITE:
	case SIW_WR_RDMA_WRITE_WITH_IMM:
	case SIW_WR_SEND_WITH_IMM:
	case SIW_WR_RDMA_READ_REQ:
		if (!SIW_INLINED_DATA(wqe))
			siw_unref_mem_sgl(wqe->wr.sgl.sge,
					  wqe->wr.sgl.num_sge);

		if (qp->attrs.flags & SIW_KERNEL_VERBS)
			siw_add_wqe(wqe, &qp->freeq, &qp->freeq_lock);
		else {
			kfree(wqe);
			SIW_DEC_STAT_WQE;
		}
		atomic_inc(&qp->sq_space);
		break;

	case SIW_WR_RECEIVE:
		siw_unref_mem_sgl(wqe->wr.sgl.sge, wqe->wr.sgl.num_sge);
		if (qp->srq) {
			struct siw_srq *srq = qp->srq;
			if (srq->kernel_verbs)
				siw_add_wqe(wqe, &srq->freeq,
					    &srq->freeq_lock);
			else {
				kfree(wqe);
				SIW_DEC_STAT_WQE;
			}
			atomic_inc(&srq->space);
		} else {
			if (qp->attrs.flags & SIW_KERNEL_VERBS)
				siw_add_wqe(wqe, &qp->freeq, &qp->freeq_lock);
			else {
				kfree(wqe);
				SIW_DEC_STAT_WQE;
			}
			atomic_inc(&qp->rq_space);
		}
		break;

	case SIW_WR_RDMA_READ_RESP:
		siw_unref_mem_sgl(wqe->wr.sgl.sge, 1);
		wqe->wr.sgl.sge[0].mem.obj = NULL;
		siw_add_wqe(wqe, &qp->freeq, &qp->freeq_lock);
		atomic_inc(&qp->irq_space);
		break;

	default:
		WARN_ON(1);
	}
	siw_qp_put(qp);
}

/*
 * Software iWARP device driver for Linux
 *
 * Authors: Bernard Metzler <bmt@zurich.ibm.com>
 *
 * Copyright (c) 2008-2015, IBM Corporation
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

#ifndef _SIW_OBJ_H
#define _SIW_OBJ_H

#include <linux/idr.h>
#include <linux/rwsem.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/semaphore.h>

#include <rdma/ib_verbs.h>

#include "siw_debug.h"


static inline struct siw_dev *siw_dev_ofa2siw(struct ib_device *ofa_dev)
{
	return container_of(ofa_dev, struct siw_dev, ofa_dev);
}

static inline void siw_cq_get(struct siw_cq *cq)
{
	kref_get(&cq->hdr.ref);
	dprint(DBG_OBJ, "(CQ%d): New refcount: %d\n",
		OBJ_ID(cq), atomic_read(&cq->hdr.ref.refcount));
}
static inline void siw_qp_get(struct siw_qp *qp)
{
	kref_get(&qp->hdr.ref);
	dprint(DBG_OBJ, "(QP%d): New refcount: %d\n",
		OBJ_ID(qp), atomic_read(&qp->hdr.ref.refcount));
}
static inline void siw_pd_get(struct siw_pd *pd)
{
	kref_get(&pd->hdr.ref);
	dprint(DBG_OBJ, "(PD%d): New refcount: %d\n",
		OBJ_ID(pd), atomic_read(&pd->hdr.ref.refcount));
}
static inline void siw_mem_get(struct siw_mem *mem)
{
	kref_get(&mem->hdr.ref);
	dprint(DBG_OBJ|DBG_MM, "(MEM%d): New refcount: %d\n",
		OBJ_ID(mem), atomic_read(&mem->hdr.ref.refcount));
}

extern void siw_remove_obj(spinlock_t *lock, struct idr *idr,
				struct siw_objhdr *hdr);

extern void siw_objhdr_init(struct siw_objhdr *);
extern void siw_idr_init(struct siw_dev *);
extern void siw_idr_release(struct siw_dev *);

extern struct siw_cq *siw_cq_id2obj(struct siw_dev *, int);
extern struct siw_qp *siw_qp_id2obj(struct siw_dev *, int);
extern struct siw_mem *siw_mem_id2obj(struct siw_dev *, int);

extern int siw_qp_add(struct siw_dev *, struct siw_qp *);
extern int siw_cq_add(struct siw_dev *, struct siw_cq *);
extern int siw_pd_add(struct siw_dev *, struct siw_pd *);
extern int siw_mem_add(struct siw_dev *, struct siw_mem *m);

extern struct siw_wqe *siw_freeq_wqe_get(struct siw_qp *);

extern void siw_cq_put(struct siw_cq *);
extern void siw_qp_put(struct siw_qp *);
extern void siw_pd_put(struct siw_pd *);
extern void siw_mem_put(struct siw_mem *);
extern void siw_wqe_put_mem(struct siw_wqe *, enum siw_opcode);

#endif

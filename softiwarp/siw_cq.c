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
#include <linux/list.h>

#include <rdma/iw_cm.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_user_verbs.h>

#include "siw.h"
#include "siw_obj.h"
#include "siw_cm.h"

static int siw_wc_op_siw2ofa[SIW_WR_NUM] = {
	[SIW_WR_RDMA_WRITE]		= IB_WC_RDMA_WRITE,
	[SIW_WR_RDMA_WRITE_WITH_IMM]	= IB_WC_RDMA_WRITE,
	[SIW_WR_SEND]			= IB_WC_SEND,
	[SIW_WR_SEND_WITH_IMM]		= IB_WC_SEND,
	[SIW_WR_RDMA_READ_REQ]		= IB_WC_RDMA_READ,
	[SIW_WR_ATOMIC_CMP_AND_SWP]	= IB_WC_COMP_SWAP,
	[SIW_WR_ATOMIC_FETCH_AND_ADD]	= IB_WC_FETCH_ADD,
	[SIW_WR_FASTREG]		= IB_WC_FAST_REG_MR,
#if (OFA_VERSION >= 140)
	[SIW_WR_INVAL_STAG]		= IB_WC_LOCAL_INV,
	[SIW_WR_RECEIVE]		= IB_WC_RECV,
#endif
	[SIW_WR_RDMA_READ_RESP]		= 0 /* not used */
};

/*
 * translate wc into ofa syntax
 */
static void siw_wc_siw2ofa(struct siw_wqe *siw_wc, struct ib_wc *ofa_wc)
{
	memset(ofa_wc, 0, sizeof *ofa_wc);

	ofa_wc->wr_id = wr_id(siw_wc);
	ofa_wc->status = siw_wc->wc_status;
	ofa_wc->byte_len = siw_wc->processed;
	ofa_wc->qp = &siw_wc->qp->ofa_qp;

	ofa_wc->opcode = siw_wc_op_siw2ofa[wr_type(siw_wc)];
	/*
	 * ofa_wc->imm_data = 0;
	 * ofa_wc->vendor_err = 0;
	 * ofa_wc->src_qp = 0;
	 * ofa_wc->wc_flags = 0; ADD immediate data support
	 * ofa_wc->pkey_index = 0;
	 * ofa_wc->slid = 0;
	 * ofa_wc->sl = 0;
	 * ofa_wc->dlid_path_bits = 0;
	 * ofa_wc->port_num = 0;
	 */
}

/*
 * Reap one CQE from the CQ.
 *
 * Caller must hold qp read lock
 *
 * TODO: Provide routine which can read more than one CQE
 */
int siw_reap_cqe(struct siw_cq *cq, struct ib_wc *ofa_wc)
{
	struct siw_wqe	*cqe = NULL;
	unsigned long flags;

	lock_cq_rxsave(cq, flags);

	if (!list_empty(&cq->queue)) {
		cqe = list_first_wqe(&cq->queue);
		list_del(&cqe->list);
		atomic_dec(&cq->qlen);
	}
	unlock_cq_rxsave(cq, flags);

	if (cqe) {
		siw_wc_siw2ofa(cqe, ofa_wc);

		dprint(DBG_WR, " QP%d, CQ%d: Reap WQE type: %d, p: %p\n",
			  QP_ID(cqe->qp), OBJ_ID(cq), wr_type(cqe), cqe);

		siw_wqe_put(cqe);
		return 1;
	} else
		return 0;
}

/*
 * siw_cq_flush()
 *
 * Flush all CQ elements. No CQ lock is taken.
 */
void siw_cq_flush(struct siw_cq *cq)
{
	struct list_head	*pos, *n;
	struct siw_wqe		*cqe;

	dprint(DBG_CM|DBG_OBJ, "(CQ%d:) Enter\n", OBJ_ID(cq));

	if (list_empty(&cq->queue))
		return;

	list_for_each_safe(pos, n, &cq->queue) {
		cqe = list_entry_wqe(pos);
		list_del(&cqe->list);

		dprint(DBG_OBJ|DBG_WR, " WQE: 0x%llu:, type: %d, p: %p\n",
			(unsigned long long)wr_id(cqe),
			wr_type(cqe), cqe);

		siw_wqe_put(cqe);
	}
	atomic_set(&cq->qlen, 0);
}



/*
 * siw_rq_complete()
 *
 * Appends RQ/SRQ WQE to CQ, if assigned.
 * Must be called with qp state read locked
 */
void siw_rq_complete(struct siw_wqe *wqe, struct siw_qp *qp)
{
	struct siw_cq	*cq = qp->rcq;
	unsigned long flags;

	dprint(DBG_OBJ|DBG_WR, " QP%d WQE: 0x%llu:, type: %d, p: %p\n",
		QP_ID(qp),
		(unsigned long long)wr_id(wqe), wr_type(wqe), wqe);

	if (cq) {
		lock_cq_rxsave(cq, flags);

		list_add_tail(&wqe->list, &cq->queue);
		atomic_inc(&cq->qlen); /* FIXME: test overflow */

		unlock_cq_rxsave(cq, flags);

		if (cq->ofa_cq.comp_handler != NULL &&
			((cq->notify & SIW_CQ_NOTIFY_ALL) ||
			 (cq->notify == SIW_CQ_NOTIFY_SOLICITED &&
			  wr_flags(wqe) & IB_SEND_SOLICITED))) {
				cq->notify = SIW_CQ_NOTIFY_NOT;
				(*cq->ofa_cq.comp_handler)
					(&cq->ofa_cq, cq->ofa_cq.cq_context);
		}
	} else
		siw_wqe_put(wqe);
}

/*
 * siw_sq_complete()
 * Appends list of former SQ WQE's to CQ, if assigned.
 * Must be called with qp state read locked
 */
void siw_sq_complete(struct list_head *c_list, struct siw_qp *qp, int num,
		     enum ib_send_flags send_flags)
{
	struct siw_cq		*cq = qp->scq;
	unsigned long flags;

	if (cq) {
		lock_cq_rxsave(cq, flags);

		list_splice_tail(c_list, &cq->queue);
		atomic_add(num, &cq->qlen); /* FIXME: test overflow */


		dprint(DBG_WR, " CQ%d: add %d from QP%d, CQ len %d\n",
			OBJ_ID(cq), num, QP_ID(qp), atomic_read(&cq->qlen));

		if (cq->ofa_cq.comp_handler != NULL &&
			((cq->notify & SIW_CQ_NOTIFY_ALL) ||
			 (cq->notify == SIW_CQ_NOTIFY_SOLICITED &&
			  send_flags & IB_SEND_SOLICITED))) {
				cq->notify = SIW_CQ_NOTIFY_NOT;
				(*cq->ofa_cq.comp_handler)
					(&cq->ofa_cq, cq->ofa_cq.cq_context);
		}
		unlock_cq_rxsave(cq, flags);
	} else {
		struct list_head *pos;

		list_for_each(pos, c_list)
			siw_wqe_put(list_entry_wqe(pos));
	}
}

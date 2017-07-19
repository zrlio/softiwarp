/*
 * Software iWARP device driver for Linux
 *
 * Authors: Bernard Metzler <bmt@zurich.ibm.com>
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
#include <linux/list.h>

#include <rdma/iw_cm.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_user_verbs.h>

#include "siw.h"
#include "siw_obj.h"
#include "siw_cm.h"

static int siw_wc_op_siw2ofa[SIW_NUM_OPCODES] = {
	[SIW_OP_WRITE]		= IB_WC_RDMA_WRITE,
	[SIW_OP_SEND]		= IB_WC_SEND,
	[SIW_OP_SEND_WITH_IMM]	= IB_WC_SEND,
	[SIW_OP_READ]		= IB_WC_RDMA_READ,
	[SIW_OP_READ_LOCAL_INV]	= IB_WC_RDMA_READ,
	[SIW_OP_COMP_AND_SWAP]	= IB_WC_COMP_SWAP,
	[SIW_OP_FETCH_AND_ADD]	= IB_WC_FETCH_ADD,
	[SIW_OP_INVAL_STAG]	= IB_WC_LOCAL_INV,
	[SIW_OP_REG_MR]		= IB_WC_REG_MR,
	[SIW_OP_RECEIVE]	= IB_WC_RECV,
	[SIW_OP_READ_RESPONSE]	= -1 /* not used */
};


static struct {
	enum siw_opcode   siw;
	enum ib_wc_opcode ofa;
} map_cqe_status[SIW_NUM_WC_STATUS] = {
	{SIW_WC_SUCCESS,		IB_WC_SUCCESS},
	{SIW_WC_LOC_LEN_ERR,		IB_WC_LOC_LEN_ERR},
	{SIW_WC_LOC_PROT_ERR,		IB_WC_LOC_PROT_ERR},
	{SIW_WC_LOC_QP_OP_ERR,		IB_WC_LOC_QP_OP_ERR},
	{SIW_WC_WR_FLUSH_ERR,		IB_WC_WR_FLUSH_ERR},
	{SIW_WC_BAD_RESP_ERR,		IB_WC_BAD_RESP_ERR},
	{SIW_WC_LOC_ACCESS_ERR,		IB_WC_LOC_ACCESS_ERR},
	{SIW_WC_REM_ACCESS_ERR,		IB_WC_REM_ACCESS_ERR},
	{SIW_WC_REM_INV_REQ_ERR,	IB_WC_REM_INV_REQ_ERR},
	{SIW_WC_GENERAL_ERR,		IB_WC_GENERAL_ERR}
};

/*
 * translate wc into ofa syntax
 */
static void siw_wc_siw2ofa(struct siw_cqe *cqe, struct ib_wc *ofa_wc)
{
	memset(ofa_wc, 0, sizeof(*ofa_wc));

	ofa_wc->wr_id = cqe->id;
	ofa_wc->status = map_cqe_status[cqe->status].ofa;
	ofa_wc->byte_len = cqe->bytes;
	ofa_wc->qp = &((struct siw_qp *)cqe->qp)->ofa_qp;

	ofa_wc->opcode = siw_wc_op_siw2ofa[cqe->opcode];
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
	struct siw_cqe *cqe;
	unsigned long flags;

	spin_lock_irqsave(&cq->lock, flags);

	cqe = &cq->queue[cq->cq_get % cq->num_cqe];
	if (cqe->flags & SIW_WQE_VALID) {
		siw_wc_siw2ofa(cqe, ofa_wc);

		dprint(DBG_WR, " QP%d, CQ%d: Reap WQE type: %d at idx %d\n",
			QP_ID((struct siw_qp *)cqe->qp), OBJ_ID(cq),
			cqe->opcode, cq->cq_get % cq->num_cqe);

		if (cq->kernel_verbs)
			siw_qp_put(cqe->qp);

		cqe->flags = 0;
		cq->cq_get++;

		/* Make cqe state visible to all */
		smp_wmb();

		spin_unlock_irqrestore(&cq->lock, flags);
		return 1;
	}
	spin_unlock_irqrestore(&cq->lock, flags);
	return 0;
}

/*
 * siw_cq_flush()
 *
 * Flush all CQ elements. No CQ lock is taken.
 */
void siw_cq_flush(struct siw_cq *cq)
{
	struct ib_wc wc;

	int got, total = 0;

	dprint(DBG_CM|DBG_OBJ, "(CQ%d:) Enter\n", OBJ_ID(cq));

	do {
		got = siw_reap_cqe(cq, &wc);
		total += got;
	} while (got > 0);
}

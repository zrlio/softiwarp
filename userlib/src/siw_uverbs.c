/*
 * Software iWARP library for Linux
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

#if HAVE_CONFIG_H
#  include <config.h>
#endif				/* HAVE_CONFIG_H */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>

#include <siw_user.h>
#include "siw.h"
#include "siw_abi.h"


#define _load_shared(a)		(*(volatile typeof(a) *)&(a))
#define _store_shared(a, b)	do { \
					_load_shared(a) = (b); wmb(); \
				} while (0)

extern const int siw_debug;
extern int rdma_db_nr;

int siw_notify_cq(struct ibv_cq *ibcq, int solicited)
{
	struct siw_cq	*cq = cq_ofa2siw(ibcq);
	int		rv = 0;

	if (cq->ctrl) {
		if (solicited)
			_store_shared(cq->ctrl->notify, SIW_NOTIFY_SOLICITED);
		else
			_store_shared(cq->ctrl->notify, SIW_NOTIFY_SOLICITED | 
				SIW_NOTIFY_NEXT_COMPLETION);
		
	} else {
		pthread_spin_lock(&cq->lock);
		rv = ibv_cmd_req_notify_cq(ibcq, solicited);
		pthread_spin_unlock(&cq->lock);
	}
	return rv;
}


int siw_post_send_ofed(struct ibv_qp *ofa_qp, struct ibv_send_wr *wr,
		       struct ibv_send_wr **bad_wr)
{
	struct siw_qp	*qp = qp_ofa2siw(ofa_qp);
	int		rv;

	pthread_spin_lock(&qp->sq_lock);
	rv = ibv_cmd_post_send(ofa_qp, wr, bad_wr);
	pthread_spin_unlock(&qp->sq_lock);

	return rv;
}

int siw_post_recv_ofed(struct ibv_qp *ofa_qp, struct ibv_recv_wr *wr,
		      struct ibv_recv_wr **bad_wr)
{
	struct siw_qp	*qp = qp_ofa2siw(ofa_qp);
	int		rv;

	pthread_spin_lock(&qp->rq_lock);
	rv = ibv_cmd_post_recv(ofa_qp, wr, bad_wr);
	pthread_spin_unlock(&qp->rq_lock);

	return rv;
}

int siw_post_srq_recv_ofed(struct ibv_srq *ofa_srq, struct ibv_recv_wr *wr,
			   struct ibv_recv_wr **bad_wr)
{
	struct siw_srq	*srq = srq_ofa2siw(ofa_srq);
	int rv;

	pthread_spin_lock(&srq->lock);
	rv = ibv_cmd_post_srq_recv(ofa_srq, wr, bad_wr);
	pthread_spin_unlock(&srq->lock);

	return rv;
}

int siw_poll_cq_ofed(struct ibv_cq *ibcq, int num_entries, struct ibv_wc *wc)
{
	struct siw_cq	*cq = cq_ofa2siw(ibcq);
	int		rv;

	pthread_spin_lock(&cq->lock);
	rv = ibv_cmd_poll_cq(ibcq, num_entries, wc);
	pthread_spin_unlock(&cq->lock);

	return rv;
}

static enum siw_opcode map_send_opcode(enum ibv_wr_opcode ibv_op)
{
	switch (ibv_op) {

	case IBV_WR_SEND:	return SIW_OP_SEND;
	case IBV_WR_RDMA_WRITE:	return SIW_OP_WRITE;
	case IBV_WR_RDMA_READ:	return SIW_OP_READ;
	default:
		printf("op %d not supported\n", ibv_op);
	}
	return SIW_NUM_OPCODES + 1;
}

static inline uint16_t map_send_flags(int ibv_flags)
{
	uint16_t flags = SIW_WQE_VALID;

	if (ibv_flags & IBV_SEND_SIGNALED)	flags |= SIW_WQE_SIGNALLED;
	if (ibv_flags & IBV_SEND_SOLICITED)	flags |= SIW_WQE_SOLICITED;
	if (ibv_flags & IBV_SEND_INLINE)	flags |= SIW_WQE_INLINE;
	if (ibv_flags & IBV_SEND_FENCE)		flags |= SIW_WQE_READ_FENCE;

	return flags;
}

static inline int push_send_wqe(struct ibv_send_wr *ofa_wr,
				struct siw_sqe *siw_sqe, int sig_all)
{
	uint32_t flags = map_send_flags(ofa_wr->send_flags);

	siw_sqe->id		= ofa_wr->wr_id;
	siw_sqe->num_sge	= ofa_wr->num_sge;
	siw_sqe->raddr		= ofa_wr->wr.rdma.remote_addr;
	siw_sqe->rkey		= ofa_wr->wr.rdma.rkey;

	siw_sqe->opcode = map_send_opcode(ofa_wr->opcode);

	if (sig_all)
		flags |= SIW_WQE_SIGNALLED;

	if (flags & SIW_WQE_INLINE) {
		char *db = (char *)&siw_sqe->sge[1];
		int bytes = 0, i = 0;

		if (ofa_wr->num_sge > SIW_MAX_SGE) {
			if (siw_debug)
				printf("too many SGEs: %d\n", ofa_wr->num_sge);
				return -EINVAL;
		}
		while (i < ofa_wr->num_sge) {

			bytes += ofa_wr->sg_list[i].length;
			if (bytes > (int)SIW_MAX_INLINE) {
				if (siw_debug)
					printf("inline data to long: %d:%d\n",
						bytes, (int)SIW_MAX_INLINE);
				return EINVAL;
			}
			memcpy(db, (void *)ofa_wr->sg_list[i].addr,
				ofa_wr->sg_list[i].length);
			db += ofa_wr->sg_list[i++].length;
		}
		siw_sqe->sge[0].length = bytes;

	} else if (ofa_wr->num_sge == 1) {
		siw_sqe->sge[0].laddr	= ofa_wr->sg_list[0].addr;
		siw_sqe->sge[0].length	= ofa_wr->sg_list[0].length;
		siw_sqe->sge[0].lkey	= ofa_wr->sg_list[0].lkey;
	} else if (ofa_wr->num_sge && ofa_wr->num_sge <= SIW_MAX_SGE)
		/* this assumes same layout of siw and ofa SGE */
		memcpy(siw_sqe->sge, ofa_wr->sg_list,
		       siw_sqe->num_sge * sizeof(struct ibv_sge));
	else
		return 1;

	/* TODO: handle inline data */

	if (siw_debug)
		printf("push SQ len %u, id %lx, op %d, num_sge %d, addr %lx\n",
			siw_sqe->sge[0].length, siw_sqe->id, siw_sqe->opcode,
			siw_sqe->num_sge, siw_sqe->sge[0].laddr);

	_store_shared(siw_sqe->flags, flags);

	return 0;
}

static int siw_db_ofa(struct ibv_qp *ofa_qp)
{
	struct ibv_post_send req;
	struct ibv_post_send_resp resp;
	int rv;

	req.command	= IB_USER_VERBS_CMD_POST_SEND;
	req.in_words	= (sizeof req) / 4;
	req.out_words	= (sizeof resp) / 4;
	req.response	= (uintptr_t)&resp;
	req.qp_handle	= ofa_qp->handle;
	req.wr_count	= 0;
	req.sge_count	= 0;
	req.wqe_size	= sizeof(struct ibv_send_wr); 

	rv = write(ofa_qp->context->cmd_fd, &req, sizeof req);
	if (rv == sizeof req)
		rv = 0;
	else
		perror("write: ");

	return rv;
}

int siw_post_send_mapped(struct ibv_qp *ofa_qp, struct ibv_send_wr *wr,
			 struct ibv_send_wr **bad_wr)
{
	struct siw_qp	*qp = qp_ofa2siw(ofa_qp);
	uint32_t	sq_put;
	int		rv = 0;

	pthread_spin_lock(&qp->sq_lock);

	*bad_wr = NULL;
	sq_put = qp->sq_put;

	/*
	 * push all work requests into mapped SQ and ring DB
	 * via empty OFA call
	 */
	while (wr) {
		int idx = sq_put % qp->num_sqe;
		struct siw_sqe *sqe = &qp->sendq[idx];
		uint16_t sqe_flags = _load_shared(sqe->flags);
		
		rmb();

		if (!(sqe_flags & SIW_WQE_VALID)) {
			if (push_send_wqe(wr, sqe, qp->sq_sig_all)) {
				rv = -ENOMEM;
				*bad_wr = wr;
				break;
			}
		} else {
			if (siw_debug)
				printf("QP[%d]: SQ overflow, idx %d\n",
					qp->id, idx);
			rv = -ENOMEM;
			*bad_wr = wr;
			break;
		}
		sq_put++;
		wr = wr->next;
	}
	if (sq_put != qp->sq_put) {
		if (rdma_db_nr > 0)
			rv = syscall(rdma_db_nr, SIW_DB_SQ,
				     qp->dev_id, qp->id);
		else
			rv = siw_db_ofa(ofa_qp);
		if (rv)
			*bad_wr = wr;

		qp->sq_put = sq_put;
	}
	pthread_spin_unlock(&qp->sq_lock);

	return rv;
}


static inline int push_recv_wqe(struct ibv_recv_wr *ofa_wr,
				struct siw_rqe *siw_rqe)
{
	siw_rqe->id = ofa_wr->wr_id;
	siw_rqe->num_sge = ofa_wr->num_sge;

	if (ofa_wr->num_sge == 1) {
		siw_rqe->sge[0].laddr    = ofa_wr->sg_list[0].addr;
		siw_rqe->sge[0].length  = ofa_wr->sg_list[0].length;
		siw_rqe->sge[0].lkey     = ofa_wr->sg_list[0].lkey;
	} else if (ofa_wr->num_sge && ofa_wr->num_sge <= SIW_MAX_SGE)
		/* this assumes same layout of siw and ofa SGE */
		memcpy(siw_rqe->sge, ofa_wr->sg_list,
		       sizeof(struct ibv_sge) * ofa_wr->num_sge);
	else
		return 1;

	if (siw_debug)
		printf("push RQ len %u, id %lx, num_sge %d\n",
			siw_rqe->sge[0].length, siw_rqe->id, siw_rqe->num_sge);

	_store_shared(siw_rqe->flags, SIW_WQE_VALID);

	return 0;
}

int siw_post_recv_mapped(struct ibv_qp *ofa_qp, struct ibv_recv_wr *wr,
			 struct ibv_recv_wr **bad_wr)
{
	struct siw_qp	*qp = qp_ofa2siw(ofa_qp);
	uint32_t	rq_put;
	int		rv = 0;

	pthread_spin_lock(&qp->rq_lock);

	rq_put = qp->rq_put;

	while (wr) {
		int idx = rq_put % qp->num_rqe;
		struct siw_rqe *rqe = &qp->recvq[idx];
		uint32_t rqe_flags = _load_shared(rqe->flags);

		rmb();

		if (!(rqe_flags & SIW_WQE_VALID)) {
			if (push_recv_wqe(wr, rqe)) {
				*bad_wr = wr;
				rv = -EINVAL;
				break;
			}
		} else {
			if (siw_debug)
				printf("QP[%d]: RQ overflow, idx %d\n",
					qp->id, idx);
			rv = -ENOMEM;
			*bad_wr = wr;
			break;
		}
		rq_put++;
		wr = wr->next;
	}
	qp->rq_put = rq_put;

	pthread_spin_unlock(&qp->rq_lock);

	return rv;
}

int siw_post_srq_recv_mapped(struct ibv_srq *ofa_srq, struct ibv_recv_wr *wr,
			     struct ibv_recv_wr **bad_wr)
{
	struct siw_srq	*srq = srq_ofa2siw(ofa_srq);
	uint32_t	srq_put;
	int rv = 0;

	pthread_spin_lock(&srq->lock);

	srq_put = srq->rq_put;

	while (wr) {
		int idx = srq_put % srq->num_rqe;
		struct siw_rqe *rqe = &srq->recvq[idx];
		uint32_t rqe_flags = _load_shared(rqe->flags);

		rmb();

		if (!(rqe_flags & SIW_WQE_VALID)) {
			if (push_recv_wqe(wr, rqe)) {
				*bad_wr = wr;
				rv = -EINVAL;
				break;
			}
		} else {
			if (siw_debug)
				printf("SRQ[%p]: SRQ overflow\n", srq);
			rv = -ENOMEM;
			*bad_wr = wr;
			break;
		}
		srq_put++;
		wr = wr->next;

	}
	srq->rq_put = srq_put;

	pthread_spin_unlock(&srq->lock);

	return rv;
}


static struct {
	enum siw_opcode   siw;
        enum ibv_wc_opcode ofa;
} map_cqe_opcode [SIW_NUM_OPCODES] = {
        {SIW_OP_WRITE,          IBV_WC_RDMA_WRITE},
        {SIW_OP_READ,           IBV_WC_RDMA_READ},
        {SIW_OP_SEND,           IBV_WC_SEND},
	{SIW_OP_SEND_WITH_IMM,	-1},
	/* Unsupported */
	{SIW_OP_FETCH_AND_ADD,	IBV_WC_FETCH_ADD},
	{SIW_OP_COMP_AND_SWAP,	IBV_WC_COMP_SWAP},
	{SIW_OP_INVAL_STAG,	-1},
	{SIW_OP_FASTREG,	-1},
        {SIW_OP_RECEIVE,        IBV_WC_RECV}
};

static struct {
	enum siw_opcode   siw;
        enum ibv_wc_opcode ofa;
} map_cqe_status [SIW_NUM_WC_STATUS] = {
	{SIW_WC_SUCCESS,	IBV_WC_SUCCESS},
	{SIW_WC_LOC_LEN_ERR,	IBV_WC_LOC_LEN_ERR},
	{SIW_WC_LOC_PROT_ERR,	IBV_WC_LOC_PROT_ERR},
	{SIW_WC_LOC_QP_OP_ERR,	IBV_WC_LOC_QP_OP_ERR},
	{SIW_WC_WR_FLUSH_ERR,	IBV_WC_WR_FLUSH_ERR},
	{SIW_WC_BAD_RESP_ERR,	IBV_WC_BAD_RESP_ERR},
	{SIW_WC_LOC_ACCESS_ERR,	IBV_WC_LOC_ACCESS_ERR},
	{SIW_WC_REM_ACCESS_ERR,	IBV_WC_REM_ACCESS_ERR},
	{SIW_WC_GENERAL_ERR,	IBV_WC_GENERAL_ERR}
};

static inline void copy_cqe(struct siw_cqe *cqe, struct ibv_wc *wc)
{
	if (siw_debug)
		printf("report CQE len %u, id %lx, op %d, status %d, QP %u\n",
			cqe->bytes, cqe->id, cqe->opcode, cqe->status,
			(uint32_t)cqe->qp_id);

	wc->wr_id = cqe->id;
	wc->byte_len = cqe->bytes;

	/* No immediate data supported yet */
	wc->wc_flags = 0;
	wc->imm_data = 0;

	wc->vendor_err = 0;
	wc->opcode = map_cqe_opcode[cqe->opcode].ofa;
	wc->status = map_cqe_status[cqe->status].ofa;
	wc->qp_num = (uint32_t)cqe->qp_id;

	wmb();
	_store_shared(cqe->flags, 0);
}

int siw_poll_cq_mapped(struct ibv_cq *ibcq, int num_entries, struct ibv_wc *wc)
{
	struct siw_cq	*cq = cq_ofa2siw(ibcq);
	int		new = 0;


	for (; num_entries--; wc++) {
		struct siw_cqe *cqe;

		pthread_spin_lock(&cq->lock);

		cqe = &cq->queue[cq->cq_get % cq->num_cqe];

		if (_load_shared(cqe->flags) & SIW_WQE_VALID) {
			copy_cqe(cqe, wc);
			++cq->cq_get;
			pthread_spin_unlock(&cq->lock);
		} else {
			pthread_spin_unlock(&cq->lock);
			break;
		}
		new++;
	}
	return new;
}


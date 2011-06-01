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
#endif

#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <errno.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <inttypes.h>

#include "siw.h"
#include "siw_abi.h"

int siw_query_device(struct ibv_context *ctx, struct ibv_device_attr *attr)
{
	struct ibv_query_device	cmd;
	uint64_t		raw_fw_ver;
	unsigned 		major, minor, sub_minor;
	int			rv;

	rv = ibv_cmd_query_device(ctx, attr, &raw_fw_ver, &cmd,
	  			   sizeof cmd);
	if (rv)
		return rv;

	major = (raw_fw_ver >> 32) & 0xffff;
	minor = (raw_fw_ver >> 16) & 0xffff;
	sub_minor = raw_fw_ver & 0xffff;

	snprintf(attr->fw_ver, sizeof attr->fw_ver,
		 "%d.%d.%d", major, minor, sub_minor);

	return 0;
}

int siw_query_port(struct ibv_context *ctx, uint8_t port,
		   struct ibv_port_attr *attr)
{
	struct ibv_query_port cmd;

	return ibv_cmd_query_port(ctx, port, attr, &cmd, sizeof cmd);
}


int siw_query_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
                        int attr_mask, struct ibv_qp_init_attr *init_attr)
{
	struct ibv_query_qp cmd;

	return ibv_cmd_query_qp(qp, attr, attr_mask, init_attr, &cmd, sizeof(cmd));
}


struct ibv_pd *siw_alloc_pd(struct ibv_context *ctx)
{
	struct ibv_alloc_pd	 cmd;
	struct siw_alloc_pd_resp resp;
	struct siw_pd 		 *pd;

	pd = malloc(sizeof *pd);
	if (!pd)
		return NULL;

	if (ibv_cmd_alloc_pd(ctx, &pd->ofa_pd, &cmd, sizeof cmd,
			     &resp.ofa_resp, sizeof resp)) {
		free(pd);
		return NULL;
	}
	return &pd->ofa_pd;
}

int siw_free_pd(struct ibv_pd *pd)
{
	int rv;

	rv = ibv_cmd_dealloc_pd(pd);
	if (rv)
		return rv;

	free(pd);
	return 0;
}


struct ibv_mr *siw_reg_mr(struct ibv_pd *pd, void *addr,
			  size_t len, int access)
{
	struct siw_mr			*mr;
	struct siw_cmd_reg_umr_req	req;
	struct siw_cmd_reg_umr_resp	resp;

	int		rv;

	mr = malloc(sizeof *mr);

	if (!mr)
		return NULL;

	rv = ibv_cmd_reg_mr(pd, addr, len, (uintptr_t)addr, access, &mr->ofa_mr,
			    &req.ofa_req, sizeof req, &resp.ofa_resp, sizeof resp);

	if (rv) {
		free(mr);
		return NULL;
	}
	return &mr->ofa_mr;
}

int siw_dereg_mr(struct ibv_mr *ofa_mr)
{
	struct siw_mr	*mr = mr_ofa2siw(ofa_mr);
	int		rv;

	rv = ibv_cmd_dereg_mr(ofa_mr);

	if (rv)
		return rv;

	free(mr);

	return 0;
}

struct ibv_cq *siw_create_cq(struct ibv_context *ctx, int num_cqe,
			     struct ibv_comp_channel *channel, int comp_vector)
{
	struct siw_cq			*cq;
	struct siw_cmd_create_cq	cmd;
	struct siw_cmd_create_cq_resp	resp;
	int				rv;

	cq = calloc(1, sizeof *cq);
	if (!cq)
		return NULL;

	rv = ibv_cmd_create_cq(ctx, num_cqe, channel, comp_vector,
			       &cq->ofa_cq, &cmd.ofa_cmd, sizeof cmd,
			       &resp.ofa_resp, sizeof resp);
	if (rv)
		goto fail;

	pthread_spin_init(&cq->lock, PTHREAD_PROCESS_PRIVATE);

	cq->k_id = resp.cq_id;

	return &cq->ofa_cq;

fail:	free (cq);
	return (struct ibv_cq *) NULL;
}

int siw_resize_cq(struct ibv_cq *ofa_cq, int num_cqe)
{
	return -ENOSYS;
}

int siw_destroy_cq(struct ibv_cq *ofacq)
{
	struct siw_cq	*cq = cq_ofa2siw(ofacq);
	int 		rv;

	pthread_spin_lock(&cq->lock);

	rv = ibv_cmd_destroy_cq(ofacq);
	if (rv) {
		pthread_spin_unlock(&cq->lock);
		return rv;
	}
	pthread_spin_unlock(&cq->lock);

	free(cq);

	return 0;
}

struct ibv_srq *siw_create_srq(struct ibv_pd *pd,
			       struct ibv_srq_init_attr *attr)
{
	struct siw_cmd_create_srq	cmd;
	struct siw_cmd_create_srq_resp	resp;
	struct siw_srq			*srq = malloc(sizeof *srq);

	if (!srq)
		return NULL;

	if (ibv_cmd_create_srq(pd, &srq->ofa_srq, attr, &cmd.ofa_cmd,
			       sizeof cmd, &resp.ofa_resp, sizeof resp)) {
		free(pd);
		return NULL;
	}
	pthread_spin_init(&srq->lock, PTHREAD_PROCESS_PRIVATE);

	return &srq->ofa_srq;
}

int siw_modify_srq(struct ibv_srq *ofa_srq, struct ibv_srq_attr *attr,
		   int attr_mask)
{
	struct siw_srq		*srq = srq_ofa2siw(ofa_srq);
	struct ibv_modify_srq	cmd;
	int			rv;

	pthread_spin_lock(&srq->lock);
	rv = ibv_cmd_modify_srq(ofa_srq, attr, attr_mask, &cmd, sizeof cmd);
	pthread_spin_unlock(&srq->lock);

	return rv;
}

int siw_destroy_srq(struct ibv_srq *ofa_srq)
{
	struct siw_srq	*srq = srq_ofa2siw(ofa_srq);

	pthread_spin_lock(&srq->lock);
	ibv_cmd_destroy_srq(ofa_srq);
	pthread_spin_unlock(&srq->lock);

	free(srq);

	return 0;
}

struct ibv_qp *siw_create_qp(struct ibv_pd *pd, struct ibv_qp_init_attr *attr)
{
	struct siw_cmd_create_qp	cmd;
	struct siw_cmd_create_qp_resp	resp;
	struct siw_qp			*qp;

	int				rv;

	qp = calloc(1, sizeof *qp);
	if (!qp)
		return NULL;

	rv = ibv_cmd_create_qp(pd, &qp->ofa_qp, attr, &cmd.ofa_cmd,
			       sizeof cmd, &resp.ofa_resp, sizeof resp);
	if (rv)
		goto fail;

	qp->id = resp.qp_id;

	pthread_spin_init(&qp->lock, PTHREAD_PROCESS_PRIVATE);
	/*
	 * TODO: assign and initialize send and receive wq
	 * for mapped qp interface
	 */
	return &qp->ofa_qp;

fail:	free(qp);

	return (struct ibv_qp *) NULL;
}

int siw_modify_qp(struct ibv_qp *ofaqp, struct ibv_qp_attr *attr,
		  int attr_mask)
{
	struct siw_qp		*qp = qp_ofa2siw(ofaqp);
	struct ibv_modify_qp	cmd;
	int			rv;

	pthread_spin_lock(&qp->lock);
	rv = ibv_cmd_modify_qp(ofaqp, attr, attr_mask, &cmd, sizeof cmd);
	pthread_spin_unlock(&qp->lock);

	return rv;
}

int siw_destroy_qp(struct ibv_qp *ofaqp)
{
	struct siw_qp	*qp = qp_ofa2siw(ofaqp);
	int		rv;

	pthread_spin_lock(&qp->lock);

	rv = ibv_cmd_destroy_qp(ofaqp);
	if (rv) {
		pthread_spin_unlock(&qp->lock);
		return rv;
	}
	pthread_spin_unlock(&qp->lock);

	free(qp);

	return 0;
}

struct ibv_ah *siw_create_ah(struct ibv_pd *pd, struct ibv_ah_attr *attr)
{
	return NULL;
}

int siw_destroy_ah(struct ibv_ah *ah)
{
	return -ENOSYS;
}

void siw_async_event(struct ibv_async_event *event)
{

	switch (event->event_type) {

	case IBV_EVENT_CQ_ERR:
		break;

	case IBV_EVENT_QP_FATAL:
	case IBV_EVENT_QP_REQ_ERR:
	case IBV_EVENT_QP_ACCESS_ERR:
		/* TODO: flush qp */
		break;

	case IBV_EVENT_SQ_DRAINED:
	case IBV_EVENT_COMM_EST:
	case IBV_EVENT_QP_LAST_WQE_REACHED:
		break;

	default:
		break;
	}
}

/*
 * Software iWARP user library for SoftiWARP 'siw' Linux driver
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

#if HAVE_CONFIG_H
#  include <config.h>
#endif				/* HAVE_CONFIG_H */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>

#include "siw.h"
#include "siw_abi.h"

int siw_notify_cq(struct ibv_cq *ibcq, int solicited)
{
	struct siw_cq	*cq = cq_ofa2siw(ibcq);
	int		rv;

	pthread_spin_lock(&cq->lock);
	rv = ibv_cmd_req_notify_cq(ibcq, solicited);
	pthread_spin_unlock(&cq->lock);

	return rv;
}


int siw_post_send_ofed(struct ibv_qp *ofa_qp, struct ibv_send_wr *wr,
		      struct ibv_send_wr **bad_wr)
{
	struct siw_qp	*qp = qp_ofa2siw(ofa_qp);
	int		rv;

	pthread_spin_lock(&qp->lock);
	rv = ibv_cmd_post_send(ofa_qp, wr, bad_wr);
	pthread_spin_unlock(&qp->lock);

	return rv;
}

int siw_post_recv_ofed(struct ibv_qp *ofa_qp, struct ibv_recv_wr *wr,
		      struct ibv_recv_wr **bad_wr)
{
	struct siw_qp	*qp = qp_ofa2siw(ofa_qp);
	int		rv;

	pthread_spin_lock(&qp->lock);
	rv = ibv_cmd_post_recv(ofa_qp, wr, bad_wr);
	pthread_spin_unlock(&qp->lock);

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
	struct siw_cq    *cq = cq_ofa2siw(ibcq);
	int		rv;

	pthread_spin_lock(&cq->lock);
	rv = ibv_cmd_poll_cq(ibcq, num_entries, wc);
	pthread_spin_unlock(&cq->lock);

	return rv;
}


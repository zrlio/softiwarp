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
#include <linux/net.h>
#include <linux/scatterlist.h>
#include <linux/highmem.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <net/tcp.h>

#include <rdma/iw_cm.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_umem.h>

#include "siw.h"
#include "siw_obj.h"
#include "siw_cm.h"


void siw_qp_event(struct siw_qp *qp, enum ib_event_type etype)
{
	struct ib_event event;
	struct ib_qp	*ofa_qp = &qp->ofa_qp;

	event.event = etype;
	event.device = ofa_qp->device;
	event.element.qp = ofa_qp;

	if (!(qp->attrs.flags & SIW_QP_IN_DESTROY) && ofa_qp->event_handler) {
		dprint(DBG_EH, ": reporting %d\n", etype);
		(*ofa_qp->event_handler)(&event, ofa_qp->qp_context);
	}
}

void siw_cq_event(struct siw_cq *cq, enum ib_event_type etype)
{
	struct ib_event event;
	struct ib_cq	*ofa_cq = &cq->ofa_cq;

	event.event = etype;
	event.device = ofa_cq->device;
	event.element.cq = ofa_cq;

	if (ofa_cq->event_handler) {
		dprint(DBG_EH, ": reporting %d\n", etype);
		(*ofa_cq->event_handler)(&event, ofa_cq->cq_context);
	}
}

void siw_srq_event(struct siw_srq *srq, enum ib_event_type etype)
{
	struct ib_event event;
	struct ib_srq	*ofa_srq = &srq->ofa_srq;

	event.event = etype;
	event.device = ofa_srq->device;
	event.element.srq = ofa_srq;

	if (ofa_srq->event_handler) {
		dprint(DBG_EH, ": reporting %d\n", etype);
		(*ofa_srq->event_handler)(&event, ofa_srq->srq_context);
	}
}

void siw_port_event(struct siw_dev *sdev, u8 port, enum ib_event_type etype)
{
	struct ib_event event;

	event.event = etype;
	event.device = &sdev->ofa_dev;
	event.element.port_num = port;

	dprint(DBG_EH, ": reporting %d\n", etype);
	ib_dispatch_event(&event);
}

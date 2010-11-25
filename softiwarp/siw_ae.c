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

/*
 * siw_async_ev()
 *
 * Report Asynchonous event to user.
 */
void siw_async_ev(struct siw_qp *qp, struct siw_cq *cq,
		  enum ib_event_type etype)
{
	static struct ib_event	event;

	dprint(DBG_EH, "(QP%d): AE type %d\n", QP_ID(qp), etype);

	event.event = etype;
	event.device = qp->ofa_qp.device;
	if (cq)
		event.element.cq = &cq->ofa_cq;
	else
		event.element.qp = &qp->ofa_qp;

	if (!(qp->attrs.flags & SIW_QP_IN_DESTROY) &&
	    qp->ofa_qp.event_handler) {
		dprint(DBG_EH, "(QP%d): Call AEH\n", QP_ID(qp));
		(*qp->ofa_qp.event_handler)(&event, qp->ofa_qp.qp_context);
	}
}

void siw_async_srq_ev(struct siw_srq *srq, enum ib_event_type etype)
{
	static struct ib_event	event;

	dprint(DBG_EH, "(SRQ%p): AE type %d\n", srq, etype);

	event.event = etype;
	event.device = srq->ofa_srq.device;
	event.element.srq = &srq->ofa_srq;

	if (srq->ofa_srq.event_handler)
		(*srq->ofa_srq.event_handler)(&event, srq->ofa_srq.srq_context);
}

/*
 * Software iWARP device driver for Linux
 *
 * Authors: Bernard Metzler <bmt@zurich.ibm.com>
 *
 * Copyright (c) 2008-2017, IBM Corporation
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

#ifndef _SIW_VERBS_H
#define _SIW_VERBS_H

#include <linux/errno.h>

#include <rdma/iw_cm.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_user_verbs.h>

#include "siw.h"
#include "siw_cm.h"


extern struct ib_ucontext *siw_alloc_ucontext(struct ib_device *ibdev,
					      struct ib_udata *udata);
extern int siw_dealloc_ucontext(struct ib_ucontext *ucontext);
extern int siw_query_port(struct ib_device *ibdev, u8 port,
			  struct ib_port_attr *attr);
extern int siw_get_port_immutable(struct ib_device *ibdev, u8 port,
				  struct ib_port_immutable *port_imm);
extern int siw_query_device(struct ib_device *ibdev,
			    struct ib_device_attr *attr,
			    struct ib_udata *udata);
extern struct ib_cq *siw_create_cq(struct ib_device *ibdev,
				   const struct ib_cq_init_attr *attr,
				   struct ib_ucontext *ucontext,
				   struct ib_udata *udata);
extern int siw_no_mad(struct ib_device *ofa_dev, int flags, u8 port,
		      const struct ib_wc *wc, const struct ib_grh *grh,
		      const struct ib_mad_hdr *in_mad, size_t in_mad_size,
		      struct ib_mad_hdr *out_mad, size_t *out_mad_size,
		      u16 *outmad_pkey_index);
extern int siw_query_port(struct ib_device *ibdev, u8 port,
			  struct ib_port_attr *attr);
extern int siw_query_pkey(struct ib_device *ibdev, u8 port,
			  u16 idx, u16 *pkey);
extern int siw_query_gid(struct ib_device *ibdev, u8 port, int idx,
			 union ib_gid *gid);
extern struct ib_pd *siw_alloc_pd(struct ib_device *ibdev,
				  struct ib_ucontext *ucontext,
				  struct ib_udata *udata);
extern int siw_dealloc_pd(struct ib_pd *pd);
extern struct ib_qp *siw_create_qp(struct ib_pd *pd,
				  struct ib_qp_init_attr *attr,
				   struct ib_udata *udata);
extern int siw_query_qp(struct ib_qp *ofa_qp, struct ib_qp_attr *qp_attr,
			int qp_attr_mask, struct ib_qp_init_attr *qp_init_attr);
extern int siw_verbs_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
			       int attr_mask, struct ib_udata *udata);
extern int siw_destroy_qp(struct ib_qp *ibqp);
extern int siw_post_send(struct ib_qp *ibqp, struct ib_send_wr *wr,
			 struct ib_send_wr **bad_wr);
extern int siw_post_receive(struct ib_qp *ibqp, struct ib_recv_wr *wr,
			    struct ib_recv_wr **bad_wr);
extern int siw_destroy_cq(struct ib_cq *ibcq);
extern int siw_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *wc);
extern int siw_req_notify_cq(struct ib_cq *ibcq, enum ib_cq_notify_flags flags);
extern struct ib_mr *siw_reg_user_mr(struct ib_pd *ibpd, u64 start, u64 len,
				     u64 rnic_va, int rights,
				     struct ib_udata *udata);
extern struct ib_mr *siw_alloc_mr(struct ib_pd *ibpd, enum ib_mr_type mr_type,
				  u32 max_sge);
extern struct ib_mr *siw_get_dma_mr(struct ib_pd *ibpd, int rights);
extern int siw_map_mr_sg(struct ib_mr *ibmr, struct scatterlist *sl,
			 int num_sle, unsigned int *sg_off);
extern int siw_dereg_mr(struct ib_mr *ibmr);
extern struct ib_srq *siw_create_srq(struct ib_pd *ibpd,
				     struct ib_srq_init_attr *attr,
				     struct ib_udata *udata);
extern int siw_modify_srq(struct ib_srq *ibsrq, struct ib_srq_attr *attr,
			  enum ib_srq_attr_mask mask, struct ib_udata *udata);
extern int siw_query_srq(struct ib_srq *ibsrq, struct ib_srq_attr *attr);
extern int siw_destroy_srq(struct ib_srq *ibsrq);
extern int siw_post_srq_recv(struct ib_srq *ibsrq, struct ib_recv_wr *wr,
			     struct ib_recv_wr **bad_wr);
extern int siw_mmap(struct ib_ucontext *ibctx, struct vm_area_struct *vma);

extern struct dma_map_ops siw_dma_generic_ops;
extern struct ib_dma_mapping_ops siw_dma_mapping_ops;

#endif

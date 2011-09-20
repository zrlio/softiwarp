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

#ifndef _SIW_VERBS_H
#define _SIW_VERBS_H

#include <linux/errno.h>

#include <rdma/iw_cm.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_user_verbs.h>

#include "siw.h"
#include "siw_cm.h"

extern int siw_query_device(struct ib_device *, struct ib_device_attr *);

extern struct ib_ucontext *siw_alloc_ucontext(struct ib_device *,
					      struct ib_udata *);
extern int siw_dealloc_ucontext(struct ib_ucontext *);
extern int siw_query_port(struct ib_device *, u8, struct ib_port_attr *);
extern int siw_query_pkey(struct ib_device *, u8, u16, u16 *);
extern int siw_query_gid(struct ib_device *, u8, int, union ib_gid *);

extern struct ib_pd *siw_alloc_pd(struct ib_device *, struct ib_ucontext *,
				  struct ib_udata *);
extern int siw_dealloc_pd(struct ib_pd *);
extern struct ib_ah *siw_create_ah(struct ib_pd *, struct ib_ah_attr *);
extern int siw_destroy_ah(struct ib_ah *);
extern struct ib_qp *siw_create_qp(struct ib_pd *, struct ib_qp_init_attr *,
				   struct ib_udata *);
extern int siw_query_qp(struct ib_qp *, struct ib_qp_attr *, int,
			struct ib_qp_init_attr *);
extern int siw_ofed_modify_qp(struct ib_qp *, struct ib_qp_attr *, int,
			      struct ib_udata *);
extern int siw_destroy_qp(struct ib_qp *);
extern int siw_post_send(struct ib_qp *, struct ib_send_wr *,
			 struct ib_send_wr **);
extern int siw_post_receive(struct ib_qp *, struct ib_recv_wr *,
			    struct ib_recv_wr **);
extern struct ib_cq *siw_create_cq(struct ib_device *, int, int,
				   struct ib_ucontext *, struct ib_udata *);
extern int siw_destroy_cq(struct ib_cq *);
extern int siw_poll_cq(struct ib_cq *, int num_entries, struct ib_wc *);
extern int siw_req_notify_cq(struct ib_cq *, enum ib_cq_notify_flags);
extern struct ib_mr *siw_reg_user_mr(struct ib_pd *, u64, u64, u64, int,
				     struct ib_udata *);
extern struct ib_mr *siw_get_dma_mr(struct ib_pd *, int);
extern int siw_dereg_mr(struct ib_mr *);
extern struct ib_srq *siw_create_srq(struct ib_pd *, struct ib_srq_init_attr *,
				     struct ib_udata *);
extern int siw_modify_srq(struct ib_srq *, struct ib_srq_attr *,
			  enum ib_srq_attr_mask, struct ib_udata *);
extern int siw_query_srq(struct ib_srq *, struct ib_srq_attr *);
extern int siw_destroy_srq(struct ib_srq *);
extern int siw_post_srq_recv(struct ib_srq *, struct ib_recv_wr *,
			     struct ib_recv_wr **);
extern int siw_mmap(struct ib_ucontext *, struct vm_area_struct *);

extern struct dma_map_ops siw_dma_generic_ops;
extern struct ib_dma_mapping_ops siw_dma_mapping_ops;
extern struct device	siw_generic_dma_device;

#endif

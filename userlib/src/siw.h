/*
 * Software iWARP library for Linux
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

#ifndef _SIW_H
#define _SIW_H

#include <pthread.h>
#include <inttypes.h>
#include <stddef.h>

#include <infiniband/driver.h>
#include <infiniband/arch.h>

#define _NR_SYSCALL_DB 313


enum siw_if_type {
	SIW_IF_OFED = 0, 	/* only via standard ofed syscall if */
	SIW_IF_MAPPED = 1	/* private qp and cq mapping */
};

struct siw_device {
	struct ibv_device	ofa_dev;
	enum siw_if_type	if_type; /* private fast path or ofed generic */
	pthread_spinlock_t	lock;
};

struct siw_pd {
	struct ibv_pd	ofa_pd;
};

struct siw_srq {
	struct ibv_srq		ofa_srq;
	struct siw_rqe		*recvq;
	uint32_t		rq_put;
	uint32_t		num_rqe;
	pthread_spinlock_t	lock;
};

struct siw_mr {
	struct ibv_mr	ofa_mr;
	uint64_t	fbo;
	uint32_t	pbl_addr;
	uint32_t	len;
};

struct siw_qp {
	struct ibv_qp		ofa_qp;
	struct siw_device	*siw_dev;

	uint32_t		id;
	uint32_t		dev_id;

	uint32_t		num_sqe;
	uint32_t		sq_put;
	struct siw_sqe		*sendq;
	pthread_spinlock_t	sq_lock;
	
	uint32_t		num_rqe;
	uint32_t		rq_put;
	struct siw_rqe		*recvq;
	pthread_spinlock_t	rq_lock;

	struct siw_srq		*srq;

	int			sq_sig_all;
};

struct siw_cq {
	struct ibv_cq		ofa_cq;
	struct siw_device	*siw_dev;
	uint32_t		id;

	/* Points to kernel shared control
	 * object at the end of CQE array */
	struct siw_cq_ctrl	*ctrl;

	int			num_cqe;
	uint32_t		cq_get;
	struct siw_cqe		*queue;
	pthread_spinlock_t	lock;
};


struct siw_context {
	struct ibv_context	ofa_ctx;	
	uint32_t		dev_id;
};


#undef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE,MEMBER) __compiler_offsetof(TYPE,MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif


/* from <linux/kernel.h> */
#ifndef container_of
	#define container_of(ptr, type, member) ({                      \
		const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
		(type *)( (char *)__mptr - offsetof(type,member) );})
#endif

#define ctx_ofa2siw(ibv_ctx) container_of(ibv_ctx, struct siw_context, ofa_ctx)
#define	dev_ofa2siw(ibv_dev) container_of(ibv_dev, struct siw_device, ofa_dev)
#define	qp_ofa2siw(ibv_qp)   container_of(ibv_qp, struct siw_qp, ofa_qp)
#define	cq_ofa2siw(ibv_cq)   container_of(ibv_cq, struct siw_cq, ofa_cq)
#define	mr_ofa2siw(ibv_mr)   container_of(ibv_mr, struct siw_mr, ofa_mr)
#define	srq_ofa2siw(ibv_srq) container_of(ibv_srq, struct siw_srq, ofa_srq)

extern int siw_query_device(struct ibv_context *, struct ibv_device_attr *);
extern int siw_query_port(struct ibv_context *, uint8_t, struct ibv_port_attr *);
/* 
 * atr: Adding support for ibv_query_qp
 */
extern int siw_query_qp(struct ibv_qp *qp, struct ibv_qp_attr *,
                        int attr_mask, struct ibv_qp_init_attr *);

extern struct ibv_pd *siw_alloc_pd(struct ibv_context *);
extern int siw_free_pd(struct ibv_pd *);
extern struct ibv_mr *siw_reg_mr(struct ibv_pd *, void *, size_t, int);
extern int siw_dereg_mr(struct ibv_mr *);
extern struct ibv_cq *siw_create_cq(struct ibv_context *, int,
				   struct ibv_comp_channel *, int);
extern int siw_resize_cq(struct ibv_cq *, int);
extern int siw_destroy_cq(struct ibv_cq *);
extern int siw_notify_cq(struct ibv_cq *, int);
extern int siw_poll_cq_ofed(struct ibv_cq *, int, struct ibv_wc *);
extern int siw_poll_cq_mapped(struct ibv_cq *, int, struct ibv_wc *);

extern struct ibv_srq *siw_create_srq(struct ibv_pd *,
				     struct ibv_srq_init_attr *);
extern int siw_modify_srq(struct ibv_srq *, struct ibv_srq_attr *, int);
extern int siw_destroy_srq(struct ibv_srq *);

extern int siw_post_srq_recv(struct ibv_srq *, struct ibv_recv_wr *, 
			    struct ibv_recv_wr **);
extern struct ibv_qp *siw_create_qp(struct ibv_pd *, struct ibv_qp_init_attr *);
extern int siw_modify_qp(struct ibv_qp *, struct ibv_qp_attr *, int);
extern int siw_destroy_qp(struct ibv_qp *);

extern int siw_post_send_ofed(struct ibv_qp *, struct ibv_send_wr *,
			     struct ibv_send_wr **);
extern int siw_post_send_mapped(struct ibv_qp *, struct ibv_send_wr *,
				struct ibv_send_wr **);
extern int siw_post_recv_ofed(struct ibv_qp *, struct ibv_recv_wr *,
			     struct ibv_recv_wr **);
extern int siw_post_recv_mapped(struct ibv_qp *, struct ibv_recv_wr *,
			     struct ibv_recv_wr **);
extern int siw_post_srq_recv_ofed(struct ibv_srq *, struct ibv_recv_wr *,
				  struct ibv_recv_wr **);
extern int siw_post_srq_recv_mapped(struct ibv_srq *, struct ibv_recv_wr *,
				    struct ibv_recv_wr **);

extern struct ibv_ah *siw_create_ah(struct ibv_pd *, struct ibv_ah_attr *);
extern int siw_destroy_ah(struct ibv_ah *);

extern void siw_async_event(struct ibv_async_event *);


#endif	/* _SIW_H */

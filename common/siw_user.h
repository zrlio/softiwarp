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

#ifndef _SIW_USER_H
#define _SIW_USER_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

/*Common string that is matched to accept the device by the user library*/
#define SIW_NODE_DESC_COMMON	"Software iWARP stack"

#define SIW_IBDEV_PREFIX "siw_"

#define VERSION_ID_SOFTIWARP	2

#define SIW_MAX_SGE		6
#define SIW_MAX_UOBJ_KEY	0xffffff
#define SIW_INVAL_UOBJ_KEY	(SIW_MAX_UOBJ_KEY + 1)

struct siw_uresp_create_cq {
	uint32_t	cq_id;
	uint32_t	num_cqe;
	uint32_t	cq_key;
};

struct siw_uresp_create_qp {
	uint32_t	qp_id;
	uint32_t	num_sqe;
	uint32_t	num_rqe;
	uint32_t	sq_key;
	uint32_t	rq_key;
};

struct siw_ureq_reg_mr {
	uint8_t	stag_key;
	uint8_t	reserved[3];
};

struct siw_uresp_reg_mr {
	uint32_t	stag;
};

struct siw_uresp_create_srq {
	uint32_t	num_rqe;
	uint32_t	srq_key;
};

struct siw_uresp_alloc_ctx {
	uint32_t	dev_id;
};

enum siw_opcode {
	SIW_OP_WRITE		= 0,
	SIW_OP_READ		= 1,
	SIW_OP_READ_LOCAL_INV	= 2,
	SIW_OP_SEND		= 3,
	SIW_OP_SEND_WITH_IMM	= 4,
	SIW_OP_SEND_REMOTE_INV	= 5,

	/* Unsupported */
	SIW_OP_FETCH_AND_ADD	= 6,
	SIW_OP_COMP_AND_SWAP	= 7,

	SIW_OP_RECEIVE		= 8,
	/* provider internal SQE */
	SIW_OP_READ_RESPONSE	= 9,
	/*
	 * below opcodes valid for
	 * in-kernel clients only
	 */
	SIW_OP_INVAL_STAG	= 10,
	SIW_OP_REG_MR		= 11,
	SIW_NUM_OPCODES		= 12
};

/* Keep it same as ibv_sge to allow for memcpy */
struct siw_sge {
	uint64_t	laddr;
	uint32_t	length;
	uint32_t	lkey;
};

/*
 * Inline data are kept within the work request itself occupying
 * the space of sge[1] .. sge[n]. Therefore, inline data cannot be
 * supported if SIW_MAX_SGE is below 2 elements.
 */
#define SIW_MAX_INLINE	(sizeof(struct siw_sge) * (SIW_MAX_SGE - 1))

#if SIW_MAX_SGE < 2
#error "SIW_MAX_SGE must be at least 2"
#endif

enum siw_wqe_flags { 
	SIW_WQE_VALID           = 1,
	SIW_WQE_INLINE          = (1 << 1),
	SIW_WQE_SIGNALLED       = (1 << 2),
	SIW_WQE_SOLICITED       = (1 << 3),
	SIW_WQE_READ_FENCE	= (1 << 4),
	SIW_WQE_COMPLETED       = (1 << 5)
};

/* Minimum sized Send Queue Element */
struct siw_sqe {
	uint64_t	id;
	uint16_t	flags;
	uint8_t		num_sge;
	uint8_t		opcode; /* Actual enum siw_opcode values */
	uint32_t	rkey;
	union {
		uint64_t	raddr;
		uint64_t	ofa_mr;
	};
	union {
		struct siw_sge	sge[SIW_MAX_SGE];
		uint32_t	access;
	};
};

struct siw_rqe {
	uint64_t	id;
	uint32_t	flags;
	uint32_t	num_sge;
	struct siw_sge	sge[SIW_MAX_SGE];
};

enum siw_notify_flags {
	SIW_NOTIFY_NOT			= (0),
	SIW_NOTIFY_SOLICITED		= (1 << 0),
	SIW_NOTIFY_NEXT_COMPLETION	= (1 << 1),
	SIW_NOTIFY_MISSED_EVENTS	= (1 << 2),
	SIW_NOTIFY_ALL = SIW_NOTIFY_SOLICITED |
			SIW_NOTIFY_NEXT_COMPLETION |
			SIW_NOTIFY_MISSED_EVENTS
};

enum siw_wc_status {
	SIW_WC_SUCCESS		= 0,
	SIW_WC_LOC_LEN_ERR	= 1,
	SIW_WC_LOC_PROT_ERR	= 2,
	SIW_WC_LOC_QP_OP_ERR	= 3,
	SIW_WC_WR_FLUSH_ERR	= 4,
	SIW_WC_BAD_RESP_ERR	= 5,
	SIW_WC_LOC_ACCESS_ERR	= 6,
	SIW_WC_REM_ACCESS_ERR	= 7,
	SIW_WC_REM_INV_REQ_ERR	= 8,
	SIW_WC_GENERAL_ERR	= 9,
	SIW_NUM_WC_STATUS	= 10
};

struct siw_cqe {
	uint64_t	id;
	uint8_t		flags;
	uint8_t		opcode;
	uint16_t	status;
	uint32_t	bytes;
	uint64_t	imm_data;
	/* QP number or QP pointer */
	union { 
		void	*qp;
		uint64_t qp_id;
	};
};

/*
 * Shared structure between user and kernel
 * to control CQ arming.
 */
struct siw_cq_ctrl {
	enum siw_notify_flags	notify;
};

#endif

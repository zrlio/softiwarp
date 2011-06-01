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

#ifndef _SIW_ABI_H
#define _SIW_ABI_H


#include <infiniband/kern-abi.h>


/*
 * response structures for resource allocation calls
 */

struct siw_alloc_pd {
	struct ibv_alloc_pd ofa_cmd;
};

struct siw_alloc_pd_resp {
	struct ibv_alloc_pd_resp ofa_resp;
	uint32_t pd_id;
};

struct siw_alloc_ucontext_resp {
	struct ibv_get_context_resp ofa_resp;
};

struct siw_cmd_reg_umr_req {
	struct ibv_reg_mr ofa_req;
	uint8_t	 stag_key;
	uint8_t reserved[3];
};

struct siw_cmd_reg_umr_resp {
	struct ibv_reg_mr_resp ofa_resp;
	uint32_t stag;
};

struct siw_cmd_create_cq {
	struct ibv_create_cq ofa_cmd;
};

struct siw_cmd_create_cq_resp {
	struct ibv_create_cq_resp ofa_resp;
	uint32_t cq_id;
};

struct siw_cmd_create_qp {
	struct ibv_create_qp ofa_cmd;
};

struct siw_cmd_create_qp_resp {
	struct ibv_create_qp_resp ofa_resp;
	uint32_t qp_id;
	uint32_t sq_size;
	uint32_t rq_size;
};

struct siw_cmd_create_srq {
	struct ibv_create_srq ofa_cmd;
};

struct siw_cmd_create_srq_resp {
	struct ibv_create_srq_resp ofa_resp;
};
#endif	/* _SIW_ABI_H */

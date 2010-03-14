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

#ifndef __SIW_UTILS_H
#define __SIW_UTILS_H

#include <rdma/iw_cm.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_user_verbs.h>


extern void __siw_utils_mem_print(char *mem_name, unsigned char *kva,
				  unsigned int num_bytes);
extern void __siw_utils_kvec_print(char *vec_name, struct kvec *vec,
				  unsigned int num_elts);

extern void __siw_print_qp_state(enum siw_qp_state, int);
extern void __siw_print_qp_attr_mask(enum ib_qp_attr_mask);
extern void __siw_print_ib_wr_send(struct ib_send_wr *);
extern void __siw_print_ib_wr_recv(struct ib_recv_wr *);
extern void __siw_print_umem(struct ib_umem *);
extern void __siw_dump_bytes(void *, int);
extern void __siw_print_hdr(union iwarp_hdrs *, int, void *);
extern int __siw_drain_pkt(struct siw_qp *qp, struct siw_iwarp_rx *);

extern char siw_qp_state_to_string[SIW_QP_STATE_COUNT][9];
extern char ib_qp_state_to_string[IB_QPS_ERR+1][5];
extern int ib_qp_state_to_siw_qp_state[IB_QPS_ERR+1];

#endif

/*
 * Software iWARP device driver for Linux
 *
 * Authors: Bernard Metzler <bmt@zurich.ibm.com>
 *          Fredy Neeser <nfd@zurich.ibm.com>
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
#include <net/tcp.h>

#include <rdma/iw_cm.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_user_verbs.h>

#include "siw.h"
#include "siw_obj.h"
#include "siw_cm.h"


#ifdef SIW_DEBUG
static int siw_debug = 1;
#else
static int siw_debug; /*  = 0; */
#endif


#define NUM_BYTES_PER_LINE (16 * 6)

/**
 * __siw_utils_mem_print
 *
 * Prints memory contents in hex, with NUM_BYTES_PER_LINE bytes
 * per line of output.
 */

void __siw_utils_mem_print(char *mem_name, unsigned char *kva,
			   unsigned int num_bytes)
{
	int cnt, n, num_chars;
	int rem = num_bytes;

	char buf[2*NUM_BYTES_PER_LINE + 1]; /* for one line of printk output */
	char *p_str;

	while (rem > 0) {
		cnt = min(rem, NUM_BYTES_PER_LINE);
		p_str = buf;

		for (n = 0; n < cnt; n++) {
			num_chars = sprintf(p_str, "%02x", *kva++);
			p_str += num_chars;
		}
		printk(KERN_INFO "%s\n", buf);
		rem -= cnt;
	}
}

#undef SIW_UTILS_KVEC_PRINT_DATA


#ifndef SIW_UTILS_KVEC_PRINT_DATA

void __siw_utils_kvec_print(char *vec_name, struct kvec *vec,
		unsigned int num_elts)
{
	int i;
	struct kvec *p_vec = vec;

	for (i = 0; i < num_elts; i++) {
		printk(KERN_INFO "%s[%d].iov_base=0x%p, %s[%d].iov_len=%u\n",
				vec_name, i, p_vec->iov_base,
				vec_name, i, (uint32_t)p_vec->iov_len);
		p_vec++;
	}
}

#else

void __siw_utils_kvec_print(char *vec_name, struct kvec *vec,
		unsigned int num_elts)
{
	int i, rem, cnt, n, num_chars;

	struct kvec *p_vec;
	unsigned char *kva;
	char buf[2*NUM_BYTES_PER_LINE + 1]; /* for one line of printk output */
	char *p_str;

	p_vec = vec;

	for (i = 0; i < num_elts; i++) {
		printk(KERN_INFO "%s[%d].iov_base=0x%p, %s[%d].iov_len=%u\n",
				vec_name, i, p_vec->iov_base,
				vec_name, i, (uint32_t)p_vec->iov_len);
		p_vec++;
	}

	p_vec = vec;

	for (i = 0; i < num_elts; i++) {
		printk(KERN_INFO "%s[%d] (hex): \n", vec_name, i);

		kva = p_vec->iov_base;
		rem = p_vec->iov_len;

		while (rem > 0) {
			cnt = min(rem, NUM_BYTES_PER_LINE);
			p_str = buf;

			for (n = 0; n < cnt; n++) {
				/*
				 * Use unsigned char pointer to avoid printing
				 * more than two (i.e., 8) characters per byte
				 * if the most significant bit of *kva happens
				 * to be 1.
				 */
				num_chars = sprintf(p_str, "%02x", *kva++);
				p_str += num_chars;
			}
			printk(KERN_INFO "%s\n", buf);
			rem -= cnt;
		}
		p_vec++;
	}
}

#endif


void __siw_print_qp_attr_mask(enum ib_qp_attr_mask attr_mask)
{
	if (!siw_debug)
		return;

	printk(KERN_INFO "------- qp attr mask ---\n");
	if (IB_QP_STATE & attr_mask)
		printk(KERN_INFO "IB_QP_STATE\n");
	if (IB_QP_CUR_STATE & attr_mask)
		printk(KERN_INFO "IB_QP_CUR_STATE\n");
	if (IB_QP_EN_SQD_ASYNC_NOTIFY & attr_mask)
		printk(KERN_INFO "IB_QP_EN_SQD_ASYNC_NOTIFY\n");
	if (IB_QP_ACCESS_FLAGS & attr_mask)
		printk(KERN_INFO "IB_QP_ACCESS_FLAGS\n");
	if (IB_QP_PKEY_INDEX & attr_mask)
		printk(KERN_INFO "IB_QP_PKEY_INDEX\n");
	if (IB_QP_PORT & attr_mask)
		printk(KERN_INFO "IB_QP_PORT\n");
	if (IB_QP_QKEY & attr_mask)
		printk(KERN_INFO "IB_QP_QKEY\n");
	if (IB_QP_AV & attr_mask)
		printk(KERN_INFO "IB_QP_AV\n");
	if (IB_QP_PATH_MTU & attr_mask)
		printk(KERN_INFO "IB_QP_PATH_MTU\n");
	if (IB_QP_TIMEOUT & attr_mask)
		printk(KERN_INFO "IB_QP_TIMEOUT\n");
	if (IB_QP_RETRY_CNT & attr_mask)
		printk(KERN_INFO "IB_QP_RETRY_CNT\n");
	if (IB_QP_RNR_RETRY & attr_mask)
		printk(KERN_INFO "IB_QP_RNR_RETRY\n");
	if (IB_QP_RQ_PSN & attr_mask)
		printk(KERN_INFO "IB_QP_RQ_PSN\n");
	if (IB_QP_MAX_QP_RD_ATOMIC & attr_mask)
		printk(KERN_INFO "IB_QP_MAX_QP_RD_ATOMIC\n");
	if (IB_QP_ALT_PATH & attr_mask)
		printk(KERN_INFO "IB_QP_ALT_PATH\n");
	if (IB_QP_MIN_RNR_TIMER & attr_mask)
		printk(KERN_INFO "IB_QP_MIN_RNR_TIMER\n");
	if (IB_QP_SQ_PSN & attr_mask)
		printk(KERN_INFO "IB_QP_SQ_PSN\n");
	if (IB_QP_MAX_DEST_RD_ATOMIC & attr_mask)
		printk(KERN_INFO "IB_QP_MAX_DEST_RD_ATOMIC\n");
	if (IB_QP_PATH_MIG_STATE & attr_mask)
		printk(KERN_INFO "IB_QP_PATH_MIG_STATE\n");
	if (IB_QP_CAP & attr_mask)
		printk(KERN_INFO "IB_QP_CAP\n");
	if (IB_QP_DEST_QPN & attr_mask)
		printk(KERN_INFO "IB_QP_DEST_QPN\n");
	printk(KERN_INFO "------------------------\n");
}

void __siw_print_ib_wr_send(struct ib_send_wr *wr)
{
	struct ib_sge	*sge;
	int i;

	if (!siw_debug)
		return;

	switch (wr->opcode) {

	case IB_WR_SEND:
		printk(KERN_INFO "SEND: ");
		break;

	case IB_WR_RDMA_WRITE:
		printk(KERN_INFO "WRITE: ");
		break;

	case IB_WR_RDMA_READ:
		printk(KERN_INFO "RREAD: ");
		break;

	default:
		printk(KERN_INFO "??%d: ", wr->opcode);

	}
	printk(KERN_INFO "__siw_print_ib_wr_send(): id=%llu, num_sge=%d, \n"
		"opcode=%d, flags=0x%04x, rem_addr=0x%016llx, rkey=0x%08x\n",
		(unsigned long long)wr->wr_id,
		wr->num_sge,
		wr->opcode,
		wr->send_flags,
		(unsigned long long)wr->wr.rdma.remote_addr,
		wr->wr.rdma.rkey);

	for (sge = wr->sg_list, i = 0; i < wr->num_sge; i++, sge++)
		printk(KERN_INFO "sge%d: addr=0x%016llx, len=%u, key=0x%08x\n",
			i, (unsigned long long)sge->addr,
			sge->length, sge->lkey);
}

void __siw_print_ib_wr_recv(struct ib_recv_wr *wr)
{
	struct ib_sge	*sge;
	int i;

	if (!siw_debug)
		return;

	printk(KERN_INFO "__siw_print_ib_wr_recv(): id=0x%llu, num_sge=%d\n",
		(unsigned long long)wr->wr_id, wr->num_sge);

	for (sge = wr->sg_list, i = 0; i < wr->num_sge; i++, sge++)
		printk(KERN_INFO "sge%d: addr=0x%016llx, len=%u, key=0x%08x\n",
			i, (unsigned long long)sge->addr,
			sge->length, sge->lkey);
}


void __siw_print_umem(struct ib_umem *mem)
{
	struct ib_umem_chunk	*chunk;
	int			i, j;

	if (!siw_debug)
		return;

	printk(KERN_INFO "\n:::::::::::: __siw_print_umem(): start :::::\n");
	printk(KERN_INFO "length=%lu\toffset=%d\n", (unsigned long)mem->length,
		mem->offset);
	printk(KERN_INFO "chunklist::::\n");

	i = 0;
	list_for_each_entry(chunk, &mem->chunk_list, list) {
		printk(KERN_INFO "chunk%d: nent=%d, nmap=%d\n", i, chunk->nents,
			chunk->nmap);
		i++;
		for (j = 0; j < chunk->nents; j++) {

			struct scatterlist *sg = &chunk->page_list[j];

			printk(KERN_INFO "sg%d: page=%lx, offset=%d, dma=%llx, "
				"length=%d\n",
				j, sg->page_link, sg->offset,
				(unsigned long long)sg->dma_address,
				sg->length);
		}
	}
	printk(":::::::::::: __siw_print_umem(): end :::::::\n\n");
}

void __siw_print_hdr(union iwarp_hdrs *hdr, int qp_id, void *data)
{
	switch (hdr->ctrl.opcode) {

	case RDMAP_RDMA_WRITE:
		printk(KERN_INFO "QP%04d %p WRITE: %08x %016llx\n", qp_id,
			data, hdr->rwrite.sink_stag, hdr->rwrite.sink_to);
		break;

	case RDMAP_RDMA_READ_REQ:
		printk(KERN_INFO "QP%04d %p RREQ : %08x %08x %08x %08x "
			"%016llx %08x %08x %016llx\n", qp_id, data,
			hdr->rreq.ddp_qn, hdr->rreq.ddp_msn,
			hdr->rreq.ddp_mo, hdr->rreq.sink_stag,
			hdr->rreq.sink_to, hdr->rreq.read_size,
			hdr->rreq.source_stag, hdr->rreq.source_to);

		break;
	case RDMAP_RDMA_READ_RESP:
		printk(KERN_INFO "QP%04d %p RRESP: %08x %016llx\n",
			qp_id, data, hdr->rresp.sink_stag, hdr->rresp.sink_to);
		break;

	case RDMAP_SEND:
		printk(KERN_INFO "QP%04d %p SEND : %08x %08x %08x\n",
			qp_id, data, hdr->send.ddp_qn, hdr->send.ddp_msn,
			hdr->send.ddp_mo);
		break;

	case RDMAP_SEND_INVAL:
		printk(KERN_INFO "QP%04d %p S_INV: %08x %08x %08x\n",
			qp_id, data, hdr->send.ddp_qn, hdr->send.ddp_msn,
			hdr->send.ddp_mo);
		break;

	case RDMAP_SEND_SE:
		printk(KERN_INFO "QP%04d %p S_SE : %08x %08x %08x\n",
			qp_id, data, hdr->send.ddp_qn, hdr->send.ddp_msn,
			hdr->send.ddp_mo);
		break;

	case RDMAP_SEND_SE_INVAL:
		printk(KERN_INFO "QP%04d %p S_SE : %08x %08x %08x\n",
			qp_id, data, hdr->send.ddp_qn, hdr->send.ddp_msn,
			hdr->send.ddp_mo);
		break;

	case RDMAP_TERMINATE:
		printk(KERN_INFO "QP%04d %p TERM :\n", qp_id, data);
		break;

	default:
		printk(KERN_INFO "QP%04d %p ?????\n", qp_id, data);
		break;
	}
}

int __siw_drain_pkt(struct siw_qp *qp, struct siw_iwarp_rx *rctx)
{
	char	buf[4096];
	int	len;

	dprint(DBG_ON|DBG_RX, " (QP%d): drain %d bytes\n",
		QP_ID(qp), rctx->fpdu_part_rem);

	while (rctx->fpdu_part_rem) {
		len = min(rctx->fpdu_part_rem, 4096);

		skb_copy_bits(rctx->skb, rctx->skb_offset,
				      buf, rctx->fpdu_part_rem);

		rctx->skb_copied += len;
		rctx->skb_offset += len;
		rctx->skb_new -= len;
		rctx->fpdu_part_rem -= len;
	}
	return 0;
}

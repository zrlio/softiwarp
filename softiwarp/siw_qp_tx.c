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

static bool zcopy_tx = 1;
module_param(zcopy_tx, bool, 0644);
MODULE_PARM_DESC(zcopy_tx, "Zero copy user data transmit if possible");

static DEFINE_PER_CPU(atomic_t, siw_workq_len);

static inline int siw_crc_txhdr(struct siw_iwarp_tx *ctx)
{
	crypto_hash_init(&ctx->mpa_crc_hd);
	return siw_crc_array(&ctx->mpa_crc_hd, (u8 *)&ctx->pkt,
			     ctx->ctrl_len);
}

#define PKT_FRAGMENTED 1
#define PKT_COMPLETE 0

/*
 * siw_qp_prepare_tx()
 *
 * Prepare tx state for sending out one fpdu. Builds complete pkt
 * if no user data or only immediate data are present.
 *
 * returns PKT_COMPLETE if complete pkt built, PKT_FRAGMENTED otherwise.
 */
static int siw_qp_prepare_tx(struct siw_iwarp_tx *c_tx)
{
	struct siw_wqe		*wqe = c_tx->wqe;
	u32			*crc = NULL;

	dprint(DBG_TX, "(QP%d):\n", TX_QPID(c_tx));

	switch (wr_type(wqe)) {

	case SIW_WR_RDMA_READ_REQ:
		memcpy(&c_tx->pkt.ctrl,
		       &iwarp_pktinfo[RDMAP_RDMA_READ_REQ].ctrl,
		       sizeof(struct iwarp_ctrl));

		c_tx->pkt.rreq.rsvd = 0;
		c_tx->pkt.rreq.ddp_qn = htonl(RDMAP_UNTAGGED_QN_RDMA_READ);
		c_tx->pkt.rreq.ddp_msn =
			htonl(++c_tx->ddp_msn[RDMAP_UNTAGGED_QN_RDMA_READ]);
		c_tx->pkt.rreq.ddp_mo = 0;
		c_tx->pkt.rreq.sink_stag = htonl(wqe->wr.rread.sge[0].lkey);
		c_tx->pkt.rreq.sink_to =
			cpu_to_be64(wqe->wr.rread.sge[0].addr); /* abs addr! */
		c_tx->pkt.rreq.source_stag = htonl(wqe->wr.rread.rtag);
		c_tx->pkt.rreq.source_to = cpu_to_be64(wqe->wr.rread.raddr);
		c_tx->pkt.rreq.read_size = htonl(wqe->bytes);

		dprint(DBG_TX, ": RREQ: Sink: %x, 0x%016llx\n",
			wqe->wr.rread.sge[0].lkey, wqe->wr.rread.sge[0].addr);

		c_tx->ctrl_len = sizeof(struct iwarp_rdma_rreq);
		crc = &c_tx->pkt.rreq_pkt.crc;
		break;

	case SIW_WR_SEND:
		if (wr_flags(wqe) & IB_SEND_SOLICITED)
			memcpy(&c_tx->pkt.ctrl,
			       &iwarp_pktinfo[RDMAP_SEND_SE].ctrl,
			       sizeof(struct iwarp_ctrl));
		else
			memcpy(&c_tx->pkt.ctrl,
			       &iwarp_pktinfo[RDMAP_SEND].ctrl,
			       sizeof(struct iwarp_ctrl));

		c_tx->pkt.send.ddp_qn = RDMAP_UNTAGGED_QN_SEND;
		c_tx->pkt.send.ddp_msn =
			htonl(++c_tx->ddp_msn[RDMAP_UNTAGGED_QN_SEND]);
		c_tx->pkt.send.ddp_mo = 0;
		c_tx->pkt.send.rsvd = 0;

		c_tx->ctrl_len = sizeof(struct iwarp_send);

		if (!wqe->bytes)
			crc = &c_tx->pkt.send_pkt.crc;
		break;

	case SIW_WR_RDMA_WRITE:
		memcpy(&c_tx->pkt.ctrl, &iwarp_pktinfo[RDMAP_RDMA_WRITE].ctrl,
		       sizeof(struct iwarp_ctrl));

		c_tx->pkt.rwrite.sink_stag = htonl(wqe->wr.write.rtag);
		c_tx->pkt.rwrite.sink_to = cpu_to_be64(wqe->wr.write.raddr);
		c_tx->ctrl_len = sizeof(struct iwarp_rdma_write);

		if (!wqe->bytes)
			crc = &c_tx->pkt.write_pkt.crc;
		break;

	case SIW_WR_RDMA_READ_RESP:
		memcpy(&c_tx->pkt.ctrl,
		       &iwarp_pktinfo[RDMAP_RDMA_READ_RESP].ctrl,
		       sizeof(struct iwarp_ctrl));

		/* NBO */
		c_tx->pkt.rresp.sink_stag = cpu_to_be32(wqe->wr.rresp.rtag);
		c_tx->pkt.rresp.sink_to = cpu_to_be64(wqe->wr.rresp.raddr);

		c_tx->ctrl_len = sizeof(struct iwarp_rdma_rresp);

		dprint(DBG_TX, ": RRESP: Sink: %x, 0x%016llx\n",
			wqe->wr.rresp.rtag, wqe->wr.rresp.raddr);

		if (!wqe->bytes)
			crc = &c_tx->pkt.rresp_pkt.crc;
		break;

	default:
		dprint(DBG_ON, "Unsupported WQE type %d\n", wr_type(wqe));
		BUG();
		break;
	}
	c_tx->ctrl_sent = 0;
	c_tx->sge_idx = 0;
	c_tx->sge_off = 0;
	c_tx->pg_idx = 0;
	c_tx->umem_chunk = NULL;

	/*
	 * Do complete CRC if enabled and short packet
	 */
	if (crc) {
		*crc = 0;
		if (c_tx->crc_enabled) {
			if (siw_crc_txhdr(c_tx) != 0)
				return -EINVAL;
			crypto_hash_final(&c_tx->mpa_crc_hd, (u8 *)crc);
		}
	}
	c_tx->ctrl_len += MPA_CRC_SIZE;

	/*
	 * Allow direct sending out of user buffer if WR is non signalled
	 * and payload is over threshold and no CRC is enabled.
	 * Per RDMA verbs, the application should not change the send buffer
	 * until the work completed. In iWarp, work completion is only
	 * local delivery to TCP. TCP may reuse the buffer for
	 * retransmission. Changing unsent data also breaks the CRC,
	 * if applied.
	 */
	if (zcopy_tx
	    && !SIW_INLINED_DATA(wqe)
	    && !(wr_flags(wqe) & IB_SEND_SIGNALED)
	    && wqe->bytes > SENDPAGE_THRESH
	    && wr_type(wqe) != SIW_WR_RDMA_READ_REQ)
		c_tx->use_sendpage = 1;
	else
		c_tx->use_sendpage = 0;

	return crc == NULL ? PKT_FRAGMENTED : PKT_COMPLETE;
}

/*
 * Send out one complete FPDU. Used for fixed sized packets like
 * Read Requests or zero length SENDs, WRITEs, READ.responses.
 * Also used for pushing an FPDU hdr only.
 */
static inline int siw_tx_ctrl(struct siw_iwarp_tx *c_tx, struct socket *s,
			      int flags)
{
	struct msghdr msg = {.msg_flags = flags};
	struct kvec iov = {
		.iov_base = (char *)&c_tx->pkt.ctrl + c_tx->ctrl_sent,
		.iov_len = c_tx->ctrl_len - c_tx->ctrl_sent};

	int rv = kernel_sendmsg(s, &msg, &iov, 1,
				c_tx->ctrl_len - c_tx->ctrl_sent);

	dprint(DBG_TX, " (QP%d): op=%d, %d of %d sent (%d)\n",
		TX_QPID(c_tx), __rdmap_opcode(&c_tx->pkt.ctrl),
		c_tx->ctrl_sent + rv, c_tx->ctrl_len, rv);

	if (rv >= 0) {
		c_tx->ctrl_sent += rv;

		if (c_tx->ctrl_sent == c_tx->ctrl_len) {
			siw_dprint_hdr(&c_tx->pkt.hdr, TX_QPID(c_tx),
					"CTRL sent");
			if (!(flags & MSG_MORE))
				c_tx->new_tcpseg = 1;
			rv = 0;
		} else if (c_tx->ctrl_sent < c_tx->ctrl_len)
			rv = -EAGAIN;
		else
			BUG();
	}
	return rv;
}

/*
 * 0copy TCP transmit interface.
 *
 * Push page array page by page or in one shot.
 * Pushing the whole page array requires the inner do_tcp_sendpages
 * function to be exported by the kernel.
 */
static int siw_tcp_sendpages(struct socket *s, struct page **page,
			     int offset, size_t size)
{
	int rv = 0;

#ifdef SIW_SENDPAGES_EXPORT
	struct sock *sk = s->sk;

	if (!(sk->sk_route_caps & NETIF_F_SG) ||
	    !(sk->sk_route_caps & NETIF_F_ALL_CSUM)) {
		/* FIXME:
		 * This should also be handled in a
		 * loop
		 */
		return -EFAULT;
	}

	lock_sock(sk);
	TCP_CHECK_TIMER(sk);

	/*
	 * just return what sendpages has return
	 */
	rv = do_tcp_sendpages(sk, page, offset, size, MSG_MORE|MSG_DONTWAIT);

	TCP_CHECK_TIMER(sk);
	release_sock(sk);
	if (rv == -EAGAIN)
		rv = 0;
#else
	/*
	 * If do_tcp_sendpages() function is not exported
	 * push page by page
	 */
	size_t todo = size;
	int i;

	for (i = 0; size > 0; i++) {
		size_t bytes = min_t(size_t, PAGE_SIZE - offset, size);

		rv = s->ops->sendpage(s, page[i], offset, bytes,
				      MSG_MORE|MSG_DONTWAIT);
		if (rv <= 0)
			break;

		size -= rv;

		if (rv != bytes)
			break;

		offset = 0;
	}
	if (rv >= 0 || rv == -EAGAIN)
		rv = todo - size;
#endif
	return rv;
}

/*
 * siw_0copy_tx()
 *
 * Pushes list of pages to TCP socket. If pages from multiple
 * SGE's, all referenced pages of each SGE are pushed in one
 * shot.
 */
static int siw_0copy_tx(struct socket *s, struct page **page,
			struct siw_sge *sge, unsigned int offset,
			unsigned int size)
{
	int i = 0, sent = 0, rv;
	int sge_bytes = min(sge->len - offset, size);

	offset  = (sge->addr + offset) & ~PAGE_MASK;

	while (sent != size) {

		rv = siw_tcp_sendpages(s, &page[i], offset, sge_bytes);
		if (rv >= 0) {
			sent += rv;
			if (size == sent || sge_bytes > rv)
				break;

			i += PAGE_ALIGN(sge_bytes + offset) >> PAGE_SHIFT;
			sge++;
			sge_bytes = min(sge->len, size - sent);
			offset = sge->addr & ~PAGE_MASK;
		} else {
			sent = rv;
			break;
		}
	}
	return sent;
}

/*
 * siw_tx_umem_init()
 *
 * Resolve memory chunk and update page index pointer
 *
 * @chunk:	Umem Chunk to be updated
 * @p_idx	Page Index to be updated
 * @mr:		Memory Region
 * @va:		Virtual Address within MR
 *
 */
static void siw_tx_umem_init(struct ib_umem_chunk **chunk, int *page_index,
			     struct siw_mr *mr, u64 va)
{
	struct ib_umem_chunk *cp;
	int p_ix;

	BUG_ON(va < mr->mem.va);
	va -= mr->mem.va & PAGE_MASK;
	/*
	 * equivalent to
	 * va += mr->umem->offset;
	 * va = va >> PAGE_SHIFT;
	 */

	p_ix = va >> PAGE_SHIFT;

	list_for_each_entry(cp, &mr->umem->chunk_list, list) {
		if (p_ix < cp->nents)
			break;
		p_ix -= cp->nents;
	}
	BUG_ON(p_ix >= cp->nents);

	dprint(DBG_MM, "(): New chunk 0x%p: Page idx %d, nents %d\n",
		cp, p_ix, cp->nents);

	*chunk = cp;
	*page_index = p_ix;

	return;
}

/*
 * update memory chunk and page index from given starting point
 * before current transmit described by: c_tx->sge_off,
 * sge->addr, c_tx->pg_idx, and c_tx->umem_chunk
 */
static inline void
siw_umem_chunk_update(struct siw_iwarp_tx *c_tx, struct siw_mr *mr,
		      struct siw_sge *sge, unsigned int off)
{
	struct ib_umem_chunk *chunk = c_tx->umem_chunk;
	u64 va_start = sge->addr + c_tx->sge_off;

	off += (unsigned int)(va_start & ~PAGE_MASK); /* + first page offset */
	off >>= PAGE_SHIFT;	/* bytes offset becomes pages offset */

	list_for_each_entry_from(chunk, &mr->umem->chunk_list, list) {
		if (c_tx->pg_idx + off < chunk->nents)
			break;
		off -= chunk->nents - c_tx->pg_idx;
		c_tx->pg_idx = 0;
	}
	c_tx->pg_idx += off;

	c_tx->umem_chunk = chunk;
}

static inline void
siw_save_txstate(struct siw_iwarp_tx *c_tx, struct ib_umem_chunk *chunk,
		 unsigned int pg_idx, unsigned int sge_idx,
		 unsigned int sge_off)
{
	c_tx->umem_chunk = chunk;
	c_tx->pg_idx = pg_idx;
	c_tx->sge_idx = sge_idx;
	c_tx->sge_off = sge_off;
}

#define MAX_TRAILER (MPA_CRC_SIZE + 4)

/*
 * siw_tx_hdt() tries to push a complete packet to TCP where all
 * packet fragments are referenced by the elements of one iovec.
 * For the data portion, each involved page must be referenced by
 * one extra element. All sge's data can be non-aligned to page
 * boundaries. Two more elements are referencing iWARP header
 * and trailer:
 * MAX_ARRAY = 64KB/PAGE_SIZE + 1 + (2 * (SIW_MAX_SGE - 1) + HDR + TRL
 */
#define MAX_ARRAY ((0xffff / PAGE_SIZE) + 1 + (2 * (SIW_MAX_SGE - 1) + 2))

/*
 * Write out iov referencing hdr, data and trailer of current FPDU.
 * Update transmit state dependent on write return status
 */
static int siw_tx_hdt(struct siw_iwarp_tx *c_tx, struct socket *s)
{
	struct siw_wqe		*wqe = c_tx->wqe;
	struct siw_sge		*sge = &wqe->wr.sgl.sge[c_tx->sge_idx],
				*first_sge = sge;
	struct siw_mr		*mr = NULL;
	struct ib_umem_chunk	*chunk = c_tx->umem_chunk;

	struct kvec		iov[MAX_ARRAY];
	struct page		*page_array[MAX_ARRAY];
	struct msghdr		msg = {.msg_flags = MSG_DONTWAIT};

	int			seg = 0, do_crc = c_tx->do_crc, is_kva = 0, rv;
	unsigned int		data_len = c_tx->bytes_unsent,
				hdr_len = 0,
				trl_len = 0,
				sge_off = c_tx->sge_off,
				sge_idx = c_tx->sge_idx,
				pg_idx = c_tx->pg_idx;


	if (c_tx->state == SIW_SEND_HDR) {
		if (c_tx->use_sendpage) {
			rv = siw_tx_ctrl(c_tx, s, MSG_DONTWAIT|MSG_MORE);
			if (rv)
				goto done;

			c_tx->state = SIW_SEND_DATA;
		} else {
			iov[0].iov_base =
				(char *)&c_tx->pkt.ctrl + c_tx->ctrl_sent;
			iov[0].iov_len = hdr_len =
				c_tx->ctrl_len - c_tx->ctrl_sent;
			seg = 1;
			siw_dprint_hdr(&c_tx->pkt.hdr, TX_QPID(c_tx),
					"HDR to send: ");
		}
	}

	wqe->processed += data_len;

	while (data_len) { /* walk the list of SGE's */
		unsigned int	sge_len = min(sge->len - sge_off, data_len);
		unsigned int	fp_off = (sge->addr + sge_off) & ~PAGE_MASK;

		BUG_ON(!sge_len);

		if (!SIW_INLINED_DATA(wqe)) {
			mr = siw_mem2mr(sge->mem.obj);
			if (!mr->umem)
				is_kva = 1;
			else if (!chunk) {
				siw_tx_umem_init(&chunk, &pg_idx, mr,
						 sge->addr + sge_off);

				if (!c_tx->umem_chunk)
					/* Starting first tx for this WQE */
					siw_save_txstate(c_tx, chunk, pg_idx,
							 sge_idx, sge_off);
			}
		} else
			is_kva = 1;

		if (is_kva && !c_tx->use_sendpage) {
			/*
			 * tx from kernel virtual address: either inline data
			 * or memory region with assigned kernel buffer
			 */
			iov[seg].iov_base = (void *)(sge->addr + sge_off);
			iov[seg].iov_len = sge_len;

			if (do_crc)
				siw_crc_array(&c_tx->mpa_crc_hd,
					      iov[seg].iov_base, sge_len);
			sge_off += sge_len;
			data_len -= sge_len;
			seg++;
			goto sge_done;
		}

		while (sge_len) {
			struct scatterlist *sl;
			size_t plen = min((int)PAGE_SIZE - fp_off, sge_len);

			BUG_ON(plen <= 0);
			if (!is_kva) {
				sl = &chunk->page_list[pg_idx];
				page_array[seg] = sg_page(sl);
				if (!c_tx->use_sendpage) {
					iov[seg].iov_base = kmap(sg_page(sl))
							    + fp_off;
					iov[seg].iov_len = plen;
				}
				if (do_crc)
					siw_crc_sg(&c_tx->mpa_crc_hd, sl,
						   fp_off, plen);
			} else {
				u64 pa = ((sge->addr + sge_off) & PAGE_MASK);
				page_array[seg] = virt_to_page(pa);
				if (do_crc)
					siw_crc_array(&c_tx->mpa_crc_hd,
						(void *)(sge->addr + sge_off),
						plen);
			}

			sge_len -= plen;
			sge_off += plen;
			data_len -= plen;

			if (!is_kva && plen + fp_off == PAGE_SIZE &&
			    sge_off < sge->len && ++pg_idx == chunk->nents) {
				chunk = mem_chunk_next(chunk);
				pg_idx = 0;
			}
			fp_off = 0;
			if (++seg > (int)MAX_ARRAY) {
				dprint(DBG_ON, "(QP%d): Too many fragments\n",
				       TX_QPID(c_tx));
				if (!is_kva) {
					int i = (hdr_len > 0) ? 1 : 0;
					seg--;
					while (i < seg)
						kunmap(page_array[i++]);
				}
				wqe->processed -= c_tx->bytes_unsent;
				rv = -EMSGSIZE;
				goto done_crc;
			}
		}
sge_done:
		/* Update SGE variables at end of SGE */
		if (sge_off == sge->len &&
		    (data_len != 0 || wqe->processed < wqe->bytes)) {
			sge_idx++;
			sge++;
			sge_off = 0;
			chunk = NULL;
		}
	}
	/* trailer */
	if (likely(c_tx->state != SIW_SEND_TRAILER)) {
		iov[seg].iov_base = &c_tx->trailer.pad[4 - c_tx->pad];
		iov[seg].iov_len = trl_len = MAX_TRAILER - (4 - c_tx->pad);
	} else {
		iov[seg].iov_base = &c_tx->trailer.pad[c_tx->ctrl_sent];
		iov[seg].iov_len = trl_len = MAX_TRAILER - c_tx->ctrl_sent;
	}

	if (c_tx->pad) {
		*(u32 *)c_tx->trailer.pad = 0;
		if (do_crc)
			siw_crc_array(&c_tx->mpa_crc_hd,
				      (u8 *)&c_tx->trailer.crc - c_tx->pad,
				      c_tx->pad);
	}
	if (!c_tx->crc_enabled)
		c_tx->trailer.crc = 0;
	else if (do_crc)
		crypto_hash_final(&c_tx->mpa_crc_hd, (u8 *)&c_tx->trailer.crc);

	data_len = c_tx->bytes_unsent;

	if (c_tx->tcp_seglen >= (int)MPA_MIN_FRAG &&
				 TX_MORE_WQE(TX_QP(c_tx))) {
		msg.msg_flags |= MSG_MORE;
		c_tx->new_tcpseg = 0;
	} else
		c_tx->new_tcpseg = 1;

	if (c_tx->use_sendpage) {
		rv = siw_0copy_tx(s, page_array, first_sge, c_tx->sge_off,
				  data_len);
		if (rv == data_len) {
			rv = kernel_sendmsg(s, &msg, &iov[seg], 1, trl_len);
			if (rv > 0)
				rv += data_len;
			else
				rv = data_len;
		}
	} else {
		rv = kernel_sendmsg(s, &msg, iov, seg + 1,
				    hdr_len + data_len + trl_len);
		if (!is_kva) {
			int i = (hdr_len > 0) ? 1 : 0;
			while (i < seg)
				kunmap(page_array[i++]);
		}
	}
	if (rv < (int)hdr_len) {
		/* Not even complete hdr pushed or negative rv */
		wqe->processed -= data_len;
		if (rv >= 0) {
			c_tx->ctrl_sent += rv;
			rv = -EAGAIN;
		}
		goto done_crc;
	}

	rv -= hdr_len;

	if (rv >= (int)data_len) {
		/* all user data pushed to TCP or no data to push */
		if (data_len > 0 && wqe->processed < wqe->bytes)
			/* Save the current state for next tx */
			siw_save_txstate(c_tx, chunk, pg_idx, sge_idx,
					 sge_off);

		rv -= data_len;

		if (rv == trl_len) /* all pushed */
			rv = 0;
		else {
			c_tx->state = SIW_SEND_TRAILER;
			c_tx->ctrl_len = MAX_TRAILER;
			c_tx->ctrl_sent = rv + 4 - c_tx->pad;
			c_tx->bytes_unsent = 0;
			rv = -EAGAIN;
		}

	} else if (data_len > 0) {
		/* Maybe some user data pushed to TCP */
		c_tx->state = SIW_SEND_DATA;
		wqe->processed -= data_len - rv;

		if (rv) {
			/*
			 * Some bytes out. Recompute tx state based
			 * on old state and bytes pushed
			 */
			c_tx->bytes_unsent -= rv;
			sge = &wqe->wr.sgl.sge[c_tx->sge_idx];

			if (!is_kva && c_tx->sge_idx == sge_idx &&
			    c_tx->umem_chunk)
				/*
				 * same SGE as starting SGE for this FPDU
				 */
				siw_umem_chunk_update(c_tx, mr, sge, rv);
			else {
				while (sge->len <= c_tx->sge_off + rv) {
					rv -= sge->len - c_tx->sge_off;
					c_tx->sge_idx++;
					c_tx->sge_off = 0;
					sge = &wqe->wr.sgl.sge[c_tx->sge_idx];
				}
				c_tx->umem_chunk = NULL;
			}
			c_tx->sge_off += rv;
			BUG_ON(c_tx->sge_off >= sge->len);
		}
		rv = -EAGAIN;
	}
done_crc:
	c_tx->do_crc = 0;
done:
	return rv;
}

static void siw_calculate_tcpseg(struct siw_iwarp_tx *c_tx, struct socket *s)
{
	/*
	 * refresh TCP segement len if we start a new segment or
	 * remaining segment len is less than MPA_MIN_FRAG or
	 * the socket send buffer is empty.
	 */
	if (c_tx->new_tcpseg || c_tx->tcp_seglen < (int)MPA_MIN_FRAG ||
	     !tcp_send_head(s->sk))
		c_tx->tcp_seglen = get_tcp_mss(s->sk);
}


/*
 * siw_unseg_txlen()
 *
 * Compute complete tcp payload len if packet would not
 * get fragmented
 */
static inline int siw_unseg_txlen(struct siw_iwarp_tx *c_tx)
{
	int pad = c_tx->bytes_unsent ? -c_tx->bytes_unsent & 0x3 : 0;

	return c_tx->bytes_unsent + c_tx->ctrl_len + pad + MPA_CRC_SIZE;
}


/*
 * siw_prepare_fpdu()
 *
 * Prepares transmit context to send out one FPDU if FPDU will contain
 * user data and user data are not immediate data.
 * Checks and locks involved memory segments of data to be sent.
 * Computes maximum FPDU length to fill up TCP MSS if possible.
 *
 * @qp:		QP from which to transmit
 * @wqe:	Current WQE causing transmission
 *
 * TODO: Take into account real available sendspace on socket
 *       to avoid header misalignment due to send pausing within
 *       fpdu transmission
 */
static int siw_prepare_fpdu(struct siw_qp *qp, struct siw_wqe *wqe)
{
	struct siw_iwarp_tx	*c_tx  = &qp->tx_ctx;
	int			rv = 0;

	/*
	 * TODO: TCP Fragmentation dynamics needs for further investigation.
	 *	 Resuming SQ processing may start with full-sized packet
	 *	 or short packet which resets MSG_MORE and thus helps
	 *	 to synchronize.
	 *	 This version resumes with short packet.
	 */
	c_tx->ctrl_len = iwarp_pktinfo[__rdmap_opcode(&c_tx->pkt.ctrl)].hdr_len;
	c_tx->ctrl_sent = 0;

	/*
	 * Update target buffer offset if any
	 */
	if (!(c_tx->pkt.ctrl.ddp_rdmap_ctrl & DDP_FLAG_TAGGED)) {
		/* Untagged message */
		c_tx->pkt.c_untagged.ddp_mo = cpu_to_be32(wqe->processed);
	} else {
		/* Tagged message */
		if (wr_type(wqe) == SIW_WR_RDMA_READ_RESP) {
			c_tx->pkt.c_tagged.ddp_to =
			    cpu_to_be64(wqe->wr.rresp.raddr + wqe->processed);
		} else {
			c_tx->pkt.c_tagged.ddp_to =
			    cpu_to_be64(wqe->wr.write.raddr + wqe->processed);
		}
	}

	/* First guess: one big unsegmented DDP segment */
	c_tx->bytes_unsent = wqe->bytes - wqe->processed;
	c_tx->tcp_seglen -= siw_unseg_txlen(c_tx);

	if (c_tx->tcp_seglen >= 0) {
		/* Whole DDP segment fits into current TCP segment */
		c_tx->pkt.ctrl.ddp_rdmap_ctrl |= DDP_FLAG_LAST;
		c_tx->pad = -c_tx->bytes_unsent & 0x3;
	} else {
		/* Trim DDP payload to fit into current TCP segment */
		c_tx->bytes_unsent += c_tx->tcp_seglen;
		c_tx->bytes_unsent &= ~0x3;
		c_tx->pad = 0;
		c_tx->pkt.ctrl.ddp_rdmap_ctrl &= ~DDP_FLAG_LAST;
	}
	c_tx->pkt.ctrl.mpa_len =
		htons(c_tx->ctrl_len + c_tx->bytes_unsent - MPA_HDR_SIZE);

#ifdef SIW_TX_FULLSEGS
	c_tx->fpdu_len =
		c_tx->ctrl_len + c_tx->bytes_unsent + c_tx->pad + MPA_CRC_SIZE;
#endif
	/*
	 * Init MPA CRC computation
	 */
	if (c_tx->crc_enabled) {
		siw_crc_txhdr(c_tx);
		c_tx->do_crc = 1;
	}
	if (c_tx->bytes_unsent && !SIW_INLINED_DATA(wqe)) {
		struct siw_sge	*sge = &wqe->wr.sgl.sge[c_tx->sge_idx];
		/*
		 * Reference memory to be tx'd
		 */
		BUG_ON(c_tx->sge_idx > wqe->wr.sgl.num_sge - 1);

		if (wr_type(wqe) != SIW_WR_RDMA_READ_RESP)
			rv = siw_check_sgl(qp->pd, sge, SR_MEM_LREAD,
					   c_tx->sge_off, c_tx->bytes_unsent);
		else
			rv = siw_check_sge(qp->pd, sge, SR_MEM_RREAD,
					   c_tx->sge_off, c_tx->bytes_unsent);
	}
	return rv;
}

#ifdef SIW_TX_FULLSEGS
static inline int siw_test_wspace(struct socket *s, struct siw_iwarp_tx *c_tx)
{
	struct sock *sk = s->sk;
	int rv = 0;

	lock_sock(sk);
	if (sk_stream_wspace(sk) < (int)c_tx->fpdu_len) {
		set_bit(SOCK_NOSPACE, &s->flags);
		rv = -EAGAIN;
	}
	release_sock(sk);

	return rv;
}
#endif
/*
 * siw_qp_sq_proc_tx()
 *
 * Process one WQE which needs transmission on the wire.
 * Return with:
 *	-EAGAIN, if handover to tcp remained incomplete
 *	0,	 if handover to tcp complete
 *	< 0,	 if other errors happend.
 *
 * @qp:		QP to send from
 * @wqe:	WQE causing transmission
 */
static int siw_qp_sq_proc_tx(struct siw_qp *qp, struct siw_wqe *wqe)
{
	struct siw_iwarp_tx	*c_tx = &qp->tx_ctx;
	struct socket		*s = qp->attrs.llp_stream_handle;
	int			rv = 0;


	if (wqe->wr_status == SR_WR_QUEUED) {
		wqe->wr_status = SR_WR_INPROGRESS;

		siw_calculate_tcpseg(c_tx, s);

		rv = siw_qp_prepare_tx(c_tx);
		if (rv == PKT_FRAGMENTED) {
			c_tx->state = SIW_SEND_HDR;
			rv = siw_prepare_fpdu(qp, wqe);
			if (rv)
				return rv;
		} else if (rv == PKT_COMPLETE)
			c_tx->state = SIW_SEND_SHORT_FPDU;
		else
			goto tx_done;
	}
next_segment:
#ifdef SIW_TX_FULLSEGS
	rv = siw_test_wspace(s, c_tx);
	if (rv < 0)
		goto tx_done;
#endif

	if (c_tx->state == SIW_SEND_SHORT_FPDU) {
		enum siw_wr_opcode tx_type = wr_type(wqe);

		/*
		 * Always end current TCP segment (no MSG_MORE flag):
		 * trying to fill segment would result in excessive delay.
		 */
		rv = siw_tx_ctrl(c_tx, s, MSG_DONTWAIT);

		if (!rv && tx_type != SIW_WR_RDMA_READ_REQ)
			wqe->processed = wqe->bytes;

		goto tx_done;

	} else
		rv = siw_tx_hdt(c_tx, s);

	if (!rv) {
		/* Verbs, 6.4.: Try stopping sending after a full DDP segment
		 * if the connection goes down (== peer halfclose)
		 */
		if (unlikely(c_tx->tx_suspend)) {
			rv = -ECONNABORTED;
			goto tx_done;
		} else if (c_tx->pkt.ctrl.ddp_rdmap_ctrl & DDP_FLAG_LAST) {
			/*
			 * One segment sent. Processing completed if last
			 * segment, Do next segment otherwise.
			 */
			dprint(DBG_TX, "(QP%d): WR completed\n", QP_ID(qp));
			goto tx_done;
		}
		c_tx->state = SIW_SEND_HDR;

		siw_calculate_tcpseg(c_tx, s);

		rv = siw_prepare_fpdu(qp, wqe);
		if (!rv)
			goto next_segment;
	}
tx_done:
	return rv;
}


/*
 * siw_wqe_sq_processed()
 *
 * Called after WQE processing completed.
 * If WQE is not of signalled typ, it can be released.
 * If the ORQ is empty, a signalled WQE is attached to the CQ.
 * Otherwise, it is appended to the end of the ORQ for later
 * completion. To keep WQE ordering, the ORQ is always consumed FIFO.
 */
static void siw_wqe_sq_processed(struct siw_wqe *wqe, struct siw_qp *qp)
{
	unsigned long flags;
	LIST_HEAD(c_list);

	if (!(wr_flags(wqe) & IB_SEND_SIGNALED)) {
		siw_wqe_put(wqe);
		return;
	}
	lock_orq_rxsave(qp, flags);

	if (ORQ_EMPTY(qp)) {
		unlock_orq_rxsave(qp, flags);
		dprint(DBG_WR|DBG_TX,
			"(QP%d): Immediate completion, wr_type %d\n",
			QP_ID(qp), wr_type(wqe));
		list_add_tail(&wqe->list, &c_list);
		siw_sq_complete(&c_list, qp, 1, wr_flags(wqe));
	} else {
		list_add_tail(&wqe->list, &qp->orq);
		unlock_orq_rxsave(qp, flags);
		dprint(DBG_WR|DBG_TX,
			"(QP%d): Defer completion, wr_type %d\n",
			QP_ID(qp), wr_type(wqe));
	}
}

static int siw_qp_sq_proc_local(struct siw_qp *qp, struct siw_wqe *wqe)
{
	pr_info("local WR's not yet implemented\n");
	BUG();
	return 0;
}


/*
 * siw_qp_sq_process()
 *
 * Core TX path routine for RDMAP/DDP/MPA using a TCP kernel socket.
 * Sends RDMAP payload for the current SQ WR @wqe of @qp in one or more
 * MPA FPDUs, each containing a DDP segment.
 *
 * SQ processing may occur in user context as a result of posting
 * new WQE's or from siw_sq_work_handler() context. Processing in
 * user context is limited to non-kernel verbs users.
 *
 * SQ processing may get paused anytime, possibly in the middle of a WR
 * or FPDU, if insufficient send space is available. SQ processing
 * gets resumed from siw_sq_work_handler(), if send space becomes
 * available again.
 *
 * Must be called with the QP state read-locked.
 *
 * TODO:
 * To be solved more seriously: an outbound RREQ can be satisfied
 * by the corresponding RRESP _before_ it gets assigned to the ORQ.
 * This happens regularly in RDMA READ via loopback case. Since both
 * outbound RREQ and inbound RRESP can be handled by the same CPU
 * locking the ORQ is dead-lock prone and thus not an option.
 * Tentatively, the RREQ gets assigned to the ORQ _before_ being
 * sent (and pulled back in case of send failure).
 */
int siw_qp_sq_process(struct siw_qp *qp, int user_ctx)
{
	struct siw_wqe		*wqe;
	enum siw_wr_opcode	tx_type;
	unsigned long		flags;
	int			rv = 0;
	int			max_burst;

	if (user_ctx)
		max_burst = SQ_USER_MAXBURST;
	else
		max_burst = max(qp->attrs.sq_size, qp->attrs.ird);

	wait_event(qp->tx_ctx.waitq, !atomic_read(&qp->tx_ctx.in_use));

	if (atomic_inc_return(&qp->tx_ctx.in_use) > 1) {
		/*
		 * at least two waiters: that should never happen!
		 */
		WARN_ON(1);
		atomic_dec(&qp->tx_ctx.in_use);
		return 0;
	}
	wqe = tx_wqe(qp);
	BUG_ON(wqe == NULL);

next_wqe:
	/*
	 * Stop QP processing if SQ state changed
	 */
	if (unlikely(qp->tx_ctx.tx_suspend)) {
		dprint(DBG_WR|DBG_TX, "(QP%d): tx suspend\n", QP_ID(qp));
		goto done;
	}
	tx_type = wr_type(wqe);

	dprint(DBG_WR|DBG_TX,
		" QP(%d): WR type %d, state %d, data %u, sent %u, id %llu\n",
		QP_ID(qp), wr_type(wqe), wqe->wr_status, wqe->bytes,
		wqe->processed, (unsigned long long)wr_id(wqe));

	if (SIW_WQE_IS_TX(wqe))
		rv = siw_qp_sq_proc_tx(qp, wqe);
	else
		rv = siw_qp_sq_proc_local(qp, wqe);

	if (!rv) {
		/*
		 * WQE processing done
		 */
		switch (tx_type) {

		case SIW_WR_SEND:
		case SIW_WR_RDMA_WRITE:

			wqe->wc_status = IB_WC_SUCCESS;
			wqe->wr_status = SR_WR_DONE;
			siw_wqe_sq_processed(wqe, qp);
			break;

		case SIW_WR_RDMA_READ_REQ:
			/*
			 * already enqueued to ORQ queue
			 */
			break;

		case SIW_WR_RDMA_READ_RESP:
			/*
			 * silently recyclye wqe
			 */
			/* XXX DEBUG AID, please remove */
			wqe->wr_status = SR_WR_DONE;
			siw_wqe_put(wqe);
			break;
		default:
			BUG();
		}

		lock_sq_rxsave(qp, flags);

		wqe = siw_next_tx_wqe(qp);
		if (!wqe) {
			tx_wqe(qp) = NULL;
			unlock_sq_rxsave(qp, flags);
			goto done;
		}
		if (wr_type(wqe) == SIW_WR_RDMA_READ_REQ) {
			if (ORD_SUSPEND_SQ(qp)) {
				tx_wqe(qp) = NULL;
				unlock_sq_rxsave(qp, flags);
				dprint(DBG_WR|DBG_TX,
					" QP%d PAUSE SQ: ORD limit\n",
					QP_ID(qp));
				goto done;
			} else {
				tx_wqe(qp) = wqe;
				siw_rreq_queue(wqe, qp);
			}
		} else  {
			list_del_init(&wqe->list);
			tx_wqe(qp) = wqe;
		}
		unlock_sq_rxsave(qp, flags);

		if (--max_burst == 0) {
			if (user_ctx) {
				/*
				 * Avoid to keep the user sending from its
				 * context for too long (blocking user thread)
				 */
				siw_sq_queue_work(qp);
				goto done;
			} else {
				/*
				 * Avoid to starve other QP's tx if consumer
				 * keeps posting new tx work for current cpu.
				 */
				int workq_len =
				    atomic_read(&get_cpu_var(siw_workq_len));

				put_cpu_var(siw_workq_len);

				if (workq_len) {
					/* Another QP's work on same WQ */
					siw_sq_queue_work(qp);
					goto done;
				}
			}
			max_burst = max(qp->attrs.sq_size, qp->attrs.ird);
		}
		goto next_wqe;

	} else if (rv == -EAGAIN) {
		dprint(DBG_WR|DBG_TX,
			"(QP%d): SQ paused: hd/tr %d of %d, data %d\n",
			QP_ID(qp), qp->tx_ctx.ctrl_sent, qp->tx_ctx.ctrl_len,
			qp->tx_ctx.bytes_unsent);
		rv = 0;
		goto done;
	} else {
		/*
		 * WQE processing failed.
		 * Verbs 8.3.2:
		 * o It turns any WQE into a signalled WQE.
		 * o Local catastrophic error must be surfaced
		 * o QP must be moved into Terminate state: done by code
		 *   doing socket state change processing
		 *
		 * o TODO: Termination message must be sent.
		 * o TODO: Implement more precise work completion errors,
		 *         see enum ib_wc_status in ib_verbs.h
		 */
		dprint(DBG_ON, " (QP%d): WQE type %d processing failed: %d\n",
				QP_ID(qp), wr_type(wqe), rv);

		lock_sq_rxsave(qp, flags);
		/*
		 * RREQ may have already been completed by inbound RRESP!
		 */
		if (tx_type == SIW_WR_RDMA_READ_REQ) {
			lock_orq(qp);
			if (!ORQ_EMPTY(qp) &&
			    wqe == list_entry_wqe(qp->orq.prev)) {
				/*
				 * wqe still on the ORQ
				 * TODO: fix a potential race condition if the
				 * rx path is currently referencing the wqe(!)
				 */
				dprint(DBG_ON, " (QP%d): Bad RREQ in ORQ\n",
					QP_ID(qp));
				list_del_init(&wqe->list);
				unlock_orq(qp);
			} else {
				/*
				 * already completed by inbound RRESP
				 */
				dprint(DBG_ON, " (QP%d): Bad RREQ completed\n",
					QP_ID(qp));
				unlock_orq(qp);
				tx_wqe(qp) = NULL;
				unlock_sq_rxsave(qp, flags);

				goto done;
			}
		}
		tx_wqe(qp) = NULL;
		unlock_sq_rxsave(qp, flags);
		/*
		 * immediately suspends further TX processing
		 */
		if (!qp->tx_ctx.tx_suspend)
			siw_qp_cm_drop(qp, 0);

		switch (tx_type) {

		case SIW_WR_SEND:
		case SIW_WR_RDMA_WRITE:
		case SIW_WR_RDMA_READ_REQ:
			wqe->wr_status = SR_WR_DONE;
			wqe->wc_status = IB_WC_LOC_QP_OP_ERR;
			wqe->error = rv;
			wr_flags(wqe) |= IB_SEND_SIGNALED;
			if (tx_type != SIW_WR_RDMA_READ_REQ)
				/*
				 * RREQ already enqueued to ORQ queue
				 */
				siw_wqe_sq_processed(wqe, qp);

			siw_qp_event(qp, IB_EVENT_QP_FATAL);

			break;

		case SIW_WR_RDMA_READ_RESP:
			/*
			 * Recyclye wqe
			 */
			dprint(DBG_WR|DBG_TX|DBG_ON, "(QP%d): "
				   "Processing RRESPONSE failed with %d\n",
				    QP_ID(qp), rv);

			siw_qp_event(qp, IB_EVENT_QP_REQ_ERR);

			siw_wqe_put(wqe);
			break;

		default:
			BUG();
		}
	}
done:
	atomic_dec(&qp->tx_ctx.in_use);
	wake_up(&qp->tx_ctx.waitq);

	return rv;
}

static struct workqueue_struct *siw_sq_wq;

int __init siw_sq_worker_init(void)
{
	siw_sq_wq = create_workqueue("siw_sq_wq");
	if (!siw_sq_wq)
		return -ENOMEM;

	dprint(DBG_TX|DBG_OBJ, " Init WQ\n");
	return 0;
}


void siw_sq_worker_exit(void)
{
	dprint(DBG_TX|DBG_OBJ, " Destroy WQ\n");
	if (siw_sq_wq) {
		flush_workqueue(siw_sq_wq);
		destroy_workqueue(siw_sq_wq);
	}
}


/*
 * siw_sq_work_handler()
 *
 * Scheduled by siw_qp_llp_write_space() socket callback if socket
 * send space became available again. This function resumes SQ
 * processing.
 */
static void siw_sq_work_handler(struct work_struct *w)
{
	struct siw_sq_work	*this_work;
	struct siw_qp		*qp;
	int			rv;

	atomic_dec(&get_cpu_var(siw_workq_len));
	put_cpu_var(siw_workq_len);

	this_work = container_of(w, struct siw_sq_work, work);
	qp = container_of(this_work, struct siw_qp, sq_work);

	dprint(DBG_TX|DBG_OBJ, "(QP%d)\n", QP_ID(qp));

	if (down_read_trylock(&qp->state_lock)) {
		if (likely(qp->attrs.state == SIW_QP_STATE_RTS &&
			   !qp->tx_ctx.tx_suspend)) {

			rv = siw_qp_sq_process(qp, 0);
			up_read(&qp->state_lock);

			if (rv < 0) {
				dprint(DBG_TX, "(QP%d): failed: %d\n",
					QP_ID(qp), rv);

				if (!qp->tx_ctx.tx_suspend)
					siw_qp_cm_drop(qp, 0);
			}
		} else {
			dprint(DBG_ON|DBG_TX, "(QP%d): state: %d %d\n",
				QP_ID(qp), qp->attrs.state,
					qp->tx_ctx.tx_suspend);
			up_read(&qp->state_lock);
		}
	} else {
		dprint(DBG_ON|DBG_TX, "(QP%d): QP locked\n", QP_ID(qp));
	}
	siw_qp_put(qp);
}


int siw_sq_queue_work(struct siw_qp *qp)
{
	int cpu, rv;

	dprint(DBG_TX|DBG_OBJ, "(QP%d)\n", QP_ID(qp));

	siw_qp_get(qp);

	INIT_WORK(&qp->sq_work.work, siw_sq_work_handler);

	cpu = get_cpu();
#if NR_CPUS > 1
	if (in_softirq()) {
		int sq_cpu;
		if (cpu == qp->cpu) {
			/*
			 * Try not to use the current CPU for tx traffic.
			 */
			for_each_online_cpu(sq_cpu) {
				if (sq_cpu != cpu)
					break;
			}
		} else
			sq_cpu = qp->cpu;

		if (cpu_online(sq_cpu))
			cpu = sq_cpu;
	}
#endif
	atomic_inc(&per_cpu(siw_workq_len, cpu));
	/*
	 * Remember CPU: Avoid spreading SQ work of QP over WQ's
	 */
	qp->cpu = cpu;
	rv = queue_work_on(cpu, siw_sq_wq, &qp->sq_work.work);

	put_cpu();

	return rv;
}

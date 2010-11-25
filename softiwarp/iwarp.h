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

#ifndef _IWARP_H
#define _IWARP_H

#include <rdma/rdma_user_cm.h>	/* RDMA_MAX_PRIVATE_DATA */
#include <linux/types.h>
#include <asm/byteorder.h>


#define RDMAP_VERSION		1
#define DDP_VERSION		1
#define MPA_REVISION_1		1
#define MPA_MAX_PRIVDATA	RDMA_MAX_PRIVATE_DATA
#define MPA_KEY_REQ		"MPA ID Req Frame"
#define MPA_KEY_REP		"MPA ID Rep Frame"

struct mpa_rr_params {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__be16	res:5,
		r:1,
		c:1,
		m:1,
		rev:8;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__be16	m:1,
		c:1,
		r:1,
		res:5,
		rev:8;
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif
	__be16	pd_len;
};

/*
 * MPA request/reply header
 */
struct mpa_rr {
	__u8	key[16];
	struct mpa_rr_params params;
};

/*
 * Don't change the layout/size of this struct!
 */
struct mpa_marker {
	__be16	rsvd;
	__be16	fpdu_hmd; /* FPDU header-marker distance (= MPA's FPDUPTR) */
};

#define MPA_MARKER_SPACING	512
#define MPA_HDR_SIZE		2

/*
 * MPA marker size:
 * - Standards-compliant marker insertion: Use sizeof(struct mpa_marker)
 * - "Invisible markers" for testing sender's marker insertion
 *   without affecting receiver: Use 0
 */
#define MPA_MARKER_SIZE		sizeof(struct mpa_marker)


/*
 * maximum MPA trailer
 */
struct mpa_trailer {
	char	pad[4];
	__be32	crc;
};

#define MPA_CRC_SIZE	4


/*
 * Common portion of iWARP headers (MPA, DDP, RDMAP)
 * for any FPDU
 */
struct iwarp_ctrl {
	__be16	mpa_len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__be16	dv:2,		/* DDP Version */
		rsvd:4,		/* DDP reserved, MBZ */
		l:1,		/* DDP Last flag */
		t:1,		/* DDP Tagged flag */
		opcode:4,	/* RDMAP opcode */
		rsv:2,		/* RDMAP reserved, MBZ */
		rv:2;		/* RDMAP Version, 01 for IETF, 00 for RDMAC */
#elif defined(__BIG_ENDIAN_BITFIELD)
	__be16	t:1,		/* DDP Tagged flag */
		l:1,		/* DDP Last flag */
		rsvd:4,		/* DDP reserved, MBZ */
		dv:2,		/* DDP Version */
		rv:2,		/* RDMAP Version, 01 for IETF, 00 for RDMAC */
		rsv:2,		/* RDMAP reserved, MBZ */
		opcode:4;	/* RDMAP opcode */
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif
};


struct rdmap_terminate_ctrl {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__be32	etype:4,
		layer:4,
		ecode:8,
		rsvd1:5,
		r:1,
		d:1,
		m:1,
		rsvd2:8;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__be32	layer:4,
		etype:4,
		ecode:8,
		m:1,
		d:1,
		r:1,
		rsvd1:5,
		rsvd2:8;
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif
};


struct iwarp_rdma_write {
	struct iwarp_ctrl	ctrl;
	__be32			sink_stag;
	__be64			sink_to;
};

struct iwarp_rdma_rreq {
	struct iwarp_ctrl	ctrl;
	__be32			rsvd;
	__be32			ddp_qn;
	__be32			ddp_msn;
	__be32			ddp_mo;
	__be32			sink_stag;
	__be64			sink_to;
	__be32			read_size;
	__be32			source_stag;
	__be64			source_to;
};

struct iwarp_rdma_rresp {
	struct iwarp_ctrl	ctrl;
	__be32			sink_stag;
	__be64			sink_to;
};

struct iwarp_send {
	struct iwarp_ctrl	ctrl;
	__be32			rsvd;
	__be32			ddp_qn;
	__be32			ddp_msn;
	__be32			ddp_mo;
};

struct iwarp_send_inv {
	struct iwarp_ctrl	ctrl;
	__be32			inval_stag;
	__be32			ddp_qn;
	__be32			ddp_msn;
	__be32			ddp_mo;
};

struct iwarp_terminate {
	struct iwarp_ctrl	ctrl;
	__be32				rsvd;
	__be32				ddp_qn;
	__be32				ddp_msn;
	__be32				ddp_mo;
	struct rdmap_terminate_ctrl	term_ctrl;
};


/*
 * Common portion of iWARP headers (MPA, DDP, RDMAP)
 * for an FPDU carrying an untagged DDP segment
 */
struct iwarp_ctrl_untagged {
	struct iwarp_ctrl	ctrl;
	__be32			rsvd;
	__be32			ddp_qn;
	__be32			ddp_msn;
	__be32			ddp_mo;
};

/*
 * Common portion of iWARP headers (MPA, DDP, RDMAP)
 * for an FPDU carrying a tagged DDP segment
 */
struct iwarp_ctrl_tagged {
	struct iwarp_ctrl	ctrl;
	__be32			ddp_stag;
	__be64			ddp_to;
};

union iwarp_hdrs {
	struct iwarp_ctrl		ctrl;
	struct iwarp_ctrl_untagged	c_untagged;
	struct iwarp_ctrl_tagged	c_tagged;
	struct iwarp_rdma_write		rwrite;
	struct iwarp_rdma_rreq		rreq;
	struct iwarp_rdma_rresp		rresp;
	struct iwarp_terminate		terminate;
	struct iwarp_send		send;
	struct iwarp_send_inv		send_inv;
};


#define MPA_MIN_FRAG ((sizeof(union iwarp_hdrs) + MPA_CRC_SIZE))

enum ddp_etype {
	DDP_ETYPE_CATASTROPHIC	= 0x0,
	DDP_ETYPE_TAGGED_BUF	= 0x1,
	DDP_ETYPE_UNTAGGED_BUF	= 0x2,
	DDP_ETYPE_RSVD		= 0x3
};

enum ddp_ecode {
	DDP_ECODE_CATASTROPHIC		= 0x00,
	/* Tagged Buffer Errors */
	DDP_ECODE_T_INVALID_STAG	= 0x00,
	DDP_ECODE_T_BASE_BOUNDS		= 0x01,
	DDP_ECODE_T_STAG_NOT_ASSOC	= 0x02,
	DDP_ECODE_T_TO_WRAP		= 0x03,
	DDP_ECODE_T_DDP_VERSION		= 0x04,
	/* Untagged Buffer Errors */
	DDP_ECODE_UT_INVALID_QN		= 0x01,
	DDP_ECODE_UT_INVALID_MSN_NOBUF	= 0x02,
	DDP_ECODE_UT_INVALID_MSN_RANGE	= 0x03,
	DDP_ECODE_UT_INVALID_MO		= 0x04,
	DDP_ECODE_UT_MSG_TOOLONG	= 0x05,
	DDP_ECODE_UT_DDP_VERSION	= 0x06
};


enum rdmap_untagged_qn {
	RDMAP_UNTAGGED_QN_SEND		= 0,
	RDMAP_UNTAGGED_QN_RDMA_READ	= 1,
	RDMAP_UNTAGGED_QN_TERMINATE	= 2,
	RDMAP_UNTAGGED_QN_COUNT		= 3
};

enum rdmap_etype {
	RDMAP_ETYPE_CATASTROPHIC	= 0x0,
	RDMAP_ETYPE_REMOTE_PROTECTION	= 0x1,
	RDMAP_ETYPE_REMOTE_OPERATION	= 0x2
};

enum rdmap_ecode {
	RDMAP_ECODE_INVALID_STAG	= 0x00,
	RDMAP_ECODE_BASE_BOUNDS		= 0x01,
	RDMAP_ECODE_ACCESS_RIGHTS	= 0x02,
	RDMAP_ECODE_STAG_NOT_ASSOC	= 0x03,
	RDMAP_ECODE_TO_WRAP		= 0x04,
	RDMAP_ECODE_RDMAP_VERSION	= 0x05,
	RDMAP_ECODE_UNEXPECTED_OPCODE	= 0x06,
	RDMAP_ECODE_CATASTROPHIC_STREAM	= 0x07,
	RDMAP_ECODE_CATASTROPHIC_GLOBAL	= 0x08,
	RDMAP_ECODE_STAG_NOT_INVALIDATE	= 0x09,
	RDMAP_ECODE_UNSPECIFIED		= 0xff
};

enum rdmap_elayer {
	RDMAP_ERROR_LAYER_RDMA	= 0x00,
	RDMAP_ERROR_LAYER_DDP	= 0x01,
	RDMAP_ERROR_LAYER_LLP	= 0x02	/* eg., MPA */
};

enum rdma_opcode {
	RDMAP_RDMA_WRITE	= 0x0,
	RDMAP_RDMA_READ_REQ	= 0x1,
	RDMAP_RDMA_READ_RESP	= 0x2,
	RDMAP_SEND		= 0x3,
	RDMAP_SEND_INVAL	= 0x4,
	RDMAP_SEND_SE		= 0x5,
	RDMAP_SEND_SE_INVAL	= 0x6,
	RDMAP_TERMINATE		= 0x7,
	RDMAP_NOT_SUPPORTED	= RDMAP_TERMINATE + 1
};

#endif

/*
 * Software iWARP device driver for Linux
 *
 * Authors: Fredy Neeser <nfd@zurich.ibm.com>
 *          Bernard Metzler <bmt@zurich.ibm.com>
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

#ifndef _SIW_DEBUG_H
#define _SIW_DEBUG_H

#include <linux/uaccess.h>
#include <linux/hardirq.h>	/* in_interrupt() */

/*
 * dprint: Selective debug printing
 *
 * Use an OR combination of DBG_* as dbgcat in dprint*(dbgcat,...)
 * to assign debug messages to categories:
 *
 * dbgcat	Debug message belongs to category
 * ----------------------------------------------------------------------------
 * DBG_ON	Always on, for really important events or error conditions
 * DBG_TMP	Temporarily on for fine-grained debugging
 * DBQ_OBJ	Object management (object construction/destruction/refcounting)
 * DBG_MM	Memory management
 * DBG_EH	Event handling (completion events and asynchronous events)
 * DBG_CM	Connection management, QP states
 * DBG_WR	Work requests
 * DBG_TX	iWARP TX path
 * DBG_RX	iWARP RX path
 * DBG_SK	Socket operations
 * DBG_KT	Kernel threads
 * DBG_IRQ	Interrupt context (SoftIRQ or HardIRQ)
 * DBG_DM	Device management
 * DBG_HDR	Packet HDRs
 * DBG_ALL	All categories above
 */
#define DBG_ON		0x00000001
#define DBG_TMP		0x00000002
#define DBG_OBJ		0x00000004
#define DBG_MM		0x00000008
#define DBG_EH		0x00000010
#define DBG_CM		0x00000020
#define DBG_WR		0x00000040
#define DBG_TX		0x00000080
#define DBG_RX		0x00000100
#define DBG_SK		0x00000200
#define DBG_KT		0x00000400
#define DBG_IRQ		0x00000800
#define DBG_DM		0x00001000
#define DBG_HDR		0x00002000
#define DBG_CQ		0x00004000
#define DBG_ALL		(DBG_IRQ|DBG_KT|DBG_SK|DBG_RX|DBG_TX|DBG_WR|\
DBG_CM|DBG_EH|DBG_MM|DBG_OBJ|DBG_TMP|DBG_DM|DBG_ON|DBG_HDR|DBG_CQ)
#define DBG_ALL_NOHDR	(DBG_IRQ|DBG_KT|DBG_SK|DBG_RX|DBG_TX|DBG_WR|\
DBG_CM|DBG_EH|DBG_MM|DBG_OBJ|DBG_TMP|DBG_DM|DBG_ON)
#define DBG_CTRL	(DBG_ON|DBG_CM|DBG_DM)

/*
 * Set DPRINT_MASK to tailor your debugging needs:
 *
 * DPRINT_MASK value		Enables debug messages for
 * ---------------------------------------------------------------------
 * DBG_ON			Important events / error conditions only
 *				(minimum number of debug messages)
 * OR-ed combination of DBG_*	Selective debugging
 * DBG_KT|DBG_ON		Kernel threads
 * DBG_ALL			All categories
 */
#define DPRINT_MASK	0

extern void siw_debug_init(void);
extern void siw_debugfs_add_device(struct siw_dev *);
extern void siw_debugfs_del_device(struct siw_dev *);
extern void siw_debugfs_delete(void);

extern void siw_print_hdr(union iwarp_hdrs *, int, char *);
extern void siw_print_rctx(struct siw_iwarp_rx *);
extern void siw_print_qp_attr_mask(enum ib_qp_attr_mask, char *);

#if DPRINT_MASK > 0

/**
 * dprint - Selective debug print for process, SoftIRQ or HardIRQ context
 *
 * Debug print with selectable debug categories,
 * starting with header
 * - "( pid /cpu) __func__" for process context
 * - "( irq /cpu) __func__" for IRQ context
 *
 * @dbgcat	: Set of debug categories (OR-ed combination of DBG_* above),
 *		  to which this debug message is assigned.
 * @fmt		: printf compliant format string
 * @args	: printf compliant argument list
 */
#define dprint(dbgcat, fmt, args...)					\
	do {								\
		if ((dbgcat) & DPRINT_MASK) {				\
			if (!in_interrupt())				\
				pr_info("(%5d/%1d) %s" fmt,		\
					current->pid,			\
					current_thread_info()->cpu,	\
					__func__, ## args);		\
			else						\
				pr_info("( irq /%1d) %s" fmt,		\
					current_thread_info()->cpu,	\
					__func__, ## args);		\
		}							\
	} while (0)


#define siw_dprint_rctx(r)	siw_print_rctx(r)

extern char ib_qp_state_to_string[IB_QPS_ERR+1][sizeof "RESET"];
extern atomic_t siw_num_wqe;

#define SIW_INC_STAT_WQE	atomic_inc(&siw_num_wqe)
#define SIW_DEC_STAT_WQE	atomic_dec(&siw_num_wqe)

#else

#define dprint(dbgcat, fmt, args...)	do { } while (0)
#define siw_dprint_rctx(r)	do { } while (0)
#define SIW_INC_STAT_WQE	do { } while (0)
#define SIW_DEC_STAT_WQE	do { } while (0)
#endif


#if DPRINT_MASK & DBG_HDR
#define siw_dprint_hdr(h, i, m)	siw_print_hdr(h, i, m)
#else
#define siw_dprint_hdr(h, i, m)	do { } while (0)
#endif

#if DPRINT_MASK & DBG_CM
#define siw_dprint_qp_attr_mask(mask)\
		siw_print_qp_attr_mask(mask, (char *)__func__)
#else
#define siw_dprint_qp_attr_mask(mask)	do { } while (0)
#endif

#endif

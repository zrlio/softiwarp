/*
 * Software iWARP device driver for Linux
 *
 * Authors: Fredy Neeser <nfd@zurich.ibm.com>
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
 * -----------------------------------------------------------------------------
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
 * DBG_DATA	Application data (payload)
 * DBG_QP	QP references (tentative dbg code)
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
#define DBG_DATA	0x00002000
#define DBG_QP		0x00004000
#define DBG_ALL		(DBG_IRQ|DBG_KT|DBG_SK|DBG_RX|DBG_TX|DBG_WR|\
DBG_CM|DBG_EH|DBG_MM|DBG_OBJ|DBG_TMP|DBG_DM|DBG_ON|DBG_DATA|DBG_QP)
#define DBG_ALL_NODATA	(DBG_IRQ|DBG_KT|DBG_SK|DBG_RX|DBG_TX|DBG_WR|\
DBG_CM|DBG_EH|DBG_MM|DBG_OBJ|DBG_TMP|DBG_DM|DBG_ON)
#define DBG_CTRL	(DBG_ON|DBG_CM|DBG_DM|DBG_QP)

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
#if 0
#define DPRINT_MASK	DBG_ON
#define DPRINT_MASK	(DBG_KT|DBG_ON)
#define DPRINT_MASK	(DBG_OBJ|DBG_ON)
#define DPRINT_MASK	(DBG_MM|DBG_ON)
#define DPRINT_MASK	(DBG_EH|DBG_ON)
#define DPRINT_MASK	(DBG_TX|DBG_CM|DBG_TMP|DBG_ON)
#define DPRINT_MASK	(DBG_RX|DBG_CM|DBG_TMP|DBG_ON)
#define DPRINT_MASK	(DBG_CM|DBG_TMP|DBG_ON)
#define DPRINT_MASK	(DBG_KT|DBG_CM|DBG_TMP|DBG_ON)
#define DPRINT_MASK	(DBG_CM|DBG_ON)
#define DPRINT_MASK	(DBG_WR|DBG_ON)
#define DPRINT_MASK	(DBG_CM|DBG_MM|DBG_EH|DBG_OBJ|DBG_WR)
#define DPRINT_MASK	DBG_DM
#define DPRINT_MASK	(~DBG_ALL)
#endif
#define DPRINT_MASK	(DBG_ON)
/* #define DPRINT_MASK	(DBG_ON|DBG_DM|DBG_TX|DBG_CQ) */


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
				printk(KERN_INFO "(%5d/%1d) %s" fmt,	\
					current->pid,			\
					current_thread_info()->cpu,	\
					__func__, ## args);		\
			else						\
				printk(KERN_INFO "( irq /%1d) %s" fmt,	\
						current_thread_info()->cpu,\
						__func__, ## args);	\
		}							\
	} while (0)


/**
 * dprint_mem - Selective debug print for memory
 *
 * Debug print with selectable debug categories,
 * starting with header
 *	"( pid /cpu) __func__" fmt "dprint_mem(start)\n"
 * and ending with trailer
 *	"( pid /cpu) __func__" fmt "dprint_mem(end)\n"
 *
 * @dbgcat	: Set of debug categories (OR-ed combination of DBG_* above),
 *		  to which this debug message is assigned.
 * TODO: Complete this ...
 *
 * @fmt		: printf compliant format string for header/trailer
 * @args	: printf compliant argument list for header/trailer
 */
#define dprint_mem(dbgcat, mem_name, kva, num_bytes, fmt, args...) {\
	do {								\
		if ((dbgcat) & DPRINT_MASK) {				\
			printk(KERN_INFO "(%5d/%1d) %s" fmt		\
					"dprint_mem(start)\n",		\
					current->pid,			\
					current_thread_info()->cpu,	\
					__func__, ## args);		\
			__siw_utils_mem_print(mem_name, kva, num_bytes);\
			printk(KERN_INFO "(%5d/%1d) %s" fmt		\
					"dprint_mem(end)\n",		\
					current->pid,			\
					current_thread_info()->cpu,	\
					 __func__, ## args);	\
		}							\
	} while (0);							\
}


/**
 * dprint_mem_irq - Selective debug print for memory for SoftIRQ/HardIRQ context
 *
 * Debug print with selectable debug categories,
 * starting with header
 *	"( irq /cpu) __func__" fmt "dprint_mem(start)\n"
 * and ending with trailer
 *	"( irq /cpu) __func__" fmt "dprint_mem(end)\n"
 *
 * @dbgcat	: Set of debug categories (OR-ed combination of DBG_* above),
 *		  to which this debug message is assigned.
 * TODO: Complete this ...
 *
 * @fmt		: printf compliant format string for header/trailer
 * @args	: printf compliant argument list for header/trailer
 */
#define dprint_mem_irq(dbgcat, mem_name, kva, num_bytes,		\
		fmt, args...) {						\
	do {								\
		if ((dbgcat) & DPRINT_MASK) {				\
			printk(KERN_INFO "( irq /%1d) %s" fmt		\
					"dprint_mem(start)\n",		\
					current_thread_info()->cpu,	\
					__func__, ## args);		\
			__siw_utils_mem_print(mem_name, kva, num_bytes);\
			printk(KERN_INFO "( irq /%1d) %s" fmt		\
					"dprint_mem(end)\n",		\
					current_thread_info()->cpu,	\
					 __func__, ## args);		\
		}							\
	} while (0);							\
}


/**
 * dprint_kvec - Selective debug print for a struct kvec array
 *
 * Debug print with selectable debug categories,
 * starting with header "( pid /cpu) __func__".
 * starting with header
 *	"( pid /cpu) __func__" fmt "dprint_kvec(start)\n"
 * and ending with trailer
 *	"( pid /cpu) __func__" fmt "dprint_kvec(end)\n"
 *
 * @dbgcat	: Set of debug categories (OR-ed combination of DBG_* above),
 *		  to which this debug message is assigned.
 * TODO: Complete this ...
 *
 * @fmt		: printf compliant format string for header/trailer
 * @args	: printf compliant argument list for header/trailer
 */
#define dprint_kvec(dbgcat, vec_name, vec, num_elts, fmt, args...) {	\
	do {								\
		if ((dbgcat) & DPRINT_MASK) {				\
			printk(KERN_INFO "(%5d/%1d) %s" fmt		\
					"dprint_kvec(start)\n",		\
					current->pid,			\
					current_thread_info()->cpu,	\
					__func__, ## args);		\
			__siw_utils_kvec_print(vec_name, vec, num_elts);\
			printk(KERN_INFO "(%5d/%1d) %s" fmt		\
					"dprint_kvec(end)\n",		\
					current->pid,			\
					current_thread_info()->cpu,	\
					 __func__, ## args);		\
		}							\
	} while (0);							\
}
#endif

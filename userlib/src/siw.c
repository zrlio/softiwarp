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

#if HAVE_CONFIG_H
#  include <config.h>
#endif				/* HAVE_CONFIG_H */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <net/if.h>
#include <pthread.h>

#include "siw.h"
#include "siw_abi.h"


int rdma_db_nr = -1;
extern const int siw_debug;

static struct ibv_context_ops siw_context_ops = {
	.query_device	= siw_query_device,
	.query_port	= siw_query_port,
	.query_qp       = siw_query_qp,
	.alloc_pd	= siw_alloc_pd,
	.dealloc_pd	= siw_free_pd,
	.reg_mr		= siw_reg_mr,
	.dereg_mr	= siw_dereg_mr,
	.create_cq	= siw_create_cq,
	.resize_cq	= siw_resize_cq,
	.destroy_cq	= siw_destroy_cq,
	.create_srq	= siw_create_srq,
	.modify_srq	= siw_modify_srq,
	.destroy_srq	= siw_destroy_srq,
	.create_qp	= siw_create_qp,
	.modify_qp	= siw_modify_qp,
	.destroy_qp	= siw_destroy_qp,
	.create_ah	= siw_create_ah,
	.destroy_ah	= siw_destroy_ah,
	.attach_mcast	= NULL,
	.detach_mcast	= NULL,
	.req_notify_cq	= siw_notify_cq,
};

static struct ibv_context *siw_alloc_context(struct ibv_device *ofa_dev, int fd)
{
	struct siw_context *context;
	struct ibv_get_context cmd;
	struct siw_alloc_ucontext_resp resp;
	struct siw_device *siw_dev = dev_ofa2siw(ofa_dev);

	context = malloc(sizeof *context);

	if (!context)
		return NULL;

	context->ofa_ctx.cmd_fd = fd;

	if (ibv_cmd_get_context(&context->ofa_ctx, &cmd, sizeof cmd,
				&resp.ofa, sizeof resp)) {
		free(context);
		return NULL;
	}
	context->ofa_ctx.device = ofa_dev;
	context->ofa_ctx.ops = siw_context_ops;
	context->dev_id = resp.siw.dev_id;
	rdma_db_nr = resp.siw.rdma_db_nr;

	/*
	 * here we take the chance to put in two versions of fast path
	 * operations: private or via OFED 
	 */
	switch (siw_dev->if_type) {

	case SIW_IF_OFED:
		context->ofa_ctx.ops.async_event = siw_async_event;
		context->ofa_ctx.ops.post_send = siw_post_send_ofed;
		context->ofa_ctx.ops.post_recv = siw_post_recv_ofed;
		context->ofa_ctx.ops.post_srq_recv = siw_post_srq_recv_ofed;
		context->ofa_ctx.ops.poll_cq = siw_poll_cq_ofed;

		break;

	case SIW_IF_MAPPED:
		context->ofa_ctx.ops.async_event = siw_async_event;
		context->ofa_ctx.ops.post_send = siw_post_send_mapped;
		context->ofa_ctx.ops.post_recv = siw_post_recv_mapped;
		context->ofa_ctx.ops.post_srq_recv = siw_post_srq_recv_mapped;
		context->ofa_ctx.ops.poll_cq = siw_poll_cq_mapped;

		break;

	default:
		printf("SIW IF type %d not supported\n", siw_dev->if_type);
		free(context);
		return NULL;
	}	

	return &context->ofa_ctx;
}

static void siw_free_context(struct ibv_context *ofa_ctx)
{
	struct siw_context *ctx = ctx_ofa2siw(ofa_ctx);

	free(ctx);
}

static struct ibv_device_ops siw_dev_ops = {
	.alloc_context = siw_alloc_context,
	.free_context = siw_free_context
};

static struct ibv_device *siw_driver_init(const char *uverbs_sys_path,
					  int abi_version)
{
	char			value[IFNAMSIZ + sizeof(SIW_IBDEV_PREFIX)],
				siw_devpath[IBV_SYSFS_PATH_MAX],
				node_desc[24];
	struct siw_device	*dev;
	int			version, if_type;

        /*
         * software iwarp does not have own PCI device or
         * vendor ID, so nothing to check in that respect.
         * We just check for kernel modul code version
         * and for fast path interface type.
         */
	if (ibv_read_sysfs_file(uverbs_sys_path, "ibdev",
				value, sizeof value) < 0)
		return NULL;

	memset(siw_devpath, 0, IBV_SYSFS_PATH_MAX);

	snprintf(siw_devpath, IBV_SYSFS_PATH_MAX, "%s/class/infiniband/%s",
		 ibv_get_sysfs_path(), value);

	if (ibv_read_sysfs_file(siw_devpath, "node_desc",
				node_desc, sizeof node_desc) < 0)
		return NULL;

	if (strncmp(SIW_NODE_DESC_COMMON, node_desc, strlen(SIW_NODE_DESC_COMMON)))
		return NULL;

	if (ibv_read_sysfs_file(siw_devpath, "sw_version",
				value, sizeof value) < 0)
		return NULL;

	sscanf(value, "%i", &version); 

	if (ibv_read_sysfs_file(siw_devpath, "if_type",
				value, sizeof value) < 0)
		return NULL;

	sscanf(value, "%i", &if_type); 

	if (version != VERSION_ID_SOFTIWARP ||
	    (if_type != SIW_IF_OFED && if_type != SIW_IF_MAPPED))
		return NULL;

	dev = malloc(sizeof *dev);
	if (!dev)
		return NULL;

	pthread_spin_init(&dev->lock, PTHREAD_PROCESS_PRIVATE);
	dev->ofa_dev.ops = siw_dev_ops;
	dev->if_type = if_type;

	return &dev->ofa_dev;
}

static __attribute__((constructor)) void siw_register_driver(void)
{
	ibv_register_driver("siw", siw_driver_init);
}

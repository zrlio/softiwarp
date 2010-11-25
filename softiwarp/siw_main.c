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

#include <linux/module.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/net_namespace.h>
#include <linux/rtnetlink.h>
#include <linux/if_arp.h>

#include <rdma/ib_verbs.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_user_verbs.h>

#include "siw.h"
#include "siw_obj.h"
#include "siw_cm.h"
#include "siw_verbs.h"


MODULE_DESCRIPTION("Software iWARP Driver");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION("0.1");

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31)
static int loopback_enabled;
module_param(loopback_enabled, int, 0644);
#else
static bool loopback_enabled;
module_param(loopback_enabled, bool, 0644);
#endif
MODULE_PARM_DESC(loopback_enabled, "enable_loopback");

static LIST_HEAD(siw_devlist);

#if defined(KERNEL_VERSION_PRE_2_6_26) && (OFA_VERSION < 140)
static ssize_t show_sw_version(struct class_device *class_dev, char *buf)
{
	struct siw_dev *siw_dev = container_of(class_dev, struct siw_dev,
					       ofa_dev.class_dev);

	return sprintf(buf, "%x\n", siw_dev->attrs.version);
}

static ssize_t show_if_type(struct class_device *class_dev, char *buf)
{
	struct siw_dev *siw_dev = container_of(class_dev, struct siw_dev,
					       ofa_dev.class_dev);

	return sprintf(buf, "%d\n", siw_dev->attrs.iftype);
}
#else
static ssize_t show_sw_version(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct siw_dev *siw_dev = container_of(dev, struct siw_dev,
						 ofa_dev.dev);

	return sprintf(buf, "%x\n", siw_dev->attrs.version);
}

static ssize_t show_if_type(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	struct siw_dev *siw_dev = container_of(dev, struct siw_dev,
					       ofa_dev.dev);

	return sprintf(buf, "%d\n", siw_dev->attrs.iftype);
}
#endif

#if defined(KERNEL_VERSION_PRE_2_6_26) && (OFA_VERSION < 140)
static CLASS_DEVICE_ATTR(sw_version, S_IRUGO, show_sw_version, NULL);
static CLASS_DEVICE_ATTR(if_type, S_IRUGO, show_if_type, NULL);

static struct class_device_attribute *siw_dev_attributes[] = {
	&class_device_attr_sw_version,
	&class_device_attr_if_type
};
#else
static DEVICE_ATTR(sw_version, S_IRUGO, show_sw_version, NULL);
static DEVICE_ATTR(if_type, S_IRUGO, show_if_type, NULL);

static struct device_attribute *siw_dev_attributes[] = {
	&dev_attr_sw_version,
	&dev_attr_if_type
};
#endif

static int siw_register_device(struct siw_dev *dev)
{
	struct ib_device *ibdev = &dev->ofa_dev;
	int rv, i;

	if (dev->l2dev->type != ARPHRD_LOOPBACK)
		strlcpy(ibdev->name, "siw%d", IB_DEVICE_NAME_MAX);
	else
		strlcpy(ibdev->name, "siw_lo%d", IB_DEVICE_NAME_MAX);
	memset(&ibdev->node_guid, 0, sizeof(ibdev->node_guid));
	memcpy(&ibdev->node_guid, dev->l2dev->dev_addr, 6);

	ibdev->owner = THIS_MODULE;

	ibdev->uverbs_cmd_mask =
	    (1ull << IB_USER_VERBS_CMD_GET_CONTEXT) |
	    (1ull << IB_USER_VERBS_CMD_QUERY_DEVICE) |
	    (1ull << IB_USER_VERBS_CMD_QUERY_PORT) |
	    (1ull << IB_USER_VERBS_CMD_ALLOC_PD) |
	    (1ull << IB_USER_VERBS_CMD_DEALLOC_PD) |
	    (1ull << IB_USER_VERBS_CMD_REG_MR) |
	    (1ull << IB_USER_VERBS_CMD_DEREG_MR) |
	    (1ull << IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL) |
	    (1ull << IB_USER_VERBS_CMD_CREATE_CQ) |
	    (1ull << IB_USER_VERBS_CMD_POLL_CQ) |
	    (1ull << IB_USER_VERBS_CMD_REQ_NOTIFY_CQ) |
	    (1ull << IB_USER_VERBS_CMD_DESTROY_CQ) |
	    (1ull << IB_USER_VERBS_CMD_CREATE_QP) |
	    (1ull << IB_USER_VERBS_CMD_QUERY_QP) |
	    (1ull << IB_USER_VERBS_CMD_MODIFY_QP) |
	    (1ull << IB_USER_VERBS_CMD_DESTROY_QP) |
	    (1ull << IB_USER_VERBS_CMD_POST_SEND) |
	    (1ull << IB_USER_VERBS_CMD_POST_RECV) |
	    (1ull << IB_USER_VERBS_CMD_CREATE_SRQ) |
	    (1ull << IB_USER_VERBS_CMD_MODIFY_SRQ) |
	    (1ull << IB_USER_VERBS_CMD_QUERY_SRQ) |
	    (1ull << IB_USER_VERBS_CMD_DESTROY_SRQ) |
	    (1ull << IB_USER_VERBS_CMD_POST_SRQ_RECV);

	ibdev->node_type = RDMA_NODE_RNIC;
	memcpy(ibdev->node_desc, SIW_NODE_DESC, sizeof(SIW_NODE_DESC));

	/*
	 * Current model (one-to-one device association):
	 * One Softiwarp device per net_device or, equivalently,
	 * per physical port.
	 */
	ibdev->phys_port_cnt = 1;

	ibdev->num_comp_vectors = 1;
	/*
	 * While DMA adresses are not used a device must be provided
	 * as long as the code relies on OFA's ib_umem_get() function for
	 * memory pinning. calling ib_umem_get() includes a
	 * (for siw case useless) translation of memory to DMA
	 * adresses for that device.
	 */
	ibdev->dma_device = dev->l2dev->dev.parent;
	ibdev->query_device = siw_query_device;
	ibdev->query_port = siw_query_port;
	ibdev->query_qp = siw_query_qp;
	ibdev->modify_port = NULL;
	ibdev->query_pkey = siw_query_pkey;
	ibdev->query_gid = siw_query_gid;
	ibdev->alloc_ucontext = siw_alloc_ucontext;
	ibdev->dealloc_ucontext = siw_dealloc_ucontext;
	ibdev->mmap = siw_mmap;
	ibdev->alloc_pd = siw_alloc_pd;
	ibdev->dealloc_pd = siw_dealloc_pd;
	ibdev->create_ah = siw_create_ah;
	ibdev->destroy_ah = siw_destroy_ah;
	ibdev->create_qp = siw_create_qp;
	ibdev->modify_qp = siw_ofed_modify_qp;
	ibdev->destroy_qp = siw_destroy_qp;
	ibdev->create_cq = siw_create_cq;
	ibdev->destroy_cq = siw_destroy_cq;
	ibdev->resize_cq = NULL;
	ibdev->poll_cq = siw_poll_cq;
	ibdev->get_dma_mr = siw_get_dma_mr;
	ibdev->reg_phys_mr = NULL;
	ibdev->rereg_phys_mr = NULL;
	ibdev->reg_user_mr = siw_reg_user_mr;
	ibdev->dereg_mr = siw_dereg_mr;
	ibdev->alloc_mw = NULL;
	ibdev->bind_mw = NULL;
	ibdev->dealloc_mw = NULL;

	ibdev->create_srq = siw_create_srq;
	ibdev->modify_srq = siw_modify_srq;
	ibdev->query_srq = siw_query_srq;
	ibdev->destroy_srq = siw_destroy_srq;
	ibdev->post_srq_recv = siw_post_srq_recv;

	ibdev->attach_mcast = NULL;
	ibdev->detach_mcast = NULL;
	ibdev->process_mad = siw_no_mad;

	ibdev->req_notify_cq = siw_req_notify_cq;
	ibdev->post_send = siw_post_send;
	ibdev->post_recv = siw_post_receive;


	ibdev->iwcm = kmalloc(sizeof(struct iw_cm_verbs), GFP_KERNEL);
	if (!ibdev->iwcm)
		return -ENOMEM;

	ibdev->iwcm->connect = siw_connect;
	ibdev->iwcm->accept = siw_accept;
	ibdev->iwcm->reject = siw_reject;
	ibdev->iwcm->create_listen = siw_create_listen;
	ibdev->iwcm->destroy_listen = siw_destroy_listen;
	ibdev->iwcm->add_ref = siw_qp_get_ref;
	ibdev->iwcm->rem_ref = siw_qp_put_ref;
	ibdev->iwcm->get_qp = siw_get_ofaqp;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 34)
	rv = ib_register_device(ibdev, NULL);
#else
	rv = ib_register_device(ibdev);
#endif
	if (rv) {
		dprint(DBG_DM|DBG_ON, "(dev=%s): "
			"ib_register_device failed: rv=%d\n", ibdev->name, rv);
		return rv;
	}

	/*
	 * set and register sw version + user if type
	 */
	dev->attrs.version = VERSION_ID_SOFTIWARP;
	dev->attrs.iftype  = SIW_IF_OFED;

	dev->attrs.vendor_id = SIW_VENDOR_ID;
	dev->attrs.vendor_part_id = SIW_VENDORT_PART_ID;
	dev->attrs.sw_version = SIW_SW_VERSION;
	dev->attrs.max_qp = SIW_MAX_QP;
	dev->attrs.max_qp_wr = SIW_MAX_QP_WR;
	dev->attrs.max_ord = SIW_MAX_ORD;
	dev->attrs.max_ird = SIW_MAX_IRD;
	dev->attrs.cap_flags = 0;
	dev->attrs.max_sge = SIW_MAX_SGE;
	dev->attrs.max_sge_rd = SIW_MAX_SGE_RD;
	dev->attrs.max_cq = SIW_MAX_CQ;
	dev->attrs.max_cqe = SIW_MAX_CQE;
	dev->attrs.max_mr = SIW_MAX_MR;
	dev->attrs.max_mr_size = SIW_MAX_MR_SIZE;
	dev->attrs.max_pd = SIW_MAX_PD;
	dev->attrs.max_mw = SIW_MAX_MW;
	dev->attrs.max_fmr = SIW_MAX_FMR;
	dev->attrs.max_srq = SIW_MAX_SRQ;
	dev->attrs.max_srq_wr = SIW_MAX_SRQ_WR;
	dev->attrs.max_srq_sge = SIW_MAX_SGE;

	siw_idr_init(dev);

	atomic_set(&dev->num_srq, 0);
	atomic_set(&dev->num_qp, 0);
	atomic_set(&dev->num_cq, 0);
	atomic_set(&dev->num_mem, 0);
	atomic_set(&dev->num_pd, 0);

	for (i = 0; i < ARRAY_SIZE(siw_dev_attributes); ++i) {
#if defined(KERNEL_VERSION_PRE_2_6_26) && (OFA_VERSION < 140)
		rv = class_device_create_file(&ibdev->class_dev,
					      siw_dev_attributes[i]);
#else
		rv = device_create_file(&ibdev->dev, siw_dev_attributes[i]);
#endif
		if (rv) {
			dprint(DBG_DM|DBG_ON, "(dev=%s): "
				"device_create_file failed: i=%d, rv=%d\n",
				ibdev->name, i, rv);
			ib_unregister_device(ibdev);
			return rv;
		}
	}

	dprint(DBG_DM, ": Registered '%s' for interface '%s', "
		"HWaddr=%02x.%02x.%02x.%02x.%02x.%02x\n",
		ibdev->name, dev->l2dev->name,
		*(u8 *)dev->l2dev->dev_addr,
		*((u8 *)dev->l2dev->dev_addr + 1),
		*((u8 *)dev->l2dev->dev_addr + 2),
		*((u8 *)dev->l2dev->dev_addr + 3),
		*((u8 *)dev->l2dev->dev_addr + 4),
		*((u8 *)dev->l2dev->dev_addr + 5));
	return 0;
}

static void siw_deregister_device(struct siw_dev *dev)
{
	int i;

	siw_idr_release(dev);

	WARN_ON(atomic_read(&dev->num_srq) || atomic_read(&dev->num_qp) ||
		atomic_read(&dev->num_cq) || atomic_read(&dev->num_mem) ||
		atomic_read(&dev->num_pd));

	for (i = 0; i < ARRAY_SIZE(siw_dev_attributes); ++i)
#if defined(KERNEL_VERSION_PRE_2_6_26) && (OFA_VERSION < 140)
		class_device_remove_file(&dev->ofa_dev.class_dev,
					 siw_dev_attributes[i]);
#else
		device_remove_file(&dev->ofa_dev.dev, siw_dev_attributes[i]);
#endif

	dprint(DBG_OBJ, ": Unregister '%s' for interface '%s'\n",
		dev->ofa_dev.name, dev->l2dev->name);

	ib_unregister_device(&dev->ofa_dev);
}


/*
 * siw_init_module - Initialize Softiwarp module and create Softiwarp devices
 *
 * There are three design options for Softiwarp device management supporting
 * - multiple physical Ethernet ports, i.e., multiple net_device instances
 * - and multi-homing, i.e., multiple IP addresses associated with net_device,
 * as follows:
 *
 *    Option 1: One Softiwarp device per net_device and
 *              IP address associated with the net_device
 *    Option 2: One Softiwarp device per net_device
 *              (and all IP addresses associated with the net_device)
 *    Option 3: Single Softiwarp device for all net_device instances
 *              (and all IP addresses associated with these instances)
 *
 * We currently use Option 2, registering a separate siw_dev for
 * each net_device.
 *
 * TODO: Dynamic device management (network device registration/removal).
 *       IPv6 support.
 */
static __init int siw_init_module(void)
{
	struct net_device	*dev;
	struct siw_dev		*siw_p;
	int rv = 0;

	/*
	 * Identify all net_device instances and create a
	 * Softiwarp device for each net_device supporting IPv4
	 *
	 * TODO:
	 * - Do we have to generalize for IPv6?
	 * - Exclude devices based on IPoIB - if any
	 * - Consider excluding Ethernet devices with an
	 *   associated iWARP hardware device
	 */
	rtnl_lock();
	for_each_netdev(&init_net, dev) {
		struct in_device *in_dev;

		in_dev = in_dev_get(dev);
		if (!in_dev) {
			dprint(DBG_DM, ": Skipped %s (no in_dev)\n", dev->name);
			continue;
		}
		if (!in_dev->ifa_list) {
			dprint(DBG_DM, ": Skipped %s (no ifa)\n", dev->name);
			in_dev_put(in_dev);
			continue;
		}
		/*
		 * This device has an in_device attached. Attach to it
		 * if it is LOOPBACK or ETHER or IEEE801-TR device.
		 *
		 * Additional hardware support can be added here
		 * (e.g. ARPHRD_FDDI, ARPHRD_ATM, ...) - see
		 * <linux/if_arp.h> for type identifiers.
		 *
		 * NOTE: ARPHRD_TUNNEL/6 are excluded.
		 */
		if (dev->type == ARPHRD_ETHER ||
		    dev->type == ARPHRD_IEEE802 ||
		    (dev->type == ARPHRD_LOOPBACK && loopback_enabled)) {
#ifdef CHECK_DMA_CAPABILITIES
			if (!dev->dev.parent || !get_dma_ops(dev->dev.parent)) {
				dprint(DBG_DM|DBG_ON,
					": No DMA capabilities: %s (skipped)\n",
					dev->name);
				in_dev_put(in_dev);
				continue;
			}
#endif
			siw_p =
			      (struct siw_dev *)ib_alloc_device(sizeof *siw_p);

			if (!siw_p) {
				in_dev_put(in_dev);
				rv = -ENOMEM;
				break;
			}

			siw_p->l2dev = dev;
			list_add_tail(&siw_p->list, &siw_devlist);

			rv = siw_register_device(siw_p);
			if (rv) {
				list_del(&siw_p->list);
				in_dev_put(in_dev);
				ib_dealloc_device(&siw_p->ofa_dev);

				break;
			}
		} else {
			dprint(DBG_DM, ": Skipped %s (type %d)\n",
				dev->name, dev->type);
			in_dev_put(in_dev);
		}
	}
	rtnl_unlock();

	if (list_empty(&siw_devlist))
		return -ENODEV;

	if (rv)
		return rv;
	/*
	 * FIXME: In case of error, we leave devices allocated.
	 *        Is this correct?
	 */
	rv = siw_cm_init();
	if (rv)
		return rv;

	rv = siw_sq_worker_init();

	printk(KERN_INFO "SoftIWARP attached\n");
	return rv;
}

static void __exit siw_exit_module(void)
{
	siw_sq_worker_exit();
	siw_cm_exit();

	while (!list_empty(&siw_devlist)) {
		struct siw_dev  *siw_p =
			list_entry(siw_devlist.next, struct siw_dev, list);
		list_del(&siw_p->list);
		siw_deregister_device(siw_p);
		in_dev_put(siw_p->l2dev->ip_ptr);
		ib_dealloc_device(&siw_p->ofa_dev);
	}
	printk(KERN_INFO "SoftIWARP detached\n");
}

module_init(siw_init_module);
module_exit(siw_exit_module);

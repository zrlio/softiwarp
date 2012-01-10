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

#include <linux/init.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/net_namespace.h>
#include <linux/rtnetlink.h>
#include <linux/if_arp.h>
#include <linux/list.h>

#include <rdma/ib_verbs.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_user_verbs.h>

#include "siw.h"
#include "siw_obj.h"
#include "siw_cm.h"
#include "siw_verbs.h"


MODULE_AUTHOR("Bernard Metzler");
MODULE_DESCRIPTION("Software iWARP Driver");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION("0.1");

#define SIW_MAX_IF 12
static char *iface_list[SIW_MAX_IF];
module_param_array(iface_list, charp, NULL, 0444);
MODULE_PARM_DESC(iface_list, "Interface list siw attaches to if present");

static bool loopback_enabled = 1;
module_param(loopback_enabled, bool, 0644);
MODULE_PARM_DESC(loopback_enabled, "enable_loopback");

static LIST_HEAD(siw_devlist);
DEFINE_SPINLOCK(siw_dev_lock);


static ssize_t show_sw_version(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct siw_dev *sdev = container_of(dev, struct siw_dev, ofa_dev.dev);

	return sprintf(buf, "%x\n", sdev->attrs.version);
}

static ssize_t show_if_type(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	struct siw_dev *sdev = container_of(dev, struct siw_dev, ofa_dev.dev);

	return sprintf(buf, "%d\n", sdev->attrs.iftype);
}

static DEVICE_ATTR(sw_version, S_IRUGO, show_sw_version, NULL);
static DEVICE_ATTR(if_type, S_IRUGO, show_if_type, NULL);

static struct device_attribute *siw_dev_attributes[] = {
	&dev_attr_sw_version,
	&dev_attr_if_type
};

static int siw_modify_port(struct ib_device *ofa_dev, u8 port, int mask,
			   struct ib_port_modify *props)
{
	return -EOPNOTSUPP;
}


static void siw_device_register(struct siw_dev *sdev)
{
	struct ib_device *ofa_dev = &sdev->ofa_dev;
	int rv, i;

	rv = ib_register_device(ofa_dev, NULL);
	if (rv) {
		dprint(DBG_DM|DBG_ON, "(dev=%s): "
		       "ib_register_device failed: rv=%d\n", ofa_dev->name, rv);
		return;
	}

	for (i = 0; i < ARRAY_SIZE(siw_dev_attributes); ++i) {
		rv = device_create_file(&ofa_dev->dev, siw_dev_attributes[i]);
		if (rv) {
			dprint(DBG_DM|DBG_ON, "(dev=%s): "
				"device_create_file failed: i=%d, rv=%d\n",
				ofa_dev->name, i, rv);
			ib_unregister_device(ofa_dev);
			return;
		}
	}
	siw_debugfs_add_device(sdev);

	dprint(DBG_DM, ": Registered '%s' for interface '%s', "
		"HWaddr=%02x.%02x.%02x.%02x.%02x.%02x\n",
		ofa_dev->name, sdev->netdev->name,
		*(u8 *)sdev->netdev->dev_addr,
		*((u8 *)sdev->netdev->dev_addr + 1),
		*((u8 *)sdev->netdev->dev_addr + 2),
		*((u8 *)sdev->netdev->dev_addr + 3),
		*((u8 *)sdev->netdev->dev_addr + 4),
		*((u8 *)sdev->netdev->dev_addr + 5));

	sdev->is_registered = 1;
}

static void siw_device_deregister(struct siw_dev *sdev)
{
	int i;

	siw_debugfs_del_device(sdev);

	if (sdev->is_registered) {

		dprint(DBG_DM, ": deregister %s at %s\n", sdev->ofa_dev.name,
			sdev->netdev->name);

		for (i = 0; i < ARRAY_SIZE(siw_dev_attributes); ++i)
			device_remove_file(&sdev->ofa_dev.dev,
					   siw_dev_attributes[i]);

		ib_unregister_device(&sdev->ofa_dev);
	}
	WARN_ON(atomic_read(&sdev->num_ctx));
	WARN_ON(atomic_read(&sdev->num_srq));
	WARN_ON(atomic_read(&sdev->num_qp));
	WARN_ON(atomic_read(&sdev->num_cq));
	WARN_ON(atomic_read(&sdev->num_mem));
	WARN_ON(atomic_read(&sdev->num_pd));
	WARN_ON(atomic_read(&sdev->num_cep));

	i = 0;

	while (!list_empty(&sdev->cep_list)) {
		struct siw_cep *cep = list_entry(sdev->cep_list.next,
						 struct siw_cep, devq);
		list_del(&cep->devq);
		dprint(DBG_ON, ": Free CEP (0x%p), state: %d\n",
			cep, cep->state);
		kfree(cep);
		i++;
	}
	if (i)
		pr_warning("siw_device_deregister: free'd %d CEPs\n", i);

	sdev->is_registered = 0;
}

static void siw_device_destroy(struct siw_dev *sdev)
{
	dprint(DBG_DM, ": destroy siw device at %s\n", sdev->netdev->name);

	siw_idr_release(sdev);
	kfree(sdev->ofa_dev.iwcm);
	dev_put(sdev->netdev);
	ib_dealloc_device(&sdev->ofa_dev);
}


static int siw_match_iflist(struct net_device *dev)
{
	int i = 0, found = *iface_list ? 0 : 1;

	while (iface_list[i]) {
		if (!strcmp(iface_list[i++], dev->name)) {
			found = 1;
			break;
		}
	}
	return found;
}

static struct siw_dev *siw_dev_from_netdev(struct net_device *dev)
{
	if (!list_empty(&siw_devlist)) {
		struct list_head *pos;
		list_for_each(pos, &siw_devlist) {
			struct siw_dev *sdev =
				list_entry(pos, struct siw_dev, list);
			if (sdev->netdev == dev)
				return sdev;
		}
	}
	return NULL;
}

static int siw_dev_qualified(struct net_device *netdev)
{
	if (!siw_match_iflist(netdev)) {
		dprint(DBG_DM|DBG_ON, ": %s (not selected)\n",
			netdev->name);
		return 0;
	}
	/*
	 * Additional hardware support can be added here
	 * (e.g. ARPHRD_FDDI, ARPHRD_ATM, ...) - see
	 * <linux/if_arp.h> for type identifiers.
	 */
	if (netdev->type == ARPHRD_ETHER ||
	    netdev->type == ARPHRD_IEEE802 ||
	    (netdev->type == ARPHRD_LOOPBACK && loopback_enabled))
		return 1;

	return 0;
}

static struct siw_dev *siw_device_create(struct net_device *netdev)
{
	struct siw_dev *sdev = (struct siw_dev *)ib_alloc_device(sizeof *sdev);
	struct ib_device *ofa_dev;

	if (!sdev)
		goto out;

	ofa_dev = &sdev->ofa_dev;

	ofa_dev->iwcm = kmalloc(sizeof(struct iw_cm_verbs), GFP_KERNEL);
	if (!ofa_dev->iwcm) {
		ib_dealloc_device(ofa_dev);
		sdev = NULL;
		goto out;
	}

	sdev->netdev = netdev;
	list_add_tail(&sdev->list, &siw_devlist);

	strcpy(ofa_dev->name, "siw_");
	strlcpy(ofa_dev->name + strlen("siw_"), netdev->name,
		IB_DEVICE_NAME_MAX - strlen("siw_"));

	memset(&ofa_dev->node_guid, 0, sizeof(ofa_dev->node_guid));
	if (netdev->type != ARPHRD_LOOPBACK)
		memcpy(&ofa_dev->node_guid, netdev->dev_addr, 6);
	else {
		/*
		 * The loopback device does not have a HW address,
		 * but connection mangagement lib expects gid != 0
		 */
		size_t gidlen = min(strlen(ofa_dev->name), (size_t)6);
		memcpy(&ofa_dev->node_guid, ofa_dev->name, gidlen);
	}
	ofa_dev->owner = THIS_MODULE;

	ofa_dev->uverbs_cmd_mask =
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

	ofa_dev->node_type = RDMA_NODE_RNIC;
	memcpy(ofa_dev->node_desc, SIW_NODE_DESC, sizeof(SIW_NODE_DESC));

	/*
	 * Current model (one-to-one device association):
	 * One Softiwarp device per net_device or, equivalently,
	 * per physical port.
	 */
	ofa_dev->phys_port_cnt = 1;

	ofa_dev->num_comp_vectors = 1;
	/*
	 * While DMA adresses are not used a device must be provided
	 * as long as the code relies on OFA's ib_umem_get() function for
	 * memory pinning. calling ib_umem_get() includes a
	 * (for siw case useless) translation of memory to DMA
	 * adresses for that device.
	 */
	ofa_dev->dma_device = &siw_generic_dma_device;
	ofa_dev->query_device = siw_query_device;
	ofa_dev->query_port = siw_query_port;
	ofa_dev->query_qp = siw_query_qp;
	ofa_dev->modify_port = siw_modify_port;
	ofa_dev->query_pkey = siw_query_pkey;
	ofa_dev->query_gid = siw_query_gid;
	ofa_dev->alloc_ucontext = siw_alloc_ucontext;
	ofa_dev->dealloc_ucontext = siw_dealloc_ucontext;
	ofa_dev->mmap = siw_mmap;
	ofa_dev->alloc_pd = siw_alloc_pd;
	ofa_dev->dealloc_pd = siw_dealloc_pd;
	ofa_dev->create_ah = siw_create_ah;
	ofa_dev->destroy_ah = siw_destroy_ah;
	ofa_dev->create_qp = siw_create_qp;
	ofa_dev->modify_qp = siw_ofed_modify_qp;
	ofa_dev->destroy_qp = siw_destroy_qp;
	ofa_dev->create_cq = siw_create_cq;
	ofa_dev->destroy_cq = siw_destroy_cq;
	ofa_dev->resize_cq = NULL;
	ofa_dev->poll_cq = siw_poll_cq;
	ofa_dev->get_dma_mr = siw_get_dma_mr;
	ofa_dev->reg_phys_mr = NULL;
	ofa_dev->rereg_phys_mr = NULL;
	ofa_dev->reg_user_mr = siw_reg_user_mr;
	ofa_dev->dereg_mr = siw_dereg_mr;
	ofa_dev->alloc_mw = NULL;
	ofa_dev->bind_mw = NULL;
	ofa_dev->dealloc_mw = NULL;

	ofa_dev->create_srq = siw_create_srq;
	ofa_dev->modify_srq = siw_modify_srq;
	ofa_dev->query_srq = siw_query_srq;
	ofa_dev->destroy_srq = siw_destroy_srq;
	ofa_dev->post_srq_recv = siw_post_srq_recv;

	ofa_dev->attach_mcast = NULL;
	ofa_dev->detach_mcast = NULL;
	ofa_dev->process_mad = siw_no_mad;

	ofa_dev->req_notify_cq = siw_req_notify_cq;
	ofa_dev->post_send = siw_post_send;
	ofa_dev->post_recv = siw_post_receive;

	ofa_dev->dma_ops = &siw_dma_mapping_ops;

	ofa_dev->iwcm->connect = siw_connect;
	ofa_dev->iwcm->accept = siw_accept;
	ofa_dev->iwcm->reject = siw_reject;
	ofa_dev->iwcm->create_listen = siw_create_listen;
	ofa_dev->iwcm->destroy_listen = siw_destroy_listen;
	ofa_dev->iwcm->add_ref = siw_qp_get_ref;
	ofa_dev->iwcm->rem_ref = siw_qp_put_ref;
	ofa_dev->iwcm->get_qp = siw_get_ofaqp;
	/*
	 * set and register sw version + user if type
	 */
	sdev->attrs.version = VERSION_ID_SOFTIWARP;
	sdev->attrs.iftype  = SIW_IF_OFED;

	sdev->attrs.vendor_id = SIW_VENDOR_ID;
	sdev->attrs.vendor_part_id = SIW_VENDORT_PART_ID;
	sdev->attrs.sw_version = SIW_SW_VERSION;
	sdev->attrs.max_qp = SIW_MAX_QP;
	sdev->attrs.max_qp_wr = SIW_MAX_QP_WR;
	sdev->attrs.max_ord = SIW_MAX_ORD;
	sdev->attrs.max_ird = SIW_MAX_IRD;
	sdev->attrs.cap_flags = 0;
	sdev->attrs.max_sge = SIW_MAX_SGE;
	sdev->attrs.max_sge_rd = SIW_MAX_SGE_RD;
	sdev->attrs.max_cq = SIW_MAX_CQ;
	sdev->attrs.max_cqe = SIW_MAX_CQE;
	sdev->attrs.max_mr = SIW_MAX_MR;
	sdev->attrs.max_mr_size = rlimit(RLIMIT_MEMLOCK);
	sdev->attrs.max_pd = SIW_MAX_PD;
	sdev->attrs.max_mw = SIW_MAX_MW;
	sdev->attrs.max_fmr = SIW_MAX_FMR;
	sdev->attrs.max_srq = SIW_MAX_SRQ;
	sdev->attrs.max_srq_wr = SIW_MAX_SRQ_WR;
	sdev->attrs.max_srq_sge = SIW_MAX_SGE;

	siw_idr_init(sdev);
	INIT_LIST_HEAD(&sdev->cep_list);
	INIT_LIST_HEAD(&sdev->qp_list);

	atomic_set(&sdev->num_ctx, 0);
	atomic_set(&sdev->num_srq, 0);
	atomic_set(&sdev->num_qp, 0);
	atomic_set(&sdev->num_cq, 0);
	atomic_set(&sdev->num_mem, 0);
	atomic_set(&sdev->num_pd, 0);
	atomic_set(&sdev->num_cep, 0);

	sdev->is_registered = 0;
out:
	if (sdev)
		dev_hold(netdev);

	return sdev;
}



static int siw_netdev_event(struct notifier_block *nb, unsigned long event,
			    void *arg)
{
	struct net_device	*netdev = arg;
	struct in_device	*in_dev;
	struct siw_dev		*sdev;

	dprint(DBG_DM, " (dev=%s): Event %lu\n", netdev->name, event);

	if (dev_net(netdev) != &init_net)
		goto done;

	if (!spin_trylock(&siw_dev_lock))
		/* The module is being removed */
		goto done;

	sdev = siw_dev_from_netdev(netdev);

	switch (event) {

	case NETDEV_UP:
		if (!sdev)
			break;

		if (sdev->is_registered) {
			sdev->state = IB_PORT_ACTIVE;
			siw_port_event(sdev, 1, IB_EVENT_PORT_ACTIVE);
			break;
		}

		in_dev = in_dev_get(netdev);
		if (!in_dev) {
			dprint(DBG_DM, ": %s: no in_dev\n", netdev->name);
			sdev->state = IB_PORT_INIT;
			break;
		}

		if (in_dev->ifa_list) {
			sdev->state = IB_PORT_ACTIVE;
			siw_device_register(sdev);
		} else {
			dprint(DBG_DM, ": %s: no ifa\n", netdev->name);
			sdev->state = IB_PORT_INIT;
		}
		in_dev_put(in_dev);

		break;

	case NETDEV_DOWN:
		if (sdev && sdev->is_registered) {
			sdev->state = IB_PORT_DOWN;
			siw_port_event(sdev, 1, IB_EVENT_PORT_ERR);
			break;
		}
		break;

	case NETDEV_REGISTER:
		if (!sdev) {
			if (!siw_dev_qualified(netdev))
				break;

			sdev = siw_device_create(netdev);
			if (sdev) {
				sdev->state = IB_PORT_INIT;
				dprint(DBG_DM, ": new siw device for %s\n",
					netdev->name);
			}
		}
		break;

	case NETDEV_UNREGISTER:
		if (sdev) {
			if (sdev->is_registered)
				siw_device_deregister(sdev);
			list_del(&sdev->list);
			siw_device_destroy(sdev);
		}
		break;

	case NETDEV_CHANGEADDR:
		if (sdev->is_registered)
			siw_port_event(sdev, 1, IB_EVENT_LID_CHANGE);

		break;
	/*
	 * Todo: Below netdev events are currently not handled.
	 */
	case NETDEV_CHANGEMTU:
	case NETDEV_GOING_DOWN:
	case NETDEV_CHANGE:

		break;

	default:
		break;
	}
	spin_unlock(&siw_dev_lock);
done:
	return NOTIFY_OK;
}


static struct notifier_block siw_netdev_nb = {
	.notifier_call = siw_netdev_event,
};

/*
 * siw_init_module - Initialize Softiwarp module and register with netdev
 *                   subsystem to create Softiwarp devices per net_device
 */
static __init int siw_init_module(void)
{
	int rv;

	rv = device_register(&siw_generic_dma_device);
	if (rv)
		goto out;

	rv = siw_cm_init();
	if (rv)
		goto out_unregister;

	rv = siw_sq_worker_init();
	if (rv)
		goto out_unregister;

	siw_debug_init();

	rv = register_netdevice_notifier(&siw_netdev_nb);
	if (rv) {
		siw_debugfs_delete();
		goto out_unregister;
	}
	pr_info("SoftIWARP attached\n");

	return 0;

out_unregister:
	device_unregister(&siw_generic_dma_device);

out:
	pr_info("SoftIWARP attach failed. Error: %d\n", rv);
	siw_sq_worker_exit();
	siw_cm_exit();

	return rv;
}


static void siw_device_release(struct device *dev)
{
	pr_info("%s device released\n", dev_name(dev));
}

struct device siw_generic_dma_device = {
	.archdata.dma_ops	= &siw_dma_generic_ops,
	.init_name		= "software-rdma",
	.release		= siw_device_release
};

static void __exit siw_exit_module(void)
{
	spin_lock(&siw_dev_lock);

	unregister_netdevice_notifier(&siw_netdev_nb);

	spin_unlock(&siw_dev_lock);

	siw_sq_worker_exit();
	siw_cm_exit();

	while (!list_empty(&siw_devlist)) {
		struct siw_dev  *sdev =
			list_entry(siw_devlist.next, struct siw_dev, list);
		list_del(&sdev->list);
		if (sdev->is_registered)
			siw_device_deregister(sdev);

		siw_device_destroy(sdev);
	}
	siw_debugfs_delete();

	device_unregister(&siw_generic_dma_device);

	pr_info("SoftIWARP detached\n");
}

module_init(siw_init_module);
module_exit(siw_exit_module);

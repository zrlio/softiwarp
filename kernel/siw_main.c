/*
 * Software iWARP device driver for Linux
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

#include <linux/init.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/net_namespace.h>
#include <linux/rtnetlink.h>
#include <linux/if_arp.h>
#include <linux/list.h>
#include <linux/kernel.h>

#include <rdma/ib_verbs.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_user_verbs.h>

#include "siw.h"
#include "siw_obj.h"
#include "siw_cm.h"
#include "siw_verbs.h"
#ifdef USE_SQ_KTHREAD
#include <linux/kthread.h>
#endif


MODULE_AUTHOR("Bernard Metzler");
MODULE_DESCRIPTION("Software iWARP Driver");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION("0.2");

#define SIW_MAX_IF 12
static char *iface_list[SIW_MAX_IF];
module_param_array(iface_list, charp, NULL, 0444);
MODULE_PARM_DESC(iface_list, "Interface list siw attaches to if present");

static bool loopback_enabled = 1;
module_param(loopback_enabled, bool, 0644);
MODULE_PARM_DESC(loopback_enabled, "enable_loopback");

LIST_HEAD(siw_devlist);
DEFINE_SPINLOCK(siw_dev_lock);

#ifdef USE_SQ_KTHREAD
static char *tx_cpu_list[NR_CPUS];
module_param_array(tx_cpu_list, charp, NULL, 0444);
MODULE_PARM_DESC(tx_cpu_list, "List of CPUs siw TX thread shall be bound to");

int default_tx_cpu = -1;
static int tx_on_all_cpus = 1;
extern int siw_run_sq(void *);
struct task_struct *qp_tx_thread[NR_CPUS];
#endif

#ifdef SIW_DB_SYSCALL
extern long siw_doorbell(u32, u32, u32);
long (*db_orig_call) (u32, u32, u32);
#endif

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

static void siw_device_release(struct device *dev)
{
	pr_info("%s device released\n", dev_name(dev));
}

static struct device siw_generic_dma_device = {
	.archdata.dma_ops	= &siw_dma_generic_ops,
	.init_name		= "software-rdma-v2",
	.release		= siw_device_release
};

static struct bus_type siw_bus = {
	.name	= "siw",
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
	static int dev_id = 1;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 34) 
	rv = ib_register_device(ofa_dev, NULL);
#else
	rv = ib_register_device(ofa_dev);
#endif
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

	sdev->attrs.vendor_part_id = dev_id++;

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

#ifdef USE_SQ_KTHREAD
static int siw_tx_qualified(int cpu)
{
	int i = 0;

	if (tx_on_all_cpus)
		return 1;

	for (i = 0; i < NR_CPUS; i++) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 39) 
		if (tx_cpu_list[i] &&
		    simple_strtoull(tx_cpu_list[i], NULL, 10) == cpu)
#else
		int c;
		if (tx_cpu_list[i] && kstrtoint(tx_cpu_list[i], 0, &c) == 0 &&
		    cpu == c)
#endif
			return 1;
	}
	return 0;
}

static int siw_create_tx_threads(int max_threads, int check_qualified)
{
	int cpu, rv, assigned = 0;

	if (max_threads < 0 || max_threads > NR_CPUS)
		return 0;

	for_each_online_cpu(cpu) {
		if (check_qualified == 0 || siw_tx_qualified(cpu)) {
			qp_tx_thread[cpu] =
				kthread_create(siw_run_sq,
					(unsigned long *)(long)cpu,
					"qp_tx_thread/%d", cpu);
			kthread_bind(qp_tx_thread[cpu], cpu);
			if (IS_ERR(qp_tx_thread)) {
				rv = PTR_ERR(qp_tx_thread);
				qp_tx_thread[cpu] = NULL;
				pr_info("Binding TX thread to CPU %d failed",
					cpu);
				break;
			}
			wake_up_process(qp_tx_thread[cpu]);
			assigned++;
			if (default_tx_cpu < 0)
				default_tx_cpu = cpu;
			if (assigned >= max_threads)
				break;
		}
	}
	return assigned;
}
#endif

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
	    netdev->type == ARPHRD_INFINIBAND ||
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

	strcpy(ofa_dev->name, SIW_IBDEV_PREFIX);
	strlcpy(ofa_dev->name + strlen(SIW_IBDEV_PREFIX), netdev->name,
		IB_DEVICE_NAME_MAX - strlen(SIW_IBDEV_PREFIX));

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
	memcpy(ofa_dev->node_desc, SIW_NODE_DESC_COMMON, sizeof(SIW_NODE_DESC_COMMON));

	/*
	 * Current model (one-to-one device association):
	 * One Softiwarp device per net_device or, equivalently,
	 * per physical port.
	 */
	ofa_dev->phys_port_cnt = 1;

	ofa_dev->num_comp_vectors = 1;
	ofa_dev->dma_device = &siw_generic_dma_device;
	ofa_dev->query_device = siw_query_device;
	ofa_dev->query_port = siw_query_port;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0) || defined(IS_RH_7_2)
	ofa_dev->get_port_immutable = siw_get_port_immutable;
#endif
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
	ofa_dev->reg_user_mr = siw_reg_user_mr;
	ofa_dev->dereg_mr = siw_dereg_mr;
	ofa_dev->alloc_mw = NULL;
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
	sdev->attrs.iftype  = SIW_IF_MAPPED;

	sdev->attrs.vendor_id = SIW_VENDOR_ID;
	sdev->attrs.vendor_part_id = SIW_VENDORT_PART_ID;
	sdev->attrs.sw_version = VERSION_ID_SOFTIWARP;
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
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
	struct net_device	*netdev = arg;
#else
	struct net_device	*netdev = netdev_notifier_info_to_dev(arg);
#endif
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
#ifdef SIW_DB_SYSCALL
extern long (*doorbell_call)(u32, u32, u32);
#endif

/*
 * siw_init_module - Initialize Softiwarp module and register with netdev
 *                   subsystem to create Softiwarp devices per net_device
 */
static __init int siw_init_module(void)
{
	int rv;
#ifdef USE_SQ_KTHREAD
	int nr_cpu;
#endif

	if (SENDPAGE_THRESH < SIW_MAX_INLINE) {
		pr_info("SENDPAGE_THRESH: %d < SIW_MAX_INLINE: %d"
			" -- check SIW_MAX_SGE (%d)\n",
			(int)SENDPAGE_THRESH, (int)SIW_MAX_INLINE,
			(int)SIW_MAX_SGE);
		rv = EINVAL;
		goto out;
	}
	/*
	 * The xprtrdma module needs at least some rudimentary bus to set
	 * some devices path MTU.
	 */
	rv = bus_register(&siw_bus);
	if (rv)
		goto out_nobus;

	siw_generic_dma_device.bus = &siw_bus;

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
#ifdef SIW_DB_SYSCALL
	db_orig_call = doorbell_call;
	doorbell_call = siw_doorbell;

	pr_info("SoftiWARP: doorbell call assigned, syscall # %d\n",
		__NR_rdma_db);
#else
	pr_info("SoftiWARP: no doorbell call\n");
#endif

#ifdef USE_SQ_KTHREAD
	for (nr_cpu = 0; nr_cpu < NR_CPUS; nr_cpu++) {
		qp_tx_thread[nr_cpu] = NULL;
		if (tx_cpu_list[nr_cpu])
			tx_on_all_cpus = 0;
	}

        if (siw_create_tx_threads(NR_CPUS, 1) == 0) {
		pr_info("Try starting default TX thread\n");
		if (siw_create_tx_threads(1, 0) == 0) {
			pr_info("Could not start any TX thread\n");
			goto out_unregister;
		}
	}
#endif
	pr_info("SoftiWARP attached\n");
	return 0;

out_unregister:
#ifdef USE_SQ_KTHREAD
	for (nr_cpu = 0; nr_cpu < NR_CPUS; nr_cpu++) {
		if (qp_tx_thread[nr_cpu]) {
			kthread_stop(qp_tx_thread[nr_cpu]);
			qp_tx_thread[nr_cpu] = NULL;
		}
	}
#endif
	device_unregister(&siw_generic_dma_device);

out:
	bus_unregister(&siw_bus);
out_nobus:
	pr_info("SoftIWARP attach failed. Error: %d\n", rv);
	siw_sq_worker_exit();
	siw_cm_exit();

	return rv;
}


static void __exit siw_exit_module(void)
{
#ifdef USE_SQ_KTHREAD
	int nr_cpu;

	for (nr_cpu = 0; nr_cpu < NR_CPUS; nr_cpu++) {
		if (qp_tx_thread[nr_cpu]) {
			kthread_stop(qp_tx_thread[nr_cpu]);
			qp_tx_thread[nr_cpu] = NULL;
		}
	}
#endif

	spin_lock(&siw_dev_lock);
	unregister_netdevice_notifier(&siw_netdev_nb);
	spin_unlock(&siw_dev_lock);

	siw_sq_worker_exit();
	siw_cm_exit();

#ifdef SIW_DB_SYSCALL
	doorbell_call = db_orig_call;
#endif

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

	bus_unregister(&siw_bus);

	pr_info("SoftiWARP detached\n");
}

module_init(siw_init_module);
module_exit(siw_exit_module);

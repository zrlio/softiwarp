#if HAVE_CONFIG_H
#  include <config.h>
#endif				/* HAVE_CONFIG_H */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>

#include "siw.h"
#include "siw_abi.h"

int siw_notify_cq(struct ibv_cq *ibcq, int solicited)
{
	struct siw_cq	*cq = cq_ofa2siw(ibcq);
	int		rv;

	pthread_spin_lock(&cq->lock);
	rv = ibv_cmd_req_notify_cq(ibcq, solicited);
	pthread_spin_unlock(&cq->lock);

	return rv;
}


int siw_post_send_ofed(struct ibv_qp *ofa_qp, struct ibv_send_wr *wr,
		      struct ibv_send_wr **bad_wr)
{
	struct siw_qp	*qp = qp_ofa2siw(ofa_qp);
	int		rv;

	pthread_spin_lock(&qp->lock);
	rv = ibv_cmd_post_send(ofa_qp, wr, bad_wr);
	pthread_spin_unlock(&qp->lock);

	return rv;
}

int siw_post_recv_ofed(struct ibv_qp *ofa_qp, struct ibv_recv_wr *wr,
		      struct ibv_recv_wr **bad_wr)
{
	struct siw_qp	*qp = qp_ofa2siw(ofa_qp);
	int		rv;

	pthread_spin_lock(&qp->lock);
	rv = ibv_cmd_post_recv(ofa_qp, wr, bad_wr);
	pthread_spin_unlock(&qp->lock);

	return rv;
}

int siw_post_srq_recv_ofed(struct ibv_srq *ofa_srq, struct ibv_recv_wr *wr,
			   struct ibv_recv_wr **bad_wr)
{
	struct siw_srq	*srq = srq_ofa2siw(ofa_srq);
	int rv;

	pthread_spin_lock(&srq->lock);
	rv = ibv_cmd_post_srq_recv(ofa_srq, wr, bad_wr);
	pthread_spin_unlock(&srq->lock);

	return rv;
}

int siw_poll_cq_ofed(struct ibv_cq *ibcq, int num_entries, struct ibv_wc *wc)
{
	struct siw_cq    *cq = cq_ofa2siw(ibcq);
	int		rv;

	pthread_spin_lock(&cq->lock);
	rv = ibv_cmd_poll_cq(ibcq, num_entries, wc);
	pthread_spin_unlock(&cq->lock);

	return rv;
}


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

#include <net/sock.h>
#include <linux/tcp.h>

#include "siw.h"
#include "siw_cm.h"
#include "siw_socket.h"

/*
 * siw_sock_nodelay() - Disable Nagle algorithm
 *
 * See also fs/ocfs2/cluster/tcp.c, o2net_set_nodelay()
 */
int siw_sock_nodelay(struct socket *sock)
{
	int ret, val = 1;
	mm_segment_t oldfs;
	oldfs = get_fs();
	set_fs(KERNEL_DS);

	/*
	 * Don't use sock_setsockopt() for SOL_TCP. It doesn't check its level
	 * argument and assumes SOL_SOCKET so, say, your TCP_NODELAY will
	 * silently turn into SO_DEBUG.
	 */
	ret = sock->ops->setsockopt(sock, SOL_TCP, TCP_NODELAY,
				    (char __user *)&val, sizeof(val));
	set_fs(oldfs);
	return ret;
}

void siw_sk_save_upcalls(struct sock *sk)
{
	struct siw_cep *cep = sk_to_cep(sk);
	BUG_ON(!cep);

	write_lock_bh(&sk->sk_callback_lock);
	cep->sk_state_change = sk->sk_state_change;
	cep->sk_data_ready   = sk->sk_data_ready;
	cep->sk_write_space  = sk->sk_write_space;
	cep->sk_error_report = sk->sk_error_report;
	write_unlock_bh(&sk->sk_callback_lock);
}

void siw_sk_restore_upcalls(struct sock *sk, struct siw_cep *cep)
{
	sk->sk_state_change	= cep->sk_state_change;
	sk->sk_data_ready	= cep->sk_data_ready;
	sk->sk_write_space	= cep->sk_write_space;
	sk->sk_error_report	= cep->sk_error_report;
	sk->sk_user_data 	= NULL;
	sk->sk_no_check 	= 0;
}

void siw_socket_disassoc(struct socket *s)
{
	struct sock	*sk = s->sk;
	struct siw_cep	*cep;

	if (sk) {
		write_lock_bh(&sk->sk_callback_lock);
		cep = sk_to_cep(sk);
		if (cep) {
			siw_sk_restore_upcalls(sk, cep);
			siw_cep_put(cep);
		}
		write_unlock_bh(&sk->sk_callback_lock);
	}
}

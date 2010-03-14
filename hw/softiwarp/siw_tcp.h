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

#ifndef __SIW_TCP_H
#define __SIW_TCP_H

#include <linux/net.h>
#include <net/sock.h>
#include <net/tcp.h>
#include "siw_cm.h"
#include "siw_socket.h"

static inline int ksock_send(struct socket *s, char *buf,
			     size_t size, int flags)
{
	struct msghdr msg = {.msg_flags = flags};
	struct kvec iov   = {.iov_base = buf, .iov_len = size};

	return kernel_sendmsg(s, &msg, &iov, 1, size);
}


static inline int ksock_recv(struct socket *sock, char *buf, size_t size,
			     int flags)
{
	struct kvec iov = {buf, size};
	struct msghdr msg = {.msg_name = NULL, .msg_flags = flags};

	return kernel_recvmsg(sock, &msg, &iov, 1, size, flags);
}


static inline int siw_skb_queue_datalen(struct sk_buff_head *q)
{
	struct sk_buff	*skb;
	struct tcp_sock *tp;
	int		off,
			len;

	skb = skb_peek(q);
	if (!skb)
		return 0;

	tp = tcp_sk(skb->sk);
	len = -1;

	do {
		if (len >= 0)
			len += skb->len;
		else {
			off =  tp->copied_seq - TCP_SKB_CB(skb)->seq;
			if (off <= skb->len)
				len = skb->len - off;
		}
		skb = skb->next;

	} while (skb != (struct sk_buff *)q);

	return len > 0 ? len : 0;
}
#endif

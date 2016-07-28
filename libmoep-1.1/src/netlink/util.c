/*
 * Copyright 2013, 2014		Maurice Leclaire <leclaire@in.tum.de>
 *				Stephan M. Guenther <moepi@moepi.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * See COPYING for more details.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/handlers.h>

#include "util.h"


static int valid_handler(struct nl_msg *msg, void *arg)
{
	nlmsg_get(msg);
	*(struct nl_msg **)arg = msg;

	return NL_OK;
}

static int ack_handler(struct nl_msg *msg, void *arg)
{
	return NL_STOP;
}

int nl_wait_for_msg_and_ack(struct nl_sock *sk, struct nl_msg **msg)
{
	int err;
	struct nl_cb *orig_cb;
	struct nl_cb *cb;

	orig_cb = nl_socket_get_cb(sk);
	cb = nl_cb_clone(orig_cb);
	nl_cb_put(orig_cb);
	if (cb == NULL)
	return -NLE_NOMEM;

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, msg);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, NULL);
	err = nl_recvmsgs(sk, cb);
	if (!err)
		err = nl_recvmsgs(sk, cb);
	nl_cb_put(cb);

	return err;
}

int nl_send_recv_sync(struct nl_sock *sk, struct nl_msg **msg)
{
	int err;

	err = nl_send_auto(sk, *msg);
	nlmsg_free(*msg);
	*msg = NULL;
	if (err < 0)
		return err;

	err = nl_wait_for_msg_and_ack(sk, msg);
	if (err && *msg) {
		nlmsg_free(*msg);
		*msg = NULL;
	} else if (!err && !*msg) {
		err = -NLE_FAILURE;
	}

	return err;
}

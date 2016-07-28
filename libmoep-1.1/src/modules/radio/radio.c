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

#include <unistd.h>
#include <errno.h>

#include <linux/if_packet.h>

#include <sys/socket.h>
#include <sys/fcntl.h>

#include <net/ethernet.h>

#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/msg.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include <moep80211/types.h>
#include <moep80211/module.h>
#include <moep80211/radiotap.h>

#include <moep80211/modules/radio.h>

#include "../../interfaces.h"

#include "../../netlink/util.h"
#include "../../netlink/error.h"

#include "radiotap.h"
#include "nl80211.h"


static void *radio_create(void)
{
	struct moep80211_radiotap *hdr;

	if (!(hdr = malloc(sizeof(*hdr)))) {
		errno = ENOMEM;
		return NULL;
	}
	hdr->hdr.it_version = 0;
	hdr->hdr.it_present = 0;
	return hdr;
}

static void radio_destroy(void *hdr)
{
	free(hdr);
}


static void *radio_parse(u8 **raw, size_t *maxlen)
{
	struct moep80211_radiotap *hdr;
	size_t len;

	if (sizeof(struct ieee80211_radiotap_header) > *maxlen) {
		errno = EINVAL;
		return NULL;
	}
	if (!(hdr = radio_create()))
		return NULL;
	if (radiotap_parse(hdr, (struct ieee80211_radiotap_header *)*raw,
			   *maxlen)) {
		radio_destroy(hdr);
		return NULL;
	}
	len = le16toh(((struct ieee80211_radiotap_header *)*raw)->it_len);
	*maxlen -= len;
	*raw += len;
	return hdr;
}

static int radio_build_len(void *hdr)
{
	return radiotap_len(((struct moep80211_radiotap *)hdr)->hdr.it_present);
}

static int radio_build(void *hdr, u8 *raw, size_t maxlen)
{
	if (sizeof(struct ieee80211_radiotap_header) > maxlen) {
		errno = EINVAL;
		return -1;
	}
	if (radiotap_build((struct moep80211_radiotap *)hdr,
			   (struct ieee80211_radiotap_header *)raw, maxlen))
		return -1;
	return le16toh(((struct ieee80211_radiotap_header *)raw)->it_len);
}

struct moep_frame_ops radio_frame_ops = {
	.create		= radio_create,
	.parse		= radio_parse,
	.build_len	= radio_build_len,
	.build		= radio_build,
	.destroy	= radio_destroy,
};

moep_frame_t moep_frame_radio_create(struct moep_frame_ops *l2_ops)
{
	return moep_frame_create(&radio_frame_ops, l2_ops);
}

struct moep80211_radiotap *moep_frame_radiotap(moep_frame_t frame)
{
	return moep_frame_l1_hdr(frame, &radio_frame_ops);
}

static int get_wiphy_index(const char *name)
{
	int wiphy;

	if ((wiphy = get_number_from_file("/sys/class/ieee80211/%s/index",
					  name)) < 0 && errno == ENOENT)
		wiphy = get_number_from_file("/sys/class/net/%s/phy80211/index",
					     name);
	return wiphy;
}

static int create_monitor(struct nl_sock *sock, int family, int wiphy,
			  const char *name)
{
	struct nl_msg *msg;
	//struct nlattr *mntr_flags;
	struct nlattr *attr[NL80211_ATTR_MAX + 1];
	int ifindex;
	int err;

	if (!(msg = nlmsg_alloc())) {
		errno = ENOMEM;
		return -1;
	}

	if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family, 0, 0,
			 NL80211_CMD_NEW_INTERFACE, 0)) {
		nlmsg_free(msg);
		errno = EFAULT;
		return -1;
	}
	nla_put_u32(msg, NL80211_ATTR_WIPHY, wiphy);
	nla_put_u32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MONITOR);
	nla_put_string(msg, NL80211_ATTR_IFNAME, name);
	//mntr_flags = nla_nest_start(msg, NL80211_ATTR_MNTR_FLAGS);
	//nla_nest_end(msg, mntr_flags);

	if ((err = nl_send_recv_sync(sock, &msg)) < 0) {
		errno = nlerr2syserr(err);
		return -1;
	}
	if ((err = genlmsg_parse(nlmsg_hdr(msg), 0, attr, NL80211_ATTR_MAX,
				 (struct nla_policy *)nl80211_policy)) < 0) {
		nlmsg_free(msg);
		errno = nlerr2syserr(err);
		return -1;
	}

	if (!attr[NL80211_ATTR_IFINDEX]) {
		// TODO should not happen
	}
	ifindex = nla_get_u32(attr[NL80211_ATTR_IFINDEX]);

	nlmsg_free(msg);

	return ifindex;
}

static int set_monitor(struct nl_sock *sock, int family, int ifindex)
{
	struct nl_msg *msg;
	//struct nlattr *mntr_flags;
	int err;

	if (!(msg = nlmsg_alloc())) {
		errno = ENOMEM;
		return -1;
	}

	if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family, 0, 0,
			 NL80211_CMD_SET_INTERFACE, 0)) {
		nlmsg_free(msg);
		errno = EFAULT;
		return -1;
	}
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex);
	nla_put_u32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MONITOR);
	//mntr_flags = nla_nest_start(msg, NL80211_ATTR_MNTR_FLAGS);
	//nla_nest_end(msg, mntr_flags);

	if ((err = nl_send_sync(sock, msg)) < 0) {
		errno = nlerr2syserr(err);
		return -1;
	}

	return 0;
}

static int set_channel(struct nl_sock *sock, int family, int ifindex, u32 freq,
		       int chan_width, u32 freq1, u32 freq2)
{
	struct nl_msg *msg;
	int err;

	if (!(msg = nlmsg_alloc())) {
		errno = ENOMEM;
		return -1;
	}

	if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family, 0, 0,
			 NL80211_CMD_SET_CHANNEL, 0)) {
		errno = EFAULT;
		return -1;
	}
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex);
	nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, freq);
	nla_put_u32(msg, NL80211_ATTR_CHANNEL_WIDTH, chan_width);
	switch (chan_width) {
	case NL80211_CHAN_WIDTH_80P80:
		nla_put_u32(msg, NL80211_ATTR_CENTER_FREQ2, freq2);
	case NL80211_CHAN_WIDTH_40:
	case NL80211_CHAN_WIDTH_80:
	case NL80211_CHAN_WIDTH_160:
		nla_put_u32(msg, NL80211_ATTR_CENTER_FREQ1, freq1);
	}

	if ((err = nl_send_sync(sock, msg)) < 0) {
		errno = nlerr2syserr(err);
		return -1;
	}

	return 0;
}

static int del_iface(struct nl_sock *sock, int family, int ifindex)
{
	struct nl_msg *msg;
	int err;

	if (!(msg = nlmsg_alloc())) {
		errno = ENOMEM;
		return -1;
	}

	if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family, 0, 0,
			 NL80211_CMD_DEL_INTERFACE, 0)) {
		nlmsg_free(msg);
		errno = EFAULT;
		return -1;
	}
	nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex);

	if ((err = nl_send_sync(sock, msg)) < 0) {
		errno = nlerr2syserr(err);
		return -1;
	}

	return 0;
}

static int radio_close(int fd, void *priv)
{
	struct nl_sock *sock;
	int family;
	int ifindex;
	struct sockaddr_ll sll;
	socklen_t addrlen;
	int err;

	addrlen = sizeof(sll);
	if (getsockname(fd, (struct sockaddr *)&sll, &addrlen))
		return -1;
	if (sll.sll_family != AF_PACKET) {
		errno = EINVAL;
		return -1;
	}
	ifindex = sll.sll_ifindex;

	if (close(fd))
		return -1;

	if (!(sock = nl_socket_alloc())) {
		errno = ENOMEM;
		return -1;
	}
	if ((err = genl_connect(sock))) {
		nl_socket_free(sock);
		errno = nlerr2syserr(err);
		return -1;
	}
	if ((family = genl_ctrl_resolve(sock, NL80211_GENL_NAME)) < 0) {
		nl_socket_free(sock);
		errno = nlerr2syserr(family);
		return -1;
	}

	if (del_iface(sock, family, ifindex)) {
		err = errno;
		nl_socket_free(sock);
		errno = err;
		return -1;
	}

	nl_socket_free(sock);
	return 0;
}

static struct moep_dev_ops radio_dev_ops = {
	.close		= radio_close,
};

moep_dev_t moep_dev_radio_open(const char *devname, u32 freq,
			       enum moep80211_chan_width chan_width,
			       u32 freq1, u32 freq2, int mtu,
			       struct moep_frame_ops *l2_ops)
{
	moep_dev_t dev;
	int fd;
	struct nl_sock *sock;
	int family;
	int wiphy;
	int ifindex;
	struct sockaddr_ll sll;
	int err;

	if ((wiphy = get_wiphy_index(devname)) < 0)
		return NULL;

	if (!(sock = nl_socket_alloc())) {
		errno = ENOMEM;
		return NULL;
	}
	if ((err = genl_connect(sock))) {
		nl_socket_free(sock);
		errno = nlerr2syserr(err);
		return NULL;
	}
	if ((family = genl_ctrl_resolve(sock, NL80211_GENL_NAME)) < 0) {
		nl_socket_free(sock);
		errno = nlerr2syserr(family);
		return NULL;
	}

	if ((ifindex = create_monitor(sock, family, wiphy, "mon%d")) < 0) {
		err = errno;
		nl_socket_free(sock);
		errno = err;
		return NULL;
	}

	if (set_link(ifindex, NULL, mtu)) {
		err = errno;
		del_iface(sock, family, ifindex);
		nl_socket_free(sock);
		errno = err;
		return NULL;
	}

	if (set_channel(sock, family, ifindex, freq, chan_width, freq1, freq2)) {
		err = errno;
		del_iface(sock, family, ifindex);
		nl_socket_free(sock);
		errno = err;
		return NULL;
	}

	if ((fd = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK,
			 htons(ETH_P_ALL))) < 0) {
		err = errno;
		del_iface(sock, family, ifindex);
		nl_socket_free(sock);
		errno = err;
		return NULL;
	}

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifindex;
	if (bind(fd, (struct sockaddr *)&sll, sizeof(sll))) {
		err = errno;
		close(fd);
		del_iface(sock, family, ifindex);
		nl_socket_free(sock);
		errno = err;
		return NULL;
	}

	nl_socket_free(sock);

	if (!(dev = moep_dev_open(fd, mtu, &radio_dev_ops, NULL,
				  &radio_frame_ops, l2_ops))) {
		err = errno;
		close(fd);
		del_iface(sock, family, ifindex);
		errno = err;
		return NULL;
	}

	return dev;
}

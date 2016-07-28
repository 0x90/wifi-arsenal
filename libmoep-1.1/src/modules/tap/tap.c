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

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <netpacket/packet.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>

#include <moep80211/types.h>
#include <moep80211/module.h>

#include <moep80211/modules/tap.h>

#include "../../interfaces.h"


moep_frame_t moep_frame_tap_create(struct moep_frame_ops *l2_ops)
{
	return moep_frame_create(NULL, l2_ops);
}

struct tap_priv {
	int ifindex;
};

static int tap_close(int fd, void *priv)
{
	free(priv);
	return close(fd);
}

static struct moep_dev_ops tap_dev_ops = {
	.close		= tap_close,
};

moep_dev_t moep_dev_tap_open(u8 *addr, const struct in_addr *ip, int prefixlen,
			     int mtu, struct moep_frame_ops *l2_ops)
{
	moep_dev_t dev;
	struct tap_priv *priv;
	int fd;
	struct ifreq ifr;
	char *ifname;
	int err;

	if (!(priv = malloc(sizeof(*priv)))) {
		errno = ENOMEM;
		return NULL;
	}

	if ((fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK)) < 0) {
		free(priv);
		return NULL;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	if (ioctl(fd, TUNSETIFF, &ifr)) {
		err = errno;
		free(priv);
		close(fd);
		errno = err;
		return NULL;
	}
	ifname = ifr.ifr_name;

	if (ioctl(fd, TUNSETPERSIST, 0)) {
		err = errno;
		free(priv);
		close(fd);
		errno = err;
		return NULL;
	}

	if ((priv->ifindex = get_ifindex(ifname)) < 0) {
		err = errno;
		free(priv);
		close(fd);
		errno = err;
		return NULL;
	}

	if (set_link(priv->ifindex, addr, mtu - sizeof(struct ether_header))) {
		err = errno;
		free(priv);
		close(fd);
		errno = err;
		return NULL;
	}

	if (ip && set_ipaddr(priv->ifindex, ip, prefixlen)) {
		err = errno;
		free(priv);
		close(fd);
		errno = err;
		return NULL;
	}

	if (!(dev = moep_dev_open(fd, mtu, &tap_dev_ops, priv, NULL, l2_ops))) {
		err = errno;
		free(priv);
		close(fd);
		errno = err;
		return NULL;
	}

	return dev;
}

int moep_dev_tap_get_hwaddr(moep_dev_t dev, u8 *addr)
{
	struct tap_priv *priv;

	if (!(priv = moep_dev_get_priv(dev, &tap_dev_ops)))
		return -1;
	return get_link_addr(priv->ifindex, addr);
}

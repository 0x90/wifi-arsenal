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

#include <linux/if_packet.h>

#include <sys/socket.h>
#include <sys/fcntl.h>

#include <net/ethernet.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <linux/if.h>
#include <linux/if_ether.h>

#include <moep80211/types.h>
#include <moep80211/module.h>

#include <moep80211/modules/eth.h>

#include "../../interfaces.h"


moep_frame_t moep_frame_eth_create(struct moep_frame_ops *l2_ops)
{
	return moep_frame_create(NULL, l2_ops);
}

struct eth_priv {
	int ifindex;
};

static int eth_close(int fd, void *priv)
{
	free(priv);
	return close(fd);
}

static struct moep_dev_ops eth_dev_ops = {
	.close		= eth_close,
};

moep_dev_t moep_dev_eth_open(const char *devname, u8 *addr,
			     const struct in_addr *ip, int prefixlen, int mtu,
			     struct moep_frame_ops *l2_ops)
{
	moep_dev_t dev;
	struct eth_priv *priv;
	int fd;
	struct sockaddr_ll sll;
	int err;

	if (!(priv = malloc(sizeof(*priv)))) {
		errno = ENOMEM;
		return NULL;
	}

	if ((priv->ifindex = get_ifindex(devname)) < 0) {
		free(priv);
		return NULL;
	}

	if (set_link(priv->ifindex, addr, mtu - sizeof(struct ether_header))) {
		free(priv);
		return NULL;
	}

	if (ip && set_ipaddr(priv->ifindex, ip, prefixlen)) {
		free(priv);
		return NULL;
	}

	if ((fd = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK,
			 htons(ETH_P_ALL))) < 0) {
		free(priv);
		return NULL;
	}

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = priv->ifindex;
	if (bind(fd, (struct sockaddr *)&sll, sizeof(sll))) {
		err = errno;
		free(priv);
		close(fd);
		errno = err;
		return NULL;
	}

	if (!(dev = moep_dev_open(fd, mtu, &eth_dev_ops, priv, NULL, l2_ops))) {
		err = errno;
		free(priv);
		close(fd);
		errno = err;
		return NULL;
	}

	return dev;
}

int moep_dev_eth_get_hwaddr(moep_dev_t dev, u8 *addr)
{
	struct eth_priv *priv;

	if (!(priv = moep_dev_get_priv(dev, &eth_dev_ops)))
		return -1;
	return get_link_addr(priv->ifindex, addr);
}

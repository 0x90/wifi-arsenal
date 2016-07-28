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
#include <string.h>
#include <errno.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <linux/if_ether.h>

#include <moep80211/types.h>
#include <moep80211/module.h>

#include <moep80211/modules/ieee8023.h>
#include <moep80211/modules/eth.h>
#include <moep80211/modules/tap.h>
#include <moep80211/modules/unix.h>


static void *ieee8023_create(void)
{
	struct ether_header *hdr;

	if (!(hdr = malloc(sizeof(*hdr)))) {
		errno = ENOMEM;
		return NULL;
	}
	return hdr;
}

static void ieee8023_destroy(void *hdr)
{
	free(hdr);
}

static void *ieee8023_parse(u8 **raw, size_t *maxlen)
{
	struct ether_header *hdr;

	if (sizeof(*hdr) > *maxlen) {
		errno = EINVAL;
		return NULL;
	}
	if (!(hdr = ieee8023_create()))
		return NULL;
	memcpy(hdr, *raw, sizeof(*hdr));
	*maxlen -= sizeof(*hdr);
	*raw += sizeof(*hdr);
	return hdr;
}

static int ieee8023_build_len(void *hdr)
{
	return sizeof(struct ether_header);
}

static int ieee8023_build(void *hdr, u8 *raw, size_t maxlen)
{
	if (sizeof(struct ether_header) > maxlen) {
		errno = EMSGSIZE;
		return -1;
	}
	memcpy(raw, hdr, sizeof(struct ether_header));
	return sizeof(struct ether_header);
}

static struct moep_frame_ops ieee8023_frame_ops = {
	.create		= ieee8023_create,
	.parse		= ieee8023_parse,
	.build_len	= ieee8023_build_len,
	.build		= ieee8023_build,
	.destroy	= ieee8023_destroy,
};

moep_frame_t moep_frame_ieee8023_create()
{
	return moep_frame_eth_create(&ieee8023_frame_ops);
}

moep_frame_t moep_frame_ieee8023_tap_create()
{
	return moep_frame_tap_create(&ieee8023_frame_ops);
}

moep_frame_t moep_frame_ieee8023_unix_create()
{
	return moep_frame_unix_create(&ieee8023_frame_ops);
}

struct ether_header *moep_frame_ieee8023_hdr(moep_frame_t frame)
{
	return moep_frame_l2_hdr(frame, &ieee8023_frame_ops);
}

moep_dev_t moep_dev_ieee8023_open(const char *devname, u8 *addr,
				  const struct in_addr *ip, int prefixlen,
				  int mtu)
{
	return moep_dev_eth_open(devname, addr, ip, prefixlen, mtu,
				 &ieee8023_frame_ops);
}

moep_dev_t moep_dev_ieee8023_tap_open(u8 *addr, const struct in_addr *ip,
				      int prefixlen, int mtu)
{
	return moep_dev_tap_open(addr, ip, prefixlen, mtu, &ieee8023_frame_ops);
}

moep_dev_t moep_dev_ieee8023_unix_open(const char *devname, int mtu)
{
	return moep_dev_unix_open(devname, mtu, &ieee8023_frame_ops);
}

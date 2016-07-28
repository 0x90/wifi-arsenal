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
#include <endian.h>

#include <moep80211/types.h>
#include <moep80211/module.h>

#include <moep80211/modules/radio.h>
#include <moep80211/modules/unix.h>
#include <moep80211/modules/moep80211.h>

#include "../../moep_hdr_ext.h"


struct moep80211_hdr_pointers {
	struct moep_hdr_ext *ext[MOEP_HDR_COUNT];
	struct moep80211_hdr hdr;
};


static void *moep80211_create(void)
{
	struct moep80211_hdr_pointers *ptrs;

	if (!(ptrs = malloc(sizeof(*ptrs)))) {
		errno = ENOMEM;
		return NULL;
	}
	memset(ptrs, 0, sizeof(*ptrs));
	ptrs->hdr.disc = htole32(MOEP80211_FRAME_DISCRIMINATOR);
	return ptrs;
}

static int moep80211_hdr_is_valid(struct moep80211_hdr *hdr, int maxlen)
{
	if (sizeof(*hdr) > maxlen)
		return -1;
	if (hdr->disc != htole32(MOEP80211_FRAME_DISCRIMINATOR))
		return -1;
	return 0;
}

static void *moep80211_parse(u8 **raw, size_t *maxlen)
{
	struct moep80211_hdr_pointers *ptrs;

	if (moep80211_hdr_is_valid((struct moep80211_hdr *)*raw, *maxlen)) {
		errno = EINVAL;
		return NULL;
	}
	if (!(ptrs = moep80211_create()))
		return NULL;
	memcpy(&ptrs->hdr, *raw, sizeof(ptrs->hdr));
	*maxlen -= sizeof(ptrs->hdr);
	*raw += sizeof(ptrs->hdr);
	if (moep_hdr_ext_parse(ptrs, raw, maxlen)) {
		moep_hdr_ext_destroy(ptrs);
		return NULL;
	}
	return ptrs;
}

static int moep80211_build_len(void *ptrs)
{
	return sizeof(struct moep80211_hdr) + moep_hdr_ext_build_len(ptrs);
}

static int moep80211_build(void *ptrs, u8 *raw, size_t maxlen)
{
	int len;

	if (sizeof(struct moep80211_hdr) > maxlen) {
		errno = EMSGSIZE;
		return -1;
	}
	memcpy(raw, &((struct moep80211_hdr_pointers *)ptrs)->hdr,
	       sizeof(struct moep80211_hdr));
	maxlen -= sizeof(struct moep80211_hdr);
	raw += sizeof(struct moep80211_hdr);
	if ((len = moep_hdr_ext_build(ptrs, raw, maxlen)) < 0)
		return -1;
	return sizeof(struct moep80211_hdr) + len;
}

static struct moep_frame_ops moep80211_frame_ops = {
	.create		= moep80211_create,
	.parse		= moep80211_parse,
	.build_len	= moep80211_build_len,
	.build		= moep80211_build,
	.destroy	= moep_hdr_ext_destroy,
};

moep_frame_t moep_frame_moep80211_create()
{
	return moep_frame_radio_create(&moep80211_frame_ops);
}

moep_frame_t moep_frame_moep80211_unix_create()
{
	return moep_frame_unix_create(&moep80211_frame_ops);
}

struct moep80211_hdr *moep_frame_moep80211_hdr(moep_frame_t frame)
{
	struct moep80211_hdr_pointers *ptrs;

	if (!(ptrs = moep_frame_l2_hdr(frame, &moep80211_frame_ops)))
		return NULL;
	return &ptrs->hdr;
}

moep_dev_t moep_dev_moep80211_open(const char *devname, u32 freq,
				   enum moep80211_chan_width chan_width,
				   u32 freq1, u32 freq2, int mtu)
{
	return moep_dev_radio_open(devname, freq, chan_width, freq1, freq2,
				   mtu, &moep80211_frame_ops);
}

moep_dev_t moep_dev_moep80211_unix_open(const char *devname, int mtu)
{
	return moep_dev_unix_open(devname, mtu, &moep80211_frame_ops);
}

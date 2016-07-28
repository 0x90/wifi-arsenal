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

#include <moep80211/types.h>
#include <moep80211/module.h>
#include <moep80211/moep_hdr_ext.h>

#include "moep_hdr_ext.h"


struct moep_hdr_pointers {
	struct moep_hdr_ext *ext[MOEP_HDR_COUNT];
};


void moep_hdr_ext_destroy(void *ptrs)
{
	int i;

	for (i = 0; i < MOEP_HDR_COUNT; i++) {
		free(((struct moep_hdr_pointers *)ptrs)->ext[i]);
	}
	free(ptrs);
}

static int moep_hdr_ext_is_valid(struct moep_hdr_ext *ext, int maxlen)
{
	if (sizeof(*ext) > maxlen)
		return -1;
	if (ext->len > maxlen)
		return -1;
	return 0;
}

static int set_moep_hdr_ext(struct moep_hdr_pointers *ptrs,
			    struct moep_hdr_ext *ext)
{
	u8 type;

	type = ext->type & MOEP_HDR_MASK;
	free(ptrs->ext[type]);
	if (!(ptrs->ext[type] = malloc(ext->len))) {
		errno = ENOMEM;
		return -1;
	}
	memcpy(ptrs->ext[type], ext, ext->len);
	ptrs->ext[type]->type &= MOEP_HDR_MASK;
	return 0;
}

int moep_hdr_ext_parse(void *ptrs, u8 **raw, size_t *maxlen)
{
	u8 nexthdr;

	do {
		if (moep_hdr_ext_is_valid((struct moep_hdr_ext *)*raw,
					  *maxlen)) {
			errno = EINVAL;
			return -1;
		}
		if (set_moep_hdr_ext(ptrs, (struct moep_hdr_ext *)*raw)) {
			return -1;
		}
		nexthdr = ((struct moep_hdr_ext *)*raw)->type
			& MOEP_HDR_NEXTHDR_PRESENT;
		*maxlen -= ((struct moep_hdr_ext *)*raw)->len;
		*raw += ((struct moep_hdr_ext *)*raw)->len;
	} while (nexthdr);
	return 0;
}

int moep_hdr_ext_build_len(void *ptrs)
{
	int i;
	int len;
	struct moep_hdr_ext *ext;

	len = 0;
	for (i = 0; i < MOEP_HDR_COUNT; i++) {
		if (!(ext = ((struct moep_hdr_pointers *)ptrs)->ext[i]))
			continue;
		len += ext->len;
	}
	return len;
}

int moep_hdr_ext_build(void *ptrs, u8 *raw, size_t maxlen)
{
	int i;
	int len;
	struct moep_hdr_ext *ext, *lastext;

	len = 0;
	lastext = NULL;
	for (i = 0; i < MOEP_HDR_COUNT; i++) {
		if (!(ext = ((struct moep_hdr_pointers *)ptrs)->ext[i]))
			continue;
		if (ext->len > maxlen) {
			errno = EMSGSIZE;
			return -1;
		}
		memcpy(raw, ext, ext->len);
		((struct moep_hdr_ext *)raw)->type = i
						   | MOEP_HDR_NEXTHDR_PRESENT;
		lastext = (struct moep_hdr_ext *)raw;
		len += ext->len;
		maxlen -= ext->len;
		raw += ext->len;
	}
	if (!lastext) {
		errno = EINVAL;
		return -1;
	}
	lastext->type &= ~MOEP_HDR_NEXTHDR_PRESENT;
	return len;
}

static struct moep_frame_ops moep_hdr_ext_frame_ops = {
	.create		= NULL,
	.parse		= NULL,
	.build_len	= NULL,
	.build		= NULL,
	.destroy	= moep_hdr_ext_destroy,
};

struct moep_hdr_ext *moep_frame_moep_hdr_ext(moep_frame_t frame,
					     enum moep_hdr_type type)
{
	struct moep_hdr_pointers *ptrs;

	if (!(ptrs = moep_frame_l2_hdr(frame, &moep_hdr_ext_frame_ops)))
		return NULL;
	if (type >= MOEP_HDR_COUNT) {
		errno = EINVAL;
		return NULL;
	}
	return ptrs->ext[type];
}

struct moep_hdr_ext *moep_frame_add_moep_hdr_ext(moep_frame_t frame,
						 enum moep_hdr_type type,
						 size_t len)
{
	struct moep_hdr_pointers *ptrs;

	if (!(ptrs = moep_frame_l2_hdr(frame, &moep_hdr_ext_frame_ops)))
		return NULL;
	if (type >= MOEP_HDR_COUNT) {
		errno = EINVAL;
		return NULL;
	}
	free(ptrs->ext[type]);
	if (!(ptrs->ext[type] = malloc(len))) {
		errno = ENOMEM;
		return NULL;
	}
	ptrs->ext[type]->type = type;
	ptrs->ext[type]->len = len;
	return ptrs->ext[type];
}

struct moep_hdr_ext *moep_frame_set_moep_hdr_ext(moep_frame_t frame,
						 struct moep_hdr_ext *ext)
{
	struct moep_hdr_pointers *ptrs;

	if (!(ptrs = moep_frame_l2_hdr(frame, &moep_hdr_ext_frame_ops)))
		return NULL;
	if (!ext) {
		errno = EINVAL;
		return NULL;
	}
	if (set_moep_hdr_ext(ptrs, ext))
		return NULL;
	return ptrs->ext[ext->type & MOEP_HDR_MASK];
}

int moep_frame_del_moep_hdr_ext(moep_frame_t frame,
				enum moep_hdr_type type)
{
	struct moep_hdr_pointers *ptrs;

	if (!(ptrs = moep_frame_l2_hdr(frame, &moep_hdr_ext_frame_ops)))
		return -1;
	if (type >= MOEP_HDR_COUNT) {
		errno = EINVAL;
		return -1;
	}
	free(ptrs->ext[type]);
	ptrs->ext[type] = NULL;
	return 0;
}

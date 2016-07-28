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

#include <moep80211/frame.h>
#include <moep80211/module.h>


#define assert_module(frame_ops, ops, ret)		\
	if ((frame_ops)->destroy != (ops)->destroy) {	\
		errno = EACCES;				\
		return ret;				\
	}


struct moep_frame {
	struct moep_frame_ops l1_ops;
	struct moep_frame_ops l2_ops;
	void *l1_hdr;
	void *l2_hdr;
	u8 *payload;
	size_t payload_len;
};


moep_frame_t moep_frame_create(struct moep_frame_ops *l1_ops,
			       struct moep_frame_ops *l2_ops)
{
	moep_frame_t frame;

	if (!(frame = malloc(sizeof(*frame)))) {
		errno = ENOMEM;
		return NULL;
	}
	memset(frame, 0, sizeof(*frame));

	if (l1_ops)
		frame->l1_ops = *l1_ops;
	if (l2_ops)
		frame->l2_ops = *l2_ops;

	return frame;
}

static void clean_header(moep_frame_t frame)
{
	if (frame->l1_hdr && frame->l1_ops.destroy)
		frame->l1_ops.destroy(frame->l1_hdr);
	frame->l1_hdr = NULL;
	if (frame->l2_hdr && frame->l2_ops.destroy)
		frame->l2_ops.destroy(frame->l2_hdr);
	frame->l2_hdr = NULL;
}

static void clean_payload(moep_frame_t frame)
{
	free(frame->payload);
	frame->payload = NULL;
	frame->payload_len = 0;
}

static void clean_frame(moep_frame_t frame)
{
	clean_header(frame);
	clean_payload(frame);
}

void moep_frame_convert(moep_frame_t frame, struct moep_frame_ops *l1_ops,
			struct moep_frame_ops *l2_ops)
{
	clean_header(frame);

	if (l1_ops)
		frame->l1_ops = *l1_ops;
	if (l2_ops)
		frame->l2_ops = *l2_ops;
}

void *moep_frame_l1_hdr(moep_frame_t frame, struct moep_frame_ops *l1_ops)
{
	assert_module(&frame->l1_ops, l1_ops, NULL);

	if (!frame->l1_hdr && frame->l1_ops.create)
		frame->l1_hdr = frame->l1_ops.create();

	return frame->l1_hdr;
}

void *moep_frame_l2_hdr(moep_frame_t frame, struct moep_frame_ops *l2_ops)
{
	assert_module(&frame->l2_ops, l2_ops, NULL);

	if (!frame->l2_hdr && frame->l2_ops.create)
		frame->l2_hdr = frame->l2_ops.create();

	return frame->l2_hdr;
}

u8 *moep_frame_get_payload(moep_frame_t frame, size_t *len)
{
	*len = frame->payload_len;
	return frame->payload;
}

u8 *moep_frame_set_payload(moep_frame_t frame, u8 *payload, size_t len)
{
	clean_payload(frame);

	if (!payload)
		return NULL;

	if (!(frame->payload = malloc(len))) {
		errno = ENOMEM;
		return NULL;
	}
	memcpy(frame->payload, payload, len);
	frame->payload_len = len;

	return frame->payload;
}

u8 *moep_frame_adjust_payload_len(moep_frame_t frame, size_t len)
{
	u8 *new;

	if (!len) {
		clean_payload(frame);
		return NULL;
	}
	if (!(new = realloc(frame->payload, len))) {
		errno = ENOMEM;
		return NULL;
	}
	frame->payload = new;
	frame->payload_len = len;

	return frame->payload;
}

int moep_frame_decode(moep_frame_t frame, u8 *buf, size_t buflen)
{
	clean_frame(frame);

	if (frame->l1_ops.parse) {
		if (!(frame->l1_hdr = frame->l1_ops.parse(&buf, &buflen)))
			return -1;
	}
	if (frame->l2_ops.parse) {
		if (!(frame->l2_hdr = frame->l2_ops.parse(&buf, &buflen)))
			return -1;
	}
	if (!moep_frame_set_payload(frame, buf, buflen))
		return -1;

	return 0;
}

int moep_frame_encode(moep_frame_t frame, u8 **buf, size_t buflen)
{
	u8 *data;
	int len;
	int internal;
	int ret;

	len = 0;
	if (frame->l1_ops.build_len) {
		if ((ret = frame->l1_ops.build_len(frame->l1_hdr)) < 0)
			return -1;
		len += ret;
	}
	if (frame->l2_ops.build_len) {
		if ((ret = frame->l2_ops.build_len(frame->l2_hdr)) < 0)
			return -1;
		len += ret;
	}
	len += frame->payload_len;

	if (!buf)
		return len;

	internal = 0;
	if (!*buf) {
		if (buflen && len > buflen) {
			errno = EMSGSIZE;
			return -1;
		}
		if (!(*buf = malloc(len))) {
			errno = ENOMEM;
			return -1;
		}
		internal = 1;
	} else if (len > buflen) {
		errno = EMSGSIZE;
		return -1;
	}

	data = *buf;
	if (frame->l1_ops.build) {
		if ((ret = frame->l1_ops.build(frame->l1_hdr, data, len)) < 0) {
			if (internal) {
				free(*buf);
				*buf = NULL;
			}
			return -1;
		}
		len -= ret;
		data += ret;
	}
	if (frame->l2_ops.build) {
		if ((ret = frame->l2_ops.build(frame->l2_hdr, data, len)) < 0) {
			if (internal) {
				free(*buf);
				*buf = NULL;
			}
			return -1;
		}
		len -= ret;
		data += ret;
	}
	if (len < frame->payload_len) {
		if (internal) {
			free(*buf);
			*buf = NULL;
		}
		errno = EMSGSIZE;
		return -1;
	}
	memcpy(data, frame->payload, frame->payload_len);
	len -= frame->payload_len;
	data += frame->payload_len;

	return data - *buf;
}

void moep_frame_destroy(moep_frame_t frame)
{
	clean_frame(frame);
	free(frame);
}

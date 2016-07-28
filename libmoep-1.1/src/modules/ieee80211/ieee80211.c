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

#include <malloc.h>
#include <string.h>
#include <errno.h>

#include <moep80211/types.h>
#include <moep80211/module.h>
#include <moep80211/ieee80211_frametypes.h>

#include <moep80211/modules/ieee80211.h>
#include <moep80211/modules/radio.h>


#define DEREF_AND_INC_PTR(type, ptr)	(*((*(type **)&(ptr))++))

#define DEREF_AND_CHANGE(type, ptr, maxlen)	(*({	\
		maxlen -= sizeof(type);			\
		((*(type **)&(ptr))++);			\
	}))

#define COPY_AND_CHANGE_SRC(dst, src, maxlen)	({	\
		memcpy(dst, src, sizeof(dst));		\
		maxlen -= sizeof(dst);			\
		src += sizeof(dst);			\
	})

#define COPY_AND_CHANGE_DST(dst, src, malen)	({	\
		memcpy(dst, src, sizeof(src));		\
		maxlen -= sizeof(src);			\
		dst += sizeof(src);			\
	})


static void *ieee80211_create(void)
{
	struct ieee80211_hdr_gen *hdr;

	if (!(hdr = malloc(sizeof(*hdr)))) {
		errno = ENOMEM;
		return NULL;
	}
	return hdr;
}

static void ieee80211_destroy(void *hdr)
{
	free(hdr);
}

static void *ieee80211_parse(u8 **raw, size_t *maxlen)
{
	struct ieee80211_hdr_gen *hdr;

	if (sizeof(hdr->frame_control) + sizeof(hdr->duration_id) +
	    sizeof(hdr->addr1) > *maxlen) {
		errno = EINVAL;
		return NULL;
	}
	if (!(hdr = ieee80211_create()))
		return NULL;
	hdr->frame_control = DEREF_AND_CHANGE(typeof(hdr->frame_control), *raw,
					      *maxlen);
	hdr->duration_id = DEREF_AND_CHANGE(typeof(hdr->duration_id), *raw,
					    *maxlen);
	COPY_AND_CHANGE_SRC(hdr->addr1, *raw, *maxlen);
	if (ieee80211_is_mgmt(hdr->frame_control)) {
		if (sizeof(hdr->addr2) + sizeof(hdr->addr3) +
		    sizeof(hdr->seq_ctrl) > *maxlen) {
			ieee80211_destroy(hdr);
			errno = EINVAL;
			return NULL;
		}
		COPY_AND_CHANGE_SRC(hdr->addr2, *raw, *maxlen);
		COPY_AND_CHANGE_SRC(hdr->addr3, *raw, *maxlen);
		hdr->seq_ctrl = DEREF_AND_CHANGE(typeof(hdr->seq_ctrl), *raw,
						 *maxlen);
		if (ieee80211_has_order(hdr->frame_control)) {
			if (sizeof(hdr->ht_ctrl) > *maxlen) {
				ieee80211_destroy(hdr);
				errno = EINVAL;
				return NULL;
			}
			hdr->ht_ctrl = DEREF_AND_CHANGE(typeof(hdr->ht_ctrl),
							*raw, *maxlen);
		}
	} else if (ieee80211_is_data(hdr->frame_control)) {
		if (sizeof(hdr->addr2) + sizeof(hdr->addr3) +
		    sizeof(hdr->seq_ctrl) > *maxlen) {
			ieee80211_destroy(hdr);
			errno = EINVAL;
			return NULL;
		}
		COPY_AND_CHANGE_SRC(hdr->addr2, *raw, *maxlen);
		COPY_AND_CHANGE_SRC(hdr->addr3, *raw, *maxlen);
		hdr->seq_ctrl = DEREF_AND_CHANGE(typeof(hdr->seq_ctrl), *raw,
						 *maxlen);
		if (ieee80211_has_a4(hdr->frame_control)) {
			if (sizeof(hdr->addr4) > *maxlen) {
				ieee80211_destroy(hdr);
				errno = EINVAL;
				return NULL;
			}
			COPY_AND_CHANGE_SRC(hdr->addr4, *raw, *maxlen);
		}
		if (ieee80211_is_data_qos(hdr->frame_control)) {
			if (sizeof(hdr->qos_ctrl) > *maxlen) {
				ieee80211_destroy(hdr);
				errno = EINVAL;
				return NULL;
			}
			hdr->qos_ctrl = DEREF_AND_CHANGE(typeof(hdr->qos_ctrl),
							 *raw, *maxlen);
			if (ieee80211_has_order(hdr->frame_control)) {
				if (sizeof(hdr->ht_ctrl) > *maxlen) {
					ieee80211_destroy(hdr);
					errno = EINVAL;
					return NULL;
				}
				hdr->ht_ctrl =
					DEREF_AND_CHANGE(typeof(hdr->ht_ctrl),
							 *raw, *maxlen);
			}
		}
	} else {
		ieee80211_destroy(hdr);
		errno = EINVAL;
		return NULL;
	}
	return hdr;
}

static int ieee80211_build_len(void *vhdr)
{
	struct ieee80211_hdr_gen *hdr = vhdr;
	int len;

	len = sizeof(hdr->frame_control);
	len += sizeof(hdr->duration_id);
	len += sizeof(hdr->addr1);

	if (ieee80211_is_mgmt(hdr->frame_control)) {
		len += sizeof(hdr->addr2);
		len += sizeof(hdr->addr3);
		len += sizeof(hdr->seq_ctrl);
		if (ieee80211_has_order(hdr->frame_control)) {
			len += sizeof(hdr->ht_ctrl);
		}
	} else if (ieee80211_is_data(hdr->frame_control)) {
		len += sizeof(hdr->addr2);
		len += sizeof(hdr->addr3);
		len += sizeof(hdr->seq_ctrl);
		if (ieee80211_has_a4(hdr->frame_control)) {
			len += sizeof(hdr->addr4);
		}
		if (ieee80211_is_data_qos(hdr->frame_control)) {
			len += sizeof(hdr->qos_ctrl);
			if (ieee80211_has_order(hdr->frame_control)) {
				len += sizeof(hdr->ht_ctrl);
			}
		}
	} else {
		errno = EINVAL;
		return -1;
	}
	return len;
}

static int ieee80211_build(void *vhdr, u8 *raw, size_t maxlen)
{
	struct ieee80211_hdr_gen *hdr = vhdr;
	int len;

	if (sizeof(hdr->frame_control) + sizeof(hdr->duration_id) +
	    sizeof(hdr->addr1) > maxlen) {
		errno = EMSGSIZE;
		return -1;
	}
	DEREF_AND_CHANGE(typeof(hdr->frame_control), raw, maxlen) =
							hdr->frame_control;
	len = sizeof(hdr->frame_control);
	DEREF_AND_CHANGE(typeof(hdr->duration_id), raw, maxlen) =
							hdr->duration_id;
	len += sizeof(hdr->duration_id);
	COPY_AND_CHANGE_DST(raw, hdr->addr1, maxlen);
	len += sizeof(hdr->addr1);
	if (ieee80211_is_mgmt(hdr->frame_control)) {
		if (sizeof(hdr->addr2) + sizeof(hdr->addr3) +
		    sizeof(hdr->seq_ctrl) > maxlen) {
			errno = EMSGSIZE;
			return -1;
		}
		COPY_AND_CHANGE_DST(raw, hdr->addr2, maxlen);
		len += sizeof(hdr->addr2);
		COPY_AND_CHANGE_DST(raw, hdr->addr3, maxlen);
		len += sizeof(hdr->addr3);
		DEREF_AND_CHANGE(typeof(hdr->seq_ctrl), raw, maxlen) =
								hdr->seq_ctrl;
		len += sizeof(hdr->seq_ctrl);
		if (ieee80211_has_order(hdr->frame_control)) {
			if (sizeof(hdr->ht_ctrl) > maxlen) {
				errno = EMSGSIZE;
				return -1;
			}
			DEREF_AND_CHANGE(typeof(hdr->ht_ctrl), raw, maxlen) =
								hdr->ht_ctrl;
			len += sizeof(hdr->ht_ctrl);
		}
	} else if (ieee80211_is_data(hdr->frame_control)) {
		if (sizeof(hdr->addr2) + sizeof(hdr->addr3) +
		    sizeof(hdr->seq_ctrl) > maxlen) {
			errno = EMSGSIZE;
			return -1;
		}
		COPY_AND_CHANGE_DST(raw, hdr->addr2, maxlen);
		len += sizeof(hdr->addr2);
		COPY_AND_CHANGE_DST(raw, hdr->addr3, maxlen);
		len += sizeof(hdr->addr3);
		DEREF_AND_CHANGE(typeof(hdr->seq_ctrl), raw, maxlen) =
								hdr->seq_ctrl;
		len += sizeof(hdr->seq_ctrl);
		if (ieee80211_has_a4(hdr->frame_control)) {
			if (sizeof(hdr->addr4) > maxlen) {
				errno = EMSGSIZE;
				return -1;
			}
			COPY_AND_CHANGE_DST(raw, hdr->addr4, maxlen);
			len += sizeof(hdr->addr4);
		}
		if (ieee80211_is_data_qos(hdr->frame_control)) {
			if (sizeof(hdr->qos_ctrl) > maxlen) {
				errno = EMSGSIZE;
				return -1;
			}
			DEREF_AND_CHANGE(typeof(hdr->qos_ctrl), raw, maxlen) =
								hdr->qos_ctrl;
			len += sizeof(hdr->qos_ctrl);
			if (ieee80211_has_order(hdr->frame_control)) {
				if (sizeof(hdr->ht_ctrl) > maxlen) {
					errno = EMSGSIZE;
					return -1;
				}
				DEREF_AND_CHANGE(typeof(hdr->ht_ctrl), raw,
						 maxlen) = hdr->ht_ctrl;
				len += sizeof(hdr->ht_ctrl);
			}
		}
	} else {
		errno = EINVAL;
		return -1;
	}
	return len;
}

static struct moep_frame_ops ieee80211_frame_ops = {
	.create		= ieee80211_create,
	.parse		= ieee80211_parse,
	.build_len	= ieee80211_build_len,
	.build		= ieee80211_build,
	.destroy	= ieee80211_destroy,
};

moep_frame_t moep_frame_ieee80211_create()
{
	return moep_frame_radio_create(&ieee80211_frame_ops);
}

struct ieee80211_hdr_gen *moep_frame_ieee80211_hdr(moep_frame_t frame)
{
	return moep_frame_l2_hdr(frame, &ieee80211_frame_ops);
}

moep_dev_t moep_dev_ieee80211_open(const char *devname, u32 freq,
				   enum moep80211_chan_width chan_width,
				   u32 freq1, u32 freq2, int mtu)
{
	return moep_dev_radio_open(devname, freq, chan_width, freq1, freq2, mtu,
				   &ieee80211_frame_ops);
}

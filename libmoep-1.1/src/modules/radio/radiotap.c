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

#include <moep80211/radiotap.h>
#include <moep80211/types.h>

#include "../../util.h"

#include "radiotap_parser.h"
#include "radiotap.h"


u16 radiotap_len(u32 present)
{
	int i;
	u16 len;

	len = sizeof(struct ieee80211_radiotap_header);
	for (i = 0; i < radiotap_ns.n_bits; i++) {
		if (present & 1) {
			len += radiotap_ns.align_size[i].align - 1;
			len -= len % radiotap_ns.align_size[i].align;
			len += radiotap_ns.align_size[i].size;
		}
		present >>= 1;
	}

	return len;
}

int radiotap_parse(struct moep80211_radiotap *moep_hdr,
		   struct ieee80211_radiotap_header *ieee_hdr, int len)
{
	struct ieee80211_radiotap_iterator it;
	int err;

	if ((err = ieee80211_radiotap_iterator_init(&it, ieee_hdr, len, NULL))) {
		errno = -err;
		return -1;
	}

	while (!(err = ieee80211_radiotap_iterator_next(&it))) {
		switch (it.this_arg_index) {
		case IEEE80211_RADIOTAP_TSFT:
			moep_hdr->mactime = le64toh(*(u64 *)it.this_arg);
			break;
		case IEEE80211_RADIOTAP_FLAGS:
			moep_hdr->flags = *(u8 *)it.this_arg;
			break;
		case IEEE80211_RADIOTAP_RATE:
			moep_hdr->rate = *(u8 *)it.this_arg;
			break;
		case IEEE80211_RADIOTAP_CHANNEL:
			moep_hdr->channel.frequency =
				le16toh(*(u16 *)it.this_arg);
			moep_hdr->channel.flags =
				le16toh(*(u16 *)(it.this_arg + 2));
			break;
		case IEEE80211_RADIOTAP_FHSS:
			moep_hdr->fhss.hop_set = *(u8 *)it.this_arg;
			moep_hdr->fhss.hop_pattern = *(u8 *)(it.this_arg + 1);
			break;
		case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
			moep_hdr->signal = *(s8 *)it.this_arg;
			break;
		case IEEE80211_RADIOTAP_DBM_ANTNOISE:
			moep_hdr->noise = *(s8 *)it.this_arg;
			break;
		case IEEE80211_RADIOTAP_LOCK_QUALITY:
			moep_hdr->lock_quality = le16toh(*(u16 *)it.this_arg);
			break;
		case IEEE80211_RADIOTAP_TX_ATTENUATION:
			moep_hdr->tx_attenuation = le16toh(*(u16 *)it.this_arg);
			break;
		case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
			moep_hdr->tx_attenuation_dB =
				le16toh(*(u16 *)it.this_arg);
			break;
		case IEEE80211_RADIOTAP_DBM_TX_POWER:
			moep_hdr->tx_power = *(s8 *)it.this_arg;
			break;
		case IEEE80211_RADIOTAP_ANTENNA:
			moep_hdr->antenna = *(u8 *)it.this_arg;
			break;
		case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
			moep_hdr->signal_dB = *(u8 *)it.this_arg;
			break;
		case IEEE80211_RADIOTAP_DB_ANTNOISE:
			moep_hdr->noise_dB = *(u8 *)it.this_arg;
			break;
		case IEEE80211_RADIOTAP_RX_FLAGS:
			moep_hdr->rx_flags = le16toh(*(u16 *)it.this_arg);
			break;
		case IEEE80211_RADIOTAP_TX_FLAGS:
			moep_hdr->tx_flags = le16toh(*(u16 *)it.this_arg);
			break;
		case IEEE80211_RADIOTAP_RTS_RETRIES:
			moep_hdr->rts_retries = *(u8 *)it.this_arg;
			break;
		case IEEE80211_RADIOTAP_DATA_RETRIES:
			moep_hdr->data_retries = *(u8 *)it.this_arg;
			break;
		case IEEE80211_RADIOTAP_MCS:
			moep_hdr->mcs.known = *(u8 *)it.this_arg;
			moep_hdr->mcs.flags = *(u8 *)(it.this_arg + 1);
			moep_hdr->mcs.mcs = *(u8 *)(it.this_arg + 2);
			break;
		case IEEE80211_RADIOTAP_AMPDU_STATUS:
			moep_hdr->ampdu.reference =
				le32toh(*(u32 *)it.this_arg);
			moep_hdr->ampdu.flags =
				le16toh(*(u16 *)(it.this_arg + 4));
			moep_hdr->ampdu.crc = *(u8 *)(it.this_arg + 6);
			moep_hdr->ampdu.reserved = *(u8 *)(it.this_arg + 7);
			break;
		case IEEE80211_RADIOTAP_VHT:
			moep_hdr->vht.known = le16toh(*(u16 *)it.this_arg);
			moep_hdr->vht.flags = *(u8 *)(it.this_arg + 2);
			moep_hdr->vht.bandwidth = *(u8 *)(it.this_arg + 3);
			memcpy(moep_hdr->vht.mcs_nss, it.this_arg + 4, 4);
			moep_hdr->vht.coding = *(u8 *)(it.this_arg + 8);
			moep_hdr->vht.group_id = *(u8 *)(it.this_arg + 9);
			moep_hdr->vht.partial_aid =
				le16toh(*(u16 *)(it.this_arg + 10));
			break;
		default:
			break;
		}
	}
	if (err != -ENOENT) {
		errno = -err;
		return -1;
	}

	moep_hdr->hdr.it_version = ieee_hdr->it_version;
	moep_hdr->hdr.it_len = le16toh(ieee_hdr->it_len);
	moep_hdr->hdr.it_present = le32toh(ieee_hdr->it_present) &
				   BIT_MASK(radiotap_ns.n_bits);
	return 0;
}

int radiotap_build(struct moep80211_radiotap *moep_hdr,
		   struct ieee80211_radiotap_header *ieee_hdr, int len)
{
	struct ieee80211_radiotap_iterator it;
	int err;

	ieee_hdr->it_version = moep_hdr->hdr.it_version;
	ieee_hdr->it_len = htole16(radiotap_len(moep_hdr->hdr.it_present));
	ieee_hdr->it_present = htole32(moep_hdr->hdr.it_present &
				       BIT_MASK(radiotap_ns.n_bits));

	if ((err = ieee80211_radiotap_iterator_init(&it, ieee_hdr, len, NULL))) {
		errno = -err;
		return -1;
	}

	while (!(err = ieee80211_radiotap_iterator_next(&it))) {
		switch (it.this_arg_index) {
		case IEEE80211_RADIOTAP_TSFT:
			*(u64 *)it.this_arg = htole64(moep_hdr->mactime);
			break;
		case IEEE80211_RADIOTAP_FLAGS:
			*(u8 *)it.this_arg = moep_hdr->flags;
			break;
		case IEEE80211_RADIOTAP_RATE:
			*(u8 *)it.this_arg = moep_hdr->rate;
			break;
		case IEEE80211_RADIOTAP_CHANNEL:
			*(u16 *)it.this_arg =
				htole16(moep_hdr->channel.frequency);
			*(u16 *)(it.this_arg + 2) =
				htole16(moep_hdr->channel.flags);
			break;
		case IEEE80211_RADIOTAP_FHSS:
			*(u8 *)it.this_arg = moep_hdr->fhss.hop_set;
			*(u8 *)(it.this_arg + 1) = moep_hdr->fhss.hop_pattern;
			break;
		case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
			*(s8 *)it.this_arg = moep_hdr->signal;
			break;
		case IEEE80211_RADIOTAP_DBM_ANTNOISE:
			*(s8 *)it.this_arg = moep_hdr->noise;
			break;
		case IEEE80211_RADIOTAP_LOCK_QUALITY:
			*(u16 *)it.this_arg = htole16(moep_hdr->lock_quality);
			break;
		case IEEE80211_RADIOTAP_TX_ATTENUATION:
			*(u16 *)it.this_arg = htole16(moep_hdr->tx_attenuation);
			break;
		case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
			*(u16 *)it.this_arg =
				htole16(moep_hdr->tx_attenuation_dB);
			break;
		case IEEE80211_RADIOTAP_DBM_TX_POWER:
			*(s8 *)it.this_arg = moep_hdr->tx_power;
			break;
		case IEEE80211_RADIOTAP_ANTENNA:
			*(u8 *)it.this_arg = moep_hdr->antenna;
			break;
		case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
			*(u8 *)it.this_arg = moep_hdr->signal_dB;
			break;
		case IEEE80211_RADIOTAP_DB_ANTNOISE:
			*(u8 *)it.this_arg = moep_hdr->noise_dB;
			break;
		case IEEE80211_RADIOTAP_RX_FLAGS:
			*(u16 *)it.this_arg = htole16(moep_hdr->rx_flags);
			break;
		case IEEE80211_RADIOTAP_TX_FLAGS:
			*(u16 *)it.this_arg = htole16(moep_hdr->tx_flags);
			break;
		case IEEE80211_RADIOTAP_RTS_RETRIES:
			*(u8 *)it.this_arg = moep_hdr->rts_retries;
			break;
		case IEEE80211_RADIOTAP_DATA_RETRIES:
			*(u8 *)it.this_arg = moep_hdr->data_retries;
			break;
		case IEEE80211_RADIOTAP_MCS:
			*(u8 *)it.this_arg = moep_hdr->mcs.known;
			*(u8 *)(it.this_arg + 1) = moep_hdr->mcs.flags;
			*(u8 *)(it.this_arg + 2) = moep_hdr->mcs.mcs;
			break;
		case IEEE80211_RADIOTAP_AMPDU_STATUS:
			*(u32 *)it.this_arg =
				htole32(moep_hdr->ampdu.reference);
			*(u16 *)(it.this_arg + 4) =
				htole16(moep_hdr->ampdu.flags);
			*(u8 *)(it.this_arg + 6) = moep_hdr->ampdu.crc;
			*(u8 *)(it.this_arg + 7) = moep_hdr->ampdu.reserved;
		case IEEE80211_RADIOTAP_VHT:
			*(u16 *)it.this_arg = htole16(moep_hdr->vht.known);
			*(u8 *)(it.this_arg + 2) = moep_hdr->vht.flags;
			*(u8 *)(it.this_arg + 3) = moep_hdr->vht.bandwidth;
			memcpy(it.this_arg + 4, moep_hdr->vht.mcs_nss, 4);
			*(u8 *)(it.this_arg + 8) = moep_hdr->vht.coding;
			*(u8 *)(it.this_arg + 9) = moep_hdr->vht.group_id;
			*(u16 *)(it.this_arg + 10) =
				htole16(moep_hdr->vht.partial_aid);
		default:
			break;
		}
	}
	if (err != -ENOENT) {
		errno = -err;
		return -1;
	}

	return 0;
}

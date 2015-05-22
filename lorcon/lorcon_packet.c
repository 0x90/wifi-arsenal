/*
    This file is part of lorcon

    lorcon is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    lorcon is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with lorcon; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

    Copyright (c) 2005 dragorn and Joshua Wright
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <pcap.h>

#include "lorcon.h"
#include "lorcon_packet.h"
#include "lorcon_endian.h"
#include "lorcon_packasm.h"
#include "lorcon_forge.h"
#include "lorcon_int.h"
#include "ieee80211.h"

/* for DLT_PRISM_HEADER */
#define WLAN_DEVNAMELEN_MAX	16

/* Define linktype headers if we don't have them in our includes for some
 * reason */
#ifndef DLT_IEEE802_11
#define DLT_IEEE802_11			105
#endif

#ifndef DLT_PRISM_HEADER
#define DLT_PRISM_HEADER		119
#endif

#ifndef DLT_IEEE802_11_RADIO	
#define DLT_IEEE802_11_RADIO 	127
#endif

#ifndef DLT_IEEE802_11_RADIO_AVS
#define DLT_IEEE802_11_RADIO_AVS 163
#endif

#ifndef DLT_PPI
#define DLT_PPI					192 /* cace PPI */
#endif

#ifndef IEEE80211_RADIOTAP_F_FCS
#define IEEE80211_RADIOTAP_F_FCS        0x10    /* frame includes FCS */
#endif

#ifndef IEEE80211_IOC_CHANNEL
#define IEEE80211_IOC_CHANNEL 0
#endif

/* Older wlan-ng headers */
typedef struct {
	uint32_t did;
	uint16_t status;
	uint16_t len;
	uint32_t data;
} __attribute__((__packed__)) p80211item_uint32_t;

typedef struct {
	uint32_t msgcode;
	uint32_t msglen;
	uint8_t devname[WLAN_DEVNAMELEN_MAX];
	p80211item_uint32_t hosttime;
	p80211item_uint32_t mactime;
	p80211item_uint32_t channel;
	p80211item_uint32_t rssi;
	p80211item_uint32_t sq;
	p80211item_uint32_t signal;
	p80211item_uint32_t noise;
	p80211item_uint32_t rate;
	p80211item_uint32_t istx;
	p80211item_uint32_t frmlen;
} __attribute__((__packed__)) wlan_ng_prism2_header;

/* Wlan-ng AVS headers */
typedef struct {
	uint32_t version;
	uint32_t length;
	uint64_t mactime;
	uint64_t hosttime;
	uint32_t phytype;
	uint32_t channel;
	uint32_t datarate;
	uint32_t antenna;
	uint32_t priority;
	uint32_t ssi_type;
	int32_t ssi_signal;
	int32_t ssi_noise;
	uint32_t preamble;
	uint32_t encoding;
} __attribute__((__packed__)) avs_80211_1_header;

/* CACE PPI headers */
typedef struct {
	uint8_t pph_version;
	uint8_t pph_flags;
	uint16_t pph_len;
	uint32_t pph_dlt;
} __attribute__((__packed__)) ppi_packet_header;

#define PPI_PH_FLAG_ALIGNED		2

typedef struct {
	uint16_t pfh_datatype;
	uint16_t pfh_datalen;
} __attribute__((__packed__)) ppi_field_header;

#define PPI_FIELD_11COMMON		2
#define PPI_FIELD_11NMAC		3
#define PPI_FIELD_11NMACPHY		4
#define PPI_FIELD_SPECMAP		5
#define PPI_FIELD_PROCINFO		6
#define PPI_FIELD_CAPINFO		7

/* The radio capture header precedes the 802.11 header. */
typedef struct {
	u_int8_t it_version;
	u_int8_t it_pad;
	u_int16_t it_len;
	u_int32_t it_present;
} __attribute__((__packed__)) radiotap_header;

enum lorcon_radiotap_type {
	TX_IEEE80211_RADIOTAP_TSFT = 0,
	TX_IEEE80211_RADIOTAP_FLAGS = 1,
	TX_IEEE80211_RADIOTAP_RATE = 2,
	TX_IEEE80211_RADIOTAP_CHANNEL = 3,
	TX_IEEE80211_RADIOTAP_FHSS = 4,
	TX_IEEE80211_RADIOTAP_DBM_ANTSIGNAL = 5,
	TX_IEEE80211_RADIOTAP_DBM_ANTNOISE = 6,
	TX_IEEE80211_RADIOTAP_LOCK_QUALITY = 7,
	TX_IEEE80211_RADIOTAP_TX_ATTENUATION = 8,
	TX_IEEE80211_RADIOTAP_DB_TX_ATTENUATION = 9,
	TX_IEEE80211_RADIOTAP_DBM_TX_POWER = 10,
	TX_IEEE80211_RADIOTAP_ANTENNA = 11,
	TX_IEEE80211_RADIOTAP_DB_ANTSIGNAL = 12,
	TX_IEEE80211_RADIOTAP_DB_ANTNOISE = 13,
	TX_IEEE80211_RADIOTAP_FCS = 14,
	TX_IEEE80211_RADIOTAP_EXT = 31,
};


#ifdef _MSC_VER
#pragma pack(push, 1)
#endif

/* Injection header */
struct lorcon_inject_radiotap_header {
	uint8_t it_version;
	uint8_t it_pad;
	uint16_t it_len;
	uint32_t it_present;
	/*
	uint8_t wr_flags;
    uint8_t wr_rate;
	uint16_t wr_chan_freq;
	uint16_t wr_chan_flags;
	*/
}
#ifdef _MSC_VER
#pragma pack(pop)
#else		
__attribute__((__packed__))
#endif
;

void lorcon_packet_free(lorcon_packet_t *packet) {
	if (packet->free_data) {
		if (packet->packet_raw)
			free((u_char *) packet->packet_raw);
		if (packet->lcpa)
			lcpa_free(packet->lcpa);
	}

	free(packet);
}

void lorcon_packet_set_channel(lorcon_packet_t *packet, int channel) {
	packet->channel = channel;
}

int lorcon_packet_decode(lorcon_packet_t *packet) {
	avs_80211_1_header *avshdr = (avs_80211_1_header *) packet->packet_raw;
	ppi_packet_header *ppihdr = (ppi_packet_header *) packet->packet_raw;
	radiotap_header *rtaphdr = (radiotap_header *) packet->packet_raw;
	int innerdlt = packet->dlt, offt = 0, rtpos = 0;
	u_int16_t *pu16, eu16, fcs = 0;
	u_int8_t rt_wr_flags;
	struct lorcon_dot11_extra *extra;

	if (packet->dlt == DLT_PRISM_HEADER) {
		if (packet->length > sizeof(avs_80211_1_header) &&
			ntohl(avshdr->version) == 0x80211001) {
			/* avs */
			if (ntohl(avshdr->length) < packet->length) {
				packet->packet_header = &(packet->packet_raw[ntohl(avshdr->length)]);
				packet->length_header = packet->length - ntohl(avshdr->length);
			} else if (packet->length > sizeof(wlan_ng_prism2_header)) {
				/* prism2 */
				packet->packet_header = 
					&(packet->packet_raw[sizeof(wlan_ng_prism2_header)]);
				packet->length_header = packet->length - sizeof(wlan_ng_prism2_header);
			}
		}

		innerdlt = DLT_IEEE802_11;
	} else if (packet->dlt == DLT_PPI) {
		if (packet->length > sizeof(ppi_packet_header) &&
			lorcon_le16(ppihdr->pph_len) < packet->length) {
			packet->packet_header = &(packet->packet_raw[lorcon_le16(ppihdr->pph_len)]);
			packet->length_header = packet->length - lorcon_le16(ppihdr->pph_len);

			innerdlt = lorcon_le32(ppihdr->pph_dlt);
		}
	} else if (packet->dlt == DLT_IEEE802_11_RADIO) {
		if (packet->length > sizeof(radiotap_header) &&
			lorcon_le16(rtaphdr->it_len) < packet->length) {
			packet->packet_header = &(packet->packet_raw[lorcon_le16(rtaphdr->it_len)]);
			packet->length_header = packet->length - lorcon_le16(rtaphdr->it_len);

			if (rtpos < packet->length &&
				(rtaphdr->it_present & BIT(TX_IEEE80211_RADIOTAP_TSFT))) {
				rtpos += 8;
			}

			if (rtpos < packet->length &&
				(rtaphdr->it_present & BIT(TX_IEEE80211_RADIOTAP_FLAGS))) {

				rt_wr_flags = packet->packet_raw[sizeof(radiotap_header) + rtpos];
				rtpos += 1;

				if (rt_wr_flags & IEEE80211_RADIOTAP_F_FCS) {
					fcs = 1;
				}
			}

			if (fcs && packet->length_header > 4) {
				packet->length_header -= 4;
			}

			innerdlt = DLT_IEEE802_11;
		}
	} else if (packet->dlt == DLT_IEEE802_11) {
		packet->packet_header = packet->packet_raw;
		packet->length_header = packet->length;
	} else {
		return 0;
	}

	/* try to decode the dot11 inner data */
	if (innerdlt == DLT_IEEE802_11 && packet->packet_header != NULL &&
		packet->length_header >= 10) {

		extra = (struct lorcon_dot11_extra *) malloc(sizeof(struct lorcon_dot11_extra));

		memset(extra, 0, sizeof(struct lorcon_dot11_extra));

		packet->extra_info = extra;
		packet->extra_type = LORCON_PACKET_EXTRA_80211;

		extra->type = WLAN_FC_FRAMETYPE(packet->packet_header[0]);
		extra->subtype = WLAN_FC_FRAMESUBTYPE(packet->packet_header[0]);

		extra->to_ds = (packet->packet_header[1] & WLAN_FC_TODS);
		extra->from_ds = (packet->packet_header[1] & WLAN_FC_FROMDS);

		extra->fragmented = (packet->packet_header[1] & WLAN_FC_MOREFRAG);
		extra->retry = (packet->packet_header[1] & WLAN_FC_RETRY);
		extra->frame_protected = (packet->packet_header[1] & WLAN_FC_ISWEP);

		pu16 = (uint16_t *) (packet->packet_header + 2);
		extra->duration = lorcon_le16(*pu16);

		if (extra->type == WLAN_FC_TYPE_CTRL) {
			extra->dest_mac = packet->packet_header + 4;
			return 1;
		}

		/* Other packet types must be > 24 */
		if (packet->length_header < 24) {
			extra->corrupt = 1;
			return 1;
		}
		pu16 = (uint16_t *) (packet->packet_header + 22);
		extra->sequence = lorcon_le16(*pu16);
		extra->fragment = WLAN_SEQCTL_FRAGNO(extra->sequence);
		extra->sequence = WLAN_SEQCTL_SEQNO(extra->sequence);


		if (extra->type == WLAN_FC_TYPE_MGMT) {
			switch (extra->subtype) {
				case WLAN_FC_SUBTYPE_ASSOCREQ:
				case WLAN_FC_SUBTYPE_ASSOCRESP:
				case WLAN_FC_SUBTYPE_REASSOCREQ:
				case WLAN_FC_SUBTYPE_REASSOCRESP:
				case WLAN_FC_SUBTYPE_PROBERESP:
				case WLAN_FC_SUBTYPE_BEACON:
				case WLAN_FC_SUBTYPE_ATIM:
				case WLAN_FC_SUBTYPE_DISASSOC:
				case WLAN_FC_SUBTYPE_AUTH:
				case WLAN_FC_SUBTYPE_DEAUTH:
					extra->dest_mac = packet->packet_header + 4;
					extra->source_mac = packet->packet_header + 10;
					extra->bssid_mac = packet->packet_header + 16;
					break;
				case WLAN_FC_SUBTYPE_PROBEREQ:
					extra->source_mac = packet->packet_header + 10;
					extra->bssid_mac = packet->packet_header + 10;
					break;
			}

			switch (extra->subtype) {
				case WLAN_FC_SUBTYPE_PROBEREQ:
				case WLAN_FC_SUBTYPE_DISASSOC:
				case WLAN_FC_SUBTYPE_AUTH:
				case WLAN_FC_SUBTYPE_DEAUTH:
					break;
				default:
					if (packet->length_header < 36)
						break;

					memcpy(&(extra->capability), packet->packet_header + 34, 2);

					break;
			}
		} else if (extra->type == WLAN_FC_TYPE_DATA) {
			if (extra->from_ds && !extra->to_ds) {
				extra->dest_mac = packet->packet_header + 4;
				extra->bssid_mac = packet->packet_header + 10;
				extra->source_mac = packet->packet_header + 16;
				offt = 24;
			} else if (!extra->from_ds && extra->to_ds) {
				extra->bssid_mac = packet->packet_header + 4;
				extra->source_mac = packet->packet_header + 10;
				extra->dest_mac = packet->packet_header + 16;
				offt = 24;
			} else if (!extra->from_ds && !extra->to_ds) {
				extra->dest_mac = packet->packet_header + 4;
				extra->source_mac = packet->packet_header + 10;
				extra->bssid_mac = packet->packet_header + 16;
				offt = 24;
			} else if (extra->from_ds && extra->to_ds) {
				if (packet->length_header < 30) {
					extra->corrupt = 1;
					return 1;
				}

				extra->bssid_mac = packet->packet_header + 4;
				extra->source_mac = packet->packet_header + 10;
				extra->dest_mac = packet->packet_header + 16;

				offt = 30;
			}

			switch (extra->subtype) {
				case WLAN_FC_SUBTYPE_QOSDATA:
				case WLAN_FC_SUBTYPE_QOSDATACFACK:
				case WLAN_FC_SUBTYPE_QOSDATACFPOLL:
				case WLAN_FC_SUBTYPE_QOSDATACFACKPOLL:
				case WLAN_FC_SUBTYPE_QOSNULL:
					offt += 2;
			}

			if (offt < packet->length_header) {
				packet->length_data = packet->length_header - offt;
				packet->packet_data = packet->packet_header + offt;
			}
		}
	}

	return 1;
}

void lorcon_packet_set_freedata(lorcon_packet_t *packet, int freedata) {
	packet->free_data = freedata;
}

lorcon_packet_t *lorcon_packet_from_lcpa(struct lorcon *context,
										 struct lcpa_metapack *lcpa) {
	lorcon_packet_t *l_packet;

	if (lcpa == NULL)
		return NULL;

	l_packet = (lorcon_packet_t *) malloc(sizeof(lorcon_packet_t));

	memset(l_packet, 0, sizeof(lorcon_packet_t));

	l_packet->lcpa = lcpa;

	return l_packet;
}

lorcon_packet_t *lorcon_packet_from_pcap(lorcon_t *context,
										 const struct pcap_pkthdr *h, 
										 const u_char *bytes) {
	lorcon_packet_t *l_packet;

	if (bytes == NULL)
		return NULL;

	l_packet = (lorcon_packet_t *) malloc(sizeof(lorcon_packet_t));

	l_packet->lcpa = NULL;

	l_packet->ts.tv_sec = h->ts.tv_sec;
	l_packet->ts.tv_usec = h->ts.tv_usec;

	l_packet->length = h->caplen;
	l_packet->length_header = 0;
	l_packet->length_data = 0;
	l_packet->channel = 0;
	
	l_packet->free_data = 0;

	l_packet->dlt = context->dlt;

	l_packet->packet_raw = bytes;

	l_packet->packet_header = NULL;
	l_packet->packet_data = NULL;

	lorcon_packet_decode(l_packet);

	return l_packet;
}

int lorcon_packet_txprep_by_ctx(lorcon_t *context, lorcon_packet_t *packet,
								u_char **data) {
	u_char *ret;
	int rlen = 0;
	struct lorcon_inject_radiotap_header *rtap_hdr;

	if (packet->lcpa == NULL && packet->length == 0)
		return 0;

	/* Only assemble a packet when we don't have raw bytes */
	if (packet->lcpa != NULL) {
		rlen += lcpa_size(packet->lcpa);
	} else  {
		rlen += packet->length;
	}

	if (context->dlt == DLT_IEEE802_11_RADIO) {
		rlen += sizeof(struct lorcon_inject_radiotap_header);

		ret = (u_char *) malloc(sizeof(u_char) * rlen);

		rtap_hdr = (struct lorcon_inject_radiotap_header *) ret;

		if (packet->lcpa != NULL) {
			lcpa_freeze(packet->lcpa, 
						ret + sizeof(struct lorcon_inject_radiotap_header));
		} else {
			memcpy(ret + sizeof(struct lorcon_inject_radiotap_header),
				   packet->packet_raw, packet->length);
		}

		rtap_hdr->it_version = 0;
		rtap_hdr->it_pad = 0;
		rtap_hdr->it_len = lorcon_le16(sizeof(struct lorcon_inject_radiotap_header));
#if 0
		rtap_hdr->it_present =
			lorcon_le32((1 << TX_IEEE80211_RADIOTAP_FLAGS) | 
						(1 << TX_IEEE80211_RADIOTAP_RATE) |
						(1 << TX_IEEE80211_RADIOTAP_CHANNEL));
		rtap_hdr->wr_flags = 0;
		/* todo - set these */
		rtap_hdr->wr_rate = 0;
		rtap_hdr->wr_chan_freq = 0;
		rtap_hdr->wr_chan_flags = 0;
#endif
	} else if (context->dlt == DLT_IEEE802_11) {
		ret = (u_char *) malloc(sizeof(u_char) * rlen);

		if (packet->lcpa != NULL)
			lcpa_freeze(packet->lcpa, ret);
		else
			memcpy(ret, packet->packet_raw, packet->length);
	}

	*data = ret;

	return rlen;
}

/* CRC32 index for verifying WEP - cribbed from ethereal */
static const uint32_t wep_crc32_table[256] = {
    0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL, 0x076dc419L,
    0x706af48fL, 0xe963a535L, 0x9e6495a3L, 0x0edb8832L, 0x79dcb8a4L,
    0xe0d5e91eL, 0x97d2d988L, 0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L,
    0x90bf1d91L, 0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL,
    0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L, 0x136c9856L,
    0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL, 0x14015c4fL, 0x63066cd9L,
    0xfa0f3d63L, 0x8d080df5L, 0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L,
    0xa2677172L, 0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
    0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L, 0x32d86ce3L,
    0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L, 0x26d930acL, 0x51de003aL,
    0xc8d75180L, 0xbfd06116L, 0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L,
    0xb8bda50fL, 0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L,
    0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL, 0x76dc4190L,
    0x01db7106L, 0x98d220bcL, 0xefd5102aL, 0x71b18589L, 0x06b6b51fL,
    0x9fbfe4a5L, 0xe8b8d433L, 0x7807c9a2L, 0x0f00f934L, 0x9609a88eL,
    0xe10e9818L, 0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
    0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL, 0x6c0695edL,
    0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L, 0x65b0d9c6L, 0x12b7e950L,
    0x8bbeb8eaL, 0xfcb9887cL, 0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L,
    0xfbd44c65L, 0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L,
    0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL, 0x4369e96aL,
    0x346ed9fcL, 0xad678846L, 0xda60b8d0L, 0x44042d73L, 0x33031de5L,
    0xaa0a4c5fL, 0xdd0d7cc9L, 0x5005713cL, 0x270241aaL, 0xbe0b1010L,
    0xc90c2086L, 0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
    0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L, 0x59b33d17L,
    0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL, 0xedb88320L, 0x9abfb3b6L,
    0x03b6e20cL, 0x74b1d29aL, 0xead54739L, 0x9dd277afL, 0x04db2615L,
    0x73dc1683L, 0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L,
    0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L, 0xf00f9344L,
    0x8708a3d2L, 0x1e01f268L, 0x6906c2feL, 0xf762575dL, 0x806567cbL,
    0x196c3671L, 0x6e6b06e7L, 0xfed41b76L, 0x89d32be0L, 0x10da7a5aL,
    0x67dd4accL, 0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
    0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L, 0xd1bb67f1L,
    0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL, 0xd80d2bdaL, 0xaf0a1b4cL,
    0x36034af6L, 0x41047a60L, 0xdf60efc3L, 0xa867df55L, 0x316e8eefL,
    0x4669be79L, 0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L,
    0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL, 0xc5ba3bbeL,
    0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L, 0xc2d7ffa7L, 0xb5d0cf31L,
    0x2cd99e8bL, 0x5bdeae1dL, 0x9b64c2b0L, 0xec63f226L, 0x756aa39cL,
    0x026d930aL, 0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
    0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L, 0x92d28e9bL,
    0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L, 0x86d3d2d4L, 0xf1d4e242L,
    0x68ddb3f8L, 0x1fda836eL, 0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L,
    0x18b74777L, 0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL,
    0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L, 0xa00ae278L,
    0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L, 0xa7672661L, 0xd06016f7L,
    0x4969474dL, 0x3e6e77dbL, 0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L,
    0x37d83bf0L, 0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
    0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L, 0xbad03605L,
    0xcdd70693L, 0x54de5729L, 0x23d967bfL, 0xb3667a2eL, 0xc4614ab8L,
    0x5d681b02L, 0x2a6f2b94L, 0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL,
    0x2d02ef8dL
};

lorcon_packet_t *lorcon_packet_decrypt(lorcon_t *context, lorcon_packet_t *packet) {
	lorcon_packet_t *ret;
	lorcon_wep_t *wepidx = context->wepkeys;
	struct lorcon_dot11_extra *extra = (struct lorcon_dot11_extra *) packet->extra_info;
	u_char pwd[LORCON_WEPKEY_MAX + 3], keyblock[256];
	int pwdlen = 3;
	int kba = 0, kbb = 0;

	/* Not 802.11, no data, not enough for IV + FCS */
	if (packet->extra_info == NULL || packet->extra_type != LORCON_PACKET_EXTRA_80211 ||
		packet->packet_data == NULL || packet->length_data < 7)
		return NULL;

	/* Find a supposed key */
	while (wepidx) {
		if (memcmp(extra->bssid_mac, wepidx->bssid, 6) == 0)
			break;

		wepidx = wepidx->next;
	}

	if (wepidx == NULL)
		return NULL;

}

int lorcon_packet_to_dot3(lorcon_packet_t *packet, u_char **data) {
	int length = 0, offt = 0;
	struct lorcon_dot11_extra *extra = (struct lorcon_dot11_extra *) packet->extra_info;

	if (packet->length_data == 0 || packet->packet_data == NULL ||
		packet->extra_info == NULL || packet->extra_type != LORCON_PACKET_EXTRA_80211) {
		*data = NULL;
		return 0;
	}

	if (extra->dest_mac == NULL || extra->source_mac == NULL) {
		*data = NULL;
		return 0;
	}

	if (packet->length_data > 8) {
		/* looks like a SNAP */
		if (packet->packet_data[0] == 0xaa &&
			packet->packet_data[1] == 0xaa &&
			packet->packet_data[2] == 0x03) {

			offt = 6;
		}
	}
	
	length = 12 + packet->length_data - offt;

	*data = (u_char *) malloc(sizeof(u_char) * length);

	memcpy(*data, extra->dest_mac, 6);
	memcpy(*data + 6, extra->source_mac, 6);
	memcpy(*data + 12, packet->packet_data + offt, packet->length_data - offt);

	return length;
}

/* Basic translate to data packet */
lorcon_packet_t *lorcon_packet_from_dot3(u_char *bssid, int dot11_direction,
										 u_char *data, int length) {
	lorcon_packet_t *ret;
	int offt = 0;
	u_char *mac0 = NULL, *mac1 = NULL, *mac2 = NULL, llc[8];
	uint8_t fcf_flags = 0;

	if (length < 12 || dot11_direction == LORCON_DOT11_DIR_INTRADS)
		return NULL;

	ret = (lorcon_packet_t *) malloc(sizeof(lorcon_packet_t));

	memset(ret, 0, sizeof(lorcon_packet_t));

	ret->lcpa = lcpa_init();

	/* Process the direction ordering */
	switch (dot11_direction) {
		case LORCON_DOT11_DIR_FROMDS:
			fcf_flags |= WLAN_FC_FROMDS;
			mac0 = data;
			mac1 = bssid;
			mac2 = data + 6;
			break;
		case LORCON_DOT11_DIR_TODS:
			fcf_flags |= WLAN_FC_TODS;
			mac0 = bssid;
			mac1 = data + 6;
			mac2 = data;
			break;
		case LORCON_DOT11_DIR_ADHOCDS:
			mac0 = data;
			mac1 = data + 6;
			mac2 = bssid;
			break;
		default:
			printf("debug - fall to default direction, %d\n", dot11_direction);
			mac0 = data;
			mac1 = data + 6;
			mac2 = bssid;
			break;
	}

	lcpf_80211headers(ret->lcpa, 
					  WLAN_FC_TYPE_DATA, WLAN_FC_SUBTYPE_DATA,
					  fcf_flags, /* fcf flags */
					  length, /* duration */
					  mac0, mac1, mac2, NULL, 0, 1234);

	/* sub macs */
	offt += 12;

	/* Alias the IP type */
	if (length > 14) {
		if (data[12] != 0xaa && data[13] != 0xaa) {
			llc[0] = 0xaa;
			llc[1] = 0xaa;
			llc[2] = 0x03;
			llc[3] = 0x00;
			llc[4] = 0x00;
			llc[5] = 0x00;
			llc[6] = data[12];
			llc[7] = data[13];

			ret->lcpa = lcpa_append_copy(ret->lcpa, "LLC", 8, llc);

			/* consume iptype from dot3 */
			offt += 2;
		}
	}

	ret->lcpa = lcpa_append_copy(ret->lcpa, "DATA", length - offt, data + offt);

	return ret;
}


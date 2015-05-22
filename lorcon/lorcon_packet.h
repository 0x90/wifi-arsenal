/*
    This file is part of LORCON

    LORCON is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    LORCON is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with LORCON; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

    Copyright (c) dragorn and Joshua Wright
*/

#ifndef __LORCON_PACKET_H__
#define __LORCON_PACKET_H__

#include <string.h>
#include <unistd.h>
#include <sys/types.h>

struct lorcon;
struct pcap_pkthdr;
struct lcpa_metapack;

/* Radio modulation flags for this packet (drivers which support setting
 * per-packet modulation controls */
enum lorcon_mod_flags {
	LORCON_MOD_DEFAULT=0,
	LORCON_MOD_FHSS,
	LORCON_MOD_DSSS,
	LORCON_MOD_OFDM,
	LORCON_MOD_TURBO,
	LORCON_MOD_MIMO,
	LORCON_MOD_MIMOGF
};

#define LORCON_DOT11_DIR_FROMDS		1
#define LORCON_DOT11_DIR_TODS		2
#define LORCON_DOT11_DIR_INTRADS	3
#define LORCON_DOT11_DIR_ADHOCDS	4

/* Channel flags for radiotap */
#define LORCON_RTAP_CHAN_TURBO		0x0010   /* Turbo channel */
#define LORCON_RTAP_CHAN_CCK		0x0020   /* CCK channel */
#define LORCON_RTAP_CHAN_OFDM		0x0040   /* OFDM channel */
#define	LORCON_RTAP_CHAN_2GHZ		0x0080   /* 2 GHz spectrum channel. */
#define LORCON_RTAP_CHAN_5GHZ		0x0100   /* 5 GHz spectrum channel */
#define LORCON_RTAP_CHAN_PASSIVE	0x0200   /* Only passive scan allowed */
#define	LORCON_RTAP_CHAN_DYN		0x0400   /* Dynamic CCK-OFDM channel */
#define	LORCON_RTAP_CHAN_GFSK		0x0800   /* GFSK channel (FHSS PHY) */
#define	LORCON_RTAP_CHAN_STURBO		0x2000   /* 11a static turbo channel only */

/* Useful combinations of channel characteristics, borrowed from Ethereal */
#define LORCON_RTAP_CHAN_A \
	(LORCON_RTAP_CHAN_5GHZ | LORCON_RTAP_CHAN_OFDM)
#define LORCON_RTAP_CHAN_B \
	(LORCON_RTAP_CHAN_2GHZ | LORCON_RTAP_CHAN_CCK)
#define LORCON_RTAP_CHAN_G \
	(LORCON_RTAP_CHAN_2GHZ | LORCON_RTAP_CHAN_DYN)
#define LORCON_RTAP_CHAN_TA \
	(LORCON_RTAP_CHAN_5GHZ | LORCON_RTAP_CHAN_OFDM | \
	LORCON_RTAP_CHAN_TURBO)
#define LORCON_RTAP_CHAN_TG \
	(LORCON_RTAP_CHAN_2GHZ | LORCON_RTAP_CHAN_DYN  | \
	LORCON_RTAP_CHAN_TURBO)

/* Values are in a quantity of 500 Kbps increments */
#define LORCON_RATE_DEFAULT 	0
#define LORCON_RATE_1MB 		2 
#define LORCON_RATE_2MB 		4 
#define LORCON_RATE_5_5MB 		11
#define LORCON_RATE_6MB 		12
#define LORCON_RATE_9MB 		18
#define LORCON_RATE_11MB 		22 
#define LORCON_RATE_12MB 		24 
#define LORCON_RATE_18MB 		36 
#define LORCON_RATE_24MB 		48 
#define LORCON_RATE_36MB 		72 
#define LORCON_RATE_48MB 		96 
#define LORCON_RATE_54MB 		108
#define LORCON_RATE_108MB 		216

struct lorcon_packet {
	struct timeval ts;
	int dlt;

	/* Channel we captured on, if available in packet headers, or channel we
	 * will tx on */
	int channel;

	/* Length of components */
	int length;
	int length_header;
	int length_data;

	/* LCPA assembly fragment */
	struct lcpa_metapack *lcpa;

	/* Do we free the data when we free the packet */
	int free_data;

	/* Beginning of packet from line */
	const u_char *packet_raw;
	/* Beginning of packet data after per-packet headers */
	const u_char *packet_header;
	/* Beginning of packet data */
	const u_char *packet_data;

	/* Additional info */
	void *extra_info;
	int extra_type;
};
typedef struct lorcon_packet lorcon_packet_t;

#define LORCON_PACKET_EXTRA_NONE		0
#define LORCON_PACKET_EXTRA_80211		1

/* 802.11 extra info */
struct lorcon_dot11_extra {
	int type, subtype;
	int reason_code;

	int corrupt;

	/* Note: these are pointers to the data segment, NOT allocated */
	const u_char *source_mac, *dest_mac, *bssid_mac, *other_mac;

	unsigned int from_ds, to_ds, frame_protected, fragmented, retry;

	unsigned int qos, sequence, duration, fragment;

	uint16_t capability;
};

void lorcon_packet_free(lorcon_packet_t *packet);
int lorcon_packet_decode(lorcon_packet_t *packet);

/* Set channel field */
void lorcon_packet_set_channel(lorcon_packet_t *packet, int channel);

/* Is data freed when packet is freed (NO if sharing data block) */
void lorcon_packet_set_freedata(lorcon_packet_t *packet, int freedata);

/* Transform a LCPA into a lorcon packet */
lorcon_packet_t *lorcon_packet_from_lcpa(struct lorcon *context,
										 struct lcpa_metapack *lcpa);
										 

/* Transform a pcap into a lorcon packet and process the DLT */
lorcon_packet_t *lorcon_packet_from_pcap(struct lorcon *context,
										 const struct pcap_pkthdr *h, 
										 const u_char *bytes);

/* Transform a lorcon packet into a bytestream for injection via the settings in
 * the LORCON context (IE DLT translation is controlled by the context DLT, most
 * contexts will use this).  Caller is responsible for freeing bytes */
int lorcon_packet_txprep_by_ctx(struct lorcon *context, lorcon_packet_t *packet,
								u_char **data);

/* Convert a *data* packet to 802.3 ethernet form, primarily for use with 
 * external packet dissectors which don't speak dot11.  This does not make
 * sense to do to an encrypted packet */
int lorcon_packet_to_dot3(lorcon_packet_t *packet, u_char **data);

/* Convert an 802.3 ethernet packet to 802.11, primarily for use with external
 * packet assemblers which don't speak dot11 */
lorcon_packet_t *lorcon_packet_from_dot3(u_char *bssid, int dot11_direction,
										 u_char *data, int length);

#endif

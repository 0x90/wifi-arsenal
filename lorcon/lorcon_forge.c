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

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include <string.h>
/* #include <netinet/in.h> */
#include <stdlib.h>
#include <stdio.h>

#include "lorcon.h"
#include "lorcon_packasm.h"
#include "lorcon_endian.h"
#include "lorcon_forge.h"
#include "ieee80211.h"

uint8_t *ouilist[] = {
    (uint8_t *) "\x00\x01\x03", (uint8_t *) "\x00\x01\x24",
    (uint8_t *) "\x00\x02\x2D", (uint8_t *) "\x00\x02\x6F",
    (uint8_t *) "\x00\x02\xA5", (uint8_t *) "\x00\x03\x2F",
    (uint8_t *) "\x00\x04\x3A", (uint8_t *) "\x00\x04\x5A",
    (uint8_t *) "\x00\x04\x75", (uint8_t *) "\x00\x04\xE2",
    (uint8_t *) "\x00\x05\x5D", (uint8_t *) "\x00\x06\x25",
    (uint8_t *) "\x00\x07\x0E", (uint8_t *) "\x00\x07\x50",
    (uint8_t *) "\x00\x08\x21", (uint8_t *) "\x00\x09\x43",
    (uint8_t *) "\x00\x09\x5B", (uint8_t *) "\x00\x09\x7C",
    (uint8_t *) "\x00\x09\x92", (uint8_t *) "\x00\x09\xE8",
    (uint8_t *) "\x00\x0A\x41", (uint8_t *) "\x00\x0A\x8A",
    (uint8_t *) "\x00\x0C\x41", (uint8_t *) "\x00\x0D\x88",
    (uint8_t *) "\x00\x30\x65", (uint8_t *) "\x00\x30\xAB",
    (uint8_t *) "\x00\x30\xBD", (uint8_t *) "\x00\x40\x05",
    (uint8_t *) "\x00\x40\x26", (uint8_t *) "\x00\x40\x96",
    (uint8_t *) "\x00\x50\x08", (uint8_t *) "\x00\x50\x8B",
    (uint8_t *) "\x00\x50\xDA", (uint8_t *) "\x00\x50\xF2",
    (uint8_t *) "\x00\x60\x01", (uint8_t *) "\x00\x60\x1D",
    (uint8_t *) "\x00\x60\x6D", (uint8_t *) "\x00\x60\xB3",
    (uint8_t *) "\x00\x80\x37", (uint8_t *) "\x00\x80\xC6",
    (uint8_t *) "\x00\x80\xC8", (uint8_t *) "\x00\x90\x4B",
    (uint8_t *) "\x00\x90\xD1", (uint8_t *) "\x00\xA0\x04",
    (uint8_t *) "\x00\xA0\xF8", (uint8_t *) "\x00\xE0\x29",
    (uint8_t *) "\x08\x00\x46", NULL
};

void lcpf_randmac(uint8_t *addr, int valid) {
	static int listlen = 0;

	if (listlen == 0) {
		while (ouilist[listlen] != NULL) {
			listlen++;
		};
	}

	if (valid) {
		memcpy(addr, ouilist[rand() % listlen], 3);
	} else {
		addr[0] = rand() % 255;
		addr[1] = rand() % 255;
		addr[2] = rand() % 255;
	}

	addr[3] = rand() % 255;
	addr[4] = rand() % 255;
	addr[5] = rand() % 255;
}

void lcpf_qosheaders(struct lcpa_metapack *pack, unsigned int priority,
		unsigned int eosp, unsigned int ackpol) {
	uint8_t chunk[2];

	/* Bits 0 and 4 are reserved. */
	chunk[0] = 0;
	chunk[0] = ((priority << 5) | (eosp << 3) | (ackpol << 1));
	/* All 8 bits reserved */
	chunk[1] = 0;
	pack = lcpa_append_copy(pack, "80211QOSHDR", 2, chunk);
}

void lcpf_80211ctrlheaders(struct lcpa_metapack *pack, 
		unsigned int type, unsigned int subtype, unsigned int fcflags, 
		unsigned int duration, uint8_t *mac1)
{

	/* Re-use a single buffer and use the copy ops, saves a malloc
	 * thrash */
	uint8_t chunk[2];
	uint16_t *sixptr;

	chunk[0] = ((type << 2) | (subtype << 4));
	chunk[1] = (uint8_t) fcflags;
	pack = lcpa_append_copy(pack, "80211FC", 2, chunk);

	sixptr = (uint16_t *) chunk;
	*sixptr = lorcon_hton16((uint16_t) duration);
	pack = lcpa_append_copy(pack, "80211DUR", 2, chunk);

	if (mac1 != NULL) {
		pack = lcpa_append_copy(pack, "80211MAC1", 6, mac1);
	}

	return;
}

void lcpf_data(struct lcpa_metapack *pack, unsigned int fcflags, 
		unsigned int duration, uint8_t *mac1, uint8_t *mac2, 
		uint8_t *mac3, uint8_t *mac4, unsigned int fragment, 
		unsigned int sequence) {

	lcpf_80211headers(pack, WLAN_FC_TYPE_DATA, WLAN_FC_SUBTYPE_DATA,
		fcflags, duration, mac1, mac2, mac3, mac4, fragment, sequence);
}

void lcpf_80211headers(struct lcpa_metapack *pack, unsigned int type, 
		unsigned int subtype, unsigned int fcflags, 
		unsigned int duration,
		uint8_t *mac1, uint8_t *mac2, uint8_t *mac3,
		uint8_t *mac4, unsigned int fragment, 
		unsigned int sequence) {

	/* Re-use a single buffer and use the copy ops, saves a malloc
	 * thrash */
	uint8_t chunk[2];
	uint16_t *sixptr;

	chunk[0] = ((type << 2) | (subtype << 4));
	chunk[1] = (uint8_t) fcflags;
	pack = lcpa_append_copy(pack, "80211FC", 2, chunk);

	sixptr = (uint16_t *) chunk;
	*sixptr = lorcon_hton16((uint16_t) duration);
	pack = lcpa_append_copy(pack, "80211DUR", 2, chunk);

	if (mac1 != NULL)
		pack = lcpa_append_copy(pack, "80211MAC1", 6, mac1);
	if (mac2 != NULL)
		pack = lcpa_append_copy(pack, "80211MAC2", 6, mac2);
	if (mac3 != NULL)
		pack = lcpa_append_copy(pack, "80211MAC3", 6, mac3);
	if (mac4 != NULL)
		pack = lcpa_append_copy(pack, "80211MAC4", 6, mac4);

	*sixptr = ((sequence << 4) | fragment);
	pack = lcpa_append_copy(pack, "80211FRAGSEQ", 2, chunk);
}

void lcpf_beacon(struct lcpa_metapack *pack, uint8_t *src, uint8_t *bssid, 
				 int framecontrol, int duration, int fragment, int sequence, 
				 uint64_t timestamp, int beacon, int capabilities) {
	uint8_t chunk[8];
	uint16_t *sixptr = (uint16_t *) chunk;
	uint64_t *ch64 = (uint64_t *) chunk;

	memcpy(chunk, "\xFF\xFF\xFF\xFF\xFF\xFF", 6);
	lcpf_80211headers(pack, WLAN_FC_TYPE_MGMT, WLAN_FC_SUBTYPE_BEACON, framecontrol, duration,
					  chunk, src, bssid, NULL,
					  fragment, sequence);

	*ch64 = timestamp;
	pack = lcpa_append_copy(pack, "BEACONBSSTIME", 8, chunk);

	*sixptr = beacon;
	pack = lcpa_append_copy(pack, "BEACONINT", 2, chunk);

	*sixptr = capabilities;
	pack = lcpa_append_copy(pack, "BEACONCAP", 2, chunk);

}

void lcpf_add_ie(struct lcpa_metapack *pack, uint8_t num, uint8_t len, uint8_t *data) {
	uint8_t chunk[257];

	chunk[0] = num;
	chunk[1] = len;
	memcpy(&(chunk[2]), data, len);

	lcpa_append_copy(pack, "IETAG", len + 2, chunk);
}

void lcpf_deauth(struct lcpa_metapack *pack, uint8_t *src, uint8_t *dst,
				   uint8_t *bssid, int framecontrol, 
				   int duration, int fragment,
				   int sequence, int reasoncode) {
	uint8_t chunk[2];
	uint16_t *ch16 = (uint16_t *) chunk;

	lcpf_80211headers(pack, WLAN_FC_TYPE_MGMT, WLAN_FC_SUBTYPE_DEAUTH, framecontrol, duration,
					  dst, src, bssid, NULL, fragment, sequence);

	*ch16 = reasoncode;
	lcpa_append_copy(pack, "REASONCODE", 2, chunk);
}

void lcpf_disassoc(struct lcpa_metapack *pack, uint8_t *src, uint8_t *dst,
				   uint8_t *bssid, int framecontrol, int duration, int fragment,
				   int sequence, int reasoncode) {
	uint8_t chunk[2];
	uint16_t *ch16 = (uint16_t *) chunk;

	lcpf_80211headers(pack, WLAN_FC_TYPE_MGMT, WLAN_FC_SUBTYPE_DISASSOC, framecontrol, duration,
					  dst, src, bssid, NULL, fragment, sequence);

	*ch16 = reasoncode;
	lcpa_append_copy(pack, "REASONCODE", 2, chunk);
}

void lcpf_probereq(struct lcpa_metapack *pack, uint8_t *src, int framecontrol,
		int duration, int fragment, int sequence) {

	uint8_t chunk[6] = "\xFF\xFF\xFF\xFF\xFF\xFF";
	lcpf_80211headers(pack, WLAN_FC_TYPE_MGMT, WLAN_FC_SUBTYPE_PROBEREQ, framecontrol, duration,
			chunk, src, chunk, NULL, fragment, sequence);
}

void lcpf_proberesp(struct lcpa_metapack *pack, uint8_t *dst, uint8_t *src, 
		uint8_t *bssid, int framecontrol, int duration, int fragment,
		int sequence, uint64_t timestamp, int beaconint, 
		int capabilities)
{
	uint8_t chunk[8];
	uint16_t *sixptr = (uint16_t *) chunk;
	uint64_t *ch64 = (uint64_t *) chunk;

	lcpf_80211headers(pack, WLAN_FC_TYPE_MGMT, WLAN_FC_SUBTYPE_PROBERESP, framecontrol, duration,
					  dst, src, bssid, NULL,
					  fragment, sequence);

	*ch64 = timestamp;
	pack = lcpa_append_copy(pack, "BEACONBSSTIME", 8, chunk);

	*sixptr = beaconint;
	pack = lcpa_append_copy(pack, "BEACONINT", 2, chunk);

	*sixptr = capabilities;
	pack = lcpa_append_copy(pack, "BEACONCAP", 2, chunk);

}

void lcpf_rts(struct lcpa_metapack *pack, uint8_t *recvmac, uint8_t *transmac, 
		int framecontrol, int duration)
{
	lcpf_80211ctrlheaders(pack, 1, 11, framecontrol, duration, recvmac);
	pack = lcpa_append_copy(pack, "TRANSMITTERMAC", 6, transmac);
}

void lcpf_authreq(struct lcpa_metapack *pack, uint8_t *dst, uint8_t *src, 
		uint8_t *bssid, int framecontrol, int duration, int fragment,
		int sequence, uint16_t authalgo, uint16_t auth_seq,
		uint16_t auth_status)
{
	uint8_t chunk[2];
	uint16_t *sixptr = (uint16_t *) chunk;
	
	lcpf_80211headers(pack, WLAN_FC_TYPE_MGMT, WLAN_FC_SUBTYPE_AUTH, framecontrol, duration,
					  dst, src, bssid, NULL,
					  fragment, sequence);

	*sixptr = authalgo;
	pack = lcpa_append_copy(pack, "AUTHALGO", 2, chunk);
	*sixptr = auth_seq;
	pack = lcpa_append_copy(pack, "AUTHSEQ", 2, chunk);
	*sixptr = auth_status;
	pack = lcpa_append_copy(pack, "AUTHSTATUS", 2, chunk);

}

/* Authentication response is the same for open networks, with IE tags */
void lcpf_authresq(struct lcpa_metapack *pack, uint8_t *dst, uint8_t *src, 
		uint8_t *bssid, int framecontrol, int duration, int fragment,
		int sequence, uint16_t authalgo, uint16_t auth_seq,
		uint16_t auth_status)
{
	lcpf_authreq(pack, dst, src, bssid, framecontrol, duration, fragment,
			sequence, authalgo, auth_seq, auth_status);
}

void lcpf_assocreq(struct lcpa_metapack *pack, uint8_t *dst, uint8_t *src, 
		uint8_t *bssid, int framecontrol, int duration, int fragment,
		int sequence, uint16_t capabilities, uint16_t listenint)
{
	uint8_t chunk[2];
	uint16_t *sixptr = (uint16_t *) chunk;

	lcpf_80211headers(pack, WLAN_FC_TYPE_MGMT, WLAN_FC_SUBTYPE_ASSOCREQ, framecontrol, duration,
					  dst, src, bssid, NULL,
					  fragment, sequence);

	*sixptr = capabilities;
	pack = lcpa_append_copy(pack, "ASSOCREQCAPAB", 2, chunk);
	*sixptr = listenint;
	pack = lcpa_append_copy(pack, "ASSOCREQLI", 2, chunk);
}

void lcpf_assocresp(struct lcpa_metapack *pack, uint8_t *dst, uint8_t *src, 
		uint8_t *bssid, int framecontrol, int duration, int fragment,
		int sequence, uint16_t capabilities, uint16_t status, 
		uint16_t aid)
{
	uint8_t chunk[2];
	uint16_t *sixptr = (uint16_t *) chunk;

	lcpf_80211headers(pack, WLAN_FC_TYPE_MGMT, WLAN_FC_SUBTYPE_ASSOCRESP, framecontrol, duration,
					  dst, src, bssid, NULL,
					  fragment, sequence);

	*sixptr = capabilities;
	pack = lcpa_append_copy(pack, "ASSOCRESPCAPAB", 2, chunk);
	*sixptr = status;
	pack = lcpa_append_copy(pack, "ASSOCRESPSTAT", 2, chunk);
	*sixptr = aid;
	pack = lcpa_append_copy(pack, "ASSOCRESPID", 2, chunk);
}


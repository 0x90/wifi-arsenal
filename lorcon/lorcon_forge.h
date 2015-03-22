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

#ifndef __LORCON_FORGE_H__
#define __LORCON_FORGE_H__

/*
 * Lorcon Packet Forge
 *
 * Relatively simplistic mechanism for building 802.11 frames using the lorcon
 * packet assembly utilities.
 *
 * Utility functions are included for most of the 802.11 packet types, as well
 * as functions for adding to dynamically sized types.
 *
 * All lorcon packet forge functions use the lcpf_ namespace
 */


#ifndef __PACKET_ASSEMBLY_H__
#include <lorcon_packasm.h>
#endif

/* Create a random MAC address, optionally seeded with a valid wireless OUI
 *
 * addr must be allocated by the caller
 */
void lcpf_randmac(uint8_t *addr, int valid);

/* Generate the common 802.11 headers.  Lower-level function which will generally
 * be wrapped in packet-specific functions
 *
 * pack is expected to be an initialized, empty metapack.
 *
 * mac1 through mac4 are expected to contain NULL or a MAC address for that
 * slot.  The interpretation of the MAC address in each slot will vary per
 * 802.11 type, the caller is expected to provide the MACs in appropriate order.
 *
 */
void lcpf_80211headers(struct lcpa_metapack *pack, unsigned int type, 
					   unsigned int subtype, unsigned int fcflags, 
					   unsigned int duration,
					   uint8_t *mac1, uint8_t *mac2, uint8_t *mac3,
					   uint8_t *mac4, unsigned int fragment, 
					   unsigned int sequence);

/* Control frame (10-byte) header */
void lcpf_80211ctrlheaders(struct lcpa_metapack *pack,
		unsigned int type, unsigned int subtype, unsigned int fcflags,
		unsigned int duration, uint8_t *mac1);

/* Generate a QoS header (2 bytes) which follows immediately after Addr4 or
 * the sequence number field in the standard 802.11 header */
void lcpf_qosheaders(struct lcpa_metapack *pack, unsigned int priority,
		unsigned int eosp, unsigned int ackpol);

/* Generate a beacon frame header with no IE tags (see lcpf_appendie)
 *
 * pack is expected to be an initialized, empty metapack
 *
 */
void lcpf_beacon(struct lcpa_metapack *pack, uint8_t *src, uint8_t *bssid, 
				 int framecontrol, int duration, int fragment, int sequence, 
				 uint64_t timestamp, int beacon, int capabilities);

/* Append an IE tag to a frame
 *
 * pack is expected to be an initialized, filled frame of a type which
 * can sanely accept IE tags
 *
 * IE tags are created as valid entities.  Users who wish to insert corrupted
 * IE tags with invalid lengths should do so via pack_append*()
 */
void lcpf_add_ie(struct lcpa_metapack *pack, uint8_t num, uint8_t len, uint8_t *data);

/* Generate a disassoc frame */
void lcpf_disassoc(struct lcpa_metapack *pack, uint8_t *src, uint8_t *dst,
				   uint8_t *bssid, int framecontrol, int duration, int fragment,
				   int sequence, int reasoncode);

/* Generate a probereq frame */
void lcpf_probereq(struct lcpa_metapack *pack, uint8_t *src, int framecontrol,
				int duration, int fragment, int sequence);

/* Generate a proberesp frame */
void lcpf_proberesp(struct lcpa_metapack *pack, uint8_t *dst, uint8_t *src, 
		uint8_t *bssid, int framecontrol, int duration, int fragment,
		int sequence, uint64_t timestamp, int beaconint, 
		int capabilities);

/* Generate a RTS frame */
void lcpf_rts(struct lcpa_metapack *pack, uint8_t *recvmac, uint8_t *transmac, 
		int framecontrol, int duration);

/* Deauthenticate frame */
void lcpf_deauth(struct lcpa_metapack *pack, uint8_t *src, uint8_t *dst,
				   uint8_t *bssid, int framecontrol, 
				   int duration, int fragment,
				   int sequence, int reasoncode); 

/* Authenticate request */
void lcpf_authreq(struct lcpa_metapack *pack, uint8_t *dst, uint8_t *src, 
		uint8_t *bssid, int framecontrol, int duration, int fragment,
		int sequence, uint16_t authalgo, uint16_t auth_seq,
		uint16_t auth_status);

/* Authenticate response */
void lcpf_authresp(struct lcpa_metapack *pack, uint8_t *dst, uint8_t *src, 
		uint8_t *bssid, int framecontrol, int duration, int fragment,
		int sequence, uint16_t authalgo, uint16_t auth_seq,
		uint16_t auth_status);

/* Associate request */
void lcpf_assocreq(struct lcpa_metapack *pack, uint8_t *dst, uint8_t *src, 
		uint8_t *bssid, int framecontrol, int duration, int fragment,
		int sequence, uint16_t capabilities, uint16_t listenint);

/* Associate response */
void lcpf_assocresp(struct lcpa_metapack *pack, uint8_t *dst, uint8_t *src, 
		uint8_t *bssid, int framecontrol, int duration, int fragment,
		int sequence, uint16_t capabilities, uint16_t status, 
		uint16_t aid);

/* Data frame */
void lcpf_data(struct lcpa_metapack *pack, unsigned int fcflags, 
		unsigned int duration, uint8_t *mac1, uint8_t *mac2, 
		uint8_t *mac3, uint8_t *mac4, unsigned int fragment, 
		unsigned int sequence);
#endif

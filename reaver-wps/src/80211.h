/*
 * Reaver - 802.11 functions
 * Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL. *  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so. *  If you
 *  do not wish to do so, delete this exception statement from your
 *  version. *  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#ifndef DOT11_H
#define DOT11_H

#include "defs.h"
#include "globule.h"
#include "argsparser.h"
#include "sql.h"
#include "builder.h"
#include "iface.h"
#include "crc.h"
#include "wps.h"

#define AUTH_OK                 1
#define ASSOCIATE_OK            2

#define ASSOCIATE_WAIT_TIME     1               /* Seconds */
#define BEACON_WAIT_TIME	2		/* Seconds */
#define ASSOCIATION_SUCCESS     0x0000
#define AUTHENTICATION_SUCCESS  0x0000

#define DEAUTH_REASON_CODE      "\x03\x00"
#define DEAUTH_REASON_CODE_SIZE 2

#define FC_AUTHENTICATE         0x00B0
#define FC_ASSOCIATE            0x0000
#define FC_DEAUTHENTICATE       0x00C0

#define FC_FLAGS_MASK           0xFF
#define FC_VERSION_MASK         0x03
#define FC_TYPE_MASK            0x0C
#define FC_TO_DS                0x01
#define FC_FROM_DS              0x02
#define FC_MORE_FRAG            0x04
#define FC_RETRY                0x08
#define FC_PWR_MGT              0x10
#define FC_MORE_DATA            0x20
#define FC_WEP                  0x40
#define FC_ORDER                0x80

#define RADIO_TAP_VERSION	0x00
#define FAKE_RADIO_TAP_HEADER	"\x00\x00\x00\x00\x00\x00\x00\x00"

#define MAX_AUTH_TRIES          5

#define MIN_AUTH_SIZE           (sizeof(struct radio_tap_header) + sizeof(struct dot11_frame_header) + sizeof(struct authentication_management_frame))

#define SUBTYPE_AUTHENTICATION  0x0B
#define SUBTYPE_ASSOCIATION     0x01

const u_char *next_packet(struct pcap_pkthdr *header);
void read_ap_beacon();
int8_t signal_strength(const u_char *packet, size_t len);
int is_wps_locked();
int reassociate();
void deauthenticate();
void authenticate();
void associate();
int associate_recv_loop();
enum encryption_type supported_encryption(const u_char *packet, size_t len);
int parse_beacon_tags(const u_char *data, size_t len);
unsigned char *parse_ie_data(const u_char *data, size_t len, uint8_t tag_number, size_t *ie_len, size_t *ie_offset);
int is_target(struct dot11_frame_header *frame_header);
int check_fcs(const u_char *packet, size_t len);
int has_rt_header(void);
const u_char *radio_header(const u_char *packet, size_t len);

#endif

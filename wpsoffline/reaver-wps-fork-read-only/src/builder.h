/*
 * Reaver - Packet building functions
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

#ifndef BUILDER_H
#define BUILDER_H

#include <arpa/inet.h>
#include "defs.h"
#include "globule.h"

#define SRATES_TAG_SIZE         8
#define ERATES_TAG_SIZE         4
#define SRATES_TAG_NUMBER       0x01
#define ERATES_TAG_NUMBER       0x32
#define WPS_TAG_SIZE            14
#define WPS_REGISTRAR_TAG       "\x00\x50\xF2\x04\x10\x4A\x00\x01\x10\x10\x3A\x00\x01\x02"
#define SUPPORTED_RATES_TAG     "\x02\x04\x0B\x16\x0C\x12\x18\x24"
#define EXTENDED_RATES_TAG      "\x30\x48\x60\x6C"
#define WPS_REGISTRAR_TAG       "\x00\x50\xF2\x04\x10\x4A\x00\x01\x10\x10\x3A\x00\x01\x02"

#define DEFAULT_DURATION        52

#define DOT1X_VERSION           0x01
#define DOT1X_START             0x01

#define FC_PROBE_REQUEST        0x0040
#define FC_STANDARD		0x0108

#define LLC_SNAP                0xAA
#define SEQ_MASK                0x10

#define LISTEN_INTERVAL         0x0064
#define OPEN_SYSTEM             0

#define UNNUMBERED_FRAME        0x03
#define WFA_VENDOR_ID           "\x00\x37\x2A"

#define WPS_PROBE_IE            "\xdd\x09\x00\x50\xf2\x04\x10\x4a\x00\x01\x10"
#define WPS_PROBE_IE_SIZE       11

const void *build_radio_tap_header(size_t *len);
const void *build_dot11_frame_header(uint16_t fc, size_t *len);
const void *build_authentication_management_frame(size_t *len);
const void *build_association_management_frame(size_t *len);
const void *build_llc_header(size_t *len);
const void *build_wps_probe_request(unsigned char *bssid, char *essid, size_t *len);
const void *build_snap_packet(size_t *len);
const void *build_dot1X_header(uint8_t type, uint16_t payload_len, size_t *len);
const void *build_eap_header(uint8_t id, uint8_t code, uint8_t type, uint16_t payload_len, size_t *len);
const void *build_eapol_start_packet(size_t *len);
const void *build_eap_packet(const void *payload, uint16_t payload_len, size_t *len);
const void *build_eap_failure_packet(size_t *len);
const void *build_tagged_parameter(uint8_t number, uint8_t size, size_t *len);
const void *build_ssid_tagged_parameter(size_t *len);
const void *build_wps_tagged_parameter(size_t *len);
const void *build_supported_rates_tagged_parameter(size_t *len);

#endif

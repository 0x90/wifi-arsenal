/*
 * Reaver - WPS exchange functions
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

#ifndef EXCHANGE_H
#define EXCHANGE_H

#include <arpa/inet.h>
#include "defs.h"
#include "globule.h"
#include "send.h"
#include "misc.h"
#include "80211.h"

#define DATA_FRAME              0x02
#define SUBTYPE_DATA            0x00

#define MIN_PACKET_SIZE         (sizeof(struct radio_tap_header) + sizeof(struct dot11_frame_header) + sizeof(struct llc_header) + sizeof(struct dot1X_header))
#define EAP_PACKET_SIZE         (MIN_PACKET_SIZE + sizeof(struct eap_header))
#define WFA_PACKET_SIZE         (EAP_PACKET_SIZE + sizeof(struct wfa_expanded_header))

#define MAX_MESSAGE_RETRIES	3

enum wps_result do_wps_exchange();
enum wps_type process_packet(const u_char *packet, struct pcap_pkthdr *header);
enum wps_type process_wps_message(const void *data, size_t data_size);
int parse_nack(const void *data, size_t data_size);

#endif

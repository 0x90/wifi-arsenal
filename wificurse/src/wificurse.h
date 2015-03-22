/*
    wificurse - WiFi Jamming tool
    Copyright (C) 2012  oblique

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef WIFICURSE_H
#define WIFICURSE_H

#include <stdint.h>
#include <linux/if.h>
#include "iw.h"
#include "ap_list.h"


#define VERSION	"0.3.9"

struct frame_control {
	uint8_t protocol_version:2;
	uint8_t type:2;
	uint8_t subtype:4;
	uint8_t to_ds:1;
	uint8_t from_ds:1;
	uint8_t more_frag:1;
	uint8_t retry:1;
	uint8_t pwr_mgt:1;
	uint8_t more_data:1;
	uint8_t protected_frame:1;
	uint8_t order:1;
} __attribute__((__packed__));

#define FRAME_CONTROL_TYPE_MGMT_FRAME	0
#define FRAME_CONTROL_SUBTYPE_DEAUTH	12
#define FRAME_CONTROL_SUBTYPE_BEACON	8

struct sequence_control {
	uint16_t fragment:4;
	uint16_t sequence:12;
} __attribute__((__packed__));

struct mgmt_frame {
	struct frame_control fc;
	uint16_t duration;
	uint8_t  dest_mac[IFHWADDRLEN];
	uint8_t  src_mac[IFHWADDRLEN];
	uint8_t  bssid[IFHWADDRLEN];
	struct sequence_control sc;
	uint8_t  frame_body[];
} __attribute__((__packed__));

struct info_element {
	uint8_t id;
	uint8_t len;
	uint8_t info[];
} __attribute__((__packed__));

#define INFO_ELEMENT_ID_SSID	0
#define INFO_ELEMENT_ID_DS	3

struct beacon_frame_body {
	uint64_t timestamp;
	uint16_t interval;
	uint16_t capabilities;
	uint8_t  infos[];
} __attribute__((__packed__));


int send_deauth(struct iw_dev *dev, struct access_point *ap);
int read_ap_info(struct iw_dev *dev, struct ap_info *api);

#endif

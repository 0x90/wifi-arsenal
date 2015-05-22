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

#ifndef __LORCONINT_H__
#define __LORCONINT_H__

#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <pcap.h>

#include <lorcon.h>
#include <lorcon_packet.h>

/* This file is meant for use inside the lorcon library ONLY, apps should not
 * count on it existing or being consistent */

#define MAX_IFNAME_LEN		32

#define LORCON_WEPKEY_MAX	26

struct lorcon_wep {
	u_char bssid[6];
	u_char key[LORCON_WEPKEY_MAX];
	int len;

	struct lorcon_wep *next;
};
typedef struct lorcon_wep lorcon_wep_t;

struct lorcon {
	char drivername[32];

	char ifname[MAX_IFNAME_LEN];
	char vapname[MAX_IFNAME_LEN];

	pcap_t *pcap;

	/* Only capture_fd is assumed to be selectable */
	int inject_fd, ioctl_fd, capture_fd;

	int packets_sent;
	int packets_recv;

	int dlt;

	int channel;

	char errstr[LORCON_STATUS_MAX];

	uint8_t original_mac[6];

	int timeout_ms;

	void *auxptr;

	lorcon_handler handler_cb;
	void *handler_user;

	int (*close_cb)(lorcon_t *context);
	
	int (*openinject_cb)(lorcon_t *context);
	int (*openmon_cb)(lorcon_t *context);
	int (*openinjmon_cb)(lorcon_t *context);

	int (*setchan_cb)(lorcon_t *context, int chan);
	int (*getchan_cb)(lorcon_t *context);

	int (*sendpacket_cb)(lorcon_t *context, lorcon_packet_t *packet);
	int (*getpacket_cb)(lorcon_t *context, lorcon_packet_t **packet);

	int (*setdlt_cb)(lorcon_t *context, int dlt);
	int (*getdlt_cb)(lorcon_t *context);

	lorcon_wep_t *wepkeys;

	int (*getmac_cb)(lorcon_t *context, uint8_t **mac);
	int (*setmac_cb)(lorcon_t *context, int len, uint8_t *mac);
};

#endif

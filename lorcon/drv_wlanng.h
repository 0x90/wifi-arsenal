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

#ifndef __WGINJECT_H__
#define __WGINJECT_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef SYS_LINUX

#define ETH_P_80211_RAW        (ETH_P_ECONET + 1)

#include "tx80211.h"
#include <stdint.h>
#include <linux/types.h>
#include <linux/if.h>
#include <linux/wireless.h>

/* Thanks KoreK - borrowed from chopchop 0.1 */
struct wg80211_frame {
	uint8_t base[0];
	uint16_t fc;
	uint16_t dur_id;
	uint8_t mac1[6];
	uint8_t mac2[6];
	uint8_t mac3[6];
	uint16_t seq;
	uint8_t mac4[6];
	uint16_t data_len;
	uint8_t null[14];
	uint8_t data[0];
} __attribute__ ((packed));

int tx80211_wlanng_init(struct tx80211 *in_tx);
int tx80211_wlanng_capabilities();
int wginj_open(struct tx80211 *wginj);
int wginj_close(struct tx80211 *wginj);
int wginj_send(struct tx80211 *wginj, struct tx80211_packet *in_pkt);
int wginj_setchannel(struct tx80211 *wginj, int channel);
int wginj_getchannel(struct tx80211 *wginj);
int wginj_setmode(struct tx80211 *wginj, int mode);
int wginj_getmode(struct tx80211 *wginj);

#endif /* linux */

#endif

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

#include <lorcon.h>
#include <lorcon_int.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef __AJINJECT_H__
#define __AJINJECT_H__

#ifdef SYS_LINUX

#define USE_DRV_AIRJACK		1

int lorcon_airjack_init(lorcon_t *in_tx);
lorcon_driver_t *lorcon_airjack_listdriver(lorcon_driver_t *);

int aj_setmonitor(char *ifname, int rfmonset);
int aj_setmode(char *ifname, int mode);
int aj_setchannel(char *ifname, int channel);
int aj_setmac(char *ifname, uint8_t * mac);
int aj_xmitframe(char *ifname, uint8_t * xmit, int len, char * errstr);
int aj_recvframe(char *ifname, uint8_t * buf, int len);
int aj_ifupdown(char *ifname, int devup);
int aj_getsocket(char *ifname);

/* Function wrappers for tx80211 */
int ajinj_open(struct tx80211 *ajinj);
int ajinj_close(struct tx80211 *ajinj);
int ajinj_setchannel(struct tx80211 *ajinj, int channel);
int ajinj_setmode(struct tx80211 *ajinj, int mode);
int ajinj_getmode(struct tx80211 *ajinj);
int ajinj_getchannel(struct tx80211 *ajinj);
int ajinj_send(struct tx80211 *ajinj, struct tx80211_packet *in_pkt);

/* our device private ioctl calls */
#define SIOCAJSMODE		SIOCDEVPRIVATE
#define SIOCAJGMODE		SIOCAJSMODE + 1

struct aj_config {
	uint16_t mode;		/* mac port operating mode */
	uint8_t ownmac[6];		/* our mac address */
	uint8_t monitor;		/* are we in monitor mode */
	uint8_t channel;		/* channel to operate on... */
	uint8_t essid[33];		/* first byte is length */
};

#endif

#endif


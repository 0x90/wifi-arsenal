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

#ifndef __AIRPINJECT_H__
#define __AIRPINJECT_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef SYS_CYGWIN

int tx80211_airpcap_init(struct tx80211 *in_tx);
int tx80211_airpcap_capabilities();
int airpcap_open(struct tx80211 *in_tx);
int airpcap_send(struct tx80211 *in_tx, struct tx80211_packet *in_pkt);
int airpcap_setfuncmode(struct tx80211 *in_tx, int funcmode);
int airpcap_close(struct tx80211 *in_tx);
int airpcap_setmode(struct tx80211 *in_tx, int mode);
int airpcap_getmode(struct tx80211 *in_tx);
int airpcap_setchannel(struct tx80211 *in_tx, int channel);
int airpcap_getchannel(struct tx80211 *in_tx);


struct airpcap_data {
	PAirpcapHandle ad;
	char errstr[AIRPCAP_ERRBUF_SIZE];
};

#endif /* cygwin */

#endif

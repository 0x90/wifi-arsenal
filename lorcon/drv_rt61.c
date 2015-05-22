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

    Copyright (c) 2007 dragorn and Joshua Wright
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef SYS_LINUX

#include "rt61inject.h"
#include "wtinject.h"

int tx80211_rt61_init(struct tx80211 *in_tx)
{

	in_tx->capabilities = tx80211_rt61_capabilities();
	in_tx->open_callthrough = &rt61_open;
	in_tx->close_callthrough = &wtinj_close;
	in_tx->setmode_callthrough = &wtinj_setmode;
	in_tx->getmode_callthrough = &wtinj_getmode;
	in_tx->getchan_callthrough = &wtinj_getchannel;
	in_tx->setchan_callthrough = &wtinj_setchannel;
	in_tx->txpacket_callthrough = &wtinj_send;
	in_tx->setfuncmode_callthrough = &wtinj_setfuncmode;

	return 0;
}


int tx80211_rt61_capabilities()
{
	/* No sequence number spoofing support, overridden in firmware :( */
	return (TX80211_CAP_SNIFF | TX80211_CAP_TRANSMIT | 
			TX80211_CAP_BSSTIME |
			TX80211_CAP_FRAG | TX80211_CAP_CTRL |
			TX80211_CAP_DURID);
}

int rt61_open(struct tx80211 *in_tx)
{

	char errstr[TX80211_STATUS_MAX];

	/* Call private ioctl "rfmontx" to enable raw TX */
	if (iwconfig_set_intpriv(in_tx->ifname, "rfmontx", 1, 0, errstr) != 0) {
		snprintf(in_tx->errstr, TX80211_STATUS_MAX,
				"Error enabling rfmontx private ioctl: %s\n",
				errstr);
		return -1;
	}

	return(wtinj_open(in_tx));
}

#endif /* SYS_LINUX */

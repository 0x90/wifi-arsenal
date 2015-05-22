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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef SYS_LINUX

#include "rt2570inject.h"
#include "wtinject.h"

int tx80211_rt2570_init(struct tx80211 *in_tx)
{
	in_tx->capabilities = tx80211_rt2570_capabilities();
	in_tx->open_callthrough = &rt2570_open;
	in_tx->close_callthrough = &wtinj_close;
	in_tx->setmode_callthrough = &wtinj_setmode;
	in_tx->getmode_callthrough = &wtinj_getmode;
	in_tx->getchan_callthrough = &wtinj_getchannel;
	in_tx->setchan_callthrough = &wtinj_setchannel;
	in_tx->txpacket_callthrough = &rt2570_send;
	in_tx->setfuncmode_callthrough = &wtinj_setfuncmode;

	return 0;
}


int tx80211_rt2570_capabilities()
{
	/* No sequence number spoofing support, overridden in firmware :( */
	return (TX80211_CAP_SNIFF | TX80211_CAP_TRANSMIT | 
			TX80211_CAP_BSSTIME |
			TX80211_CAP_FRAG | TX80211_CAP_CTRL |
			TX80211_CAP_DURID);
}

int rt2570_open(struct tx80211 *in_tx)
{
	char errstr[TX80211_STATUS_MAX];

	/* Call rfmontx to enable raw tx.
	 * Some drivers prefer set_intpriv, others charpriv.  Try both.
	 */

	if (iwconfig_set_charpriv(in_tx->ifname, "rfmontx", "1", errstr) >= 0)
		return(wtinj_open(in_tx));

	if (iwconfig_set_intpriv(in_tx->ifname, "rfmontx", 1, 0, errstr) >= 0)
		return(wtinj_open(in_tx));

	/* If we reach this point, failed to enable rfmontx */	

	fprintf(stderr, "Error enabling rfmontx private ioctl: %s\n", errstr);
	return -1;
}

int rt2570_send(struct tx80211 *in_tx, struct tx80211_packet *in_pkt)
{

	int ret;

	if (!(in_tx->raw_fd > 0)) {
		/* file descriptor is not open */
		return 0;
	}

	ret = write(in_tx->raw_fd, in_pkt->packet, in_pkt->plen);

	/* With no delay, the rt2570 only sends < 1% of frames, by adding
	   this (nominal) delay, we get consistent 100% TX */
	usleep(2);

	if (ret < 0)
		return TX80211_ENOTX;
	if (ret < (in_pkt->plen))
		return TX80211_EPARTTX;
	return (ret);
}

#endif /* linux */


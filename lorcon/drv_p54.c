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

#include "p54inject.h"
#include "wtinject.h"

int tx80211_prism54_init(struct tx80211 *in_tx)
{

	in_tx->capabilities = tx80211_prism54_capabilities();
	in_tx->open_callthrough = &wtinj_open;
	in_tx->close_callthrough = &wtinj_close;
	in_tx->setmode_callthrough = &wtinj_setmode;
	in_tx->getmode_callthrough = &wtinj_getmode;
	in_tx->getchan_callthrough = &wtinj_getchannel;
	in_tx->setchan_callthrough = &wtinj_setchannel;
	in_tx->txpacket_callthrough = &wtinj_send;
	in_tx->setfuncmode_callthrough = &wtinj_setfuncmode;
	in_tx->selfack_callthrough = &wtinj_selfack;

	return 0;
}

int tx80211_prism54_capabilities()
{
	return (TX80211_CAP_SNIFF | TX80211_CAP_TRANSMIT |
		TX80211_CAP_SEQ | TX80211_CAP_BSSTIME |
		TX80211_CAP_FRAG | TX80211_CAP_DURID |
		TX80211_CAP_SNIFFACK | TX80211_CAP_DSSSTX |
		TX80211_CAP_SELFACK | TX80211_CAP_CTRL);
}

#endif /* linux */

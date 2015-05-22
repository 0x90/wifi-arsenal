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

#include "zd1211rwinject.h"
#include "wtinject.h"

int tx80211_zd1211rw_init(struct tx80211 *in_tx)
{
	in_tx->capabilities = tx80211_zd1211rw_capabilities();
	in_tx->open_callthrough = &wtinj_open;
	in_tx->close_callthrough = &wtinj_close;
	in_tx->setmode_callthrough = &wtinj_setmode;
	in_tx->getmode_callthrough = &wtinj_getmode;
	in_tx->getchan_callthrough = &wtinj_getchannel;
	in_tx->setchan_callthrough = &wtinj_setchannel;
	in_tx->txpacket_callthrough = &tx80211_zd1211rw_send;
	in_tx->setfuncmode_callthrough = &wtinj_setfuncmode;

	return 0;
}

int tx80211_zd1211rw_capabilities()
{
	return (TX80211_CAP_SNIFF | TX80211_CAP_TRANSMIT |
		TX80211_CAP_SEQ | TX80211_CAP_BSSTIME |
		TX80211_CAP_FRAG | TX80211_CAP_DURID |
		TX80211_CAP_SNIFFACK | TX80211_CAP_DSSSTX);
}

int tx80211_zd1211rw_send(struct tx80211 *in_tx, struct tx80211_packet *in_pkt)
{
	struct tx80211_packet mwng_pkt;
	struct tx80211_radiotap_header *rtaphdr;
	uint8_t *pkt;
	int len, channel, sendcount;

	memset(&mwng_pkt, 0, sizeof(mwng_pkt));
	len = (in_pkt->plen + TX80211_RTAP_LEN);

	pkt = malloc(len);
	if (pkt == NULL) {
		snprintf(in_tx->errstr, TX80211_STATUS_MAX, 
				"Unable to allocate memory buffer "
				"for send function");
		return -1;
	}

	memset(pkt, 0, len);

	channel = tx80211_getchannel(in_tx);

	/* Setup radiotap header */
	rtaphdr = (struct tx80211_radiotap_header *)pkt;
	rtaphdr->it_version = 0;
	rtaphdr->it_pad = 0;
	rtaphdr->it_len = tx80211_le16(TX80211_RTAP_LEN);
	rtaphdr->it_present = tx80211_le32(TX80211_RTAP_PRESENT);
	rtaphdr->wr_flags = 0;
	rtaphdr->wr_rate = in_pkt->txrate; /* 0 if not set for default */
	rtaphdr->wr_chan_freq = tx80211_chan2mhz(channel);

	switch(in_pkt->modulation) {
		case TX80211_MOD_DEFAULT:
			rtaphdr->wr_chan_flags = 0;
			break;
		case TX80211_MOD_DSSS:
			rtaphdr->wr_chan_flags =
				tx80211_le16(TX80211_RTAP_CHAN_B);
			break;
		case TX80211_MOD_OFDM:
			/* OFDM can be 802.11g or 802.11a */
			if (channel <= 14) {
				/* 802.11g network */
				rtaphdr->wr_chan_flags = 
					tx80211_le16(TX80211_RTAP_CHAN_G);
			} else {
				rtaphdr->wr_chan_flags = 
					tx80211_le16(TX80211_RTAP_CHAN_A);
			}
			break;
		case TX80211_MOD_TURBO:
			/* Turbo can be 802.11g or 802.11a */
			if (channel <= 14) {
				/* 802.11g network */
				rtaphdr->wr_chan_flags = 
					tx80211_le16(TX80211_RTAP_CHAN_TG);
			} else {
				rtaphdr->wr_chan_flags = 
					tx80211_le16(TX80211_RTAP_CHAN_TA);
			}
			break;
		default:
			snprintf(in_tx->errstr, TX80211_STATUS_MAX, 
					"Unsupported modulation mechanism "
					"specified in send function.");
			return TX80211_ENOTSUPP;
	}

	memcpy(pkt + TX80211_RTAP_LEN, in_pkt->packet, in_pkt->plen);

	mwng_pkt.packet = pkt;
	mwng_pkt.plen = len;

	sendcount = wtinj_send(in_tx, &mwng_pkt);
	free(pkt);

	if (sendcount < 0) {
		return TX80211_ENOTX;
	} else if (sendcount != mwng_pkt.plen) {
		snprintf(in_tx->errstr, TX80211_STATUS_MAX,
			"Error sending packet data, partial write.");
		return TX80211_EPARTTX;
	} else {
		return (sendcount);
	}
}

#endif /* linux */

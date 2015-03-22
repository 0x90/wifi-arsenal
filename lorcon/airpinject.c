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

#ifdef SYS_CYGWIN

#include <windows.h>
#include <airpcap.h>
#include "tx80211.h"
#include "tx80211_errno.h"
#include "airpinject.h"

int tx80211_airpcap_init(struct tx80211 *in_tx)
{

	struct airpcap_data *apcap = in_tx->extra;

	in_tx->capabilities = tx80211_airpcap_capabilities();
	in_tx->open_callthrough = &airpcap_open;
	in_tx->close_callthrough = &airpcap_close;
	in_tx->setmode_callthrough = &airpcap_setmode;
	in_tx->getmode_callthrough = &airpcap_getmode;
	in_tx->getchan_callthrough = &airpcap_getchannel;
	in_tx->setchan_callthrough = &airpcap_setchannel;
	in_tx->txpacket_callthrough = &airpcap_send;
	in_tx->setfuncmode_callthrough = &airpcap_setfuncmode;
	in_tx->selfack_callthrough = NULL;
	

	/* Allocate memory for the airpcap_data structure */
	in_tx->extra = malloc(sizeof(struct airpcap_data));
	if (in_tx->extra == NULL) {
		snprintf(in_tx->errstr, TX80211_STATUS_MAX, 
				"Unable to allocate memory for initialization data.");
		return TX80211_ENOMEM;
	}

	apcap = in_tx->extra;
	apcap->ad = AirpcapOpen(in_tx->ifname, apcap->errstr);
	if(!apcap->ad)
	{
		snprintf(in_tx->errstr, TX80211_STATUS_MAX,
				"Error opening the adapter: %s\n", 
				apcap->errstr);
		return -1;
	}


	return TX80211_ENOERR;
}

int airpcap_close(struct tx80211 *in_tx)
{
	if (in_tx->extra != NULL) {
		free(in_tx->extra);
	}
	return close(in_tx->raw_fd);
}



int tx80211_airpcap_capabilities()
{
	return (TX80211_CAP_SNIFF | TX80211_CAP_TRANSMIT |
		TX80211_CAP_SETMODULATION | TX80211_CAP_SETRATE);
	/* Capabilities TBD */
	/*	TX80211_CAP_SEQ |  
		TX80211_CAP_BSSTIME |
		TX80211_CAP_FRAG | TX80211_CAP_CTRL | 
		TX80211_CAP_DURID | TX80211_CAP_SNIFFACK | 
		TX80211_CAP_DSSSTX | TX80211_CAP_OFDMTX |
		TX80211_CAP_SELFACK | TX80211_CAP_SETRATE |
	*/		
}


int airpcap_open(struct tx80211 *in_tx)
{

	struct airpcap_data *apcap = in_tx->extra;
	apcap->ad = AirpcapOpen(in_tx->ifname, apcap->errstr);
	if (apcap->ad == NULL) {
		snprintf(in_tx->errstr, TX80211_STATUS_MAX,
				"Unable to open airpcap interface: %s",
				apcap->errstr);
		return TX80211_ENOOPENINT;
	}

	/* Set the link type to standard 802.11 header */
	if (!AirpcapSetLinkType(apcap->ad, AIRPCAP_LT_802_11_PLUS_RADIO)) {
		snprintf(in_tx->errstr, TX80211_STATUS_MAX,
				"Unable to set airpcap link type: %s",
				AirpcapGetLastError(apcap->ad));
		return TX80211_ENOOPENINT;
	}

	return TX80211_ENOERR;
}

int airpcap_setmode(struct tx80211 *in_tx, int mode)
{
	if (mode == TX80211_MODE_MONITOR) {
		return TX80211_ENOERR;
	}	
	return TX80211_ENOTSUPP;
}

int airpcap_getmode(struct tx80211 *in_tx)
{
	return TX80211_MODE_MONITOR;
}

int airpcap_setchannel(struct tx80211 *in_tx, int channel)
{
	struct airpcap_data *apcap = in_tx->extra;

	if (AirpcapSetDeviceChannel(apcap->ad, (unsigned int)channel) != 1) {
		return TX80211_ENOCHANSET;
	}

	return TX80211_ENOERR;
}

int airpcap_getchannel(struct tx80211 *in_tx)
{
	struct airpcap_data *apcap = in_tx->extra;
	unsigned int channel;

	if (AirpcapGetDeviceChannel(apcap->ad, &channel) != 1) {
		return TX80211_ENOCHANSET;
	}

	return channel;
}

int airpcap_setfuncmode(struct tx80211 *in_tx, int funcmode)
{
	switch(funcmode) {
	case TX80211_FUNCMODE_RFMON:
	case TX80211_FUNCMODE_INJECT:
	case TX80211_FUNCMODE_INJMON:
		return TX80211_ENOERR;
	default:
		return TX80211_ENOTSUPP;
	}
}

int airpcap_send(struct tx80211 *in_tx, struct tx80211_packet *in_pkt)
{
	struct airpcap_data *apcap = in_tx->extra;
	struct tx80211_radiotap_header *rtaphdr;
	PCHAR pkt;
	int channel;
	ULONG len;

	len = (in_pkt->plen + TX80211_RTAP_LEN);

	pkt = malloc(len);
	if (pkt == NULL) {
		snprintf(in_tx->errstr, TX80211_STATUS_MAX, 
				"Unable to allocate memory buffer "
				"for send function");
		return TX80211_ENOMEM;
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

	if (in_pkt->txrate == 0) {
		/* Airpcap can't handle a rate of 0, set to 2 Mbps as default */
		rtaphdr->wr_rate = TX80211_RATE_2MB;
	} else {
		rtaphdr->wr_rate = in_pkt->txrate; 
	}

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

	if (AirpcapWrite(apcap->ad, pkt, len) != 1) {
		free(pkt);
		snprintf(in_tx->errstr, TX80211_STATUS_MAX,
				"Error sending packet: %s",
				AirpcapGetLastError(apcap->ad));
		return TX80211_ETXFAILED;
	}

	free(pkt);
	return (len - TX80211_RTAP_LEN);
}


#endif /* cygwin */

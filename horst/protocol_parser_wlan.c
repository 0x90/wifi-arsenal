/* horst - Highly Optimized Radio Scanning Tool
 *
 * Copyright (C) 2005-2014 Bruno Randolf (br1@einfach.org)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if_arp.h>

#include "prism_header.h"
#include "radiotap/radiotap.h"
#include "radiotap/radiotap_iter.h"
#include "wlan80211.h"
#include "wlan_util.h"
#include "main.h"
#include "util.h"

static int parse_prism_header(unsigned char** buf, int len, struct packet_info* p);
static int parse_radiotap_header(unsigned char** buf, int len, struct packet_info* p);
static int parse_80211_header(unsigned char** buf, int len, struct packet_info* p);


/* return rest of packet length (may be 0) or negative value on error */
int
parse_packet_wlan(unsigned char** buf, int len, struct packet_info* p)
{
	if (conf.arphrd == ARPHRD_IEEE80211_PRISM) {
		len = parse_prism_header(buf, len, p);
		if (len <= 0)
			return -1;
	}
	else if (conf.arphrd == ARPHRD_IEEE80211_RADIOTAP) {
		len = parse_radiotap_header(buf, len, p);
		if (len <= 0) {/* 0: Bad FCS, allow packet but stop parsing */
			DEBUG("A");
			return len;
		}
	}

	DEBUG("before parse 80211 len: %d\n", len);
	return parse_80211_header(buf, len, p);
}


/* return packet lenght or -1 on error */
static int
parse_prism_header(unsigned char** buf, int len, struct packet_info* p)
{
	wlan_ng_prism2_header* ph;

	DEBUG("PRISM2 HEADER\n");

	if (len > 0 && (size_t)len < sizeof(wlan_ng_prism2_header))
		return -1;

	ph = (wlan_ng_prism2_header*)*buf;

	/*
	 * different drivers report S/N and rssi values differently
	*/
	if (((int)ph->noise.data) < 0) {
		/* new madwifi */
		p->phy_signal = ph->signal.data;
	}
	else if (((int)ph->rssi.data) < 0) {
		/* broadcom hack */
		p->phy_signal = ph->rssi.data;
	}
	else {
		/* assume hostap */
		p->phy_signal = ph->signal.data;
	}

	p->phy_rate = ph->rate.data * 10;

	/* just in case...*/
	if (p->phy_rate == 0 || p->phy_rate > 1080) {
		/* assume min rate, guess mode from channel */
		DEBUG("*** fixing wrong rate\n");
		if (ph->channel.data > 14)
			p->phy_rate = 120; /* 6 * 2 */
		else
			p->phy_rate = 20; /* 1 * 2 */
	}

	p->phy_rate_idx = rate_to_index(p->phy_rate);

	/* guess phy mode */
	if (ph->channel.data > 14)
		p->phy_flags |= PHY_FLAG_A;
	else
		p->phy_flags |= PHY_FLAG_G;
	/* always assume shortpre */
	p->phy_flags |= PHY_FLAG_SHORTPRE;

	DEBUG("devname: %s\n", ph->devname);
	DEBUG("signal: %d -> %d\n", ph->signal.data, p->phy_signal);
	DEBUG("rate: %d\n", ph->rate.data);
	DEBUG("rssi: %d\n", ph->rssi.data);

	*buf = *buf + sizeof(wlan_ng_prism2_header);
	return len - sizeof(wlan_ng_prism2_header);
}


static void
get_radiotap_info(struct ieee80211_radiotap_iterator *iter, struct packet_info* p)
{
	uint16_t x;
	signed char c;
	unsigned char known, flags, ht20, lgi;

	switch (iter->this_arg_index) {
	/* ignoring these */
	case IEEE80211_RADIOTAP_TSFT:
	case IEEE80211_RADIOTAP_FHSS:
	case IEEE80211_RADIOTAP_LOCK_QUALITY:
	case IEEE80211_RADIOTAP_TX_ATTENUATION:
	case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
	case IEEE80211_RADIOTAP_DBM_TX_POWER:
	case IEEE80211_RADIOTAP_TX_FLAGS:
	case IEEE80211_RADIOTAP_RX_FLAGS:
	case IEEE80211_RADIOTAP_RTS_RETRIES:
	case IEEE80211_RADIOTAP_DATA_RETRIES:
	case IEEE80211_RADIOTAP_AMPDU_STATUS:
		break;
	case IEEE80211_RADIOTAP_FLAGS:
		/* short preamble */
		DEBUG("[flags %0x", *iter->this_arg);
		if (*iter->this_arg & IEEE80211_RADIOTAP_F_SHORTPRE) {
			p->phy_flags |= PHY_FLAG_SHORTPRE;
			DEBUG(" shortpre");
		}
		if (*iter->this_arg & IEEE80211_RADIOTAP_F_BADFCS) {
			p->phy_flags |= PHY_FLAG_BADFCS;
			p->pkt_types |= PKT_TYPE_BADFCS;
			DEBUG(" badfcs");
		}
		DEBUG("]");
		break;
	case IEEE80211_RADIOTAP_RATE:
		//TODO check!
		//printf("\trate: %lf\n", (double)*iter->this_arg/2);
		DEBUG("[rate %0x]", *iter->this_arg);
		p->phy_rate = (*iter->this_arg)*5; /* rate is in 500kbps */
		p->phy_rate_idx = rate_to_index(p->phy_rate);
		break;
#define IEEE80211_CHAN_A \
	(IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM)
#define IEEE80211_CHAN_G \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_OFDM)
	case IEEE80211_RADIOTAP_CHANNEL:
		/* channel & channel type */
		p->phy_freq = le16toh(*(uint16_t*)iter->this_arg);
		DEBUG("[freq %d", p->phy_freq);
		iter->this_arg = iter->this_arg + 2;
		x = le16toh(*(uint16_t*)iter->this_arg);
		if ((x & IEEE80211_CHAN_A) == IEEE80211_CHAN_A) {
			p->phy_flags |= PHY_FLAG_A;
			DEBUG("A]");
		}
		else if ((x & IEEE80211_CHAN_G) == IEEE80211_CHAN_G) {
			p->phy_flags |= PHY_FLAG_G;
			DEBUG("G]");
		}
		else if ((x & IEEE80211_CHAN_2GHZ) == IEEE80211_CHAN_2GHZ) {
			p->phy_flags |= PHY_FLAG_B;
			DEBUG("B]");
		}
		break;
	case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
		c = *(signed char*)iter->this_arg;
		DEBUG("[sig %0d]", c);
		/* we get the signal per rx chain with newer drivers.
		 * save the highest value, but make sure we don't override
		 * with invalid values */
		if (c < 0 && (p->phy_signal == 0 || c > p->phy_signal))
			p->phy_signal = c;
		break;
	case IEEE80211_RADIOTAP_DBM_ANTNOISE:
		DEBUG("[noi %0x]", *(signed char*)iter->this_arg);
		// usually not present
		//p->phy_noise = *(signed char*)iter->this_arg;
		break;
	case IEEE80211_RADIOTAP_ANTENNA:
		DEBUG("[ant %0x]", *iter->this_arg);
		break;
	case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
		DEBUG("[snr %0x]", *iter->this_arg);
		// usually not present
		//p->phy_snr = *iter->this_arg;
		break;
	case IEEE80211_RADIOTAP_DB_ANTNOISE:
		//printf("\tantnoise: %02d\n", *iter->this_arg);
		break;
	case IEEE80211_RADIOTAP_MCS:
		/* Ref http://www.radiotap.org/defined-fields/MCS */
		known = *iter->this_arg++;
		flags = *iter->this_arg++;
		DEBUG("[MCS known %0x flags %0x index %0x]", known, flags, *iter->this_arg);
		if (known & IEEE80211_RADIOTAP_MCS_HAVE_BW)
			ht20 = (flags & IEEE80211_RADIOTAP_MCS_BW_MASK) == IEEE80211_RADIOTAP_MCS_BW_20;
		else
			ht20 = 1; /* assume HT20 if not present */

		if (known & IEEE80211_RADIOTAP_MCS_HAVE_GI)
			lgi = !(flags & IEEE80211_RADIOTAP_MCS_SGI);
		else
			lgi = 1; /* assume long GI if not present */

		DEBUG(" %s %s", ht20 ? "HT20" : "HT40", lgi ? "LGI" : "SGI");

		p->phy_rate_idx = 12 + *iter->this_arg;
		p->phy_rate_flags = flags;
		p->phy_rate = mcs_index_to_rate(*iter->this_arg, ht20, lgi);

		DEBUG(" RATE %d ", p->phy_rate);
		break;
	default:
		printlog("UNKNOWN RADIOTAP field %d", iter->this_arg_index);
		break;
	}
}


/* return length of packet, 0 for bad FCS, -1 on error */
static int
parse_radiotap_header(unsigned char** buf, int len, struct packet_info* p)
{
	struct ieee80211_radiotap_header* rh;
	struct ieee80211_radiotap_iterator iter;
	int err, rt_len;

	rh = (struct ieee80211_radiotap_header*)*buf;
	rt_len = le16toh(rh->it_len);

	err = ieee80211_radiotap_iterator_init(&iter, rh, rt_len, NULL);
	if (err) {
		DEBUG("malformed radiotap header (init returns %d)\n", err);
		return -1;
	}

	DEBUG("Radiotap: ");
	while (!(err = ieee80211_radiotap_iterator_next(&iter))) {
		if (iter.is_radiotap_ns) {
			get_radiotap_info(&iter, p);
		}
	}

	DEBUG("\nSIG %d", p->phy_signal);

	/* sanitize */
	if (p->phy_rate == 0 || p->phy_rate > 6000) {
		/* assume min rate for mode */
		DEBUG("*** fixing wrong rate\n");
		if (p->phy_flags & PHY_FLAG_A)
			p->phy_rate = 120; /* 6 * 2 */
		else if (p->phy_flags & PHY_FLAG_B)
			p->phy_rate = 20; /* 1 * 2 */
		else if (p->phy_flags & PHY_FLAG_G)
			p->phy_rate = 120; /* 6 * 2 */
		else
			p->phy_rate = 20;
	}

	DEBUG("\nrate: %.2f = idx %d\n", (float)p->phy_rate/10, p->phy_rate_idx);
	DEBUG("signal: %d\n", p->phy_signal);

	if (p->phy_flags & PHY_FLAG_BADFCS) {
		/* we can't trust frames with a bad FCS - stop parsing */
		DEBUG("=== bad FCS, stop ===\n");
		return 0;
	} else {
		*buf = *buf + rt_len;
		return len - rt_len;
	}
}


/* return rest of packet length (may be 0) or -1 on error */
static int
parse_80211_header(unsigned char** buf, int len, struct packet_info* p)
{
	struct wlan_frame* wh;
	int hdrlen;
	u_int8_t* ra = NULL;
	u_int8_t* ta = NULL;
	u_int8_t* bssid = NULL;
	u_int16_t fc, cap_i;

	if (len < 10) /* minimum frame size (CTS/ACK) */
		return -1;

	p->wlan_mode = WLAN_MODE_UNKNOWN;

	wh = (struct wlan_frame*)*buf;

	fc = le16toh(wh->fc);
	p->wlan_type = (fc & WLAN_FRAME_FC_MASK);
	DEBUG("wlan_type %x - type %x - stype %x\n", fc, fc & WLAN_FRAME_FC_TYPE_MASK, fc & WLAN_FRAME_FC_STYPE_MASK);
	DEBUG("%s\n", get_packet_type_name(fc));

	if (WLAN_FRAME_IS_DATA(fc)) {
		p->pkt_types |= PKT_TYPE_DATA;

		hdrlen = 24;
		if (WLAN_FRAME_IS_QOS(fc)) {
			hdrlen += 2;
			if (fc & WLAN_FRAME_FC_ORDER)
				hdrlen += 4;
		}

		/* AP, STA or IBSS */
		if ((fc & WLAN_FRAME_FC_FROM_DS) == 0 &&
		    (fc & WLAN_FRAME_FC_TO_DS) == 0) {
			p->wlan_mode = WLAN_MODE_IBSS;
			bssid = wh->addr3;
		} else if ((fc & WLAN_FRAME_FC_FROM_DS) &&
			   (fc & WLAN_FRAME_FC_TO_DS)) {
			p->wlan_mode = WLAN_MODE_4ADDR;
			hdrlen += 6;
			if (WLAN_FRAME_IS_QOS(fc)) {
				u_int16_t qos = le16toh(wh->u.addr4_qos_ht.qos);
				DEBUG("4ADDR A-MSDU %x\n", qos & WLAN_FRAME_QOS_AMSDU_PRESENT);
				if (qos & WLAN_FRAME_QOS_AMSDU_PRESENT)
					bssid = wh->addr3;
				// in the MSDU case BSSID is unknown
			}
		} else if (fc & WLAN_FRAME_FC_FROM_DS) {
			p->wlan_mode = WLAN_MODE_AP;
			bssid = wh->addr2;
		} else if (fc & WLAN_FRAME_FC_TO_DS) {
			p->wlan_mode = WLAN_MODE_STA;
			bssid = wh->addr1;
		}

		if (len < hdrlen)
			return -1;

		p->wlan_nav = le16toh(wh->duration);
		DEBUG("DATA NAV %d\n", p->wlan_nav);
		p->wlan_seqno = le16toh(wh->seq);
		DEBUG("DATA SEQ %d\n", p->wlan_seqno);

		DEBUG("A1 %s\n", ether_sprintf(wh->addr1));
		DEBUG("A2 %s\n", ether_sprintf(wh->addr2));
		DEBUG("A3 %s\n", ether_sprintf(wh->addr3));
		if (p->wlan_mode == WLAN_MODE_4ADDR) {
			DEBUG("A4 %s\n", ether_sprintf(wh->u.addr4));
		}
		DEBUG("ToDS %d FromDS %d\n", (fc & WLAN_FRAME_FC_FROM_DS) != 0, (fc & WLAN_FRAME_FC_TO_DS) != 0);

		ra = wh->addr1;
		ta = wh->addr2;

		/* WEP */
		if (fc & WLAN_FRAME_FC_PROTECTED)
			p->wlan_wep = 1;

		if (fc & WLAN_FRAME_FC_RETRY)
			p->wlan_retry = 1;

	} else if (WLAN_FRAME_IS_CTRL(fc)) {
		p->pkt_types |= PKT_TYPE_CTRL;

		if (p->wlan_type == WLAN_FRAME_CTS ||
		    p->wlan_type == WLAN_FRAME_ACK)
			hdrlen = 10;
		else
			hdrlen = 16;

		if (len < hdrlen)
			return -1;

	} else if (WLAN_FRAME_IS_MGMT(fc)) {
		p->pkt_types |= PKT_TYPE_MGMT;

		hdrlen = 24;
		if (fc & WLAN_FRAME_FC_ORDER)
			hdrlen += 4;

		if (len < hdrlen)
			return -1;

		ra = wh->addr1;
		ta = wh->addr2;
		bssid = wh->addr3;
		p->wlan_seqno = le16toh(wh->seq);
		DEBUG("MGMT SEQ %d\n", p->wlan_seqno);

		if (fc & WLAN_FRAME_FC_RETRY)
			p->wlan_retry = 1;
	} else {
		DEBUG("!!!UNKNOWN FRAME!!!");
		return -1;
	}

	p->wlan_len = len;

	switch (p->wlan_type) {
		case WLAN_FRAME_NULL:
			p->pkt_types |= PKT_TYPE_NULL;
			break;

		case WLAN_FRAME_QDATA:
			p->pkt_types |= PKT_TYPE_QDATA;
			p->wlan_qos_class = le16toh(wh->u.qos) & WLAN_FRAME_QOS_TID_MASK;
			DEBUG("***QDATA %x\n", p->wlan_qos_class);
			break;

		case WLAN_FRAME_RTS:
			p->pkt_types |= PKT_TYPE_RTSCTS;
			p->wlan_nav = le16toh(wh->duration);
			DEBUG("RTS NAV %d\n", p->wlan_nav);
			ra = wh->addr1;
			ta = wh->addr2;
			break;

		case WLAN_FRAME_CTS:
			p->pkt_types |= PKT_TYPE_RTSCTS;
			p->wlan_nav = le16toh(wh->duration);
			DEBUG("CTS NAV %d\n", p->wlan_nav);
			ra = wh->addr1;
			break;

		case WLAN_FRAME_ACK:
			p->pkt_types |= PKT_TYPE_ACK;
			p->wlan_nav = le16toh(wh->duration);
			DEBUG("ACK NAV %d\n", p->wlan_nav);
			ra = wh->addr1;
			break;

		case WLAN_FRAME_PSPOLL:
			ra = wh->addr1;
			bssid = wh->addr1;
			ta = wh->addr2;
			break;

		case WLAN_FRAME_CF_END:
		case WLAN_FRAME_CF_END_ACK:
			ra = wh->addr1;
			ta = wh->addr2;
			bssid = wh->addr2;
			break;

		case WLAN_FRAME_BLKACK:
		case WLAN_FRAME_BLKACK_REQ:
			p->pkt_types |= PKT_TYPE_ACK;
			p->wlan_nav = le16toh(wh->duration);
			ra = wh->addr1;
			ta = wh->addr2;
			break;

		case WLAN_FRAME_BEACON:
		case WLAN_FRAME_PROBE_RESP:
			if (p->wlan_type == WLAN_FRAME_BEACON)
				p->pkt_types |= PKT_TYPE_BEACON;
			else
				p->pkt_types |= PKT_TYPE_PROBE;
			struct wlan_frame_beacon* bc = (struct wlan_frame_beacon*)(*buf + hdrlen);
			p->wlan_tsf = le64toh(bc->tsf);
			p->wlan_bintval = le16toh(bc->bintval);
			//DEBUG("TSF %u\n BINTVAL %u", p->wlan_tsf, p->wlan_bintval);

			wlan_parse_information_elements(bc->ie,
				len - hdrlen - sizeof(struct wlan_frame_beacon) - 4 /* FCS */, p);
			DEBUG("ESSID %s \n", p->wlan_essid );
			DEBUG("CHAN %d \n", p->wlan_channel );
			cap_i = le16toh(bc->capab);
			if (cap_i & WLAN_CAPAB_IBSS)
				p->wlan_mode = WLAN_MODE_IBSS;
			else if (cap_i & WLAN_CAPAB_ESS)
				p->wlan_mode = WLAN_MODE_AP;
			if (cap_i & WLAN_CAPAB_PRIVACY)
				p->wlan_wep = 1;
			break;

		case WLAN_FRAME_PROBE_REQ:
			p->pkt_types |= PKT_TYPE_PROBE;
			wlan_parse_information_elements((*buf + hdrlen),
				len - hdrlen - 4 /* FCS */, p);
			p->wlan_mode = WLAN_MODE_PROBE;
			break;

		case WLAN_FRAME_ASSOC_REQ:
		case WLAN_FRAME_ASSOC_RESP:
		case WLAN_FRAME_REASSOC_REQ:
		case WLAN_FRAME_REASSOC_RESP:
		case WLAN_FRAME_DISASSOC:
			p->pkt_types |= PKT_TYPE_ASSOC;
			break;

		case WLAN_FRAME_AUTH:
			if (fc & WLAN_FRAME_FC_PROTECTED)
				p->wlan_wep = 1;
				/* no break */
		case WLAN_FRAME_DEAUTH:
			p->pkt_types |= PKT_TYPE_AUTH;
			break;

		case WLAN_FRAME_ACTION:
			break;
	}

	if (ta != NULL) {
		memcpy(p->wlan_src, ta, MAC_LEN);
		DEBUG("TA    %s\n", ether_sprintf(ta));
	}
	if (ra != NULL) {
		memcpy(p->wlan_dst, ra, MAC_LEN);
		DEBUG("RA    %s\n", ether_sprintf(ra));
	}
	if (bssid != NULL) {
		memcpy(p->wlan_bssid, bssid, MAC_LEN);
		DEBUG("BSSID %s\n", ether_sprintf(bssid));
	}

	/* only data frames contain more info, otherwise stop parsing */
	if (WLAN_FRAME_IS_DATA(p->wlan_type) && p->wlan_wep != 1) {
		*buf = *buf + hdrlen;
		return len - hdrlen;
	}
	return 0;
}

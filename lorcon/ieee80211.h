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

#ifndef __IEEE80211_H__
#define __IEEE80211_H__

/* Packet types and reason codes copied from various 
   sources (ieee docs and significant copying from the
   hostapd common defines) */

#define BIT(x) (1 << (x))

#define WLAN_FC_FRAMETYPE(x)		(((x) & 0xC) >> 2)
#define WLAN_FC_FRAMESUBTYPE(x)		(((x) & 0xF0) >> 4)

#define WLAN_FC_TYPE_MGMT 0
#define WLAN_FC_TYPE_CTRL 1
#define WLAN_FC_TYPE_DATA 2

/* mgmt subtypes */
#define WLAN_FC_SUBTYPE_ASSOCREQ    0
#define WLAN_FC_SUBTYPE_ASSOCRESP   1
#define WLAN_FC_SUBTYPE_REASSOCREQ  2
#define WLAN_FC_SUBTYPE_REASSOCRESP 3
#define WLAN_FC_SUBTYPE_PROBEREQ    4
#define WLAN_FC_SUBTYPE_PROBERESP   5
#define WLAN_FC_SUBTYPE_BEACON      8
#define WLAN_FC_SUBTYPE_ATIM        9
#define WLAN_FC_SUBTYPE_DISASSOC    10
#define WLAN_FC_SUBTYPE_AUTH        11
#define WLAN_FC_SUBTYPE_DEAUTH      12

/* phy subtypes */
#define WLAN_FC_SUBTYPE_PSPOLL      10
#define WLAN_FC_SUBTYPE_RTS         11
#define WLAN_FC_SUBTYPE_CTS         12
#define WLAN_FC_SUBTYPE_ACK         13
#define WLAN_FC_SUBTYPE_CFEND       14
#define WLAN_FC_SUBTYPE_CFENDACK    15

/* data subtypes */
#define WLAN_FC_SUBTYPE_DATA            0
#define WLAN_FC_SUBTYPE_DATACFACK       1
#define WLAN_FC_SUBTYPE_DATACFPOLL      2
#define WLAN_FC_SUBTYPE_DATACFACKPOLL   3
#define WLAN_FC_SUBTYPE_DATANULL        4
#define WLAN_FC_SUBTYPE_CFACK           5
#define WLAN_FC_SUBTYPE_CFACKPOLL       6
#define WLAN_FC_SUBTYPE_CFACKPOLLNODATA 7
#define WLAN_FC_SUBTYPE_QOSDATA	        8
#define WLAN_FC_SUBTYPE_QOSDATACFACK	9
#define WLAN_FC_SUBTYPE_QOSDATACFPOLL	10
#define WLAN_FC_SUBTYPE_QOSDATACFACKPOLL	11
#define WLAN_FC_SUBTYPE_QOSNULL	        12

/* Framecontrol flags */
#define WLAN_FC_TODS                BIT(0)
#define WLAN_FC_FROMDS              BIT(1)
#define WLAN_FC_MOREFRAG            BIT(2)
#define WLAN_FC_RETRY               BIT(3)
#define WLAN_FC_PWRMGT              BIT(4)
#define WLAN_FC_MOREDATA            BIT(5)
#define WLAN_FC_ISWEP               BIT(6)
#define WLAN_FC_ORDER               BIT(7)

/* Auth stuff */
#define WLAN_AUTH_OPEN              0
#define WLAN_AUTH_SHARED_KEY        1
#define WLAN_AUTH_CHALLENGE_LEN     128

/* 802.11 capabilities */
#define WLAN_CAPABILITY_ESS         BIT(0)
#define WLAN_CAPABILITY_IBSS        BIT(1)
#define WLAN_CAPABILITY_CF_POLLABLE BIT(2)
#define WLAN_CAPABILITY_CF_POLL_REQUEST BIT(3)
#define WLAN_CAPABILITY_PRIVACY     BIT(4)
#define WLAN_CAPABILITY_SHORTPRE    BIT(5)

/* Reason codes */
#define WLAN_REASON_UNSPECIFIED                     1
#define WLAN_REASON_PREV_AUTH_NOT_VALID             2
#define WLAN_REASON_DEAUTH_LEAVING                  3
#define WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY      4
#define WLAN_REASON_DISASSOC_AP_BUSY                5
#define WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA   6
#define WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA  7
#define WLAN_REASON_DISASSOC_STA_HAS_LEFT           8
#define WLAN_REASON_STA_REQ_ASSOC_WITHOUT_AUTH      9

/* Status codes */
#define WLAN_STATUS_SUCCESS                     0
#define WLAN_STATUS_UNSPECIFIED_FAILURE         1
#define WLAN_STATUS_CAPS_UNSUPPORTED            10
#define WLAN_STATUS_REASSOC_NO_ASSOC            11
#define WLAN_STATUS_ASSOC_DENIED_UNSPEC         12
#define WLAN_STATUS_NOT_SUPPORTED_AUTH_ALG      13
#define WLAN_STATUS_UNKNOWN_AUTH_TRANSACTION    14
#define WLAN_STATUS_CHALLENGE_FAIL              15
#define WLAN_STATUS_AUTH_TIMEOUT                16
#define WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA 17
#define WLAN_STATUS_ASSOC_DENIED_RATES          18

#define WLAN_STATUS_ASSOC_DENIED_NOSHORT        19
#define WLAN_STATUS_ASSOC_DENIED_NOPBCC         20
#define WLAN_STATUS_ASSOC_DENIED_NOAGILITY      21

#define WLAN_STATUS_INVALID_IE                  40
#define WLAN_STATUS_GROUP_CIPHER_NOT_VALID      41
#define WLAN_STATUS_PAIRWISE_CIPHER_NOT_VALID   42
#define WLAN_STATUS_AKMP_NOT_VALID              43
#define WLAN_STATUS_UNSUPPORTED_RSN_IE_VERSION  44
#define WLAN_STATUS_INVALID_RSN_IE_CAPAB        45
#define WLAN_STATUS_CIPHER_REJECTED_PER_POLICY  46

/* Tagged parameters */
#define WLAN_TAGPARM_SSID           0
#define WLAN_TAGPARM_SUPPRATES      1
#define WLAN_TAGPARM_FH_PARAMS      2
#define WLAN_TAGPARM_DS_PARAMS      3
#define WLAN_TAGPARM_CF_PARAMS      4
#define WLAN_TAGPARM_TIM            5
#define WLAN_TAGPARM_IBSS_PARAMS    6
#define WLAN_TAGPARM_CHALLENGE      16
#define WLAN_TAGPARM_GENERIC        221

#define WLAN_SEQCTL_FRAGNO(x)		((x) & 0x000F)
#define WLAN_SEQCTL_SEQNO(x)		(((x) & 0xFFF0) >> 4)

/* 802.11 management frames */
#define IEEE80211_HDRLEN_A3 (sizeof(struct ieee80211_hdr))
#define IEEE80211_HDRLEN_A4 (sizeof(struct ieee80211_hdr) + 6)

struct ieee80211_hdr {
	union {
		struct {
			uint8_t version:2;
			uint8_t type:2;
			uint8_t subtype:4;
			uint8_t to_ds:1;
			uint8_t from_ds:1;
			uint8_t more_frag:1;
			uint8_t retry:1;
			uint8_t pwrmgmt:1;
			uint8_t more_data:1;
			uint8_t wep:1;
			uint8_t order:1;
		} __attribute__ ((packed)) fc;

		uint16_t fchdr;
	} u1;

	uint16_t duration;
	uint8_t addr1[6];
	uint8_t addr2[6];
	uint8_t addr3[6];

	union {
		struct {
			uint16_t fragment:4;
			uint16_t sequence:12;
		} __attribute__ ((packed)) seq;

		uint16_t seqhdr;
	} u2;
	/* followed by 'u8 addr4[6];' if ToDS and FromDS is set in data frame
	 */

	/* followed by wmmhdr is type = 2 and subtype = QoS data (8) or QoS
	   NULL (12) 
	 */

} __attribute__ ((packed));

struct ieee80211_mgmt {
	union {
		struct {
			uint16_t auth_alg;
			uint16_t auth_transaction;
			uint16_t status_code;
			/* possibly followed by Challenge text */
			uint8_t variable[0];
		} __attribute__ ((packed)) auth;
		struct {
			uint16_t reason_code;
		} __attribute__ ((packed)) deauth;
		struct {
			uint16_t capab_info;
			uint16_t listen_interval;
			/* followed by SSID and Supported rates */
			uint8_t variable[0];
		} __attribute__ ((packed)) assoc_req;
		struct {
			uint16_t capab_info;
			uint16_t status_code;
			uint16_t aid;
			/* followed by Supported rates */
			uint8_t variable[0];
		} __attribute__ ((packed)) assoc_resp, reassoc_resp;
		struct {
			uint16_t capab_info;
			uint16_t listen_interval;
			uint8_t current_ap[6];
			/* followed by SSID and Supported rates */
			uint8_t variable[0];
		} __attribute__ ((packed)) reassoc_req;
		struct {
			uint16_t reason_code;
		} __attribute__ ((packed)) disassoc;
		struct {
			uint8_t variable[0];
		} __attribute__ ((packed)) probe_req;
		struct {
			uint8_t timestamp[8];
			uint16_t beacon_int;
			uint16_t capab_info;
			/* followed by some of SSID, Supported rates,
			 * FH Params, DS Params, CF Params, IBSS Params, TIM */
			uint8_t variable[0];
		} __attribute__ ((packed)) beacon;
	} u;
} __attribute__ ((packed));

/* IEEE 802.11 fixed parameters */
struct ieee80211_beacon_fixparm {
	uint8_t timestamp[8];
	uint16_t beaconinterval;
	uint16_t capability;
} __attribute__ ((packed));

struct ieee80211_qos {
	uint8_t priority:3;
	uint8_t reserved3:1;
	uint8_t eosp:1;
	uint8_t ackpol:2;
	uint8_t reserved1:1;
	uint8_t reserved2;
} __attribute__ ((packed));

struct ieee80211_wep {
	uint8_t iv[3];

	union {
		uint8_t indexhdr;

		struct {
			uint8_t reserved1:6;
			uint8_t keyid:2;
		} __attribute__ ((packed)) index;
	} u1;
} __attribute__ ((packed));

struct ieee80211_tkip {
	union {
		struct {
			uint8_t tsc1;
			uint8_t wepseed;
			uint8_t tsc0;
			uint8_t reserved1:5;
			uint8_t extiv:1;
			uint8_t keyid:2;
		} __attribute__ ((packed)) iv;

		uint8_t ivhdr;
	} u1;

	union {
		struct {
			uint8_t tsc2;
			uint8_t tsc3;
			uint8_t tsc4;
			uint8_t tsc5;
		} extiv;

		uint8_t extivhdr[4];
	} u2;

} __attribute__ ((packed));

struct ieee80211_ccmp {
	union {
		struct {
			uint8_t pn0;
			uint8_t pn1;
			uint8_t reserved1;
			uint8_t reserved2:5;
			uint8_t extiv:1;
			uint8_t keyid:2;
		} __attribute__ ((packed)) iv;

		uint8_t ivhdr;
	} u1;

	union {
		struct {
			uint8_t pn2;
			uint8_t pn3;
			uint8_t pn4;
			uint8_t pn5;
		} extiv;

		uint8_t extivhdr[4];
	} u2;

} __attribute__ ((packed));
#endif

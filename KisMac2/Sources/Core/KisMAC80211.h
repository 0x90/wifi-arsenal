/*
 *  KisMAC80211.h
 *  KisMAC
 *
 *  Created by pr0gg3d on 04/02/08.
 *  Copyright 2008 __MyCompanyName__. All rights reserved.
 *
 */

// pr0gg3d:
// FIXME: This fields are here only for compatibility
// check effective use as soon as possible

typedef struct {
    UInt16 status;
    UInt16 channel;
    UInt16 reserved1;
    UInt8  signal;
    UInt8  silence;
    UInt8  rate;
    UInt8  rx_flow;
    UInt8  tx_rtry;
    UInt8  tx_rate;
    UInt16 txControl;
	UInt16 len;
} KCtrlFrame;

#define MAX_FRAME_BYTES 2364
typedef struct
{
	KCtrlFrame ctrl;
	UInt8 data[MAX_FRAME_BYTES];
} KFrame;

#define BCAST_MACADDR "\xff\xff\xff\xff\xff\xff"

#define COMPARE_MACADDR(m1, m2) (memcmp(m1, m2, ETH_ALEN))
#define IS_EQUAL_MACADDR(m1, m2) (COMPARE_MACADDR(m1, m2) == 0)
#define IS_GREATER_MACADDR(m1, m2) (COMPARE_MACADDR(m1, m2) > 0)
#define IS_LESS_MACADDR(m1, m2) (COMPARE_MACADDR(m1, m2) < 0)
#define IS_BCAST_MACADDR(m) (COMPARE_MACADDR(m, BCAST_MACADDR) == 0)

enum {
    ieee80211ElementSSID             = 0,
    ieee80211ElementSupportedRates   = 1,
    ieee80211ElementFHParameterSet   = 2,
    ieee80211ElementDSParameterSet   = 3,
    ieee80211ElementCFParameterSet   = 4,
    ieee80211ElementTIM              = 5,
    ieee80211ElementIBSSParameterSet = 6,
    ieee80211ElementChallengeText    = 16,
};

typedef UInt8 ieee80211Element;

/*	pr0gg3d: This was taken and adapted from linux kernel headers 
	I Would to remember that fields are in little endianness.
*/

/* Minimal header; can be used for passing 802.11 frames with sufficient
 * information to determine what type of underlying data type is actually
 * stored in the data. */

#define ETH_ALEN 6

struct ieee80211_hdr {
	UInt16 frame_ctl;
	UInt16 duration_id;
	UInt8 payload[0];
} __attribute__ ((packed));

struct ieee80211_hdr_1addr {
	UInt16 frame_ctl;
	UInt16 duration_id;
	UInt8 addr1[ETH_ALEN];
	UInt8 payload[0];
} __attribute__ ((packed));

struct ieee80211_hdr_2addr {
	UInt16 frame_ctl;
	UInt16 duration_id;
	UInt8 addr1[ETH_ALEN];
	UInt8 addr2[ETH_ALEN];
	UInt8 payload[0];
} __attribute__ ((packed));

struct ieee80211_hdr_3addr {
	UInt16 frame_ctl;
	UInt16 duration_id;
	UInt8 addr1[ETH_ALEN];
	UInt8 addr2[ETH_ALEN];
	UInt8 addr3[ETH_ALEN];
	UInt16 seq_ctl;
	UInt8 payload[0];
} __attribute__ ((packed));

struct ieee80211_hdr_4addr {
	UInt16 frame_ctl;
	UInt16 duration_id;
	UInt8 addr1[ETH_ALEN];
	UInt8 addr2[ETH_ALEN];
	UInt8 addr3[ETH_ALEN];
	UInt16 seq_ctl;
	UInt8 addr4[ETH_ALEN];
	UInt8 payload[0];
} __attribute__ ((packed));

struct ieee80211_hdr_3addrqos {
	UInt16 frame_ctl;
	UInt16 duration_id;
	UInt8 addr1[ETH_ALEN];
	UInt8 addr2[ETH_ALEN];
	UInt8 addr3[ETH_ALEN];
	UInt16 seq_ctl;
	UInt16 qos_ctl;
	UInt8 payload[0];
} __attribute__ ((packed));

struct ieee80211_hdr_4addrqos {
	UInt16 frame_ctl;
	UInt16 duration_id;
	UInt8 addr1[ETH_ALEN];
	UInt8 addr2[ETH_ALEN];
	UInt8 addr3[ETH_ALEN];
	UInt16 seq_ctl;
	UInt8 addr4[ETH_ALEN];
	UInt16 qos_ctl;
	UInt8 payload[0];
} __attribute__ ((packed));

/* More complex frametypes */

struct ieee80211_disassoc {
	struct ieee80211_hdr_3addr header;
	UInt16 reason;
} __attribute__ ((packed));

struct ieee80211_deauth {
	struct ieee80211_hdr_3addr header;
	UInt16 reason;
} __attribute__ ((packed));

struct ieee80211_info_element {
	UInt8 id;
	UInt8 len;
	UInt8 data[0];
} __attribute__ ((packed));

struct ieee80211_probe_request {
	struct ieee80211_hdr_3addr header;
	/* SSID, supported rates */
	struct ieee80211_info_element info_element[0];
} __attribute__ ((packed));

struct ieee80211_probe_response {
	struct ieee80211_hdr_3addr header;
	UInt32 time_stamp[2];
	UInt16 beacon_interval;
	UInt16 capability;
	/* SSID, supported rates, FH params, DS params,
	 * CF params, IBSS params, TIM (if beacon), RSN */
	struct ieee80211_info_element info_element[0];
} __attribute__ ((packed));

struct ieee80211_probe_beacon {
	struct ieee80211_hdr_3addr header;
	UInt32 time_stamp[2];
	UInt16 beacon_interval;
	UInt16 capability;
	/* SSID, supported rates, FH params, DS params,
	 * CF params, IBSS params, TIM (if beacon), RSN */
	struct ieee80211_info_element info_element[0];
} __attribute__ ((packed));

struct ieee80211_assoc_request {
	struct ieee80211_hdr_3addr header;
	UInt16 capability;
	UInt16 listen_interval;
	/* SSID, supported rates, RSN */
	struct ieee80211_info_element info_element[0];
} __attribute__ ((packed));

struct ieee80211_reassoc_request {
	struct ieee80211_hdr_3addr header;
	UInt16 capability;
	UInt16 listen_interval;
	UInt8 current_ap[ETH_ALEN];
	struct ieee80211_info_element info_element[0];
} __attribute__ ((packed));

struct ieee80211_auth {
	struct ieee80211_hdr_3addr header;
	UInt16 algorithm;
	UInt16 transaction;
	UInt16 status;
	/* challenge */
	struct ieee80211_info_element info_element[0];
} __attribute__ ((packed));

///

struct ieee80211_rts {
	struct ieee80211_hdr_2addr header;
} __attribute__ ((packed));


/* copied from linux wireless-2.6/net/mac80211/util.c */

/*
 * Copyright 2002-2005, Instant802 Networks, Inc.
 * Copyright 2005-2006, Devicescape Software, Inc.
 * Copyright 2006-2007	Jiri Benc <jbenc@suse.cz>
 * Copyright 2007	Johannes Berg <johannes@sipsolutions.net>
 * Copyright 2014	Bruno Randolf (br1@einfach.org)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * utilities for mac80211
 */

#include <stddef.h>
#include <string.h>
#include <math.h>

#include "ieee80211_util.h"
#include "wlan80211.h"
#include "main.h"
#include "util.h"


/* from mac80211/ieee80211_i.c, slightly modified */

/**
 * ieee80211_is_erp_rate - Check if a rate is an ERP rate
 * @phymode: The PHY-mode for this rate (MODE_IEEE80211...)
 * @rate: Transmission rate to check, in 100 kbps
 *
 * Check if a given rate is an Extended Rate PHY (ERP) rate.
 */
static inline int
ieee80211_is_erp_rate(int phymode, int rate)
{
	if (phymode & PHY_FLAG_G) {
		if (rate != 10 && rate != 20 &&
		    rate != 55 && rate != 110) {
			DEBUG("erp\n");
			return 1;
		}
	}
	DEBUG("no erp\n");
	return 0;
}

static int
get_cw_time(int cw_min, int cw_max, int retries, int slottime)
{
	int cw = pow(2, (cw_min + retries)) - 1;
	cw_max = pow(2, cw_max) - 1;

	if(cw >  cw_max)
		cw = cw_max;

	DEBUG("CW min %d max %d ret %d = %d\n", cw_min, cw_max, retries, cw);
	return (cw * slottime) / 2;
}

static const unsigned char ieee802_1d_to_ac[8] = { 0, 1, 1, 0, 2, 2, 3, 3 };
					    /* BE	BK	VI	VO */
static const unsigned char ac_to_aifs[4] = {	3,	7,	2,	2};
static const unsigned char ac_to_cwmin[4] = {	4,	4,	3,	2};
static const unsigned int ac_to_cwmax[4] = {	10,	10,	4,	3};

/* from mac80211/util.c, modified */
int
ieee80211_frame_duration(int phymode, size_t len, int rate, int short_preamble,
			 int shortslot, int type, char qos_class, int retries)
{
	int dur;
	int erp;
	int sifs, slottime;
	static int last_was_cts;

	erp = ieee80211_is_erp_rate(phymode, rate);

	/* calculate duration (in microseconds, rounded up to next higher
	 * integer if it includes a fractional microsecond) to send frame of
	 * len bytes (does not include FCS) at the given rate. Duration will
	 * also include SIFS.
	 *
	 * rate is in 100 kbps, so divident is multiplied by 10 in the
	 * DIV_ROUND_UP() operations.
	 */

	DEBUG("DUR mode %d, len %d, rate %d, shortpre %d shortslot %d type %x UP %d\n", phymode, (int)len, rate, short_preamble, shortslot, type, qos_class);

	if (phymode == PHY_FLAG_A || erp) {
		DEBUG("OFDM\n");
		/*
		 * OFDM:
		 *
		 * N_DBPS = DATARATE x 4
		 * N_SYM = Ceiling((16+8xLENGTH+6) / N_DBPS)
		 *	(16 = SIGNAL time, 6 = tail bits)
		 * TXTIME = T_PREAMBLE + T_SIGNAL + T_SYM x N_SYM + Signal Ext
		 *
		 * T_SYM = 4 usec
		 * 802.11a - 17.5.2: aSIFSTime = 16 usec
		 * 802.11g - 19.8.4: aSIFSTime = 10 usec +
		 *	signal ext = 6 usec
		 */
		sifs = 16;  /* SIFS + signal ext */
		slottime = 9;
		dur = 16; /* 17.3.2.3: T_PREAMBLE = 16 usec */
		dur += 4; /* 17.3.2.3: T_SIGNAL = 4 usec */
		dur += 4 * DIV_ROUND_UP((16 + 8 * (len + 4) + 6) * 10,
					4 * rate); /* T_SYM x N_SYM */
	} else {
		DEBUG("CCK\n");
		/*
		 * 802.11b or 802.11g with 802.11b compatibility:
		 * 18.3.4: TXTIME = PreambleLength + PLCPHeaderTime +
		 * Ceiling(((LENGTH+PBCC)x8)/DATARATE). PBCC=0.
		 *
		 * 802.11 (DS): 15.3.3, 802.11b: 18.3.4
		 * aSIFSTime = 10 usec
		 * aPreambleLength = 144 usec or 72 usec with short preamble
		 * aPLCPHeaderLength = 48 usec or 24 usec with short preamble
		 */
		sifs = 10; /* aSIFSTime = 10 usec */
		slottime = shortslot ? 9 : 20;
		dur = short_preamble ? (72 + 24) : (144 + 48);
		dur += DIV_ROUND_UP(8 * (len + 4) * 10, rate);
	}

	if (type == WLAN_FRAME_CTS ||
	    type == WLAN_FRAME_ACK) {
		//TODO: also fragments
		DEBUG("DUR SIFS\n");
		dur += sifs;
	}
	else if (type == WLAN_FRAME_BEACON) {
		/* TODO: which AIFS and CW should be used for beacons? */
		dur += sifs + (2 * slottime); /* AIFS */
		dur += (slottime * 1) / 2; /* contention */
	}
	else if (WLAN_FRAME_IS_DATA(type) && last_was_cts) {
		DEBUG("DUR LAST CTS\n");
		dur += sifs;
	}
	else if (type == WLAN_FRAME_QDATA) {
		unsigned char ac = ieee802_1d_to_ac[(unsigned char)qos_class];
		dur += sifs + (ac_to_aifs[ac] * slottime); /* AIFS */
		dur += get_cw_time(ac_to_cwmin[ac], ac_to_cwmax[ac], retries, slottime);
		DEBUG("DUR AIFS %d CWMIN %d AC %d, UP %d\n", ac_to_aifs[ac], ac_to_cwmin[ac], ac, qos_class);
	}
	else {
		DEBUG("DUR DIFS\n");
		dur += sifs + (2 * slottime); /* DIFS */
		dur += get_cw_time(4, 10, retries, slottime);
	}

	if (type == WLAN_FRAME_CTS) {
		DEBUG("SET CTS\n");
		last_was_cts = 1;
	}
	else
		last_was_cts = 0;

	/* TODO: Add EIFS (SIFS + ACKTXTIME) to frames with CRC errors, if we can get them */

	DEBUG("DUR %d\n", dur);
	return dur;
}

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

#ifndef __MADWIFI_CONTROL_H__
#define __MADWIFI_CONTROL_H__

#include "config.h"

#ifdef SYS_LINUX

/* Madwifi-NG ioctls from net80211 */
#define SIOC80211IFCREATE       (SIOCDEVPRIVATE+7)
#define SIOC80211IFDESTROY      (SIOCDEVPRIVATE+8)

#define	IEEE80211_CLONE_BSSID	0x0001
#define	IEEE80211_NO_STABEACONS	0x0002
#define IEEE80211_M_STA			1
#define IEEE80211_M_IBSS		0
#define IEEE80211_M_MASTER		6
#define IEEE80211_M_MONITOR 	8

#define ARPHDR_RADIOTAP "803"

struct madwifi_vaps {
	char **vaplist;
	int vaplen;
};

/* Return a list of vaps.  Caller must free this list. */
struct madwifi_vaps *madwifing_list_vaps(const char *ifname, char *errstr);

/* Free a vaplist */
void madwifing_free_vaps(struct madwifi_vaps *in_vaplist);

/* Destroy a vap */
int madwifing_destroy_vap(const char *ifname, char *errstr);

/* Make a vap */
int madwifing_build_vap(const char *ifname, char *errstr, const char *vapname,
						char *retvapname, int vapmode, int vapflags);

/* Set the device type for a VAP */
int madwifing_setdevtype(const char *ifname, char *devtype, char *errstr);

char *madwifing_find_parent(struct madwifi_vaps *vaplist);

#endif
#endif


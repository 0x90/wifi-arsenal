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

#ifndef __MWOLDINJECT_H__
#define __MWOLDINJECT_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef SYS_LINUX

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include <net/if_arp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <sys/poll.h>
#include <sys/types.h>

#ifdef HAVE_LINUX_WIRELESS
#include <linux/types.h>
#include <linux/if.h>
#include <linux/wireless.h>
#else
#include <net/if.h>
#endif

#include <net/ethernet.h>
#include <netpacket/packet.h>

#include "wtinject.h"

int tx80211_madwifiold_init(struct tx80211 *in_tx);
int tx80211_madwifiold_capabilities();
int madwifiold_open(struct tx80211 *in_tx);
int madwifiold_close(struct tx80211 *in_tx);
int madwifiold_rawdev(struct tx80211 *in_tx, int argument);

#endif /* linux */

#endif


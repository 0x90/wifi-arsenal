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

#ifndef __IFCONTROL_H__
#define __IFCONTROL_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef SYS_LINUX

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
#ifdef HAVE_LINUX_WIRELESS
// Because some kernels include ethtool which breaks horribly...
// The stock ones don't but others seem to
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

#include <linux/types.h>
#include <linux/if.h>

#include <linux/wireless.h>

#endif

#define TX80211_IFUP 1
#define TX80211_IFDOWN 0

/* Get the driver via the /sys path */
char *ifconfig_get_sysdriver(const char *in_dev);
/* Check if an attribute (ie, file) exists in the /sys path for an interface */
int ifconfig_get_sysattr(const char *in_dev, const char *attr);

int ifconfig_set_flags(const char *in_dev, char *errstr, short flags);
int ifconfig_delta_flags(const char *in_dev, char *errstr, short flags);
int ifconfig_get_flags(const char *in_dev, char *errstr, short *flags);
int ifconfig_get_hwaddr(const char *in_dev, char *errstr, uint8_t * ret_hwaddr);
int ifconfig_set_hwaddr(const char *in_dev, char *errstr, uint8_t * in_hwaddr);
int ifconfig_set_mtu(const char *in_dev, char *errstr, uint16_t in_mtu);
int ifconfig_ifupdown(const char *in_dev, char *errstr, int devup);

#endif /* linux */

#endif

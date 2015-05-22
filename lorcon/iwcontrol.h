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

#ifndef __IWCONTROL_H__
#define __IWCONTROL_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#ifdef SYS_LINUX
#include <net/if_arp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#ifdef HAVE_LINUX_WIRELESS
#include <linux/types.h>
#include <linux/if.h>
#include <linux/wireless.h>
#endif

#endif

#define min(x,y) ((x) < (y) ? (x) : (y))

#ifdef HAVE_LINUX_WIRELESS

#define IW_MAX_PRIV_DEF 128
// Wireless extensions monitor mode number
#define LINUX_WLEXT_MONITOR 6
// Wireless extensions master mode
#define LINUX_WLEXT_MASTER  3

// remove the SSID of the device.  Some cards seem to need this.
int iwconfig_set_ssid(const char *in_dev, char *errstr, char *in_essid);
int iwconfig_get_ssid(const char *in_dev, char *errstr, char *in_essid);

// Get the name
int iwconfig_get_name(const char *in_dev, char *errstr, char *in_name);

// Set a private ioctl that takes 1 or 2 integer parameters
// A return of -2 means no privctl found that matches, so that the caller
// can return a more detailed failure message
//
// This DOES NOT handle sub-ioctls.  I've never seen them used.  If this
// blows up some day on some driver, I'll fix it.
int iwconfig_set_intpriv(const char *in_dev, const char *privcmd,
			 int val1, int val2, char *errstr);

// Get a single-param private ioctl.  This will have to be changed if we 
// ever need to remember a two-value privioctl, but hopefully nothing
// will.
int iwconfig_get_intpriv(const char *in_dev, const char *privcmd,
			 int *val, char *errstr);

int iwconfig_set_charpriv(const char *in_dev, const char *privcmd,
			 char *val, char *errstr);

// Fetch levels
int iwconfig_get_levels(const char *in_dev, char *in_err, int *level,
			int *noise);

// Get/set channel
int iwconfig_get_channel(const char *in_dev, char *errstr);
int iwconfig_set_channel(const char *in_dev, char *errstr, int in_ch);

// Get/set mode
int iwconfig_get_mode(const char *in_dev, char *errstr);
int iwconfig_set_mode(const char *in_dev, char *errstr, int in_mode);

// Info conversion
float iwfreq2float(struct iwreq *inreq);
float iwfreq2float(struct iwreq *inreq);
int floatchan2int(float in_chan);

#endif

#endif

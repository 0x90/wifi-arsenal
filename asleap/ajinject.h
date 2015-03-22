/*
 * asleap - recover weak LEAP passwords.  Pronounced "asleep".
 *
 * $Id: ajinject.h,v 1.2 2004/03/28 15:37:02 jwright Exp $
 *
 * Copyright (c) 2004, Joshua Wright <jwright@hasborg.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See COPYING for more
 * details.
 *
 * asleap is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/* Much of this code is taken form the AirJack project and associated tools */

typedef unsigned char u8;
typedef unsigned short u16;

/* prototypes */
int aj_setnonblock(char *ifname, int nonblock);
int aj_getnonblock(char *ifname);
int aj_setmonitor(char *ifname, int rfmonset);
int aj_setmode(char *ifname, int mode);
int aj_setchannel(char *ifname, int channel);
int aj_setessid(char *ifname, char *essid, int len);
int aj_setmac(char *ifname, u8 *mac);
int aj_xmitframe(char *ifname, u8 *xmit, int len);
int aj_recvframe(char *ifname, u8 *buf, int len);
int aj_ifupdown(char *ifname, int devup);
int aj_getsocket(char *ifname);


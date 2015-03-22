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

/* Generic functions suitable for packet injection on any wireless-tools
   compliant driver (prism54, madwifi). */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef SYS_LINUX

#include "wtinject.h"
#include "tx80211.h"
#include "tx80211_errno.h"
#include "ifcontrol_linux.h"

int wtinj_send(struct tx80211 *wtinj, struct tx80211_packet *in_pkt)
{

	int ret;

	if (!(wtinj->raw_fd > 0)) {
		/* file descriptor is not open */
		return TX80211_ENOTX;
	}

	ret = write(wtinj->raw_fd, in_pkt->packet, in_pkt->plen);

	if (ret < 0) {
		snprintf(wtinj->errstr, TX80211_STATUS_MAX, "write failed, %s",
				 strerror(errno));
		return TX80211_ENOTX;;
	}
	if (ret < (in_pkt->plen)) {
		snprintf(wtinj->errstr, TX80211_STATUS_MAX, "incomplete write"
				", %s", strerror(errno));
		return ret;
	}
	return (ret);
}

int wtinj_open(struct tx80211 *wtinj)
{

	int err;
	short flags;
	struct ifreq if_req;
	struct sockaddr_ll sa_ll;

	if (ifconfig_get_flags(wtinj->ifname, wtinj->errstr, &flags) < 0) {
		return TX80211_ENOOPENINT;
	}

	/* Up the interface if it's down */
	if ((flags & IFF_UP) == 0) {
		if (ifconfig_ifupdown(wtinj->ifname, wtinj->errstr,
				TX80211_IFUP) < 0) {
			return TX80211_ENOOPENINT;
		}
	}

	wtinj->raw_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (wtinj->raw_fd < 0) {
		snprintf(wtinj->errstr, TX80211_STATUS_MAX, "no socket fd in tx descriptor");
		return -1;
	}

	memset(&if_req, 0, sizeof if_req);
	memcpy(if_req.ifr_name, wtinj->ifname, IFNAMSIZ);
	if_req.ifr_name[IFNAMSIZ - 1] = 0;
	err = ioctl(wtinj->raw_fd, SIOCGIFINDEX, &if_req);
	if (err < 0) {
		snprintf(wtinj->errstr, TX80211_STATUS_MAX, "SIOCGIFINDEX ioctl failed, %s",
				 strerror(errno));
		close(wtinj->raw_fd);
		return -2;
	}

	memset(&sa_ll, 0, sizeof sa_ll);
	sa_ll.sll_family = AF_PACKET;
	sa_ll.sll_protocol = htons(ETH_P_80211_RAW);
	sa_ll.sll_ifindex = if_req.ifr_ifindex;
	err = bind(wtinj->raw_fd, (struct sockaddr *)&sa_ll, sizeof sa_ll);
	if (err != 0) {
		snprintf(wtinj->errstr, TX80211_STATUS_MAX, "bind() failed, %s",
				 strerror(errno));
		close(wtinj->raw_fd);
		return -3;
	}

	return 0;
}

int wtinj_close(struct tx80211 *wtinj)
{
	return close(wtinj->raw_fd);
}

int wtinj_setchannel(struct tx80211 *wtinj, int channel)
{
	/* wrapper for iwconfig_set_channel */
	return (iwconfig_set_channel(wtinj->ifname, wtinj->errstr, channel));

}

int wtinj_getchannel(struct tx80211 *wtinj)
{
	/* wrapper for iwconfig_get_channel */
	return (iwconfig_get_channel(wtinj->ifname, wtinj->errstr));

}

int wtinj_setmode(struct tx80211 *wtinj, int mode)
{
	/* wrapper for iwconfig_set_mode */
	return (iwconfig_set_mode(wtinj->ifname, wtinj->errstr, mode));
}

int wtinj_getmode(struct tx80211 *wtinj)
{
	/* wrapper for iwconfig_get_mode */
	return (iwconfig_get_mode(wtinj->ifname, wtinj->errstr));

}

int wtinj_setfuncmode(struct tx80211 *wtinj, int funcmode)
{
	int ret;

	/* All the iw* drivers use rfmon mode for injection so we just set it
	 * here the same */
	if (funcmode == TX80211_FUNCMODE_RFMON ||
		funcmode == TX80211_FUNCMODE_INJECT ||
		funcmode == TX80211_FUNCMODE_INJMON) {

		// If we fail to set a mode, bring the interface down and try again
		if ((ret = iwconfig_set_mode(wtinj->ifname, wtinj->errstr, IW_MODE_MONITOR)) < 0) 
		{
			ifconfig_ifupdown(wtinj->ifname, wtinj->errstr, TX80211_IFDOWN);
			ret = iwconfig_set_mode(wtinj->ifname, wtinj->errstr, IW_MODE_MONITOR);
		}

		return ret;
	}

	/* Otherwise we don't have a handler */
	return TX80211_ENOHANDLER;
}

int wtinj_selfack(struct tx80211 *wtinj, uint8_t *addr)
{

	if (ifconfig_ifupdown(wtinj->ifname, wtinj->errstr,
			TX80211_IFDOWN) < 0) {

		snprintf(wtinj->errstr, TX80211_STATUS_MAX,
				"Failed to place interface %d in the "
				"DOWN state before changing the MAC "
				"address.", wtinj->ifname);
		return -1;
	}

	if (ifconfig_set_hwaddr(wtinj->ifname, wtinj->errstr, 
			wtinj->startingmac) < 0) {
		/* Retain message from set_hwaddr */
		return -1;
	}

	if (ifconfig_ifupdown(wtinj->ifname, wtinj->errstr,
			TX80211_IFUP) < 0) {
		snprintf(wtinj->errstr, TX80211_STATUS_MAX,
				"Failed to place interface %d in the "
				"UP state after changing the MAC "
				"address.", wtinj->ifname);
			return -1;
	}

	return TX80211_ENOERR;
}

#endif /* linux */


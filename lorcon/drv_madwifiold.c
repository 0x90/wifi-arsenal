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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef SYS_LINUX

#include "mwoldinject.h"
#include "wtinject.h"

#define ENABLE_ATHRAWDEV 1
#define DISABLE_ATHRAWDEV 0

int tx80211_madwifiold_init(struct tx80211 *in_tx)
{

	in_tx->capabilities = tx80211_madwifiold_capabilities();
	in_tx->open_callthrough = &madwifiold_open;
	in_tx->close_callthrough = &wtinj_close;
	in_tx->setmode_callthrough = &wtinj_setmode;
	in_tx->getmode_callthrough = &wtinj_getmode;
	in_tx->getchan_callthrough = &wtinj_getchannel;
	in_tx->setchan_callthrough = &wtinj_setchannel;
	in_tx->txpacket_callthrough = &wtinj_send;
	in_tx->setfuncmode_callthrough = &wtinj_setfuncmode;

	return 0;
}

int tx80211_madwifiold_capabilities()
{
	return (TX80211_CAP_SNIFF | TX80211_CAP_TRANSMIT |
		TX80211_CAP_SEQ | TX80211_CAP_BSSTIME |
		TX80211_CAP_FRAG | TX80211_CAP_CTRL | 
		TX80211_CAP_DURID | TX80211_CAP_SNIFFACK | 
		TX80211_CAP_DSSSTX | TX80211_CAP_OFDMTX |
		TX80211_CAP_SELFACK | TX80211_CAP_SETRATE);
}

int madwifiold_open(struct tx80211 *in_tx)
{

	int err, ret, sock;
	struct ifreq if_req;
	struct sockaddr_ll sa_ll;

	/* Versions of the MADWIFI driver following ~2005/06 require the use of
	   a second interface, athXraw, for packet TX.  Enable this interface
	   through procps, and bind the socket to the new interface name. */

	if (madwifiold_rawdev(in_tx, ENABLE_ATHRAWDEV) != 0) {
		printf("Error enabling athXraw interface.\n");
		return -1;
	}

	memset(&if_req, 0, sizeof if_req);
	snprintf(if_req.ifr_name, sizeof(if_req.ifr_name) - 1, "%sraw",
		 in_tx->ifname);

	/* Open the socket for packet TX */
	in_tx->raw_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (in_tx->raw_fd < 0)
		return -1;

	err = ioctl(in_tx->raw_fd, SIOCGIFINDEX, &if_req);
	if (err < 0) {
		close(in_tx->raw_fd);
		return -2;
	}

	memset(&sa_ll, 0, sizeof sa_ll);
	sa_ll.sll_family = AF_PACKET;
	sa_ll.sll_protocol = htons(ETH_P_80211_RAW);
	sa_ll.sll_ifindex = if_req.ifr_ifindex;
	err = bind(in_tx->raw_fd, (struct sockaddr *)&sa_ll, sizeof sa_ll);
	if (err != 0) {
		close(in_tx->raw_fd);
		return -3;
	}

	/* Place the new athXraw device in the up state */
	if (ioctl(in_tx->raw_fd, SIOCGIFFLAGS, &if_req) != 0) {
		snprintf(in_tx->errstr, TX80211_STATUS_MAX,
				"Error retriving interface flags: %s",
				strerror(errno));
		return TX80211_ENOOPENINT;
	}

	if_req.ifr_flags |= IFF_UP;

	if (ioctl(in_tx->raw_fd, SIOCSIFFLAGS, &if_req) != 0) {
		snprintf(in_tx->errstr, TX80211_STATUS_MAX,
				"Error setting interface flags: %s",
				strerror(errno));
		return TX80211_ENOOPENINT;
	}

	return 0;
}

int madwifiold_close(struct tx80211 *in_tx)
{

	struct ifreq if_req;

	/* Causes a kernel oops, reported to MADWIFI developers on 11/21/2005
	   http://madwifiold.org/ticket/167 - JWRIGHT
	 */

	/*
	   if (madwifiold_rawdev(in_tx, DISABLE_ATHRAWDEV) != 0) {
	   printf("Error disabling athXraw interface.\n");
	   return -1;
	   }
	 */

	/* Place the new athXraw device in the down state */
	memset(&if_req, 0, sizeof if_req);
	snprintf(if_req.ifr_name, sizeof(if_req.ifr_name) - 1, "%sraw",
		 in_tx->ifname);
	
	if (ioctl(in_tx->raw_fd, SIOCGIFFLAGS, &if_req) != 0) {
		snprintf(in_tx->errstr, TX80211_STATUS_MAX,
				"Error getting interface flags: %s",
				strerror(errno));
		return TX80211_ENOCLOSEINT;
	}

	if_req.ifr_flags &= ~IFF_UP;

	if (ioctl(in_tx->raw_fd, SIOCSIFFLAGS, &if_req) != 0) {
		snprintf(in_tx->errstr, TX80211_STATUS_MAX,
				"Error getting interface flags: %s",
				strerror(errno));
		return TX80211_ENOCLOSEINT;
	}

	return (close(in_tx->raw_fd));

}

int madwifiold_rawdev(struct tx80211 *in_tx, int argument)
{
	int ret, sock;
	struct ifreq req;
	struct sockaddr_ll addr;
	FILE *fp;
	char athprocpath[64];

	if (argument > ENABLE_ATHRAWDEV || argument < DISABLE_ATHRAWDEV) {
		snprintf(in_tx->errstr, TX80211_STATUS_MAX,
				"Invalid argument to madwifiold_rawdev: %s",
				strerror(errno));
		return -1;
	}

	snprintf(athprocpath, sizeof(athprocpath) - 1,
		 "/proc/sys/dev/%s/rawdev", in_tx->ifname);

	fp = fopen(athprocpath, "w");
	if (!fp) {
		snprintf(in_tx->errstr, TX80211_STATUS_MAX,
				"Unable to open proc device \"%s\": %s ",
				athprocpath, strerror(errno));
		return -1;
	}

	/* Write a "1" or "0" to enable or disable */
	ret = fprintf(fp, "%d\n", argument);
	if (ret < 0) {
		snprintf(in_tx->errstr, TX80211_STATUS_MAX,
				"Unable to write to proc device \"%s\": %s ",
				athprocpath, strerror(errno));
		return ret;
	}

	fclose(fp);
	return 0;

}

#endif /* linux */

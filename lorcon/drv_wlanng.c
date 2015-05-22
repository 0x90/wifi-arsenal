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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include "wginject.h"
#include "tx80211.h"

#include <net/ethernet.h>
#include <netinet/in.h>
#include <netpacket/packet.h>


int tx80211_wlanng_init(struct tx80211 *in_tx)
{

	in_tx->capabilities = tx80211_wlanng_capabilities();
	in_tx->open_callthrough = &wginj_open;
	in_tx->close_callthrough = &wginj_close;
	in_tx->setmode_callthrough = &wginj_setmode;
	in_tx->getmode_callthrough = &wginj_getmode;
	in_tx->getchan_callthrough = &wginj_getchannel;
	in_tx->setchan_callthrough = &wginj_setchannel;
	in_tx->txpacket_callthrough = &wginj_send;
	in_tx->setfuncmode_callthrough = NULL;

	return 0;
}

int tx80211_wlanng_capabilities()
{
	return (TX80211_CAP_SNIFF | TX80211_CAP_TRANSMIT |
		TX80211_CAP_DSSSTX);
}

int wginj_send(struct tx80211 *wginj, struct tx80211_packet *in_pkt)
{

	/* 
	   The wlan-ng drivers require a special struct for transmitting packets
	   that includes the 802.11 header (4 addresses), followed by a uint16_t
	   to specify payload length, then 14 bytes of null data, then the
	   actual payload.  This format requires us to over-allocate the 
	   wg80211_frame struct to include enough space for the payload
	   (wg80211_frame->data is a uint8_t [0] array).
	   This also requires us to deal with various packet length trickery,
	   which is why we are subtracting 24 from different values (size of a
	   3-address 802.11 header), and returning the packet size actually 
	   written, not the return value from write().
	 */

	int ret;
	int payloadlen;
	struct wg80211_frame *frame;

	/* control packets cannot be transmitted with this driver, must be at
	   least a full 802.11 header */
	if (in_pkt->plen < 24) {
		snprintf(wginj->errstr, TX80211_STATUS_MAX, "wlan-ng raw "
				"injection only capable with fill 802.11 "
				"frames, control frames are not possible.");
		return TX80211_ENOTX;
	}

	payloadlen = in_pkt->plen - 24;

	/* Error check to ensure socket is open */
	if (!(wginj->raw_fd > 0)) {
		/* file descriptor is not open */
		snprintf(wginj->errstr, TX80211_STATUS_MAX, "wlan-ng raw inject file descriptor "
				 "not open");
		return TX80211_ENOTX;
	}

	frame = malloc(sizeof(*frame) + payloadlen);
	if (frame == NULL) {
		snprintf(wginj->errstr, TX80211_STATUS_MAX, "wlan-ng send unable to allocate "
				 "memory buffer");
		return TX80211_ENOTX;
	}

	memset(frame, 0, sizeof(*frame));

	frame->data_len = payloadlen;

	/* populate the header of the frame with the packet */
	memcpy(frame->base, in_pkt->packet, 24);

	/* fill in the packet */
	memcpy(frame->data, in_pkt->packet + 24, payloadlen);

	ret = write(wginj->raw_fd, frame, (payloadlen + sizeof(*frame)));
	free(frame);
	if (ret < 0) {
		snprintf(wginj->errstr, TX80211_STATUS_MAX, "Error transmitting"
				" frame: %s", strerror(errno));
		return TX80211_ENOTX;
	}
	if (ret < (payloadlen + sizeof(*frame))) {
		snprintf(wginj->errstr, TX80211_STATUS_MAX, "Partial frame "
				" transmission: %s", strerror(errno));
		return TX80211_EPARTTX;
	}

	return (ret - sizeof(*frame) + 24);
}

int wginj_open(struct tx80211 *wginj)
{
	int err;
	struct ifreq if_req;
	struct sockaddr_ll sa_ll;

	wginj->raw_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (wginj->raw_fd < 0)
		return -1;

	memset(&if_req, 0, sizeof if_req);
	memcpy(if_req.ifr_name, wginj->ifname, IFNAMSIZ);
	if_req.ifr_name[IFNAMSIZ - 1] = 0;
	err = ioctl(wginj->raw_fd, SIOCGIFINDEX, &if_req);
	if (err < 0) {
		snprintf(wginj->errstr, TX80211_STATUS_MAX, "wlan-ng unable to find interface "
				 "index (SIOCGIFINDEX): %s", strerror(errno));
		close(wginj->raw_fd);
		return -2;
	}

	memset(&sa_ll, 0, sizeof sa_ll);
	sa_ll.sll_family = AF_PACKET;
	sa_ll.sll_protocol = htons(ETH_P_80211_RAW);
	sa_ll.sll_ifindex = if_req.ifr_ifindex;
	err = bind(wginj->raw_fd, (struct sockaddr *)&sa_ll, sizeof sa_ll);
	if (err != 0) {
		snprintf(wginj->errstr, TX80211_STATUS_MAX, "wlan-ng unable to bind() socket: %s",
				 strerror(errno));
		close(wginj->raw_fd);
		return -3;
	}

	return 0;
}

int wginj_close(struct tx80211 *wginj)
{
	return close(wginj->raw_fd);
}

int wginj_setmode(struct tx80211 *wginj, int mode)
{
	char cmdline[2048];
	int currentchan = 0;

	switch (mode) {
	case TX80211_MODE_MONITOR:
		currentchan = wginj_getchannel(wginj);
		snprintf(cmdline, sizeof(cmdline),
			 "wlanctl-ng %s lnxreq_wlansniff channel=%d enable=true >/dev/null 2>&1",
			 wginj->ifname, currentchan);
		return (system(cmdline));

	case TX80211_MODE_INFRA:
		currentchan = wginj_getchannel(wginj);
		snprintf(cmdline, sizeof(cmdline),
			 "wlanctl-ng %s lnxreq_wlansniff channel=%d enable=false >/dev/null 2>&1",
			 wginj->ifname, currentchan);
		return (system(cmdline));

	case TX80211_MODE_AUTO:
	case TX80211_MODE_ADHOC:
	case TX80211_MODE_MASTER:
	case TX80211_MODE_REPEAT:
	case TX80211_MODE_SECOND:
	default:
		return -1;	/* not supported */
	}

}

int wginj_getmode(struct tx80211 *wginj)
{
	/* wrapper for iwconfig_get_mode */
	char errstr[TX80211_STATUS_MAX];	/* Not used for now */
	return (iwconfig_get_mode(wginj->ifname, errstr));
}

int wginj_getchannel(struct tx80211 *wginj)
{
	/* wrapper for iwconfig_get_channel */
	char errstr[TX80211_STATUS_MAX];	/* Not used for now */
	return (iwconfig_get_channel(wginj->ifname, errstr));
}

int wginj_setchannel(struct tx80211 *wginj, int channel)
{
	/* TODO: Figure out how to rip enough code from wlan-ng to do this
	   programatically. */
	char cmdline[2048];
	int ret;

	snprintf(cmdline, sizeof(cmdline),
		 "wlanctl-ng %s lnxreq_wlansniff channel=%d enable=true >/dev/null 2>&1",
		 wginj->ifname, channel);
	ret = system(cmdline);
	if (ret != 0) {
		return -1;
	}

	return 0;
}

#endif /* linux */


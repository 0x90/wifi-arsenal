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

#include "config.h"
#include "drv_tuntap.h"

#if defined(SYS_LINUX)

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

#include <linux/types.h>
#include <linux/if.h>
#include <linux/wireless.h>

#include <net/ethernet.h>
#include <netpacket/packet.h>

#define ETH_P_80211_RAW        (ETH_P_ECONET + 1)

#include "ifcontrol_linux.h"
#include "nl80211_control.h"
#include "lorcon_int.h"

/* Monitor, inject, and injmon are all the same method, open a new vap */
int tuntap_openmon_cb(lorcon_t *context) {
	char *parent;
	char pcaperr[PCAP_ERRBUF_SIZE];
	struct mac80211_lorcon *extras = (struct mac80211_lorcon *) context->auxptr;
	short flags;
	struct ifreq if_req;
	struct sockaddr_ll sa_ll;

	if (ifconfig_delta_flags(context->ifname, context->errstr,
							 (IFF_UP | IFF_RUNNING | IFF_PROMISC)) < 0) {
		return -1;
	}

	pcaperr[0] = '\0';

	if ((context->pcap = pcap_open_live(context->ifname, LORCON_MAX_PACKET_LEN, 
										1, 1000, pcaperr)) == NULL) {
		snprintf(context->errstr, LORCON_STATUS_MAX, "%s", pcaperr);
		return -1;
	}

	context->capture_fd = pcap_get_selectable_fd(context->pcap);

	context->dlt = pcap_datalink(context->pcap);

	context->inject_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (context->inject_fd < 0) {
		snprintf(context->errstr, LORCON_STATUS_MAX, "failed to create injection "
				 "socket: %s", strerror(errno));
		pcap_close(context->pcap);
		return -1;
	}

	memset(&if_req, 0, sizeof(if_req));
	memcpy(if_req.ifr_name, context->ifname, IFNAMSIZ);
	if_req.ifr_name[IFNAMSIZ - 1] = 0;
	if (ioctl(context->inject_fd, SIOCGIFINDEX, &if_req) < 0) {
		snprintf(context->errstr, LORCON_STATUS_MAX, "failed to get interface idex: %s",
				 strerror(errno));
		close(context->inject_fd);
		pcap_close(context->pcap);
		return -1;
	}

	memset(&sa_ll, 0, sizeof(sa_ll));
	sa_ll.sll_family = AF_PACKET;
	sa_ll.sll_protocol = htons(ETH_P_80211_RAW);
	sa_ll.sll_ifindex = if_req.ifr_ifindex;
	if (bind(context->inject_fd, (struct sockaddr *) &sa_ll, sizeof(sa_ll)) != 0) {
		snprintf(context->errstr, LORCON_STATUS_MAX, "failed to bind injection "
				 "socket: %s", strerror(errno));
		close(context->inject_fd);
		pcap_close(context->pcap);
		return -1;
	}

	return 1;
}

int tuntap_sendbytes(lorcon_t *context, int length, u_char *bytes) {
	int ret;

	if (context->inject_fd < 0) {
		snprintf(context->errstr, LORCON_STATUS_MAX, "no inject control opened");
		return -1;
	}

	ret = write(context->inject_fd, bytes, length);

	if (ret < 0) {
		snprintf(context->errstr, LORCON_STATUS_MAX, "injection write failed: %s",
				 strerror(errno));
		return -1;
	}

	if (ret < length) 
		snprintf(context->errstr, LORCON_STATUS_MAX, "injection got short write");
		

	return ret;
}

int drv_tuntap_init(lorcon_t *context) {
	context->openinject_cb = tuntap_openmon_cb;
	context->openmon_cb = tuntap_openmon_cb;
	context->openinjmon_cb = tuntap_openmon_cb;

	return 1;
}

lorcon_driver_t *drv_tuntap_listdriver(lorcon_driver_t *head) {
	lorcon_driver_t *d = (lorcon_driver_t *) malloc(sizeof(lorcon_driver_t));

	d->name = strdup("tuntap");
	d->details = strdup("Linux tuntap virtual interface drivers");
	d->init_func = drv_tuntap_init;
	d->probe_func = NULL;

	d->next = head;

	return d;
}

#endif



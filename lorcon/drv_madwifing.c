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
#include "drv_madwifing.h"

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

#include <linux/types.h>
#include <linux/if.h>
#include <linux/wireless.h>

#include <net/ethernet.h>
#include <netpacket/packet.h>

#include "ifcontrol_linux.h"
#include "madwifing_control.h"
#include "lorcon_int.h"

/* Monitor, inject, and injmon are all the same method, make a new
 * mwng VAP */
int madwifing_openmon_cb(lorcon_t *context) {
	struct madwifi_vaps *mwvaps;
	char *parent;
	char pcaperr[PCAP_ERRBUF_SIZE];
	short flags;
	struct ifreq if_req;
	struct sockaddr_ll sa_ll;
	int optval;
	socklen_t optlen;

	if ((mwvaps = madwifing_list_vaps(context->ifname, context->errstr)) == NULL) {
		snprintf(context->errstr, LORCON_STATUS_MAX, "drv_madwifing failed to find "
				 "information about %s", context->ifname);
		return -1;
	}

	// Assign a vapname based on the interface
	if (strlen(context->vapname) == 0) {
		snprintf(context->vapname, MAX_IFNAME_LEN, "%smon", context->ifname);
	}


	// Find the parent of whatever interface they specified (ought to be the 
	// parent already)
	if ((parent = madwifing_find_parent(mwvaps)) == NULL) {
		free(parent);
		madwifing_free_vaps(mwvaps);
		return -1;
	}

	// Make a vap
	if (madwifing_build_vap(parent, context->errstr, context->vapname,
							context->vapname, IEEE80211_M_MONITOR, 
							IEEE80211_CLONE_BSSID) < 0) { 
		free(parent);
		madwifing_free_vaps(mwvaps);
		return -1;
	}

	madwifing_free_vaps(mwvaps);
	free(parent);
	parent = NULL;

	if (ifconfig_delta_flags(context->vapname, context->errstr,
							 (IFF_UP | IFF_RUNNING | IFF_PROMISC)) < 0) {
		return -1;
	}

	// Set the VAP to radiotap
	if (madwifing_setdevtype(context->vapname, ARPHDR_RADIOTAP, 
							 context->errstr) != 0) {
		return -1;
	}

	pcaperr[0] = '\0';

	if ((context->pcap = pcap_open_live(context->vapname, LORCON_MAX_PACKET_LEN, 
										1, context->timeout_ms, pcaperr)) == NULL) {
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
	memcpy(if_req.ifr_name, context->vapname, IFNAMSIZ);
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
	sa_ll.sll_protocol = htons(ETH_P_ALL);
	sa_ll.sll_ifindex = if_req.ifr_ifindex;

	if (bind(context->inject_fd, (struct sockaddr *) &sa_ll, sizeof(sa_ll)) != 0) {
		snprintf(context->errstr, LORCON_STATUS_MAX, "failed to bind injection "
				 "socket: %s", strerror(errno));
		close(context->inject_fd);
		pcap_close(context->pcap);
		return -1;
	}

	optlen = sizeof(optval);
	optval = 20;
	if (setsockopt(context->inject_fd, SOL_SOCKET, SO_PRIORITY, &optval, optlen)) {
		snprintf(context->errstr, LORCON_STATUS_MAX, "failed to set priority on "
				 "injection socket: %s", strerror(errno));
		close(context->inject_fd);
		pcap_close(context->pcap);
		return -1;
	}

	return 1;
}


int madwifing_getmac_cb(lorcon_t *context, uint8_t **mac) {
	/* 802.11 MACs are always 6 */
	uint8_t int_mac[6];

	if (ifconfig_get_hwaddr(context->vapname, context->errstr, int_mac) < 0) {
		return -1;
	}

	(*mac) = malloc(sizeof(uint8_t) * 6);

	memcpy(*mac, int_mac, 6);

	return 6;
}

int madwifing_setmac_cb(lorcon_t *context, int mac_len, uint8_t *mac) {
	short flags;

	/* 802.11 MACs are always 6 */
	if (mac_len != 6) {
		snprintf(context->errstr, LORCON_STATUS_MAX, 
				 "MAC passed to mac80211 driver on %s not 6 bytes, all "
				 "802.11 MACs must be 6 bytes", context->vapname);
		return -1;
	}

	if (flags = ifconfig_get_flags(context->vapname, 
								   context->errstr, &flags) < 0) 
		return -1;

	if (flags & IFF_UP) 
		if (ifconfig_ifupdown(context->vapname, context->errstr, 0) < 0)
			return -1;

	if (ifconfig_set_hwaddr(context->vapname, context->errstr, mac) < 0)
		return -1;

	if (flags & IFF_UP)
		if (ifconfig_ifupdown(context->vapname, context->errstr, 1) < 0)
			return -1;

	return 1;
}

int madwifing_sendpacket(lorcon_t *context, lorcon_packet_t *packet) {
	int ret;

	u_char rtap_hdr[] = {
		/* rt version */
		0x00, 0x00, 
		/* rt len */
		0x0e, 0x00, 
		/* rt bitmap, flags, tx, rx */
		0x02, 0xc0, 0x00, 0x00, 
		/* Don't allow frgmentation */
		0x00,
		/* pad */
		0x00,
		/* rx and tx set to inject */
		0x00, 0x00,
		0x00, 0x00,
	};

	u_char *bytes;
	int len, freebytes;

	struct iovec iov[2];

	struct msghdr msg = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = iov,
		.msg_iovlen = 2,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = 0,
	};

	if (packet->lcpa != NULL) {
		len = lcpa_size(packet->lcpa);
		freebytes = 1;
		bytes = (u_char *) malloc(sizeof(u_char) * len);
		lcpa_freeze(packet->lcpa, bytes);
	} else if (packet->packet_header != NULL) {
		freebytes = 0;
		len = packet->length_header;
		bytes = (u_char *) packet->packet_header;
	} else {
		freebytes = 0;
		len = packet->length;
		bytes = (u_char *) packet->packet_raw;
	}

	iov[0].iov_base = &rtap_hdr;
	iov[0].iov_len = sizeof(rtap_hdr);
	iov[1].iov_base = bytes;
	iov[1].iov_len = len;

	/*
	if (encrypt)
		rtap_hdr[8] |= IEEE80211_RADIOTAP_F_WEP;
	*/

	ret = sendmsg(context->inject_fd, &msg, 0);

	if (freebytes)
		free(bytes);
	
	return ret;
}

int drv_madwifing_init(lorcon_t *context) {
	context->openinject_cb = madwifing_openmon_cb;
	context->openmon_cb = madwifing_openmon_cb;
	context->openinjmon_cb = madwifing_openmon_cb;

	context->sendpacket_cb = madwifing_sendpacket;

	context->getmac_cb = madwifing_getmac_cb;
	context->setmac_cb = madwifing_setmac_cb;

	context->auxptr = NULL;

	return 1;
}

int drv_madwifing_probe(const char *interface) {

	return 0;
}

lorcon_driver_t *drv_madwifing_listdriver(lorcon_driver_t *head) {
	lorcon_driver_t *d = (lorcon_driver_t *) malloc(sizeof(lorcon_driver_t));

	d->name = strdup("madwifing");
	d->details = strdup("Linux madwifi-ng drivers, deprecated by ath5k and ath9k");
	d->init_func = drv_madwifing_init;
	d->probe_func = drv_madwifing_probe;

	d->next = head;

	return d;
}

#if 0
/* 
 * Change the local interface to the specified MAC address to let the 
 * Atheros chip ACK for us.
 * Procedure is:
 *   + Delete all VAPs
 *   + ifconfig wifi0 down
 *   + SIOCSIFHWADDR
 *   + Create new VAP
 *   + ifconfig lor0 up
 */
int madwifing_selfack(struct tx80211 *in_tx, uint8_t *addr)
{
	struct madwifi_vaps *vaplist = NULL;
	int n;

	if (in_tx->extra == NULL) {
		/* User specified sub-interface, not master; 
		 * This doesn't help us
		 */
                snprintf(in_tx->errstr, TX80211_STATUS_MAX,
				"MADWIFI SelfACK: Cannot set MAC address for "
				"sub-interface, must specify master name");
		return TX80211_ENOTSUPP;
	}

	/* Close the socket for the interface */
	wtinj_close(in_tx);

	/* Get a list of all VAP's (should be only one) */
	vaplist = madwifing_list_vaps(in_tx->extra, in_tx->errstr);

	/* Delete all VAPs */
	if (vaplist != NULL) {
		for (n = 0; n < vaplist->vaplen; n++) {
			if (madwifing_destroy_vap(vaplist->vaplist[n], 
					in_tx->errstr) < 0) {
				madwifing_free_vaps(vaplist);
				return -1;
			}
		}
		madwifing_free_vaps(vaplist);
	}

	if (ifconfig_ifupdown(in_tx->extra, in_tx->errstr, 
			TX80211_IFDOWN) < 0) {
		snprintf(in_tx->errstr, TX80211_STATUS_MAX,
			"MADWIFI SelfACK: Failed to place interface %d in the "
			"DOWN state before changing MAC address.", 
			in_tx->ifname);
		return -1;
	}
	
	if (ifconfig_set_hwaddr(in_tx->extra, in_tx->errstr, addr) < 0) {
		/* Retain message from set_hwaddr */
		return -1;
	}

	if (ifconfig_ifupdown(in_tx->extra, in_tx->errstr, TX80211_IFUP) < 0) {
		snprintf(in_tx->errstr, TX80211_STATUS_MAX,
			"MADWIFI SelfACK: Failed to place interface %d in the "
			"UP state after changing MAC address.", 
			in_tx->extra);
		return -1;
	}

	/* Build the vap and put the name into ifname */
	if (madwifing_build_vap(in_tx->extra, in_tx->errstr, "lorcon", 
			in_tx->ifname, IEEE80211_M_MONITOR,
			IEEE80211_CLONE_BSSID) < 0) {
		snprintf(in_tx->errstr, TX80211_STATUS_MAX,
				"MADWIFI SelfACK: Failed to build a new VAP");
		return -1;
	}

	if (ifconfig_ifupdown(in_tx->ifname, in_tx->errstr, 
			TX80211_IFUP) < 0) {
		snprintf(in_tx->errstr, TX80211_STATUS_MAX,
			"MADWIFI SelfACK: Failed to place interface %s"
			"in the UP state after changing MAC address.",
			in_tx->ifname);
		return -1;
	}

	if (wtinj_open(in_tx) != 0) {
		return -1;
	}

	return 0;
}

#endif

#endif /* linux */

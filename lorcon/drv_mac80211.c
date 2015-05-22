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
#include "drv_mac80211.h"

#if defined(SYS_LINUX) && defined(HAVE_LINUX_WIRELESS) && defined(HAVE_LIBNL)

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

#ifndef IEEE80211_RADIOTAP_F_FRAG
#define IEEE80211_RADIOTAP_F_FRAG	0x08
#endif

struct mac80211_lorcon {
	void *nlhandle, *nlcache, *nlfamily;
};

/* Monitor, inject, and injmon are all the same method, open a new vap */
int mac80211_openmon_cb(lorcon_t *context) {
	char *parent;
	char pcaperr[PCAP_ERRBUF_SIZE];
	struct mac80211_lorcon *extras = (struct mac80211_lorcon *) context->auxptr;
	short flags;
	struct ifreq if_req;
	struct sockaddr_ll sa_ll;
	int optval;
	socklen_t optlen;

	if (strlen(context->vapname) == 0) {
		snprintf(context->vapname, MAX_IFNAME_LEN, "%smon", context->ifname);
	}

	if ((parent = nl80211_find_parent(context->vapname)) == NULL) {
		if (nl80211_createvap(context->ifname, context->vapname, context->errstr) < 0) {
			free(parent);
			return -1;
		}
	} 

	free(parent);

	if (ifconfig_delta_flags(context->vapname, context->errstr,
							 (IFF_UP | IFF_RUNNING | IFF_PROMISC)) < 0) {
		return -1;
	}

	if (nl80211_connect(context->vapname, &(extras->nlhandle), &(extras->nlcache),
						&(extras->nlfamily), context->errstr) < 0) {
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
		nl80211_disconnect(extras->nlhandle);
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
		nl80211_disconnect(extras->nlhandle);
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
		nl80211_disconnect(extras->nlhandle);
		return -1;
	}

	optlen = sizeof(optval);
	optval = 20;
	if (setsockopt(context->inject_fd, SOL_SOCKET, SO_PRIORITY, &optval, optlen)) {
		snprintf(context->errstr, LORCON_STATUS_MAX, "failed to set priority on "
				 "injection socket: %s", strerror(errno));
		close(context->inject_fd);
		pcap_close(context->pcap);
		nl80211_disconnect(extras->nlhandle);
		return -1;
	}

	return 1;
}

int mac80211_setchan_cb(lorcon_t *context, int channel) {
	struct mac80211_lorcon *extras = (struct mac80211_lorcon *) context->auxptr;

	if (nl80211_setchannel_cache(context->vapname, extras->nlhandle, extras->nlfamily,
								 channel, 0, context->errstr) < 0) {
		return -1;
	}

	return 0;
}

int mac80211_getchan_cb(lorcon_t *context) {
	int ch;

	if ((ch = iwconfig_get_channel(context->vapname, context->errstr)) < 0) {
		// Fall back to parent if vap doesn't act right (mac80211 seems to do this)
		if ((ch = iwconfig_get_channel(context->ifname, context->errstr)) < 0)
			return -1;
	}

	return ch;
}

int mac80211_getmac_cb(lorcon_t *context, uint8_t **mac) {
	/* 802.11 MACs are always 6 */
	uint8_t int_mac[6];

	if (ifconfig_get_hwaddr(context->vapname, context->errstr, int_mac) < 0) {
		return -1;
	}

	(*mac) = malloc(sizeof(uint8_t) * 6);

	memcpy(*mac, int_mac, 6);

	return 6;
}

int mac80211_setmac_cb(lorcon_t *context, int mac_len, uint8_t *mac) {
	short flags;

	/* 802.11 MACs are always 6 */
	if (mac_len != 6) {
		snprintf(context->errstr, LORCON_STATUS_MAX, 
				 "MAC passed to mac80211 driver on %s not 6 bytes, all "
				 "802.11 MACs must be 6 bytes", context->vapname);
		return -1;
	}

	if (ifconfig_ifupdown(context->vapname, context->errstr, 0) < 0)
		return -1;

	if (ifconfig_set_hwaddr(context->vapname, context->errstr, mac) < 0)
		return -1;

	if (ifconfig_ifupdown(context->vapname, context->errstr, 1) < 0)
		return -1;

	return 0;
}

int mac80211_sendpacket(lorcon_t *context, lorcon_packet_t *packet) {
	int ret;

	u_char rtap_hdr[] = {
		/* rt version */
		0x00, 0x00, 
		/* rt len */
		0x0e, 0x00, 
		/* rt bitmap, flags, tx, rx */
		0x02, 0xc0, 0x00, 0x00, 
		/* Allow frgmentation */
		IEEE80211_RADIOTAP_F_FRAG,
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

	snprintf(context->errstr, LORCON_STATUS_MAX, "drv_mac80211 failed "
			 "to send packet: %s", strerror(errno));

	if (freebytes)
		free(bytes);
	
	return ret;
}

int drv_mac80211_init(lorcon_t *context) {
	struct mac80211_lorcon *extras = 
		(struct mac80211_lorcon *) malloc(sizeof(struct mac80211_lorcon));

	memset(extras, 0, sizeof(struct mac80211_lorcon));

	context->openinject_cb = mac80211_openmon_cb;
	context->openmon_cb = mac80211_openmon_cb;
	context->openinjmon_cb = mac80211_openmon_cb;

	context->sendpacket_cb = mac80211_sendpacket;

	context->setchan_cb = mac80211_setchan_cb;
	context->getchan_cb = mac80211_getchan_cb;

	context->getmac_cb = mac80211_getmac_cb;
	context->setmac_cb = mac80211_setmac_cb;

	context->auxptr = extras;

	return 1;
}

int drv_mac80211_probe(const char *interface) {
	/* key driver detection entirely off the phy80211 /sys attribute */
	if (ifconfig_get_sysattr(interface, "phy80211"))
		return 1;

	return 0;
}

lorcon_driver_t *drv_mac80211_listdriver(lorcon_driver_t *head) {
	lorcon_driver_t *d = (lorcon_driver_t *) malloc(sizeof(lorcon_driver_t));

	d->name = strdup("mac80211");
	d->details = strdup("Linux mac80211 kernel drivers, includes all in-kernel "
						"drivers on modern systems");
	d->init_func = drv_mac80211_init;
	d->probe_func = drv_mac80211_probe;

	d->next = head;

	return d;
}

#endif



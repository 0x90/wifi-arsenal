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

#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <pcap.h>

#include <lorcon.h>
#include <lorcon_packet.h>
#include "lorcon_int.h"

#include "drv_mac80211.h"
#include "drv_madwifing.h"
#include "drv_tuntap.h"

const char *lorcon_get_error(lorcon_t *context) {
	return context->errstr;
}

lorcon_driver_t *lorcon_list_drivers() {
	lorcon_driver_t *drv_head = NULL;

#ifdef USE_DRV_MAC80211
	drv_head = drv_mac80211_listdriver(drv_head);
#endif

#ifdef USE_DRV_TUNTAP
	drv_head = drv_tuntap_listdriver(drv_head);
#endif

#ifdef USE_DRV_MADWIFING
	drv_head = drv_madwifing_listdriver(drv_head);
#endif

	return drv_head;

}

lorcon_driver_t *_lorcon_copy_driver(lorcon_driver_t *driver) {
	lorcon_driver_t *r;

	r = (lorcon_driver_t *) malloc(sizeof(lorcon_driver_t));

	r->name = strdup(driver->name);
	r->details = strdup(driver->details);
	r->init_func = driver->init_func;
	r->probe_func = driver->probe_func;
	r->next = NULL;

	return r;
}

lorcon_driver_t *lorcon_find_driver(const char *driver) {
	lorcon_driver_t *list = NULL, *i = NULL, *ret = NULL;

	i = list = lorcon_list_drivers();

	while (i) {
		if (strcasecmp(i->name, driver) == 0) {
			ret = _lorcon_copy_driver(i);
			break;
		}

		i = i->next;
	}

	lorcon_free_driver_list(list);

	return ret;
}

lorcon_driver_t *lorcon_auto_driver(const char *interface) {
	lorcon_driver_t *list = NULL, *i = NULL, *ret = NULL;

	i = list = lorcon_list_drivers();

	while (i) {
		if (i->probe_func != NULL) {
			if ((*(i->probe_func))(interface) > 0) {
				ret = _lorcon_copy_driver(i);
				break;
			}
		}

		i = i->next;
	}

	lorcon_free_driver_list(list);

	return ret;
}

void lorcon_free_driver_list(lorcon_driver_t *list) {
	lorcon_driver_t *t = NULL;

	while (list != NULL) {
		free(list->name);
		free(list->details);
		t = list;
		list = list->next;
		free(t);
	}
}

lorcon_t *lorcon_create(const char *interface, lorcon_driver_t *driver) {
	lorcon_t *context = NULL;

	if (driver->init_func == NULL)
		return NULL;
	
	context = (lorcon_t *) malloc(sizeof(lorcon_t));

	memset(context, 0, sizeof(lorcon_t));

	snprintf(context->drivername, 32, "%s", driver->name);
	snprintf(context->ifname, MAX_IFNAME_LEN, "%s", interface);

	context->vapname[0] = 0;

	context->pcap = NULL;
	context->inject_fd = context->ioctl_fd = context->capture_fd = -1;
	context->packets_sent = 0;
	context->packets_recv = 0;
	context->dlt = -1;
	context->channel = -1;
	context->errstr[0] = 0;

	context->timeout_ms = 0;

	memset(context->original_mac, 0, 6);

	context->handler_cb = NULL;
	context->handler_user = NULL;

	context->close_cb = NULL;
	context->openinject_cb = NULL;
	context->openmon_cb = NULL;
	context->openinjmon_cb = NULL;
	context->setchan_cb = NULL;
	context->getchan_cb = NULL;
	context->sendpacket_cb = NULL;
	context->getpacket_cb = NULL;
	context->setdlt_cb = NULL;
	context->getdlt_cb = NULL;
	context->getmac_cb = NULL;
	context->setmac_cb = NULL;

	context->wepkeys = NULL;

	if ((*(driver->init_func))(context) < 0) {
		free(context);
		return NULL;
	}


	return context;
}

void lorcon_free(lorcon_t *context) {
	if (context->close_cb != NULL) 
		(*(context->close_cb))(context);

	free(context);
}

void lorcon_set_timeout(lorcon_t *context, int in_timeout) {
	context->timeout_ms = in_timeout;
}

int lorcon_get_timeout(lorcon_t *context) {
	return context->timeout_ms;
}

int lorcon_set_channel(lorcon_t *context, int channel) {
	if (context->setchan_cb == NULL) {
		snprintf(context->errstr, LORCON_STATUS_MAX, 
				 "Driver %s does not support setting channel", context->drivername);
		return LORCON_ENOTSUPP;
	}

	return (*(context->setchan_cb))(context, channel);
}

int lorcon_get_channel(lorcon_t *context) {
	if (context->getchan_cb == NULL) {
		snprintf(context->errstr, LORCON_STATUS_MAX, 
				 "Driver %s does not support getting channel", context->drivername);
		return LORCON_ENOTSUPP;
	}

	return (*(context->getchan_cb))(context);
}

int lorcon_open_inject(lorcon_t *context) {
	if (context->openinject_cb == NULL) {
		snprintf(context->errstr, LORCON_STATUS_MAX, 
				 "Driver %s does not support INJECT mode", context->drivername);
		return LORCON_ENOTSUPP;
	}

	return (*(context->openinject_cb))(context);
}

int lorcon_open_monitor(lorcon_t *context) {
	if (context->openmon_cb == NULL) {
		snprintf(context->errstr, LORCON_STATUS_MAX, 
				 "Driver %s does not support MONITOR mode", context->drivername);
		return LORCON_ENOTSUPP;
	}

	return (*(context->openmon_cb))(context);
}

int lorcon_open_injmon(lorcon_t *context) {
	if (context->openinjmon_cb == NULL) {
		snprintf(context->errstr, LORCON_STATUS_MAX, 
				 "Driver %s does not support INJMON mode", context->drivername);
		return LORCON_ENOTSUPP;
	}

	return (*(context->openinjmon_cb))(context);
}

void lorcon_set_vap(lorcon_t *context, const char *vap) {
	snprintf(context->vapname, MAX_IFNAME_LEN, "%s", vap);
}

const char *lorcon_get_vap(lorcon_t *context) {
	return context->vapname;
}

const char *lorcon_get_capiface(lorcon_t *context) {
	if (context->vapname)
		return context->vapname;

	return context->ifname;
}

const char *lorcon_get_driver_name(lorcon_t *context) {
	return context->drivername;
}

void lorcon_close(lorcon_t *context) {
	if (context->close_cb == NULL) {
		return;
	}

	(*(context->close_cb))(context);
}

int lorcon_get_selectable_fd(lorcon_t *context) {
	return context->capture_fd;
}

pcap_t *lorcon_get_pcap(lorcon_t *context) {
	return context->pcap;
}

void lorcon_pcap_handler(u_char *user, const struct pcap_pkthdr *h,
						 const u_char *bytes) {
	lorcon_t *context = (lorcon_t *) user;
	lorcon_packet_t *packet;

	if (context->handler_cb == NULL)
		return;

	packet = lorcon_packet_from_pcap(context, h, bytes);

	(*(context->handler_cb))(context, packet, context->handler_user);
}

int lorcon_loop(lorcon_t *context, int count, lorcon_handler callback,
				u_char *user) {
	if (context->pcap == NULL) {
		snprintf(context->errstr, LORCON_STATUS_MAX, 
				 "capture driver %s did not create a pcap context",
				 lorcon_get_driver_name(context));
		return LORCON_ENOTSUPP;
	}

	context->handler_cb = callback;
	context->handler_user = user;

	return pcap_loop(context->pcap, count, lorcon_pcap_handler, (u_char *) context);
}

int lorcon_dispatch(lorcon_t *context, int count, lorcon_handler callback,
					u_char *user) {
	if (context->pcap == NULL) {
		snprintf(context->errstr, LORCON_STATUS_MAX, 
				 "capture driver %s did not create a pcap context",
				 lorcon_get_driver_name(context));
		return LORCON_ENOTSUPP;
	}

	context->handler_cb = callback;
	context->handler_user = user;

	return pcap_dispatch(context->pcap, count, lorcon_pcap_handler, (u_char *) context);
}

int lorcon_next_ex(lorcon_t *context, lorcon_packet_t **packet) {
	struct pcap_pkthdr *pkt_hdr;
	const u_char *pkt_data;
	int ret;

	/* If it's not a pcap source, try the direct fetch */
	if (context->pcap == NULL) {
		if (context->getpacket_cb == NULL) {
			snprintf(context->errstr, LORCON_STATUS_MAX, 
					 "capture driver %s did not create a pcap context and does not "
					 "define a getpacket callback", lorcon_get_driver_name(context));
			return LORCON_ENOTSUPP;
		}

		return (*(context->getpacket_cb))(context, packet);
	}

	if ((ret = pcap_next_ex(context->pcap, &pkt_hdr, &pkt_data)) < 0) {
		*packet = NULL;
		return ret;
	}

	if (pkt_data == NULL)
		return 0;

	*packet = lorcon_packet_from_pcap(context, pkt_hdr, pkt_data);

	if (*packet == NULL)
		return ret;

	lorcon_packet_set_freedata(*packet, 0);

	return ret;
}

void lorcon_breakloop(lorcon_t *context) {
	if (context->pcap == NULL) {
		snprintf(context->errstr, LORCON_STATUS_MAX, 
				 "capture driver %s did not create a pcap context",
				 lorcon_get_driver_name(context));
		return;
	}

	pcap_breakloop(context->pcap);
}

int lorcon_inject(lorcon_t *context, lorcon_packet_t *packet) {
	if (context->sendpacket_cb == NULL) {
		snprintf(context->errstr, LORCON_STATUS_MAX, 
				 "Driver %s does not define a send function", context->drivername);
		return LORCON_ENOTSUPP;
	}

	return (*(context->sendpacket_cb))(context, packet);
}

int lorcon_send_bytes(lorcon_t *context, int length, u_char *bytes) {
	lorcon_packet_t *pack;
	int ret;

	if (context->sendpacket_cb == NULL) {
		snprintf(context->errstr, LORCON_STATUS_MAX, 
				 "Driver %s does not define a send function", context->drivername);
		return LORCON_ENOTSUPP;
	}

	pack = (lorcon_packet_t *) malloc(sizeof(lorcon_packet_t));
	memset(pack, 0, sizeof(lorcon_packet_t));
	pack->free_data = 0;
	pack->packet_raw = bytes;
	pack->length = length;

	ret = (*(context->sendpacket_cb))(context, pack);

	lorcon_packet_free(pack);
	return ret;
}

unsigned long int lorcon_get_version() {
	return LORCON_VERSION;
}

int lorcon_add_wepkey(lorcon_t *context, u_char *bssid, u_char *key, int length) {
	lorcon_wep_t *wep;

	if (length > 26)
		return -1;
	
	wep = (lorcon_wep_t *) malloc(sizeof(lorcon_wep_t));

	memcpy(wep->bssid, bssid, 6);
	memcpy(wep->key, key, length);
	wep->len = length;

	wep->next = context->wepkeys;
	context->wepkeys = wep;

	return 1;
}

int lorcon_set_filter(lorcon_t *context, const char *filter) {
	struct bpf_program fp;

	if (context->pcap == NULL) {
		snprintf(context->errstr, LORCON_STATUS_MAX,
				 "Driver %s does not define a pcap capture type", context->drivername);
		return LORCON_ENOTSUPP;
	}

	if (pcap_compile(context->pcap, &fp, filter, 1, 0) < 0) {
		snprintf(context->errstr, LORCON_STATUS_MAX,
				 "%s", pcap_geterr(context->pcap));
		return -1;
	}

	if (pcap_setfilter(context->pcap, &fp) < 0) {
		snprintf(context->errstr, LORCON_STATUS_MAX,
				 "%s", pcap_geterr(context->pcap));
		return -1;
	}

	return 1;
}

int lorcon_set_compiled_filter(lorcon_t *context, struct bpf_program *filter) {
	if (context->pcap == NULL) {
		snprintf(context->errstr, LORCON_STATUS_MAX,
				 "Driver %s does not define a pcap capture type", context->drivername);
		return LORCON_ENOTSUPP;
	}

	if (pcap_setfilter(context->pcap, filter) < 0) {
		snprintf(context->errstr, LORCON_STATUS_MAX,
				 "%s", pcap_geterr(context->pcap));
		return -1;
	}

	return 1;
}

int lorcon_get_hwmac(lorcon_t *context, uint8_t **mac) {
	if (context->getmac_cb == NULL) {
		snprintf(context->errstr, LORCON_STATUS_MAX,
				 "Driver %s does not support fetching MAC address",
				 context->drivername);
		return LORCON_ENOTSUPP;
	}

	return (*(context->getmac_cb))(context, mac);
}

int lorcon_set_hwmac(lorcon_t *context, int mac_len, uint8_t *mac) {
	if (context->setmac_cb == NULL) {
		snprintf(context->errstr, LORCON_STATUS_MAX,
				 "Driver %s does not support fetching MAC address",
				 context->drivername);
		return LORCON_ENOTSUPP;
	}

	return (*(context->setmac_cb))(context, mac_len, mac);
}



/* horst - Highly Optimized Radio Scanning Tool
 *
 * Copyright (C) 2005-2014 Bruno Randolf (br1@einfach.org)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "main.h"
#include "util.h"
#include "wlan80211.h"
#include "essid.h"


static struct timeval last_nodetimeout;


static void
copy_nodeinfo(struct node_info* n, struct packet_info* p)
{
	struct node_info* ap;

	memcpy(&(n->last_pkt), p, sizeof(struct packet_info));
	// update timestamp
	n->last_seen = time(NULL);
	n->pkt_count++;
	n->pkt_types |= p->pkt_types;
	if (p->ip_src)
		n->ip_src = p->ip_src;
	if (p->wlan_mode)
		n->wlan_mode |= p->wlan_mode;
	if (p->olsr_tc)
		n->olsr_tc = p->olsr_tc;
	if (p->olsr_neigh)
		n->olsr_neigh = p->olsr_neigh;
	if (p->pkt_types & PKT_TYPE_OLSR)
		n->olsr_count++;
	if (p->bat_gw)
		n->bat_gw = 1;
	if (p->wlan_bssid[0] != 0xff &&
	    !(p->wlan_bssid[0] == 0 && p->wlan_bssid[1] == 0 &&
	      p->wlan_bssid[2] == 0 && p->wlan_bssid[3] == 0 &&
	      p->wlan_bssid[4] == 0 && p->wlan_bssid[5] == 0)) {
		memcpy(n->wlan_bssid, p->wlan_bssid, MAC_LEN);

		if ((n->wlan_mode & WLAN_MODE_STA) && n->wlan_ap_node == NULL) {
			/* find AP node for this BSSID */
			list_for_each(&nodes, ap, list) {
				if (memcmp(p->wlan_bssid, ap->last_pkt.wlan_src, MAC_LEN) == 0) {
					DEBUG("AP node found %p\n", ap);
					DEBUG("AP node ESSID %s\n",
					      ap->essid != NULL ? ap->essid->essid : "unknown");
					n->wlan_ap_node = ap;
					break;
				}
			}
			n->wlan_rsn = ap->wlan_rsn;
			n->wlan_wpa = ap->wlan_wpa;
		}
	}
	if ((p->wlan_type == WLAN_FRAME_BEACON) ||
	    (p->wlan_type == WLAN_FRAME_PROBE_RESP)) {
		n->wlan_tsf = p->wlan_tsf;
		n->wlan_bintval = p->wlan_bintval;
		n->wlan_wpa = p->wlan_wpa;
		n->wlan_rsn = p->wlan_rsn;
		// Channel is only really known for Beacon and Probe response
		n->wlan_channel = p->wlan_channel;
	} else if ((n->wlan_mode & WLAN_MODE_STA) && n->wlan_ap_node != NULL) {
		// for STA we can use the channel from the AP
		n->wlan_channel = n->wlan_ap_node->wlan_channel;
	} else if (n->wlan_channel == 0 && p->wlan_channel != 0) {
		// otherwise only override if channel was unknown
		n->wlan_channel = p->wlan_channel;
	}

	ewma_add(&n->phy_sig_avg, -p->phy_signal);
	n->phy_sig_sum += -p->phy_signal;
	n->phy_sig_count += 1;

	if (p->phy_signal > n->phy_sig_max || n->phy_sig_max == 0)
		n->phy_sig_max = p->phy_signal;

	if ((p->wlan_type == WLAN_FRAME_DATA) ||
	    (p->wlan_type == WLAN_FRAME_QDATA) ||
	    (p->wlan_type == WLAN_FRAME_AUTH) ||
	    (p->wlan_type == WLAN_FRAME_BEACON) ||
	    (p->wlan_type == WLAN_FRAME_PROBE_RESP) ||
	    (p->wlan_type == WLAN_FRAME_DATA_CF_ACK) ||
	    (p->wlan_type == WLAN_FRAME_DATA_CF_POLL) ||
	    (p->wlan_type == WLAN_FRAME_DATA_CF_ACKPOLL) ||
	    (p->wlan_type == WLAN_FRAME_QDATA_CF_ACK) ||
	    (p->wlan_type == WLAN_FRAME_QDATA_CF_POLL) ||
	    (p->wlan_type == WLAN_FRAME_QDATA_CF_ACKPOLL))
		n->wlan_wep = p->wlan_wep;

	if (p->wlan_seqno != 0) {
		if (p->wlan_retry && p->wlan_seqno == n->wlan_seqno) {
			n->wlan_retries_all++;
			n->wlan_retries_last++;
		} else
			n->wlan_retries_last = 0;
		n->wlan_seqno = p->wlan_seqno;
	}
}


struct node_info*
node_update(struct packet_info* p)
{
	struct node_info* n;

	if (p->phy_flags & PHY_FLAG_BADFCS)
		return NULL;

	if (p->wlan_src[0] == 0 && p->wlan_src[1] == 0 &&
	    p->wlan_src[2] == 0 && p->wlan_src[3] == 0 &&
	    p->wlan_src[4] == 0 && p->wlan_src[5] == 0)
		return NULL;

	/* find node by wlan source address */
	list_for_each(&nodes, n, list) {
		if (memcmp(p->wlan_src, n->last_pkt.wlan_src, MAC_LEN) == 0) {
			DEBUG("node found %p\n", n);
			break;
		}
	}

	/* not found */
	if (&n->list == &nodes.n) {
		DEBUG("node adding\n");
		n = malloc(sizeof(struct node_info));
		memset(n, 0, sizeof(struct node_info));
		n->essid = NULL;
		ewma_init(&n->phy_sig_avg, 1024, 8);
		list_head_init(&n->on_channels);
		list_add_tail(&nodes, &n->list);
	}

	copy_nodeinfo(n, p);

	return n;
}

void
timeout_nodes(void)
{
	struct node_info *n, *m, *n2, *m2;
	struct chan_node *cn, *cn2;

	if ((the_time.tv_sec - last_nodetimeout.tv_sec) < conf.node_timeout )
		return;

	list_for_each_safe(&nodes, n, m, list) {
		if (n->last_seen < (the_time.tv_sec - conf.node_timeout)) {
			list_del(&n->list);
			if (n->essid != NULL)
				remove_node_from_essid(n);
			list_for_each_safe(&n->on_channels, cn, cn2, node_list) {
				list_del(&cn->node_list);
				list_del(&cn->chan_list);
				cn->chan->num_nodes--;
				free(cn);
			}
			/* remove AP pointers to this node */
			list_for_each_safe(&nodes, n2, m2, list) {
				if (n2->wlan_ap_node == n) {
					DEBUG("remove AP ref\n");
					n->wlan_ap_node = NULL;
				}
			}
			free(n);
		}
	}
	last_nodetimeout = the_time;
}

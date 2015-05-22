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

/******************* MAIN / OVERVIEW *******************/

#include <stdlib.h>
#include <string.h>

#include "display.h"
#include "main.h"
#include "util.h"
#include "wlan80211.h"
#include "wlan_util.h"
#include "olsr_header.h"
#include "batman_adv_header-14.h"
#include "listsort.h"
#include "channel.h"


static WINDOW *sort_win = NULL;
static WINDOW *dump_win = NULL;
static WINDOW *list_win = NULL;
static WINDOW *stat_win = NULL;

static int do_sort = 'n';
/* pointer to the sort function */
static int(*sortfunc)(const struct list_node*, const struct list_node*) = NULL;

/* sizes of split window (list_win & status_win) */
static int win_split;
static int stat_height;

static struct ewma usen_avg;
static struct ewma bpsn_avg;


/******************* UTIL *******************/

void
print_dump_win(const char *str, int refresh)
{
	wattron(dump_win, RED);
	wprintw(dump_win, str);
	wattroff(dump_win, RED);
	if (refresh)
		wrefresh(dump_win);
	else
		wnoutrefresh(dump_win);
}


/******************* SORTING *******************/

static int
compare_nodes_signal(const struct list_node *p1, const struct list_node *p2)
{
	struct node_info* n1 = list_entry(p1, struct node_info, list);
	struct node_info* n2 = list_entry(p2, struct node_info, list);

	if (n1->last_pkt.phy_signal > n2->last_pkt.phy_signal)
		return -1;
	else if (n1->last_pkt.phy_signal == n2->last_pkt.phy_signal)
		return 0;
	else
		return 1;
}


static int
compare_nodes_time(const struct list_node *p1, const struct list_node *p2)
{
	struct node_info* n1 = list_entry(p1, struct node_info, list);
	struct node_info* n2 = list_entry(p2, struct node_info, list);

	if (n1->last_seen > n2->last_seen)
		return -1;
	else if (n1->last_seen == n2->last_seen)
		return 0;
	else
		return 1;
}


static int
compare_nodes_channel(const struct list_node *p1, const struct list_node *p2)
{
	struct node_info* n1 = list_entry(p1, struct node_info, list);
	struct node_info* n2 = list_entry(p2, struct node_info, list);

	if (n1->wlan_channel < n2->wlan_channel)
		return 1;
	else if (n1->wlan_channel == n2->wlan_channel)
		return 0;
	else
		return -1;
}


static int
compare_nodes_bssid(const struct list_node *p1, const struct list_node *p2)
{
	struct node_info* n1 = list_entry(p1, struct node_info, list);
	struct node_info* n2 = list_entry(p2, struct node_info, list);

	return -memcmp(n1->wlan_bssid, n2->wlan_bssid, MAC_LEN);
}


static int
sort_input(int c)
{
	switch (c) {
	case 'n': case 'N': sortfunc = NULL; break;
	case 's': case 'S': sortfunc = compare_nodes_signal; break;
	case 't': case 'T': sortfunc = compare_nodes_time; break;
	case 'c': case 'C': sortfunc = compare_nodes_channel; break;
	case 'b': case 'B': sortfunc = compare_nodes_bssid; break;
	}

	switch (c) {
	case 'n': case 'N':
	case 's': case 'S':
	case 't': case 'T':
	case 'c': case 'C':
	case 'b': case 'B':
		do_sort = c;
		/* no break */
	case '\r': case KEY_ENTER:
		delwin(sort_win);
		sort_win = NULL;
		update_display(NULL);
		return 1;
	}
	return 0;
}


static void
show_sort_win(void)
{
	if (sort_win == NULL) {
		sort_win = newwin(1, COLS-2, win_split - 2, 1);
		wattron(sort_win, BLACKONWHITE);
		mvwhline(sort_win, 0, 0, ' ', COLS);
		mvwprintw(sort_win, 0, 0, " -> Sort by s:Signal t:Time b:BSSID c:Channel n:Don't sort [current: %c]", do_sort);
		wrefresh(sort_win);
	}
}


/******************* WINDOWS *******************/

#define STAT_WIDTH 11
#define STAT_START 4

static void
update_status_win(struct packet_info* p)
{
	int sig, siga, bps, dps, pps, rps, bpsn, usen;
	float use, rpsp = 0.0;
	int max_stat_bar = stat_height - STAT_START;
	struct channel_info* chan = NULL;

	if (p != NULL)
		werase(stat_win);

	wattron(stat_win, WHITE);
	mvwvline(stat_win, 0, 0, ACS_VLINE, stat_height);

	get_per_second(stats.bytes, stats.duration, stats.packets, stats.retries,
		       &bps, &dps, &pps, &rps);
	bps *= 8;
	bpsn = normalize(bps, 32000000, max_stat_bar); //theoretical: 54000000

	use = dps * 1.0 / 10000; /* usec, in percent */
	usen = normalize(use, 100, max_stat_bar);

	if (pps)
		rpsp = rps * 100.0 / pps;

	ewma_add(&usen_avg, usen);
	ewma_add(&bpsn_avg, bpsn);

	if (p != NULL) {
		sig = normalize_db(-p->phy_signal, max_stat_bar);

		if (p->pkt_chan_idx > 0)
			chan = &spectrum[p->pkt_chan_idx];

		if (chan != NULL && chan->packets >= 8)
			siga = normalize_db(ewma_read(&chan->signal_avg),
					    max_stat_bar);
		else
			siga = sig;

		wattron(stat_win, GREEN);
		mvwprintw(stat_win, 0, 1, "Sig: %5d", p->phy_signal);

		signal_average_bar(stat_win, sig, siga, STAT_START, 2, stat_height, 2);
	}

	wattron(stat_win, CYAN);
	mvwprintw(stat_win, 1, 1, "bps:%6s", kilo_mega_ize(bps));
	general_average_bar(stat_win, bpsn, ewma_read(&bpsn_avg),
			    stat_height, 5, 2,
			    CYAN, ALLCYAN);

	wattron(stat_win, YELLOW);
	mvwprintw(stat_win, 2, 1, "Use:%5.1f%%", use);
	general_average_bar(stat_win, usen, ewma_read(&usen_avg),
			    stat_height, 8, 2,
			    YELLOW, ALLYELLOW);

	mvwprintw(stat_win, 3, 1, "Retry: %2.0f%%", rpsp);

	wnoutrefresh(stat_win);
}


#define COL_PKT		3
#define COL_CHAN	COL_PKT + 7
#define COL_SIG		COL_CHAN + 4
#define COL_RATE	COL_SIG + 4
#define COL_SOURCE	COL_RATE + 4
#define COL_MODE	COL_SOURCE + 18
#define COL_ENC		COL_MODE + 9
#define COL_ESSID	COL_ENC + 6
#define COL_INFO	COL_ESSID + 13

static char spin[4] = {'/', '-', '\\', '|'};

static void
print_node_list_line(int line, struct node_info* n)
{
	struct packet_info* p = &n->last_pkt;
	char* ssid = NULL;

	if (n->pkt_types & PKT_TYPE_OLSR)
		wattron(list_win, GREEN);
	if (n->last_seen > (the_time.tv_sec - conf.node_timeout / 2))
		wattron(list_win, A_BOLD);
	else
		wattron(list_win, A_NORMAL);

	if (n->essid != NULL && n->essid->split > 0)
		wattron(list_win, RED);

	mvwprintw(list_win, line, 1, "%c", spin[n->pkt_count % 4]);

	mvwprintw(list_win, line, COL_PKT, "%.0f/%.0f%%",
		  n->pkt_count * 100.0 / stats.packets,
		  n->wlan_retries_all * 100.0 / n->pkt_count);

	if (n->wlan_channel)
		mvwprintw(list_win, line, COL_CHAN, "%3d", n->wlan_channel );

	mvwprintw(list_win, line, COL_SIG, "%3d", -ewma_read(&n->phy_sig_avg));
	mvwprintw(list_win, line, COL_RATE, "%3d", p->phy_rate/10);
	mvwprintw(list_win, line, COL_SOURCE, "%-17s", mac_name_lookup(p->wlan_src, 0));

	if (n->wlan_mode & WLAN_MODE_AP) {
		wprintw(list_win, " AP");
		if (n->essid != NULL)
			ssid = n->essid->essid;
	}
	if (n->wlan_mode & WLAN_MODE_IBSS) {
		wprintw(list_win, " ADH");
		if (n->essid != NULL)
			ssid = n->essid->essid;
	}
	if (n->wlan_mode & WLAN_MODE_STA) {
		wprintw(list_win, " STA");
		if (n->wlan_ap_node != NULL && n->wlan_ap_node->essid != NULL)
			ssid = n->wlan_ap_node->essid->essid;
	}
	if (n->wlan_mode & WLAN_MODE_PROBE) {
		wprintw(list_win, " PRB");
		ssid = p->wlan_essid;
	}
	if (n->wlan_mode & WLAN_MODE_4ADDR) {
			wprintw(list_win, " WDS");
	}

	if (n->wlan_rsn && n->wlan_wpa)
		mvwprintw(list_win, line, COL_ENC, "WPA12");
	else if (n->wlan_rsn)
		mvwprintw(list_win, line, COL_ENC, "WPA2");
	else if (n->wlan_wpa)
		mvwprintw(list_win, line, COL_ENC, "WPA1");
	else if (n->wlan_wep)
		mvwprintw(list_win, line, COL_ENC, "WEP?");

	if (ssid != NULL)
		mvwprintw(list_win, line, COL_ESSID, "%s ", ssid);

	if (ssid == NULL || strlen(ssid) < 12)
		wmove(list_win, line, COL_INFO);

	if (n->pkt_types & PKT_TYPE_OLSR)
		wprintw(list_win, "OLSR N:%d ", n->olsr_neigh);

	if (n->pkt_types & PKT_TYPE_BATMAN)
		wprintw(list_win, "BATMAN %s", n->bat_gw ? "GW " : "");

	if (n->pkt_types & (PKT_TYPE_MESHZ))
		wprintw(list_win, "MC ");

	if (n->pkt_types & PKT_TYPE_IP)
		wprintw(list_win, "%s", ip_sprintf(n->ip_src));

	wattroff(list_win, A_BOLD);
	wattroff(list_win, GREEN);
	wattroff(list_win, RED);
}


static void
update_node_list_win(void)
{
	struct node_info* n;
	int line = 0;

	werase(list_win);
	wattron(list_win, WHITE);
	box(list_win, 0 , 0);
	mvwprintw(list_win, 0, COL_PKT, "Pk/Re%%");
	mvwprintw(list_win, 0, COL_CHAN, "Cha");
	mvwprintw(list_win, 0, COL_SIG, "Sig");
	mvwprintw(list_win, 0, COL_RATE, "RAT");
	mvwprintw(list_win, 0, COL_SOURCE, "TRANSMITTER");
	mvwprintw(list_win, 0, COL_MODE, "MODE");
	mvwprintw(list_win, 0, COL_ENC, "ENCR");
	mvwprintw(list_win, 0, COL_ESSID, "ESSID");
	mvwprintw(list_win, 0, COL_INFO, "INFO");

	/* reuse bottom line for information on other win */
	mvwprintw(list_win, win_split - 1, 0, "Cha-Sig");
	wprintw(list_win, "-RAT-TRANSMITTER");
	mvwprintw(list_win, win_split - 1, 29, "(BSSID)");
	mvwprintw(list_win, win_split - 1, 49, "TYPE");
	mvwprintw(list_win, win_split - 1, 56, "INFO");
	mvwprintw(list_win, win_split - 1, COLS-10, "LiveStatus");

	if (sortfunc)
		listsort(&nodes.n, sortfunc);

	list_for_each(&nodes, n, list) {
		if (conf.filter_mode != 0 && (n->wlan_mode & conf.filter_mode) == 0)
			continue;
		line++;
		if (line >= win_split - 1)
			break; /* prevent overdraw of last line */
		print_node_list_line(line, n);
	}

	if (essids.split_active > 0) {
		wattron(list_win, WHITEONRED);
		mvwhline(list_win, win_split - 2, 1, ' ', COLS - 2);
		print_centered(list_win, win_split - 2, COLS - 2,
			"*** IBSS SPLIT DETECTED!!! ESSID '%s' %d nodes ***",
			essids.split_essid->essid, essids.split_essid->num_nodes);
		wattroff(list_win, WHITEONRED);
	}

	wnoutrefresh(list_win);
}


void
update_dump_win(struct packet_info* p)
{
	if (!p) {
		redrawwin(dump_win);
		wnoutrefresh(dump_win);
		return;
	}

	wattron(dump_win, get_packet_type_color(p->wlan_type));

	if (p->pkt_types & PKT_TYPE_IP)
		wattron(dump_win, A_BOLD);

	if (p->phy_flags & PHY_FLAG_BADFCS)
		wattron(dump_win, RED);

	wprintw(dump_win, "\n%3d ", p->wlan_channel);
	wprintw(dump_win, "%03d ", p->phy_signal);
	wprintw(dump_win, "%3d ", p->phy_rate/10);
	wprintw(dump_win, "%-17s ", mac_name_lookup(p->wlan_src, 0));
	wprintw(dump_win, "(%s) ", ether_sprintf(p->wlan_bssid));

	if (p->phy_flags & PHY_FLAG_BADFCS) {
		wprintw(dump_win, "*BADFCS* ");
		return;
	}

	if ((p->pkt_types & PKT_TYPE_BATMAN) && p->bat_packet_type == BAT_UNICAST) {
		/* unicast traffic can carry IP/ICMP which we show below */
		wprintw(dump_win, "BATMAN ");
	}

	if (p->pkt_types & PKT_TYPE_OLSR) {
		wprintw(dump_win, "%-7s%s ", "OLSR", ip_sprintf(p->ip_src));
		switch (p->olsr_type) {
			case HELLO_MESSAGE: wprintw(dump_win, "HELLO"); break;
			case TC_MESSAGE: wprintw(dump_win, "TC"); break;
			case MID_MESSAGE: wprintw(dump_win, "MID");break;
			case HNA_MESSAGE: wprintw(dump_win, "HNA"); break;
			case LQ_HELLO_MESSAGE: wprintw(dump_win, "LQ_HELLO"); break;
			case LQ_TC_MESSAGE: wprintw(dump_win, "LQ_TC"); break;
			default: wprintw(dump_win, "(%d)", p->olsr_type);
		}
	}
	else if ((p->pkt_types & PKT_TYPE_BATMAN) && p->bat_packet_type != BAT_UNICAST) {
		wprintw(dump_win, "BATMAN ");
		switch (p->bat_packet_type) {
			case BAT_OGM: wprintw(dump_win, "OGM"); break;
			case BAT_ICMP: wprintw(dump_win, "BAT_ICMP"); break;
			case BAT_BCAST: wprintw(dump_win, "BCAST"); break;
			case BAT_VIS: wprintw(dump_win, "VIS"); break;
			case BAT_UNICAST_FRAG: wprintw(dump_win, "FRAG"); break;
			case BAT_TT_QUERY: wprintw(dump_win, "TT_QUERY"); break;
			case BAT_ROAM_ADV: wprintw(dump_win, "ROAM_ADV"); break;
			default: wprintw(dump_win, "UNKNOWN %d", p->bat_packet_type);
		}
	}
	else if (p->pkt_types & PKT_TYPE_MESHZ) {
		wprintw(dump_win, "%-7s%s",
			p->tcpudp_port == 9256 ? "MC_NBR" : "MC_RT",
			ip_sprintf(p->ip_src));
		wprintw(dump_win, " -> %s", ip_sprintf(p->ip_dst));
	}
	else if (p->pkt_types & PKT_TYPE_UDP) {
		wprintw(dump_win, "%-7s%s", "UDP", ip_sprintf(p->ip_src));
		wprintw(dump_win, " -> %s", ip_sprintf(p->ip_dst));
	}
	else if (p->pkt_types & PKT_TYPE_TCP) {
		wprintw(dump_win, "%-7s%s", "TCP", ip_sprintf(p->ip_src));
		wprintw(dump_win, " -> %s", ip_sprintf(p->ip_dst));
	}
	else if (p->pkt_types & PKT_TYPE_ICMP) {
		wprintw(dump_win, "%-7s%s", "PING", ip_sprintf(p->ip_src));
		wprintw(dump_win, " -> %s", ip_sprintf(p->ip_dst));
	}
	else if (p->pkt_types & PKT_TYPE_IP) {
		wprintw(dump_win, "%-7s%s", "IP", ip_sprintf(p->ip_src));
		wprintw(dump_win, " -> %s", ip_sprintf(p->ip_dst));
	}
	else if (p->pkt_types & PKT_TYPE_ARP) {
		wprintw(dump_win, "%-7s", "ARP", ip_sprintf(p->ip_src));
	}
	else {
		wprintw(dump_win, "%-7s", get_packet_type_name(p->wlan_type));

		switch (p->wlan_type) {
		case WLAN_FRAME_DATA:
		case WLAN_FRAME_DATA_CF_ACK:
		case WLAN_FRAME_DATA_CF_POLL:
		case WLAN_FRAME_DATA_CF_ACKPOLL:
		case WLAN_FRAME_QDATA:
		case WLAN_FRAME_QDATA_CF_ACK:
		case WLAN_FRAME_QDATA_CF_POLL:
		case WLAN_FRAME_QDATA_CF_ACKPOLL:
			if ( p->wlan_wep == 1)
				wprintw(dump_win, "ENCRYPTED");
			break;
		case WLAN_FRAME_CTS:
		case WLAN_FRAME_RTS:
		case WLAN_FRAME_ACK:
		case WLAN_FRAME_BLKACK:
		case WLAN_FRAME_BLKACK_REQ:
			wprintw(dump_win, "%-17s", mac_name_lookup(p->wlan_dst, 0));
			break;
		case WLAN_FRAME_BEACON:
		case WLAN_FRAME_PROBE_RESP:
			wprintw(dump_win, "'%s' %llx", p->wlan_essid,
				p->wlan_tsf);
			break;
		case WLAN_FRAME_PROBE_REQ:
			wprintw(dump_win, "'%s'", p->wlan_essid);
			break;
		}
	}

	if (p->wlan_retry)
		wprintw(dump_win, " [r]");

	wattroff(dump_win, A_BOLD);
}


void
update_main_win(struct packet_info *p)
{
	update_node_list_win();
	update_status_win(p);
	update_dump_win(p);
	wnoutrefresh(dump_win);
	if (sort_win != NULL) {
		redrawwin(sort_win);
		wnoutrefresh(sort_win);
	}
}


int
main_input(int key)
{
	if (sort_win != NULL)
		return sort_input(key);

	switch(key) {
	case 'o': case 'O':
		show_sort_win();
		return 1;
	}
	return 0;
}


void
init_display_main(void)
{
	win_split = LINES / 2 + 1;
	stat_height = LINES - win_split - 1;

	list_win = newwin(win_split, COLS, 0, 0);
	scrollok(list_win, FALSE);

	stat_win = newwin(stat_height, STAT_WIDTH, win_split, COLS - STAT_WIDTH);
	scrollok(stat_win, FALSE);

	dump_win = newwin(stat_height, COLS - STAT_WIDTH, win_split, 0);
	scrollok(dump_win, TRUE);

	ewma_init(&usen_avg, 1024, 8);
	ewma_init(&bpsn_avg, 1024, 8);
}


void
resize_display_main(void)
{
	win_split = LINES / 2 + 1;
	stat_height = LINES - win_split - 1;
	wresize(list_win, win_split, COLS);
	wresize(dump_win, stat_height, COLS - STAT_WIDTH);
	mvwin(dump_win, win_split, 0);
	wresize(stat_win, stat_height, STAT_WIDTH);
	mvwin(stat_win, win_split, COLS - STAT_WIDTH);
}


void
clear_display_main(void) {
	werase(dump_win);
	werase(stat_win);
}

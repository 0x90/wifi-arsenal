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

/******************* FILTER *******************/

#include <stdlib.h>

#include "display.h"
#include "main.h"
#include "util.h"
#include "wlan80211.h"
#include "network.h"

#define CHECKED(_x) (conf.filter_pkt & (_x)) ? '*' : ' '
#define CHECKED_MODE(_x) (conf.filter_mode & (_x)) ? '*' : ' '
#define CHECK_ETHER(_mac) MAC_NOT_EMPTY(_mac) ? '*' : ' '
#define CHECK_FILTER_EN(_i) conf.filtermac_enabled[_i] ? '*' : ' '
#define MAC_COL 30
#define FILTER_MAX 26

void
update_filter_win(WINDOW *win)
{
	int l, i;

	box(win, 0 , 0);
	print_centered(win, 0, 57, " Edit Filters ");

	l = 2;
	wattron(win, get_packet_type_color(WLAN_FRAME_TYPE_MGMT));
	wattron(win, A_BOLD);
	mvwprintw(win, l++, 2, "m: [%c] MANAGEMENT Frames", CHECKED(PKT_TYPE_MGMT));
	wattroff(win, A_BOLD);
	mvwprintw(win, l++, 2, "b: [%c] Beacons", CHECKED(PKT_TYPE_BEACON));
	mvwprintw(win, l++, 2, "p: [%c] Probe Req/Resp", CHECKED(PKT_TYPE_PROBE));
	mvwprintw(win, l++, 2, "a: [%c] Association", CHECKED(PKT_TYPE_ASSOC));
	mvwprintw(win, l++, 2, "u: [%c] Authentication", CHECKED(PKT_TYPE_AUTH));
	l++;
	wattron(win, get_packet_type_color(WLAN_FRAME_TYPE_CTRL));
	wattron(win, A_BOLD);
	mvwprintw(win, l++, 2, "c: [%c] CONTROL Frames", CHECKED(PKT_TYPE_CTRL));
	wattroff(win, A_BOLD);
	mvwprintw(win, l++, 2, "r: [%c] CTS/RTS", CHECKED(PKT_TYPE_RTSCTS));
	mvwprintw(win, l++, 2, "k: [%c] ACK", CHECKED(PKT_TYPE_ACK));
	l++;
	wattron(win, get_packet_type_color(WLAN_FRAME_TYPE_DATA));
	wattron(win, A_BOLD);
	mvwprintw(win, l++, 2, "d: [%c] DATA Frames", CHECKED(PKT_TYPE_DATA));
	wattroff(win, A_BOLD);
	mvwprintw(win, l++, 2, "Q: [%c] QoS Data", CHECKED(PKT_TYPE_QDATA));
	mvwprintw(win, l++, 2, "n: [%c] Null Data", CHECKED(PKT_TYPE_NULL));
	mvwprintw(win, l++, 2, "R: [%c] ARP", CHECKED(PKT_TYPE_ARP));
	mvwprintw(win, l++, 2, "P: [%c] ICMP/PING", CHECKED(PKT_TYPE_ICMP));
	mvwprintw(win, l++, 2, "i: [%c] IP", CHECKED(PKT_TYPE_IP));
	mvwprintw(win, l++, 2, "U: [%c] UDP", CHECKED(PKT_TYPE_UDP));
	mvwprintw(win, l++, 2, "T: [%c] TCP", CHECKED(PKT_TYPE_TCP));
	mvwprintw(win, l++, 2, "o: [%c] OLSR", CHECKED(PKT_TYPE_OLSR));
	mvwprintw(win, l++, 2, "B: [%c] BATMAN", CHECKED(PKT_TYPE_BATMAN));
	mvwprintw(win, l++, 2, "M: [%c] MeshCruzer", CHECKED(PKT_TYPE_MESHZ));

	l++;
	wattron(win, RED);
	mvwprintw(win, l++, 2, "*: [%c] Bad FCS", CHECKED(PKT_TYPE_BADFCS));
	wattroff(win, RED);

	l = 2;
	wattron(win, WHITE);
	wattron(win, A_BOLD);
	mvwprintw(win, l++, MAC_COL, "BSSID");
	wattroff(win, A_BOLD);
	mvwprintw(win, l++, MAC_COL, "s: [%c] %s",
		CHECK_ETHER(conf.filterbssid), ether_sprintf(conf.filterbssid));

	l++;
	wattron(win, A_BOLD);
	mvwprintw(win, l++, MAC_COL, "Source MAC Addresses");
	wattroff(win, A_BOLD);

	for (i = 0; i < MAX_FILTERMAC; i++) {
		mvwprintw(win, l++, MAC_COL, "%d: [%c] %s", i+1,
			CHECK_FILTER_EN(i), ether_sprintf(conf.filtermac[i]));
	}

	l++;
	wattron(win, A_BOLD);
	mvwprintw(win, l++, MAC_COL, "Mode");
	wattroff(win, A_BOLD);
	mvwprintw(win, l++, MAC_COL, "A: [%c] Access Point", CHECKED_MODE(WLAN_MODE_AP));
	mvwprintw(win, l++, MAC_COL, "S: [%c] Station", CHECKED_MODE(WLAN_MODE_STA));
	mvwprintw(win, l++, MAC_COL, "I: [%c] IBSS (Ad-hoc)", CHECKED_MODE(WLAN_MODE_IBSS));
	mvwprintw(win, l++, MAC_COL, "O: [%c] Probe Request", CHECKED_MODE(WLAN_MODE_PROBE));
	mvwprintw(win, l++, MAC_COL, "W: [%c] WDS/4ADDR", CHECKED_MODE(WLAN_MODE_4ADDR));
	mvwprintw(win, l++, MAC_COL, "N: [%c] Unknown", CHECKED_MODE(WLAN_MODE_UNKNOWN));

	l++;
	wattron(win, A_BOLD);
	mvwprintw(win, l++, MAC_COL, "0: [%c] All Filters Off", conf.filter_off ? '*' : ' ' );
	wattroff(win, A_BOLD);

	print_centered(win, FILTER_MAX, 57, "[ Press key or ENTER ]");

	wrefresh(win);
}

int
filter_input(WINDOW *win, int c)
{
	char buf[18];
	int i;

	switch (c) {
	case 'm':
		TOGGLE_BIT(conf.filter_pkt, PKT_TYPE_MGMT);
		if (conf.filter_pkt & PKT_TYPE_MGMT)
			conf.filter_pkt |= PKT_TYPE_ALL_MGMT;
		else
			conf.filter_pkt &= ~PKT_TYPE_ALL_MGMT;
		break;
	case 'b': TOGGLE_BIT(conf.filter_pkt, PKT_TYPE_BEACON); break;
	case 'p': TOGGLE_BIT(conf.filter_pkt, PKT_TYPE_PROBE); break;
	case 'a': TOGGLE_BIT(conf.filter_pkt, PKT_TYPE_ASSOC); break;
	case 'u': TOGGLE_BIT(conf.filter_pkt, PKT_TYPE_AUTH); break;
	case 'c':
		TOGGLE_BIT(conf.filter_pkt, PKT_TYPE_CTRL);
		if (conf.filter_pkt & PKT_TYPE_CTRL)
			conf.filter_pkt |= PKT_TYPE_ALL_CTRL;
		else
			conf.filter_pkt &= ~PKT_TYPE_ALL_CTRL;
		break;
	case 'r': TOGGLE_BIT(conf.filter_pkt, PKT_TYPE_RTSCTS); break;
	case 'k': TOGGLE_BIT(conf.filter_pkt, PKT_TYPE_ACK); break;
	case 'd':
		TOGGLE_BIT(conf.filter_pkt, PKT_TYPE_DATA);
		if (conf.filter_pkt & PKT_TYPE_DATA)
			conf.filter_pkt |= PKT_TYPE_ALL_DATA;
		else
			conf.filter_pkt &= ~PKT_TYPE_ALL_DATA;
		break;
	case 'Q': TOGGLE_BIT(conf.filter_pkt, PKT_TYPE_QDATA); break;
	case 'n': TOGGLE_BIT(conf.filter_pkt, PKT_TYPE_NULL); break;
	case 'R': TOGGLE_BIT(conf.filter_pkt, PKT_TYPE_ARP); break;
	case 'P': TOGGLE_BIT(conf.filter_pkt, PKT_TYPE_ICMP); break;
	case 'i': TOGGLE_BIT(conf.filter_pkt, PKT_TYPE_IP); break;
	case 'U': TOGGLE_BIT(conf.filter_pkt, PKT_TYPE_UDP); break;
	case 'T': TOGGLE_BIT(conf.filter_pkt, PKT_TYPE_TCP); break;
	case 'o': TOGGLE_BIT(conf.filter_pkt, PKT_TYPE_OLSR); break;
	case 'B': TOGGLE_BIT(conf.filter_pkt, PKT_TYPE_BATMAN); break;
	case 'M': TOGGLE_BIT(conf.filter_pkt, PKT_TYPE_MESHZ); break;
	case '*': TOGGLE_BIT(conf.filter_pkt, PKT_TYPE_BADFCS); break;

	case 'A': TOGGLE_BIT(conf.filter_mode, WLAN_MODE_AP); break;
	case 'S': TOGGLE_BIT(conf.filter_mode, WLAN_MODE_STA); break;
	case 'I': TOGGLE_BIT(conf.filter_mode, WLAN_MODE_IBSS); break;
	case 'O': TOGGLE_BIT(conf.filter_mode, WLAN_MODE_PROBE); break;
	case 'W': TOGGLE_BIT(conf.filter_mode, WLAN_MODE_4ADDR); break;
	case 'N': TOGGLE_BIT(conf.filter_mode, WLAN_MODE_UNKNOWN); break;

	case 's':
		echo();
		print_centered(win, FILTER_MAX, 57,
			       "[ Enter new BSSID and ENTER ]");
		mvwprintw(win, 3, MAC_COL + 4, ">");
		mvwgetnstr(win, 3, MAC_COL + 7, buf, 17);
		noecho();
		convert_string_to_mac(buf, conf.filterbssid);
		break;

	case '1': case '2': case '3': case '4': case '5': case '6': case '7': case '8': case '9':
		i = c - '1';
		if (MAC_NOT_EMPTY(conf.filtermac[i]) && conf.filtermac_enabled[i]) {
			conf.filtermac_enabled[i] = 0;
		}
		else {
			echo();
			print_centered(win, FILTER_MAX, 57,
				       "[ Enter new MAC %d and ENTER ]", i+1);
			mvwprintw(win, 6 + i, MAC_COL + 4, ">");
			mvwgetnstr(win, 6 + i, MAC_COL + 7, buf, 17);
			noecho();
			/* just enable old MAC if user pressed return only */
			if (*buf == '\0' && MAC_NOT_EMPTY(conf.filtermac[i]))
				conf.filtermac_enabled[i] = 1;
			else {
				convert_string_to_mac(buf, conf.filtermac[i]);
				if (MAC_NOT_EMPTY(conf.filtermac[i]))
					conf.filtermac_enabled[i] = true;
			}
		}
		break;

	case '0':
		conf.filter_off = conf.filter_off ? 0 : 1;
		break;

	default:
		return 0;
	}

	/* convenience: */
	/* if one of the individual subtype frames is selected we enable the general frame type */
	if (conf.filter_pkt & PKT_TYPE_ALL_MGMT)
		conf.filter_pkt |= PKT_TYPE_MGMT;
	if (conf.filter_pkt & PKT_TYPE_ALL_CTRL)
		conf.filter_pkt |= PKT_TYPE_CTRL;
	if (conf.filter_pkt & PKT_TYPE_ALL_DATA)
		conf.filter_pkt |= PKT_TYPE_DATA;

	/* recalculate filter flag */
	conf.do_macfilter = 0;
	for (i = 0; i < MAX_FILTERMAC; i++) {
		if (conf.filtermac_enabled[i])
			conf.do_macfilter = 1;
	}

	net_send_filter_config();

	update_filter_win(win);
	return 1;
}

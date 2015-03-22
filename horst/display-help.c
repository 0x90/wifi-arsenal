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

/******************* HELP *******************/

#include <stdlib.h>

#include "display.h"
#include "main.h"
#include "wlan_util.h"


void
update_help_win(WINDOW *win)
{
	int i, l;
	struct pkt_name c;

	werase(win);
	wattron(win, WHITE);
	box(win, 0 , 0);
	print_centered(win, 0, COLS, " Help ");
	print_centered(win, 2, COLS, "HORST - Horsts OLSR Radio Scanning Tool (or)");
	print_centered(win, 3, COLS, "HORST - Highly Optimized Radio Scanning Tool");

	print_centered(win, 5, COLS, "Version " VERSION " (build date " __DATE__ " " __TIME__ ")");
	print_centered(win, 6, COLS, "(C) 2005-2014 Bruno Randolf, Licensed under the GPLv2");

	mvwprintw(win, 8, 2, "Known IEEE802.11 Packet Types:");

	l = 10;
	/* this is weird but it works */
	mvwprintw(win, l++, 2, "MANAGEMENT FRAMES");
	for (i = 0x00; i <= 0xE0; i = i + 0x10) {
		c = get_packet_struct(i);
		if (c.c != '?')
			mvwprintw(win, l++, 4, "%c  %-6s  %s", c.c, c.name, c.desc);
	}

	l = 10;
	mvwprintw(win, l++, 45, "DATA FRAMES");
	for (i = 0x08; i <= 0xF8; i = i + 0x10) {
		c = get_packet_struct(i);
		if (c.c != '?')
			mvwprintw(win, l++, 47, "%c  %-6s  %s", c.c, c.name, c.desc);
	}

	mvwprintw(win, l++, 2, "CONTROL FRAMES");
	for (i = 0x74; i <= 0xF4; i = i + 0x10) {
		c = get_packet_struct(i);
		if (c.c != '?')
			mvwprintw(win, l++, 4, "%c  %-6s  %s", c.c, c.name, c.desc);
	}

	print_centered(win, ++l, COLS, "For more info read the man page or check http://br1.einfach.org/horst/");

	wrefresh(win);
}

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
#include "channel.h"
#include "network.h"


void
update_channel_win(WINDOW *win)
{
	box(win, 0 , 0);
	print_centered(win, 0, 39, " Channel Settings ");

	mvwprintw(win, 2, 2, "a: [%c] Automatically change channel",
		  conf.do_change_channel ? '*' : ' ');
	mvwprintw(win, 3, 2, "d: Channel dwell time: %d ms   ",
		  conf.channel_time/1000);
	mvwprintw(win, 4, 2, "u: Upper channel limit: %d  ", conf.channel_max);

	mvwprintw(win, 6, 2, "m: Manually change channel: %d  ", channel_get_current_chan());

	print_centered(win, 8, 39, "[ Press key or ENTER ]");

	wrefresh(win);
}


int
channel_input(WINDOW *win, int c)
{
	char buf[6];
	int x;

	switch (c) {
	case 'a': case 'A':
		conf.do_change_channel = conf.do_change_channel ? 0 : 1;
		break;

	case 'd': case 'D':
		echo();
		curs_set(1);
		mvwgetnstr(win, 3, 25, buf, 6);
		curs_set(0);
		noecho();
		sscanf(buf, "%d", &x);
		conf.channel_time = x*1000;
		break;

	case 'u': case 'U':
		echo();
		curs_set(1);
		mvwgetnstr(win, 4, 26, buf, 6);
		curs_set(0);
		noecho();
		sscanf(buf, "%d", &x);
		conf.channel_max = x;
		break;

	case 'm': case 'M':
		conf.do_change_channel = 0;
		echo();
		curs_set(1);
		mvwgetnstr(win, 6, 30, buf, 3);
		curs_set(0);
		noecho();
		sscanf(buf, "%d", &x);
		x = channel_find_index_from_chan(x);
		if (x >= 0) {
			if (!conf.serveraddr[0] != '\0')
				channel_change(x);
			else
				conf.channel_idx = x;
		}
		break;

	default:
		return 0; /* didn't handle input */
	}

	net_send_channel_config();

	update_channel_win(win);
	return 1;
}

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

/******************* HISTORY *******************/

#include <stdlib.h>

#include "display.h"
#include "main.h"
#include "util.h"
#include "wlan_util.h"

#define SIGN_POS LINES-17
#define TYPE_POS SIGN_POS+1
#define RATE_POS LINES-2


void
update_history_win(WINDOW *win)
{
	int i;
	int col = COLS-2;
	int sig, rat;

	if (col > MAX_HISTORY)
		col = 4 + MAX_HISTORY;

	werase(win);
	wattron(win, WHITE);
	box(win, 0 , 0);
	print_centered(win, 0, COLS, " Signal/Rate History ");
	mvwhline(win, SIGN_POS, 1, ACS_HLINE, col);
	mvwhline(win, SIGN_POS+2, 1, ACS_HLINE, col);
	mvwvline(win, 1, 4, ACS_VLINE, LINES-3);

	wattron(win, GREEN);
	mvwprintw(win, 2, 1, "dBm");
	mvwprintw(win, normalize_db(30, SIGN_POS - 1) + 1, 1, "-30");
	mvwprintw(win, normalize_db(40, SIGN_POS - 1) + 1, 1, "-40");
	mvwprintw(win, normalize_db(50, SIGN_POS - 1) + 1, 1, "-50");
	mvwprintw(win, normalize_db(60, SIGN_POS - 1) + 1, 1, "-60");
	mvwprintw(win, normalize_db(70, SIGN_POS - 1) + 1, 1, "-70");
	mvwprintw(win, normalize_db(80, SIGN_POS - 1) + 1, 1, "-80");
	mvwprintw(win, normalize_db(90, SIGN_POS - 1) + 1, 1, "-90");
	mvwprintw(win, SIGN_POS-1, 1, "-99");

	mvwprintw(win, 1, col-6, "Signal");

	wattron(win, CYAN);
	mvwprintw(win, TYPE_POS, 1, "TYP");
	mvwprintw(win, 2, col-11, "Packet Type");

	wattron(win, A_BOLD);
	wattron(win, BLUE);
	mvwprintw(win, 3, col-4, "Rate");
	mvwprintw(win, RATE_POS-12, 1, "300");
	mvwprintw(win, RATE_POS-11, 1, "275");
	mvwprintw(win, RATE_POS-10, 1, "250");
	mvwprintw(win, RATE_POS-9, 1, "225");
	mvwprintw(win, RATE_POS-8, 1, "200");
	mvwprintw(win, RATE_POS-7, 1, "175");
	mvwprintw(win, RATE_POS-6, 1, "150");
	mvwprintw(win, RATE_POS-5, 1, "125");
	mvwprintw(win, RATE_POS-4, 1, "100");
	mvwprintw(win, RATE_POS-3, 1, " 75");
	mvwprintw(win, RATE_POS-2, 1, " 50");
	mvwprintw(win, RATE_POS-1, 1, " 25");
	wattroff(win, A_BOLD);

	i = hist.index - 1;

	while (col > 4 && hist.signal[i] != 0)
	{
		sig = normalize_db(-hist.signal[i], SIGN_POS - 1);

		wattron(win, ALLGREEN);
		mvwvline(win, sig + 1, col, ACS_BLOCK, SIGN_POS - sig - 1);

		wattron(win, get_packet_type_color(hist.type[i]));
		mvwprintw(win, TYPE_POS, col, "%c", \
			get_packet_type_char(hist.type[i]));

		if (hist.retry[i])
			mvwprintw(win, TYPE_POS+1, col, "r");

		rat = hist.rate[i]/250;

		wattron(win, A_BOLD);
		wattron(win, BLUE);
		mvwvline(win, RATE_POS - rat, col, 'x', rat);
		wattroff(win, A_BOLD);

		i--;
		col--;
		if (i < 0)
			i = MAX_HISTORY-1;
	}
	wnoutrefresh(win);
}

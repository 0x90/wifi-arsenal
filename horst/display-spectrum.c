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

/******************* POOR MAN's "SPECTRUM ANALYZER" *******************/

#include <stdlib.h>

#include "display.h"
#include "main.h"
#include "util.h"

#define CH_SPACE	6
#define SPEC_POS_Y	1
#define SPEC_HEIGHT	(LINES - SPEC_POS_X - 2)
#define SPEC_POS_X	6

static unsigned int show_nodes;

void
update_spectrum_win(WINDOW *win)
{
	int i, sig, siga, use, usen, usean, nnodes;
	struct chan_node *cn;
	const char *id;

	werase(win);
	wattron(win, WHITE);
	box(win, 0 , 0);
	print_centered(win, 0, COLS, " \"Spectrum Analyzer\" ");

	mvwhline(win, SPEC_HEIGHT + 1, 1, ACS_HLINE, COLS - 2);
	mvwvline(win, SPEC_POS_Y, 4, ACS_VLINE, LINES - SPEC_POS_Y - 2);

	mvwprintw(win, SPEC_HEIGHT + 2, 1, "CHA");
	wattron(win, BLUE);
	mvwprintw(win, SPEC_HEIGHT + 4, 1, "Nod");
	wattron(win, YELLOW);
	mvwprintw(win, SPEC_HEIGHT + 5, 1, "Use");
	for(i = 80; i > 0; i -= 20) {
		sig = normalize(i, 100, SPEC_HEIGHT);
		mvwprintw(win, SPEC_POS_Y + sig, 1, "%d%%", 100-i);
	}
	wattron(win, GREEN);
	mvwprintw(win, SPEC_HEIGHT + 3, 1, "Sig");
	mvwprintw(win, SPEC_POS_Y + 1, 1, "dBm");
	for(i = -30; i > -100; i -= 10) {
		sig = normalize_db(-i, SPEC_HEIGHT);
		mvwprintw(win, SPEC_POS_Y + sig, 1, "%d", i);
	}
	wattroff(win, GREEN);

	for (i = 0; i < conf.num_channels && SPEC_POS_X + CH_SPACE*i+4 < COLS; i++) {
		mvwprintw(win, SPEC_HEIGHT + 2, SPEC_POS_X + CH_SPACE*i,
			  "%02d", channel_get_chan_from_idx(i));
		wattron(win, GREEN);
		mvwprintw(win,  SPEC_HEIGHT + 3, SPEC_POS_X + CH_SPACE*i, "%d",
			  spectrum[i].signal);
		wattron(win, BLUE);
		mvwprintw(win,  SPEC_HEIGHT + 4, SPEC_POS_X + CH_SPACE*i, "%d",
			  spectrum[i].num_nodes);

		if (spectrum[i].signal != 0) {
			sig = normalize_db(-spectrum[i].signal, SPEC_HEIGHT);
			if (spectrum[i].packets > 8)
				siga = normalize_db(
					ewma_read(&spectrum[i].signal_avg),
					SPEC_HEIGHT);
			else
				siga = sig;

			signal_average_bar(win, sig, siga,
					   SPEC_POS_Y, SPEC_POS_X + CH_SPACE*i,
					   SPEC_HEIGHT, show_nodes ? 1 : 2);
		}

		/* usage in percent */
		use = (spectrum[i].durations_last * 100.0) / conf.channel_time;
		wattron(win, YELLOW);
		mvwprintw(win, SPEC_HEIGHT + 5, SPEC_POS_X + CH_SPACE*i, "%d", use);
		wattroff(win, YELLOW);

		if (show_nodes) {
			wattron(win, BLUE);
			list_for_each(&spectrum[i].nodes, cn, chan_list) {
				if (cn->packets >= 8)
					sig = normalize_db(ewma_read(&cn->sig_avg),
						SPEC_HEIGHT);
				else
					sig = normalize_db(-cn->sig, SPEC_HEIGHT);
				if (cn->node->ip_src) {
					wattron(win, A_BOLD);
					id = ip_sprintf_short(cn->node->ip_src);
				}
				else
					id = mac_name_lookup(cn->node->last_pkt.wlan_src, 1);
				mvwprintw(win, SPEC_POS_Y + sig,
					SPEC_POS_X + CH_SPACE*i + 1, "%s", id);
				if (cn->node->ip_src)
					wattroff(win, A_BOLD);
			}
			wattroff(win, BLUE);
		}
		else {
			nnodes = spectrum[i].num_nodes;
			if (nnodes > SPEC_HEIGHT)
				nnodes = SPEC_HEIGHT;

			wattron(win, ALLBLUE);
			mvwvline(win, SPEC_POS_Y + SPEC_HEIGHT - nnodes,
				SPEC_POS_X + CH_SPACE*i + 2, ACS_BLOCK, nnodes);
			wattroff(win, ALLBLUE);

			usen = normalize(use, 100, SPEC_HEIGHT);

			use = (ewma_read(&spectrum[i].durations_avg) * 100.0)
				/ conf.channel_time;
			usean = normalize(use, 100, SPEC_HEIGHT);

			general_average_bar(win, usen, usean,
					    SPEC_POS_Y + SPEC_HEIGHT,
					    SPEC_POS_X + CH_SPACE*i + 3,
					    1, YELLOW, ALLYELLOW);
		}
	}

	wnoutrefresh(win);
}


int
spectrum_input(WINDOW *win, int c)
{
	switch (c) {
	case 'n': case 'N':
		show_nodes = show_nodes ? 0 : 1;
		break;

	default:
		return 0; /* didn't handle input */
	}

	update_spectrum_win(win);
	return 1;
}

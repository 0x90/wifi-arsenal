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
#include <curses.h>
#include <string.h>
#include <ctype.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <sys/ioctl.h>

#include "display.h"
#include "main.h"
#include "wlan80211.h"
#include "channel.h"


static WINDOW *conf_win = NULL;
static WINDOW *show_win = NULL;
static int conf_win_current;
static int show_win_current;

static struct timeval last_time;

static int display_resize_needed = 0;

/* main windows are special */
void init_display_main(void);
void clear_display_main(void);
void update_main_win(struct packet_info *pkt);
void update_dump_win(struct packet_info* pkt);
int main_input(int c);
void print_dump_win(const char *str, int refresh);
void resize_display_main(void);
static void resize_display_all(void);

/* smaller config windows */
void update_filter_win(WINDOW *win);
void update_channel_win(WINDOW *win);
int filter_input(WINDOW *win, int c);
int channel_input(WINDOW *win, int c);

/* "standard" windows */
void update_spectrum_win(WINDOW *win);
void update_statistics_win(WINDOW *win);
void update_essid_win(WINDOW *win);
void update_history_win(WINDOW *win);
void update_help_win(WINDOW *win);
int spectrum_input(WINDOW *win, int c);

/******************* HELPERS *******************/

void
get_per_second(unsigned long bytes, unsigned long duration,
	       unsigned long packets, unsigned long retries,
	       int *bps, int *dps, int *pps, int *rps)
{
	static struct timeval last;
	static unsigned long last_bytes, last_dur, last_pkts, last_retr;
	static int last_bps, last_dps, last_pps, last_rps;
	float timediff;

	/* reacalculate only every second or more */
	timediff = (the_time.tv_sec + the_time.tv_usec/1000000.0) -
		   (last.tv_sec + last.tv_usec/1000000.0);
	if (timediff >= 1.0) {
		last_dps = (1.0*(duration - last_dur)) / timediff;
		last_bps = (1.0*(bytes - last_bytes)) / timediff;
		last_pps = (1.0*(packets - last_pkts)) / timediff;
		last_rps = (1.0*(retries - last_retr)) / timediff;
		last = the_time;
		last_dur = duration;
		last_bytes = bytes;
		last_pkts = packets;
		last_retr = retries;
	}
	*bps = last_bps;
	*dps = last_dps;
	*pps = last_pps;
	*rps = last_rps;
}


void __attribute__ ((format (printf, 4, 5)))
print_centered(WINDOW* win, int line, int cols, const char *fmt, ...)
{
	char* buf;
	va_list ap;

	buf = malloc(cols);
	if (buf == NULL)
		return;

	va_start(ap, fmt);
	vsnprintf(buf, cols, fmt, ap);
	va_end(ap);

	mvwprintw(win, line, cols / 2 - strlen(buf) / 2, buf);
	free(buf);
}


int
get_packet_type_color(int type)
{
	if (type == 1) /* special case for bad FCS */
		return RED;
	switch (type & WLAN_FRAME_FC_TYPE_MASK) {
		case WLAN_FRAME_TYPE_DATA: return BLUE;
		case WLAN_FRAME_TYPE_CTRL: return WHITE;
		case WLAN_FRAME_TYPE_MGMT: return CYAN;
	}
	return YELLOW;
}


void
signal_average_bar(WINDOW *win, int val, int avg, int y, int x, int height,
		   int width)
{
	int i;
	if (avg <= val) {
		wattron(win, ALLGREEN);
		for (i = 0; i < width; i++)
			mvwvline(win, y + avg, x + i, ACS_BLOCK, val - avg);
		wattron(win, A_BOLD);
		for (i = 0; i < width; i++)
			mvwvline(win, y + val, x + i, '=', height - val);
	}
	else {
		wattron(win, GREEN);
		wattron(win, A_BOLD);
		for (i = 0; i < width; i++)
			mvwvline(win, y + val, x + i, '=', avg - val);
		wattron(win, ALLGREEN);
		for (i = 0; i < width; i++)
			mvwvline(win, y + avg, x + i, '=', height - avg);
	}
	wattroff(win, A_BOLD);
	wattroff(win, ALLGREEN);
}


void
general_average_bar(WINDOW *win, int val, int avg, int y, int x,
		    int width, short color, short color_avg)
{
	int i;
	if (avg >= val) {
		wattron(win, color_avg);
		for (i = 0; i < width; i++)
			mvwvline(win, y - avg, x + i, ACS_BLOCK, avg - val);
		wattron(win, A_BOLD);
		for (i = 0; i < width; i++)
			mvwvline(win, y - val, x + i, '=', val);
	}
	else {
		wattron(win, color);
		wattron(win, A_BOLD);
		for (i = 0; i < width; i++)
			mvwvline(win, y - val, x + i, '=', val - avg);
		wattron(win, color_avg);
		for (i = 0; i < width; i++)
			mvwvline(win, y - avg, x + i, '=', avg);
	}
	wattroff(win, A_BOLD);
	wattroff(win, color_avg);
}


/******************* STATUS *******************/

static void
update_clock(time_t* sec)
{
	static char buf[9];
	strftime(buf, 9, "%H:%M:%S", localtime(sec));
	wattron(stdscr, BLACKONWHITE);
	mvwprintw(stdscr, LINES-1, COLS-9, "|%s", buf);
	wattroff(stdscr, BLACKONWHITE);
	wnoutrefresh(stdscr);
}


static void
update_mini_status(void)
{
	wattron(stdscr, BLACKONWHITE);
	mvwprintw(stdscr, LINES-1, COLS-25, conf.paused ? "|=" : "|>");
	if (!conf.filter_off && (conf.do_macfilter || conf.filter_pkt != PKT_TYPE_ALL || conf.filter_mode != WLAN_MODE_ALL))
		mvwprintw(stdscr, LINES-1, COLS-23, "|F");
	else
		mvwprintw(stdscr, LINES-1, COLS-23, "| ");
	mvwprintw(stdscr, LINES-1, COLS-21, "|Ch%03d", channel_get_current_chan());
	wattroff(stdscr, BLACKONWHITE);
	wnoutrefresh(stdscr);
}


static void
update_menu(void)
{
	wattron(stdscr, BLACKONWHITE);
	mvwhline(stdscr, LINES-1, 0, ' ', COLS);

#define KEYMARK A_UNDERLINE
	attron(KEYMARK); printw("Q"); attroff(KEYMARK); printw("uit ");
	attron(KEYMARK); printw("P"); attroff(KEYMARK); printw("ause ");
	attron(KEYMARK); printw("R"); attroff(KEYMARK); printw("eset ");
	attron(KEYMARK); printw("H"); attroff(KEYMARK); printw("ist ");
	attron(KEYMARK); printw("E"); attroff(KEYMARK); printw("SSID St");
	attron(KEYMARK); printw("a"); attroff(KEYMARK); printw("ts ");
	attron(KEYMARK); printw("S"); attroff(KEYMARK); printw("pec ");
	attron(KEYMARK); printw("F"); attroff(KEYMARK); printw("ilt ");
	attron(KEYMARK); printw("C"); attroff(KEYMARK); printw("han ");
	attron(KEYMARK); printw("?"); attroff(KEYMARK); printw(" ");
	if (show_win == NULL) {
		printw("s"); attron(KEYMARK); printw("O"); attroff(KEYMARK); printw("rt");
	}
	if (show_win != NULL && show_win_current == 's') {
		attron(KEYMARK); printw("N"); attroff(KEYMARK); printw("odes");
	}
#undef KEYMARK
	mvwprintw(stdscr, LINES-1, COLS-15, "|%s",
		  conf.serveraddr[0] != '\0' ? conf.serveraddr : conf.ifname);
	wattroff(stdscr, BLACKONWHITE);

	update_mini_status();
	update_clock(&the_time.tv_sec);
}


/******************* WINDOW MANAGEMENT / UPDATE *******************/

static void
update_show_win(void)
{
	if (show_win_current == 'e')
		update_essid_win(show_win);
	else if (show_win_current == 'h')
		update_history_win(show_win);
	else if (show_win_current == 'a')
		update_statistics_win(show_win);
	else if (show_win_current == 's')
		update_spectrum_win(show_win);
	else if (show_win_current == '?')
		update_help_win(show_win);
}


static void
show_window(int which)
{
	if (show_win != NULL && show_win_current == which) {
		delwin(show_win);
		show_win = NULL;
		show_win_current = 0;
		update_menu();
		return;
	}
	if (show_win == NULL) {
		show_win = newwin(LINES-1, COLS, 0, 0);
		scrollok(show_win, FALSE);
	}
	show_win_current = which;
	update_show_win();
	update_menu();
}


static void
show_conf_window(int key)
{
	if (conf_win != NULL &&
	    (conf_win_current == key || key == '\r' || key == KEY_ENTER)) {
		delwin(conf_win);
		conf_win = NULL;
		conf_win_current = 0;
		return;
	}
	if (conf_win == NULL) {
		if (key == 'f') {
			conf_win = newwin(27, 57, LINES/2-13, COLS/2-28);
			update_filter_win(conf_win);
		}
		else if (key == 'c') {
			conf_win = newwin(9, 39, LINES/2-6, COLS/2-20);
			update_channel_win(conf_win);
		}
		scrollok(conf_win, FALSE);
		conf_win_current = key;
	}
}


void
update_display_clock(void)
{
	/* helper to update just the clock every second */
	if (the_time.tv_sec > last_time.tv_sec) {
		update_clock(&the_time.tv_sec);
		doupdate();
	}
}


void
display_log(const char *string)
{
	print_dump_win(string, show_win == NULL);
}


void
update_display(struct packet_info* pkt)
{
	/*
	 * update only in specific intervals to save CPU time
	 * if pkt is NULL we want to force an update
	 */
	if (pkt != NULL &&
	    the_time.tv_sec == last_time.tv_sec &&
	    (the_time.tv_usec - last_time.tv_usec) < conf.display_interval ) {
		/* just add the line to dump win so we don't loose it */
		update_dump_win(pkt);
		return;
	}

	if (display_resize_needed == 1) {
		resize_display_all();
		display_resize_needed = 0;
	}

	update_menu();

	/* update clock every second */
	if (the_time.tv_sec > last_time.tv_sec)
		update_clock(&the_time.tv_sec);

	last_time = the_time;

	if (show_win != NULL)
		update_show_win();
	else
		update_main_win(pkt);

	if (conf_win != NULL) {
		redrawwin(conf_win);
		wnoutrefresh(conf_win);
	}

	/* only one redraw */
	doupdate();
}


/******************* RESIZE *******************/

static void
resize_display_all(void)
{
	struct winsize winsz;

	/* get new window size */
	winsz.ws_col = winsz.ws_row = 0;
	ioctl(0, TIOCGWINSZ, &winsz);	/* ioctl on STDIN */
	if (winsz.ws_col && winsz.ws_row)
		resizeterm(winsz.ws_row, winsz.ws_col);
	COLS = winsz.ws_col;
	LINES = winsz.ws_row;

	resize_display_main();

	if (show_win)
		wresize(show_win, LINES-1, COLS);

	if (conf_win) {
		if (conf_win_current == 'f')
			mvwin(conf_win, LINES/2-12, COLS/2-28);
		else if (conf_win_current == 'c')
			mvwin(conf_win, LINES/2-5, COLS/2-20);
	}
}


static void
window_change_handler(__attribute__((unused)) int sig) {
	display_resize_needed = 1;
}


/******************* INPUT *******************/

void
handle_user_input(void)
{
	int key;

	key = getch();

	/* if windows are active pass the input to them first. if they handle
	 * it they will return 1. if not we handle the input below */

	if (conf_win != NULL) {
		if (conf_win_current == 'f')
			if (filter_input(conf_win, key))
				return;
		if (conf_win_current == 'c')
			if (channel_input(conf_win, key))
				return;
	}

	if (show_win != NULL && show_win_current == 's')
		if (spectrum_input(show_win, key))
			return;

	if (show_win == NULL) {
		if (main_input(key))
			return;
	}

	switch(key) {
	case ' ': case 'p': case 'P':
		main_pause(conf.paused = conf.paused ? 0 : 1);
		break;

	case 'q': case 'Q':
		exit(0);

	case 'r': case 'R':
		main_reset();
		break;

	/* big windows */
	case '?':
	case 'e': case 'E':
	case 'h': case 'H':
	case 'a': case 'A':
	case 's': case 'S':
		show_window(tolower(key));
		break;

	/* config windows */
	case 'f': case 'F':
	case 'c': case 'C':
	case '\r': case KEY_ENTER: /* used to close win */
		show_conf_window(tolower(key));
		break;
	}

	update_display(NULL);
}


/******************* INIT *******************/

void
init_display(void)
{
	initscr();
	start_color();	/* Start the color functionality */
	keypad(stdscr, TRUE);
	nonl();		/* tell curses not to do NL->CR/NL on output */
	cbreak();	/* take input chars one at a time, no wait for \n */
	curs_set(0);	/* don't show cursor */
	noecho();
	nodelay(stdscr, TRUE);

	init_pair(1, COLOR_WHITE, COLOR_BLACK);
	init_pair(2, COLOR_GREEN, COLOR_BLACK);
	init_pair(3, COLOR_RED, COLOR_BLACK);
	init_pair(4, COLOR_CYAN, COLOR_BLACK);
	init_pair(5, COLOR_BLUE, COLOR_BLACK);
	init_pair(6, COLOR_BLACK, COLOR_WHITE);
	init_pair(7, COLOR_MAGENTA, COLOR_BLACK);

	init_pair(8, COLOR_GREEN, COLOR_GREEN);
	init_pair(9, COLOR_RED, COLOR_RED);
	init_pair(10, COLOR_BLUE, COLOR_BLUE);
	init_pair(11, COLOR_CYAN, COLOR_CYAN);
	init_pair(12, COLOR_YELLOW, COLOR_BLACK);
	init_pair(13, COLOR_YELLOW, COLOR_YELLOW);
	init_pair(14, COLOR_WHITE, COLOR_RED);

	/* COLOR_BLACK COLOR_RED COLOR_GREEN COLOR_YELLOW COLOR_BLUE
	COLOR_MAGENTA COLOR_CYAN COLOR_WHITE */

	erase();

	init_display_main();

	if (conf.display_view != 0)
		show_window(conf.display_view);

	update_menu();
	update_display(NULL);

	signal(SIGWINCH, window_change_handler);
	conf.display_initialized = 1;
}


void
finish_display(void)
{
	endwin();
}


void
display_clear(void)
{
	clear_display_main();
}

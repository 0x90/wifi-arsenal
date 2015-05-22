#include <curses.h>
#include <panel.h>
#include "karma.h"

WINDOW* sta_window;

static const char title[] = "KARMA";

void kui_init()
{
    int y, x;
    
    initscr();
    cbreak();
    noecho();

    nonl();
    intrflush(stdscr, FALSE);
    keypad(stdscr, TRUE);

    sta_window = newwin(0, 0, 3, 0);

    getmaxyx(stdscr, y, x);
    mvprintw(0, (x - sizeof(title))/2, "KARMA");
    
    mvprintw(2, 0, "Hardware Address");
    mvprintw(2, 18, "Sig");
    mvprintw(2, 22, "Probe Requests");
    
    refresh();
}

void kui_update()
{
    struct sta* sta_entry;
    int i = 0;
    int y, x;

    getmaxyx(sta_window, y, x);
    
    wclear(sta_window);
    for (sta_entry = sta_list; sta_entry; sta_entry = sta_entry->next) {
        sta_t* sta = sta_entry->sta;
        struct ssid* s;
        int xi = 0;

        xi = mvwprintw(sta_window, i, 0, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
                       sta->mac[0], sta->mac[1], sta->mac[2],
                       sta->mac[3], sta->mac[4], sta->mac[5]);

        xi += wprintw(sta_window, " %.3d", sta->signal);
        
        for (s = sta->probed_networks; s && xi < y; s = s->next) {
            xi += wprintw(sta_window, " %s", s->ssid);
        }

        i += 1;
    }

    move(0, 0);
    wrefresh(sta_window);
}

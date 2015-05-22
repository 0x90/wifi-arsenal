/**
 * AirScan - display.h
 *
 * Copyright 2008-2010 Raphaël Rigo
 *
 * For mails :
 * user : devel-nds
 * domain : syscall.eu
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef DISPLAY_H
#define DISPLAY_H

#include "airscan.h"

#define SCREEN_SEP "--------------------------------"
#define MAX_Y_TEXT 24			/* Number of vertical tiles */
#define MAX_X_TEXT 33			/* Number of horiz tiles */

#define DISPLAY_LINES 8

/* Currently displayed APs */
extern struct AP_HT_Entry *cur_entries[DISPLAY_LINES];

void display_ap(Wifi_AccessPoint *ap, int new_ap);
void display_entry(int line, struct AP_HT_Entry *entry, char *mode);
void display_list(int index, int flags);

#endif

/*
    wificurse - WiFi Jamming tool
    Copyright (C) 2012  oblique

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include "iw.h"
#include "ap_list.h"
#include "console.h"
#include "wificurse.h"


void clear_scr() {
	printf("\033[2J\033[1;1H");
	fflush(stdout);
}

void update_scr(struct ap_list *apl, struct iw_dev *dev) {
	struct access_point *ap;

	/* move cursor at colum 1 row 1 */
	printf("\033[1;1H");

	printf("\n CH %3d ][ WiFi Curse v" VERSION "\n\n", dev->chan);
	printf("       Deauth  "
	       "BSSID             "
	       "  CH  "
	       "ESSID\n\n");

	ap = apl->head;
	while (ap != NULL) {
		/* erase whole line */
		printf("\033[2K");
		if (ap->info.chan == dev->chan)
			printf(RED_COLOR "*" RESET_COLOR);
		else
			printf(" ");
		printf(" %11d", ap->num_of_deauths);
		printf("  %02x:%02x:%02x:%02x:%02x:%02x", ap->info.bssid[0],
		       ap->info.bssid[1], ap->info.bssid[2], ap->info.bssid[3],
		       ap->info.bssid[4], ap->info.bssid[5]);
		printf("  %3d ", ap->info.chan);
		if (ap->info.essid[0] == '\0') {
			printf(" <hidden>\n");
		} else
			printf(" %s\n", ap->info.essid);
		ap = ap->next;
	}

	/* clear screen from cursor to end of display */
	printf("\033[J");
	fflush(stdout);
}

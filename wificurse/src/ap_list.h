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

#ifndef AP_LIST_H
#define AP_LIST_H

#include <stdint.h>
#include <time.h>
#include <sys/socket.h>
#include <linux/wireless.h>


#define ESSID_LEN 32

struct ap_info {
	int chan;
	uint8_t bssid[IFHWADDRLEN];
	uint8_t essid[ESSID_LEN+1];
};

struct access_point {
	volatile unsigned int num_of_deauths;
	time_t last_beacon_tm;
	uint16_t sequence:12;
	struct ap_info info;
	struct access_point *next;
	struct access_point *prev;
};

struct ap_list {
	struct access_point *head;
	struct access_point *tail;
};


void init_ap_list(struct ap_list *apl);
void free_ap_list(struct ap_list *apl);
void link_ap(struct ap_list *apl, struct access_point *ap);
void unlink_ap(struct ap_list *apl, struct access_point *ap);
int add_or_update_ap(struct ap_list *apl, struct ap_info *api);

#endif

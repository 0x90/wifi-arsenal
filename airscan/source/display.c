/**
 * AirScan - display.c
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

#include <netinet/in.h>
#include <nds.h>
#include <dswifi9.h>
#include <netdb.h>
#include <errno.h>
#include "airscan.h"
#include "utils.h"
#include "display.h"

struct AP_HT_Entry *cur_entries[DISPLAY_LINES] = { NULL };

int displayed;			/* Number of items already displayed */

/* try to get the Google homepage and display ip on debug screen */
int try_google(struct in_addr *ip)
{
	const char *request = "GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n";
	int http_socket, recvd_len;
	int res, ret;		/* calls ret and function return value */
	struct sockaddr_in addr;
	char resp[256];

	ret = -1;
	http_socket = socket(AF_INET, SOCK_STREAM, 0);
	DEBUG_PRINT("http_socket : %d\n", http_socket);
	if (http_socket == -1)
		goto g_cleanup;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(80);
	addr.sin_addr.s_addr = *(unsigned long int *)ip;
	res = connect(http_socket, (struct sockaddr *)&addr, sizeof(addr));
	DEBUG_PRINT("connect : %d\n", res);
	if (res == -1)
		goto g_cleanup;

	res = send(http_socket, request, strlen(request), 0);
	DEBUG_PRINT("send : %d\n", res);
	if (res == -1)
		goto g_cleanup;

	printf_to_debug("response beginning : \n");
	recvd_len = recv(http_socket, resp, 255, 0);
	if (recvd_len > 0) {
		resp[recvd_len] = 0;	// null-terminate
		printf_to_debug("%s\n", resp);
	}
	if (recvd_len == -1)
		goto g_cleanup;

	ret = 0;
 g_cleanup:
	shutdown(http_socket, 0);
	closesocket(http_socket);
	return ret;
}

/* Display IP data for connected AP */
void display_ap(Wifi_AccessPoint * ap, int new_ap)
{
	static struct in_addr ip, gw, sn, dns1, dns2;
	int status;
	static struct hostent *google_addr = NULL;
	static struct in_addr g_ip;
	static int errno_cache;

	clear_main();

	status = Wifi_AssocStatus();

	print_xy(0, 0, "SSID :");
	print_xy(0, 1, ap->ssid);
	print_xy(0, 3, "State :");
	printf_xy(0, 4, "%s", ASSOCSTATUS_STRINGS[status]);
	if (status == ASSOCSTATUS_ASSOCIATED) {
		ip = Wifi_GetIPInfo(&gw, &sn, &dns1, &dns2);

		printf_xy(0, 6, "IP :        %s", inet_ntoa(ip));
		printf_xy(0, 7, "Subnet :    %s", inet_ntoa(sn));
		printf_xy(0, 8, "GW :        %s", inet_ntoa(gw));
		printf_xy(0, 9, "DNS1 :      %s", inet_ntoa(dns1));
		printf_xy(0, 10, "DNS2 :      %s", inet_ntoa(dns2));

		/* new association, try Google again */
		if (new_ap) {
			DEBUG_PRINT("new ap!");
			google_addr = gethostbyname("www.google.com");
			if (google_addr != NULL) {
				g_ip =
				    *(struct in_addr
				      *)(google_addr->h_addr_list[0]);
				if (try_google(&g_ip) == 0) {
					errno_cache = 0;
				} else {
					errno_cache = errno;
				}
			}
		} else {
			if (google_addr == NULL)
				printf_xy(0, 12, "DNS failed");
			else {
				printf_xy(0, 12, "Google IP : %s",
					  inet_ntoa(g_ip));
				if (errno_cache) {
					printf_xy(0, 13, "GET errno : %d",
						  errno_cache);
				} else {
					printf_xy(0, 13,
						  "GET : OK, see top screen");
				}
			}
		}
	}
}

/* Print "entry" on line "line" */
void display_entry(int line, struct AP_HT_Entry *entry, char *mode)
{

	if (line < DISPLAY_LINES)
		cur_entries[line] = entry;

	printf_xy(0, line * 3, "%s", entry->ap->ssid);
	printf_xy(0, line * 3 + 1,
		  "%02X%02X%02X%02X%02X%02X %s c%02d %3dp %ds",
		  entry->ap->macaddr[0], entry->ap->macaddr[1],
		  entry->ap->macaddr[2], entry->ap->macaddr[3],
		  entry->ap->macaddr[4], entry->ap->macaddr[5], mode,
		  entry->ap->channel, (entry->ap->rssi * 100) / 0xD0,
		  (curtick - entry->tick) / 1000);
	print_xy(0, line * 3 + 2, SCREEN_SEP);
}

int display_type(int type, int index, char *str)
{
	int i;
	int real_index = 0;

	if (index > num[type])
		return index - num[type];

	i = (first_null[type] >= 0 && index > first_null[type] ?
	     first_null[type] : index);
	real_index = i;
	for (; i < (num[type] + num_null[type])
	     && displayed < DISPLAY_LINES; i++) {
		if (ap[type][i]) {
			if (real_index >= index)
				display_entry(displayed++, ap[type][i], str);
			real_index++;
		}
	}
	index -= num[type];
	if (index < 0)
		index = 0;
	return index;
}

/* display a list of AP on the screen, starting at "index", displaying
   only those specified in "flags" */
void display_list(int index, int flags)
{
	/* header */
	displayed = 1;

	clear_main();

	printf_xy(0, 0, "%d AP On:%s Tmot:%03d", numap, modes, timeout / 1000);
	printf_xy(0, 1, "OPN:%03d WEP:%03d WPA:%03d idx:%03d", num[OPN],
		  num[WEP], num[WPA], index);
	print_xy(0, 2, SCREEN_SEP);

	memset(cur_entries, 0, sizeof(cur_entries));

	if (flags & DISP_OPN)
		index = display_type(OPN, index, "OPN");

	if (flags & DISP_WEP)
		index = display_type(WEP, index, "WEP");

	if (flags & DISP_WPA)
		display_type(WPA, index, "WPA");

	return;
}

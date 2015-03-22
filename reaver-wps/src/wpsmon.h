/*
 * Walsh - Main and usage functions
 * Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL. *  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so. *  If you
 *  do not wish to do so, delete this exception statement from your
 *  version. *  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#ifndef WPSMON_H
#define WPSMON_H

#include <getopt.h>
#include <signal.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <libwps.h>
#include "defs.h"
#include "globule.h"
#include "misc.h"
#include "init.h"
#include "sql.h"
#include "iface.h"
#include "80211.h"
#include "builder.h"
#include "config.h"

#define INTERFACE       	0
#define PCAP_FILE       	1

#define PROBE_RESPONSE          0x05

#define WPS_VENDOR_ID		"\x00\x50\xF2\x04"
#define WPS_VENDOR_ID_SIZE      4
#define VENDOR_ID_OFFSET	2
#define LENGTH_OFFSET		1

#define SURVEY			0
#define SCAN			1

#define CHANNEL_INTERVAL	999999

#define YES			"Yes"
#define NO			"No "

#define FAKE_RADIO_TAP_HEADER	"\x00\x00\x00\x00\x00\x00\x00\x00"
#define PACKET_FILTER		"type mgt and (subtype beacon or subtype proberesp)"

enum tag_type
{
        HEX = 0,
        STRING = 1
};

struct elements
{
        int number;
        enum tag_type type;
        char *name;
};

struct data_element
{
	uint16_t type;
	uint16_t len;
};

struct global_variables
{
	int csv;
	FILE *fp;
	int bssid_count;
	unsigned char **bssids;
} wpsmon;

void monitor(char *bssid, int passive, int source, int channel, int mode);
void parse_wps_settings(const u_char *packet, struct pcap_pkthdr *header, char *target, int passive, int mode, int source);
void send_probe_request(unsigned char *bssid, char *essid);
int is_dup(unsigned char *bssid);
void mark_bssid(unsigned char *bssid);
void free_bssid_list(unsigned char **list, int count);
void sigalrm_handler(int x);
void usage(char *prog);

#endif

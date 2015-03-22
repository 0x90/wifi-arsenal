/**
 * AirScan - main.c
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
#include "airscan.h"
#include "display.h"
#include "utils.h"

int timeout = 0;
u32 curtick;			/* Current tick to handle timeout */
char modes[13];			/* display modes (OPN/WEP/WPA) */

struct AP_HT_Entry *ap_ht[256] = { NULL };	/* hash table */

unsigned int numap = 0;		/* number of APs */

/* Default allocation size for arrays */
#define DEFAULT_ALLOC_SIZE 100
/* Arrays of pointers for fast access */
struct AP_HT_Entry **ap[3];
/* Arrays size, to check if realloc is needed */
int sizes[3];
/* Number of entries in each array */
int num[3];
/* Number of NULL entries in each array */
int num_null[3];
/* First NULL entry */
int first_null[3];

u32 tick()
{
	return ((TIMER1_DATA * (1 << 16)) + TIMER0_DATA) / 33;
}

bool inline macaddr_cmp(void *mac1, void *mac2)
{
	return (((u32 *) mac1)[0] == ((u32 *) mac2)[0]) &&
	    (((u16 *) mac1)[2] == ((u16 *) mac2)[2]);
}

/* Try to connect to given AP and get an IP via DHCP */
int connect_ap(Wifi_AccessPoint * ap)
{
	int ret;
	int status = ASSOCSTATUS_DISCONNECTED;

	clear_main();

	/* Ask for DHCP */
	Wifi_SetIP(0, 0, 0, 0, 0);
	ret = Wifi_ConnectAP(ap, WEPMODE_NONE, 0, NULL);
	if (ret) {
		print_to_debug("error connecting");
		return ASSOCSTATUS_CANNOTCONNECT;
	}

	while (status != ASSOCSTATUS_ASSOCIATED &&
	       status != ASSOCSTATUS_CANNOTCONNECT) {
		int oldStatus = status;

		status = Wifi_AssocStatus();
		if (oldStatus != status)
			printf_to_main("\n%s",
				       (char *)ASSOCSTATUS_STRINGS[status]);
		else
			printf_to_main(".");

		scanKeys();
		if (keysDown() & KEY_B)
			break;
		swiWaitForVBlank();
	}

	return status;
}

#define MAX_PACKET_SIZE 3192
unsigned char mac_filter[6], valid_packet;
unsigned char capture_data[MAX_PACKET_SIZE];

void cap_handler(int packetID, int packetlength)
{
	if (packetlength > MAX_PACKET_SIZE)
		packetlength = MAX_PACKET_SIZE;

	valid_packet = 1;
	Wifi_RxRawReadPacket(packetID, packetlength,
			     (unsigned short *)(capture_data));
	if (!macaddr_cmp(capture_data + 10, mac_filter) &&
	    !macaddr_cmp(capture_data + 4, mac_filter))
		valid_packet = 0;
}

void do_realloc(int type)
{
	/* realloc needed */
	if (num[type] >= sizes[type]) {
		sizes[type] += DEFAULT_ALLOC_SIZE;
		ap[type] =
		    (struct AP_HT_Entry **)realloc(ap[type], sizes[type]);
		if (!ap[type])
			abort_msg("Alloc failed !");
#ifdef DEBUG
		print_to_debug("realloc'd");
#endif
	}
}

/* AP insertion algorithm :
	1) check in hash table (and linked list)
	   if the AP is already present
	2) if not, insert in HT
	3) insert also in fast access list
	     - is there any NULL entry ?
	     	yes : use it, change NULL index
		no : put at the end
	4) update counters
*/

/* Insert the new AP in the fast access list
   and update the NULL entries if needed */
void insert_fast(int type, struct AP_HT_Entry *new_ap)
{
	/* Any NULL entry (timeouts) ? */
	if (num_null[type] > 0) {
		num_null[type]--;
		new_ap->array_idx = first_null[type];
		ap[type][first_null[type]] = new_ap;
		if (num_null[type] > 0) {
			while (first_null[type] < sizes[type]
			       && ap[type][++first_null[type]]) ;
			if (first_null[type] >= sizes[type])
				abort_msg
				    ("out of bound while looking for NULL");
		} else
			first_null[type] = -1;
	} else {
		new_ap->array_idx = num[type];
		ap[type][num[type]] = new_ap;
	}
	num[type]++;
}

/* Copy data from internal wifi storage
 * update tick
 * insert ptr into opn/wep/wpa tables
 */
struct AP_HT_Entry *entry_from_ap(Wifi_AccessPoint * ap)
{
	struct AP_HT_Entry *new_ht_ap;
	Wifi_AccessPoint *ap_copy;

	ap_copy = (Wifi_AccessPoint *) malloc(sizeof(Wifi_AccessPoint));
	if (!ap_copy)
		abort_msg("Alloc failed !");

	memcpy(ap_copy, ap, sizeof(Wifi_AccessPoint));

	new_ht_ap = (struct AP_HT_Entry *)malloc(sizeof(struct AP_HT_Entry));
	if (!new_ht_ap)
		abort_msg("Alloc failed !");

	new_ht_ap->ap = ap_copy;
	new_ht_ap->tick = curtick;
	new_ht_ap->next = NULL;

	return new_ht_ap;
}

/* Insert or update ap data in the hash table
 * returns 0 if the ap wasn't present
 * 1 otherwise
 */
char insert_ap(Wifi_AccessPoint * ap)
{
	int key = ap->macaddr[5];
	struct AP_HT_Entry *ht_entry;
	char same;
	struct AP_HT_Entry *to_insert = NULL;

	/* check if there's already an entry in the hash table */
	if (ap_ht[key] == NULL) {
		to_insert = entry_from_ap(ap);
		ap_ht[key] = to_insert;
	} else {
		ht_entry = ap_ht[key];
		/* Check if the AP is already known, walking the linked list */
		while (!(same = macaddr_cmp(ap->macaddr, ht_entry->ap->macaddr))
		       && ht_entry->next)
			ht_entry = ht_entry->next;

		if (same == 0) {
			to_insert = entry_from_ap(ap);
			ht_entry->next = to_insert;
		} else {
			/* AP is already there, just update data */
			ht_entry->tick = curtick;
			ht_entry->ap->channel = ap->channel;
			ht_entry->ap->rssi = ap->rssi;
			ht_entry->ap->flags = ap->flags;
			if (ap->ssid_len == 0) {
				memset(ht_entry->ap->ssid, 0, 32);
			} else {
				memcpy(ht_entry->ap->ssid, ap->ssid,
				       (unsigned char)ap->ssid_len >
				       32 ? 32 : ap->ssid_len);
			}
			return 1;
		}
	}

	if (to_insert) {
		if (to_insert->ap->flags & WFLAG_APDATA_WPA) {
			do_realloc(WPA);
			insert_fast(WPA, to_insert);
		} else {
			if (to_insert->ap->flags & WFLAG_APDATA_WEP) {
				do_realloc(WEP);
				insert_fast(WEP, to_insert);
			} else {
				do_realloc(OPN);
				insert_fast(OPN, to_insert);
			}
		}
	}
	numap++;

	return 0;
}

/* Delete APs which have timeouted */
void clean_timeouts()
{
	struct AP_HT_Entry *cur, *prev, *to_del;
	int i, type, idx;

	to_del = NULL;
	/* walk the whole hash table */
	for (i = 0; i < 256; i++) {
		cur = ap_ht[i];
		prev = NULL;
		while (cur) {
			if (curtick - (cur->tick) > timeout) {
				printf_to_debug("Timeout : %s\n",
						cur->ap->ssid);
				if (prev)
					prev->next = cur->next;
				else
					ap_ht[i] = cur->next;

				if (cur->ap->flags & WFLAG_APDATA_WPA) {
					type = WPA;
				} else {
					if (cur->ap->flags & WFLAG_APDATA_WEP)
						type = WEP;
					else
						type = OPN;
				}
				idx = cur->array_idx;

				ap[type][idx] = NULL;
				if (!num_null[type] || idx < first_null[type])
					first_null[type] = idx;
				num_null[type]++;
				num[type]--;

				to_del = cur;
				cur = cur->next;
				free(to_del->ap);
				free(to_del);
				numap--;
			} else {
				prev = cur;
				cur = cur->next;
			}
		}
	}
}

void wardriving_loop()
{
	int num_aps, i, index, flags, pressed;
	touchPosition touchXY;
	Wifi_AccessPoint cur_ap;
	u32 lasttick;
	char state, display_state;
	/* Vars for AP_DISPLAY */
	int entry_n;
	struct AP_HT_Entry *entry = NULL;

	print_to_debug("Setting scan mode...");

	Wifi_ScanMode();
	state = STATE_SCANNING;
	display_state = STATE_CONNECTING;

	for (i = 0; i < 3; i++) {
		sizes[i] = DEFAULT_ALLOC_SIZE;
		num[i] = num_null[i] = 0;
		first_null[i] = -1;
		ap[i] = (struct AP_HT_Entry **)
		    malloc(sizes[i] * sizeof(struct AP_HT_Entry *));
		if (ap[i] == NULL)
			abort_msg("alloc failed");
	}

	flags = DISP_WPA | DISP_OPN | DISP_WEP;
	memset(modes, 0, sizeof(modes));
	strcpy(modes, "OPN+WEP+WPA");

	index = 0;

	TIMER0_CR = TIMER_ENABLE | TIMER_DIV_1024;
	TIMER1_CR = TIMER_ENABLE | TIMER_CASCADE;
	lasttick = tick();

	while (1) {
		switch (state) {
		case STATE_SCANNING:
			curtick = tick();

			/* Wait for VBL just before key handling and redraw */
			swiWaitForVBlank();
			scanKeys();
			pressed = keysDown();

			/* Handle stylus press to display more detailed infos 
			 * handle this before AP insertion, to avoid race
			 * conditions */
			if (pressed & KEY_TOUCH) {
				touchRead(&touchXY);
				/* Entry number : 8 pixels for text, 3 lines */
				entry_n = touchXY.py / 8 / 3;
				entry = cur_entries[entry_n];
#ifdef DEBUG
				printf_to_debug("Entry : Y : %d\n", entry_n);
				printf_to_debug("SSID : %s\n", entry->ap->ssid);
#endif
				if (entry) {
					state = STATE_AP_DISPLAY;
					//display_state = STATE_PACKET_INIT;
					display_state = STATE_CONNECTING;
					print_to_debug("Packet scan mode");
					print_to_debug(" A : try to connect");
					print_to_debug(" B : back to scan");
					break;
				}
			}

			num_aps = Wifi_GetNumAP();
			for (i = 0; i < num_aps; i++) {
				if (Wifi_GetAPData(i, &cur_ap) !=
				    WIFI_RETURN_OK)
					continue;
				insert_ap(&cur_ap);
			}

			/* Check timeouts every second */
			if (timeout && (curtick - lasttick > 1000)) {
				lasttick = tick();
				clean_timeouts(lasttick);
			}

			if (pressed & KEY_RIGHT)
				timeout += 5000;
			if (pressed & KEY_LEFT && timeout > 0)
				timeout -= 5000;

			if (pressed & KEY_DOWN)
				index++;
			if (pressed & KEY_UP && index > 0)
				index--;
			if (pressed & KEY_R
			    && (index + (DISPLAY_LINES - 1)) <= numap)
				index += DISPLAY_LINES - 1;
			if (pressed & KEY_L && index >= DISPLAY_LINES - 1)
				index -= DISPLAY_LINES - 1;

			if (pressed & KEY_B)
				flags ^= DISP_OPN;
			if (pressed & KEY_A)
				flags ^= DISP_WEP;
			if (pressed & KEY_X)
				flags ^= DISP_WPA;

			/* Update modes string */
			if (pressed & KEY_B || pressed & KEY_A
			    || pressed & KEY_X) {
				modes[0] = 0;
				if (flags & DISP_OPN)
					strcat(modes, "OPN+");
				if (flags & DISP_WEP)
					strcat(modes, "WEP+");
				if (flags & DISP_WPA)
					strcat(modes, "WPA+");
				modes[strlen(modes) - 1] = 0;	/* remove the + */
			}

			display_list(index, flags);
			break;

		case STATE_AP_DISPLAY:
			switch (display_state) {
			case STATE_CONNECTING:
				/* TODO:
				 * 1) default to packet display
				 * 2) try DHCP [DONE]
				 * 3) try default IPs
				 * 4) handle WEP ?
				 */
				/* Try to connect */
				if (!(entry->ap->flags & WFLAG_APDATA_WPA) &&
				    !(entry->ap->flags & WFLAG_APDATA_WEP)) {
					print_to_debug
					    ("Trying to connect to :");
					print_to_debug(entry->ap->ssid);
					if (entry->ap->rssi <= 40)
						print_to_debug
						    ("Warning : weak signal");
					print_to_debug("Press B to cancel");
					switch (connect_ap(entry->ap)) {
					case ASSOCSTATUS_ASSOCIATED:
						display_state =
						    STATE_CONNECTED_FIRST;
						break;

					default:
						print_to_debug("Cnx failed");
						state = STATE_SCANNING;
						Wifi_ScanMode();
					}
				} else {
					print_to_debug
					    ("WEP/WPA AP not supported");
					state = STATE_SCANNING;
					break;
				}
				break;

			case STATE_CONNECTED_FIRST:
				display_ap(entry->ap, 1);
				display_state = STATE_CONNECTED;
				break;

			case STATE_CONNECTED:
				display_ap(entry->ap, 0);
				break;

			case STATE_PACKET_INIT:
				memcpy(mac_filter, entry->ap->macaddr, 6);
				Wifi_SetChannel(entry->ap->channel);
				Wifi_RawSetPacketHandler(cap_handler);
				Wifi_SetPromiscuousMode(1);
				display_state = STATE_PACKET;
				break;

			case STATE_PACKET:
				Wifi_Update();
				if (valid_packet)
					print_to_debug("Un paquet !\n");
				else
					print_to_debug("No paquet !\n");
				break;
			}

			scanKeys();
			if (keysDown() & KEY_A && state == STATE_PACKET) {
				state = STATE_CONNECTING;
			}
			if (keysDown() & KEY_B) {
				print_to_debug("Back to scan mode");
				state = STATE_SCANNING;
				Wifi_RawSetPacketHandler(NULL);
				Wifi_SetPromiscuousMode(0);
				Wifi_ScanMode();
			}
			swiWaitForVBlank();
			break;
		}
	}
}

int main(int argc, char **argv)
{

	//irqInit();
	irqEnable(IRQ_VBLANK);

	/* Setup logging console on top screen */
	init_consoles();

	print_to_debug("AirScan v1.0 by Raphael Rigo");
	print_to_debug("released 07/11/2010");
	print_to_debug("");
	print_to_debug("B: Toggle OPN");
	print_to_debug("A: Toggle WEP");
	print_to_debug("X: Toggle WPA");
	print_to_debug("Up/Down : scroll");
	print_to_debug("Left/Right : Timeout -/+");
	print_to_debug("");

	print_to_debug("Initializing Wifi...");
	Wifi_InitDefault(false);

	wardriving_loop();

	return 0;
}

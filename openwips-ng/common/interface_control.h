/*
 * OpenWIPS-ng - common stuff.
 * Copyright (C) 2011 Thomas d'Otreppe de Bouvette
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 *      Author: Thomas d'Otreppe de Bouvette
 */

#ifndef COMMON_INTERFACE_CONTROL_H_
#define COMMON_INTERFACE_CONTROL_H_

#include "pcap.h"

#ifdef __CYGWIN__
	#include <windows.h>
	#include <airpcap.h>

	#define pcap_interface_ptr PAirpcapHandle
#else
	#define pcap_interface_ptr pcap_t *
#endif

// Libpcap read error
#define ERROR_PCAP_INVALID_PARAM -8
// The previous one is a custom one
#define ERROR_PCAP_OEF -2
#define ERROR_PCAP_PACKET_READ_ERROR -1
#define ERROR_PCAP_TIMEOUT 0

enum rfmon_action_enum {
	FIRST_CALL,
	TRY_RFMON_NL80211,
	DONT_TRY_AGAIN
};

struct rfmon {
	pcap_interface_ptr handle; // See local pcap.h
	char * interface;
	bpf_u_int32 link_type;
};

struct rfmon * init_struct_rfmon();
int free_struct_rfmon(struct rfmon * elt);

int set_monitor_mode_nl80211(char * interface, char * new_iface_name);
int set_interface_up(char * interface);
struct rfmon * enable_monitor_mode(char * interface, enum rfmon_action_enum action);
int interface_exist(char * interface_name);

int close_pcap_handle(pcap_interface_ptr handle);
int inject_frame(pcap_interface_ptr handle, unsigned char * frame, unsigned length);
int get_pcap_datalink(pcap_interface_ptr handle);
char * get_pcap_last_error(pcap_interface_ptr handle);
int get_pcap_next_packet(pcap_interface_ptr handle, struct pcap_pkthdr ** packet_header, const u_char ** packet, unsigned char * buffer, unsigned int buffer_size, int linktype);

#endif /* COMMON_INTERFACE_CONTROL_H_ */

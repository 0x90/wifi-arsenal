/*
 * OpenWIPS-ng server plugin: Check if IEs are valid in management frames.
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
#include <stdlib.h>
#include <string.h>
#include "frame_plugin_header.h"
#include "IEs.h"

void * init_plugin(char * config_line, int version)
{
	struct IE_Check * iec;

	if (version) { }

	iec = (struct IE_Check *)malloc(sizeof(struct IE_Check));
	iec->attack = (char*)calloc(1, 4096 * sizeof(char));
	iec->frame = NULL;
	iec->ignore_wve_2006_0064 = 1;

	if (config_line) {
		if (strcmp("enable wve-2006-0064", config_line) == 0) {
			iec->ignore_wve_2006_0064 = 0;
		}
	}

	return iec;
}

void free_memory_and_unload(void * data)
{
	if (data != NULL) { }
}

char plugin_type(void)
{
	return PLUGIN_TYPE_FRAME;
}

int min_supported_version()
{
	return 100;
}

int max_supported_version()
{
	return NO_MAX_SUPPORTED_VERSION;
}

char * init_text(void * config)
{
	if (config) { }
	char * ret = malloc(sizeof(char) * 100);
	strcpy(ret, "IE (Information Element) Check plugin - Initialized.");

	return ret;
}

// Functions specific to this type of plugin

int static_frame_type()
{
	return FRAME_TYPE_MANAGEMENT; // Management frames only
}

int static_frame_subtype()
{
	// Multiple subtypes
	return ANALYZES_ALL_FRAMES;
}

int need_all_frames()
{
	return 0;
}

int is_single_frame_attack()
{
	return 1;
}

int require_packet_parsed()
{
	return 1;
}

int can_use_frame(struct pcap_packet * packet, void * config)
{
	// We can use the following subtypes:
	// - Association request/response (0, 1)
	// - Probe request/response (4, 5)
	// - Beacons: 8
	// - Authentication: 11
	static int can_use[] = { 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0 };
	if (config) { }

	return (packet && packet->info && packet->info->frame_subtype < 16 && can_use[packet->info->frame_subtype]);
}

int analyze(struct pcap_packet * packet, void * config)
{
	if (config) { }
	return 1;
}

int nb_frames_before_analyzing(void * config)
{
	if (config) { }
	return 1;
}

int time_ms_before_analyzing(void * config)
{
	if (config) { }
	return NO_TIME_CONSTRAINT;
}

int is_attacked(struct pcap_packet * packet_list, void * config)
{
	struct IE_Check * iec;
	unsigned char SSID_len;
	unsigned int fixed_param_length;
	static unsigned int fixed_param_lengths[] = { 4, 6, 0, 0, 0, 12, 0, 0, 12, 0, 0, 6, 0, 0, 0, 0, 0 };
	if (packet_list == NULL || config == NULL) {
		return 0;
	}

	iec = (struct IE_Check *)config;

	// Check the ESSID IE. If length above 32, then invalid.
	if (iec == NULL || iec->frame == NULL || iec->frame->info == NULL || iec->frame->info->frame_payload == NULL || iec->frame->data == NULL) {
		return 0;
	}

	// Check if length is OK (2 is for the minimum length of an IE)
	fixed_param_length = fixed_param_lengths[iec->frame->info->frame_subtype];
	if (iec->frame->header.cap_len < (iec->frame->info->frame_payload - iec->frame->data) + 2 + fixed_param_length) {
		return 0;
	}

	// SSID is the first IE and has a tag number of 0
	if (iec->frame->info->frame_payload[fixed_param_length] != 0) {
		return 0;
	}

	// Next is the length and it must be 32 or lower.
	SSID_len = iec->frame->info->frame_payload[fixed_param_length + 1];
	if (SSID_len > MAX_SSID_LENGTH) {
		// Prepare message
		sprintf(iec->attack, "ANOMALY/ATTACK - Invalid frame (Type: %u - Subtype: %u - SN: %u): length of the ESSID must be 32 characters of lower. Got an SSID with %u characters long.",
				packet_list->info->frame_type,
				packet_list->info->frame_subtype,
				packet_list->info->sequence_number,
				SSID_len);

		// And attach the frame
		iec->frame = packet_list;

		return 1;
	}

	if (SSID_len == 0) {
		// WVE-2008-0010: Marvell Null SSID Association Request
		if (packet_list->info->frame_subtype == 0) {
			sprintf(iec->attack, "ATTACK - Station sending an association request with an SSID length of 0 - See WVE-2008-0010.");
			return 1;
		}

		// WVE-2006-0064: NULL SSID Probe Response DoS
		if (packet_list->info->frame_subtype == 5 && iec->ignore_wve_2006_0064 == 0) {
			sprintf(iec->attack, "ATTACK - Station sending a probe response with an SSID length of 0 - See WVE-2006-0064.");
		}
	}

	// TODO: Add WVE-2006-0072 and WVE-2006-0071 (MOKB-11-11-2006)

	return 0;
}

char * attack_details(void * config)
{
	char * ret;
	struct IE_Check * iec;
	if (!config) {
		return NULL;
	}

	iec = (struct IE_Check *)config;
	ret = NULL;
	if (iec->attack) {
		ret = (char*)malloc(sizeof(char) * (strlen(iec->attack) + 1));
		strcpy(ret, iec->attack);
	}

	return ret;
}


unsigned char ** get_attacker_macs(void * config, int * nb_mac, int * deauth)
{
	int nbmacs;
	unsigned char ** macs;
	struct IE_Check * iec = NULL;
	if (config) {
		iec = (struct IE_Check *) config;
	}

	// Add all 4 addresses
	macs = NULL;
	nbmacs = 0;
	if (iec->frame && iec->frame->info) {
		macs = (unsigned char **)malloc(sizeof(unsigned char *) * 4);
		// TODO: Check if the mac is not a special one (packet_analysis): broadcast, null, ipv4 multicast, etc
		//       packet_analysis will also take care of verifying if one of the mac is not a bssid we take care of

		COPY_MAC(iec->frame->info->address1, macs, nbmacs)
		COPY_MAC(iec->frame->info->address2, macs, nbmacs)
		COPY_MAC(iec->frame->info->address3, macs, nbmacs)
		COPY_MAC(iec->frame->info->address4, macs, nbmacs)

		macs = (unsigned char **)realloc(macs, sizeof(unsigned char *) * nbmacs);
	}

	if (nb_mac) {
		*nb_mac = nbmacs;
	}

	// Deauth these guys
	if (deauth) {
		*deauth = 1;
	}

	return macs;
}

void clear_attack(void * config)
{
	struct IE_Check * iec;

	if (config != NULL) {
		iec = (struct IE_Check *) config;
		memset(iec->attack, 0, strlen(iec->attack) * sizeof(char));
		iec->frame = NULL;
	}
}

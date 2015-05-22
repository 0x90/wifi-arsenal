/*
 * OpenWIPS-ng server plugin: Check if the frame subtype value is valid.
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

struct attack_details {
	unsigned char address1[6], address2[6], address3[6], address4[6];
	unsigned char nb_addr;
	unsigned char frame_type;
	unsigned char frame_subtype;
};

struct attack_details * init_attack_details()
{
	struct attack_details * ret = (struct attack_details *)malloc(sizeof(struct attack_details));
	NULLIFY_MAC_ARRAY(ret->address1);
	NULLIFY_MAC_ARRAY(ret->address2);
	NULLIFY_MAC_ARRAY(ret->address3);
	NULLIFY_MAC_ARRAY(ret->address4);
	ret->nb_addr = 0;
	ret->frame_type = 0;
	ret->frame_subtype = 0;

	return ret;
}

void * init_plugin(char * config_line, int version)
{
	if (config_line || version) { }
	return init_attack_details();
}

void free_memory_and_unload(void * data)
{
	if (data) {
		free(data);
	}
}

char plugin_type(void)
{
	return 'F';
}

int min_supported_version()
{
	return 100;
}

int max_supported_version()
{
	return 0;
}

char * init_text(void * config)
{
	char * ret = (char *)calloc(1, sizeof(char) * 30);
	strcpy(ret, "Frame subtype anomaly check.");
	return ret;
}

int static_frame_type()
{
	return -1;
}

int static_frame_subtype()
{
	return -1;
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
	if (config) { }
	return packet != NULL;
}

int analyze(struct pcap_packet * packet, void * config)
{
	return 1;
}

int nb_frames_before_analyzing(void * config)
{
	return 1;
}

int time_ms_before_analyzing(void * config)
{
	return -1;
}

int is_attacked(struct pcap_packet * packet_list, void * config)
{
	struct attack_details * ad;

	const static unsigned int is_attacked_array[3][16] = {
			{ 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1 },	// Management: wlan.fc.type == 0 && (wlan.fc.subtype == 7 || wlan.fc.subtype == 15)
			{ 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 },	// Control frames: wlan.fc.type == 1 && wlan.fc.subtype < 7
			{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0 }	// Data frames: wlan.fc.type == 2 && wlan.fc.subtype == 13
	};

	if (packet_list == NULL) {
		return 0;
	}

	// Return 1 if the subtype is reserved
	if (packet_list->info->frame_type < 3 && packet_list->info->frame_subtype < 16
			&& is_attacked_array[packet_list->info->frame_type][packet_list->info->frame_subtype]) {

		if (config) {
			ad = (struct attack_details *)config;

			ad->frame_type = packet_list->info->frame_type;
			ad->frame_subtype = packet_list->info->frame_subtype;

			COPY_MAC_TO_ARRAY(packet_list->info->address1, ad->address1);
			if (packet_list->info->frame_type == FRAME_TYPE_CONTROL) {
				ad->nb_addr = 1;
			} else {
				COPY_MAC_TO_ARRAY(packet_list->info->address2, ad->address2);
				COPY_MAC_TO_ARRAY(packet_list->info->address3, ad->address3);
				ad->nb_addr = (packet_list->info->toDS && packet_list->info->fromDS) ? 4 : 3;
				if (ad->nb_addr == 4) {
					COPY_MAC_TO_ARRAY(packet_list->info->address4, ad->address4);
				}
			}
		}

		return 1;
	}

	return 0;
}

char * attack_details(void * config)
{
	struct attack_details * ad;
	if (config == NULL) {
		return NULL;
	}

	char * ret = (char *)calloc(1, sizeof(char) * 100);
	ad = (struct attack_details *)config;
	sprintf(ret, "ANOMALY - Subtype <%d> is not a valid value (reserved) for %s frame.",
			ad->frame_subtype,
			FRAME_TYPE_TO_STRING(ad->frame_type));

	return ret;
}

unsigned char ** get_attacker_macs(void * config, int * nb_mac, int * deauth)
{
	int counter;
	struct attack_details * ad;
	unsigned char ** macs = NULL;

	if (config == NULL) {
		return NULL;
	}

	ad = (struct attack_details *)config;
	if (nb_mac) {
		*nb_mac = ad->nb_addr;

		if (ad->nb_addr) {
			// Copy macs
			macs = (unsigned char **)malloc(sizeof(unsigned char *) * (ad->nb_addr));
			counter = 0;

			COPY_MAC(ad->address1, macs, counter)
			if (ad->nb_addr > 1) {
				COPY_MAC(ad->address2, macs, counter)
			}
			if (ad->nb_addr > 2) {
				COPY_MAC(ad->address3, macs, counter)
			}
			if (ad->nb_addr > 3) {
				COPY_MAC(ad->address4, macs, counter)
			}
		}
	}

	if (ad->nb_addr == 0) {
		return NULL;
	}

	if (deauth) {
		*deauth = 1;
	}

	return macs;
}

void clear_attack(void * config)
{
	struct attack_details * ad;
	if (config) {
		ad = (struct attack_details *)config;
		ad->nb_addr = 0;
	}
}

/*
 * OpenWIPS-ng server plugin: Deauthentication (directed/broadcast) detection.
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
#include "deauth_detect.h"
#include "../common/utils.h"

void * init_plugin(char * config_line, int version)
{
	struct deauth_attack_struct * config;

	if (config_line) {}
	if (version) {}

	config = (struct deauth_attack_struct *)malloc(sizeof(struct deauth_attack_struct));
	config->is_attacked = 0;
	NULLIFY_MAC_ARRAY(config->source_mac);
	NULLIFY_MAC_ARRAY(config->dest_mac);

	config->last_packet = NULL;

	return config;
}

void free_memory_and_unload(void * data)
{
	if (data != NULL) {
		free(data);
	}
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
	char * ret = malloc(sizeof(char) * 65);
	strcpy(ret, "Deauth (directed/broadcast) Attack Checker plugin - Initialized.");

	return ret;
}

// Functions specific to this type of plugin

int static_frame_type()
{
	return FRAME_TYPE_MANAGEMENT;
}

int static_frame_subtype()
{
	return 12; // Deauth
}

int need_all_frames()
{
	return 0;
}

// It's not
int is_single_frame_attack()
{
	return 0;
}

int require_packet_parsed()
{
	return 1;
}

int can_use_frame(struct pcap_packet * packet, void * config)
{
	if (config) { }

	return 1;
}

int analyze(struct pcap_packet * packet, void * config)
{
	struct deauth_attack_struct * das = NULL;

	if (packet == NULL) {
		return 1;
	}


	if (config != NULL) {
		das = (struct deauth_attack_struct *) config;
		clear_attack(config);
		das->last_packet = copy_packets(packet, 0, 1);
		if (is_mac_broadcast(das->last_packet->info->address1) ||
			is_mac_broadcast(das->last_packet->info->address2) ||
			is_mac_broadcast(das->last_packet->info->address3)) {
			das->is_broadcast = 1;
			das->is_attacked = 1;
		}
	}

	return 1;
}

int nb_frames_before_analyzing(void * config)
{
	struct deauth_attack_struct * das = NULL;

	if (config != NULL) {
		das = (struct deauth_attack_struct *) config;
		if (das->is_attacked || das->is_broadcast) {
			return 1;
		}
	}

	// Else, 10 within 500 ms
	return 10;
}

int time_ms_before_analyzing(void * config)
{
	struct deauth_attack_struct * das = NULL;

	if (config != NULL) {
		das = (struct deauth_attack_struct *) config;
		if (das->is_attacked || das->is_broadcast) {
			return NO_TIME_CONSTRAINT;
		}
	}

	// If ! broadcast, then 500ms
	return 500;
}

int is_attacked(struct pcap_packet * packet_list, void * config)
{
	int nb_packets, nb_airplay_ng, nb_broadcast;
	//char mac_broadcast[6];
	//char mac_aireplay[6];
	int broadcast_addr[3];
	//int nb_aireplayng[2]; // Number from aireplay-ng (first: normal, second: broadcast)
	struct pcap_packet * cur;
	struct deauth_attack_struct * das = NULL;
	if (config != NULL) {
		das = (struct deauth_attack_struct *) config;
		das->is_attacked = 0; // Not attacked by default
	}

	// Do the packet analysis

	// Reset mac buffer
	memset(das->source_mac, 0, 6);
	memset(das->dest_mac, 0, 6);

	if (packet_list == NULL || (nb_packets = pcap_packet_len(packet_list)) == 0) {
		das->is_attacked = 0;
		das->is_broadcast = 0;
		free_pcap_packet(&(das->last_packet), 0);
		das->last_packet = NULL;

		return 0;
	}

	// Need more frames?
	if (nb_packets < 10 && !(das->is_attacked || das->is_broadcast)) {
		return 0;
	}


	// If more than 30% of the frame contains the famous 2 bytes from aireplay-ng (0x07 0x00), mark it as coming from aireplay-ng and use that mac
	//nb_aireplayng[0] = nb_aireplayng[1] = 0;
	nb_airplay_ng = 0; nb_broadcast = 0;
	for (cur = packet_list; cur != NULL; cur = cur->next) {
		// Count the ones coming from aireplay-ng
		if (cur->info == NULL) {
			cur->info = parse_packet_basic_info(cur);
		}
		if (cur->info != NULL && cur->header.cap_len > cur->info->packet_header_len + 25) {
			if ((*(cur->info->frame_start + 24) == 0x07) && (*(cur->info->frame_start + 25) == 0x00)) {
				++nb_airplay_ng;
			}
		}

		// Check the amount of broacast
		if (das->is_broadcast == 0 && (
				is_mac_broadcast(cur->info->address1) ||
				is_mac_broadcast(cur->info->address2) ||
				is_mac_broadcast(cur->info->address3))) {
			nb_broadcast++;
		}
	}

	// If more than 30% of the frames come from aireplay-ng then say it is coming from aireplay-ng
	das->is_aireplay = (nb_airplay_ng > 0) ? ((nb_packets * 100) / nb_airplay_ng > 30) : 0;
	if (das->is_broadcast == 0 && nb_broadcast) {
		das->is_broadcast = ((nb_packets * 100) / nb_broadcast > 50);
	}
	das->is_attacked = das->is_attacked || das->is_broadcast || das->is_aireplay;

	if (das->is_broadcast) {
		// Get source address : address 2 or 3

		// 1. Find a broadcast packet
		// TODO: Add custom field (and free_er) so that it can be stored and it will save CPU cycles
		for (cur = packet_list; cur != NULL; cur = cur->next) {

			if (cur->info == NULL) {
				continue;
			}

			// 2. Get address
			broadcast_addr[0] = is_mac_broadcast(cur->info->address1);
			broadcast_addr[1] = is_mac_broadcast(cur->info->address2);
			broadcast_addr[2] = is_mac_broadcast(cur->info->address3);
			if (broadcast_addr[0] + broadcast_addr[1] + broadcast_addr[2]) {
				if (!broadcast_addr[0]) {
					memcpy(das->source_mac, cur->info->address1, 6);
				} else if (!broadcast_addr[1]) {
					memcpy(das->source_mac, cur->info->address2, 6);
				} else if (!broadcast_addr[2]) {
					memcpy(das->source_mac, cur->info->address3, 6);
				}
			}
		}
	} else {
		for (cur = packet_list; cur != NULL; cur = cur->next) {

			if (cur->info == NULL) {
				continue;
			}

			// 2. Get address
			if (!is_mac_broadcast(cur->info->source_address)) {
				memcpy(das->source_mac, cur->info->source_address, 6);
			}

			if (!is_mac_broadcast(cur->info->destination_address)) {
				memcpy(das->dest_mac, cur->info->destination_address, 6);
			}
		}
	}

	if (das->is_attacked || das->is_broadcast) {
		return 1;
	}

	return 0;
}

char * attack_details(void * config)
{
	struct deauth_attack_struct * das;
	if (!config) {
		return NULL;
	}
	das = (struct deauth_attack_struct *) config;
	char * ret = (char*)calloc(1, 200 * sizeof(char));
	if (das->is_attacked == 0) {
		strcpy(ret, "Do not call attack_details() if not attacked.");
		return ret;
	}

	if (das->is_broadcast) {
		sprintf(ret, "ALERT - Broadcast deauthentication attack %s(source: %02x:%02x:%02x:%02x:%02x:%02x)",
									(das->is_aireplay) ? "from aireplay-ng " : "",
									das->source_mac[0], das->source_mac[1], das->source_mac[2],
									das->source_mac[3], das->source_mac[4], das->source_mac[5]);
	} else {
		sprintf(ret, "ALERT - Deauthentication attack %s(Source: %02x:%02x:%02x:%02x:%02x:%02x - Destination: %02x:%02x:%02x:%02x:%02x:%02x)",
								(das->is_aireplay) ? "from aireplay-ng " : "",
								das->source_mac[0], das->source_mac[1], das->source_mac[2],
								das->source_mac[3], das->source_mac[4], das->source_mac[5],
								das->dest_mac[0], das->dest_mac[1], das->dest_mac[2],
								das->dest_mac[3], das->dest_mac[4], das->dest_mac[5]);
	}

	return ret;
}

unsigned char ** get_attacker_macs(void * config, int * nb_mac, int * deauth)
{
	int counter;
	unsigned char ** macs;
	struct deauth_attack_struct * das = NULL;
	if (config) {
		das = (struct deauth_attack_struct *) config;
	}

	macs = NULL;

	if (das) {
		if (nb_mac) {
			*nb_mac = (das->is_broadcast) ? 1 : 2;
		}
		macs = (unsigned char **)malloc(sizeof(unsigned char *) * (das->is_broadcast) ? 1 : 2);
		counter = 0;

		COPY_MAC(das->source_mac, macs, counter)
		if (das->is_broadcast == 0) {
			COPY_MAC(das->dest_mac, macs, counter)
		}
	} else if (nb_mac) {
		macs = NULL;
		*nb_mac = 0;
	}

	// Deauth the attacker doesn't really make sense in this case.
	// Use a baseball bat to restore service. Quick, cheap and easy ;-)
	if (deauth) {
		*deauth = 0;
	}

	return macs;
}

void clear_attack(void * config)
{
	struct deauth_attack_struct * das = NULL;
	if (config) {
		das = (struct deauth_attack_struct *)config;
	}

	das->is_attacked = 0;
	das->is_broadcast = 0;
	if (das->last_packet != NULL) {
		free_pcap_packet(&(das->last_packet), 0);
		das->last_packet = NULL;
	}
}

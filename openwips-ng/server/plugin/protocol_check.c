/*
 * OpenWIPS-ng server plugin: Check if the protocol value is valid.
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

void * init_plugin(char * config_line, int version)
{
	if (config_line) {}
	if (version) {}

	return NULL;
}

void free_memory_and_unload(void * data)
{
	if (data != NULL) {}
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
	strcpy(ret, "Protocol Version Check plugin - For demo only (Do not use, check already done).");

	return ret;
}

// Functions specific to this type of plugin

int static_frame_type()
{
	return ANALYZES_ALL_FRAMES;
}

int static_frame_subtype()
{
	return ANALYZES_ALL_FRAMES;
}

int need_all_frames()
{
	return 1;
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
	if (packet && config) { }
	// We check against every frame
	return 1;
}

int analyze(struct pcap_packet * packet, void * config)
{
	if (config) { }
	return (packet && packet->info && packet->info->protocol != 0);
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
	if (config) { }
	return analyze(packet_list, config);
}

char * attack_details(void * config)
{
	if (config) { }
	char * ret = (char*)calloc(1, 73 * sizeof(char));
	strcpy(ret, "ALERT - Invalid protocol version in frame. Protocol should always be 0.\n");
	return ret;
}

unsigned char ** get_attacker_macs(void * config, int * nb_mac, int * deauth)
{
	if (config) { }
	if (nb_mac) {
		*nb_mac = 0;
	}
	if (deauth) {
		*deauth = 0;
	}

	return NULL;
}

void clear_attack(void * config)
{
	if (config) { }
}

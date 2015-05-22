/*
 * OpenWIPS-ng server plugin: Fragmentation detection.
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

#define NB_ADDRESSES 4

struct frag_attack {
	unsigned int nb_frames; // TODO: Handle more than one frame and several attacks at the same time
	unsigned char **addresses;
	int nb_mac;
};

void * init_plugin(char * config_line, int version)
{
	int i;
	struct frag_attack * fa = (struct frag_attack *)malloc(sizeof(struct frag_attack));
	fa->nb_frames = 1; // By default 1 frame is enough (frag should never happen on any network

	// Allocate memory at startup
	fa->addresses = (unsigned char **)malloc(sizeof(unsigned char *) * NB_ADDRESSES);
	for (i = 0; i < NB_ADDRESSES; i++) {
		fa->addresses[i] = (unsigned char *)malloc(sizeof(unsigned char) * MAC_LEN);
	}

	fa->nb_mac = 0;

	/*
	if (config_line) {

		fa->nb_frames = atoi(config_line);
		if (fa->nb_frames == 0) {
			fa->nb_frames = 1;
		}
	}
	*/

	return fa;
}

void free_memory_and_unload(void * data)
{
	int i;
	struct frag_attack * fa;

	if (!data) {
		return;
	}

	fa = (struct frag_attack *)data;

	for (i = 0; i < NB_ADDRESSES; i++) {
		free(fa->addresses[i]);
	}
	free(fa->addresses);

	free(fa);
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
	return 0;
}

char * init_text(void * config)
{
	struct frag_attack * fa;
	char * ret = (char *)calloc(1, 80 * sizeof(char));
	if (config) {
		fa = (struct frag_attack *)config;
		sprintf(ret, "Fragmentation attack detection (with %u frame%s) v1.0", fa->nb_frames, (fa->nb_frames > 1) ? "s" : "");
	} else {
		strcpy(ret, "Fragmentation attack detection v1.0");
	}

	return ret;
}

int static_frame_type()
{
	// It should only be data frames with data but there can be
	// an idiot out there to try it on control/management frames too (more frag bit on control)
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
	// No because it depends on the config but currently it is
	return 1;
}

int require_packet_parsed()
{
	return 1;
}

int can_use_frame(struct pcap_packet * packet, void * config)
{
	if (packet == NULL || packet->info == NULL || config == NULL) {
		return 0;
	}

	return 1;
}

int analyze(struct pcap_packet * packet, void * config)
{
	if (packet == NULL || packet->info == NULL || config == NULL) {
		return 0;
	}

	return packet->info->fragment_nr || packet->info->more_frag;
}

int nb_frames_before_analyzing(void * config)
{
	struct frag_attack * fa;
	if (config) {
		fa = (struct frag_attack *)config;
		return fa->nb_frames;
	}

	return 1;
}

int time_ms_before_analyzing(void * config)
{
	if (config) { }
	return NO_TIME_CONSTRAINT;
}

int is_attacked(struct pcap_packet * packet_list, void * config)
{
	int counter;
	struct frag_attack * fa;
	int ret = analyze(packet_list, config);
	if (packet_list == NULL || packet_list->info == NULL || config == NULL || ret == 0) {
		return 0;
	}

	// TODO: Make sure we can handle multiple attacks at the same time when more than 1 frame is required (the amount of frame PER attack).
	//       Do a chained list and same logic like another plugin.

	// Keep attacker info in the structure
	counter = 0;
	fa = (struct frag_attack *)config;

	// Copy MACs
	if (packet_list->info->address1) {
		memcpy(fa->addresses[counter++], packet_list->info->address1, MAC_LEN);
	}
	if (packet_list->info->address2) {
		memcpy(fa->addresses[counter++], packet_list->info->address2, MAC_LEN);
	}
	if (packet_list->info->address3) {
		memcpy(fa->addresses[counter++], packet_list->info->address3, MAC_LEN);
	}
	if (packet_list->info->address4) {
		memcpy(fa->addresses[counter++], packet_list->info->address4, MAC_LEN);
	}

	fa->nb_mac = counter;

	return ret;
}

char * attack_details(void * config)
{
	int i;
	struct frag_attack * fa;
	char * ret;

	if (config == NULL) {
		return NULL;
	}

	fa = (struct frag_attack *)config;
	ret = (char *)calloc(1, 100 + (fa->nb_mac * 3 * MAC_LEN));

	strcpy(ret, "ALERT - Fragmentation attack in progress");
	if (fa->nb_mac) {
		// TODO: Only the calling thread should reveal the mac since the plugin doesn't do any check on it.
		strcat(ret, ". MAC Addresses involved:");
		for (i = 0; i < fa->nb_mac; i++) {
			sprintf(ret + strlen(ret), " %02X:%02X:%02X:%02X:%02X:%02X",
									fa->addresses[i][0], fa->addresses[i][1], fa->addresses[i][2],
									fa->addresses[i][3], fa->addresses[i][4], fa->addresses[i][5]);
		}
	}

	return ret;
}

unsigned char ** get_attacker_macs(void * config, int * nb_mac, int * deauth)
{
	int i;
	unsigned char ** macs;
	struct frag_attack * fa;
	int counter = 0;

	if (config == NULL) {
		return NULL;
	}

	fa = (struct frag_attack *)config;

	if (deauth) {
		*deauth = 1;
	}

	if (nb_mac) {
		*nb_mac = fa->nb_mac;
	}

	// Copy the mac addresses
	macs = (unsigned char **)malloc(sizeof(unsigned char *) * (fa->nb_mac));
	for (i = 0; i < fa->nb_mac; i++) {
		COPY_MAC(fa->addresses[i], macs, counter)
	}

	return fa->addresses;
}

void clear_attack(void * config)
{
	struct frag_attack * fa;
	if (config) {
		fa = (struct frag_attack *)config;
		// Do not free, memory (since we know how much we allocated at startup, we know what to free at exit).
		fa->nb_mac = 0;
	}
}

#undef NB_ADDRESSES

/*
 * OpenWIPS-ng server plugin: Frame replay detection.
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
#include "replay_detect.h"

struct replay_attack * init_new_replay_attack_strut()
{
	struct replay_attack * ret = (struct replay_attack *)malloc(sizeof(struct replay_attack));
	ret->attack = NULL;
	ret->next = NULL;
	NULLIFY_MAC_ARRAY(ret->address1);
	NULLIFY_MAC_ARRAY(ret->address2);
	NULLIFY_MAC_ARRAY(ret->address3);
	NULLIFY_MAC_ARRAY(ret->address4);
	ret->attack_returned = 0;

	// TODO: Implenent is_attacked
	fprintf(stderr, "Replay attack plugin: Work in Progress - Do not use it yet.\n");
	exit(0);

	return ret;
}

// TODO: Add a parameter to tell how many frames it needs (and an optional second one for time)
void * init_plugin(char * config_line, int version)
{
	if (config_line || version) { }

	return init_new_replay_attack_strut();
}

void free_memory_and_unload(void * data)
{
	struct replay_attack * conf, * prev;

	if (data == NULL) {
		return;
	}

	// Free all the data
	prev = NULL;
	for (conf = (struct replay_attack *)data; conf != NULL;) {
		prev = conf;
		if (conf->attack) {
			free(conf->attack);
		}
		conf = conf->next;
		free(prev);
	}

	free(conf);
	data = NULL;
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
	char * ret;
	if (config) { }

	ret = (char *)calloc(1, 50*sizeof(char));
	strcpy(ret, "Replay attack detection v1.0");
	return ret;
}

// Specific functions
int static_frame_type()
{
	return FRAME_TYPE_DATA;
}

int static_frame_subtype()
{
	return ANALYZES_ALL_FRAMES;
}

int need_all_frames()
{
	return 0;
}

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
	const char is_frame_usable[16] = { 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0 };
	if (!packet || !packet->info) {
		return 0;
	}

	// Check if it's a frame carrying data
	return !packet->info->retry && packet->info->frame_subtype < 16 && is_frame_usable[packet->info->frame_subtype];
}

int analyze(struct pcap_packet * packet, void * config)
{
	if (!config || !packet) {
		return 0;
	}
	return 1; // Need more than 1 frame to analyze, so always return attack attempt and thus is_attack is going to do the analysis
}

int nb_frames_before_analyzing(void * config)
{
	if (config) { }
	return 2;
}

int time_ms_before_analyzing(void * config)
{
	if (config) { }
	return NO_TIME_CONSTRAINT;
}

int is_attacked(struct pcap_packet * packet_list, void * config)
{
	struct replay_attack * ra;

	if (!config || !packet_list) {
		return 0;
	}

	ra = (struct replay_attack *)config;

	// Analyze the current frame list to see if there is any new (then add it to the chained list)



	// Return if there is (at least) one
	return ra->attack != NULL;
}

char * attack_details(void * config)
{
	struct replay_attack * ra;
	if (config == NULL) {
		return NULL;
	}

	ra = (struct replay_attack *)config;
	if (ra == NULL) {
		return NULL;
	}

	ra->attack_returned = 1;

	return ra->attack;
}

// nb_mac indicates the amount of mac in the returned array
// deauth indicates if the macs needs to be deauthenticated.
unsigned char ** get_attacker_macs(void * config, int * nb_mac, int * deauth)
{
	unsigned char ** macs = NULL;
	if (deauth) {
		*deauth = 1;
	}

	return macs;
}

void clear_attack(void * config)
{
	struct replay_attack * ra;
	if (config == NULL) {
		return;
	}

	ra = (struct replay_attack *)config;

	// Clear the first attack
	config = ra->next; // Return the next one

	// Note: No need to free attack if it has been returned, the calling thread takes care of that
	if (ra->attack_returned == 0) {
		free(ra->attack);
	}
	free(ra);

}

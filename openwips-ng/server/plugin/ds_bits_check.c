/*
 * OpenWIPS-ng server plugin: Check FromDS and ToDS bits.
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
#include "ds_bits_check.h"
#include "frame_plugin_header.h"

void * init_plugin(char * config_line, int version)
{
	struct ds_bits_check_config * config;

	if (config_line) {}
	if (version) {}

	config = (struct ds_bits_check_config *)malloc(sizeof(struct ds_bits_check_config));
	config->is_attacked = 0;
	config->frame = NULL;

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
	char * ret = malloc(sizeof(char) * 100);
	strcpy(ret, "FromDS/ToDS bits Check plugin - Initialized.");

	return ret;
}

// Functions specific to this type of plugin

int static_frame_type()
{
	return ANALYZES_ALL_FRAMES; // ! data frame
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
	if (config) { }

	return (packet && packet->info && packet->info->frame_type != FRAME_TYPE_DATA);
}

int analyze(struct pcap_packet * packet, void * config)
{
	if (config) { }
	return ( (packet && packet->info) && (packet->info->toDS != 0 || packet->info->fromDS != 0) && packet->info->frame_type != FRAME_TYPE_DATA);
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
	struct ds_bits_check_config * dsbc_conf = NULL;
	if (config != NULL) {
		dsbc_conf = (struct ds_bits_check_config *) config;
		dsbc_conf->is_attacked = 0; // Not attacked by default
	}

	if (analyze(packet_list, config)) {

		if (dsbc_conf != NULL) {
			dsbc_conf->is_attacked = 1;

			dsbc_conf->sn = packet_list->info->sequence_number;
			dsbc_conf->type = packet_list->info->frame_type;
			dsbc_conf->subtype = packet_list->info->frame_subtype;
			dsbc_conf->frame = packet_list;
		}

		return 1;
	}

	return 0;
}

char * attack_details(void * config)
{
	struct ds_bits_check_config * dsbc_conf;
	if (!config) {
		return NULL;
	}
	dsbc_conf = (struct ds_bits_check_config *) config;
	char * ret = (char*)calloc(1, 200 * sizeof(char));
	if (dsbc_conf->is_attacked == 0) {
		strcpy(ret, "Do not call attack_details() if not attacked.");
		return ret;
	}

	sprintf(ret, "ANOMALY - ToDS and/or FromDS bit set in a control or management frame (SN <%u> - Type <%u> - Subtype <%u>). Only data frames can have FromDS and/or ToDS bit sets.",
				dsbc_conf->sn, dsbc_conf->type, dsbc_conf->subtype);

	return ret;
}


unsigned char ** get_attacker_macs(void * config, int * nb_mac, int * deauth)
{
	int nbmacs;
	unsigned char ** macs;
	struct ds_bits_check_config * dsbc_conf = NULL;
	if (config) {
		dsbc_conf = (struct ds_bits_check_config *) config;
	}



	// Add all 4 addresses
	macs = NULL;
	nbmacs = 0;
	if (dsbc_conf->frame && dsbc_conf->frame->info) {
		macs = (unsigned char **)malloc(sizeof(unsigned char *) * 4);
		// TODO: Check if the mac is not a special one (packet_analysis): broadcast, null, ipv4 multicast, etc
		//       packet_analysis will also take care of verifying if one of the mac is not a bssid we take care of

		COPY_MAC(dsbc_conf->frame->info->address1, macs, nbmacs)
		COPY_MAC(dsbc_conf->frame->info->address2, macs, nbmacs)
		COPY_MAC(dsbc_conf->frame->info->address3, macs, nbmacs)
		COPY_MAC(dsbc_conf->frame->info->address4, macs, nbmacs)

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
	struct ds_bits_check_config * dsbc_conf;

	if (config != NULL) {
		dsbc_conf = (struct ds_bits_check_config *) config;
		dsbc_conf->is_attacked = 0; // Not attacked by default
		//free_pcap_packet(&(dsbc_conf->frame), 0);
	}
}

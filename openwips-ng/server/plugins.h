/*
 * OpenWIPS-ng server.
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

#ifndef PLUGINS_H_
#define PLUGINS_H_

#include "common/pcap.h"
#include "common/version.h"

// Version of OpenWIPS-ng
#define OPENWIPS_NG_VERSION ((_MAJ * 1000) + (_MIN * 100) + (_SUB_MIN * 10))

// This thing avoid to call plugin fct all the time (save CPU cycles)
struct frame_plugin_settings {
	int static_frame_type;
	int static_frame_subtype;
	int need_all_frames;
	int is_single_frame_attack;
	int require_packet_parsed;
};

// Common plugin functions
struct plugin_common_functions {
	void * (*init_plugin)(char * config_line, int version); // Version can be useful (some changes in OpenWIPS-ng might require some different way of processing in the plugin)
	char * (*init_text)(void * config);
	void (*free_memory_and_unload)(void * data);
	char (*plugin_type)(void);
	int (*min_supported_version)();
	int (*max_supported_version)();
	//char * (*get_name)(); // Name of the plugin
};

// Frame plugins specific functions
struct frame_plugin_functions {
	int (*static_frame_type)();
	int (*static_frame_subtype)();
	int (*need_all_frames)(); // Does it need all frame to check for an attack
	int (*is_single_frame_attack)();
	int (*require_packet_parsed)();

	int (*can_use_frame)(struct pcap_packet *, void * config);
	int (*analyze)(struct pcap_packet *, void * config); // TODO: return struct attack_analysis { uint64_t attack_id; ... }

	// The following 2 can be combined to specify the amount of frame per sec
	int (*nb_frames_before_analyzing)(void * config);
	int (*time_ms_before_analyzing)(void * config);

	int (*is_attacked)(struct pcap_packet * packet_list, void * config);
	//int (*is_attack_done)(struct attack_analysis * analysis);
	char * (*attack_details)(void * config);
	unsigned char ** (*get_attacker_macs)(void * config, int * nb_mac, int * deauth); // Return the attacker macs (=> blacklist)
	void (*clear_attack)(void * config); // Cleanup any data stored about the attack by the plugin

	// TODO: Use id for attacks

	struct frame_plugin_settings settings;
	int potential_attack_in_progress;
	int nb_frames_before_analysis;
	int time_before_analysis;
	//int is_attack_logged;

	struct packet_list * frame_list;
	// TODO: Plugin should keep a list of packets if it needs to (and clear when needed)
	//       They MUST make a copy of the packet
};

// Plugin information
struct plugin_info {
	void *lib_handle;
	char * path;
	char * name;
	int loaded;
	char * config_line;
	void * plugin_data;

	char plugin_type; // Will be filled by plugin_type() function so that plugin_specific_fct can be casted to the struct depending on the type of plugin)

	struct plugin_common_functions common_fct;
	void * plugin_specific_fct;

	struct plugin_info * next;
} * _plugin_frame, *_plugin_database, *_plugin_logging, *_plugin_alert; // list of plugins


struct frame_plugin_functions * init_new_frame_plugin_functions();
struct plugin_info * init_new_plugin_info();

int free_plugin_info(struct plugin_info ** plugin);

int show_plugin_settings(struct plugin_info * ret);
struct plugin_info * load_plugin(char * name, char * path, char * config_line, int check);
int unload_plugin(struct plugin_info * plugin);

#endif /* PLUGINS_H_ */

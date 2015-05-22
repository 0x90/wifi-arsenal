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

#ifndef MAIN_H_
#define MAIN_H_

#define CONFIG_FILE_LOCATION "/usr/local/etc/openwips-ng/openwips-ng-server.conf"

// Local variables
volatile int _stop_threads;
char * _config_file_location, *_version;
int _deamonize;

// Local function
void help();
void free_global_memory();
void stop_threads();
void init();
int parse_args(int nbarg, char * argv[]);

// Free memory
extern void free_global_memory_config();
extern void free_global_memory_sensor();
extern void free_global_memory_rpcap_server();
extern void free_global_memory_packet_assembly();
extern void free_global_memory_packet_analysis();
extern void free_global_memory_message();
extern void free_global_memory_database();

// Initialization
extern void init_packet_assembly();
extern void init_sensor();
extern void init_packet_analysis();
extern void init_message_thread();
extern void init_database_thread();

// Threads
extern int start_sensor_socket();
extern int start_packet_assembly_thread();
extern int start_packet_analysis_thread();
extern int start_message_thread();
extern int start_database_thread();

#endif /* MAIN_H_ */

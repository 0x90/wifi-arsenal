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

#ifndef CONFIG_H_
#define CONFIG_H_

#include "users.h"
#include "common/config.h"
#include "database/common.h"

#define IS_TEXT_TRUE(text)	(strcasecmp((text), "y") == 0 || \
							strcasecmp((text), "yes") == 0 || \
							strcasecmp((text), "true") == 0 || \
							strcasecmp((text), "1") == 0)

extern int _rpcap_port_min, _rpcap_port_max; // rpcap_server.h
extern int rpcap_add_ports(int min, int max); // rpcap_server.c
extern void rpcap_init(); // rpcap_server.c
extern struct userpass * new_userpass(); // in user.c
extern int free_userpass(struct userpass ** ptr); // in user.c

extern int is_ip_valid(char * ip); // in common/sockets.c

int _disable_encryption; // Disable encryption between sensor and server?
int _port;
// struct userpass * _userlist, * _sensorlist; // See users.h
struct key_value * _config;

// Time a user is banned when it is part of an attack
int _ban_time_seconds;

// Force FCS check (enabled by default)
int _force_fcs_check;

// Mac addresses to protect
unsigned char ** _our_macs;
int _nb_macs;

// Database connection (defined in database/common.h)
//extern struct database_info _db_connection;

// TODO: Add function to return a specific set of keys and use it: struct key_value * get_keys(char * key_name)

int parse_plugins_config(); // Parse plugin options and load them
int read_conf_file(char * path); // Main function to read the config file
int parse_our_mac_addresses(); // Parse list of protected mac addreses
int parse_simple_options(); // Parse other simple options
int parse_all_userpass(const char * key, struct userpass ** upp); // Parse _config for users
void free_global_memory_config(); // Free memory allocated by config
void free_global_memory_config_userpass(struct userpass ** upp); // Free memory allocated for structures userpass

#endif /* CONFIG_H_ */

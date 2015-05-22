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

#ifndef RPCAP_SERVER_H_
#define RPCAP_SERVER_H_

#include "../common/pcap.h"
#include "../common/server.h"

#define MUTEX_NAME_RPCAP "rpcap"

pthread_mutex_t _mutex_port_req;
int _rpcap_port_min, _rpcap_port_max; // values <= 0 means any port can be used
int * _ports_used; // list of port used
int _nb_port_used;

//pthread_mutex_t _mutex_rpcap_server;
//struct server_params * _rpcap_servers;


void rpcap_init();
int rpcap_add_ports(int min, int max);
int rpcap_get_port();
void rpcap_free_port(int port);

struct server_params * rpcap_start_socket(int port);
void free_global_memory_rpcap_server();
int receive_pcap_file_header(unsigned char ** data, int * data_length, struct client_params * params);

extern int _stop_threads;

#endif /* RPCAP_SERVER_H_ */

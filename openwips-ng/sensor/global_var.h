/*
 * OpenWIPS-ng sensor.
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

#ifndef GLOBAL_VAR_H_
#define GLOBAL_VAR_H_
#include <netdb.h>
#include "common/config.h"

volatile int _stop_threads;



struct client_params * _rpcap_client_params;
struct server_params * _rpcap_server_params;

unsigned int _protocol_version;

char * _mon_iface;
char * _login, * _pass;
char * _host; // TODO: Temporary until migration to new system
int _clientSocket;
struct sockaddr_in _serv_addr;
struct hostent *_server;
pthread_t _server_connection_thread;
pthread_t _pcap_thread;

struct packet_list * _received_packet_list;
struct packet_list * _to_send_packet_list;

struct pcap_file_header * _pcap_header;
struct key_value * _config; // Unused yet

void init_global_var();

#endif /* GLOBAL_VAR_H_ */

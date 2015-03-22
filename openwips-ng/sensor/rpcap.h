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

#ifndef RPCAP_SENSOR_H_
#define RPCAP_SENSOR_H_
#include "common/server.h"
#include "structures.h"

extern int handle_rpcap_data(unsigned char ** data, int * data_length, struct client_params * params); // in common/rpcap.c
extern int send_rpcap_data(unsigned char ** data, int * data_length, struct client_params * params); // in common/rpcap.c
extern int start_monitor_thread(struct client_params * params);// in packet_capture.c


void global_memory_free_rpcap();
int start_rpcap(struct rpcap_link * link_info);
int send_pcap_file_header_upon_connection(unsigned char ** data, int * data_length, struct client_params * params);

#endif /* RPCAP_SENSOR_H_ */

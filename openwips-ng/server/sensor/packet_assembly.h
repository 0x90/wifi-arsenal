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

#ifndef PACKET_ASSEMBLY_H_
#define PACKET_ASSEMBLY_H_
#include <pthread.h>
#include "../common/pcap.h"

extern int _stop_threads;
extern struct server_params * _sensor_server_params;
extern int _force_fcs_check; // in config.h

pthread_t _packet_assembly_thread;

volatile int _stop_packet_assembly_thread;
volatile int _packet_assembly_thread_stopped;

struct packet_list * _receive_packet_list;
struct packet_list * _to_send_packet_list;

void init_packet_assembly();
void free_global_memory_packet_assembly();

int kill_packet_assembly_thread();

int start_packet_assembly_thread();
int packet_assembly_thread(void * data);

#endif /* PACKET_ASSEMBLY_H_ */

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

#ifndef PACKET_CAPTURE_H_
#define PACKET_CAPTURE_H_

#include "common/server-client.h"
//#include "common/pcap.h"

#define DUMP_FILENAME "openwips-ng_sensor.pcap"

int is_valid_iface(const char * dev);
int inject(pcap_t * handle, const void * packet, size_t size);
int start_monitor_thread(struct client_params * params);
int monitor(void * data);

void global_memory_free_packet_capture();
void init_packet_capture();

#ifdef __CYGWIN__

#endif /* __CYGWIN__ */

#endif /* PACKET_CAPTURE_H_ */

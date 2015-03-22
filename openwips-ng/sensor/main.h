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

#ifndef MAIN_H_
#define MAIN_H_

void init();
void help();
void stop_threads();
void free_memory();
void parse_args(int argc, char * argv[]);

extern int connect_to_server_old(int argc, char * argv[]); // in client.c
//extern int is_valid_iface(const char * dev); // in packet_capture.c
extern int monitor(const char * dev); // in packet_capture.c

extern void global_memory_free_rpcap(); // rpcap.c

#endif /* MAIN_H_ */

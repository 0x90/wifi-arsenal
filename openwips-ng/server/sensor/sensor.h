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

#ifndef SENSOR_H_
#define SENSOR_H_

#include "../users.h"
#include "../common/server.h"

#define MUTEX_NAME_SENSORS "sensor"

extern int _disable_encryption; // config.h
extern int _port; // declared in config.h
extern int _stop_threads; // main.h

extern char * parse_command(char * command, struct client_params * cp); // command_parse.c
extern char * get_command(char * ringbuffer, int * ringbuffer_len); // command_parse.c
extern char * get_login(char * command); // command_parse.c


struct server_params * _sensor_server_params;

void init_sensor();
int start_sensor_socket(); // Start server socket thread
int handle_sensor_data(unsigned char ** data, int * data_length, struct client_params * params);
void free_global_memory_sensor(); // Free all memory allocated by 'sensor'



#endif /* SENSOR_H_ */

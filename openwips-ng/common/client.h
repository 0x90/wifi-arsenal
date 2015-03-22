/*
 * OpenWIPS-ng - common stuff.
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

#ifndef COMMON_CLIENT_H_
#define COMMON_CLIENT_H_

#include "server-client.h"

#define TIME_BEFORE_RECONNECT_SEC 10

int connect_to_server(struct client_params * params, int * stop_threads);
int recreate_socket();
int client_connect_thread(void * data);


int * _client_global_stop_thread;

extern int client_socket_handling_thread(void * object);

#endif /* COMMON_CLIENT_H_ */

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

#ifndef COMMON_SERVER_H_
#define COMMON_SERVER_H_

#include <pthread.h>
#include "sockets.h"
#include "defines.h"
#include "server-client.h"

#define GLOBAL_STOP_THREAD (_server_stop_threads != NULL && *_server_stop_threads)

int dead_client_thread_cleanup(struct client_params ** ptr);

int create_server_listening(struct server_params * params, int * stop_threads);
int create_server_listening_thread(void * data);
extern int client_socket_handling_thread(void * object); // in server-client.c

int * _server_stop_threads;

#endif /* COMMON_SERVER_H_ */

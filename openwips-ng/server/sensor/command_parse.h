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

#ifndef COMMAND_PARSE_H_
#define COMMAND_PARSE_H_

#include "../users.h"
#include "../common/server.h" // struct client_params

extern int rpcap_get_port(); // in rpcap_server.c
extern void rpcap_free_port(int port); // in rpcap_server.c
extern struct server_params * rpcap_start_socket(int port); // in rpcap_server.c

char * parse_command(char * command, struct client_params * cp);
char * get_command(char * ringbuffer, int * ringbuffer_len);

#endif /* COMMAND_PARSE_H_ */

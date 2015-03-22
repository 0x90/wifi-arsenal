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

#ifndef COMMON_SOCKETS_H_
#define COMMON_SOCKETS_H_

#include <netdb.h>

#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif

#define CLOSE_SOCKET(s) if (s != INVALID_SOCKET) close(s);(s) = INVALID_SOCKET
#define SOCKET_MAX_PACKET_SIZE (1536 - 66)

int is_ip_valid(char * ip);
inline void close_socket(int * sock);
int accept_connection(int listen_socket);
int is_data_to_read(int sock);
inline int receive_data(int sock, void * buffer, size_t buffer_size);
inline int send_data(int sock, void * buffer, size_t buffer_size);
int send_all_data(int sock, void * buffer, size_t buffer_size, int use_select);
int get_listening_socket(int port, int single_connection);
int set_socket_options(int socket);
inline int create_socket();
char * get_sock_addr(int sock);
inline struct hostent * get_host_by_name(char * name);
inline int socket_connect(int sock, struct sockaddr_in * serv_addr);
int can_send_to_socket(int sock);

#endif /* COMMON_SOCKETS_H_ */

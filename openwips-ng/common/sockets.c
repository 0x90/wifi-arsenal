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
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <strings.h>
#include <unistd.h>
#include "sockets.h"

int is_ip_valid(char * ip)
{
	int success = EXIT_SUCCESS;
	void * temp = calloc(1, 256);

	// Check if it's a valid IP
	if (inet_pton(AF_INET, ip, temp) == 0) {
		// Try IPv6
		if (inet_pton(AF_INET6, ip, temp) == 0) {
			success = EXIT_FAILURE;
		}
	}

	free(temp);

	return success;
}

inline int socket_connect(int sock, struct sockaddr_in * serv_addr)
{
	return connect(sock, (struct sockaddr *) serv_addr, sizeof(struct sockaddr_in));
}

inline struct hostent * get_host_by_name(char * name)
{
	return gethostbyname(name);
}

inline int create_socket()
{
	return socket(AF_INET, SOCK_STREAM, 0);
}

inline void close_socket(int * sock)
{
	if (sock != NULL) {
		CLOSE_SOCKET(*sock);
	}
}

int accept_connection(int listen_socket)
{
	struct sockaddr_in cli_addr;
	socklen_t clilen = sizeof(cli_addr);

	if (listen_socket == INVALID_SOCKET) {
		return INVALID_SOCKET;
	}

	return accept(listen_socket,
			(struct sockaddr *) &cli_addr,
			&clilen);
}

int is_data_to_read(int sock)
{
	fd_set fs;
	struct timeval nowait;

	if (sock == INVALID_SOCKET) {
		return 0;
	}

	nowait.tv_sec = 0;
	nowait.tv_usec = 0;

	FD_ZERO(&fs);
	FD_SET(sock, &fs);

	return select(sock + 1, &fs, NULL, NULL, &nowait) == 1;
}

inline int receive_data(int sock, void * buffer, size_t buffer_size)
{
	return recv(sock, buffer, buffer_size, 0);
}

inline int send_data(int sock, void * buffer, size_t buffer_size)
{
	return send(sock, buffer, buffer_size, 0);
}

int send_all_data(int sock, void * buffer, size_t buffer_size, int use_select)
{
	size_t pos = 0;
	int sel, packet_size, data_sent = 0;

	while (pos < buffer_size) {
		if (use_select) {
			sel = can_send_to_socket(sock);
			if (sel < 0) {
				return -1;
			}
			if (sel == 0) {
			usleep(500);
			continue;
			}
		}

		// Send data
		packet_size = buffer_size - pos;
		data_sent = send_data(sock, buffer + pos,
				(packet_size < SOCKET_MAX_PACKET_SIZE) ?
					packet_size : SOCKET_MAX_PACKET_SIZE);

		if (data_sent == -1) {
			return -1;
		}
		pos += data_sent;
	}

	return buffer_size;
}

int get_listening_socket(int port, int single_connection)
{
	struct sockaddr_in serv_addr;

	if (port < 1 || port > 65535) {
		return INVALID_SOCKET;
	}

	int listen_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_socket < 0) {
		fprintf(stderr, "ERROR opening socket.\n");
		return INVALID_SOCKET;
	}

	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(port);

	if (bind(listen_socket, (struct sockaddr *) &serv_addr,
			sizeof(serv_addr)) < 0) {
		fprintf(stderr, "ERROR on binding (port %d).\n", port);
		CLOSE_SOCKET(listen_socket);
		return INVALID_SOCKET;
	}
	if (listen(listen_socket, (single_connection) ? 1 : 5) == -1) {
		fprintf(stderr, "ERROR on listening (port %d).\n", port);
		CLOSE_SOCKET(listen_socket);
		return INVALID_SOCKET;
	}

	return listen_socket;
}

int set_socket_options(int socket)
{
	// Set Keep-alive (see http://tldp.org/HOWTO/html_single/TCP-Keepalive-HOWTO/ )
	int temp, keep_alive = 1;
	temp = setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, &keep_alive, sizeof(keep_alive));
	if (temp < 0) {
		fprintf(stderr, "Failed setting setsockopt() for new client. Not fatal.\n");
	}
#ifdef DEBUG
	else {
		fprintf(stderr, "Successfully set socket options for socket <%d>.\n", socket);
	}
#endif
	// See also the following SOL_TCP options: TCP_KEEPCNT, TCP_KEEPIDLE and TCP_KEEPINTVL

	if (temp < 0) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

char * get_sock_addr(int sock)
{
	struct sockaddr_in m_addr;
	socklen_t sock_len = sizeof m_addr;

	if (sock == -1) {
		return NULL;
	}

	if (getpeername(sock, (struct sockaddr*)&m_addr, &sock_len) == 0) {
		return inet_ntoa(m_addr.sin_addr);
	}

	return NULL;
}

int can_send_to_socket(int sock)
{
	fd_set fs;
	struct timeval nowait;

	if (sock == INVALID_SOCKET) {
		return 0;
	}

	nowait.tv_sec = 0;
	nowait.tv_usec = 0;

	FD_ZERO(&fs);
	FD_SET(sock, &fs);

	return select(sock + 1, NULL, &fs, NULL, &nowait) == 1;
}

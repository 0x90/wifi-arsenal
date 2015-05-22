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

#ifndef COMMON_SERVER_CLIENT_H_
#define COMMON_SERVER_CLIENT_H_
#include <netinet/in.h>
#include "pcap.h"

#define THREAD_TYPE_NOT_SET	0
#define THREAD_TYPE_SENSOR	1
#define THREAD_TYPE_RPCAP	2
#define THREAD_TYPE_USER	3

#define GET_DEVICE_TYPE_STRING(tt)	((tt) == THREAD_TYPE_NOT_SET) ? "Not set" : \
										((tt) == THREAD_TYPE_SENSOR) ? "Sensor" : \
												((tt) == THREAD_TYPE_RPCAP) ? "RPCAP" : \
														((tt) == THREAD_TYPE_USER) ? "User" : "Undefined"

struct client_socket_params {
	struct hostent * hostent;
	struct sockaddr_in serv_addr;
	char * host;
	uint16_t port;
	char * login, * pass;
	unsigned int protocol_version;
	int auto_reconnect; // Auto-reconnect when disconnected (or if connection fails)
};

struct client_params
{
	struct socket_thread * client;
	struct server_params * rpcap_server; // For the remote pcap (if used)
	struct client_params * rpcap_client;
	char * last_command; // TODO: Implement last command
	int state; // State of the client connection

	int modify_thread_status; // is client_socket_handling_thread allowed to modify thread status?

	struct packet_list * received_packets; // Packets received on the socket
	struct packet_list * to_send_packets; // Packets to send on the socket

	struct client_params * next;
};

struct socket_thread
{
	pthread_mutex_t mutex;
	pthread_t thread;
	int sock;
	int connected;
	char * IP;
	int is_thread_running;
	int is_thread_starting;
	int (*handle_client_data) (unsigned char ** data, int * data_length, struct client_params * client); // Handle data reception
	int (*send_client_data) (unsigned char ** data, int * data_length, struct client_params * params); // Send data
	int (*upon_connection) (unsigned char ** data, int * data_length, struct client_params * params); // Called when a connection is established
	int (*upon_connection_receive) (unsigned char ** data, int * data_length, struct client_params * params); // Called when a connection is established and receive data
	struct userpass ** userlist; // pointer to the list of users (if any)
	struct userpass * user;
	int stop_thread; // Do the thread have to be stopped?
	int thread_type; // For debug information only
	int encrypt; // Encrypt data? By default, yes
	int allow_multiple_login; // Allow multiple identical logins? Default: No

	// Custom data and a function to clean up that data
	void * custom_data;
	unsigned long int custom_data_length;
	void (*cleanup_custom_data) (void*, unsigned long int); // Pointer to the data and length
};

#define UPON_CONNECTION_RECEIVE_SUCCESS			1
#define UPON_CONNECTION_RECEIVE_FAILURE			0
#define UPON_CONNECTION_RECEIVE_NOT_ENOUGH_DATA	-1

struct server_params
{
	struct client_params * client_list;
	struct socket_thread * server;
	int single_connection; // 0 to allow an unlimited number of clients, 1 to allow a single one
	int port;
	char * identifier;

	struct server_params * next;
};

// Constructors
struct socket_thread * init_new_socket_thread();
struct server_params * init_new_server_params();
struct client_params * init_new_client_params();
struct client_socket_params * init_new_client_socket_params();

// Destructors
int free_socket_thread(struct socket_thread ** ptr);
int free_server_params(struct server_params ** ptr);
int free_client_params(struct client_params ** ptr);
int free_client_socket_params(struct client_socket_params ** params);

int kill_server(struct server_params * server, int wait);
int kill_client(struct client_params * client, int wait);

int client_socket_handling_thread(void * object);

void cleanup_custom_data_client_socket_params(void * client_socket_params_struct, unsigned long int length);
int remove_bytes_from_buffer(unsigned char ** data, int * data_length, int nb_bytes_to_remove, int memset0);

#endif /* COMMON_SERVER_CLIENT_H_ */

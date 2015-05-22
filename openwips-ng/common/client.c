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
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <pthread.h>
#include "sockets.h"
#include "client.h"
#include "defines.h"

int client_connect_thread(void * data)
{
	// Buffer
#define BUFFER_LENGTH 256
#define RING_BUFFER_LENGTH 4096

// Don't forget to recreate the socket before calling connect (just the socket; the structures are still OK)
#define CLOSESOCKET() close_socket(&_clientSocket);\
					disconnected = 1;\
					params->client->connected = 0;\
					err_send = 0;\
					socket_param->protocol_version = 0; = 0;\
					fprintf(stderr, "Disconnected from server\n")

	struct client_params * params;
	struct client_socket_params * socket_param;

	// Socket stuff
	int err_send, disconnected, connect_err_shown;

	// Initialize
	err_send = disconnected = connect_err_shown = 0;

	if (err_send) { }

	params = (struct client_params *)data;
	socket_param = (struct client_socket_params *)params->client->custom_data;
	params->modify_thread_status = 0; // Do not allow function to handle socket communication to modify thread status

	pthread_mutex_lock(&(params->client->mutex));
	params->client->is_thread_running = 1;
	params->client->is_thread_starting = 0;
	pthread_mutex_unlock(&(params->client->mutex));

	// Connection loop
	while (!params->client->stop_thread) {
		if (params->client->connected == 0) {

			if (disconnected) {
				fprintf(stderr, "[*] Trying to reconnect\n");
				connect_err_shown = 1;
				disconnected = 0;

				// Stop connection if no auto reconnect
				if (!socket_param->auto_reconnect) {
					break;
				}

				// Since it has been disconnected, recreate the socket
				params->client->sock = recreate_socket();

				// Wait 10s before reconnecting
#ifdef DEBUG
				fprintf(stderr, "[*] Sleeping %d seconds before reconnecting.\n", TIME_BEFORE_RECONNECT_SEC);
#endif
				sleep(TIME_BEFORE_RECONNECT_SEC);
			}

			if (socket_connect(params->client->sock,&(socket_param->serv_addr)) < 0) {

				if (!connect_err_shown) {
					fprintf(stderr,"ERROR connecting to <%s:%u>.\n", socket_param->host, socket_param->port);
					connect_err_shown = 1;
				}

				// Stop connection if no auto reconnect
				if (!socket_param->auto_reconnect) {
					break;
				}

				// Sleep a little bit to avoid overloading the CPU if it keeps err.
				sleep(TIME_BEFORE_RECONNECT_SEC);

				continue;

			} else {
				// Reset error shown
				connect_err_shown = 0;

				// Connected
				params->client->connected = 1;

				// Set socket options
				if (set_socket_options(params->client->sock) < 0) {
					perror("setsockopt()");
				}

				fprintf(stderr, "[*] Connected to <%s:%u>.\n", socket_param->host, socket_param->port);
			}
		}

		// Call the other function to handle the connection
		client_socket_handling_thread(params);
		params->client->connected = 0;
	}

	// End
	pthread_mutex_lock(&(params->client->mutex));
	params->client->is_thread_running = 0;
	pthread_mutex_unlock(&(params->client->mutex));

	return EXIT_SUCCESS;

#undef BUFFER_LENGTH
#undef RING_BUFFER_LENGTH
#undef CLOSESOCKET
}

int recreate_socket()
{
	int sock = create_socket();

	if (sock < 0) {
		perror("ERROR creating socket");
		exit(EXIT_FAILURE);
	}

	return sock;
}

int connect_to_server(struct client_params * params, int * stop_threads)
{
	int thread_created;
	struct client_socket_params * socket_params;

	if (params == NULL) {
		return EXIT_FAILURE;
	}

	// Pointer to the value to stop all threads
	_client_global_stop_thread = stop_threads;

	// Create socket
	params->client->sock = recreate_socket();
	socket_params = (struct client_socket_params *)params->client->custom_data;

	// Resolve hostname
	fprintf(stderr, "[*] Trying to connect to %s:%u\n", socket_params->host, socket_params->port);
	socket_params->hostent = get_host_by_name(socket_params->host);

	if (socket_params->hostent == NULL) {
		fprintf(stderr,"ERROR, no such host\n");
		close_socket(&params->client->sock);
		free_client_params(&params); // it cleans up the struct too
		return EXIT_FAILURE;
	}

	// Init structures
	bzero((char *) &(socket_params->serv_addr), sizeof(socket_params->serv_addr));
	socket_params->serv_addr.sin_family = AF_INET;
	bcopy((char *)(socket_params->hostent)->h_addr,
		(char *)&(socket_params->serv_addr).sin_addr.s_addr,
		socket_params->hostent->h_length);
	socket_params->serv_addr.sin_port = htons(socket_params->port);

	// Create thread to connect to it
	thread_created = pthread_create(&(params->client->thread), NULL, (void*)&client_connect_thread, params);
	if (thread_created != 0) {
		fprintf(stderr, "[*] Failed to create connection thread.\n");
		close_socket(&params->client->sock);
		free_client_params(&params); // it cleans up the struct too
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

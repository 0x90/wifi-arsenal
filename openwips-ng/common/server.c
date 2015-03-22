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
#include <unistd.h>
#include <string.h> // strlen
#include "server.h"

int create_server_listening(struct server_params * params, int * stop_threads)
{
	// Create a server listening thread and handle the connection and communication
	// In the case of the server, it will call itself to manage rpcap connections
	int thread_created;

	if (!params || params->port < 1 || params->port > 65535) {
		return EXIT_FAILURE;
	}

	// Pointer to the value to stop the threads
	_server_stop_threads = stop_threads;

	params->server->sock = get_listening_socket(params->port, params->single_connection);

	// Failure, so exit
	if (params->server->sock == INVALID_SOCKET) {
		return EXIT_FAILURE;
	}

	// Create server socket thread
	thread_created = pthread_create(&(params->server->thread), NULL, (void*)&create_server_listening_thread, params);
	if (thread_created != 0) {
		fprintf(stderr,"ERROR, failed to create listening thread (port %d).\n", params->port);
		close_socket(&(params->server->sock));

		return EXIT_FAILURE;
	}

#ifdef DEBUG
	printf("Successfully created <%s> thread.\n", GET_DEVICE_TYPE_STRING(params->server->thread_type));
#endif

	return EXIT_SUCCESS;
}

int create_server_listening_thread(void * data)
{
	int newsockfd, thread_created;
	struct client_params * cp, *current;
	struct server_params *params = (struct server_params *)data;

	params->server->is_thread_running = 1;
	params->server->is_thread_starting = 0;

	while(!GLOBAL_STOP_THREAD && !params->server->stop_thread) {

		if (is_data_to_read(params->server->sock) != 1) {
			usleep(10000);
			continue;
		}
		// else: there's something to accept


		newsockfd = accept_connection(params->server->sock) ;
		if (newsockfd < 0) {
			fprintf(stderr, "ERROR on accept");
			usleep(10000);
			continue;
		}

		// Kill that connection if it allows a single connection
		if (params->single_connection && params->client_list != NULL &&
				((!(params->client_list->client->is_thread_starting) && !(params->client_list->client->is_thread_running)) ||
				params->client_list->client->connected) ) {
			close_socket(&newsockfd);
			continue;
		}

		printf("[*] New client <socket %d> connected: %s.\n", newsockfd, get_sock_addr(newsockfd));

		// Set Socket options (keep alive, etc)
		set_socket_options(newsockfd);

		cp = init_new_client_params();
		cp->client->sock = newsockfd;
		cp->client->connected = 1;
		cp->client->upon_connection = params->server->upon_connection;
		cp->client->upon_connection_receive = params->server->upon_connection_receive;
		cp->client->handle_client_data = params->server->handle_client_data;
		cp->client->send_client_data = params->server->send_client_data;
		cp->client->stop_thread = params->server->stop_thread;
		cp->client->thread_type = params->server->thread_type;
		cp->client->userlist = params->server->userlist;
		cp->client->encrypt = params->server->encrypt;
		cp->client->IP = get_sock_addr(cp->client->sock); // Do not free. TODO: Check when memleak is fixed again
		cp->client->allow_multiple_login = params->server->allow_multiple_login;

		// Add to the list
		if (params->client_list == NULL) {
			params->client_list = cp;
		} else {
			current = params->client_list;
			while (current->next != NULL) {
				current = current->next;
			}
			current->next = cp;
		}

		// Create thread
		cp->client->is_thread_starting = 1;

		thread_created = pthread_create(&(cp->client->thread),
										NULL,
										(void*)&client_socket_handling_thread,
										cp);
		if (thread_created != 0) {
			fprintf(stderr,"ERROR, failed to create new <%s> handling thread\n", GET_DEVICE_TYPE_STRING(params->server->thread_type));
			cp->client->is_thread_starting = 0; // Make sure it's going to be cleaned up
		}

		// Cleanup dead threads
		dead_client_thread_cleanup(&(params->client_list));
	}

	// Stop client threads
	if (params->server->stop_thread && params->client_list != NULL)
	{
		for (current = params->client_list; current != NULL; current = current->next) {
			current->client->stop_thread = 1;
		}
	}

	// Close socket
	close_socket(&(params->server->sock));

	// TODO: Cleanup memory?

	params->server->is_thread_running = 0;

	return EXIT_SUCCESS;
}

int dead_client_thread_cleanup(struct client_params ** start)
{
	int is_dead;
	struct client_params *cur, *prev, *next;

	if (start == NULL || *start == NULL) {
		return EXIT_FAILURE;
	}

	prev = NULL;
	cur = *start;

	while (cur != NULL) {
		next = cur->next;
		is_dead = 0;

		pthread_mutex_lock(&(cur->client->mutex));
		is_dead = !(cur->client->is_thread_starting) && !(cur->client->is_thread_running);
		pthread_mutex_unlock(&(cur->client->mutex));

		if (is_dead) {

			// Make sure to kill RPCAP server before freeing memory.
			if (cur->rpcap_server) {
				kill_server(cur->rpcap_server, 1);
			}

			// Kill RPCAP_Client
			if (cur->rpcap_client) {
				kill_client(cur->rpcap_client, 1);
			}

			// Thread is dead, remove it
			free_client_params(&cur);
			if (prev == NULL) {
				*start = next;
			} else {
				prev->next = next;
			}

			cur = prev;
		}
		if (cur) {
			prev = cur;
			cur = cur->next;
		}
	}

	return EXIT_SUCCESS;
}

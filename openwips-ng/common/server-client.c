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
#include <unistd.h>
#include "server-client.h"
#include "server.h"

// TODO: Use that function in all situations (and avoid manual stuff)
int remove_bytes_from_buffer(unsigned char ** data, int * data_length, int nb_bytes_to_remove, int memset0)
{
	int new_len;
	if (data == NULL || *data == NULL || data_length == NULL || *data_length <= 0 || *data_length < nb_bytes_to_remove) {
		return EXIT_FAILURE;
	}

	new_len = (*data_length) - nb_bytes_to_remove;

	if (new_len) {
		memmove(* data, (*data) + nb_bytes_to_remove, new_len);
	}

	if (memset0) {
		memset((*data) + new_len, 0, nb_bytes_to_remove);
	}

	*data_length = new_len;

	return EXIT_SUCCESS;
}

int client_socket_handling_thread(void * object)
{
#define BUFFER_LENGTH 2048
#define RING_BUFFER_LENGTH 8192

	unsigned char * to_send;
	unsigned char * buffer;
	unsigned char * ringbuffer;
	int data_length, readsockets, ring_buffer_len, ret, to_send_data_length, receive_first_time;
#ifdef DEBUG
	FILE * f;
#endif

	struct client_params * params = (struct client_params *)object;
	if (params->modify_thread_status) {
		pthread_mutex_lock(&(params->client->mutex));
		params->client->is_thread_running = 1;
		params->client->is_thread_starting = 0;
		pthread_mutex_unlock(&(params->client->mutex));
	}
	// TODO: Make the communications encrypted (even if localhost)

	buffer = (unsigned char *)calloc(1, BUFFER_LENGTH * sizeof(unsigned char));
	ringbuffer = (unsigned char *)calloc(1, RING_BUFFER_LENGTH * sizeof(unsigned char));
	data_length = -1;
	ring_buffer_len = 0;
	ret = EXIT_SUCCESS;
	to_send = NULL;
	to_send_data_length = 0;
	receive_first_time = 1;

#ifdef DEBUG
	f = fopen("received.pcap", "r");
	if (f == NULL) {
		createPcapFile("received.pcap", 127 /*DLT_IEEE802_11_RADIO*/);
	} else {
		fclose(f);
	}
#endif

	// Send data since we just got connected
	if (/*!GLOBAL_STOP_THREAD && */ params->client->connected && !params->client->stop_thread
			&& params->client->upon_connection) {
		(*(params->client->upon_connection))(NULL, NULL, params);
	}

	// TODO: !GLOBAL_STOP_THREAD
	while (/*!GLOBAL_STOP_THREAD && */ params->client->connected && !params->client->stop_thread) {
		// Check if there's any data to read
		readsockets = is_data_to_read(params->client->sock);

		if (readsockets < 0) { 	// Error: disconnect

			ret = EXIT_FAILURE;
			break;
		}

		// Check if we can send data (must check if the function exist first so that we save some CPU cycles)
		if (params->client->send_client_data && can_send_to_socket(params->client->sock)) {
			(*(params->client->send_client_data))(&to_send, &to_send_data_length, params);

			if (to_send) {
				if (send_all_data(params->client->sock, to_send, to_send_data_length, 0) < 0 ) {
					ret = EXIT_FAILURE;
					FREE_AND_NULLIFY(to_send);
					break;
				}

				to_send_data_length = 0;
				FREE_AND_NULLIFY(to_send);
			}
		}

		if (readsockets == 0) { // Nothing to read
			// Sleep a little bit to avoid overloading the CPU.
			usleep(200);
			continue;
		}

		// Read data
		data_length = receive_data(params->client->sock, buffer, BUFFER_LENGTH);
		if (data_length <= 0) {

			if (data_length == -1) { // Error
				ret = EXIT_FAILURE;
			}

			//return EXIT_SUCCESS; // Disconnection
			break;
		}

#ifdef EXTRA_DEBUG
		printf("[*] Socket %d - received length: %d\n", params->client->sock, data_length);
#endif
		// Put data at the back of the ring buffer
		if (ring_buffer_len + data_length > RING_BUFFER_LENGTH) {
			fprintf(stderr, "[*] Data left unprocessed in the ring buffer, dumping %d bytes to accommodate new data arrived.\n",
					ring_buffer_len + data_length - RING_BUFFER_LENGTH);
			remove_bytes_from_buffer(&ringbuffer, &ring_buffer_len, ring_buffer_len + data_length - RING_BUFFER_LENGTH, 0);
		}
		memcpy(ringbuffer + ring_buffer_len, buffer, data_length);
		ring_buffer_len += data_length;

#ifdef EXTRA_DEBUG
		printf("[*] Socket %d - ring buffer length: %d\n", params->client->sock, ring_buffer_len);
#endif

		// Reset memory
		memset(buffer, 0, data_length);


		// Handle data received (for the first time
		if (receive_first_time) {
			if (params->client && params->client->upon_connection_receive) {
				if (ring_buffer_len > 0) {
					switch ((*(params->client->upon_connection_receive))(&ringbuffer, &ring_buffer_len, params)) {
						case UPON_CONNECTION_RECEIVE_SUCCESS:
							receive_first_time = 0; // Great, we've got what we need, we can continue
							break;

						case UPON_CONNECTION_RECEIVE_NOT_ENOUGH_DATA:
							continue; // Go again in the loop to check for data
							break;

						case UPON_CONNECTION_RECEIVE_FAILURE: // Disconnect
							fprintf(stderr, "Client data handler for <%p> returned failure (receiving data for the first time).\n", params);
							close_socket(&(params->client->sock));
							params->client->connected = 0;
							ring_buffer_len = 0;
							break;

						default:
							break;
					}
				}
			} else {
				receive_first_time = 0;
			}
		}

		// Handle data received
		if (ring_buffer_len > 0) {
			if (params->client->handle_client_data) {
				if ((*(params->client->handle_client_data))(&ringbuffer, &ring_buffer_len, params) == EXIT_FAILURE) {
					fprintf(stderr, "Client data handler for <%p> returned failure.\n", params);
				}
			} else {
				// dump everything since there's no function to handle that
#ifdef DEBUG
				fprintf(stderr, "Dumping %d bytes of data since there's no function to handle that.\n", ring_buffer_len);
#endif
				memset(ringbuffer, 0, ring_buffer_len);
				ring_buffer_len = 0;
			}
		}
	}

	fprintf(stderr, "[*] Client disconnected or disconnection forced - socket <%d>.\n", params->client->sock);

	// TODO: Check that these are correctly freed
	// Free local stuff (only)
	FREE_AND_NULLIFY(buffer);
	FREE_AND_NULLIFY(ringbuffer);

	// Reset socket so that the thread can be cleaned up.
	close_socket(&(params->client->sock));
	params->client->connected = 0;

	if (params->modify_thread_status) {
		// Thread is done
		pthread_mutex_lock(&(params->client->mutex));
		params->client->is_thread_running = 0;
		pthread_mutex_unlock(&(params->client->mutex));
	}

	return ret;
#undef BUFFER_LENGTH
#undef RING_BUFFER_LENGTH
}

int kill_client(struct client_params * client, int wait)
{
	if (client == NULL) {
		return EXIT_FAILURE;
	}

	client->client->stop_thread = 1;

	while (wait && client->client->is_thread_running) {
		usleep(500);
	}

	return EXIT_SUCCESS;
}

int kill_server(struct server_params * server, int wait)
{
	struct client_params * cur;

	if (server == NULL) {
		return EXIT_FAILURE;
	}

	// Stop server ...
	server->server->stop_thread = 1;

	if (wait) {
		// Stop server and wait for it to finish
		while (server->server->is_thread_running) {
			usleep(500);
		}
	}

	// ... then kill client threads (server will take care of its clients but we never know)
	for (cur = server->client_list; cur != NULL; cur = cur->next) {
		kill_client(cur, wait);
	}

	return EXIT_SUCCESS;
}


struct socket_thread * init_new_socket_thread()
{
	struct socket_thread * st = (struct socket_thread *)malloc(sizeof(struct socket_thread));

	st->allow_multiple_login = 0;
	st->IP = NULL;
	st->cleanup_custom_data = NULL;
	st->connected = 0;
	st->custom_data = NULL;
	st->custom_data_length = 0;
	st->encrypt = 1;
	st->handle_client_data = NULL;
	st->is_thread_running = 0;
	st->is_thread_starting = 0;
	pthread_mutex_init(&(st->mutex), NULL);
	st->send_client_data = NULL;
	st->sock = INVALID_SOCKET;
	st->stop_thread = 0;
	st->thread = PTHREAD_NULL;
	st->thread_type = THREAD_TYPE_NOT_SET;
	st->userlist = NULL;
	st->upon_connection = NULL;
	st->upon_connection_receive = NULL;
	st->user = NULL;

	return st;
}

struct server_params * init_new_server_params()
{
	struct server_params * param = (struct server_params *)malloc(sizeof(struct server_params));


	param->client_list = NULL;
	param->identifier = NULL;
	param->next = NULL;
	param->server = init_new_socket_thread();
	param->single_connection = 0;
	param->port = 0;

	return param;
}

struct client_params * init_new_client_params()
{
	struct client_params * param = (struct client_params *)malloc(sizeof(struct client_params));

	param->modify_thread_status = 1;
	param->client = init_new_socket_thread();
	param->last_command = NULL;
	param->next = NULL;
	param->rpcap_server = NULL;
	param->rpcap_client = NULL;
	param->state = -1;

	param->received_packets = init_new_packet_list();
	param->to_send_packets = init_new_packet_list();

	return param;
}

int free_socket_thread(struct socket_thread ** ptr)
{
	if (ptr == NULL || *ptr == NULL) {
		return EXIT_FAILURE;
	}

	if ((*ptr)->custom_data) {
		if ((*ptr)->cleanup_custom_data) {
			(*((*ptr)->cleanup_custom_data))((*ptr)->custom_data, (*ptr)->custom_data_length);
			(*ptr)->custom_data = NULL;
		} else {
			FREE_AND_NULLIFY((*ptr)->custom_data);
		}
	}

	if ((*ptr)->user) {
		// TODO: create function to cleanup that struct
	}

	pthread_mutex_destroy(&((*ptr)->mutex));

	/*
	// Looks like IP shouldn't be freed
	FREE_AND_NULLIFY((*ptr)->IP);
	*/

	FREE_AND_NULLIFY(*ptr);

	return EXIT_SUCCESS;
}

int free_server_params(struct server_params ** ptr)
{
	struct client_params * cur_client, * prev_client;
	if (ptr == NULL || *ptr == NULL) {
		return EXIT_FAILURE;
	}

	if ((*ptr)->client_list) {
		prev_client = NULL;
		cur_client = (*ptr)->client_list;
		while (cur_client != NULL) {
			prev_client = cur_client;
			cur_client = cur_client->next;
			free_client_params(&prev_client);
		}
	}

	if ((*ptr)->server) {
		free_socket_thread(&((*ptr)->server));
	}

	FREE_AND_NULLIFY((*ptr)->identifier);
	FREE_AND_NULLIFY(*ptr);

	return EXIT_SUCCESS;
}

int free_client_params(struct client_params ** ptr)
{
	struct server_params * cur_server, * prev_server;
	struct client_params * cur_client, * prev_client;

	if (ptr == NULL || *ptr == NULL) {
		return EXIT_FAILURE;
	}

	if ((*ptr)->client) {
		free_socket_thread(&((*ptr)->client));
	}

	FREE_AND_NULLIFY((*ptr)->last_command);

	if ((*ptr)->rpcap_server) {
		prev_server = NULL;
		cur_server = (*ptr)->rpcap_server;
		while (cur_server != NULL) {
			prev_server = cur_server;
			cur_server = cur_server->next;
			free_server_params(&prev_server);
		}
	}

	if ((*ptr)->rpcap_client) {
	prev_client = NULL;
		cur_client = (*ptr)->rpcap_client;
		while (cur_client != NULL) {
			prev_client = cur_client;
			cur_client = cur_client->next;
			free_client_params(&prev_client);
		}
	}

	if ((*ptr)->received_packets) {
		free_packet_list(&((*ptr)->received_packets));
	}
	if ((*ptr)->to_send_packets) {
		free_packet_list(&((*ptr)->to_send_packets));
	}

	FREE_AND_NULLIFY(*ptr);

	return EXIT_SUCCESS;
}

struct client_socket_params * init_new_client_socket_params()
{
	struct client_socket_params * ret = malloc(sizeof(struct client_socket_params));
	ret->login = NULL;
	ret->host = NULL;
	ret->pass = NULL;
	ret->protocol_version = 0;
	ret->port = 0;
	ret->hostent = NULL;
	ret->auto_reconnect = 1;

	return ret;
}

int free_client_socket_params(struct client_socket_params ** params)
{
	if (params == NULL || *params == NULL) {
		return EXIT_FAILURE;
	}
	//hostent shouldn't be freed


	FREE_AND_NULLIFY((*params)->login);
	FREE_AND_NULLIFY((*params)->host);
	FREE_AND_NULLIFY((*params)->pass);

	FREE_AND_NULLIFY(*params);

	return EXIT_SUCCESS;
}

void cleanup_custom_data_client_socket_params(void * client_socket_params_struct, unsigned long int length)
{
	struct client_socket_params * params = (struct client_socket_params *)client_socket_params_struct;
	free_client_socket_params(&params);
	if (length) {} // Don't complain about length not used
}

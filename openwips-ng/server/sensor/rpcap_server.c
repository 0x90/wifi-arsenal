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
#include <stdio.h>
#include <stdlib.h>
//#include <linux/futex.h>
//#include <sys/time.h>
#include <pthread.h>
#include <string.h>
#include "rpcap_server.h"
#include "../common/defines.h"
#include "../common/rpcap.h"

/*
Remote pcap is a custom one:
- can be encrypted with openssl and the key = sha1(password) so no need of login/pass
- regular pcap header (so that it can be written to file)
- might also include login/pass -> or not if a key can be used with openssl
*/

void rpcap_init()
{
	// Init ports stuff
	_ports_used = NULL;
	_nb_port_used = 0;
	_rpcap_port_min = _rpcap_port_max = -1;
	pthread_mutex_init(&_mutex_port_req, NULL);

	// Init server stuff
	//_rpcap_servers = NULL;
	//pthread_mutex_init(&_mutex_rpcap_server, NULL);

	//// TODO: Create thread to cleanup dead servers
}

// TODO: Fix range choice
int rpcap_get_port()
{
	int i;
	int ret = -1;
	pthread_mutex_lock(&_mutex_port_req); // Lock

	ret = _rpcap_port_min;
	do {
		for (i = 0; i <_nb_port_used; i++) {
			if (_ports_used[i] == ret) {
				++ret;
				break;
			}
		}
	} while (i != _nb_port_used);

	// Add port to list
	++_nb_port_used;
	if (_ports_used == NULL) {
		_ports_used = (int *)malloc(sizeof(int));
	} else {
		_ports_used = (int *)realloc(_ports_used, sizeof(int) * _nb_port_used);
	}

	_ports_used[_nb_port_used - 1] = ret;

	pthread_mutex_unlock(&_mutex_port_req); // Unlock
	return ret;
}

void rpcap_free_port(int port)
{
	int i;
	pthread_mutex_lock(&_mutex_port_req); // Lock

	for (i = 0; i <_nb_port_used; i++) {
		if (_ports_used[i] == port) {
			// Move the last one here and realloc
			--_nb_port_used;
			_ports_used[i] = _ports_used[_nb_port_used];
			_ports_used = (int *)realloc(_ports_used, sizeof(int) * _nb_port_used);
			break;
		}
	}

	pthread_mutex_unlock(&_mutex_port_req); // Unlock
}

int rpcap_add_ports(int min, int max)
{
	_rpcap_port_min = _rpcap_port_max = -1;

	if (min > max) {
		return EXIT_FAILURE;
	}

	if (min < 1 || max < 1) {
		return EXIT_FAILURE;
	}

	if (min > 65535 || max > 65535) {
		return EXIT_FAILURE;
	}

	_rpcap_port_min = min;
	_rpcap_port_max = max;

	return EXIT_SUCCESS;
}

struct server_params * rpcap_start_socket(int port)
{
	int success;
	struct server_params * rpcap_server_params = init_new_server_params();

	rpcap_server_params->port = port;
	rpcap_server_params->server->encrypt = 0;
	rpcap_server_params->single_connection = 1; // Only one connection
	rpcap_server_params->server->thread_type = THREAD_TYPE_RPCAP; // Pure information
	rpcap_server_params->server->handle_client_data = handle_rpcap_data;
	rpcap_server_params->server->send_client_data = send_rpcap_data;
	rpcap_server_params->server->upon_connection_receive = receive_pcap_file_header;
	rpcap_server_params->identifier = (char *)calloc(1, (strlen(MUTEX_NAME_RPCAP) + 5 + 1) * sizeof(char));
	sprintf(rpcap_server_params->identifier, "%s%d", MUTEX_NAME_RPCAP, port);

	success = create_server_listening(rpcap_server_params, &_stop_threads);

	if (success == EXIT_SUCCESS) {
		return rpcap_server_params;
	}

	return NULL;
}

void free_global_memory_rpcap_server()
{
	pthread_mutex_destroy(&_mutex_port_req);
	FREE_AND_NULLIFY(_ports_used);
}

int receive_pcap_file_header(unsigned char ** data, int * data_length, struct client_params * params)
{
	if (!data || !(*data) || !data_length || !params) {
		return UPON_CONNECTION_RECEIVE_FAILURE;
	}

#ifdef DEBUG
	fprintf(stderr, "Receiving pcap_file_headers.\n");
#endif

	// Check if there is enough data
	if (*data_length < sizeof(struct pcap_file_header)) {
		return UPON_CONNECTION_RECEIVE_NOT_ENOUGH_DATA;
	}

	// Get item and remove those bytes from the buffer
	params->received_packets->pcap_header = (struct pcap_file_header*)malloc(sizeof(struct pcap_file_header));
	memcpy(params->received_packets->pcap_header, *data, sizeof(struct pcap_file_header));
	remove_bytes_from_buffer(data, data_length, sizeof(struct pcap_file_header), 1);

#ifdef DEBUG
	fprintf(stderr, "Received pcap_file_headers successfully.\n");
	fprintf(stderr, "Link type: %u\n", params->received_packets->pcap_header->linktype);
#endif

	// Success
	return UPON_CONNECTION_RECEIVE_SUCCESS;
}

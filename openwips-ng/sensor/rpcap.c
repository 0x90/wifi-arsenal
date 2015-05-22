/*
 * OpenWIPS-ng sensor.
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h> //usleep
#include "rpcap.h"
#include "common/client.h"
#include "common/rpcap.h"
#include "structures.h"
#include "global_var.h"

void global_memory_free_rpcap()
{
	if (_rpcap_client_params) {
		free_client_params(&_rpcap_client_params);
	}

	if (_rpcap_server_params) {
		free_server_params(&_rpcap_server_params);
	}
}

int start_rpcap(struct rpcap_link * link_info)
{
	int ret;
	struct client_socket_params * socket_params;

	if (link_info == NULL) {
		return EXIT_FAILURE;
	}

	// Verify structure is valid
#define RETURN_FAILURE_IF_INVALID(value)	if ((value) == -1) return EXIT_FAILURE

	RETURN_FAILURE_IF_INVALID(link_info->encrypted);
	RETURN_FAILURE_IF_INVALID(link_info->compressed);
	RETURN_FAILURE_IF_INVALID(link_info->send_payload);
	RETURN_FAILURE_IF_INVALID(link_info->send_data_frames);
	RETURN_FAILURE_IF_INVALID(link_info->pasv);
#undef RETURN_FAILURE_IF_INVALID

	if (link_info->compressed) {
		fprintf(stderr, "[*] RPCAP: Compressed link not yet supported.\n");
		return EXIT_FAILURE;
	}

	if (link_info->encrypted) {
		fprintf(stderr, "[*] RPCAP: Encrypted link not yet supported.\n");
		return EXIT_FAILURE;
	}

	if (link_info->pasv) {
		fprintf(stderr, "[*] RPCAP: Passive link not yet supported.\n");
		return EXIT_FAILURE;
	}

	if (link_info->pasv == 0 && link_info->host == NULL) {
		fprintf(stderr, "[*] RPCAP: Host missing in active mode.\n");
		return EXIT_FAILURE;
	}

	if (link_info->pasv && link_info->port != -1) {
		fprintf(stderr, "[*] RPCAP: Ignoring port in passive mode.\n");
	}

	if (link_info->send_payload == 0) {
		if (link_info->send_data_frames == 0) {
			fprintf(stderr, "[*] RPCAP: Frames without payload (and no data frames) not supported yet.\n");
		} else {
			fprintf(stderr, "[*] RPCAP: Frames without payload not supported yet.\n");
		}
		return EXIT_FAILURE;
	}

	if (link_info->send_data_frames == 0) {
		fprintf(stderr, "[*] RPCAP: Everything except data frames not supported yet.\n");
		return EXIT_FAILURE;
	}

	_rpcap_client_params = init_new_client_params();
	_rpcap_client_params->modify_thread_status = 0;

	// Get server port
	if (!CHECK_SOCKET_PORT(link_info->port)) {
		fprintf(stderr, "[*] Invalid port: %d\n", link_info->port);
		return EXIT_FAILURE;
	}

	socket_params = init_new_client_socket_params();
	socket_params->host = (char *)calloc(1, (strlen(link_info->host) + 1) * sizeof(char));
	strcpy(socket_params->host, link_info->host);
	socket_params->port = (uint16_t)link_info->port;

	_rpcap_client_params->client->handle_client_data = handle_rpcap_data;
	_rpcap_client_params->client->send_client_data = send_rpcap_data;
	_rpcap_client_params->client->custom_data = (void*)socket_params;
	_rpcap_client_params->client->upon_connection = send_pcap_file_header_upon_connection;
	_rpcap_client_params->client->cleanup_custom_data = cleanup_custom_data_client_socket_params;

	ret = connect_to_server(_rpcap_client_params, (int*)&_stop_threads);
	if (ret == EXIT_SUCCESS) {
		ret = start_monitor_thread(_rpcap_client_params);
	}

	return ret;
}

int send_pcap_file_header_upon_connection(unsigned char ** data, int * data_length, struct client_params * params)
{
	unsigned char * buffer;

	if (params || data_length) {}

	if (params == NULL) {
		return EXIT_FAILURE;
	}

#ifdef DEBUG
	fprintf(stderr, "Sending pcap_file_header.\n");
#endif

	while (_pcap_header == NULL) {
		usleep(100);
	}

	buffer = (unsigned char *)malloc(sizeof(unsigned char) * sizeof(struct pcap_file_header));
	memcpy(buffer, _pcap_header, sizeof(struct pcap_file_header));

	if (send_all_data(params->client->sock, buffer, sizeof(struct pcap_file_header), 1) == sizeof(struct pcap_file_header)) {
#ifdef DEBUG
		fprintf(stderr, "pcap_file_header sent successfully.\n");
#endif
		return EXIT_SUCCESS;
	}

#ifdef DEBUG
	fprintf(stderr, "Failed to send pcap_file_header.\n");
#endif
	return EXIT_FAILURE;
}

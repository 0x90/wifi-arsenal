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
#include <string.h>
#include "sensor.h"
#include "state_machine.h"
#include "../common/defines.h"

void init_sensor()
{
	_sensor_server_params = NULL;
}

int start_sensor_socket()
{
	_sensor_server_params = init_new_server_params();

	_sensor_server_params->port = _port;
	_sensor_server_params->server->encrypt = !_disable_encryption;
	_sensor_server_params->server->thread_type = THREAD_TYPE_SENSOR; // Pure information
	_sensor_server_params->server->userlist = &_sensorlist;
	_sensor_server_params->server->handle_client_data = handle_sensor_data;
	_sensor_server_params->identifier = (char *)calloc(1, (strlen(MUTEX_NAME_SENSORS) + 1) * sizeof(char));
	strcpy(_sensor_server_params->identifier, MUTEX_NAME_SENSORS);

	return create_server_listening(_sensor_server_params, &_stop_threads);
}

int handle_sensor_data(unsigned char ** data, int * data_length, struct client_params * params)
{
	char * command, * answer;

#ifdef DEBUG
	fprintf(stderr, "handle_sensor_data(data -> <%s>, length -> %d, params -> %p)\n", *data, *data_length, params);
#endif

	if (params->client->user == NULL) {
		// TODO: Create constructor for that struct
		params->client->user = (struct userpass *)malloc(sizeof(struct userpass));
	}

	// while the ring buffer has command, parse them (and answer them)
	command = get_command((char*)(*data), data_length);
	while (command != NULL && params->state != STATE_LOGIN_FAILED) {

#ifdef DEBUG
		printf("[*] Socket %d - Parsing command: <%s>\n", params->client->sock, command);
#endif

		answer = parse_command(command, params);
		free(command);

		// Send the answer (if exist)
		if (answer != NULL) {

#ifdef DEBUG
			printf("[*] Socket %d - Sending response: <%s>\n", params->client->sock, answer);
#endif
			if (send_data(params->client->sock, answer, strlen(answer)) != strlen(answer)) {
				params->client->connected = 0;
				free(answer);
				return EXIT_FAILURE;
			}

			free(answer);
		}
#ifdef DEBUG
		else {
			fprintf(stderr, "[*] No answer to send.\n");
		}
#endif

		command = get_command((char*)(*data), data_length);
	}

	// Disconnect user if invalid login
	if (params->state == STATE_LOGIN_FAILED) {
		fprintf(stderr, "[*] Invalid login/password, disconnecting.\n");
		params->client->connected = 0; // It will be disconnected

		return EXIT_FAILURE;
	}


	return EXIT_SUCCESS;
}


void free_global_memory_sensor()
{
	free_server_params(&_sensor_server_params);
}

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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include "client.h"
#include "state_machine.h"
#include "common/defines.h"
#include "common/sockets.h"
#include "global_var.h"

int connect_thread(void * data)
{
	// Buffer
#define BUFFER_LENGTH 256
#define RING_BUFFER_LENGTH 4096

// Don't forget to recreate the socket before calling connect (just the socket; the structures are still OK)
#define CLOSESOCKET() close(_clientSocket);\
					disconnected = 1;\
					connected = 0;\
					memset(buffer, 0, BUFFER_LENGTH);\
					memset(ringbuffer, 0, RING_BUFFER_LENGTH);\
					data_length = -1;\
					err_send = 0;\
					state_machine = STATE_NOT_CONNECTED;\
					_protocol_version = 0;\
					fprintf(stderr, "Disconnected from server\n")

	char buffer[BUFFER_LENGTH];
	char ringbuffer[RING_BUFFER_LENGTH];
	int connected, state_machine;
	char * command, * answer;

	// Socket stuff
	int readsockets, data_length, err_send, disconnected, connect_err_shown;

	// Set those 3 things to 0.
	memset(buffer, 0, BUFFER_LENGTH);
	memset(ringbuffer, 0, RING_BUFFER_LENGTH);
	err_send = disconnected = connected = connect_err_shown = 0;
	data_length = -1;


	// Make sure the compiler doesn't complain about it
	if (data) { }
	if (err_send) { }

	// Connection loop
	while (!_stop_threads) {
		if (connected == 0) {

			state_machine = STATE_NOT_CONNECTED;

			if (disconnected) {
				fprintf(stderr, "Trying to reconnect\n");
				connect_err_shown = 1;
				disconnected = 0;

				// Since it has been disconnected, recreate the socket
				createSocket();

				// Wait 10s before reconnecting
#ifdef DEBUG
				fprintf(stderr, "[*] Sleeping %d seconds before reconnecting.\n", TIME_BEFORE_RECONNECT_SEC);
#endif
				sleep(TIME_BEFORE_RECONNECT_SEC);
			}

			if (connect(_clientSocket,(struct sockaddr *) &_serv_addr, sizeof(_serv_addr)) < 0) {

				if (!connect_err_shown) {
					fprintf(stderr,"ERROR connecting to server\n");
					connect_err_shown = 1;
				}

				// Sleep a little bit to avoid overloading the CPU if it keeps err.
				sleep(5);
				continue;

			} else {
				// Reset error shown
				connect_err_shown = 0;

				// Connected
				connected = 1;

				fprintf(stderr, "Connected to server\n");

				_protocol_version = -1;
				state_machine = STATE_CONNECTED;

				// We're connected, send supported version
				answer = parse_command(NULL, &state_machine);
				if (send_data(_clientSocket, answer, strlen(answer)) != strlen(answer)) {
					err_send = 1; // Don't forget to reset it
					CLOSESOCKET();
					free(answer);
					continue;
				}
				free(answer);
			}
		}

		// Check if there's any data to read
		readsockets = is_data_to_read(_clientSocket);

		// Read buffer and parse command
		if (readsockets < 0) {
			// disconnected
			CLOSESOCKET();
			continue;
		}

		if (readsockets == 0) {
			// Sleep a little bit to avoid overloading the CPU.connect_to_server_old
			usleep(200);
			continue;
		}

		data_length = recv(_clientSocket, buffer, BUFFER_LENGTH, 0);
		if (data_length <= 0) {
			// -1: Error
			// 0: Disconnect
			CLOSESOCKET();
			continue;
		}

		// Put data at the back of the ring buffer
		memcpy(ringbuffer + strlen(ringbuffer), buffer, data_length);

		// Reset memory
		memset(buffer, 0, data_length);

		// Assume that the beginning of the ringbuffer is a new command

#ifdef DEBUG
		fprintf(stderr, "[*] Ring buffer <%s>.\n", ringbuffer);
#endif

		// while the ring buffer has command, parse them (and answer them)
		command = get_command(ringbuffer, RING_BUFFER_LENGTH);
		while (command != NULL) {

			answer = parse_command(command, &state_machine);
			free(command);

			// Send the answer (if exist)
			if (answer != NULL) {

				if (send(_clientSocket, answer, strlen(answer), 0) != strlen(answer)) {
					err_send = 1; // Don't forget to reset it
					CLOSESOCKET();
					free(answer);
					break;
				}

				free(answer);
			} else {
				// state VERSION/LOGIN and NULL result means disconnect
				if (state_machine == STATE_CONNECTED || state_machine == STATE_VERSION || state_machine == STATE_LOGIN) {
					if (state_machine == STATE_CONNECTED) {
						fprintf(stderr, "[*] Doesn't support any protocol, aborting.\n");
					}
					else {
						fprintf(stderr, "[*] Invalid login/pass, aborting.\n");
					}

					// Disconnect
					CLOSESOCKET();
					exit(EXIT_FAILURE);

					break;
				}
			}

			command = get_command(ringbuffer, RING_BUFFER_LENGTH);
		}
	}

	return EXIT_SUCCESS;

#undef BUFFER_LENGTH
#undef RING_BUFFER_LENGTH
#undef CLOSESOCKET
}



void createSocket()
{
	// Create socket
	_clientSocket = create_socket();

	if (_clientSocket < 0) {
		perror("ERROR opening socket");
		exit(EXIT_FAILURE);
	}

	// Set socket options: Keep-alive, etc.
	if (set_socket_options(_clientSocket) == EXIT_FAILURE) {
		perror("setsockopt()");
	}
}

// TODO: Update and use common/client.c connect_to_server (will reduce code)
int connect_to_server_old(int argc, char * argv[])
{
	int thread_created, parsed_port;
	uint16_t server_port = DEFAULT_SERVER_PORT;
	_login = NULL;
	_pass = NULL;

	// Get login, pass
	_login = argv[4];
	_pass = argv[5];

	// Get server port
	parsed_port = atoi(argv[3]);
	if (parsed_port < 1 || parsed_port > 65535) {
		fprintf(stderr, "Invalid port\n");
		help();
	}

	server_port = (uint16_t)parsed_port;

	// Create socket
	createSocket();

	// Resolve hostname
	fprintf(stderr, "Trying to connect to %s:%u\n",
			(argc > 2) ?  argv[2] : DEFAULT_SERVER_ADDRESS,
			server_port);
	_server = get_host_by_name(
			(argc > 2) ?  argv[2] : DEFAULT_SERVER_ADDRESS);

	if (_server == NULL) {
		fprintf(stderr,"ERROR, no such host\n");
		close(_clientSocket);
		exit(EXIT_FAILURE);
	}

	// Init structures
	bzero((char *) &_serv_addr, sizeof(_serv_addr));
	_serv_addr.sin_family = AF_INET;
	bcopy((char *)_server->h_addr,
		(char *)&_serv_addr.sin_addr.s_addr,
		_server->h_length);
	_serv_addr.sin_port = htons(server_port);

	// Connect
	thread_created = pthread_create(&_server_connection_thread, NULL, (void*)&connect_thread, NULL);
	if (thread_created != 0) {
		fprintf(stderr,"ERROR, failed to create connection thread\n");
		close(_clientSocket);
		exit(EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}

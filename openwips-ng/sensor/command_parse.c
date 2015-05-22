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
#include <string.h>
#include <math.h>
#include <stdio.h>

#include "command_parse.h"
#include "state_machine.h"
#include "common/defines.h"
#include "common/protocol.h"
#include "global_var.h"

#define IS_ACK(command)		((command) != NULL && \
							strlen(command) == 3 && \
							strncmp((command), "ACK", 3) == 0)

#define IS_NACK(command)	((command) != NULL && \
							strlen(command) == 4 && \
							strncmp((command), "NACK", 4) == 0)

// TODO: Check for ';' with '\' before (and for double '\')
// NULL: not enough data to determine length
// other: command
char * get_command(char * ringbuffer, int ringbuffer_len)
{
	char * command = NULL;
	char * newpos;
	int pos = 0;
	size_t length;
	CommandEndEnum cmdEndChars;

	for (pos = 0 ; ringbuffer[pos] != 0 && ringbuffer[pos] != '\n'; pos++ ) {

	}

	if (ringbuffer[pos] == '\n' || ringbuffer[pos] == '\r') {

		// Get the command
		command = decode(ringbuffer, 1, &cmdEndChars, NULL);

		// Remove that from the ringbuffer
		newpos = ringbuffer + pos + 1;
		if (cmdEndChars == CarriageReturnNewline) {
			++newpos;
		}
		length =  strlen(newpos);
		memmove(ringbuffer, newpos, length);
		memset(ringbuffer + length, 0, ringbuffer_len - length);
	}

#ifdef DEBUG
	if (command == NULL) {
		fprintf(stderr, "No command.\n");
	} else {
		fprintf(stderr, "Command <%s>.\n", command);
	}
#endif

	return command;
}

int parse_rpcap_command(char * command, char * host, struct rpcap_link * rlp)
{
	int item, pch_len;
	char * pch, * save_ptr;

	if (host == NULL || command == NULL || rlp == NULL) {
		return EXIT_FAILURE;
	}

	// TODO: Give host
	rlp->host = (char *)calloc(1, (strlen(host) + 1) * sizeof(char));
	strcpy(rlp->host, host);

	pch = strtok_r(command, " ", &save_ptr);
	for (item = 0; pch != NULL; item++) {
		// Make sure it is not empty because it cannot
		pch_len = strlen(pch);
		if (pch_len == 0) {
			return EXIT_FAILURE;
		}

#define COMPARE_PCH_LEN(str_compare, len) (pch_len == (len) && strncmp(pch, (str_compare), (len)) == 0)

		switch (item) {
			case 0: // RPCAP type
				rlp->encrypted = rlp->compressed = 0;

				if (COMPARE_PCH_LEN("ECRPCAP", 7)) {
					rlp->encrypted = rlp->compressed = 1;
				} else if (COMPARE_PCH_LEN("ERPCAP", 6)) {
					rlp->encrypted = 1;
				} else if (COMPARE_PCH_LEN("CRPCAP", 6)) {
					rlp->compressed = 1;
				} else if (!COMPARE_PCH_LEN("RPCAP", 5)) {
					// Invalid command, NACK
					return EXIT_FAILURE;
				}
				break;
			case 1: // Kind of data to receive

				if (COMPARE_PCH_LEN("EVERYTHING", 10)) {
					rlp->send_payload = rlp->send_data_frames = 1;
				} else if (COMPARE_PCH_LEN("NOPAYLOAD", 9)) {
					rlp->send_payload = 0;
					rlp->send_data_frames = 1;
				} else if (COMPARE_PCH_LEN("NODATA", 6)) {
					rlp->send_payload = 1;
					rlp->send_data_frames = 0;
				} else if (COMPARE_PCH_LEN("NODATA_NOPAYLOAD", 16)) {
					rlp->send_payload = rlp->send_data_frames = 0;
				} else {
					return EXIT_FAILURE;
				}
				break;
			case 2: // Active/Passive
				rlp->pasv = COMPARE_PCH_LEN("PASV", 4);
				if (!rlp->pasv && !COMPARE_PCH_LEN("ACTIVE", 6)) {
					return EXIT_FAILURE;
				}
				break;
			case 3: // Port (if active)
				if (rlp->pasv) {
					return EXIT_FAILURE;
				}
				rlp->port = atoi(pch);

				break;
			default: // If there is anymore arguments, there is something wrong
				return EXIT_FAILURE;
				break;
		}

		pch = strtok_r(command, " ", &save_ptr);
	}
#undef COMPARE_PCH_LEN

	return EXIT_SUCCESS;
}

char * parse_command(char * command, int * state)
{
	struct rpcap_link * rlp;
	int unknown_command = 1;
	char * ret = NULL;

	if (state == NULL) {
		return NULL;
	}
#ifdef DEBUG
	fprintf(stderr, "[*] State: %d.\n", *state);
	if (command != NULL) {
		fprintf(stderr, "[*] Command <%s>.\n", command);
	}
#endif

	if (*state == STATE_CONNECTED && command == NULL) {
		_protocol_version = MAX_SUPPORTED_PROTOCOL_VERSION;
		return get_supported_version(_protocol_version);
	}

	if (IS_ACK(command)) {
		unknown_command = 0;
		switch(*state) {
			case STATE_CONNECTED:
				// Version sent and approved, send login
#ifdef DEBUG
	fprintf(stderr, "[*] Sending login.\n");
#endif
				ret = encode(Newline, "LOGIN %s", _login);
				*state = STATE_VERSION;
				break;
			case STATE_VERSION:
				// Login sent, send PASS
#ifdef DEBUG
	fprintf(stderr, "[*] Sending password.\n");
#endif
				ret = encode(Newline, "PASS %s", _pass);
				*state = STATE_LOGIN;
				break;
			case STATE_LOGIN:
				// pass sent, send GET_CONFIG
#ifdef DEBUG
	fprintf(stderr, "[*] Sending GET_CONFIG.\n");
#endif
				ret = encode(Newline, "GET_CONFIG");
				*state = STATE_LOGGED_IN;
				break;
			default:
				break;
		}
	} else if (IS_NACK(command)) {
		// Log and disconnect
		unknown_command = 0;
		switch(*state) {
			case STATE_CONNECTED:
				// Version sent and approved, send login
				// Try a lower version
				if (_protocol_version == MIN_SUPPORTED_PROTOCOL_VERSION) {
#ifdef DEBUG
					fprintf(stderr, "Protocol version %u unsupported, are you sure it's our server? Disconnecting.\n", MIN_SUPPORTED_PROTOCOL_VERSION);
#endif
					*state = STATE_NOT_CONNECTED;
					return NULL;
				} else {
#ifdef DEBUG
					fprintf(stderr, "Protocol version %u unsupported, trying a lower version.\n", _protocol_version);
#endif
					--_protocol_version;
				}
				ret = get_supported_version(_protocol_version);
				break;
			case STATE_VERSION:
				// WTF, NACK on login, is it really our server?
#ifdef DEBUG
				fprintf(stderr, "WTF, NACK on LOGIN, are you sure it's our server? Disconnecting.\n");
#endif
				return NULL;
				break;
			case STATE_LOGIN:
				// NACK on pass: Disconnect and abort
				return NULL;
				break;
			default:
				break;
		}
	} else if (strlen(command) > 5 && strstr(command, "RPCAP ")) {

		// TODO: Fix that stuff (I mean use common/client)
		rlp = init_new_rpcap_link();
		if (parse_rpcap_command(command, _host, rlp) == EXIT_SUCCESS
				&& start_rpcap(rlp) == EXIT_SUCCESS) { // Connect to the server (in the background)
			unknown_command = 0;
			ret = encode(Newline, "ACK");
		}
		free_rpcap_link(&rlp);
	}

	if (unknown_command) {
		fprintf(stderr, "No freakin' idea what the command <%s> means.\n", command);
		ret = encode(Newline, "NACK");
	}

	return ret;
}


inline char * get_supported_version(unsigned int version)
{
	return encode(Newline, "VERSION %u", version);
}

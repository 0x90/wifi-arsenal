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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "command_parse.h"
#include "state_machine.h"
#include "../common/defines.h"
#include "../common/protocol.h"

/*
Sensor		Server
VERSION 1
		ACK
LOGIN xxxx
		ACK
PASS yyyy
		(N)ACK
NAME aaaa (name of the sensor, implemented later)
		ACK
LOCATION bbbb (location of the sensor, implemented later)
		ACK
GET_CONFIG
		RPCAP	EVERYTHING (ENCRYPTED) (COMPRESSED)	PASV
			NOPAYLOAD				ACTIVE	port_on_server
			NODATA (delay between report in seconds)

(E)(C)RPCAP	IP:port (if passive)
		ACK (if active)

-------------------------------
EVERYTHING: Send every single frame
NOPAYLOAD: Strip payload from data frames
NODATA: Do not send data frames, analyze them on the sensor (depending on the traffic, may require quite a bit of CPU power but will offload network usage)
-------------------------------
*/

char * parse_command(char * command, struct client_params * cp)
{
	char * arg, * ret;
	int cmd_len, port;
	int success = -1;
	if (STRING_IS_NULL_OR_EMPTY(command) || cp == NULL) {
		return NULL;
	}

	ret = NULL;
	cmd_len = strlen(command);


	if (cmd_len == 9 && strncmp(command, "VERSION ", 8) == 0) {
		arg = command + 8;
		success = (atoi(arg) <= MAX_SUPPORTED_PROTOCOL_VERSION);

		if (success) {
			cp->state = STATE_VERSION;
		}

#ifdef DEBUG
		else {
			fprintf(stderr, "[*] Invalid supported version: %s.\n", arg);
		}
#endif
	} else if (cp->state == STATE_VERSION && cmd_len > 6 && strncmp(command, "LOGIN ", 6) == 0) {
		arg = command + 6;
		success = 1;
		cp->client->user->user = (char *)calloc(1, (strlen(arg) + 1) * sizeof(char));
		strcpy(cp->client->user->user, arg);
		cp->state = STATE_LOGIN;
	} else if (cp->state == STATE_LOGIN && cmd_len > 5 && strncmp(command, "PASS ", 5) == 0) {
		arg = command + 5;

		// Search for login/pass
		cp->state = STATE_LOGIN_FAILED;
		success = 0;
		if (cp->client && cp->client->userlist &&
				is_user_valid(*(cp->client->userlist),
								cp->client->user->user,
								arg,
								cp->client->IP)) {

			// Check if multiple identical logins are allowed and if not, then check if the user is not already logged (if he is, send NACK)
			if (cp->client->allow_multiple_login || !is_user_already_logged_in(cp->client->user->user)) {
				cp->state = STATE_LOGGED_IN;
				success = 1;
			}
		}
	} else if (cp->state == STATE_LOGGED_IN) {
		if (cmd_len == 10 && strncmp(command, "GET_CONFIG", 10) == 0) {

			// Get port for rpcap then start server
			port = rpcap_get_port();
			cp->rpcap_server = rpcap_start_socket(port);
			if (cp->rpcap_server) {
				ret = encode(Newline, "RPCAP EVERYTHING ACTIVE %d;", port);
			} else {
				rpcap_free_port(port);
			}
			return ret;
		} else if (cmd_len == 3 && is_command_ack(command)) {
			// RPCAP successful
#ifdef DEBUG
			fprintf(stderr, "[*] Sensor accepted RPCAP.\n");
#endif
		} else if (cmd_len == 4 && is_command_nack(command)) {
			// RPCAP failed: close port
			fprintf(stderr, "[*] Sensor failed to do RPCAP, killing thread <%s>.\n", SHOW_TEXT_OR_NULL(cp->rpcap_server->identifier));
			kill_server(cp->rpcap_server, 1);
			free_server_params(&(cp->rpcap_server));
		}
#ifdef DEBUG
		else {
			fprintf(stderr, "[*] Unknown command <%s> while logged in.\n", command);
		}
#endif
	}
#ifdef DEBUG
	else {
		fprintf(stderr, "[*] Unknown command <%s>.\n", command);
	}
#endif

	return encode(Newline, get_ack_nack(success));
}

// TODO: Make it common for both sensor and server and take into account the slash
// NULL: not enough data to determine length
// other: command
char * get_command(char * ringbuffer, int * ringbuffer_len)
{
	char * command = NULL;
	char * newpos;
	int pos = 0;
	size_t length;
	CommandEndEnum cmdEnd;
	int cmdEndLen;

	if (ringbuffer_len == NULL || (*ringbuffer_len) == 0 || ringbuffer == NULL) {
		return NULL;
	}

#ifdef DEBUG
	fprintf(stderr, "get_command(ringbuffer -> <%s>, ringbuffer_len -> %d)\n", ringbuffer, *ringbuffer_len);
#endif

	// Search for end of command
	for (pos = 0;
			pos < (*ringbuffer_len) &&
			ringbuffer[pos] != 0 &&
			ringbuffer[pos] != '\n'
			; pos++);

	// If found, then parse it
	if (pos < (*ringbuffer_len) && (ringbuffer[pos] == '\n' || ringbuffer[pos] == '\r')) {

		// Copy content of the command
		command = decode(ringbuffer, 1, &cmdEnd, &pos);
		cmdEndLen = (cmdEnd == CarriageReturnNewline) ? 2 : 1;

		// Remove that from the ringbuffer
		if (pos + cmdEndLen == (*ringbuffer_len)) { // The whole ringbuffer has been used
			memset(ringbuffer, 0, *ringbuffer_len);
			*ringbuffer_len = 0;
		} else { // Only a part of it has been used
			newpos = ringbuffer + pos + cmdEndLen;
			length =  (*ringbuffer_len) - pos - cmdEndLen;
			memmove(ringbuffer, newpos, length);
			memset(ringbuffer + length, 0, (*ringbuffer_len) - length);
			*ringbuffer_len = length;
		}
	}

#ifdef DEBUG
	fprintf(stderr, "get_command(): %s\n", (command) ? command : "null");
#endif

	return command;
}

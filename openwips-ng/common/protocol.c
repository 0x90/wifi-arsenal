/*
 * OpenWIPS-ng - common stuff.
 * Copyright (C) 2012 Thomas d'Otreppe de Bouvette
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
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include "protocol.h"
#include "defines.h"

char * encode(CommandEndEnum command_end, char * format, ...)
{
	va_list args;
	int str_len;
	int required_length;
	int protocol_length = (command_end == Newline) ? 1 : 2;
	char * ret = calloc(1, protocol_length + 1);

	if (!STRING_IS_NULL_OR_EMPTY(format)) {
		str_len = strlen(format);

		// First, get the amount of bytes needed to store the string
		va_start(args, format);
		required_length = vsnprintf(ret, protocol_length + 1, format, args) + protocol_length + 1;
		va_end(args);

		// Do the actual vsnprintf
		ret = (char *)realloc(ret, required_length * sizeof(char));
		va_start(args, format);
		required_length = vsnprintf(ret, required_length, format, args);
		va_end(args);
	}

	// Add the \r\n or \n
	if (command_end == Newline) {
		strcat(ret, "\n");
	} else {
		strcat(ret, "\r\n");
	}

	return ret;
}

char * encode_simple(char * format, ...)
{
	va_list args;
	char * ret;

	if (STRING_IS_NULL_OR_EMPTY(format)) {
		return encode(DEFAULT_PROTOCOL_ENCODE, "");
	}

	va_start(args, format);
	ret = encode(DEFAULT_PROTOCOL_ENCODE, format, args);
	va_end(args);

	return ret;
}

inline char * decode_simple(char * input_string) { return decode_dup(input_string, 1); }
inline char * decode_dup(char * input_string, int duplicate) { return decode(input_string, duplicate, NULL, NULL); }

char * decode(char * input_string, int duplicate, CommandEndEnum * command_end, int * length)
{
	int str_len;
	char * new_string;
	if (STRING_IS_NULL_OR_EMPTY(input_string)) {
		return NULL;
	}

	str_len = strlen(input_string);

	// Decode both \n and \r\n
	// TODO: Handle buffer
	if (input_string[str_len -1] != '\n') {
		return NULL;
	}

	if (command_end != NULL) {
		*command_end = Newline;
	}

	if (duplicate) {
		new_string = (char *)calloc(1, str_len * sizeof(char));
		strncpy(new_string, input_string, str_len -1);
	} else {
		new_string = input_string;
	}

	new_string[--str_len] = '\0';

	if (new_string[str_len -1] == '\r') {
		new_string[--str_len] = '\0';
		if (command_end != NULL) {
			*command_end = CarriageReturnNewline;
		}
	}

	if (length != NULL) {
		*length = str_len;
	}

	return new_string;
}

char * get_ack_nack(int success)
{
	char * ret = NULL;
	if (success == -1) {
		return NULL;
	}

	if (success) {
		ret = (char *)calloc(1, (strlen(ACK) + 1)*sizeof(char));
		strcpy(ret, ACK);
	} else {
		ret = (char *)calloc(1, (strlen(NACK) + 1)*sizeof(char));
		strcpy(ret, NACK);
	}

	return ret;
}

inline int is_command_ack(char * command) {
	return command != NULL && strncmp(command, ACK, 3) == 0;
}

inline int is_command_nack(char * command) {
	return command != NULL && strncmp(command, NACK, 4) == 0;
}


// Add a function get_string_from_buffer()

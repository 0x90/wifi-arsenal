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
#include "config.h"

int parse_keyvalues(char * config_content)
{
	int line_begin, line_nb, skip_line, newpos;
	size_t file_length, i, value_len, key_len;
	char * line, *equal;
	struct key_value * cur_key_value;

	cur_key_value = NULL;
	file_length = strlen(config_content);
	line = (char *)calloc(1, file_length * sizeof (char));

	line_begin = line_nb = 1;
	skip_line = newpos = 0;
	for (i = 0; i <= file_length; i++) {
		// Skip line if # at the beginning (or \r\n or \n)
		if (line_begin) {
			if (config_content[i] == '#') {
				skip_line = 1;
				line_begin = 0;
				continue;
			}
			else if (config_content[i] == '\r' || config_content[i] == '\n' || config_content[i] == ' ' || config_content[i] == '\t') {
				if (config_content[i] == '\n') {
					line_nb++;
				}
				continue;
			}

			line_begin = 0;
		} else if (config_content[i] == '\n' || i == file_length) {
			line_begin = 1;
			skip_line = 0;

			if (newpos != 0) {
				// Parse line
				equal = strchr(line, '=');
				if (equal == NULL) {
					fprintf(stderr, "Failed to parse configuration at line %d: %s\n", line_nb, line);
					free(line);

					// Don't free _config, let main() do it

					return EXIT_SUCCESS;
				}

				// Allocate memory
				if (_config == NULL) {
					cur_key_value = (struct key_value *)malloc(sizeof(struct key_value));
					_config = cur_key_value;
				} else {
					cur_key_value->next = (struct key_value *)malloc(sizeof(struct key_value));
					cur_key_value = cur_key_value->next;
				}

				// Init values
				cur_key_value->next = NULL;

				// Get Value
				value_len = strlen(equal + 1); // Skip equal char
				cur_key_value->value = (char *)calloc(1, value_len + 1 );
				strncpy(cur_key_value->value, equal + 1, value_len);

				// Get key
				key_len = strlen(line) - value_len - 1; // Skip equal char
				cur_key_value->key = (char *)calloc(1, key_len + 1 );
				strncpy(cur_key_value->key, line, key_len);


				// Reset line content
				memset(line, 0, strlen(line));
				newpos = 0;
			}

			line_nb++;
			continue;
		}

		if (skip_line || i == file_length) {
			continue;
		}

		// Copy it to temp
		line[newpos++] = config_content[i];
	}

	// Free memory that is not needed anymore
	free(line);

#ifdef DEBUG
	printf("Configuration file key/value pairs:\n");
	cur_key_value = _config;
	while (cur_key_value != NULL) {
		printf("%s -> %s\n", cur_key_value->key, cur_key_value->value);
		cur_key_value = cur_key_value->next;
	}
	printf("\n-----------------------\n");
#endif

	return EXIT_SUCCESS;
}


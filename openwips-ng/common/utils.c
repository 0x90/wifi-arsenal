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
#include <sys/time.h>
#include <ctype.h>
#include <pcap/pcap.h>
#include "defines.h"
#include "utils.h"

int is_mac_broadcast(unsigned char * mac)
{
	if (mac == NULL) {
		return 0;
	}

	return (mac[0] == 255   && mac[0] == mac[1] && mac[1] == mac[2] &&
			mac[2] == mac[3]&& mac[3] == mac[4] && mac[4] == mac[5]);
}

int get_hex_value(char c)
{
	if (!isxdigit((int)c)) {
		return -1;
	}

	if (isdigit((int)c)) {
		return c - '0';
	}

	return toupper((int)c) - 'A' + 10;
}

unsigned char * parse_mac_from_string(char * mac)
{
	char * mac_no_separator;
	unsigned char * ret;
	int i, len, new_pos;

	if (STRING_IS_NULL_OR_EMPTY(mac)) {
		return NULL;
	}

	// Cleanup mac (remove separators)
	mac_no_separator = (char *)calloc(1, ((6 * 2) + 1) * sizeof(char));
	len = strlen(mac);
	new_pos = 0;
	for (i = 0; i < len; i++) {
		if (!isalnum((int)mac[i])) {
			continue;
		}

		if (!isxdigit((int)mac[i])) {
			free(mac_no_separator);
			return NULL;
		}

		*(mac_no_separator + new_pos) = *(mac +i);
		++new_pos;
	}

	// Check lenght
	len = strlen(mac_no_separator);
	if (len != 12) {
		free(mac_no_separator);
		return NULL;
	}

	ret = (unsigned char *)malloc(6 * sizeof(unsigned char));
	for (i = 0; i < 6; i++) {
		*(ret + i) = get_hex_value(*(mac_no_separator + (i * 2))) * 16;
		*(ret + i) += get_hex_value(*(mac_no_separator + ((i * 2) + 1)));
	}

	free(mac_no_separator);
	return ret;
}

// Packet 1 - Packet 2
struct timeval * get_time_difference_between_packet(struct pcap_packet * packet1, struct pcap_packet * packet2)
{
	struct timeval * diff;
	if (packet1 == NULL || packet2 == NULL) {
		return NULL;
	}

	diff = (struct timeval *)malloc(sizeof(struct timeval));
	diff->tv_sec = packet1->header.ts_sec - packet2->header.ts_sec;


	diff->tv_usec = packet1->header.ts_usec - packet2->header.ts_usec;
	if (packet2->header.ts_usec > packet1->header.ts_usec) {
		--(diff->tv_sec);
		diff->tv_usec += 1000000;
	}

	return diff;
}

int is_mac_equal(unsigned char *  from_packet, char * printed_mac)
{
	int i, success = 0;
	unsigned char * mac_bytes;
	unsigned int * mac_bytes_int;

	if (from_packet == NULL || printed_mac == NULL) {
		return 0;
	}
	mac_bytes = (unsigned char*)malloc(sizeof(char) * 6);
	mac_bytes_int = (unsigned int*)malloc(sizeof(unsigned int) * 6);
	sscanf(printed_mac, "%02x:%02x:%02x:%02x:%02x:%02x", mac_bytes_int, mac_bytes_int + 1, mac_bytes_int + 2, mac_bytes_int + 3, mac_bytes_int + 4, mac_bytes_int + 5);
	for (i = 0; i < 6; i++) {
		*(mac_bytes + i) = (unsigned char)(*(mac_bytes_int + i));
	}
	success = memcmp(mac_bytes, from_packet, 6) == 0;

	free(mac_bytes);
	return success;
}

char * read_text_file_content(char * path, int replace_null_by_space)
{
	FILE * f;
	long int file_length, i;
	long int items_read;
	char * ret = NULL;

	if (path == NULL) {
		fprintf(stderr, "No path to the configuration file given.\n");
		return ret;
	}

	// Check if file exist
	f = fopen(path, "r");
	if (f == NULL) {
		fprintf(stderr, "Configuration file does not exist.\n");
		return ret;
	}

	// Get length of the file then allocate the char * storing it
	fseek(f, 0, SEEK_END);
	file_length = ftell(f);

	if (file_length == 0) {
		fprintf(stderr, "Failed to read configuration file: file is empty.\n");
		fclose(f);
		return EXIT_SUCCESS;
	}

	fseek(f, 0, SEEK_SET);
	ret = (char *)calloc(1, (file_length + 2)* sizeof (char));
	items_read = fread(ret, file_length, 1, f);
	fclose(f);
	if (items_read != 1) {
		fprintf(stderr, "Failed to read configuration file.\n");
		free(ret);
		return EXIT_SUCCESS;
	}

	if (replace_null_by_space) {
		// Replace any occurence of NULL in the config file by a space.
		for (i = 0; i < file_length; i++) {
			if (ret[i] == '\0') {
				ret[i] = ' ';
			}
		}
	}

	return ret;
}

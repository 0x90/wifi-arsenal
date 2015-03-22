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

#ifndef COMMON_UTILS_H_
#define COMMON_UTILS_H_

#include "pcap.h"

int is_mac_broadcast(unsigned char * mac);
struct timeval * get_time_difference_between_packet(struct pcap_packet * packet1, struct pcap_packet * packet2);
int is_mac_equal(unsigned char *  from_packet, char * printed_mac);
unsigned char * parse_mac_from_string(char * mac);
int get_hex_value(char c);
char * read_text_file_content(char * path, int replace_null_by_space); // Read the content of the file and return it

#endif /* COMMON_UTILS_H_ */

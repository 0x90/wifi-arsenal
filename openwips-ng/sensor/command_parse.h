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

#ifndef COMMAND_PARSE_H_
#define COMMAND_PARSE_H_

#include "structures.h"

extern int start_rpcap(struct rpcap_link * link_info); // in rpcap.c

int parse_rpcap_command(char * command, char * host, struct rpcap_link * rlp);
char * parse_command(char * command, int * state);
char * get_supported_version(unsigned int version); // Return max supported version
char * get_command(char * ringbuffer, int ringbuffer_len);

#endif /* COMMAND_PARSE_H_ */

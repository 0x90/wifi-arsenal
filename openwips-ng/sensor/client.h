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

#ifndef CLIENT_H_
#define CLIENT_H_

#define DEFAULT_SERVER_ADDRESS "127.0.0.1"

#define TIME_BEFORE_RECONNECT_SEC 10

int connect_thread(void * data);
void createSocket();
int connect_to_server_old(int argc, char * argv[]);


extern void help(); // in main.c
extern char * parse_command(char * command, int * state); // in command_parse.c
extern char * get_command(char * ringbuffer, int ringbuffer_len); // in command_parse.c

#endif /* CLIENT_H_ */

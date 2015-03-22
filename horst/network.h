/* horst - Highly Optimized Radio Scanning Tool
 *
 * Copyright (C) 2005-2014 Bruno Randolf (br1@einfach.org)
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
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef _PROTOCOL_NETWORK_H_
#define _PROTOCOL_NETWORK_H_

#include <stddef.h>

struct packet_info;

extern int srv_fd;
extern int cli_fd;

void
net_init_server_socket(int rport);

int net_handle_server_conn(void);

int
net_send_packet(struct packet_info *pkt);

void
net_send_channel_config(void);

void
net_send_filter_config(void);

int
net_receive(int fd, unsigned char* buffer, size_t* buflen, size_t maxlen);

int
net_open_client_socket(char* server, int rport);

void
net_finish(void);

#endif

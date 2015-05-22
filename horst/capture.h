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

#ifndef _CAPTURE_H_
#define _CAPTURE_H_

#include <stddef.h>

int
open_packet_socket(char* devname, int recv_buffer_size);

int
recv_packet(int fd, unsigned char* buffer, size_t bufsize);

void
close_packet_socket(int fd, char* ifname);

int
device_get_hwinfo(int fd, char* ifname, unsigned char* mac);

#endif // _CAPTURE_H_

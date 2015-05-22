/* copied from batman batman.h */

/*
 * Copyright (C) 2006 B.A.T.M.A.N. contributors:
 * Thomas Lopatic, Corinna 'Elektra' Aichele, Axel Neumann, Marek Lindner
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 *
 */

#ifndef _BATMAN_BATMAN_H
#define _BATMAN_BATMAN_H

#include <stdint.h>

#define BAT_PORT 4305
#define BAT_UNIDIRECTIONAL 0x80
#define BAT_DIRECTLINK 0x40
#define BAT_ADDR_STR_LEN 16
#define BAT_TQ_MAX_VALUE 255

struct bat_packet
{
        uint32_t orig;
        uint32_t old_orig;
        uint8_t  flags;    /* 0x80: UNIDIRECTIONAL link, 0x40: DIRECTLINK flag, ... */
        uint8_t  ttl;
        uint16_t seqno;
        uint8_t  gwflags;  /* flags related to gateway functions: gateway class */
        uint8_t  version;  /* batman version field */
        uint8_t  tq;
} __attribute__((packed));

#endif

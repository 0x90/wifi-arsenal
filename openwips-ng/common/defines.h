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

#ifndef COMMON_DEFINES_H_
#define COMMON_DEFINES_H_

#if defined(__APPLE__) && defined(__MACH__)
	#define OSX
#endif

#define FREE_AND_NULLIFY(item) if ((item) != NULL) free(item); (item) = NULL
#define PTHREAD_NULL 0
#define STRING_IS_NULL_OR_EMPTY(s) ((s) == NULL || strlen(s) == 0)
#define SHOW_TEXT_OR_NULL(s) (s) ? (s) : "null"
#define ALLOC_NEW_TYPE(type)	((type)*)malloc(sizeof(type))
#define ALLOC_COPY_STRING(from,to)	if ((from) != NULL) (to) = (char *)calloc(1, (strlen(from) + 1) * sizeof(char)); \
									if ((from) != NULL) strcpy((to), (from)); \
									else to = NULL
#define IS_BIG_ENDIAN	(htonl(47) == 47)
/*
// GET_BITS doesn't work correctly, fix it before enabling it again.
#define GET_BITS(value, start_bit, nb_bits) (start_bit) ? \
											(( (value) >> ((start_bit) - 1)) & ((1 << (nb_bits)) - 1)) : \
											((value) & ((1 << (nb_bits)) - 1))
*/
// Default server port: WIPS
#define DEFAULT_SERVER_PORT 9477

#define CHECK_SOCKET_PORT(port) ((port) > 0 && (port) < 65536)

#endif /* COMMON_DEFINES_H_ */

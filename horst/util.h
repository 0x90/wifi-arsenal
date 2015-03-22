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

#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdio.h>

#ifdef _ALLBSD_SOURCE
#include <machine/endian.h>
#elif __linux__
#include <endian.h>
#endif

#if defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#define le64toh(x) OSSwapLittleToHostInt64(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#else
#include <byteswap.h>
#endif


#if BYTE_ORDER == LITTLE_ENDIAN

#if !defined(le64toh)
	#define le64toh(x) (x)
#endif
#if !defined(le32toh)
	#define le32toh(x) (x)
#endif
#if !defined(le16toh)
	#define le16toh(x) (x)
#endif
#if !defined(htole64)
	#define htole64(x) (x)
#endif
#if !defined(htole32)
	#define htole32(x) (x)
#endif
#if !defined(htole16)
	#define htole16(x) (x)
#endif

#else
#if !defined(le64toh)
	#define le64toh(x) bswap_64(x)
#endif
#if !defined(le32toh)
	#define le32toh(x) bswap_32(x)
#endif
#if !defined(le16toh)
	#define le16toh(x) bswap_16(x)
#endif
#if !defined(htole64)
	#define htole64(x) bswap_64(x)
#endif
#if !defined(htole32)
	#define htole32(x) bswap_32(x)
#endif
#if !defined(htole16)
	#define htole16(x) bswap_16(x)
#endif
#endif

void
dump_packet(const unsigned char* buf, int len);

const char*
ether_sprintf(const unsigned char *mac);

const char*
ether_sprintf_short(const unsigned char *mac);

const char*
ip_sprintf(const unsigned int ip);

const char*
ip_sprintf_short(const unsigned int ip);

void
convert_string_to_mac(const char* string, unsigned char* mac);

int
normalize(float val, int max_val, int max);

static inline int normalize_db(int val, int max)
{
	if (val <= 30)
		return 0;
	else if (val >= 100)
		return max;
	else
		return normalize(val - 30, 70, max);
}

const char*
kilo_mega_ize(unsigned int val);

#define MAC_NOT_EMPTY(_mac) (_mac[0] || _mac[1] || _mac[2] || _mac[3] || _mac[4] || _mac[5])
#define MAC_EMPTY(_mac) (!_mac[0] && !_mac[1] && !_mac[2] && !_mac[3] && !_mac[4] && !_mac[5])

#define TOGGLE_BIT(_x, _m) (_x) ^= (_m)

#define max(_x, _y) ((_x) > (_y) ? (_x) : (_y))
#define min(_x, _y) ((_x) < (_y) ? (_x) : (_y))

#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))

static inline __attribute__((const))
int is_power_of_2(unsigned long n)
{
	return (n != 0 && ((n & (n - 1)) == 0));
}

int
ilog2(int x);

#endif

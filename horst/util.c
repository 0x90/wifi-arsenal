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

#include <stdio.h>
#include <string.h>

#include "util.h"


int
normalize(float oval, int max_val, int max) {
	int val;
	val= (oval / max_val) * max;
	if (val > max) /* cap if still bigger */
		val = max;
	if (val == 0 && oval > 0)
		val = 1;
	if (val < 0)
		val = 0;
	return val;
}


#if DO_DEBUG
void
dump_packet(const unsigned char* buf, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		if ((i % 2) == 0) {
			printf(" ");
		}
		if ((i % 16) == 0) {
			printf("\n");
		}
		printf("%02x", buf[i]);
	}
	printf("\n");
}
#else
void
dump_packet(__attribute__((unused)) const unsigned char* buf,
	    __attribute__((unused)) int len)
{
}
#endif


const char*
ether_sprintf(const unsigned char *mac)
{
	static char etherbuf[18];
	snprintf(etherbuf, sizeof(etherbuf), "%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return etherbuf;
}


const char*
ether_sprintf_short(const unsigned char *mac)
{
	static char etherbuf[5];
	snprintf(etherbuf, sizeof(etherbuf), "%02x%02x",
		mac[4], mac[5]);
	return etherbuf;
}


const char*
ip_sprintf(const unsigned int ip)
{
	static char ipbuf[18];
	unsigned char* cip = (unsigned char*)&ip;
	snprintf(ipbuf, sizeof(ipbuf), "%d.%d.%d.%d",
		cip[0], cip[1], cip[2], cip[3]);
	return ipbuf;
}


const char*
ip_sprintf_short(const unsigned int ip)
{
	static char ipbuf[5];
	unsigned char* cip = (unsigned char*)&ip;
	snprintf(ipbuf, sizeof(ipbuf), ".%d", cip[3]);
	return ipbuf;
}


void
convert_string_to_mac(const char* string, unsigned char* mac)
{
	int c;
	for(c = 0; c < 6 && string; c++) {
		int x = 0;
		if (string)
			sscanf(string, "%x", &x);
		mac[c] = x;
		string = strchr(string, ':');
		if (string)
			string++;
	}
}


const char*
kilo_mega_ize(unsigned int val) {
	static char buf[20];
	char c = 0;
	int rest;
	if (val >= 1024) { /* kilo */
		rest = (val & 1023) / 102.4; /* only one digit */
		val = val >> 10;
		c = 'k';
	}
	if (val >= 1024) { /* mega */
		rest = (val & 1023) / 102.4; /* only one digit */
		val = val >> 10;
		c = 'M';
	}
	if (c)
		snprintf(buf, sizeof(buf), "%d.%d%c", val, rest, c);
	else
		snprintf(buf, sizeof(buf), "%d", val);
	return buf;
}


/* simple ilog2 implementation */
int
ilog2(int x) {
	int n;
	for (n = 0; !(x & 1); n++)
		x = x >> 1;
	return n;
}

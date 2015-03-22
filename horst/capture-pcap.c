/* horst - Highly Optimized Radio Scanning Tool
 *
 * Copyright (C) 2005-2014 Bruno Randolf (br1@einfach.org)
 * Copyright (C) 2007 Sven-Ola Tuecke
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
#include <pcap.h>
#include <err.h>

#include "capture.h"
#include "util.h"


void __attribute__ ((format (printf, 1, 2)))
printlog(const char *fmt, ...);


#define PCAP_TIMEOUT 200

static unsigned char* pcap_buffer;
static size_t pcap_bufsize;
static pcap_t *pcap_fp = NULL;


static void
handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	*((int *)user) = h->len;
	if (pcap_bufsize < h->len) {
		printlog("ERROR: Buffer(%d) too small for %d bytes",
			 (int)pcap_bufsize, h->len);
		*((int *)user) = pcap_bufsize;
	}
	memmove(pcap_buffer, bytes, *((int *)user));
}


int
open_packet_socket(char* devname, __attribute__((unused)) int recv_buffer_size)
{
	char error[PCAP_ERRBUF_SIZE];
	int ret;

	pcap_fp = pcap_create(devname, error);
	if (pcap_fp == NULL) {
		fprintf(stderr, "Couldn't create pcap: %s\n", error);
		return -1;
	}

	pcap_set_promisc(pcap_fp, 1);

#if defined(__APPLE__)
	if (pcap_can_set_rfmon(pcap_fp))
		pcap_set_rfmon(pcap_fp, 1);
	else
		err(1, "Couldn't activate monitor mode");
#endif

	ret = pcap_activate(pcap_fp);
	if (ret < 0) {
		fprintf(stderr, "Can't activate pcap: %d\n", ret);
		return -1;
	}

	return pcap_fileno(pcap_fp);
}


int
device_get_hwinfo(__attribute__((unused)) int fd,
		  __attribute__((unused)) char* ifname,
		  __attribute__((unused)) unsigned char* mac)
{
	if (pcap_fp != NULL) {
		switch (pcap_datalink(pcap_fp)) {
		case DLT_IEEE802_11_RADIO:
			return 803;
		case DLT_PRISM_HEADER:
			return 802;
		default:
			return 801;
		}
	}
	/* TODO: mac address not implemented */
	return -1;
}


int
recv_packet(__attribute__((unused)) int fd,
	    unsigned char* buffer, size_t bufsize)
{
	int ret = 0; 
	pcap_buffer = buffer;
	pcap_bufsize = bufsize;
	if (0 == pcap_dispatch(pcap_fp, 1, handler, (u_char *)&ret))
		return -1;
	return ret;
}


void
close_packet_socket(__attribute__((unused)) int fd,
		    __attribute__((unused)) char* ifname)
{
	if (pcap_fp != NULL)
		pcap_close(pcap_fp);
}

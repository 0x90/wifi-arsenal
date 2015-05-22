/*
 * Reaver - Misc functions
 * Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL. *  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so. *  If you
 *  do not wish to do so, delete this exception statement from your
 *  version. *  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#include "misc.h"

/* Converts a raw MAC address to a colon-delimited string */
unsigned char *mac2str(unsigned char *mac, char delim)
{
	int i = 0, str_len = 0;
	int str_mult = 3;
	int buf_size = str_mult+1;
	unsigned char *str = NULL;
	unsigned char buf[4] = { 0 };	/* 4 == buf_size */

	str_len = (MAC_ADDR_LEN * str_mult) + 1;

	str = malloc(str_len);
	if(!str)
	{
		perror("malloc");
	} else {
		memset(str, 0, str_len);
	
		for(i=0; i<MAC_ADDR_LEN; i++)
		{
			memset((char *) &buf, 0, buf_size);
			snprintf((char *) &buf, buf_size, "%.2X%c", mac[i], delim);
			strncat((char *) str, (char *) &buf, str_mult);
		}
		memset(str+((MAC_ADDR_LEN*str_mult)-1), 0, 1);
	}

	return str;
}

/* Converts a colon-delimited string to a raw MAC address */
void str2mac(unsigned char *str, unsigned char *mac)
{
	char *delim_ptr = NULL, *num_ptr = NULL, *tmp_str = NULL;
	char delim = ':';
	int count = 0;

	tmp_str = strdup((char *) str);
	delim_ptr = num_ptr = tmp_str;

	while((delim_ptr = strchr(delim_ptr, delim)) && count < (MAC_ADDR_LEN-1))
	{
		memset(delim_ptr, 0, 1);
		mac[count] = strtol(num_ptr, NULL, 16);
		delim_ptr++;
		count++;
		num_ptr = delim_ptr;
	}
	mac[count] = strtol(num_ptr, NULL, 16);
	
	free(tmp_str);
	return;
}

/* Conditional printf wrapper */
void cprintf(enum debug_level level, const char *fmt, ...)
{
	va_list arg;

	if(level <= get_debug())
	{
		va_start(arg, fmt);
		vfprintf(get_log_file(), fmt, arg);
		va_end(arg);
	}

	fflush(get_log_file());
}

/* Daemonizes the process */
void daemonize(void)
{
	if(fork() > 0)
	{
		exit(EXIT_SUCCESS);
	}

	if(chdir("/") == 0)
	{
		setsid();
		umask(0);

		if(fork() > 0)
		{
			exit(EXIT_SUCCESS);
		}
	}
}

/* Closes libpcap during sleep period to avoid stale packet data in pcap buffer */
void pcap_sleep(int seconds)
{
	if(seconds > 0)
	{
		pcap_close(get_handle());
		set_handle(NULL);
		sleep(seconds);
        	set_handle(capture_init(get_iface()));

		if(!get_handle())
		{
			cprintf(CRITICAL, "[-] Failed to re-initialize interface '%s'\n", get_iface());
		}
	}
}


/*
 * Copyright 2013, 2014		Maurice Leclaire <leclaire@in.tum.de>
 *				Stephan M. Guenther <moepi@moepi.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * See COPYING for more details.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <string.h>
#include <malloc.h>
#include <errno.h>

#include <moep80211/ieee80211_addr.h>
#include <moep80211/types.h>


u8 *ieee80211_aton(const char *addr)
{
	u8 *hwaddr;

	if (!(hwaddr = malloc(IEEE80211_ALEN))) {
		errno = ENOMEM;
		return NULL;
	}

	if (sscanf(addr, "%hhx%*c%hhx%*c%hhx%*c%hhx%*c%hhx%*c%hhx",
		   hwaddr, hwaddr+1, hwaddr+2, hwaddr+3, hwaddr+4, hwaddr+5)
	    != 6) {
		errno = EINVAL;
		return NULL;
	}

	return hwaddr;
}

char *ieee80211_ntoa(const u8 *addr)
{
	char *str;

	if (!(str = malloc(18))) {
		errno = ENOMEM;
		return NULL;
	}

	if (snprintf(str, 18, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
		     addr[0], addr[1], addr[2], addr[3], addr[4], addr[5])
	    != 17) {
		errno = EINVAL;
		return NULL;
	}

	return str;
}

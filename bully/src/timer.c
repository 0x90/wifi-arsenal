/*
    bully - retrieve WPA/WPA2 passphrase from a WPS-enabled AP

    Copyright (C) 2012  Brian Purcell <purcell.briand@gmail.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

static inline void set_timer(struct timeval *tv, int ms_from_now)
{
	gettimeofday(tv, 0);
	tv->tv_sec += ms_from_now/1000;
	ms_from_now -= (ms_from_now/1000)*1000;
	tv->tv_usec += ms_from_now*1000;
};


static inline int check_timer(struct timeval *tv)
{
	struct timeval now;
	gettimeofday(&now, 0);
	if (tv->tv_sec < now.tv_sec)
		return TRUE;
	if (tv->tv_sec == now.tv_sec && tv->tv_usec < now.tv_usec)
		return TRUE;
	return FALSE;
};


static inline int elapsed(struct timeval *then)
{
	struct timeval now;
	gettimeofday(&now, 0);

	if (now.tv_usec < then->tv_usec)
		return ((now.tv_sec - 1) - then->tv_sec)*1000 + (now.tv_usec+1000000 - then->tv_usec)/1000;
	else
		return (now.tv_sec - then->tv_sec)*1000 + (now.tv_usec - then->tv_usec)/1000;
};

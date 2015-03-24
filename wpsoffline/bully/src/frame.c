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
#include "80211.h"
#include "frame.h"


static inline void f_set(frame_t *fp, int id, int next, uint8 *data, int size, int list)
{
	fp[id].next = (next ? &fp[next] : NULL);
	fp[id].data = data;
	fp[id].size = size;
	fp[id].list = (list ? &fp[list] : NULL);
};


frame_t *f_init()
{
	frame_t *fp = calloc(F_SIZE, F_MAX);
	if (fp) {
		f_set(fp, F_ALL,     0, NULL, 0, F_TAP);
		f_set(fp, F_TAP, F_MAC, NULL, 0,     0);
		f_set(fp, F_MAC, F_PAY, NULL, 0,     0);
		f_set(fp, F_PAY, F_FCS, NULL, 0, F_LLC);
		f_set(fp, F_FCS,     0, NULL, 0,     0);
		f_set(fp, F_LLC, F_D1X, NULL, 0,     0);
		f_set(fp, F_D1X, F_EAP, NULL, 0,     0);
		f_set(fp, F_EAP, F_WFA, NULL, 0,     0);
		f_set(fp, F_WFA, F_MSG, NULL, 0,     0);
		f_set(fp, F_MSG, F_IDK, NULL, 0,     0);
		f_set(fp, F_IDK,     0, NULL, 0,     0);
	};
	return fp;
};

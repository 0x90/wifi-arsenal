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
#ifndef _FRAME_H
#define _FRAME_H


struct frame {
  struct frame	*next;
	uint8	*data;
	int	size;
  struct frame	*list;
};
typedef	struct frame frame_t;
#define	F_SIZE	(sizeof(frame_t))

#define	F_ALL	0
#define	F_TAP	1
#define	F_MAC	2
#define	F_PAY	3
#define	F_FCS	4
#define	F_LLC	5
#define	F_D1X	6
#define	F_EAP	7
#define	F_WFA	8
#define	F_MSG	9
#define	F_IDK	10
#define	F_MAX	11

static inline void f_set(frame_t *fp, int id, int next, uint8 *data, int size, int list);

#endif /* _FRAME_H */

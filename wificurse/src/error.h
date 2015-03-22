/*
    wificurse - WiFi Jamming tool
    Copyright (C) 2012  oblique

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

#ifndef ERROR_H
#define ERROR_H

#include <errno.h>


#define GOTERR		-1
#define ERRNODATA	-2

void set_error(char *file, int line, int errnum, char *fmt, ...);
void print_error();
void _err_msg(char *file, int line, int errnum, char *fmt, ...);


#define return_error(fmt, ...)						\
do {									\
	set_error(__FILE__, __LINE__, errno, fmt, ##__VA_ARGS__);	\
	return GOTERR;							\
} while(0)

#define err_msg(fmt, ...) \
	_err_msg(__FILE__, __LINE__, errno, fmt, ##__VA_ARGS__)


#endif

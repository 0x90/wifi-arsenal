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

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "error.h"


struct _error {
	int errnum;
	int line;
	char *file;
	char msg[1024];
};

static struct _error __thread _error;


void set_error(char *file, int line, int errnum, char *fmt, ...) {
	va_list args;

	_error.file = file;
	_error.line = line;
	_error.errnum = errnum;
	va_start(args, fmt);
	vsnprintf(_error.msg, sizeof(_error.msg), fmt, args);
	va_end(args);
}

void print_error() {
	char buf[1024];
	strerror_r(_error.errnum, buf, sizeof(buf));
	fprintf(stderr, "%s:%d: %s: %s\n", _error.file, _error.line, _error.msg, buf);
}

void _err_msg(char *file, int line, int errnum, char *fmt, ...) {
	char buf[1024], msg[1024];
	va_list args;

	va_start(args, fmt);
	vsnprintf(msg, sizeof(msg), fmt, args);
	va_end(args);
	strerror_r(errnum, buf, sizeof(buf));
	fprintf(stderr, "%s:%d: %s: %s\n", file, line, msg, buf);
}

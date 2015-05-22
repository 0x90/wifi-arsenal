/*
 * Copyright (C) 2004 toast
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 */
#include <pcre.h>
#include <python2.7/Python.h>

#define CONF_MAX_LEN 2048
#define CONF_MAX_RESPONSE 32000

#define PYFUNCNAME "airpwn_response"

struct conf_entry {
  char name[64];
  pcre *match;
  pcre *ignore;
  char *response;
  PyObject *pyfunc;
  unsigned int response_len;
  unsigned int options;
#define CONF_OPTION_RESET 1

  struct conf_entry *next;
};

typedef struct conf_entry conf_entry;

conf_entry *parse_config_file(char *conf_file_path);

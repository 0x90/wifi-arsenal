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
#include "conf.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

struct conf_entry *parse_config_file(char *conf_file_path){

  FILE *conf_file;
  char conf_line[CONF_MAX_LEN];
  struct conf_entry *head = NULL;
  unsigned int line_no = 0;

  conf_file = fopen(conf_file_path, "r");

  if(conf_file == NULL){
    perror("fopen");
    return NULL;
  }

  while(fgets(conf_line, CONF_MAX_LEN, conf_file) != NULL){
    char command[64] = {0};
    char *argument, *ptr;
    const char *errptr;
    unsigned int arglen, lenread=0;
    int c, fd, pyinitialized=0;
    struct stat statbuf;

    line_no++;

    conf_line[CONF_MAX_LEN - 1] = 0;

    sscanf(conf_line, "%64s", command);

    if(command[0] == 0){
      continue;
    }

    argument = conf_line + strlen(command);
    // skip over any whitespace
    while(*argument == 0x20 || *argument == 0x09)
      argument++;

    arglen = strlen(argument);

    // truncate any new-lines etc
    for(ptr = argument + arglen -1; ptr > argument ; ptr--){
      if(*ptr == '\n' || *ptr == '\r')
	*ptr = 0;
    }
    
    // start parsing commands
    if(strcmp(command, "begin") == 0){
      struct conf_entry *tmp = malloc(sizeof(struct conf_entry));

      if(tmp == NULL){
	perror("malloc");
	return NULL;
      }

      bzero(tmp, sizeof(struct conf_entry));

      // now's a good time to make sure the previous block had
      // everything we care about..
      if(head){
	if(head->match == NULL){
	  printf("Error: block ending at line %u missing match!\n", line_no);
	  return NULL;
	}

	if((head->response == NULL && head->pyfunc == NULL) || 
	    head->response_len < 1 || head->response_len > CONF_MAX_RESPONSE)
	{
	  printf("Error: block ending at line %u has missing or malformed response!\n", line_no);
	  return NULL;
	}
      }

      tmp->next = head;

      head = tmp;

      strncpy(tmp->name, argument, sizeof(tmp->name));

    } else {
      if(head == NULL){
	printf("Error in config file line %u\n", line_no);
	return NULL;
      }

      if(strcmp(command, "match") == 0){
	// the regex to match
	head->match = pcre_compile(argument, PCRE_MULTILINE|PCRE_DOTALL, 
	    &errptr, &c, NULL);

	if(head->match == NULL){
	  printf("Error at character %d in pattern: \"%s\" (%s)\n",
	      c, argument, errptr);
	  return NULL;
	}
      } else if(strcmp(command, "ignore") == 0){
	// the regex to ignore
	head->ignore = pcre_compile(argument, PCRE_MULTILINE|PCRE_DOTALL, 
	    &errptr, &c,NULL);

	if(head->ignore == NULL){
	  printf("Error at character %d in pattern: \"%s\" (%s)\n",
	      c, argument, errptr);
	  return NULL;
	}
      } else if(strcmp(command, "option") == 0){
	if(strcmp(argument, "reset") == 0)
	  head->options |= CONF_OPTION_RESET;
	else {
	  printf("Unknown option: %s\n", argument);
	  return NULL;
	}
      } else if(strcmp(command, "response") == 0){
	// path to the file to load the response from
	if((fd = open(argument, O_RDONLY)) < 0){
	  printf("Error opening file: %s\n", argument);
	  perror("open");
	  return NULL;
	}

	if(fstat(fd, &statbuf) < 0){
	  perror("stat");
	  return NULL;
	}

	if(statbuf.st_size > CONF_MAX_RESPONSE){
	  printf("Error: file %s is too large! (Maximum size is %u)\n",
	      argument, CONF_MAX_RESPONSE);
	  return NULL;
	}

	head->response = malloc(statbuf.st_size + 1);
	if(head->response == NULL){
	  perror("malloc");
	  return NULL;
	}

	while((c = read(fd, 
		head->response + lenread, statbuf.st_size - lenread)) 
	    < statbuf.st_size)
	{
	  lenread += c;
	  printf("read %d bytes\n", lenread);
	}

	lenread += c;

	head->response_len = lenread;

      } else if(strcmp(command, "pymodule") == 0){
	if(!pyinitialized){
          printf("initializing python..\n");
	  Py_Initialize();
	  pyinitialized = 1;
	}
	PyObject *module = PyImport_Import(PyString_FromString(argument));

	if(module == NULL){
	  printf("Error loading module: %s\n", argument);
	  return NULL;
	}

	head->pyfunc = PyObject_GetAttrString(module, PYFUNCNAME);

	if(head->pyfunc == NULL){
	  printf("No function named 'PYFUNCNAME' in module: %s\n", argument);
	  return NULL;
	}
      } else {
	printf("Unknown command at line %u\n", line_no);
	return NULL;
      }
    }

  }
  return head;
}

/*
    This file is part of lorcon

    lorcon is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    lorcon is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with lorcon; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

    Copyright (c) 2005 dragorn and Joshua Wright
*/

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include "lorcon_packasm.h"

struct lcpa_metapack *lcpa_init() {
	struct lcpa_metapack *c = 
		(struct lcpa_metapack *) malloc(sizeof(struct lcpa_metapack));

	c->len = 0;
	c->data = NULL;
	c->freedata = 0;
	snprintf(c->type, 24, "INIT");

	c->prev = NULL;
	c->next = NULL;

	return c;
}

struct lcpa_metapack *lcpa_append_copy(struct lcpa_metapack *in_pack, char *in_type,
									   int in_len, uint8_t *in_data) {
	struct lcpa_metapack *c = 
		(struct lcpa_metapack *) malloc(sizeof(struct lcpa_metapack));
	struct lcpa_metapack *i = NULL, *j = NULL;

	c->len = in_len;
	c->data = (uint8_t *) malloc(in_len);
	memcpy(c->data, in_data, in_len);
	c->freedata = 1;
	snprintf(c->type, 24, "%s", in_type);

	/* Find the end of the list */
	j = i;
	for (i = in_pack; i != NULL; i = i->next) {
		j = i;
	}

	j->next = c;
	c->prev = j;
	c->next = NULL;

	return c;
}

struct lcpa_metapack *lcpa_append(struct lcpa_metapack *in_pack, char *in_type,
								  int in_len, uint8_t *in_data) {
	struct lcpa_metapack *c = 
		(struct lcpa_metapack *) malloc(sizeof(struct lcpa_metapack));
	struct lcpa_metapack *i = NULL, *j = NULL;

	c->len = in_len;
	c->data = in_data;
	c->freedata = 0;
	snprintf(c->type, 24, "%s", in_type);

	j = i;
	for (i = in_pack; i != NULL; i = i->next) {
		j = i;
	}

	j->next = c;
	c->prev = j;
	c->next = NULL;

	return c;
}

struct lcpa_metapack *lcpa_insert_copy(struct lcpa_metapack *in_pack, char *in_type,
									   int in_len, uint8_t *in_data) {
	struct lcpa_metapack *c = 
		(struct lcpa_metapack *) malloc(sizeof(struct lcpa_metapack));
	
	c->len = in_len;
	c->data = (uint8_t *) malloc(in_len);
	memcpy(c->data, in_data, in_len);
	c->freedata = 1;
	snprintf(c->type, 24, "%s", in_type);

	c->next = in_pack->next;
	c->prev = in_pack;
	in_pack->next = c;

	return c;
}

struct lcpa_metapack *lcpa_insert(struct lcpa_metapack *in_pack, char *in_type,
								int in_len, uint8_t *in_data) {
	struct lcpa_metapack *c = 
		(struct lcpa_metapack *) malloc(sizeof(struct lcpa_metapack));

	c->len = in_len;
	c->data = in_data;
	snprintf(c->type, 24, "%s", in_type);

	c->next = in_pack->next;
	c->prev = in_pack;
	in_pack->next = c;

	return c;
}

struct lcpa_metapack *lcpa_find_name(struct lcpa_metapack *in_head, char *in_type) {
	struct lcpa_metapack *i = NULL;

	for (i = in_head; i != NULL; i = i->next) {
		if (!strcmp(i->type, in_type)) 
			return i;
	}

	return NULL;
}

void lcpa_replace_copy(struct lcpa_metapack *in_pack, char *in_type,
					   int in_len, uint8_t *in_data) {
	if (in_pack->freedata) {
		free(in_pack->data);
	}

	in_pack->data = (uint8_t *) malloc(in_len);
	memcpy(in_pack->data, in_data, in_len);
	in_pack->len = in_len;
	in_pack->freedata = 1;
	snprintf(in_pack->type, 24, "%s", in_type);
}

void lcpa_replace(struct lcpa_metapack *in_pack, char *in_type,
				  int in_len, uint8_t *in_data) {
	if (in_pack->freedata) {
		free(in_pack->data);
	}

	in_pack->data = in_data;
	in_pack->len = in_len;
	in_pack->freedata = 0;
	snprintf(in_pack->type, 24, "%s", in_type);
}

void lcpa_free(struct lcpa_metapack *in_head) {
	struct lcpa_metapack *i, *j;

	/* Seek to the beginning of the list */
	for (i = in_head; i->prev != NULL; i = i->prev)
		;

	j = NULL;
	for (i = i; i != NULL; i = i->next) {
		if (j == NULL) {
			j = i;
			continue;
		}

		if (j->freedata)
			free(j->data);

		free(j);

		j = i;
	}
}

int lcpa_size(struct lcpa_metapack *in_head) {
	struct lcpa_metapack *h = NULL, *i = NULL;
	int len = 0;

	/* Find the head */
	for (h = in_head; h->prev != NULL; h = h->prev) {
		;
	}
	/* Step one down */
	h = h->next;

	len = 0;

	for (i = h; i != NULL; i = i->next) {
		len += i->len;
	}

	return len;
}

void lcpa_freeze(struct lcpa_metapack *in_head, u_char *bytes) {
	struct lcpa_metapack *h = NULL, *i = NULL;
	int offt = 0;

	/* Find the head */
	for (h = in_head; h->prev != NULL; h = h->prev) {
		;
	}
	/* Step one down */
	h = h->next;

	for (i = h; i != NULL; i = i->next) {
		memcpy(&(bytes[offt]), i->data, i->len);
		offt += i->len;
	}
}


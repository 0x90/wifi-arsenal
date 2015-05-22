/*
 * OpenWIPS-ng server.
 * Copyright (C) 2011 Thomas d'Otreppe de Bouvette
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.
 *  If you modify file(s) with this exception, you may extend this exception
 *  to your version of the file(s), but you are not obligated to do so.
 *  If you do not wish to do so, delete this exception statement from your version.
 *  If you delete this exception statement from all source files in the program,
 *  then also delete it here.
 *
 *      Author: Thomas d'Otreppe de Bouvette
 */
#include <stdlib.h>
#include <string.h>
#if defined(__APPLE__) && defined(__MACH__)
	#define COMMON_DIGEST_FOR_OPENSSL
	#include <CommonCrypto/CommonDigest.h>
	#define SHA1 CC_SHA1
#else
	#include <openssl/sha.h>
#endif
#include <stdio.h>
#include "users.h"
#include "common/defines.h"

// TODO: Implement the following function + fix signature
int is_user_already_logged_in(char * user)
{
	if (STRING_IS_NULL_OR_EMPTY(user)) {
		return -1;
	}

	return 0;
}

char * get_printable_hash(char * password)
{
	unsigned char hash[SHA_DIGEST_LENGTH];
	char * ret = NULL;

	if (STRING_IS_NULL_OR_EMPTY(password)) {
		return NULL;
	}

	if (SHA1((unsigned char *)password, strlen(password) * sizeof (unsigned char), hash) != NULL) {
		ret = (char *)calloc(1, ((SHA_DIGEST_LENGTH*2) + 1) * sizeof(char));
		sprintf(ret, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
				hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7], hash[8], hash[9],
				hash[10], hash[11], hash[12], hash[13], hash[14], hash[15], hash[16], hash[17], hash[18], hash[19]);
	}

	return ret;
}

// TODO: Figure out why SHA1() result is different from sha1sum
int is_user_valid(struct userpass * userlist, char * user, char * pass, char * ip)
{
	// TODO: When loading users, convert printable hash to memory hash (less memory + faster comparison)
	char * hash_printable_hex;
	struct userpass * list = userlist;

	if (userlist == NULL || STRING_IS_NULL_OR_EMPTY(user) || STRING_IS_NULL_OR_EMPTY(pass) /*|| ip == NULL*/) {
		return -1;
	}

	while (list != NULL) {
		// Search for user
		if (strcmp(list->user, user)) {
			list = list->next;
			continue;
		}

		// hash password and check it
		hash_printable_hex = get_printable_hash(pass);
		if (hash_printable_hex != NULL) {
			if (strcmp(list->pass, hash_printable_hex) == 0) {
				// TODO: Check for IP address

				free(hash_printable_hex);
				return 1;
			}
#ifdef DEBUG
			else {
				fprintf(stderr, "Hash comparison failed for user <%s>: got <%s> expected <%s>.\n", list->user, hash_printable_hex, list->pass );
			}
#endif
			free(hash_printable_hex);
		}
		break;
	}

	return 0;
}

struct userpass * new_userpass()
{
	struct userpass * ret = (struct userpass *)malloc(sizeof(struct userpass));
	ret->allowed_ips = NULL;
	ret->nb_allowed_ips = 0;
	ret->next = NULL;
	ret->pass = NULL;
	ret->user = NULL;

	return ret;
}

int free_userpass(struct userpass ** ptr)
{
	int i;

	if (ptr == NULL || *ptr == NULL) {
		return EXIT_FAILURE;
	}

	if ((*ptr)->nb_allowed_ips != 0) {
		for (i = 0; i < (*ptr)->nb_allowed_ips; i++) {
			FREE_AND_NULLIFY((*ptr)->allowed_ips[i]);
		}
		FREE_AND_NULLIFY((*ptr)->allowed_ips);
	}

	FREE_AND_NULLIFY((*ptr)->pass);
	FREE_AND_NULLIFY((*ptr)->user);

	FREE_AND_NULLIFY(*ptr);

	return EXIT_SUCCESS;
}


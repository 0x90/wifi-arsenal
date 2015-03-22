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
 *      Author: Thomas d'Otreppe de Bouvette
 */

#ifndef USERS_H_
#define USERS_H_

struct userpass {
	char * user;
	char * pass;
	char ** allowed_ips;
	struct userpass * next;
	unsigned int nb_allowed_ips;
} * _userlist, * _sensorlist;

struct userpass * new_userpass();
int free_userpass(struct userpass ** ptr);

int is_user_already_logged_in(char * user);
int is_user_valid(struct userpass * userlist, char * user, char * pass, char * ip);
char * get_printable_hash(char * password);

#endif /* USERS_H_ */

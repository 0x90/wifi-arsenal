/*
 * OpenWIPS-ng server - common database stuff.
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

#ifndef _DB_COMMON_H
#define _DB_COMMON_H

struct database_info {
	int database_type;

#define DB_TYPE_INVALID 	-1
#define DB_TYPE_SQLITE_DISK	0
#define DB_TYPE_SQLITE_RAM	1
#define DB_TYPE_POSTGRES	2
#define DB_TYPE_ORACLE		3
#define DB_TYPE_MYSQL		4

	char * database_connection_string;
} _db_connection;

#endif /* _DB_COMMON_H */

 /* OpenWIPS-ng - * OpenWIPS-ng - Database Handler
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
 *      Author: Joel Valenzuela
 */

#ifndef DATABASE_H
#define DATABASE_H

#include "common.h"

void init_database_thread();
int start_database_thread();
void free_global_memory_database();

int database_thread(void * data);

int open_database(struct database_info * db_connection);
void close_database();

sqlite3 ** db;
pthread_t _database_thread;

#endif /* Database */


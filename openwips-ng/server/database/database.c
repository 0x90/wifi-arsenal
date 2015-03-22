/*
 * OpenWIPS-ng - Database Handler
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <pthread.h>
#include <sqlite3.h>

#include "init.h"
#include "../common/defines.h"
#include "database.h"

extern int _stop_threads;


void init_database_thread()
{
	_database_thread = PTHREAD_NULL;

	db = NULL;
}


int start_database_thread()
{
	int thread_created;

	if (_database_thread != PTHREAD_NULL) {
		return EXIT_SUCCESS;
	}

	thread_created = pthread_create(&_database_thread, NULL, (void*)&database_thread, &_db_connection);
	if (thread_created != 0) {
		fprintf(stderr, "ERROR, failed to create database thread.\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

void free_global_memory_database()
{
	close_database();
}

int database_thread(void * data)
{
	if (data == NULL) {
		// TODO: Log that we need the database connection information
		return EXIT_FAILURE;
	}

	open_database((struct database_info *)data);

	while (!_stop_threads) {
		//check_for_messages();
		//insert_into_db();

		// Make sure it doesn't use 100% CPU usage
		usleep(10);
	}

	close_database();

	// Don't free db_connection because the end variable is not a pointer

	return EXIT_SUCCESS;
}

void close_database()
{
	if (db != NULL) {
		sqlite3_close(*db);
		db = NULL;
	}
}

int open_database(struct database_info * db_connection)
{
	FILE * f;
	int sqlite_open_fd;

	if (db != NULL) {
		// Log that it is already open
		return EXIT_SUCCESS;
	}

	// Verify we can write to that location
	f = fopen(db_connection->database_connection_string, "w");
	if (f == NULL) {
		// TODO: send error message that we cannot write there
		return EXIT_FAILURE;
	}
	fclose(f);

	// Check if the file exist
	f = fopen(db_connection->database_connection_string, "r");
	if (f == NULL) {
		// Initialize it
		init_database(db_connection->database_connection_string);
	} else {
		fclose(f);
	}


	// Open it
	sqlite_open_fd = sqlite3_open(db_connection->database_connection_string, &(*db));

	if (sqlite_open_fd != SQLITE_OK) {
		fprintf(stderr, "ERROR, failed to open database: %s\n", sqlite3_errmsg(*db));
		close_database();
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}


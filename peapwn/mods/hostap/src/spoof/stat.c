/*
 * stat.c
 *
 *  Created on: Apr 29, 2014
 *      Author: netphyx
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "ap/ap_config.h"
#include "stat.h"
#include "ap/wpa_auth.h"
#include "ap/wpa_auth_i.h"
#include <sqlite3.h>


void create_tables(char* path) {
	sqlite3 *connection;
	int error = 0;
	char *errorMsg = NULL;
	const char *sql;

	error = sqlite3_open(path, &connection);
	if (error) {
		printf("Can't open credentials database. Exiting...");
		exit(0);
	}

	// Create STATS table
	sql =   "CREATE TABLE IF NOT EXISTS STATS("  \
			"id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL," \
			"type INTEGER NOT NULL," \
			"description TEXT NOT NULL," \
			"number INTEGER NOT NULL," \
			"datetime DATETIME);";

	error = sqlite3_exec(connection, sql, NULL, NULL, &errorMsg);
	if( error != SQLITE_OK ){
		printf("SQL error: %s (%d)", errorMsg, error);
		sqlite3_free(errorMsg);
	}

	// Close connection
	sqlite3_close(connection);

	printf("Created SQLite tables.\n");
}

void dump_stat(struct hostapd_data *hapd, int type, const char* description, int number) {
	sqlite3 *connection;
	int error = 0;
	char *errorMsg = NULL;
	char sql[255];

	error = sqlite3_open(hapd->conf->stat_database_path, &connection);
	if (error) {
		printf("Can't open credentials database. Exiting...");
		exit(0);
	}

	sprintf(sql, "INSERT INTO STATS VALUES(NULL, %d, '%s', %d, datetime())", type, description, number);

	error = sqlite3_exec(connection, sql, NULL, NULL, &errorMsg);
	if( error != SQLITE_OK && error != SQLITE_CONSTRAINT ){ // Not OK and not a duplicate entry
		printf("SQL error: %s (%d)", errorMsg, error);
		sqlite3_free(errorMsg);
	}

	// Close connection
	sqlite3_close(connection);
}

void store_stat(struct hostapd_data *hapd, int type, const char* description, int number) {
	// Future work. We need a hash map data structure to cache data, so we can limit disk access.
}

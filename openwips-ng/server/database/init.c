/*
 * OpenWIPS-ng -Database Initialization
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
#include <stdlib.h>
#include <sqlite3.h>
#include "init.h"

int init_database(const char * filename)
{
	sqlite3 * db = NULL;
	char * errmsg = NULL;

	int rc = sqlite3_open(filename, &db);

	if (rc != SQLITE_OK) {
		fprintf(stderr, "ERROR, failed to open database: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return EXIT_FAILURE;
	}

	// TODO: Send message "Initializing database"

#define CREATE_TABLE(table_name, sql_order) 	sqlite3_exec(db, sql_order, NULL, NULL, &errmsg); \
												if (errmsg != NULL) { \
													fprintf(stderr, "ERROR creating '%s' table in the database.\n", table_name); \
													sqlite3_free(&errmsg); \
												} \
												errmsg = NULL;

	CREATE_TABLE("message", "create table messages (message_id integer primary key autoincrement, source text, sub_source text, type integer, date_time text, read integer);");
	CREATE_TABLE("client", "create table client (client_id integer primary key autoincrement, state integer, date_time text, username text);");
	CREATE_TABLE("clients_actions", "create table clients_actions (client_id integer foreign key, command text, parameters text, data integer, date_time text);");
	CREATE_TABLE("response_type", "create table response_type (reponse_type_id integer primary key autoincrement, description text);");
	CREATE_TABLE("responses", "create table responses (reponses_id integer primary key autoincrement, response_type_id integer foreign key, date_time text, attack_id integer foreign key);");
	CREATE_TABLE("attack", "create table attack (attack_id integer primary key autoincrement, source_name text, date_time text, victim_id integer);");
	CREATE_TABLE("sensor", "create table sensor (sensor_id integer primary key autoincrement, state integer, date_time, text, mac_addr text, username text);");
	CREATE_TABLE("invalid_frames", "create table invalid_frames (sensor_id integer foreign key, fail_count integer, invalid_protocol integer);");
	CREATE_TABLE("frames", "create table frames (frame_id integer primary key autoincrement, sourceID integer, frame_type integer, frame_subtype integer, protected integer, addr_1 text, addr_2 text, addr_3 text, addr_4 text, to_dest integer, from_dest integer, retry integer, frag_num integer, seq_num integer);");
	CREATE_TABLE("banlist", "create table banlist (banlist_id integer primary key autoincrement, mac_addr text, is_AP integer, ban_creation_time text, ban_length_sec integer, is_active integer);");

#ifdef SQL_DEBUG
	sql_exec(*db, "begin;");
	sql_exec(*db, "insert into messages (source , sub_source, type, date_time, read) values ('Ape', 'Mammal', 1, 1, '9999-09-09 09:09:09.999', 1)");
	sql_exec(*db, "insert into client (state, date_time, username) values (1,'9999-09-09 09:09:09.999', 'KingKong')");
	sql_exec(*db, "insert into clients_actions (client_id, command, parameters, data, date_time) values();");
	sql_exec(*db, "insert into essid (essid,prio) select essid||'b',random() from essid;");
	sql_exec(*db, "insert into essid (essid,prio) select essid||'c',random() from essid;");
	sql_exec(*db, "insert into essid (essid,prio) select essid||'d',random() from essid;");
	sql_exec(*db, "insert into passwd (passwd) select passwd||'a' from passwd;");
	sql_exec(*db, "insert into passwd (passwd) select passwd||'b' from passwd;");
	sql_exec(*db, "insert into passwd (passwd) select passwd||'c' from passwd;");
	sql_exec(*db, "insert into passwd (passwd) select passwd||'d' from passwd;");
	sql_exec(*db, "insert into passwd (passwd) select passwd||'e' from passwd;");
	sql_exec(*db, "insert into pmk (essid_id,passwd_id) select essid_id,passwd_id from essid,passwd limit 1000000;");
	sql_exec(*db,"commit;");
#endif

	sqlite3_close(db);

	// TODO: Send message "Database initialization successful"
	return EXIT_SUCCESS;
}

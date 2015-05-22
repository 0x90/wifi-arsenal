/*
 * Reaver - SQLite wrapper functions
 * Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL. *  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so. *  If you
 *  do not wish to do so, delete this exception statement from your
 *  version. *  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#ifndef _SQL_H_
#define _SQL_H_

#include <unistd.h>
#include <string.h>
#include <sqlite3.h>
#include <libwps.h>
#include "defs.h"
#include "globule.h"

#ifndef REAVER_DATABASE
#define REAVER_DATABASE		"/etc/reaver/reaver.db"
#endif

#define BUSY_WAIT_PERIOD	100
#define SETTINGS_TABLE		"auto"
#define HISTORY_TABLE		"history"
#define AP_TABLE		"survey"
#define DROP_TABLE		"DROP TABLE %s"
#define CREATE_TABLE		"CREATE TABLE %s (bssid TEXT PRIMARY KEY NOT NULL, essid TEXT, manufacturer TEXT, model_name TEXT, model_number TEXT, device_name TEXT, version INTEGER DEFAULT 0, state INTEGER DEFAULT 0, locked INTEGER DEFAULT 0, encryption INTEGER DEFAULT 0, probes INTEGER DEFAULT 0, rssi TEXT, complete INTEGER DEFAULT 0, rowid INTEGER NOT NULL)"

int sql_init(void);
int create_ap_table(void);
int update_probe_count(char *bssid);
int update_ap_power(char *bssid, int8_t ssi);
int update_history(char *bssid, char *essid, int attempts, char *key);
int mark_ap_complete(char *bssid);
int is_done(char *bssid);
int should_probe(char *bssid);
int update(char *bssid, char *essid, struct libwps_data *wps, int encryption);
int insert(char *bssid, char *essid, struct libwps_data *wps, int encryption, int rssi);
char *get_db_ssid(char *bssid);
char **auto_detect_settings(char *bssid, int *argc);
int sql_exec(char *query);
void *get(char *query, int *result_size, int *err_code);
char *sql_error_string(void);
void sql_cleanup(void);

#endif

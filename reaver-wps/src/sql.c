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

#include "sql.h"

sqlite3 *db = NULL;

int sql_init(void)
{
	int retval = 0;

	if(!db)
	{
		if(sqlite3_open(REAVER_DATABASE, &db) == 0)
		{
			retval = 1;
		}
	}

	return retval;
}

int create_ap_table(void)
{
	int err_code = 0;
	char *drop_table = sqlite3_mprintf(DROP_TABLE, AP_TABLE);
	char *create_table = sqlite3_mprintf(CREATE_TABLE, AP_TABLE);

	if(db && drop_table && create_table)
	{
		sql_exec(drop_table);
		err_code = sql_exec(create_table);
	
		sqlite3_free(drop_table);
		sqlite3_free(create_table);
	}

	return err_code;
}

int should_probe(char *bssid)
{
	int n = 0, yn = 0, size = 0, err = 0, max = get_max_num_probes();
	char *ns = NULL;
	char *q = sqlite3_mprintf("SELECT probes FROM %s WHERE bssid = %Q AND complete = 0", AP_TABLE, bssid);

	if(q)
	{
		ns = get(q, &size, &err);
		if(err == SQLITE_OK && ns && size > 0)
		{
			n = atoi(ns);
		}

		if(max == 0 || n < max)
		{
			yn = 1;
		}

		sqlite3_free(q);
	}

	if(ns) free(ns);
	return yn;
}

int is_done(char *bssid)
{
	int size = 0, err = 0, rv = 0;
	char *s = NULL, *q = sqlite3_mprintf("SELECT complete FROM %s WHERE bssid = %Q", AP_TABLE, bssid);

	if(q)
	{
		s = get(q, &size, &err);

		if(err == SQLITE_OK && size > 0 && s != NULL)
		{
			rv = atoi(s);
			free(s);
		}

		sqlite3_free(q);
	}

	return rv;
}

int mark_ap_complete(char *bssid)
{
	int rv = 0;
	char *q = sqlite3_mprintf("UPDATE %s SET probes = '%d', complete = '1' WHERE bssid = %Q", AP_TABLE, get_max_num_probes(), bssid);

	if(q)
	{
		if(sql_exec(q) == SQLITE_OK)
		{
			rv = 1;
		}

		sqlite3_free(q);
	}

	return rv;
}

int update_probe_count(char *bssid)
{
	int rv = 0;
	char *q = sqlite3_mprintf("UPDATE %s SET probes = probes+1 WHERE bssid = %Q", AP_TABLE, bssid);

	if(q)
	{
		if(sql_exec(q) == SQLITE_OK)
		{
			rv = 1;
		}

		sqlite3_free(q);
	}

	return rv;
}

int update_ap_power(char *bssid, int8_t ssi)
{
	int rv = 0;
	char *q = sqlite3_mprintf("UPDATE %s SET rssi = '%d' WHERE bssid = %Q", AP_TABLE, ssi, bssid);

	if(q)
	{
		if(sql_exec(q) == SQLITE_OK)
		{
			rv = 1;
		}

		sqlite3_free(q);
	}
	
	return rv;
}

int update_history(char *bssid, char *essid, int attempts, char *key)
{
	int result = 0;
	char *q = sqlite3_mprintf("INSERT OR REPLACE INTO %s (bssid, essid, attempts, key) VALUES (%Q, %Q, '%d', %Q)", HISTORY_TABLE, bssid, essid, attempts, key);

	if(q)
	{
		if(sql_exec(q) == SQLITE_OK)
		{
			result = 1;
		}

		sqlite3_free(q);
	}
	
	return result;
}

int insert(char *bssid, char *essid, struct libwps_data *wps, int encryption, int rssi)
{
	int result = 0;
	char *q = sqlite3_mprintf("INSERT INTO %s (bssid, essid, manufacturer, model_name, model_number, device_name, version, state, locked, encryption, probes, rssi, rowid) VALUES (%Q, %Q, %Q, %Q, %Q, %Q, '%d', '%d', '%d', '%d', '0', '%d', '%d')", AP_TABLE, bssid, essid, wps->manufacturer, wps->model_name, wps->model_number, wps->device_name, wps->version, wps->state, wps->locked, encryption, rssi, sqlite3_last_insert_rowid(db));

	if(q)
	{
		if(sql_exec(q) == SQLITE_OK)
		{
			result = 1;
		}

		sqlite3_free(q);
	}

	return result;
}

int update(char *bssid, char *essid, struct libwps_data *wps, int encryption)
{
	int result = 0;
	char *q = NULL;

	if(wps)
	{
		q = sqlite3_mprintf("UPDATE %s SET essid = %Q, manufacturer = %Q, model_name = %Q, model_number = %Q, device_name = %Q, version ='%d', state = '%d', locked = '%d', encryption = '%d' WHERE bssid = %Q AND complete <> '1'", AP_TABLE, essid, wps->manufacturer, wps->model_name, wps->model_number, wps->device_name, wps->version, wps->state, wps->locked, encryption, bssid);

		if(q)
		{
			if(sql_exec(q) == SQLITE_OK)
			{
				result = 1;
			}

			sqlite3_free(q);
		}
	}
	
	return result;
}

int sql_exec(char *query)
{
	int result = SQLITE_ERROR;

	if(query)
	{
		do
		{
			result = sqlite3_exec(db, query, NULL, NULL, NULL);
			usleep(BUSY_WAIT_PERIOD);
		} 
		while(result == SQLITE_BUSY);
	}

	return result;
}

char *get_db_ssid(char *bssid)
{
	char *ssid = NULL;
	int size = 0, err = 0;
	char *q = sqlite3_mprintf("SELECT essid FROM %s WHERE bssid = %Q LIMIT 1", AP_TABLE, bssid);

	if(q)
	{
		ssid = (char *) get(q, &size, &err);
		if(err != SQLITE_OK || size < 0)
		{
			if(ssid) free(ssid);
			ssid = NULL;
		}

		sqlite3_free(q);
	}

	return ssid;
}

char **auto_detect_settings(char *bssid, int *argc)
{
	int size = 0, err = 0, i = 0;
	char *args = NULL, *token = NULL;
	char **argv = NULL, **tmp = NULL;
	char *q1 = sqlite3_mprintf("SELECT args FROM %s WHERE model_name = (SELECT model_name FROM %s WHERE bssid = %Q LIMIT 1) AND model_number = (SELECT model_number FROM %s WHERE bssid = %Q LIMIT 1) AND device_name = (SELECT device_name FROM %s WHERE bssid = %Q LIMIT 1) LIMIT 1", SETTINGS_TABLE, AP_TABLE, bssid, AP_TABLE, bssid, AP_TABLE, bssid);
	char *q2 = sqlite3_mprintf("SELECT args FROM %s WHERE manufacturer LIKE (SELECT manufacturer FROM %s WHERE bssid = %Q LIMIT 1) LIMIT 1", SETTINGS_TABLE, AP_TABLE, bssid);

	if(q1 && q2)
	{
		args = (char *) get(q1, &size, &err);
		if(err != SQLITE_OK || size <= 0 || args == NULL)
		{
			args = (char *) get(q2, &size, &err);
		}

		if(err == SQLITE_OK && size > 0 && args != NULL)
		{
			token = strtok(args, " ");
			if(token)
			{
				argv = malloc(sizeof(char *));
				argv[i] = strdup("reaver");
				i++;

				do
				{
					tmp = argv;
					argv = realloc(argv, ((i + 1) * sizeof(char *)));
					if(!argv)
					{
						free(tmp);
						i = 0;
						break;
					}
					else if(argv != tmp)
					{
						free(tmp);
					}

					argv[i] = strdup(token);
					i++;
					
				} while((token = strtok(NULL, " ")) != NULL);
			}

			free(args);
		}

		sqlite3_free(q1);
		sqlite3_free(q2);
	}

	*argc = i;

	return argv;
}

/* Execute given SQL query. Will only return the FIRST row of the FIRST column of data. Caller must free the returned pointer. */
void *get(char *query, int *result_size, int *err_code)
{
        sqlite3_stmt *stmt = NULL;
        int rc = 0, col_type = 0;
        void *result = NULL, *tmp_result = NULL;

        *result_size = 0;

        if(!query){
                return NULL;
        }

        /* Prepare the SQL query */
        rc = sqlite3_prepare_v2(db,query,strlen(query),&stmt,NULL);
        if(rc != SQLITE_OK){
                *err_code = sqlite3_errcode(db);
                return NULL;
        }

        /* Loop until the query has finished */
        while(((rc = sqlite3_step(stmt)) != SQLITE_DONE) && (result == NULL)){
                switch(rc){

                        case SQLITE_ERROR:
                                *err_code = sqlite3_errcode(db);
                                sqlite3_finalize(stmt);
                                return NULL;
                                break;

                        case SQLITE_BUSY:
                                /* If the table is locked, wait then try again */
                                usleep(BUSY_WAIT_PERIOD);
                                break;

                        case SQLITE_ROW:
                        {
                                col_type = sqlite3_column_type(stmt,0);
                                switch(col_type)
                                {
                                        case SQLITE_TEXT:
                                        case SQLITE_INTEGER:
                                                tmp_result = (void *) sqlite3_column_text(stmt,0);
                                                break;
                                        
                                        case SQLITE_BLOB:
                                                tmp_result = (void *) sqlite3_column_blob(stmt,0);
                                                break;
                                        
                                        default:
                                                continue;
                                }

                                /* Get the size of the data we just received from the database */
                                *result_size = sqlite3_column_bytes(stmt,0);

                                /* Create a copy of tmp_result to pass back to the caller */
                                if((tmp_result != NULL) && (*result_size > 0)){
                                        if((result = malloc(*result_size+1)) == NULL){
                                                perror("Malloc failure");
                                                return NULL;
                                        }
                                        memset(result,0,*result_size+1);
                                        memcpy(result,tmp_result,*result_size);
                                }
                                break;
                        }
                }
        }

        sqlite3_finalize(stmt);
        *err_code = sqlite3_errcode(db);        

        return result;
}

char *sql_error_string(void)
{
	return (char *) sqlite3_errmsg(db);
}

void sql_cleanup(void)
{
	sqlite3_close(db);
	db = NULL;
}

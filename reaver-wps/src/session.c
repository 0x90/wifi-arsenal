/*
 * Reaver - Session save/restore functions
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

#include "session.h"

int restore_session()
{
	struct stat wpstat = { 0 };
	char line[MAX_LINE_SIZE] = { 0 };
	char temp[P1_READ_LEN] = { 0 };
	char *file = NULL;
	unsigned char *bssid = NULL;
	char answer = 0;
	FILE *fp = NULL;
	int ret_val = 0, i = 0;

	/* 
	 * If a session file was explicitly specified, use that; else, check for the 
	 * default session file name for this BSSID.
	 */
	if(get_session())
	{
		file = strdup(get_session());
	}
	else
	{
		file = malloc(FILENAME_MAX);
		if(!file)
		{
			return ret_val;
		}
		memset(file, 0, FILENAME_MAX);

		bssid = mac2str(get_bssid(), '\0');
		snprintf(file, FILENAME_MAX, "%s/%s.%s", CONF_DIR, bssid, CONF_EXT);
		free(bssid);
	}

	/*
	 * If a session was explicitly specified, or if the auto detect option was specified,
	 * then the answer to any of the following questions will be 'yes'.
	 */
	if(get_session() || get_auto_detect_options())
	{
		answer = 'y';
	}

	if(stat(file, &wpstat) == 0)
	{
		/* If the user explicitly specified a session file, don't prompt them */
		if(answer == 0)
		{
			bssid = mac2str(get_bssid(), ':');

			/* Don't use cprintf here; else, if the output is sent to a file via -o, the user won't see this prompt. */
			fprintf(stderr, "[?] Restore previous session for %s? [n/Y] ", bssid);
			answer = getc(stdin);
			free(bssid);
		}
	
		if(answer == 'y' || answer == 'Y' || answer == '\n')
		{
			if((fp = fopen(file, "r")))
			{
				/* Get the key1 index value */
				if(fgets((char *) &line, MAX_LINE_SIZE, fp) != NULL)
				{
					set_p1_index(atoi(line));
					memset((char *) &line, 0, MAX_LINE_SIZE);
	
					/* Get the key2 index value */
					if(fgets((char *) &line, MAX_LINE_SIZE, fp) != NULL)
					{
						set_p2_index(atoi(line));
						memset((char *) &line, 0, MAX_LINE_SIZE);
				
						/* Get the key status value */
						if(fgets((char *) &line, MAX_LINE_SIZE, fp) != NULL)
						{
							set_key_status(atoi(line));

							/* Read in all p1 values */
							for(i=0; i<P1_SIZE; i++)
							{
								memset((char *) &temp, 0, P1_READ_LEN);

								if(fgets((char *) &temp, P1_READ_LEN, fp) != NULL)
								{
									/* NULL out the new line character */
									temp[P1_STR_LEN] = 0;
									set_p1(i, (char *) &temp);
								}
							}

							/* Read in all p2 values */
							for(i=0; i<P2_SIZE; i++)
							{
								memset((char *) &temp, 0, P1_READ_LEN);

								if(fgets((char *) &temp, P2_READ_LEN, fp) != NULL)
								{
									/* NULL out the new line character */
									temp[P2_STR_LEN] = 0;
									set_p2(i, (char *) &temp);
								}
							}

							ret_val = 1;
						}
					}
				}
		
				fclose(fp);
			}
			else
			{
				perror("fopen");
			}
		}
	}

	if(!ret_val)
	{
		set_p1_index(0);
		set_p2_index(0);
		set_key_status(KEY1_WIP);
	} else {
		cprintf(INFO, "[+] Restored previous session\n");
	}

	free(file);
	return ret_val;
}

int save_session()
{
	unsigned char *bssid = NULL;
	char *wpa_key = NULL, *essid = NULL, *pretty_bssid = NULL;
        char file_name[FILENAME_MAX] = { 0 };
        char line[MAX_LINE_SIZE] = { 0 };
        FILE *fp = NULL;
	size_t write_size = 0;
        int attempts = 0, ret_val = 0, i = 0;
	struct wps_data *wps = NULL;

	wps = get_wps();
	bssid = mac2str(get_bssid(), '\0');
	pretty_bssid = (char *) mac2str(get_bssid(), ':');

	if(wps)
	{
		wpa_key = wps->key;
		essid = wps->essid;
	}
	
	if(!bssid || !pretty_bssid)
	{
		cprintf(CRITICAL, "[X] ERROR: Failed to save session data (memory error).\n");
	}
	else
	{
		/* 
		 * If a session file was explicitly specified, use that; else, check for the 
		 * default session file name for this BSSID.
		 */
		if(get_session())
		{
			memcpy((char *) &file_name, get_session(), FILENAME_MAX-1);
		}
		else
		{	
			/* 
			 * If the configuration directory exists, save the session file there; else, save it to the 
			 * current working directory.
			 */
			if(configuration_directory_exists())
			{
        			snprintf((char *) &file_name, FILENAME_MAX, "%s/%s.%s", CONF_DIR, bssid, CONF_EXT);
			}
			else
			{
				snprintf((char *) &file_name, FILENAME_MAX, "%s.%s", bssid, CONF_EXT);
			}
		}

		/* Don't bother saving anything if nothing has been done */
		if((get_p1_index() > 0) || (get_p2_index() > 0))
		{
			if((fp = fopen((char *) &file_name, "w")))
			{
				snprintf((char *) &line, MAX_LINE_SIZE, "%d\n", get_p1_index());
				write_size = strlen((char *) &line);

				/* Save key1 index value */
				if(fwrite((char *) &line, 1, write_size, fp) == write_size)
				{
					memset((char *) &line, 0, MAX_LINE_SIZE);
					snprintf((char *) &line, MAX_LINE_SIZE, "%d\n", get_p2_index());
					write_size = strlen((char *) &line);

					/* Save key2 index value */
					if(fwrite((char *) &line, 1, write_size, fp) == write_size)
					{
						memset((char *) &line, 0, MAX_LINE_SIZE);
        		                	snprintf((char *) &line, MAX_LINE_SIZE, "%d\n", get_key_status());
        		                	write_size = strlen((char *) &line);
	
						/* Save key status value */
						if(fwrite((char *) &line, 1, write_size, fp) == write_size)
						{
							/* Save all the p1 values */
							for(i=0; i<P1_SIZE; i++)
							{
								fwrite(get_p1(i), 1, strlen(get_p1(i)), fp);
								fwrite("\n", 1, 1, fp);
							}

							/* Save all the p2 values */
							for(i=0; i<P2_SIZE; i++)
							{
								fwrite(get_p2(i), 1, strlen(get_p2(i)), fp);
								fwrite("\n", 1, 1, fp);
							}

							/* If we have the WPA key, then we've exhausted all attempts, and the UI should reflect that */
							if(wpa_key && strlen(wpa_key) > 0)
							{
								attempts = P1_SIZE + P2_SIZE;
							}
							else
							{
								if(get_key_status() == KEY1_WIP)
								{
									attempts = get_p1_index() + get_p2_index();
								}
								else if(get_key_status() == KEY2_WIP)
								{
									attempts = P1_SIZE + get_p2_index();
								}
							}

							/* If we got an SSID from the WPS data, then use that; else, use whatever was used to associate with the AP */
							if(!essid || strlen(essid) < 0)
							{
								essid = get_ssid();
							}

							update_history(pretty_bssid, essid, attempts, wpa_key);

							ret_val = 1;
						}
					}
				}
				
				fclose(fp);
			}
		}
		else
		{
			cprintf(VERBOSE, "[+] Nothing done, nothing to save.\n");
		}
		
		free(bssid);
		free(pretty_bssid);
	}

	return ret_val;
}

/* Does the configuration directory exist? Returns 1 for yes, 0 for no. */
int configuration_directory_exists()
{
	struct stat dirstat = { 0 };
	int retval = 0;

	if(stat(CONF_DIR, &dirstat) == 0)
	{
		retval = 1;
	}

	return retval;
}

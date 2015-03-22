/*
 * Reaver - Main and usage functions
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

#include "wpscrack.h"

int main(int argc, char **argv)
{
    int ret_val = EXIT_FAILURE, r = 0;
    time_t start_time = 0, end_time = 0;
    struct wps_data *wps = NULL;

    globule_init();
    sql_init();
    init_default_settings();

    fprintf(stderr, "\nReaver v%s WiFi Protected Setup Attack Tool\n", PACKAGE_VERSION);
    fprintf(stderr, "Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>\n\n");

    if(argc < 2)
    {
        ret_val = usage(argv[0]);
        goto end;
    }

    /* Process the command line arguments */
    if(process_arguments(argc, argv) == EXIT_FAILURE)
    {
        ret_val = usage(argv[0]);
        goto end;
    }

    /* Double check usage */
    if(!get_iface() || (memcmp(get_bssid(), NULL_MAC, MAC_ADDR_LEN) == 0))
    {
        usage(argv[0]);
        goto end;
    }

    /* If no MAC address was provided, get it ourselves */
    if(memcmp(get_mac(), NULL_MAC, MAC_ADDR_LEN) == 0)
    {
        if(!read_iface_mac())
        {
            fprintf(stderr, "[-] Failed to retrieve a MAC address for interface '%s'!\n", get_iface());
            goto end;
        }
    }

    /* Sanity checking on the message timeout value */	
    if(get_m57_timeout() > M57_MAX_TIMEOUT) 
    {
        set_m57_timeout(M57_MAX_TIMEOUT);
    }
    else if(get_m57_timeout() <= 0)
    {
        set_m57_timeout(M57_DEFAULT_TIMEOUT);
    }

    /* Sanity checking on the receive timeout value */
    if(get_rx_timeout() <= 0)
    {
        set_rx_timeout(DEFAULT_TIMEOUT);
    }

    /* Initialize signal handlers */
    sigint_init();
    sigalrm_init();

    /* Mark the start time */
    start_time = time(NULL);

    /* Do it. */
    crack();

    /* Mark the end time */
    end_time = time(NULL);

    /* Check our key status */
    if(get_key_status() == KEY_DONE)
    {
        wps = get_wps();

        cprintf(VERBOSE,  		    "[+] Pin cracked in %d seconds\n", (int) (end_time - start_time));
        cprintf(CRITICAL, 		    "[+] WPS PIN: '%s'\n", get_pin());
        if(wps->key)      cprintf(CRITICAL, "[+] WPA PSK: '%s'\n", wps->key);
        if(wps->essid)    cprintf(CRITICAL, "[+] AP SSID: '%s'\n", wps->essid);

        /* Run user-supplied command */
        if(get_exec_string())
        {
            r = system(get_exec_string());
        }

        ret_val = EXIT_SUCCESS;
    }
    else 
    {
        cprintf(CRITICAL, "[-] Failed to recover WPA key\n");
    }

    save_session();

end:
    globule_deinit();
    return ret_val;
}

int usage(char *prog_name)
{
    float fail_timeout = 0;

    fail_timeout = ((float) M57_DEFAULT_TIMEOUT / (float) SEC_TO_US);

    fprintf(stderr, "Required Arguments:\n");
    fprintf(stderr, "\t-i, --interface=<wlan>          Name of the monitor-mode interface to use\n");
    fprintf(stderr, "\t-b, --bssid=<mac>               BSSID of the target AP\n");

    fprintf(stderr, "\nOptional Arguments:\n");
    fprintf(stderr, "\t-m, --mac=<mac>                 MAC of the host system\n");
    fprintf(stderr, "\t-e, --essid=<ssid>              ESSID of the target AP\n");
    fprintf(stderr, "\t-c, --channel=<channel>         Set the 802.11 channel for the interface (implies -f)\n");
    fprintf(stderr, "\t-o, --out-file=<file>           Send output to a log file [stdout]\n");
    fprintf(stderr, "\t-s, --session=<file>            Restore a previous session file\n");
    fprintf(stderr, "\t-C, --exec=<command>            Execute the supplied command upon successful pin recovery\n");
    fprintf(stderr, "\t-D, --daemonize                 Daemonize reaver\n");
    fprintf(stderr, "\t-a, --auto                      Auto detect the best advanced options for the target AP\n");
    fprintf(stderr, "\t-f, --fixed                     Disable channel hopping\n");
    fprintf(stderr, "\t-5, --5ghz                      Use 5GHz 802.11 channels\n");
    fprintf(stderr, "\t-v, --verbose                   Display non-critical warnings (-vv for more)\n");
    fprintf(stderr, "\t-q, --quiet                     Only display critical messages\n");
    fprintf(stderr, "\t-h, --help                      Show help\n");

    fprintf(stderr, "\nAdvanced Options:\n");
    fprintf(stderr, "\t-p, --pin=<wps pin>             Use the specified 4 or 8 digit WPS pin\n");
    fprintf(stderr, "\t-d, --delay=<seconds>           Set the delay between pin attempts [%d]\n", DEFAULT_DELAY);
    fprintf(stderr, "\t-l, --lock-delay=<seconds>      Set the time to wait if the AP locks WPS pin attempts [%d]\n", DEFAULT_LOCK_DELAY);
    fprintf(stderr, "\t-g, --max-attempts=<num>        Quit after num pin attempts\n");
    fprintf(stderr, "\t-x, --fail-wait=<seconds>       Set the time to sleep after %d unexpected failures [0]\n", WARN_FAILURE_COUNT);
    fprintf(stderr, "\t-r, --recurring-delay=<x:y>     Sleep for y seconds every x pin attempts\n");
    fprintf(stderr, "\t-t, --timeout=<seconds>         Set the receive timeout period [%d]\n", DEFAULT_TIMEOUT);
    fprintf(stderr, "\t-T, --m57-timeout=<seconds>     Set the M5/M7 timeout period [%.2f]\n", fail_timeout);
    fprintf(stderr, "\t-A, --no-associate              Do not associate with the AP (association must be done by another application)\n");
    fprintf(stderr, "\t-N, --no-nacks                  Do not send NACK messages when out of order packets are received\n");
    fprintf(stderr, "\t-S, --dh-small                  Use small DH keys to improve crack speed\n");
    fprintf(stderr, "\t-L, --ignore-locks              Ignore locked state reported by the target AP\n");
    fprintf(stderr, "\t-E, --eap-terminate             Terminate each WPS session with an EAP FAIL packet\n");
    fprintf(stderr, "\t-n, --nack                      Target AP always sends a NACK [Auto]\n");
    fprintf(stderr, "\t-w, --win7                      Mimic a Windows 7 registrar [False]\n");
    fprintf(stderr, "\t-X, --exhaustive                Set exhaustive mode from the beginning of the session [False]\n");
    fprintf(stderr, "\t-1, --p1-index                  Set initial array index for the first half of the pin [False]\n");
    fprintf(stderr, "\t-2, --p2-index                  Set initial array index for the second half of the pin [False]\n");

    fprintf(stderr, "\nExample:\n\t%s -i mon0 -b 00:90:4C:C1:AC:21 -vv\n\n", prog_name);

    return EXIT_FAILURE;
}


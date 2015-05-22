/*
 * Reaver - Command line processing functions
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

#include "argsparser.h"

/* Processes Reaver command line options */
int process_arguments(int argc, char **argv)
{
    int ret_val = EXIT_SUCCESS;
    int c = 0, channel = 0;
    int long_opt_index = 0;
    char bssid[MAC_ADDR_LEN] = { 0 };
    char mac[MAC_ADDR_LEN] = { 0 };
    char *short_options = "b:e:m:i:t:d:c:T:x:r:g:l:o:p:s:C:1:2:aA5ELfnqvDShwXN";
    struct option long_options[] = {
        { "interface", required_argument, NULL, 'i' },
        { "bssid", required_argument, NULL, 'b' },
        { "essid", required_argument, NULL, 'e' },
        { "mac", required_argument, NULL, 'm' },
        { "timeout", required_argument, NULL, 't' },
        { "m57-timeout", required_argument, NULL, 'T' },
        { "delay", required_argument, NULL, 'd' },
        { "lock-delay", required_argument, NULL, 'l' },
        { "fail-wait", required_argument, NULL, 'x' },
        { "channel", required_argument, NULL, 'c' },
        { "session", required_argument, NULL, 's' },
        { "recurring-delay", required_argument, NULL, 'r' },
        { "max-attempts", required_argument, NULL, 'g' },
        { "out-file", required_argument, NULL, 'o' },
        { "pin", required_argument, NULL, 'p' },
        { "exec", required_argument, NULL, 'C' },
        { "p1-index", required_argument, NULL, '1' },
        { "p2-index", required_argument, NULL, '2' },
        { "no-associate", no_argument, NULL, 'A' },
        { "ignore-locks", no_argument, NULL, 'L' },
        { "no-nacks", no_argument, NULL, 'N' },
        { "eap-terminate", no_argument, NULL, 'E' },
        { "dh-small", no_argument, NULL, 'S' },
        { "auto", no_argument, NULL, 'a' },
        { "fixed", no_argument, NULL, 'f' },
        { "daemonize", no_argument, NULL, 'D' },
        { "5ghz", no_argument, NULL, '5' },
        { "nack", no_argument, NULL, 'n' },
        { "quiet", no_argument, NULL, 'q' },
        { "verbose", no_argument, NULL, 'v' },
        { "win7", no_argument, NULL, 'w' },
        { "exhaustive", no_argument, NULL, 'X' },
        { "help", no_argument, NULL, 'h' },
        { 0, 0, 0, 0 }
    };

    /* Since this function may be called multiple times, be sure to set opt index to 0 each time */
    optind = 0;

    while((c = getopt_long(argc, argv, short_options, long_options, &long_opt_index)) != -1)
    {
        switch(c)
        {
            case 'i':
                set_iface(optarg);
                break;
            case 'b':
                str2mac((unsigned char *) optarg, (unsigned char *) &bssid);
                set_bssid((unsigned char *) &bssid);
                break;
            case 'e':
                set_ssid(optarg);
                break;
            case 'm':
                str2mac((unsigned char *) optarg, (unsigned char *) &mac);
                set_mac((unsigned char *) &mac);
                break;
            case 't':
                set_rx_timeout(atoi(optarg));
                break;
            case 'T':
                set_m57_timeout(strtof(optarg, NULL) * SEC_TO_US);
                break;
            case 'c':
                channel = strtod(optarg, NULL);
                set_fixed_channel(1);
                break;
            case '5':
                set_wifi_band(AN_BAND);
                break;
            case 'd':
                set_delay(atoi(optarg));
                break;
            case 'l':
                set_lock_delay(atoi(optarg));
                break;
            case 'p':
                parse_static_pin(optarg);
                break;
            case 's':       
                set_session(optarg);   
                break;
            case 'C':
                set_exec_string(optarg);
                break;
            case '1':
                set_p1_index(atoi(optarg));
                break;
            case '2':
                set_p2_index(atoi(optarg));
                break;
            case 'A':
                set_external_association(1);
                break;
            case 'L':
                set_ignore_locks(1);
                break;
            case 'a':       
                set_auto_detect_options(1); 
                break;
            case 'o':
                set_log_file(fopen(optarg, "w"));
                break;
            case 'x':
                set_fail_delay(atoi(optarg));
                break;
            case 'r':
                parse_recurring_delay(optarg);
                break;
            case 'g':
                set_max_pin_attempts(atoi(optarg));
                break;
            case 'D':
                daemonize();
                break;
            case 'E':
                set_eap_terminate(1);
                break;
            case 'S':
                set_dh_small(1);
                break;
            case 'n':
                set_timeout_is_nack(0);
                break;
            case 'f':
                set_fixed_channel(1);
                break;
            case 'v':
                set_debug(get_debug() + 1);
                break;
            case 'q':
                set_debug(CRITICAL);
                break;
            case 'w':
                set_win7_compat(1);
                break;
            case 'X':
                set_exhaustive(1);
                break;
            case 'N':
                set_oo_send_nack(0);
                break;
            default:
                ret_val = EXIT_FAILURE;
        }
    }

    if(channel)
    {
        change_channel(channel);
    }

    return ret_val;
}

/* Initialize some basic config settings */
void init_default_settings(void)
{
    set_log_file(stdout);
    set_max_pin_attempts(P1_SIZE + P2_SIZE);
    set_delay(DEFAULT_DELAY);
    set_lock_delay(DEFAULT_LOCK_DELAY);
    set_key_status(KEY1_WIP);
    set_debug(INFO);
    set_auto_channel_select(1);
    set_timeout_is_nack(1);
    set_oo_send_nack(1);
    set_wifi_band(BG_BAND);
    set_p1_index(0);
    set_p2_index(0);
}

/* Parses the recurring delay optarg */
void parse_recurring_delay(char *arg)
{
    char *x = NULL, *y = NULL;

    x = strdup(arg);
    y = strchr(x, ':');

    if(y)
    {
        memset(y, 0, 1);
        y++;

        set_recurring_delay_count(atoi(x));
        set_recurring_delay(atoi(y));
    }

    free(x);
}

/* Parse the WPS pin to use into p1 and p2 */
void parse_static_pin(char *pin)
{
    int len = 0;
    char p1[5] = { 0 };
    char p2[4] = { 0 };

    if(pin)
    {
        len = strlen(pin);

        if(len == 4 || len == 7 || len == 8)
        {
            memcpy((void *) &p1, pin, sizeof(p1)-1);
            set_static_p1((char *) &p1);
            set_key_status(KEY2_WIP);

            if(len > 4)
            {
                memcpy((void *) &p2, pin+sizeof(p1)-1, sizeof(p2)-1);
                set_static_p2((char *) &p2);
            }
        }
        else
        {
            cprintf(CRITICAL, "[X] ERROR: Invalid pin specified! Ignoring '%s'.\n", pin);
        }
    }
}

/* Process auto-applied options from the database. read_ap_beacon should be called before this. */
void process_auto_options(void)
{
    char **argv = NULL;
    int argc = 0, i = 0;
    char *bssid = NULL, *ssid = NULL;

    if(get_auto_detect_options())
    {
        bssid = (char *) mac2str(get_bssid(), ':');


        if(bssid)
        {
            /* If we didn't get the SSID from the beacon packet, check the database */
            if(get_ssid() == NULL)
            {
                ssid = get_db_ssid(bssid);
                if(ssid)
                {
                    set_ssid(ssid);
                    free(ssid);
                }
            }

            argv = auto_detect_settings(bssid, &argc);
            if(argc > 1 && argv != NULL)
            {
                /* Process the command line arguments */
                process_arguments(argc, argv);

                /* Clean up argument memory allocation */
                for(i=0; i<argc; i++)
                {
                    free(argv[i]);
                }
                free(argv);
            }

            free(bssid);
        }
    }

    return;
}

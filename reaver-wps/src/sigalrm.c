/*
 * Reaver - Sigalrm handler functions
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

#include "sigalrm.h"

/* Initializes SIGALRM handler */
void sigalrm_init()
{
        struct sigaction act;

        memset(&act, 0, sizeof(struct sigaction));
        act.sa_handler = alarm_handler;

        sigaction (SIGALRM, &act, 0);
}

/* Starts receive timer. Called from send_packet() after a packet is trasmitted */
void start_timer()
{
        struct itimerval timer;
	struct wps_data *wps = get_wps();

        memset(&timer, 0, sizeof(struct itimerval));

        /* 
	 * The M5 and M7 messages have very fast turn around times -
         * typically a few hundreths of a second. We don't want to wait
         * around forever to see if we get them or not, so use a short
         * timeout value when waiting for those messages.
	 * Ignore this timeout if we know the AP responds with NACKs when
	 * the wrong pin is supplied instead of not responding at all.
         */
        if(get_timeout_is_nack() &&
	  (wps->state == RECV_M5 || wps->state == RECV_M7))
	{
                timer.it_value.tv_usec = get_m57_timeout();
        }
        else
        {
                /* 
		 * Other messages may take up to 2 seconds to respond - 
                 * wait a little longer for them.
                 */
                timer.it_value.tv_sec = get_rx_timeout();
        }

	set_out_of_time(0);

        setitimer(ITIMER_REAL, &timer, 0);
}

/* Timer is stopped by process_packet() when any valid EAP packet is received */
void stop_timer()
{
        struct itimerval timer;

	set_out_of_time(0);

        memset(&timer, 0, sizeof(struct itimerval));

        setitimer(ITIMER_REAL, &timer, 0);
}

/* Handles SIGALRM interrupts */
void alarm_handler(int x)
{
	set_out_of_time(1);
	cprintf(VERBOSE, "[!] WARNING: Receive timeout occurred\n");
}


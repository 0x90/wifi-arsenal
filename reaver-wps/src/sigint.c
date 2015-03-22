/*
 * Reaver - Sigint handler functions
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

#include "sigint.h"

/* Initializes SIGINT handler */
void sigint_init()
{
	struct sigaction act;

        memset(&act, 0, sizeof(struct sigaction));
        act.sa_handler = sigint_handler;

        sigaction (SIGINT, &act, 0);

	return;
}

/* Handles Ctrl+C */
void sigint_handler(int x)
{
	/* If we have initiated a WPS exchange, try to end it before quitting */
	if(get_wps() != NULL)
	{
		send_termination();
	}

	/* 
	 * This is just here because I get annoyed when the terminal displays the
	 * '^C' on the same line as my intentional output.
	 */
	printf("\n");
	fflush(stdout);

	/* Save our session */
	if(save_session())
	{
		cprintf(INFO, "[+] Session saved.\n");
	}

	/* Clean up and get out */
	globule_deinit();
	exit(EXIT_FAILURE);
}

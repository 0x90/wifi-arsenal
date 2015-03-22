/* horst - Highly Optimized Radio Scanning Tool
 *
 * Copyright (C) 2005-2014 Bruno Randolf (br1@einfach.org)
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
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <err.h>

#include "main.h"
#include "channel.h"
#include "control.h"
#include "conf_options.h"

#define MAX_CMD 255

/* FIFO (named pipe) */

int ctlpipe = -1;

void
control_init_pipe(void)
{
	mkfifo(conf.control_pipe, 0666);
	ctlpipe = open(conf.control_pipe, O_RDWR|O_NONBLOCK);
}


void
control_send_command(const char* cmd)
{
	int len = strlen(cmd);
	char new[len+1];
	char* pos;

	if (conf.control_pipe[0] == '\0') {
		strncpy(conf.control_pipe, DEFAULT_CONTROL_PIPE, MAX_CONF_VALUE_LEN);
	}

	while (access(conf.control_pipe, F_OK) < 0) {
		printf("Waiting for control pipe '%s'...\n", conf.control_pipe);
		sleep(1);
	}

	ctlpipe = open(conf.control_pipe, O_WRONLY);
	if (ctlpipe < 0)
		err(1, "Could not open control socket '%s'", conf.control_pipe);

	/* always terminate command with newline */
	strncpy(new, cmd, len);
	new[len] = '\n';
	new[len+1] = '\0';

	/* replace : with newline */
	while ((pos = strchr(new, ';')) != NULL) {
		*pos = '\n';
	}

	printf("Sending command: %s\n", new);

	write(ctlpipe, new, len+1);
	close(ctlpipe);
}


static void
parse_command(char* in) {
	char* cmd;
	char* val;

	cmd = strsep(&in, "=");
	val = in;
	//printlog("RECV CMD %s VAL %s", cmd, val);

	/* commands without value */

	if (strcmp(cmd, "pause") == 0) {
		main_pause(1);
	}
	else if (strcmp(cmd, "resume") == 0) {
		main_pause(0);
	}
	else if (strcmp(cmd, "reset") == 0) {
		main_reset();
	}
	else {
		/* handle the rest thru config options */
		config_handle_option(0, cmd, val);
	}
}


void
control_receive_command(void) {
	char buf[MAX_CMD];
	char *pos = buf;
	char *end;
	int len;

	len = read(ctlpipe, buf, MAX_CMD);
	if (len > 0) {
		buf[len] = '\0';
		/* we can receive multiple \n separated commands */
		while ((end = strchr(pos, '\n')) != NULL) {
			*end = '\0';
			parse_command(pos);
			pos = end + 1;
		}
	}
}


void
control_finish(void)
{
	if (ctlpipe == -1)
		return;

	close(ctlpipe);
	unlink(conf.control_pipe);
	ctlpipe = -1;
}

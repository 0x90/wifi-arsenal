/*
 * OpenWIPS-ng sensor.
 * Copyright (C) 2011 Thomas d'Otreppe de Bouvette
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 *      Author: Thomas d'Otreppe de Bouvette
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "main.h"
#include "common/defines.h"
#include "common/interface_control.h"
#include "common/version.h"
#include "global_var.h"

inline void stop_threads()
{
	_stop_threads = 1;
}

void init()
{
	init_global_var();
	_stop_threads = 0;
	_host = NULL;
}

void free_memory()
{
	global_memory_free_rpcap();

	FREE_AND_NULLIFY(_host);
}

void help()
{
	printf("%s - %s\n\n", getVersion("OpenWIPS-ng", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC), WEBSITE);
	printf("openwips-ng [interface] [server IP] [port] [login] [pass]\n");
	exit(-1);
}

void parse_args(int argc, char * argv[])
{
	ALLOC_COPY_STRING(((argc > 2) ?  argv[2] : "127.0.0.1"), _host);
	ALLOC_COPY_STRING(argv[1], _mon_iface);
}

int main (int argc, char * argv[])
{
	if (argc < 6) {
		// Display help
		help();
	}

	if (getuid() != 0) {
		fprintf( stderr, "This program requires root privileges.\n" );
		exit(EXIT_FAILURE);
	}

	// Check if interface exist
	if (!interface_exist(argv[1])) {
		fprintf(stderr, "Interface <%s> does not exist.\n", argv[1]);
		exit(EXIT_FAILURE);
	}

	// Initialize
	init();

	// Parse args
	parse_args(argc, argv);


	// Connect to server
	connect_to_server_old(argc, argv);

	while (1) {
		sleep(1000);
	}

	return EXIT_SUCCESS;
}



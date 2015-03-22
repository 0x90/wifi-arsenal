/*
 * OpenWIPS-ng server.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> //sleep
#include <getopt.h>
#include "main.h"
#include "config.h"
#include "plugins.h"
#include "common/deamonize.h"
#include "common/version.h"
#include "messages.h"

// TODO: Handle signal to clean stuff up (especially the socket)

void help()
{
	char usage[] =
	"\n"
	"  %s - (C) 2011 Thomas d\'Otreppe\n"
	"  %s\n"
	"\n"
	"  Usage: openwips-ng-server <config file_path> [-d]\n"
	"         or\n"
	"         openwips-ng-server [options]\n"
	"\n"
	"  Options:\n"
	"\n"
	"      -p <plugin> : Check if a plugin is valid and exit\n"
	"      -c <config> : Check if a configuration file is\n"
	"                    valid and exit\n"
//	"      -d          : Deamonize\n"
	"      -v          : Display version and exit\n"
	"      -h          : Display help and exit\n"
	"\n";

	printf(usage, _version, WEBSITE);
	exit(-1);
}

void free_global_memory()
{
	free_global_memory_config();
	free_global_memory_sensor();
	free_global_memory_rpcap_server();
	free_global_memory_packet_assembly();
	free_global_memory_packet_analysis();
	free_global_memory_message();
	free_global_memory_database();

	// Free the rest of memory allocated by main.
	free(_version);
}

void init()
{
	//init_sensors_users_list();
	_stop_threads = 0;
	_config_file_location = CONFIG_FILE_LOCATION;
	_deamonize = 0;
	_version = getVersion("OpenWIPS-ng server", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC);
	init_packet_assembly();
	init_sensor();
	init_packet_analysis();
	init_message_thread();
	init_database_thread();
}

inline void stop_threads()
{
	_stop_threads = 1;
}

int parse_args(int nbarg, char * argv[])
{
	int option_index, option;
	static struct option long_options[] = {
		{"help",			0, 0, 'h'},
		{"check-plugin",	1, 0, 'p'},
		{"check-config",	1, 0, 'c'},
		{"version",			0, 0, 'v'},
//		{"deamonize",		0, 0, 'd'},
		{0,             	0, 0,  0 }
	};

	while( 1 )
	{
		option_index = 0;

		option = getopt_long( nbarg, argv,
//						"hp:vc:d",
						"hp:vc:",
				long_options, &option_index );

		if( option < 0 ) break;

		switch( option )
		{
			case 0 :

				break;

			case ':' :

				printf("\"%s --help\" for help.\n", argv[0]);
				return( 1 );

			case 'd' :
				_deamonize = 1;
				fprintf(stderr, "Deamonize is not implemented yet.\n");
				break;

			case '?' :
			case 'h' :

				help();
				break;

			case 'p' : // Check plugin
				printf("%s\n", _version);
				_deamonize = 0;
				load_plugin("Check Plugin", optarg, NULL, 1);
				exit(EXIT_SUCCESS);
				break;

			case 'v' :
				// Display version and exit
				printf("%s\n", _version);
				exit(EXIT_SUCCESS);

			case 'c' : // Check configuration
				printf("%s\n", _version);
				_deamonize = 0;
				fprintf(stderr, "Checking configuration file <%s>\n", optarg);

				if (read_conf_file(optarg) == EXIT_SUCCESS) {
					fprintf(stderr, "[*] Configuration file <%s> is valid.\n", optarg);
				} else {
					fprintf(stderr, "[*] Configuration file <%s> is not correct.\n", optarg);
				}
				free_global_memory_config();
				exit(EXIT_SUCCESS);
				break;

			default:
				help();
				break;
		}
	}

	return EXIT_SUCCESS;
}

int main(int nbarg, char * argv[])
{
	char * temp;

	// Initialize stuff
	init();

	// Parse arguments
	parse_args(nbarg, argv);

	if (nbarg > 2 && !_deamonize) {
		help();
	}

	if (nbarg == 2 || nbarg == 3) {
		_config_file_location = argv[1];
	}

	// Read configuration file
	fprintf(stderr, "[*] Reading configuration file <%s>.\n", _config_file_location);
	if (read_conf_file(_config_file_location) == EXIT_FAILURE) {
		fprintf(stderr, "[*] Failed to read configuration, exiting.\n");
		free_global_memory();
		return EXIT_FAILURE;
	}
	fprintf(stderr, "[*] Successfully read configuration.\n");

	if (start_message_thread() == EXIT_FAILURE) {
		fprintf(stderr, "Failed to start message thread, exiting.\n");
		free_global_memory();
		return EXIT_FAILURE;
	}

	// Deamonize once the message thread is started.
	if (_deamonize) {
		daemonize();
	}

	/*
	if (start_database_thread() == EXIT_FAILURE) {
		fprintf(stderr, "Failed to start database thread, exiting.\n");
		free_global_memory();
		return EXIT_FAILURE;
	}
	*/

	temp = (char *)calloc(1, 100);
	sprintf(temp, "%s starting", _version);
	add_message_to_queue(MESSAGE_TYPE_REG_LOG, NULL, 1, temp, 0);

	if (parse_plugins_config() == EXIT_FAILURE) {
		add_message_to_queue(MESSAGE_TYPE_REG_LOG, NULL, 1, "Failed to load plugins, exiting", 1);
		sleep(1); // Make sure the message is processed
		free_global_memory();
		return EXIT_FAILURE;
	}

	add_message_to_queue(MESSAGE_TYPE_REG_LOG, NULL, 1, "Successfully loaded plugins", 1);

	if (start_packet_assembly_thread() == EXIT_FAILURE) {
		add_message_to_queue(MESSAGE_TYPE_REG_LOG, NULL, 1, "Failed to start packet reassembly and analysis thread, exiting", 1);
		sleep(1); // Make sure the message is processed
		free_global_memory();
		return EXIT_FAILURE;
	}

	add_message_to_queue(MESSAGE_TYPE_REG_LOG, NULL, 1, "Successfully started packet reassembly thread", 1);

	if (start_packet_analysis_thread() == EXIT_FAILURE) {
		add_message_to_queue(MESSAGE_TYPE_REG_LOG, NULL, 1, "Failed to start packet analysis and analysis thread, exiting", 1);
		sleep(1); // Make sure the message is processed
		free_global_memory();
		return EXIT_FAILURE;
	}

	add_message_to_queue(MESSAGE_TYPE_REG_LOG, NULL, 1, "Successfully started frame analysis thread", 1);

	// Start sensor socket
	if (start_sensor_socket() == EXIT_FAILURE) {
		temp = (char *)calloc(1, 100);
		sprintf(temp, "Failed to start server on port %d, exiting", _port);
		add_message_to_queue(MESSAGE_TYPE_REG_LOG, NULL, 1, temp, 0); // No need to free temp, the thread is going to do
		sleep(1); // Make sure the message is processed
		free_global_memory();
		return EXIT_FAILURE;
	}

	temp = (char *)calloc(1, 100);
	sprintf(temp, "Listening for sensors on port %d", _port);
	add_message_to_queue(MESSAGE_TYPE_REG_LOG, NULL, 1, temp, 0); // No need to free temp, the thread is going to do it.

	// Serve
	while(1) {
		sleep(1000);
	}

	// Stop threads
	stop_threads();

	// Free memory
	free_global_memory();

	return EXIT_SUCCESS;
}

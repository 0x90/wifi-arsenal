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
#include "common/defines.h"
#include "common/sockets.h"
#include "global_var.h"

void init_global_var()
{
	_mon_iface = NULL;
	_stop_threads = 0;
	_rpcap_client_params = NULL;
	_rpcap_server_params = NULL;
	_login = NULL;
	_pass = NULL;
	_host = NULL;
	_clientSocket = INVALID_SOCKET;
	_server_connection_thread = PTHREAD_NULL;
	_received_packet_list = NULL;
	_to_send_packet_list = NULL;
	_pcap_thread = PTHREAD_NULL;
	_pcap_header = NULL;
	_config = NULL;
}

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
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <zlib.h>
#include "packet_assembly.h"
#include "../common/defines.h"
#include "../common/server-client.h"
#include "../messages.h"

void init_packet_assembly()
{
	_packet_assembly_thread = PTHREAD_NULL;
	_stop_packet_assembly_thread = 0;
	_packet_assembly_thread_stopped = 1;
	_receive_packet_list = init_new_packet_list();
	_to_send_packet_list = init_new_packet_list();
}

void free_global_memory_packet_assembly()
{
	_stop_packet_assembly_thread = 1;

	while (!_packet_assembly_thread_stopped) {
		usleep(500);
	}
	free_packet_list(&_receive_packet_list);
	free_packet_list(&_to_send_packet_list);
}

int start_packet_assembly_thread()
{
	int thread_created = pthread_create(&_packet_assembly_thread, NULL, (void*)&packet_assembly_thread, NULL);
	if (thread_created != 0) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int kill_packet_assembly_thread()
{
	if (_packet_assembly_thread != PTHREAD_NULL) {

		_stop_packet_assembly_thread = 1;

		_packet_assembly_thread = PTHREAD_NULL;
	}

	return EXIT_SUCCESS;
}

int packet_assembly_thread(void * data)
{
	struct client_params * cur;
	struct pcap_packet * packets, *local_list, *cur_packet_list, *prev, *cur2;
	_packet_assembly_thread_stopped = 0;
	local_list = NULL;
	uint32_t fcs;
	char * temp_str;
	int bad_frame;

#ifdef DEBUG
	add_message_to_queue(MESSAGE_TYPE_REG_LOG, NULL, 1, "Packet assembly thread started", 1);
#endif

	while (!_stop_threads && !_stop_packet_assembly_thread) {

		// Check that the server is initialized
		if (_sensor_server_params == NULL) {
			usleep(5000);
			continue;
		}

		// Check if it has clients
		if (_sensor_server_params->client_list == NULL) {
			usleep(10000);
			continue;
		}

		// TODO: Check the client isn't dead and thus being removed/free (there is probably a mutex next to the dead check function)
		// 1. Search in all connected clients (rpcap) ...
		for (cur = _sensor_server_params->client_list; cur != NULL; cur = cur->next) {

			if (!(cur->rpcap_server && cur->rpcap_server->client_list && /*&& cur->rpcap_server->client_list->client->connected*/
			cur->rpcap_server->client_list->received_packets &&
			cur->rpcap_server->client_list->received_packets->nb_packet &&
			cur->rpcap_server->client_list->received_packets->pcap_header)) {
				continue;
			}

			// Is there any packet in the structure
			// ... RPCAP is connected, we probably have some packets (take all) ...
			packets = get_packets(INT_MAX, &(cur->rpcap_server->client_list->received_packets));

			if (packets == NULL) {
				continue;
			}

			// Tag all packets with socket id (TODO: Use sensor login)
			for (cur_packet_list = packets; cur_packet_list != NULL; cur_packet_list = cur_packet_list->next) {
				cur_packet_list->source = cur->rpcap_server->client_list->client->sock;
				cur_packet_list->linktype = cur->rpcap_server->client_list->received_packets->pcap_header->linktype;
			}


			// ... and add them to our local list
			if (local_list == NULL) {
				local_list = packets;
			} else {
				for (cur_packet_list = local_list; cur_packet_list->next != NULL; cur_packet_list = cur_packet_list->next);
				cur_packet_list->next = packets;
			}
			packets = NULL;
		}

		if (!local_list) {
			usleep(100);
			continue;
		}

		// 2. Remove bad CRC/FCS
		prev = NULL;
		cur_packet_list = local_list;
		while (cur_packet_list != NULL) {
			bad_frame = 1;
			if (cur_packet_list->header.cap_len < MIN_PACKET_SIZE + FCS_SIZE) {
				temp_str = (char *)calloc(1, 200 * sizeof(char));
				sprintf(temp_str, "Received invalid packet - frame too short to be analyzed. Expected %d bytes, received %u.", MIN_PACKET_SIZE + FCS_SIZE, cur_packet_list->header.cap_len);
				add_message_to_queue(MESSAGE_TYPE_ANOMALY, NULL, 1, temp_str, 0);
			} else {

				// Get packet information
				cur_packet_list->info = parse_packet_basic_info(cur_packet_list);

				if (cur_packet_list->info != NULL) {
					// If FCS is bad, discard the frame and log it.
					if (cur_packet_list->info->bad_fcs) {
#ifdef EXTRA_DEBUG
						add_message_to_queue(MESSAGE_TYPE_DEBUG, NULL, 1, "Invalid FCS flags set. Ignoring frame", 1);
#endif
					} else if (_force_fcs_check && cur_packet_list->info->fcs_present) {
						// Check FCS before processing frame (ignore if invalid but log it in DB).
						fcs = crc32(0L, cur_packet_list->info->frame_start, cur_packet_list->header.cap_len - FCS_SIZE - cur_packet_list->info->packet_header_len);
						if (fcs != cur_packet_list->info->fcs) {
#ifdef EXTRA_DEBUG
							temp_str = (char *)calloc(1, 80);
							fprintf(stderr, "Invalid FCS: Got 0x%x, expected 0x%x. Ignoring frame", cur_packet_list->info->fcs, fcs);
							add_message_to_queue(MESSAGE_TYPE_DEBUG, NULL, 1, temp_str, 0);
#endif
						} else bad_frame = 0;
					} else bad_frame = 0;
				}
			}

			if (!bad_frame) {
				prev = cur_packet_list;
				cur_packet_list = cur_packet_list->next;
				continue;
			}

			// Remove frame from list
			if (prev == NULL) {
				// First frame of the list
				local_list =  cur_packet_list->next;
				free_pcap_packet(&cur_packet_list, 0); // Free
				cur_packet_list = local_list;
			} else {
				cur2 = cur_packet_list;
				prev->next = cur_packet_list->next;
				cur_packet_list = cur_packet_list->next;
				free_pcap_packet(&cur2, 0); // Free
			}
		}

		// 3. TODO: Remove duplicates (within 1 second of the last received packet) within several sources
		//			Easy in most cases thanks to the Sequence Number (or FCS if it present)
		//			More problematic with Control packets (can use FCS if present) but also need to check time difference more accurately)

		// 4. TODO: Re-order (if needed)

		// 5. Put it on the list
		add_multiple_packets_to_list(local_list, &_receive_packet_list, 1);

		local_list = NULL;

		// Make sure the CPU won't get overloaded
		usleep(250);
	}

	_packet_assembly_thread_stopped = 1;

	return EXIT_SUCCESS;
}

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
#include <pcap.h>
#include <ctype.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include "common/pcap.h"
#include "common/interface_control.h"
#include "common/defines.h"
#include "packet_capture.h"
#include "global_var.h"

void init_packet_capture()
{
#ifdef __CYGWIN__
	// Load DLL functions
#endif
}

void global_memory_free_packet_capture()
{
#ifdef __CYGWIN__
	// Unload DLL functions
#endif
}

int is_valid_iface(const char * dev)
{
	if (dev == NULL) {
		return 0;
	}
#ifndef __CYGWIN__
	int ifaceLen = strlen(dev);
	return ifaceLen >= 3 && isdigit(dev[ifaceLen - 1]);
#else
	return strstr(dev, "airpcap") != NULL;
#endif
}

// Also call this function when starting remote pcap (only is _pcap_thread == PTHREAD_NULL)
int start_monitor_thread(struct client_params * params)
{
	int thread_created;
	if (params == NULL) {
		return EXIT_FAILURE;
	}

	if (_pcap_thread != PTHREAD_NULL) {
		return EXIT_SUCCESS;
	}

	thread_created = pthread_create(&_pcap_thread, NULL, (void*)&monitor, params);
	if (thread_created != 0) {
		fprintf(stderr,"ERROR, failed to create packet capture (on %s) thread\n", _mon_iface);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

// TODO: Add detection when the interface gets down or disappear.
// TODO: Only start capture when we start RPCAP (instead of doing it at startup)
int monitor(void * data)
{
	struct rfmon * rfmon_struct;
	struct pcap_pkthdr * packet_header;
	struct pcap_packet * whole_packet, *to_inject;
	const u_char * packet;
	int capture_success;
	struct client_params * params;
	struct pcap_file_header pfh;
	int link_type;
#define PACKET_CAPTURE_BUFFER_SIZE 4096
	unsigned char * buffer;

#ifdef DEBUG
	int pcap_created = 1;
#endif

	_pcap_header = NULL;
	buffer = (unsigned char *)calloc(1, PACKET_CAPTURE_BUFFER_SIZE * sizeof(unsigned char));

	params =  (struct client_params *)data;
	if (data == NULL) {
		fprintf(stderr, "Monitor mode failure due to NULL param.\n");
	}

	// Enable monitor mode
	rfmon_struct = enable_monitor_mode(_mon_iface, FIRST_CALL);
	if (rfmon_struct == NULL) {
		free(buffer);
		return EXIT_FAILURE;
	}

	// Get pcap file header
	link_type = get_pcap_datalink(rfmon_struct->handle);
	pfh = get_packet_file_header(link_type);
	_pcap_header = &pfh;

	// No need to verify link type, already check and it is supported

#ifdef DEBUG
	// TODO: Create another thread to avoid blocking
	pcap_created = (createPcapFile(DUMP_FILENAME, pcap_datalink(rfmon_struct->handle)) == EXIT_SUCCESS);
	if (!pcap_created) {
		fprintf(stderr, "Failed to create pcap file.\n");
	}
#endif

	while (params->client->connected && !params->client->stop_thread)
	{
		// Check if there are packets to send and send them
		if (params->received_packets->nb_packet > 0) {
			to_inject = get_packets(1, &(params->received_packets));
			if (to_inject) {
				inject_frame(rfmon_struct->handle, to_inject->data, to_inject->header.cap_len);
				free_pcap_packet(&to_inject, 1);
			}
		}

		capture_success = get_pcap_next_packet(rfmon_struct->handle,
												&packet_header,
												&packet,
												buffer,
												PACKET_CAPTURE_BUFFER_SIZE,
												rfmon_struct->link_type);

		// Handle errors
		if (capture_success != 1) {
			if (capture_success == ERROR_PCAP_OEF) {
				fprintf(stderr, "Capturing from a file, EOF.\n");
				break; // End capture
			}
			if (capture_success == ERROR_PCAP_PACKET_READ_ERROR) {
				fprintf(stderr, "Error occurred while reading the packet: %s\n", get_pcap_last_error(rfmon_struct->handle));
			} if (capture_success == ERROR_PCAP_TIMEOUT) {
				fprintf(stderr, "Timeout occurred while reading the packet\n");
			} else {
				fprintf(stderr, "Unknown pcap_next_ex() error: %i\n", capture_success);
			}

			// Make sure it won't consume 100% of the CPU in case of error
			usleep(500);
			continue;
		}

#ifdef DEBUG
		if (pcap_created && !append_packet_tofile(DUMP_FILENAME, packet_header, packet)) {
			fprintf(stderr, "Failed to append frame to pcap file.\n");
		}
#endif

		// Add packet to the queue of packets to send
		whole_packet = init_new_pcap_packet();
		whole_packet->header.cap_len = packet_header->caplen;
		whole_packet->header.orig_len = packet_header->len;
		whole_packet->header.ts_sec = packet_header->ts.tv_sec;
		whole_packet->header.ts_usec = packet_header->ts.tv_usec;
		whole_packet->data = (unsigned char *)malloc((packet_header->caplen) * sizeof(unsigned char));
		memcpy(whole_packet->data, packet, packet_header->caplen);
		add_packet_to_list(whole_packet, &(params->to_send_packets));
		//free_pcap_packet(&whole_packet); // Do not free packet (since the function doesn't make a copy to save some CPU cycles)

	}

#ifdef DEBUG
	fprintf(stderr, "monitor() thread finished.\n");
#endif

	_pcap_header = NULL; // Don't free
	_pcap_thread = PTHREAD_NULL;
	free_struct_rfmon(rfmon_struct); // Takes care of closing the handle
	free(buffer);

	return EXIT_SUCCESS;
}

/*
 * OpenWIPS-ng - common stuff.
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
#include <string.h>
#include "rpcap.h"
#include "pcap.h"
#include "sockets.h"

// TODO: Move this processing to a separate thread and keep the socket thread just putting the data it receives in
//       a buffer and sending from a buffer (create struct: unsigned char * + length + mutex. Optimize by only reallocating lower
//		  when after a certain threshold). This processing is moved to another thread to avoid blocking the socket thread.
// TODO: Use futex instead of mutex
// TODO: Move all common structs to another file and make that file BSD/GPLv2 license so that it can be used in plugins
int send_rpcap_data(unsigned char ** data, int * data_length, struct client_params * params)
{
	struct pcap_packet * packets, *cur;
	unsigned char * buffer;
	int pos, len = 0;
	if (params == NULL || (data && !data_length)) {
		return EXIT_FAILURE;
	}

	if (params->to_send_packets->nb_packet) {
		// Get X packets
		packets = get_packets(MAX_NB_PACKET_TO_SEND_AT_ONCE, &(params->to_send_packets));
		if (packets == NULL) {
			return EXIT_FAILURE;
		}

		// Get total length
		for (cur = packets; cur != NULL; cur = cur->next) {
			len += sizeof(struct pcap_record_header) + cur->header.cap_len;
		}

		// Allocate memory
		buffer = (unsigned char *)malloc(len*sizeof(unsigned char));

		// Append packets to buffer
		pos = 0;
		for (cur = packets; cur != NULL; cur = cur->next) {
			memcpy(buffer + pos, &(cur->header), sizeof(struct pcap_record_header));
			pos += sizeof(struct pcap_record_header);
			memcpy(buffer + pos, cur->data, cur->header.cap_len);
			pos += cur->header.cap_len;
		}

		// De-allocate list
		free_pcap_packet(&cur, 1);

		if (data == NULL) { // Send the data
			send_all_data(params->client->sock, buffer, len, 1);
			free(buffer);
		} else { // Let the calling function do it
			*data = buffer;
			*data_length = len;
		}
	}

	return EXIT_SUCCESS;
}

int handle_rpcap_data(unsigned char ** data, int * data_length, struct client_params * params)
{
#if 0
	int i;
#endif
	struct pcap_packet * packet;
	int ret = EXIT_FAILURE;

	// Should never happen but we never know
	if (params == NULL || data == NULL || *data == NULL || data_length == NULL || *data_length <= 0) {
		return EXIT_FAILURE;
	}

	while (*data_length && *data_length > sizeof(struct pcap_record_header)) {
		// Basically, it will be real_pcap_pkthdr followed by the data (we know how much data based on the real_pcap_pkthdr.
		packet = init_new_pcap_packet();
		memcpy(&(packet->header), *data, sizeof(struct pcap_record_header));

#if 0
		printf("Header - caplen: %u - len: %u\n", packet->header.caplen, packet->header.len);
		printf("Header - tv_sec: %d - tv_usec: %d \n", packet->header.tv_sec, packet->header.tv_usec);

		printf("Header data:");
		for (i = 0; i < sizeof(struct real_pcap_pkthdr); i++) {
			printf(" 0x%02x", (*data)[i]);
		}
		printf("\n");
#endif

		// Check that we have enough data
		if (*data_length < packet->header.cap_len + sizeof(struct pcap_record_header)) {
			free_pcap_packet(&packet, 0);
#ifdef EXTRA_DEBUG
			fprintf(stderr, "handle_rpcap_data() - Not enough data in buffer to create a packet.\n");
#endif
			break;
		}

#if 0
		printf("Data frame:");
		for (i = 0; i < packet->header.caplen; i++) {
			printf(" 0x%02x", (*data) + sizeof(struct real_pcap_pkthdr) + i);
		}
		printf("\n");
#endif

		// Copy content to the packet
		packet->data = (unsigned char *)malloc(sizeof(unsigned char) * (packet->header.cap_len));
		memcpy(packet->data, (*data) + sizeof(struct pcap_record_header), packet->header.cap_len);

		// Add the packet to the list
		if (params->received_packets == NULL) {
			params->received_packets = init_new_packet_list();
		}

		// Remove the packet from the buffer
		remove_bytes_from_buffer(data, data_length, packet->header.cap_len + sizeof(struct pcap_record_header), 1);

#ifdef DEBUG
		append_pcap_packet_tofile("received.pcap", packet);
#endif

		// That function takes care to get the lock, so we don't have to
		add_packet_to_list(packet, &(params->received_packets));

		ret = EXIT_SUCCESS;
	}

	return ret;
}

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
/*
 * Linking exception:
 * 		You are allowed to link you code (no matter what license
 * 		 your code is, even if your code is closed source) to this file
 * 		or any other file linked to this one during compilation
 * 		ONLY if it is a plugin for OpenWIPS-ng.
 * Limitation:
 * 		Functions (or variables) in this file MUST NOT be exposed in the plugin
 * 		(not visible when listing functions/variables in the shared object/DLL).
 * Modifications:
 * 		Modifications to this file are allowed if the modifications
 * 		(or patch) has a GPLv2 license and are publicly available.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pcap.h"
#include "defines.h"

struct packet_list * init_new_packet_list()
{
	struct packet_list * ret = (struct packet_list *)malloc(sizeof(struct packet_list));
	pthread_mutex_init(&(ret->mutex), NULL);
	ret->nb_packet = 0;
	ret->packets = NULL;
	ret->pcap_header = NULL;

	return ret;
}

int free_packet_list(struct packet_list ** ptr)
{
	if (ptr == NULL || *ptr == NULL) {
		return EXIT_FAILURE;
	}

	pthread_mutex_destroy(&((*ptr)->mutex));

	free_pcap_packet(&((*ptr)->packets), 1);
	FREE_AND_NULLIFY((*ptr)->pcap_header);

	FREE_AND_NULLIFY(*ptr);

	return EXIT_SUCCESS;
}

struct pcap_packet * init_new_pcap_packet()
{
	struct pcap_packet * ret = (struct pcap_packet *)malloc(sizeof(struct pcap_packet));
	ret->data = NULL;
	ret->next = NULL;
	ret->info = NULL;
	ret->linktype = 0;
	ret->source = -1;

	return ret;
}

int free_pcap_packet(struct pcap_packet ** ptr, int recursive)
{
	struct pcap_packet *cur, *next;

	if (ptr == NULL || *ptr == NULL) {
		return EXIT_FAILURE;
	}

	cur = *ptr;
	while (cur != NULL) {
		next = cur->next;
		FREE_AND_NULLIFY(cur->data);
		FREE_AND_NULLIFY(cur->info);
		FREE_AND_NULLIFY(cur);
		if (!recursive) {
			break;
		}
		cur = next;
	}

	return EXIT_SUCCESS;
}

struct packet_info * copy_packet_info(struct pcap_packet * src, struct pcap_packet * dst)
{
	struct packet_info * ret;

	if (src == NULL || dst == NULL) {
		return NULL;
	}

	ret = (struct packet_info *)malloc(sizeof(struct packet_info));

	ret->address1 = (src->info->address1) ? dst->data + (src->info->address1 - src->data) : NULL;
	ret->address2 = (src->info->address2) ? dst->data + (src->info->address2 - src->data) : NULL;
	ret->address3 = (src->info->address3) ? dst->data + (src->info->address3 - src->data) : NULL;
	ret->address4 = (src->info->address4) ? dst->data + (src->info->address4 - src->data) : NULL;
	ret->bssid = (src->info->bssid) ? dst->data + (src->info->bssid - src->data) : NULL;
	ret->destination_address = (src->info->destination_address) ? dst->data + (src->info->destination_address - src->data) : NULL;
	ret->fcs = src->info->fcs;
	ret->frame_start = (src->info->frame_start) ? dst->data + (src->info->frame_start - src->data) : NULL;
	ret->frame_subtype = src->info->frame_subtype;
	ret->frame_type = src->info->frame_type;
	ret->fromDS = src->info->fromDS;
	ret->packet_header_len = src->info->packet_header_len;
	ret->protocol = src->info->protocol;
	ret->sequence_number = src->info->sequence_number;
	ret->toDS = src->info->toDS;
	ret->recipient_address = (src->info->recipient_address) ? dst->data + (src->info->recipient_address - src->data) : NULL;
	ret->source_address = (src->info->source_address) ? dst->data + (src->info->source_address - src->data) : NULL;
	ret->transmitter_address = (src->info->transmitter_address) ? dst->data + (src->info->transmitter_address - src->data) : NULL;
	ret->retry = src->info->retry;
	ret->QoS = src->info->QoS;
	ret->signal = src->info->signal;
	ret->noise = src->info->noise;
	ret->rate = src->info->rate;
	ret->fcs_present = src->info->fcs_present;
	ret->frequency = src->info->frequency;
	ret->channel = src->info->channel;
	ret->frame_payload = (src->info->frame_payload) ? dst->data + (src->info->frame_payload - src->data) : NULL;
	ret->more_frag = src->info->more_frag;
	ret->fragment_nr = src->info->fragment_nr;
	ret->more_data = src->info->more_data;
	ret->protected = src->info->protected;
	ret->order = src->info->order;
	ret->power_management = src->info->power_management;
	ret->channel_width = src->info->channel_width;
	ret->guard_interval = src->info->guard_interval;
	ret->mcs_index = src->info->mcs_index;
	ret->nb_spatial_stream = src->info->nb_spatial_stream;
	ret->bad_fcs = src->info->bad_fcs;

	return ret;
}

struct packet_info * init_new_packet_info()
{
	struct packet_info * ret = (struct packet_info *)malloc(sizeof(struct packet_info));
	ret->address1 = NULL;
	ret->address2 = NULL;
	ret->address3 = NULL;
	ret->address4 = NULL;
	ret->bssid = NULL;
	ret->source_address = NULL;
	ret->destination_address = NULL;
	ret->transmitter_address = NULL;
	ret->recipient_address = NULL;
	ret->frame_start = NULL;
	ret->fromDS = 0;
	ret->toDS = 0;
	ret->packet_header_len = 0;
	ret->frame_type = 0;
	ret->frame_subtype = 0;
	ret->sequence_number = 0;
	ret->protocol = 0;
	ret->fcs = 0;
	ret->retry = 0;
	ret->QoS = 0;
	ret->signal = 0;
	ret->noise = 0;
	ret->rate = 0;
	ret->fcs_present = 0;
	ret->bad_fcs = 0;
	ret->frequency = 0;
	ret->channel = 0;
	ret->frame_payload = NULL;
	ret->more_frag = 0;
	ret->fragment_nr = 0;
	ret->more_data = 0;
	ret->protected = 0;
	ret->order = 0;
	ret->power_management = 0;
	ret->channel_width = 20; // Default: 20MHz
	ret->guard_interval = -1;
	ret->mcs_index = -1;
	ret->nb_spatial_stream = 0;

	return ret;
}

int parse_packet_basic_info_radiotap(struct pcap_packet * packet, struct packet_info * info)
{
	int i, pos;
	uint32_t radiotap_flags;
	static const int radiotap_item_length_bytes[] = { 8, 1, 1, 4, 2, 1, 1, 2, 2, 2, 1, 1, 1, 1, 2, 2, 1, 1, 8, 3 }; // Length of each radiotap field

	// MCS information. See http://mcsindex.com
	static const double rate_mcs_20MHz [2][MAX_MCS_INDEX + 1] =
	{
		// Long GI
		{ 6.5, 13, 19.5, 26, 39, 52, 58.5, 65, 13, 26, 39, 52, 78, 104, 117, 130, 19.5, 39, 58.5, 78, 117, 156, 175.5, 195, 26, 52, 78, 104, 156, 208, 234, 260, -1, 39, 52, 65, 28.5, 78, 97.5, 52, 65, 65, 78, 91, 91, 104, 78, 97.5, 97.5, 117, 136.5, 136.5, 156, 65, 78, 91, 78, 91, 104, 117, 104, 117, 130, 130, 143, 97.5, 117, 136.5, 117, 136.5, 156, 175.5, 156, 175.5, 195, 195, 214.5 },
		// Short GI
		{ 7.2, 14.4, 21.7, 28.90, 43.30, 57.80, 65, 72.2, 14.40, 28.90, 43.30, 57.80, 86.70, 115.60, 130.0, 144.40, 21.7, 43.3, 65, 86.70, 130.70, 173.30, 195, 216.70, 28.80, 57.60, 86.80, 115.60, 173.20, 231.20, 260, 288.80, -1, 43.3, 57.8, 72.2, 65.0, 86.7, 108.3, 57.8, 72.2, 72.2, 86.7, 101.1, 101.1, 115.6, 86.7, 108.3, 108.3, 130, 151.7, 151.7, 173.3, 72.2, 86.7, 101.1, 86.7, 101.1, 115.6, 130, 115.6, 130, 144.4, 144.4, 158.9, 108.3, 130, 151.7, 130, 151.7, 173.3, 195, 173.3, 195, 216.7, 216.7, 238.3 }
	};

	static const double rate_mcs_40MHz [2][MAX_MCS_INDEX + 1] =
	{
		// Long GI
		{ 13.5, 27.0, 40.5, 54, 81, 108, 121.5, 135, 27, 54, 81, 108, 162, 216, 243, 270, 40.5, 81, 121.5, 162, 243, 324, 364.5, 405.0, 54, 108, 162, 216, 324, 432, 486, 540, 6, 81, 108, 135, 121.5, 162, 202.5, 108, 135, 135, 162, 189, 189, 216, 162, 202.5, 205.5, 243, 283.5, 283.5, 324, 135, 162, 189, 162, 189, 216, 243, 216, 243, 270, 270, 297, 202.5, 243, 283.5, 243, 283.5, 324, 364.5, 324, 364.5, 405, 405, 445.5},
		// Short GI
		{ 15, 30, 45, 60, 90, 120, 135, 150, 30, 60, 90, 120, 180, 240, 270, 300, 45, 90, 135, 180, 270, 360, 405, 450, 60, 120, 180, 240, 360, 480, 540, 600, 6.7, 90, 120, 150, 135, 180, 225, 120, 150, 150, 180, 210, 210, 240, 180, 225, 225, 270, 315, 315, 360, 150, 180, 210, 180, 210, 240, 270, 240, 270, 300, 300, 330, 225, 270, 315, 270, 315, 360, 405, 360, 405, 450, 450, 495 }
	};

	static const unsigned char rate_mcs_nb_streams [MAX_MCS_INDEX + 1] = { 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4 };

	if (packet == NULL || info == NULL) {
		return EXIT_FAILURE;
	}

	// Get radiotap information
	memcpy(&radiotap_flags, (packet->data) + 4, 4);
	pos = 8; // Start position of the items in the flags
	for (i = 0; radiotap_flags != 0; i++) {
		if (radiotap_flags % 2) {
			switch (i) {
			case 1: // Flags
				// TODO: Check if flags are parsed correctly
				info->fcs_present = ((*(packet->data + pos)) & 0x10) == 0x10;
				info->bad_fcs = ((*(packet->data + pos)) & 0x40) == 0x40;
				break;
			case 2: // Rate
				info->rate = (*((packet->data) + pos)) / 2.0;
				break;
			case 3: // Channel
				info->frequency = (*((packet->data) + pos + 1))* 256;
				info->frequency += *((packet->data) + pos);
				if (info->frequency >= 2407 && info->frequency <= 2472) {
					info->channel = (info->frequency - 2407) / 5;
				} else if (info->frequency == 2484) {
					info->channel = 14;
				} else if (info->frequency >= 5000 && info->frequency <= 6100) {
					info->channel = (info->frequency - 5000) / 5;
				}
				break;
			case 5: // DBM Antenna signal
				info->signal = *((packet->data) + pos);
				break;
			case 6: // DBM Antenna noise
				info->noise = *((packet->data) + pos);
				break;
			case 14: // RX Flags
				// TODO: 'value & 1' indicates if FCS failed, add that field.
				//       That will avoid FCS calculation
				// TODO: Make the sensor validate its frames to offload the server and report every X times the amount of broken frames.
				break;
			case 19: // HT information
				if (info->rate > 0) {
					break;
				}

				// TODO: Check first byte to know what's available
				if (((*((packet->data) + pos + 1)) & 3) != 0) {
					info->channel_width = 40;
					// 40 Mhz
				} // Default is 20Mhz

				// MCS rate index
				info->mcs_index = *((packet->data) + pos + 2);

				// Guard Interval
				if (((*((packet->data) + pos + 1)) & 4) == 0) {
					// Long GI
					info->guard_interval = 800; // 800 ns

				} else {
					// Short GI
					info->guard_interval = 400; // 400 ns
				}

				if (info->mcs_index > MAX_MCS_INDEX) {
#ifdef DEBUG
					fprintf(stderr, "Invalid MCS index for frame: %u (max value: %d).", info->mcs_index, MAX_MCS_INDEX);
#endif
					break;
				}

				// Rate
				if (info->channel_width == 40) {
					info->rate = rate_mcs_40MHz[(int)(info->guard_interval == 400)][(int)(info->mcs_index)];
				} else {
					info->rate = rate_mcs_20MHz[(int)(info->guard_interval == 400)][(int)(info->mcs_index)];
				}

				// Get # of spatial streams
				info->nb_spatial_stream = rate_mcs_nb_streams[(int)(info->mcs_index)];

				break;
			default:
				break;
			}
			// Go to the next field
			if (i <= 17) {
				pos += radiotap_item_length_bytes[i];
			}
		}
		radiotap_flags /= 2;
	}

	return EXIT_SUCCESS;
}

struct packet_info * parse_packet_basic_info(struct pcap_packet * packet)
{
	// QoS frames - That indicates there will be 2 bytes right after the sequence number called 'QoS Control'
	// TODO: Check frame length before getting each field and return NULL if it's not long enough
	struct packet_info * ret;
	int to_from_ds;

	if (packet == NULL || packet->header.cap_len < MIN_PACKET_SIZE) {
#ifdef EXTRA_DEBUG
		fprintf(stderr, "parse_packet_basic_info(): Frame way too small to be parsed. Min size: %d (Got %d including packet headers).\n",
				MIN_PACKET_SIZE, packet->header.cap_len);
#endif
		return NULL;
	}

	if (*(packet->data) != 0) {
#ifdef EXTRA_DEBUG
		fprintf(stderr, "parse_packet_basic_info(): Invalid radiotap version. Expected 0, got %d.\n", *(packet->data));
#endif
		return NULL;
	}

	ret = init_new_packet_info();

	if (packet->linktype == LINKTYPE_RADIOTAP) {
		ret->packet_header_len = *((packet->data) + 2); // Radiotap header length
		if (packet->header.cap_len < ret->packet_header_len + MIN_PACKET_SIZE) {
#ifdef EXTRA_DEBUG
			fprintf(stderr, "parse_packet_basic_info(): Frame too small to be parsed. Min size: %d (Got %d).\n",
					MIN_PACKET_SIZE, packet->header.cap_len - ret->packet_header_len);
#endif
			free(ret);
			return NULL;
		}

		// Parse radiotop header
		if (parse_packet_basic_info_radiotap(packet, ret) == EXIT_FAILURE) {
			free(ret);
			return NULL;
		}

	} else if (packet->linktype == LINKTYPE_NOHEADERS) {
		// OK, no headers
		ret->packet_header_len = 0;
	} else if (packet->linktype == LINKTYPE_PRSIM) {
#ifdef DEBUG
		fprintf(stderr, "PRISM headers can't be parsed yet.\n");
#endif
		ret->packet_header_len = packet->data[4] + (packet->data[5] * 256) + (packet->data[6] * 256 * 256) + (packet->data[7] * 256 * 256 * 256);

	} else if (packet->linktype == LINKTYPE_PPI) {
#ifdef DEBUG
		fprintf(stderr, "PPI headers can't be parsed yet.\n");
#endif
		ret->packet_header_len = packet->data[2] + (packet->data[3] * 256);
	} else {
		fprintf(stderr, "Unknown Link type: %u. Please do a tcpdump on the wireless interface and report it.\n", packet->linktype);
		exit(EXIT_FAILURE);
	}

	// TODO: Move that inside each type of header being parsed.
	if (packet->header.cap_len < ret->packet_header_len + MIN_PACKET_SIZE) {
#ifdef EXTRA_DEBUG
		fprintf(stderr, "parse_packet_basic_info(): Frame too small to be parsed. Min size: %d (Got %d).\n",
				MIN_PACKET_SIZE, packet->header.cap_len - ret->packet_header_len);
#endif
		free(ret);
		return NULL;
	}

	ret->frame_start = ((packet->data) + ret->packet_header_len);

	ret->protocol = (unsigned char)(*(ret->frame_start) & 3);
	ret->frame_type = (unsigned char)(((*(ret->frame_start)) & 0x0D) >> 2);
	ret->frame_subtype = (unsigned char)(((*(ret->frame_start)) & 0xF0) >> 4);
	to_from_ds = (unsigned char)(*(ret->frame_start + 1) & 3);
	ret->fromDS = (to_from_ds < 2) ? 0 : 1;
	ret->toDS = to_from_ds % 2 == 1;
	ret->retry = (*(ret->frame_start + 1) & 8) == 8;
	ret->QoS = ((((*(ret->frame_start)) & 0xf0 ) >> 4 ) << 4) == 0x80; // TODO: Make sure this is correct
	ret->more_frag = (unsigned char)(*(ret->frame_start + 1) & 4) == 4;
	ret->order = (unsigned char)(*(ret->frame_start + 1) & 0x80) == 0x80;
	ret->protected = (unsigned char)(*(ret->frame_start + 1) & 0x40) == 0x40;
	ret->more_data = (unsigned char)(*(ret->frame_start + 1) & 0x20) == 0x20;
	ret->power_management = (unsigned char)(*(ret->frame_start + 1) & 0x10) == 0x10;

	if (ret->fcs_present) {
		memcpy(&(ret->fcs), (packet->data + packet->header.cap_len - FCS_SIZE), FCS_SIZE);
	}

	ret->address1 = ret->frame_start + 4;
	if (ret->frame_type == 1) {
		// Only address 1 exists (receiver address)
		ret->recipient_address = ret->address1;
	} else {
		if (packet->header.cap_len < ret->packet_header_len + 23 + (ret->fcs_present) ? FCS_SIZE : 0) {
			// Packet not long enough for a sequence number
#ifdef EXTRA_DEBUG
			fprintf(stderr, "parse_packet_basic_info(): Error - Frame <%d-%d> too short to get SN and fragment # (FCS: 0x%x).\n",
					ret->frame_type,
					ret->frame_subtype,
					ret->fcs);
#endif
		} else {
			ret->sequence_number = (unsigned short)(((*(ret->frame_start + 22))>>4)+((*(ret->frame_start + 23))<<4));
			ret->fragment_nr = (*(ret->frame_start + 22)) & 0xF;
		}

		ret->frame_payload = ret->frame_start + 24 + ((ret->QoS) ? 2 : 0); // There are 2 bytes of QoS

		if (packet->header.cap_len > ret->packet_header_len + 10 + 6 + (ret->fcs_present) ? FCS_SIZE : 0) {
			ret->address2 = ret->frame_start + 10;
		}
		if (packet->header.cap_len > ret->packet_header_len + 16 + 6 + (ret->fcs_present) ? FCS_SIZE : 0) {
			ret->address3 = ret->frame_start + 16;
		}

		switch(to_from_ds)
		{
			case  0: // Adhoc (or frames sent by the AP only to anybody)
				//ret->fromDS = (ret->from_to_ds < 2) ? 0 : 1
				ret->destination_address = ret->address1;
				ret->source_address = ret->address2;
				ret->bssid = ret->address3;
				break;
			case  1: // To DS (Clients -> LAN)
				ret->bssid = ret->address1;
				ret->source_address = ret->address2;
				ret->destination_address = ret->address3;
				break;
			case  2: // From DS (LAN -> Clients)
				ret->destination_address = ret->address1;
				ret->bssid = ret->address2;
				ret->source_address = ret->address3;
				break;
			case  3: // WDS
				ret->address4 = ret->frame_start + 24;
				ret->frame_payload += 6;

				ret->recipient_address = ret->address1;
				ret->bssid = ret->address2; // Transmitter taken as BSSID
				ret->transmitter_address = ret->address2;
				ret->destination_address = ret->address3;
				ret->source_address = ret->address4;
				break;
			default:
				break;
		}
	}

#ifdef EXTRA_DEBUG
	print_pcap_packet_info(ret);
#endif

	return ret;
}

int print_pcap_packet_info(struct packet_info * pi)
{
	if (pi == NULL) {
		return EXIT_FAILURE;
	}

	printf("Protocol: %u\n", pi->protocol);
	printf("Header length: %u\n", pi->packet_header_len);
	printf("Frame type-subtype: %u-%u\n", pi->frame_type, pi->frame_subtype);
	printf("FromDS-ToDS: %d-%d\n", pi->fromDS, pi->toDS);
	printf("Sequence #: %u\n", pi->sequence_number);
	printf("QoS: %s\n", (pi->QoS) ? "Yes" : "No");
	printf("Retry: %s\n", (pi->retry) ? "Yes" : "No");
	printf("Frame Check Sequence (FCS) present: %s", (pi->fcs_present) ? "Yes" : "No");
	if (pi->fcs_present) {
		printf(" (0x%x)", pi->fcs);
	}
	printf("Bad Frame Check Sequence (FCS): %s\n", (pi->bad_fcs) ? "Yes" : "No");
	printf("\nSignal/Noise: %d/%d\n", pi->signal, pi->noise);
	printf("Rate: %.1fM\n", pi->rate);
	printf("HT Information:\n");
	printf("- Guard Interval: %d ns\n", pi->guard_interval);
	printf("- MCS Index: %d\n", pi->mcs_index);
	printf("Channel Width: %u\n", pi->channel_width);
	printf("Frequency: %u (channel %u)\n", pi->frequency, pi->channel);
	printf("More fragments: %s (Fragment #: %d)\n", (pi->more_frag) ? "Yes" : "No", pi->fragment_nr);
	printf("More data bit: %s\n", (pi->more_data) ? "Yes" : "No");
	printf("Protected bit: %s\n", (pi->protected) ? "Yes" : "No");
	printf("Order bit: %s\n", (pi->order) ? "Yes" : "No");
	printf("Power management bit: %s\n", (pi->power_management) ? "Yes" : "No");

	if (pi->frame_type == 1) {
		printf("Addresses (1): %02x:%02x:%02x:%02x:%02x:%02x\n", *(pi->address1), *(pi->address1 + 1), *(pi->address1 + 2), *(pi->address1 + 3), *(pi->address1 + 4), *(pi->address1 + 5));
	} else {
		printf("Addresses (%d): %02x:%02x:%02x:%02x:%02x:%02x - %02x:%02x:%02x:%02x:%02x:%02x - %02x:%02x:%02x:%02x:%02x:%02x",
						(pi->address4 != NULL) ? 4 : 3,
						*(pi->address1), *(pi->address1 + 1), *(pi->address1 + 2), *(pi->address1 + 3), *(pi->address1 + 4), *(pi->address1 + 5),
						*(pi->address2), *(pi->address2 + 1), *(pi->address2 + 2), *(pi->address2 + 3), *(pi->address2 + 4), *(pi->address2 + 5),
						*(pi->address3), *(pi->address3 + 1), *(pi->address3 + 2), *(pi->address3 + 3), *(pi->address3 + 4), *(pi->address3 + 5));

		if (pi->address4 != NULL) {
			printf(" - %02x:%02x:%02x:%02x:%02x:%02x",
					*(pi->address4), *(pi->address4 + 1), *(pi->address4 + 2), *(pi->address4 + 3), *(pi->address4 + 4), *(pi->address4 + 5));
		}
		printf("\n");
	}

	return EXIT_SUCCESS;
}

struct pcap_packet * copy_packets(struct pcap_packet * packet, int recursive, int do_parse)
{
	struct pcap_packet * ret;

	if (packet == NULL) {
		return NULL;
	}

	// Copy packet
	ret = init_new_pcap_packet();
	ret->header = packet->header;
	ret->data = (unsigned char *)malloc(sizeof(unsigned char) * ret->header.cap_len);
	memcpy(ret->data, packet->data, ret->header.cap_len);
	ret->linktype = packet->linktype;
	ret->source = packet->source;

	// Parse if needed
	if (do_parse) {
		if (packet->info == NULL) {
			ret->info = parse_packet_basic_info(ret);
		} else {
			ret->info = copy_packet_info(packet, ret);
		}
	}

	// Do it recursively?
	if (recursive && packet->next != NULL) {
		ret->next = copy_packets(packet->next, 1, do_parse);
	}

	return ret;
}

int add_packet_to_list(struct pcap_packet * packet, struct packet_list ** list)
{
	// Do not free memory of the packet passed to this structure, functions here will take care of that

	struct pcap_packet * cur;

	if (packet == NULL || list == NULL || *list == NULL) {
		return EXIT_FAILURE;
	}

	// Lock mutex
	pthread_mutex_lock(&((*list)->mutex));

	// Add it to the list
	if ((*list)->packets != NULL) {
		for (cur = (*list)->packets; cur->next != NULL; cur = cur->next);
		cur->next = packet;
	} else {
		(*list)->packets = packet;
	}

	// Update number of packets
	(*list)->nb_packet = (*list)->nb_packet + 1;

	// Unlock mutex
	pthread_mutex_unlock(&((*list)->mutex));

	return EXIT_SUCCESS;
}

int put_back_multiple_packets_to_list(struct pcap_packet * packets, struct packet_list ** list, int use_mutex)
{
	// Do not free memory of the packet passed to this structure, functions here will take care of that
	struct pcap_packet * cur;

	if (packets == NULL || list == NULL || *list == NULL) {
		return EXIT_FAILURE;
	}

	// Lock
	if (use_mutex) {
		pthread_mutex_lock(&((*list)->mutex));
	}

	// Update number of packets
	for (cur = packets; cur != NULL; cur = cur->next) {
		++((*list)->nb_packet);
	}

	// Add it to the list
	if ((*list)->packets != NULL) {
		for(cur = packets; cur->next != NULL; cur = cur->next);
		cur->next = (*list)->packets;
	}
	(*list)->packets = packets;

	// Unlock
	if (use_mutex) {
		pthread_mutex_unlock(&((*list)->mutex));
	}

	return EXIT_SUCCESS;
}

int add_multiple_packets_to_list(struct pcap_packet * packets, struct packet_list ** list, int use_mutex)
{
	// Do not free memory of the packet passed to this structure, functions here will take care of that
	struct pcap_packet * cur;

	if (packets == NULL || list == NULL || *list == NULL) {
		return EXIT_FAILURE;
	}

	if (use_mutex) {
		pthread_mutex_lock(&((*list)->mutex));
	}

	// Add it to the list
	if ((*list)->packets != NULL) {
		for (cur = (*list)->packets; cur->next != NULL; cur = cur->next);
		cur->next = packets;
	} else {
		(*list)->packets = packets;
	}

	// Update number of packets
	for (cur = packets; cur != NULL; cur = cur->next) {
		++((*list)->nb_packet);
	}

	if (use_mutex) {
		pthread_mutex_unlock(&((*list)->mutex));
	}

	return EXIT_SUCCESS;
}

int pcap_packet_len(struct pcap_packet * packets)
{
	struct pcap_packet * cur;
	int ret = 0;

	if (packets == NULL) {
		return -1;
	}

	for (cur = packets; cur != NULL; cur = cur->next) {
		++ret;
	}

	return ret;
}

int remove_first_X_packets(int nb_packets, struct packet_list ** list, int use_mutex)
{
	struct pcap_packet * packets;
	if (list == NULL || *list == NULL || nb_packets < 0) {
		return EXIT_FAILURE;
	}

	if (nb_packets == 0) {
		return EXIT_SUCCESS;
	}


	// TODO: Make use of Mutex
	packets = get_packets(nb_packets, list);

	free_pcap_packet(& packets, 1);

	return EXIT_SUCCESS;
}

int remove_packet_older_than(struct pcap_packet * packet, int time_ms, struct packet_list ** list, int use_mutex)
{
	// Remove packets older than 'time_ms' ago
	struct pcap_packet * cur, *last, *next;
	uint32_t tv_sec, tv_usec, remaining_ms;
	int negative;

	if (packet == NULL || list == NULL || *list == NULL || time_ms < 0) {
		return EXIT_FAILURE;
	}

	if ((*list)->nb_packet == 0) {
		return EXIT_SUCCESS;
	}

	// Calculate the exact time when to remove
	negative = 0;
	if (time_ms != 0) {
		remaining_ms = time_ms % 1000;
		negative = (packet->header.ts_sec < time_ms / 1000)
							|| ((packet->header.ts_sec == time_ms / 1000) &&
									(remaining_ms * 1000 > packet->header.ts_usec) );

		if (negative) {
			return EXIT_FAILURE;
		} else {
			tv_sec = packet->header.ts_sec - (time_ms/1000);

			if (remaining_ms * 1000 > packet->header.ts_usec) {
				--tv_sec;
				tv_usec = 1000000 + packet->header.ts_usec - (remaining_ms * 1000);
			} else {
				tv_usec = packet->header.ts_usec - (remaining_ms * 1000);
			}
		}
	} else {
		tv_usec = packet->header.ts_usec;
		tv_sec = packet->header.ts_sec;
	}

	// Lock
	if (use_mutex) {
		pthread_mutex_lock(&((*list)->mutex));
	}

	for (cur = (*list)->packets; cur != NULL; cur = cur->next) {
		if (cur->header.ts_sec < tv_sec) {
			continue;
			// Remove
		} else if (cur->header.ts_sec == tv_sec && cur->header.ts_usec < tv_usec) {
			continue;
			// Remove
		}
		break;
	}

	if (cur == NULL) {
		// Clear list
		free_pcap_packet(&((*list)->packets), 1);
		(*list)->nb_packet = 0;
		//(*list)->packets = NULL;
	} else {
		last = cur;
		cur = (*list)->packets;
		while (cur != NULL && cur != last) {
			next = cur->next;
			free_pcap_packet(&cur, 0);
			cur = next;
		}

		// Update list
		(*list)->packets = last;
		(*list)->nb_packet = pcap_packet_len(last);
	}

	// Unlock
	if (use_mutex) {
		pthread_mutex_unlock(&((*list)->mutex));
	}

	return EXIT_SUCCESS;
}

struct pcap_packet * get_packets(int nb_max, struct packet_list ** list)
{
	struct pcap_packet * cur;
	struct pcap_packet * ret = NULL;

	if (list == NULL || *list == NULL || nb_max <= 0 || (*list)->nb_packet <= 0) {
		return NULL;
	}

	// Lock mutex
	pthread_mutex_lock(&((*list)->mutex));

	ret = (*list)->packets;
	cur = (*list)->packets;
	--nb_max; --((*list)->nb_packet);
	while (nb_max > 0 && cur != NULL) {
		cur = cur->next;
		--nb_max; --((*list)->nb_packet);
	}

	// Set new position for the list
	(*list)->packets = (cur) ? cur->next : NULL;

	// Unlink the current packet from the next one
	if (cur != NULL) {
		cur->next = NULL;
	}


	// Unlock mutex
	pthread_mutex_unlock(&((*list)->mutex));

	return ret;
}

struct pcap_file_header get_packet_file_header(const bpf_u_int32 linktype)
{
	struct pcap_file_header pfh;
	pfh.magic           = TCPDUMP_MAGIC;
	pfh.version_major   = PCAP_VERSION_MAJOR;
	pfh.version_minor   = PCAP_VERSION_MINOR;
	pfh.thiszone        = 0; // TODO: Get timezone information
	pfh.sigfigs         = 0;
	pfh.snaplen         = SNAP_LEN;
	pfh.linktype        = linktype;

	return pfh;
}

int createPcapFile(const char * filename, const bpf_u_int32 linktype)
{
	struct pcap_file_header pfh = get_packet_file_header(linktype);

	return createPcapFile_with_header(filename, &pfh);
}

int createPcapFile_with_header(const char * filename, struct pcap_file_header * header)
{
	FILE * pcapFile;
	int ret;

	if (header == NULL) {
		return EXIT_FAILURE;
	}

	// Write header and close it
	pcapFile = fopen(filename, "wb");
	if (pcapFile == NULL) {
		return EXIT_FAILURE;
	}

	ret = ( fwrite( header, 1, sizeof( struct pcap_file_header ), pcapFile ) == (size_t) sizeof( struct pcap_file_header ) ) ? EXIT_SUCCESS : EXIT_FAILURE;
	fclose(pcapFile);

	return ret;
}

int append_pcap_packet_tofile(const char * filename, struct pcap_packet * packet)
{
	FILE * pcapFile = fopen(filename, "ab");
	int success = EXIT_FAILURE;

	if (pcapFile != NULL && packet != NULL) {

		// Write packet header
		if ( fwrite( &(packet->header), 1, sizeof( packet->header ), pcapFile ) == sizeof(  packet->header ) ) {

			// Write packet
			success = (fwrite( packet->data, 1, packet->header.cap_len, pcapFile ) == (size_t) packet->header.cap_len) ? EXIT_SUCCESS : EXIT_FAILURE;
		}

		fclose(pcapFile);
	}

	return success;
}

int append_packet_tofile(const char * filename, const struct pcap_pkthdr * packet_header, const u_char * packet)
{
	struct pcap_record_header pkh;
	FILE * pcapFile = fopen(filename, "ab");
	int success = 0;

	if (pcapFile != NULL) {

		// Convert struct pcap_pkthdr for use in the pcap file (altough the name of the struct used in the pcap file is the same, it is slightly different).
		pkh.cap_len = packet_header->caplen;
		pkh.orig_len = packet_header->len;
		pkh.ts_sec = packet_header->ts.tv_sec;
		pkh.ts_usec = packet_header->ts.tv_usec;

		// Write packet header
		if ( fwrite( &pkh, 1, sizeof( pkh ), pcapFile ) == sizeof( pkh ) ) {

			// Write packet
			success = (fwrite( packet, 1, pkh.cap_len, pcapFile ) == (size_t) pkh.cap_len);
		}

		fclose(pcapFile);
	}

	return success;
}

inline int is_valid_linktype(bpf_u_int32 linktype)
{
	return (linktype == LINKTYPE_NOHEADERS || linktype == LINKTYPE_PRSIM || linktype == LINKTYPE_RADIOTAP || linktype == LINKTYPE_PPI);
}

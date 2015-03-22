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
 *
 * Note: pcap_record_header, pcap_packet and packet_info structures are dual licensed: GPLv2/BSD
 */

#ifndef COMMON_PCAP_H_
#define COMMON_PCAP_H_

#if defined(__APPLE__) && defined(__MACH__)
	#include <pcap/pcap.h>
#else
	#include <pcap.h>
#endif
#include <pthread.h>
#include <stdint.h>

#define TCPDUMP_MAGIC 0xA1B2C3D4

// Libpcap snapshot (max frame length)
#define SNAP_LEN 65535

// Minimum packet size (if no FCS and no radiotap/any kind of headers)
#define FCS_SIZE 4
#define MIN_PACKET_SIZE 10

// Header types
#define LINKTYPE_NOHEADERS	105
// DLT_IEEE802_11
#define LINKTYPE_PRSIM		119
// DLT_PRISM_HEADER
#define LINKTYPE_RADIOTAP	127
// DLT_IEEE802_11_RADIO
#define LINKTYPE_PPI		192
// DLT_PPI


struct pcap_record_header
{
	uint32_t ts_sec;	// timestamp seconds (since january 1st, 1970, midnight)
	uint32_t ts_usec;   // timestamp microseconds (Shouldn't go over 1000 000
	uint32_t cap_len;  // number of octets of packet saved in file (cap_len)
	uint32_t orig_len;  // original length of packet (len)
};

// Packet
struct pcap_packet
{
	bpf_u_int32 linktype;
	struct pcap_record_header header;
    unsigned char * data;

    // TODO: Later, userid (or a pointer to a 'user'
    int source; // Source information (can be a socket, an identifier, etc)

    struct packet_info * info; // Parsed information from the packet

    struct pcap_packet * next;
};

// Packet list structure
struct packet_list {
	int nb_packet;
	struct pcap_packet * packets;
	int source; // Source information (can be a socket, an identifier, etc)
	pthread_mutex_t mutex;
	struct pcap_file_header * pcap_header;
};

#define MAX_MCS_INDEX		76

// !!! Do not free the fields inside since they are pointers to allocated data, not allocated data
struct packet_info {
	unsigned char * address1, *address2, *address3, * address4;
	unsigned char * bssid, *source_address, *destination_address, *transmitter_address, *recipient_address;
	unsigned char * frame_start, *frame_payload;
	unsigned short sequence_number;
	unsigned char protocol, packet_header_len, frame_type, frame_subtype, fromDS, toDS, retry, QoS;
	char signal, noise;
	unsigned short channel;
	uint32_t fcs, frequency;
	unsigned char fcs_present;
	unsigned char bad_fcs;
	unsigned char more_frag;
	unsigned char fragment_nr;
	unsigned char more_data, protected, order, power_management;
	unsigned char channel_width; // In MHz

	// 802.11n stuff
	short guard_interval; // GI, for 802.11n rates (HT)
	char mcs_index;
	unsigned char nb_spatial_stream;

	double rate;
};

struct packet_info * copy_packet_info(struct pcap_packet * src, struct pcap_packet * dst);
struct packet_info * init_new_packet_info();
int parse_packet_basic_info_radiotap(struct pcap_packet * packet, struct packet_info * info);
struct packet_info * parse_packet_basic_info(struct pcap_packet * packet);
int print_pcap_packet_info(struct packet_info * pi);

int add_packet_to_list(struct pcap_packet * packet, struct packet_list ** list);
int put_back_multiple_packets_to_list(struct pcap_packet * packets, struct packet_list ** list, int use_mutex);
int add_multiple_packets_to_list(struct pcap_packet * packet, struct packet_list ** list, int use_mutex);
struct pcap_packet * get_packets(int nb_max, struct packet_list ** list);

struct packet_list * init_new_packet_list();
int free_packet_list(struct packet_list ** ptr);

int pcap_packet_len(struct pcap_packet * packets);
struct pcap_packet * copy_packets(struct pcap_packet * packet, int recursive, int do_parse); // If recursive is 0, then copy only that packet. If do_parse is 1, then call parse_basic_info
int remove_first_X_packets(int nb_packets, struct packet_list ** list, int use_mutex);
int remove_packet_older_than(struct pcap_packet * packet, int time_ms, struct packet_list ** list, int use_mutex);

struct pcap_packet * init_new_pcap_packet();
int free_pcap_packet(struct pcap_packet ** ptr, int recursive);

struct pcap_file_header get_packet_file_header(const bpf_u_int32 linktype);
int createPcapFile(const char * filename, const bpf_u_int32 linktype);
int createPcapFile_with_header(const char * filename, struct pcap_file_header * header);
int append_packet_tofile(const char * filename, const struct pcap_pkthdr * packet_header, const u_char * packet);
int append_pcap_packet_tofile(const char * filename, struct pcap_packet * packet);

inline int is_valid_linktype(bpf_u_int32 linktype);

#endif /* COMMON_PCAP_H_ */

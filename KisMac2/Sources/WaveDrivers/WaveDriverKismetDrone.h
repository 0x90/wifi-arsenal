/*
        
        File:			WaveDriverKismetDrone.m
        Program:		KisMAC
		Author:			Geordie Millar
						themacuser@gmail.com
						Contains a lot of code from Kismet - 
						http://kismetwireless.net/
						
		Description:	Scan with a Kismet drone (as opposed to kismet server) in KisMac.
		
		Details:		Tested with kismet_drone 2006.04.R1 on OpenWRT White Russian RC6 on a Diamond Digital R100
						(broadcom mini-PCI card, wrt54g capturesource)
						and kismet_drone 2006.04.R1 on Voyage Linux on a PC Engines WRAP.2E
						(CM9 mini-PCI card, madwifing)
                
        This file is part of KisMAC.

    KisMAC is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License, version 2,
    as published by the Free Software Foundation;

    KisMAC is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with KisMAC; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#import <Cocoa/Cocoa.h>
#import "WaveDriver.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define STREAM_DRONE_VERSION 9

#define STREAM_SENTINEL      0xDECAFBAD

#define STREAM_FTYPE_VERSION 1
#define STREAM_FTYPE_PACKET  2

#define STREAM_COMMAND_FLUSH -1

#define MAX_PACKET_LEN 10240

#define SSID_SIZE 255

@class WaveDriver;
struct stream_frame_header {
    uint32_t frame_sentinel;
    uint8_t frame_type;
    uint32_t frame_len;
} __attribute__((__packed__));

struct stream_version_packet {
    uint16_t drone_version;
	uint8_t gps_enabled;
};

struct stream_packet_header {
    uint32_t header_len;
    uint16_t drone_version;
    uint32_t len;
    uint32_t caplen;
    uint64_t tv_sec;
    uint64_t tv_usec;
    uint16_t quality;
    uint16_t signal;
    uint16_t noise;
    uint8_t error;
    uint8_t channel;
    uint8_t carrier;
    uint8_t encoding;
    uint32_t datarate;

    int16_t gps_lat;
    int64_t gps_lat_mant;
    int16_t gps_lon;
    int64_t gps_lon_mant;
    int16_t gps_alt;
    int64_t gps_alt_mant;
    int16_t gps_spd;
    int64_t gps_spd_mant;
    int16_t gps_heading;
    int64_t gps_heading_mant;
    int8_t gps_fix;

    uint8_t sourcename[32];
} __attribute__((__packed__));

typedef enum {
    carrier_unknown,
    carrier_80211b,
    carrier_80211bplus,
    carrier_80211a,
    carrier_80211g,
    carrier_80211fhss,
    carrier_80211dsss
} carrier_type;

typedef enum {
    encoding_unknown,
    encoding_cck,
    encoding_pbcc,
    encoding_ofdm
} encoding_type;

struct packet_parm {
    int fuzzy_crypt;
	int fuzzy_decode;
};

typedef struct kis_packet {
    unsigned int len;		// The amount of data we've actually got
    unsigned int caplen;	// The amount of data originally captured
    struct timeval ts;          // Capture timestamp
    int quality;                // Signal quality
    int signal;                 // Signal strength
    int noise;                  // Noise level
    int error;                  // Capture source told us this was a bad packet
    int channel;                // Hardware receive channel, if the drivers tell us
    int modified;               // Has moddata been populated?
    uint8_t *data;              // Raw packet data
    uint8_t *moddata;           // Modified packet data
    char sourcename[32];        // Name of the source that generated the data
	carrier_type carrier;       // Signal carrier
	encoding_type encoding;     // Signal encoding
    int datarate;               // Data rate in units of 100 kbps
    float gps_lat;              // GPS coordinates
    float gps_lon;
    float gps_alt;
    float gps_spd;
    float gps_heading;
    int gps_fix;
    struct packet_parm parm;           // Parameters from the packet source that trickle down
} kismet_packet;

typedef enum {
    packet_noise = -2,  // We're too short or otherwise corrupted
    packet_unknown = -1, // What are we?
    packet_management = 0, // LLC management
    packet_phy = 1, // Physical layer packets, most drivers can't provide these
    packet_data = 2 // Data frames
} packet_type;

// Subtypes are a little odd because we re-use values depending on the type
typedef enum {
    packet_sub_unknown = -1,
    // Management subtypes
    packet_sub_association_req = 0,
    packet_sub_association_resp = 1,
    packet_sub_reassociation_req = 2,
    packet_sub_reassociation_resp = 3,
    packet_sub_probe_req = 4,
    packet_sub_probe_resp = 5,
    packet_sub_beacon = 8,
    packet_sub_atim = 9,
    packet_sub_disassociation = 10,
    packet_sub_authentication = 11,
    packet_sub_deauthentication = 12,
    // Phy subtypes
    packet_sub_rts = 11,
    packet_sub_cts = 12,
    packet_sub_ack = 13,
    packet_sub_cf_end = 14,
    packet_sub_cf_end_ack = 15,
    // Data subtypes
    packet_sub_data = 0,
    packet_sub_data_cf_ack = 1,
    packet_sub_data_cf_poll = 2,
    packet_sub_data_cf_ack_poll = 3,
    packet_sub_data_null = 4,
    packet_sub_cf_ack = 5,
    packet_sub_cf_ack_poll = 6,
    packet_sub_data_qos_data = 8,
    packet_sub_data_qos_data_cf_ack = 9,
    packet_sub_data_qos_data_cf_poll = 10,
    packet_sub_data_qos_data_cf_ack_poll = 11,
    packet_sub_data_qos_null = 12,
    packet_sub_data_qos_cf_poll_nod = 14,
    packet_sub_data_qos_cf_ack_poll = 15
} packet_sub_type;

// distribution directions
typedef enum {
    no_distribution, from_distribution, to_distribution, inter_distribution, adhoc_distribution
} distribution_type;

typedef struct {
	short unsigned int macaddr[6];
} mac_addr;

typedef enum {
    proto_unknown,
    proto_udp, proto_misc_tcp, proto_arp, proto_dhcp_server,
    proto_cdp,
    proto_netbios, proto_netbios_tcp,
    proto_ipx,
    proto_ipx_tcp,
    proto_turbocell,
    proto_netstumbler,
    proto_lucenttest,
    proto_wellenreiter,
    proto_iapp,
    proto_leap,
    proto_ttls,
    proto_tls,
    proto_peap,
    proto_isakmp,
    proto_pptp,
} protocol_info_type;

typedef struct {
    unsigned int : 8 __attribute__ ((packed));
    unsigned int : 8 __attribute__ ((packed));

    unsigned int : 8 __attribute__ ((packed));
    unsigned int : 1 __attribute__ ((packed));
    unsigned int level1 : 1 __attribute__ ((packed));
    unsigned int igmp_forward : 1 __attribute__ ((packed));
    unsigned int nlp : 1 __attribute__ ((packed));
    unsigned int level2_switching : 1 __attribute__ ((packed));
    unsigned int level2_sourceroute : 1 __attribute__ ((packed));
    unsigned int level2_transparent : 1 __attribute__ ((packed));
    unsigned int level3 : 1 __attribute__ ((packed));
} cdp_capabilities;

#if BYTE_ORDER == BIG_ENDIAN
typedef struct {
    unsigned short subtype : 4 __attribute__ ((packed));
    unsigned short type : 2 __attribute__ ((packed));
    unsigned short version : 2 __attribute__ ((packed));

    unsigned short order : 1 __attribute__ ((packed));
    unsigned short wep : 1 __attribute__ ((packed));
    unsigned short more_data : 1 __attribute__ ((packed));
    unsigned short power_management : 1 __attribute__ ((packed));

    unsigned short retry : 1 __attribute__ ((packed));
    unsigned short more_fragments : 1 __attribute__ ((packed));
    unsigned short from_ds : 1 __attribute__ ((packed));
    unsigned short to_ds : 1 __attribute__ ((packed));
} frame_control;

typedef struct {
    uint8_t timestamp[8];

    // This field must be converted to host-endian before being used
    unsigned int beacon : 16 __attribute__ ((packed));

    unsigned short agility : 1 __attribute__ ((packed));
    unsigned short pbcc : 1 __attribute__ ((packed));
    unsigned short short_preamble : 1 __attribute__ ((packed));
    unsigned short wep : 1 __attribute__ ((packed));

    unsigned short unused2 : 1 __attribute__ ((packed));
    unsigned short unused1 : 1 __attribute__ ((packed));
    unsigned short ibss : 1 __attribute__ ((packed));
    unsigned short ess : 1 __attribute__ ((packed));

    unsigned int coordinator : 8 __attribute__ ((packed));

} fixed_parameters;

#else
typedef struct {
    unsigned short version : 2 __attribute__ ((packed));
    unsigned short type : 2 __attribute__ ((packed));
    unsigned short subtype : 4 __attribute__ ((packed));

    unsigned short to_ds : 1 __attribute__ ((packed));
    unsigned short from_ds : 1 __attribute__ ((packed));
    unsigned short more_fragments : 1 __attribute__ ((packed));
    unsigned short retry : 1 __attribute__ ((packed));

    unsigned short power_management : 1 __attribute__ ((packed));
    unsigned short more_data : 1 __attribute__ ((packed));
    unsigned short wep : 1 __attribute__ ((packed));
    unsigned short order : 1 __attribute__ ((packed));
} frame_control;

typedef struct {
    uint8_t timestamp[8];

    // This field must be converted to host-endian before being used
    unsigned int beacon : 16 __attribute__ ((packed));

    unsigned short ess : 1 __attribute__ ((packed));
    unsigned short ibss : 1 __attribute__ ((packed));
    unsigned short unused1 : 1 __attribute__ ((packed));
    unsigned short unused2 : 1 __attribute__ ((packed));

    unsigned short wep : 1 __attribute__ ((packed));
    unsigned short short_preamble : 1 __attribute__ ((packed));
    unsigned short pbcc : 1 __attribute__ ((packed));
    unsigned short agility : 1 __attribute__ ((packed));

    unsigned int coordinator : 8 __attribute__ ((packed));
} fixed_parameters;
#endif

typedef struct {
    char dev_id[128];
    uint8_t ip[4];
    char interface[128];
    cdp_capabilities cap;
    char software[512];
    char platform[128];
} cdp_packet;

typedef enum {
    proto_netbios_unknown,
    proto_netbios_host, proto_netbios_master,
    proto_netbios_domain, proto_netbios_query, proto_netbios_pdcquery
} protocol_netbios_type;

typedef struct {
    protocol_info_type type;
    uint8_t source_ip[4];
    uint8_t dest_ip[4];
    uint8_t misc_ip[4];
    uint8_t mask[4];
    uint8_t gate_ip[4];
    uint16_t sport, dport;
    cdp_packet cdp;
    char netbios_source[17];
    protocol_netbios_type nbtype;
    int prototype_extra;
} proto_info;

typedef enum {
    turbocell_unknown,
    turbocell_ispbase, // 0xA0
    turbocell_pollbase, // 0x80
    turbocell_nonpollbase, // 0x00
    turbocell_base // 0x40
} turbocell_type;

typedef struct {
    packet_type type;
    packet_sub_type subtype;
    uint16_t qos; 
    int corrupt;
    int reason_code;
    struct timeval ts;
    int quality;
    int signal;
    int noise;
    char ssid[SSID_SIZE+1];
    int ssid_len;
    char sourcename[32];
    distribution_type distrib;
	int crypt_set;
    int fuzzy;
    int ess;
    int channel;
    int encrypted;
    int decoded;
    int interesting;
    carrier_type carrier;
    encoding_type encoding;
    int datarate;
    mac_addr source_mac;
    mac_addr dest_mac;
    mac_addr bssid_mac;
    int beacon;
    char beacon_info[SSID_SIZE+1];
    unsigned int header_offset;
    proto_info proto;
    double maxrate;
    uint64_t timestamp;
    int sequence_number;
    int frag_number;
    int duration;
    int datasize;
    int turbocell_nid;
    turbocell_type turbocell_mode;
    int turbocell_sat;
    float gps_lat, gps_lon, gps_alt, gps_spd, gps_heading;
    int gps_fix;
    uint32_t ivset;
} packet_info;

@interface WaveDriverKismetDrone : WaveDriver {
    struct sockaddr_in drone_sock, local_sock;
	int drone_fd;
	int valid;
    int resyncs;	
    unsigned int resyncing;
    unsigned int stream_recv_bytes;
	struct stream_frame_header fhdr;
	struct stream_version_packet vpkt;
	struct stream_packet_header phdr;
    uint8_t databuf[MAX_PACKET_LEN];
	kismet_packet *packet;
	uint8_t data[MAX_PACKET_LEN];
    uint8_t moddata[MAX_PACKET_LEN];
}


@end

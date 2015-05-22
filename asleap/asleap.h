/*
 * asleap - recover weak LEAP passwords.  Pronounced "asleep".
 *
 * $Id: asleap.h,v 1.15 2004/11/29 19:56:33 jwright Exp $
 *
 * Copyright (c) 2004, Joshua Wright <jwright@hasborg.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See COPYING for more
 * details.
 *
 * asleap is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/*
 * Significant code is graciously taken from the following:
 * MS-CHAPv2 and attack tools by Jochen Eisinger, Univ. of Freiburg
 */

#include <asm/types.h>
#include <pcap.h>
#define IFNAMSIZ 16

/* modes for controlling HostAP with prism2 cards */
#define MODE_MANAGED 2
#define MODE_MONITOR 6
#define MODE_MASTER 3
#define MODE_SECOND 5

/* For error-checking purposes */
#define MAX_80211_PACKET_LEN 2312

/* frame control types */
#define WLAN_FC_TYPE_MGMT 0
#define WLAN_FC_TYPE_CTRL 1
#define WLAN_FC_TYPE_DATA 2

/* frame control management subtypes */
#define WLAN_FC_STYPE_ASSOC_REQ 0
#define WLAN_FC_STYPE_ASSOC_RESP 1
#define WLAN_FC_STYPE_REASSOC_REQ 2
#define WLAN_FC_STYPE_REASSOC_RESP 3
#define WLAN_FC_STYPE_PROBE_REQ 4
#define WLAN_FC_STYPE_PROBE_RESP 5
#define WLAN_FC_STYPE_BEACON 8
#define WLAN_FC_STYPE_ATIM 9
#define WLAN_FC_STYPE_DISASSOC 10
#define WLAN_FC_STYPE_AUTH 11
#define WLAN_FC_STYPE_DEAUTH 12

/* for AirJack headers */
#define FC_TYPE_MGT 0x00
#define MGT_DEAUTH 0x0C
#define mh_type			fc1.fc2.fc2_type
#define mh_subtype		fc1.fc2.fc2_subtype
#define mh_from_ds		fc1.fc2.fc2_from_ds

/* File types for offline pcap */
#define UNRECOGNIZED_FILE 0
#define LPCAP_DLTRFMON_PCAP 1
#define LPCAP_DLTETH_PCAP 2
#define LPCAP_DLTNULL_PCAP 3
#define LPCAP_DLTTZSP_PCAP 4
#define APEEK_LEGACY_OFFLINE_PCAP 5
#define APEEK_XML_OFFLINE_PCAP 6

/* AiroPeek Legacy File Identification Information */
#define SECONDH_PHYSMEDIUM 1
#define MASTERH_VERSION 7
#define MASTERH_STATUS 0

/* AiroPeek XML'ish File Identification Information */
#define APEEKX_MAGIC_NUM 0x7265767f
#define FILE_VERSION "<FileVersion>9</FileVersion>"
#define PKTS_HEADER 0x706b7473
#define APEEKX_MIN_PKTS_OFFSET 0x650 /* Minimum offset for beginning of packet
                                       information */

/* Magic number information for libpcap files */
#define LEPCAP_MAGIC_NUM 0xd4c3b2a1 /* Little Endian */
#define BEPCAP_MAGIC_NUM 0xa1b2c3d4 /* Big Endian */

/* Offset information for header information */
#define DOT11LINK_DOT11_OFFSET 0
#define DOT11LINK_DOT1X_OFFSET 32
#define DOT11LINK_LEAP_OFFSET 36
#define DOT11LINK_IP_OFFSET 32
#define EN10MBLINK_DOT1X_OFFSET 14
#define EN10MBLINK_LEAP_OFFSET 18
#define EN10MBLINK_IP_OFFSET 14
#define NULLLINK_DOT1X_OFFSET EN10MBLINK_DOT1X_OFFSET
#define NULLLINK_IP_OFFSET EN10MBLINK_IP_OFFSET
#define NULLLINK_LEAP_OFFSET EN10MBLINK_LEAP_OFFSET
#define TZSP_DOT11_OFFSET 29
#define TZSP_DOT1X_OFFSET 61
#define TZSP_LEAP_OFFSET 65
#define TZSP_IP_OFFSET 61

/* These offsets follow start at the beginning of the IP Header */
//#define GREOFFSET   20
#define IPHDRLEN   20 /* Not always constant, but usually */
#define GREMINHDRLEN 8
#define GRESYNSETFLAG 0x0010
#define GREACKSETFLAG 0x8000
//#define PPPGREOFFSET  16
#define PPPGRECHAPOFFSET 2
#define PPPUSERNAMEOFFSET 54

#define LPEXCH_ERR -1
#define LPEXCH_TIMEOUT 0
#define LEAPEXCHFOUND 1
#define PPTPEXCHFOUND 2

#define GREPROTOPPP 0x880b
#define PPPPROTOCHAP 0xc223

/* asleap data structure, containing information from command line options and
   gathered information from the network.
   XXX This should *really* be broken up into two structures for command line
   configuration information and packet capture results.  Such is the result
   of poor planning in the initial design. */
struct asleap_data {
    __u8    username[256+1];
    __u8    challenge[8];
    __u8    response[24];
    __u8    endofhash[2];
    __u8    password[32];
    __u8    nthash[16];
    /* for PPTP/true MS-CHAPv2 */
    __u8    pptpauthchal[16];
    __u8    pptppeerchal[16];
//    __u8    pptpchal[8];
//    __u8    pptppeerresp[24];

    int   eapsuccess;
	int   skipeapsuccess; /* Don't bother checking for success after auth */
    int	  verbose;
    char  dictfile[255];
    char  dictidx[255];
    char  wordfile[255];

    /* Tracking values */
    __u8    leapchalfound;
    __u8    leaprespfound;
    __u8    leapsuccessfound;
    __u8    pptpchalfound;
    __u8    pptprespfound;
    __u8    pptpsuccessfound;
} __attribute__ ((packed));


typedef struct airjack_data {
    char    ifname[IFNAMSIZ]; /* interface name */
    __u8    own_addr[6]; /* own MAC address */
} ajdata_t;

struct clientlist_data {
    __u8    stamac[6];
};

struct dump_output {
    char    wfilename[255];
    pcap_dumper_t *wp;
};

struct capturedata_s {
    int     captype;
    /* Should include the file handle for pcap here as well */
    FILE    *apeekfp;
    char    filename[255];
    unsigned short int     pcaptype;
    unsigned short int     livecapture;
    int     dot11offset;
    int     dot1xoffset;
    int     leapoffset;
    int     iphdroffset;
};


/* Airopeek legacy file format information taken from Ethereal source.
   Thanks guys */

/* Master header for Legacy AiroPeek NX files */
struct apeekl_master_h {
    __u8    version;
    __u8    status;
} __attribute__ ((packed));

/* Secondary header for Legacy AiroPeek NX files */
struct apeekl_secondary_h {
    __u32   filelength;
    __u32   numpackets;
    __u32   timedate;
    __u32   timestart;
    __u32   timestop;
    __u32   mediatype;
    __u32   physmedium;
    __u32   appver;
    __u32   linkspeed;
    __u32   reserved[3];
} __attribute__ ((packed));

/* Record header for Legacy AiroPeek NX files */
struct apeekl_rec_h {
    __u16   protonum;
    __u16   length;
    __u16   slice_length;
    __u8    flags;
    __u8    status;
    __u32   timestamp_upper;
    __u32   timestamp_lower;
    /* Next 4 fields are for radio information */
    __u8    data_rate;
    __u8    channel;
    __u8    signal_level;
    __u8    reserved1;
} __attribute__ ((packed));



/* Airopeek 2.X NEW file format, some XML information is embedded.  We only
   care about the packet payload information. 
   Many thanks to Dmitri Varsanofiev for making his analysis of this file i
   format available:  http://www.varsanofiev.com/inside/airopeekv9.htm

   The fields with leading h_ indicate header tags for the information that
   follows.  According to Dmitri, AiroPeek files using this format use the
   following tags:

       0100	Header for LSB of timestamp
       0200     Header for MSB of timestamp
       0300     Header for flag information
       0400     Header for channel number
       0500     Header for rate information
       0600     Header for signal level in %
       0700     Header for signal level in dBm
       0800     Not sure what this is for, data is always 0's in my analysis
       0900     Mystery tag, the value "0180FFFFFFFF" always follows
*/

/* Data that indicates the start of the packet portion of the file */
struct apeekx_pkts_h {
    __u8     unknown[8];         /* Observed always NULL */
} __attribute__ ((packed));

/* Data that precedes each packet in the file */
struct apeekx_rec_h {
    __u16    unknown1;
    __u32    length1;
    __u16    h_timestamp_upper;
    __u32    timestamp_upper;
    __u16    h_timestamp_lower;
    __u32    timestamp_lower;
    __u16    h_flags;
    __u32    flags;
    __u16    h_channel;
    __u32    channel;
    __u16    h_data_rate;
    __u32    data_rate;
    __u16    h_signal_level_percent;
    __u32    signal_level_percent;
    __u16    h_signal_level_dbm;
    __u32    signal_level_dbm;
    __u16    h_unknown2;
    __u32    unknown2;
    __u16    h_unknown3;
    __u8     unknown3[6];  /* Mystery 01 80 FF FF FF FF data */
    __u32    length2;
} __attribute__ ((packed));


/* 802.11 frame formats */

struct ieee80211 {
    __u8    version:2;
    __u8    type:2;
    __u8    subtype:4;
    __u8    to_ds:1;
    __u8    from_ds:1;
    __u8    more_frag:1;
    __u8    retry:1;
    __u8    pwrmgmt:1;
    __u8    more_data:1;
    __u8    wep:1;
    __u8    order:1;
    __u16	  duration;
    __u8    addr1[6];
    __u8    addr2[6];
    __u8    addr3[6];
    __u16   fragment:4;
    __u16   sequence:12;
} __attribute__ ((packed));

struct ieee80211_mgmt {
    __u16 frame_control;
    __u16 duration;
    __u8  da[6];
    __u8  sa[6];
    __u8  bssid[6];
    __u16 seq_ctrl;
    union {
        struct {
             __u16 reason_code;
        } __attribute__ ((packed)) deauth;
        struct {
             __u16 reason_code;
        } __attribute__ ((packed)) disassoc;
    } u;
} __attribute__ ((packed)) ;


/* AirJack needs 4 address fields for transmitting packets */
struct ieee80211_a4_mgmt {
    __u16 frame_control;
    __u16 duration;
    __u8  da[6];
    __u8  sa[6];
    __u8  bssid[6];
    __u16 seq_ctrl;
    __u8  ta[6];
    union {
        struct {
             __u16 reason_code;
        } __attribute__ ((packed)) deauth;
        struct {
             __u16 reason_code;
        } __attribute__ ((packed)) disassoc;
    } u;
} __attribute__ ((packed)) ;


/*** four address Mac Header ***/
struct a4_80211 {
    union {
        __u16	fc1_frame_control;
        struct {
            __u16	fc2_version:2;
            __u16	fc2_type:2;
            __u16	fc2_subtype:4;
            __u16	fc2_to_ds:1;
            __u16	fc2_from_ds:1;
            __u16	fc2_more_frag:1;
            __u16	fc2_retry:1;
            __u16	fc2_pwr_man:1;
            __u16	fc2_more_data:1;
            __u16	fc2_wep:1;
            __u16	fc2_order:1;
        } fc2;
    } fc1;
    __u16	mh_duration_id;
    __u8	mh_mac1[6];
    __u8	mh_mac2[6];
    __u8	mh_mac3[6];
    union {
        __u16	seq1_seq;
        struct {
            __u16	seq2_frag_num:4;
            __u16	seq2_seq_num:12;
        } seq2;
    } seq1;
    __u8	mh_mac4[6];
};


/* We don't really care about these values, they are just included here
   for sanity's sake */
struct ieee8022 {
    __u8    dsap;
    __u8    ssap;
    __u8    control;
    __u8    oui[3];
    __u8    type[2];
} __attribute__ ((packed));


/* The 802.1x header indicates a version, type and length */
struct ieee8021x {
    __u8    version;
    __u8    type;
    __u16   length;
} __attribute__ ((packed));


/* This is the structure of Cisco LEAP packets.  Reference:
   http://www.missl.cs.umd.edu/wireless/ethereal/leap.txt */
struct eap_leap {
    __u8    code; /* 1=request, 2=response, 3=success, 4=failure? */
    __u8    identifier; /* Sequential counter, not sure what it's for */
    __u16   length; /* Length of the entire EAP message */
    __u8    type; /* 0x11 for LEAP */
    __u8    version; /* Always 1 in my tests */
    __u8    reserved;
    __u8    count; /* Length in octets of the challenge/response field */
    /* The challenge or response field follows count, depending on code. */
    /* The username follows, variable length.  Must calculate based on 
       length - (count + sizeof(eap_leap)) */
} __attribute__ ((packed));

/* This is the structure of the GRE header */
struct grehdr {
    __u16   flags;
    __u16   type;
    __u16   length;
    __u16   callid;
    __u16   seq; /* optional based on flags */
    __u16   ack; /* optional based on flags */
} __attribute__ ((packed));

/* This is the structure of the Point-to-Point Protocol header */
struct ppphdr {
    __u16   proto;
} __attribute__ ((packed));

/* This is the structure of the PPP CHAP header */
struct pppchaphdr {
    __u8    code;
    __u8    identifier;
    __u16   length;
    union {
        struct {
            __u8    datalen;
            __u8    authchal[16];
        } chaldata;
        struct {
            __u8    datalen;
            __u8    peerchal[16];
            __u8    unknown[8]; /* all zero's */
            __u8    peerresp[24];
            __u8    state;
            __u8    *name;
        } respdata;
    } u;
} __attribute__ ((packed));


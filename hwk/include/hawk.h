/*******************************************************************************
 *                ____                     _ __                                *
 *     ___  __ __/ / /__ ___ ______ ______(_) /___ __                          *
 *    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                          *
 *   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                           *
 *                                            /___/ team                       *
 *                                                                             *
 * hawk.h                                                                      *
 *                                                                             *
 * DATE                                                                        *
 * 18/09/2012                                                                  *
 *                                                                             *
 * AUTHOR                                                                      *
 * atzeton - http://www.nullsecurity.net/                                      *
 *                                                                             *
 * LICENSE                                                                     *
 * GNU GPLv2, see COPYING                                                      *
 *                                                                             *
 ******************************************************************************/

#ifndef HDR_HAWK
#define HDR_HAWK

#include <inttypes.h>
#include <pcap.h>
#include "hwk.h"


#define __BANNER printf(\
"\t __                   __    \n"\
"\t|  |__ _____ __  _  _|  | __\n"\
"\t|  |  \\\\__  \\\\ \\/ \\/ /  |/ /\n"\
"\t|   Y  \\/ __ \\\\     /|    < \n"\
"\t|___|  (____  /\\/\\_/ |__|_ \\\n"\
"\t     \\/     \\/            \\/\n"\
"\n"\
"> hawk "VERSION" by atzeton - 802.11 stress testing \n"\
"> check out http://nullsecurity.net for updates!\n"\
"> hawk comes with ABSOLUTELY NO WARRANTY, USE AT YOUR OWN RISK\n")


#define AUTH_INJECT   (1)
#define DEAUTH_INJECT (2)

#define __REQUIRED_BSSID if(memcmp(opts->bssid,MAC_ZERO_ADDR,6) == 0) { __ERROR("BSSID not given"); __EXIT_FAILURE;}
#define __REQUIRED_CLMAC if(memcmp(opts->clmac,MAC_ZERO_ADDR,6) == 0) { __ERROR("Client mac not given"); __EXIT_FAILURE;}

#define IEEE80211_QOS_DATA	 				(0x28)
#define IEEE80211_NULL		 				(0x24)
#define IEEE80211_BEACON 					(0x08)
#define IEEE80211_DATA		 				(0x20)


typedef struct IEEE80211_FCTRL {
	unsigned version:2;
	unsigned type:2;
	unsigned subtype:4;
	unsigned to_ds:1;
	unsigned from_ds:1;
	unsigned mf:1;
	unsigned retry:1;
	unsigned pwr:1;
	unsigned moredata:1;
	unsigned protected:1;
	unsigned order:1;
} IEEE80211_FCTRL_t;

typedef struct IEEE80211_MAC {
	uint16_t fctrl;
	uint16_t drtn;
	uint8_t dst[6];
	uint8_t src[6];
	uint8_t bssid[6];
	uint16_t seq;
} IEEE80211_MAC_t;


typedef struct IEEE80211_BEACON_t {
	uint16_t fctrl;
	uint16_t drtn;
	uint8_t dst[6];
	uint8_t src[6];
	uint8_t bssid[6];
	uint16_t seq;
} IEEE80211_BEACON_t;
	
typedef struct IEEE80211_BEACON_FIXEDPARAM {
	unsigned timestamp1:32;
	unsigned timestamp2:32;
	
	unsigned beacon_interval:16;
	unsigned ess_ap:1;
	unsigned ibss_stat:1;
	unsigned cfp_part:2;
	unsigned wep:1;
	unsigned short_preamble:1;
	unsigned pbcc:1;
	unsigned chan_agi:1;
	unsigned spec_man:1;
	unsigned cfp_part2:1;
	unsigned sslottime:1;
	unsigned apsd:1;
	unsigned dsss_ofdm:1;
	unsigned del_bl_ack:1;
	unsigned imm_bl_ack:1;
} IEEE80211_BEACON_FIXEDPARAM_t;


typedef struct IEEE80211_PROBE_REQUEST_t {
	uint16_t duration;	
	uint8_t dst[6];
	uint8_t src[6];
	uint8_t bssid[6];
	uint16_t seq;
} IEEE80211_PROBE_REQUEST_t;

typedef struct IEEE80211_PROBE_RESPONSE_t {
	uint16_t duration;	
	uint8_t dst[6];
	uint8_t src[6];
	uint8_t bssid[6];
	uint16_t seq;		
} IEEE80211_PROBE_RESPONSE_t;


/* ToDS */
typedef struct IEEE80211_DATA_t {
	uint16_t duration;	
	uint8_t bssid[6];
	uint8_t src[6];
	uint8_t dst[6];
	uint16_t seq;
} IEEE80211_DATA_t;

typedef struct IEEE80211_DATA2_t {
	uint16_t duration;	
	uint8_t dst[6];
	uint8_t bssid[6];
	uint8_t src[6];
	uint16_t seq;
} IEEE80211_DATA2_t;

typedef struct IEEE80211_CTS_t {
	uint16_t duration;	
	uint8_t dst[6];
} IEEE80211_CTS_t;
	
typedef struct IEEE80211_AUTH_t {
	uint16_t fctrl;
	uint16_t duration;	
	uint8_t dst[6];
	uint8_t src[6];
	uint8_t bssid[6];
	uint16_t seq;
	
	uint16_t aalg;
	uint16_t aseq;
	uint16_t acode;
	
} IEEE80211_AUTH_t;

typedef struct IEEE80211_AUTH_FIXED_t {
	uint16_t algorithm;
	uint16_t seq;
	uint16_t code;
} IEEE80211_AUTH_FIXED_t;

typedef struct IEEE80211_DEAUTH_t {
	uint16_t fctrl;
	uint16_t duration;	
	uint8_t dst[6];
	uint8_t src[6];
	uint8_t bssid[6];
	uint16_t seq;
	uint16_t reason;
} IEEE80211_DEAUTH_t;


typedef struct IEEE80211_NULL_t {
	uint8_t recv[6];
	uint8_t tansm[6];
	uint8_t dst[6];
	uint16_t seq;
	uint8_t src[6];
} IEEE80211_NULL_t;

typedef struct IEEE80211_ACK_t {
	uint16_t fctrl;
	uint16_t duration;	
	uint8_t dst[6];
} IEEE80211_ACK_t;

typedef struct client_elem {
	uint8_t addr[6];
	struct client_elem *next;
} client_t;

typedef struct netelem {
	uint8_t  bssid[6];
	int8_t   channel;
	uint16_t lseq;
	client_t *first_client;
	client_t *last_client;
	struct netelem *next;
} bssid_t;


typedef struct OPTS_t {
	pcap_t  *pcapd;
	char	 pcap_errbuf[PCAP_ERRBUF_SIZE]; 

	char *iface;
	
	uint8_t mode;
	uint32_t delay;
	
	int scandelay;
	
	uint16_t channel;
	
	uint16_t current_seq;
	
	uint8_t  bssid[6];
	uint8_t  clmac[6];
	uint8_t  dstmac[6];
	
	bssid_t *first_bssid;
	bssid_t *last_bssid;

} OPTS_t;


OPTS_t 		*opts_init();
void 		seq_cancel_thread(pthread_t trd);
pthread_t	seq_start_thread();
void 		print_mac_addr(uint8_t *addr);
void 		help();
void 		sig_int();

#endif


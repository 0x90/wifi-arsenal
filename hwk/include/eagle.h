/*******************************************************************************
 *                ____                     _ __                                *
 *     ___  __ __/ / /__ ___ ______ ______(_) /___ __                          *
 *    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                          *
 *   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                           *
 *                                            /___/ team                       *
 *                                                                             *
 * eagle.h                                                                     *
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

#ifndef HDR_EAGLE
#define HDR_EAGLE

#include <inttypes.h>
#include <pcap.h>
#include "rtap.h"

#include "hwk.h"
#include "wlan.h"
#include "llc.h"
#include "field.h"

#define __BANNER printf(\
"\t                       __          \n"\
"\t  ____ _____     ____ |  |   ____  \n"\
"\t_/ __ \\\\__  \\   / ___\\|  | _/ __ \\\n"\
"\t\\  ___/ / __ \\_/ /_/  >  |_\\  ___/ \n"\
"\t \\___  >____  /\\___  /|____/\\___  >\n"\
"\t     \\/     \\//_____/           \\/ \n"\
"\n"\
"> eagle "VERSION" by atzeton - 802.11 packet crafting\n"\
"> check out http://nullsecurity.net for updates!\n"\
"> eagle comes with ABSOLUTELY NO WARRANTY, USE AT YOUR OWN RISK\n")

#define __APPEND_RTAP               ( opts->rtap_append = 1         )
#define __APPEND_WLAN_HEADER 		( opts->wlan_append = 1 		) 
#define __APPEND_MGT_HEADER  		( opts->mgt_append = 1  		) 
#define __APPEND_MGT_TAGGED_HEADER  ( opts->mgt_append_tagged = 1  	) 
#define __APPEND_LLC_HEADER  		( opts->llc_append = 1 			) 
#define __APPEND_PAYLOAD			( opts->payload_append = 1 		)

#define __NO_IFACE 	                ( opts->iface == NULL)

#define __OPT(x)	                ( strcmp(opt->name,x) == 0)


typedef struct OPTS_t {
	pcap_t  *pcapd;
	char	 pcap_errbuf[PCAP_ERRBUF_SIZE]; 
	char    *iface;
	
	uint32_t delay;
	uint16_t mtu;
	uint16_t channel;
	
	uint8_t  bssid[6];
	uint8_t  clmac[6];
	uint8_t  dstmac[6];
	
	uint8_t  rtap_append;
	FIELD_t *rtap_hrev;
	FIELD_t *rtap_hpad;
	FIELD_t *rtap_hlen;
	FIELD_t *rtap_pflags;
	FIELD_t *rtap_rate;
	
	uint8_t  wlan_append;
	FIELD_t *wlan_fctrl;
	FIELD_t *wlan_drtn;
	FIELD_t *wlan_dst;
	FIELD_t *wlan_src;
	FIELD_t *wlan_bssid;
	FIELD_t *wlan_seq;
	
	uint8_t  mgt_append;
	FIELD_t *mgt_fixed_bi;
	FIELD_t *mgt_fixed_capinf;
	
	uint8_t  mgt_append_tagged;
	FIELD_t *mgt_tagged_count;
	
	FIELD_t *mgt_tagged_id;
	FIELD_t *mgt_tagged_len;
	
	uint8_t  llc_append;
	FIELD_t *llc_dsap;
	FIELD_t *llc_ssap;
	FIELD_t *llc_ctrl;
	FIELD_t *llc_ocode;
	FIELD_t *llc_type;

	uint8_t  payload_append;
	FIELD_t *payload_len;
	
} OPTS_t;


PACKET_t   *payload_append(uint16_t len);
void 		help();
void 		sig_int();


#endif


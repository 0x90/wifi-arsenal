/*******************************************************************************
 *                ____                     _ __                                *
 *     ___  __ __/ / /__ ___ ______ ______(_) /___ __                          *
 *    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                          *
 *   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                           *
 *                                            /___/ team                       *
 *                                                                             *
 * rtap.h                                                                      *
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

#ifndef HDR_RADIOTAP
#define HDR_RADIOTAP

#include <inttypes.h>
#include "packet.h"

#define RADIOTAP_HAVE_FULL      (26) /* grrr argh... */
#define RADIOTAP_RESTRICED_SIZE ( 5)
#define RADIOTAP_PREAMBLE_SIZE  ( 8)

typedef struct RADIOTAP_CTYPE_t {
	unsigned unused0:4;
	unsigned turbo:1;
	unsigned cck:1;
	unsigned ofdm:1;
	unsigned _2GHz:1;
	unsigned _5GHz:1;
	unsigned passive:1;
	unsigned dynamic_cck_ofdm:1;
	unsigned gfsk:1;
	unsigned GSM_900MHz:1;
	unsigned static_turbo:1;
	unsigned halfrc_10MHz:1;
	unsigned quartrc_5MHz:1;
} RADIOTAP_CTYPE_t;

typedef struct RADIOTAP_PFLAGS_t {
	unsigned tsft:1;
	unsigned flags:1;
	unsigned rate:1;
	unsigned channel:1;
	unsigned fhss:1;
	unsigned dbm_signal:1;
	unsigned dbm_noise:1;
	unsigned lockqa:1;		
	unsigned txatt:1;
	unsigned dbtxatt:1;	
	unsigned dbm_tx_power:1;
	unsigned antenna:1;	
	unsigned db_signal:1;
	unsigned db_noise:1;	
	unsigned rx_flags:1;
	unsigned unused2:3;
	unsigned channelplus:1;
	unsigned unused1:4;
	unsigned unused0;
	unsigned ext:1;
} RADIOTAP_PFLAGS_t;

typedef struct RADIOTAP_FLAGS_t {
	unsigned cfp:1;
	unsigned preamble:1;
	unsigned wep:1; /* == 0 yeah */
	unsigned frag:1;
	unsigned fcs:1; 
	unsigned datapad:1;
	unsigned bad_fcs:1;
	unsigned shortGI:1;
} RADIOTAP_FLAGS_t;


/* Preamble is always the same.*/
typedef struct RADIOTAP_PREAMBLE_t {
	uint8_t hrev;
	uint8_t hpad;
	uint16_t hlen;
	uint32_t pflags;
} RADIOTAP_PREAMBLE_t;

typedef struct RADIOTAP_t {
	uint64_t tsft;
	uint16_t channel;
	uint16_t channel2;
	uint16_t fhss;
	uint8_t rate;
	int8_t dbm_signal;
	int8_t dbm_noise;
	uint8_t db_signal;
	uint8_t db_noise;
	uint16_t lock_quality; /* what the hell? (Barker Code lock) */
	uint16_t tx_attenuation;
	uint16_t db_tx_attenuation;
	int8_t dbm_tx_power;
	uint8_t flags;
	uint8_t antenna;
	uint16_t rx_flags;
	uint16_t tx_flags;
	uint8_t rts_retries;
	uint8_t data_retries;
} RADIOTAP_t;

typedef struct RADIOTAP_CONTROL_t {
	RADIOTAP_PREAMBLE_t rpre;
	RADIOTAP_PFLAGS_t rpflags;
	RADIOTAP_t rtap;
} RADIOTAP_CONTROL_t;


/* in fact there is no restricted radiotap header */
typedef struct RADIOTAP_RESTRICTED {
	uint8_t rate;
	uint8_t placebo[4];
} RADIOTAP_RESTRICTED_t;

#define RADIOTAP_SEND_LEN (13)

typedef struct RADIOTAP_SEND_t {
	uint8_t hrev;
	uint8_t hpad;
	uint16_t hlen;
	uint32_t pflags;
	uint8_t rate;
	uint8_t unknown;
} RADIOTAP_SEND_t;


RADIOTAP_CONTROL_t 	*radiotap_init();
PACKET_t 			*rtap_build_send();
PACKET_t 			*rtap_build_custom_send(uint8_t hrev, uint8_t hpad, uint16_t hlen, uint32_t pflags, uint8_t rate);
int8_t   			 radiotap_parse(const uint8_t *pkt, RADIOTAP_CONTROL_t *rmanage);
uint16_t 			 radiotap_get_total_length(RADIOTAP_CONTROL_t *rmanage);

#endif


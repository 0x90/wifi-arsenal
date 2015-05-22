/*******************************************************************************
 *                ____                     _ __                                *
 *     ___  __ __/ / /__ ___ ______ ______(_) /___ __                          *
 *    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                          *
 *   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                           *
 *                                            /___/ team                       *
 *                                                                             *
 * wlan.h                                                                      *
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

#ifndef HDR_WLAN
#define HDR_WLAN

#include <inttypes.h>

typedef struct FCTRL_t {
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
} FCTRL_t;


typedef struct WLAN_SEND_t {
	uint16_t fctrl;
	uint16_t drtn;
	uint8_t mac1[6];
	uint8_t mac2[6];
	uint8_t mac3[6];
	uint16_t seq;
} WLAN_SEND_t;

typedef struct BEACON_FIXED_t {
	uint8_t tstamp[8];
	uint16_t binterval;
	uint16_t cinf;
} BEACON_FIXED_t;

PACKET_t 		*wlan_build_custom( uint16_t fctrl, uint16_t drtn, uint8_t *src, uint8_t *dst, uint8_t *bssid, uint16_t seq);


#endif


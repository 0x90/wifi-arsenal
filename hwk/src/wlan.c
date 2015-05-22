/*******************************************************************************
 *                ____                     _ __                                *
 *     ___  __ __/ / /__ ___ ______ ______(_) /___ __                          *
 *    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                          *
 *   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                           *
 *                                            /___/ team                       *
 *                                                                             *
 * wlan.c                                                                      *
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>

#include "packet.h"
#include "wlan.h"

#include "hwk.h"


PACKET_t *
wlan_build_custom( uint16_t fctrl, uint16_t drtn, uint8_t *src, uint8_t *dst, uint8_t *bssid, uint16_t seq)
{
	WLAN_SEND_t *wlan = calloc(1, sizeof(WLAN_SEND_t) );
	
	wlan->fctrl = fctrl;
	wlan->drtn = drtn;
	
	FCTRL_t *fc = (FCTRL_t *)&wlan->fctrl;
	
	if( fc->to_ds == 0 && fc->from_ds == 0) {
		memcpy(wlan->mac2, src, 6);
		memcpy(wlan->mac1, dst, 6);
		memcpy(wlan->mac3, bssid, 6);
	}
	
	//if( fc->from_ds == 1) {
	//	memcpy(wlan->mac1, dst, 6);
	//	memcpy(wlan->mac2, src, 6);
	//	memcpy(wlan->mac3, bssid, 6);

	//}

	wlan->seq = seq;

	PACKET_t *wp = packet_create( (uint8_t *)wlan, sizeof(WLAN_SEND_t) );
	
	return( wp );
}

PACKET_t *
wlan_build_param_fixed(uint16_t interval, uint16_t capinfo)
{
	BEACON_FIXED_t *beacon = calloc(1, sizeof( BEACON_FIXED_t *));
	
	uint8_t i = 0;
	for(i=0; i<8; i++) {
		memset(&beacon->tstamp[i], __RAND_U8 , 1);
	}
	
	beacon->binterval = interval;
	beacon->cinf = capinfo;

	PACKET_t *p = packet_create( (uint8_t *)beacon, sizeof(BEACON_FIXED_t) );

	return(p);
}


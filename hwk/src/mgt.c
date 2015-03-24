/*******************************************************************************
 *                ____                     _ __                                *
 *     ___  __ __/ / /__ ___ ______ ______(_) /___ __                          *
 *    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                          *
 *   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                           *
 *                                            /___/ team                       *
 *                                                                             *
 * mgt.c                                                                       *
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
#include "mgt.h"

#include "hwk.h"



PACKET_t *
mgt_build_param_fixed(uint16_t interval, uint16_t capinfo)
{
	MGT_FIXED_t *beacon = calloc(1, sizeof( MGT_FIXED_t *));
	
	uint8_t i = 0;
	for(i=0; i<8; i++) {
		memset(&beacon->tstamp[i], __RAND_U8 , 1);
	}
	
	beacon->binterval = interval;
	beacon->cinf = capinfo;

	PACKET_t *p = packet_create( (uint8_t *)beacon, sizeof(MGT_FIXED_t) );

	return(p);
}

PACKET_t *
mgt_build_tagged( uint8_t id, uint8_t len)
{
	uint8_t *pkt = calloc(1, len +2 );
	
	memset(&pkt[0], id, 1);  // tag id
	memset(&pkt[1], len, 1); // length
	
	
	uint8_t i = 0;
	
	for(i=0; i<len; i++) {
		memset(&pkt[2+i], __RAND_U8 , 1);
	}
	
	
	return( packet_create( pkt, len + 2) );
}


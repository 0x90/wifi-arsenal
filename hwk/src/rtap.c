/*******************************************************************************
 *                ____                     _ __                                *
 *     ___  __ __/ / /__ ___ ______ ______(_) /___ __                          *
 *    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                          *
 *   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                           *
 *                                            /___/ team                       *
 *                                                                             *
 * rtap.c                                                                        *
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
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/wireless.h>
#include <sys/ioctl.h>
#include <string.h>
#include <inttypes.h>
#include <pcap.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <signal.h>
#include <ctype.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>

#include "rtap.h"
#include "packet.h"


/* allocate space for the radiotap header */    
RADIOTAP_CONTROL_t
*radiotap_init() 
{
	RADIOTAP_CONTROL_t *rctrl = calloc(1, sizeof(RADIOTAP_CONTROL_t) );
	
    return( rctrl );
}


PACKET_t
*rtap_build_send()
{
	RADIOTAP_SEND_t *rs = (RADIOTAP_SEND_t *) calloc(1, RADIOTAP_SEND_LEN );
	
	rs->hrev    = 0x00;
	rs->hpad    = 0x00;
	rs->hlen    = 0x000d;
	rs->pflags  = 0x00028004;
	rs->rate    = 0x02;
	
	
	PACKET_t *rtap = packet_create( (uint8_t *)rs, RADIOTAP_SEND_LEN );
	
	return( rtap );
}

PACKET_t
*rtap_build_custom_send(uint8_t hrev, uint8_t hpad, uint16_t hlen, uint32_t pflags, uint8_t rate)
{
	RADIOTAP_SEND_t *rs = (RADIOTAP_SEND_t *) calloc(1, RADIOTAP_SEND_LEN );
	
	rs->hrev    = hrev;
	rs->hpad    = hpad;
	rs->hlen    = hlen;
	rs->pflags  = pflags;
	rs->rate    = rate;
	
	PACKET_t *rtap = packet_create( (uint8_t *)rs, RADIOTAP_SEND_LEN );
	
	return( rtap );
}


/* parse the radiotap header */
int8_t 
radiotap_parse(const uint8_t *pkt, RADIOTAP_CONTROL_t *rmanage) 
{   
    RADIOTAP_PREAMBLE_t *rpre  		= NULL;
    RADIOTAP_PFLAGS_t *rpflags 		= NULL;
    size_t iterator         		= sizeof(RADIOTAP_PREAMBLE_t);
    
    rpre = (RADIOTAP_PREAMBLE_t *)pkt;            /* first parse the preable which is always the same  */
    rpflags = (RADIOTAP_PFLAGS_t *)&rpre->pflags; /* rpflags is a bitmap indicating the present fields */
    
    memcpy(&rmanage->rpre,rpre,		 sizeof(RADIOTAP_PREAMBLE_t));
    memcpy(&rmanage->rpflags,rpflags,sizeof(RADIOTAP_PFLAGS_t));
    
    /* time sync */
    if( rpflags->tsft == 0x01 ) {
        memcpy(&rmanage->rtap.tsft,&pkt[iterator],8);
        iterator += sizeof(uint64_t);
    }
            
    /* channel flags */
    if( rpflags->flags == 0x01 ) {
        memcpy(&rmanage->rtap.flags,&pkt[iterator],1);
        iterator += sizeof(uint8_t);
    }
            
    /* rate */
    if( rpflags->rate == 0x01 ) {
        memcpy(&rmanage->rtap.rate,&pkt[iterator],1);
        iterator += sizeof(uint8_t);
    }
    
    /* channel */   
    if( rpflags->channel == 0x01) {
        memcpy(&rmanage->rtap.channel,&pkt[iterator],2);
        iterator += sizeof(uint16_t);
    }
    
    /* frequency hopping */
    if( rpflags->fhss == 0x01 ) {
        memcpy(&rmanage->rtap.rate,&pkt[iterator],2);
        iterator += sizeof(uint16_t);
    }
    
    /* */
    if( rpflags->flags == 0x01 ) {
        memcpy(&rmanage->rtap.flags,&pkt[iterator],2);
        iterator += sizeof(uint16_t);
    }
    
    if( rpflags->dbm_signal == 0x01 ) {
        memcpy(&rmanage->rtap.dbm_signal,&pkt[iterator],1);
        iterator += sizeof(int8_t);
    }
    
    if( rpflags->dbm_noise == 0x01 ) {
        memcpy(&rmanage->rtap.dbm_noise,&pkt[iterator],1);
        iterator += sizeof(int8_t);
    }
    
    /* barker lock quality */
    if( rpflags->lockqa == 0x01 ) {
        memcpy(&rmanage->rtap.lock_quality,&pkt[iterator],2);
        iterator += sizeof(uint16_t);
    }
    
    if( rpflags->txatt == 0x01 ) {
        memcpy(&rmanage->rtap.tx_attenuation,&pkt[iterator],2);
        iterator += sizeof(uint16_t);
    }
    
    if( rpflags->dbtxatt == 0x01 ) {
        memcpy(&rmanage->rtap.db_tx_attenuation,&pkt[iterator],2);
        iterator += sizeof(uint16_t);
    }
    
    if( rpflags->dbm_tx_power == 0x01 ) {
        memcpy(&rmanage->rtap.dbm_tx_power,&pkt[iterator],1);
        iterator += sizeof(uint8_t);
    }
    
    if( rpflags->antenna == 0x01 ) {
        memcpy(&rmanage->rtap.antenna,&pkt[iterator],1);
        iterator += sizeof(uint8_t);
    }
    
    if( rpflags->db_signal == 0x01 ) {
        memcpy(&rmanage->rtap.db_signal,&pkt[iterator],1);
        iterator += sizeof(uint8_t);
    }
    
    if( rpflags->db_noise == 0x01 ) {
        memcpy(&rmanage->rtap.db_noise,&pkt[iterator],1);
        iterator += sizeof(uint8_t);
    }
    
    if( rpflags->rx_flags == 0x01 ) {
        memcpy(&rmanage->rtap.rx_flags,&pkt[iterator],2);
        iterator += sizeof(uint16_t);
    }
    
    /* well, where are channel+ and exensions field?  ;) */
    
    return(0);
}


/* get the length of the radiotap header */
uint16_t 
radiotap_get_total_length(RADIOTAP_CONTROL_t *rmanage) 
{
    return(rmanage->rpre.hlen);
}

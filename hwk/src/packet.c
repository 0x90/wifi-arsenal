/*******************************************************************************
 *                ____                     _ __                                *
 *     ___  __ __/ / /__ ___ ______ ______(_) /___ __                          *
 *    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                          *
 *   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                           *
 *                                            /___/ team                       *
 *                                                                             *
 * packet.c                                                                    *
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
#include <stdarg.h>

#include "packet.h"
#include "hwk.h"


PACKET_t
*packet_recv(pcap_t *pcapd) 
{
	PACKET_t *packet        = (PACKET_t*)calloc(1, sizeof(PACKET_t));
    uint8_t  *pkt           = NULL;
	struct pcap_pkthdr        hdr;
    
    memset(&hdr, 0x00, sizeof(struct pcap_pkthdr));
	
	while(pkt == NULL)
	{
		pkt = (uint8_t *)pcap_next(pcapd, &hdr);
		usleep(1);
	}
	
	packet->data = calloc(1, hdr.caplen );
	
	memcpy(packet->data, pkt, hdr.caplen);
	
	packet->len = hdr.caplen;

	return( packet );
}


void
packet_free(PACKET_t *packet) 
{
	free(packet->data);
	free(packet);
	
	return;
}


PACKET_t 
*packet_create(uint8_t *data, uint16_t len)
{
	PACKET_t *pkt = (PACKET_t*)calloc(1, sizeof(PACKET_t));
	pkt->len = len;
	pkt->data = data;
	
	return( pkt );
}


int8_t 
packet_inject(pcap_t *pcapd, PACKET_t *packet) 
{
	return( pcap_inject(pcapd, packet->data, packet->len) ); 
}


PACKET_t
*packet_melt_two(PACKET_t *fst, PACKET_t *snd) 
{
	uint8_t *mem = calloc(1, fst->len + snd->len );
	
	if( fst->data != NULL) {
		memcpy(mem, fst->data, fst->len);
	}
	
	if( snd->data != NULL) {
		memcpy(&mem[fst->len], snd->data, snd->len);
	}
	
	PACKET_t *new = packet_create(mem, fst->len + snd->len);
	
	packet_free(fst);
	packet_free(snd);
	
	return(new);
	
}


PACKET_t
*packet_melt(uint8_t count, ... ) 
{
	va_list ptr; 
	
	int i = 0;
	
	PACKET_t *tmpp = NULL;
	
	PACKET_t *totalp = packet_create(NULL, 0);
	
	va_start(ptr, count);
	
	for(i = 1; i <= count; i++) {
		tmpp = va_arg(ptr , PACKET_t *);
		
		totalp = packet_melt_two(totalp, tmpp);
	}
		
	va_end(ptr);
	
	return(totalp);
}




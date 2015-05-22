/*******************************************************************************
 *                ____                     _ __                                *
 *     ___  __ __/ / /__ ___ ______ ______(_) /___ __                          *
 *    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                          *
 *   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                           *
 *                                            /___/ team                       *
 *                                                                             *
 * packet.h                                                                    *
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

#ifndef HDR_PACKET
#define HDR_PACKET

#include <inttypes.h>

typedef struct PACKET_t {
	uint8_t *data;
	uint16_t len;
} PACKET_t;

PACKET_t *packet_recv(pcap_t *pcapd);
PACKET_t *packet_create(uint8_t *data, uint16_t len);
PACKET_t *packet_melt(uint8_t count, ... );
void      packet_free(PACKET_t *packet); 
int8_t    packet_inject(pcap_t *pcapd, PACKET_t *packet); 
PACKET_t *packet_melt_two(PACKET_t *fst, PACKET_t *snd);


#endif


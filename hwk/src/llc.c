/*******************************************************************************
 *                ____                     _ __                                *
 *     ___  __ __/ / /__ ___ ______ ______(_) /___ __                          *
 *    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                          *
 *   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                           *
 *                                            /___/ team                       *
 *                                                                             *
 * llc.c                                                                       *
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

#include "hwk.h"
#include "llc.h"


PACKET_t *
llc_build_custom(uint8_t dsap, uint8_t ssap, uint8_t ctrl, uint32_t ocode, uint16_t type)
{
	LLC_t  *llc = calloc(1, sizeof(LLC_t ));
	
	llc->dsap = dsap;
	llc->ssap = ssap;
	llc->ctrl = ctrl;
	llc->ocode = ocode;
	llc->type = type;
	
	return( packet_create( (uint8_t *)llc, sizeof( LLC_t )));
}
	

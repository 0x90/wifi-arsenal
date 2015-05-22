/*******************************************************************************
 *                ____                     _ __                                *
 *     ___  __ __/ / /__ ___ ______ ______(_) /___ __                          *
 *    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                          *
 *   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                           *
 *                                            /___/ team                       *
 *                                                                             *
 * llc.h                                                                       *
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

#ifndef HDR_LLC
#define HDR_LLC

#include <inttypes.h>


typedef struct LLC_t {
	unsigned dsap:8;
	unsigned ssap:8;
	unsigned ctrl:8;
	unsigned ocode:24;
	unsigned type:16;
} LLC_t;

PACKET_t *llc_build_custom(uint8_t dsap, uint8_t ssap, uint8_t ctrl, uint32_t ocode, uint16_t type);



#endif


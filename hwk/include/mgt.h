/*******************************************************************************
 *                ____                     _ __                                *
 *     ___  __ __/ / /__ ___ ______ ______(_) /___ __                          *
 *    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                          *
 *   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                           *
 *                                            /___/ team                       *
 *                                                                             *
 * mgt.h                                                                       *
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

#ifndef HDR_MGT
#define HDR_MGT

#include <inttypes.h>

typedef struct MGT_FIXED_t {
	uint8_t tstamp[8];
	uint16_t binterval;
	uint16_t cinf;
} MGT_FIXED_t;


PACKET_t 		*mgt_build_param_fixed(uint16_t interval, uint16_t capinfo);
PACKET_t 		*mgt_build_tagged( uint8_t id, uint8_t len);


#endif


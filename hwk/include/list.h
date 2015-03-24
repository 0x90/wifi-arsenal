/*******************************************************************************
 *                ____                     _ __                                *
 *     ___  __ __/ / /__ ___ ______ ______(_) /___ __                          *
 *    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                          *
 *   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                           *
 *                                            /___/ team                       *
 *                                                                             *
 * list.h                                                                      *
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

#ifndef HDR_LIST
#define HDR_LIST

#include <inttypes.h>
#include "hawk.h"

int8_t 		bssid_is_in_list(uint8_t *bssid, bssid_t *first);
int8_t 		bssid_has_client( uint8_t *clmac, OPTS_t *opts);
void 		bssid_print(OPTS_t *opts);
uint32_t 	bssid_count_elem(OPTS_t *opts, bssid_t *bssidd);
void 		print_mac_addr(uint8_t *addr);
uint8_t		bssid_append(OPTS_t *opts, uint8_t *bssid, uint8_t channel, uint16_t seq);
uint8_t 	bssid_append_client(bssid_t *bssid2, uint8_t *src);
uint8_t 	bssid_append_dst(bssid_t *bssid2, uint8_t *dst);

#endif


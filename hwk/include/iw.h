/*******************************************************************************
 *                ____                     _ __                                *
 *     ___  __ __/ / /__ ___ ______ ______(_) /___ __                          *
 *    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                          *
 *   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                           *
 *                                            /___/ team                       *
 *                                                                             *
 * iw.h                                                                        *
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

#ifndef HDR_IW
#define HDR_IW

#include <inttypes.h>


int8_t 		iw_get_txpower(char *devname);
int8_t 		iw_freq2channel(uint16_t freq);
uint16_t 	iw_channel2freq(uint8_t channel);
int8_t 		iw_get_channel(char *devname);
int8_t 		iw_set_channel(char *dev, int8_t channel);
int8_t 		iw_set_mtu(char *ifa, uint16_t mtu);

#endif


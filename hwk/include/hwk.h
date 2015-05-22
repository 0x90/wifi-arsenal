/*******************************************************************************
 *                ____                     _ __                                *
 *     ___  __ __/ / /__ ___ ______ ______(_) /___ __                          *
 *    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                          *
 *   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                           *
 *                                            /___/ team                       *
 *                                                                             *
 * hwk.h                                                                       *
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

#ifndef HDR_HWK
#define HDR_HWK

#include <inttypes.h>
#include <pcap.h>
#include "rtap.h"

#define VERSION 			"0.4"

#define TRUE			  	(0 == 0)
#define FALSE		   		( !TRUE) 

#define MAC_ZERO_ADDR	 	"\x00\x00\x00\x00\x00\x00"
#define MAC_BROADCAST_ADDR	"\xff\xff\xff\xff\xff\xff"


#define __NOTE(str)			printf("> "str); printf("\n");
#define __ERROR(str)		fprintf(stderr,"error: "str"\n"); /*fprintf(stderr,"errno: %d ",errno); perror(NULL); printf("\n") */
#define __WARNING(str)		fprintf(stderr,"warning: "str"\n")

#define __EXIT_SUCCESS  	exit(EXIT_SUCCESS)
#define __EXIT_FAILURE  	exit(EXIT_FAILURE)

#define __RAND_U32			(uint32_t) rand() % 0xffffffff
#define __RAND_U16 			(uint16_t) rand() % 0xffff
#define __RAND_U8   		(uint8_t)  rand() % 0xff

#define __CLEAR_LINE		printf("\033[1A"); printf("\033[0K")

#define __ENABLED(x) 		(x == 1)
#define __DISABLED(x) 		(x == 0)

#endif


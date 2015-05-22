/*******************************************************************************
 *                ____                     _ __                                *
 *     ___  __ __/ / /__ ___ ______ ______(_) /___ __                          *
 *    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                          *
 *   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                           *
 *                                            /___/ team                       *
 *                                                                             *
 * field.h                                                                     *
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

#ifndef HDR_FIELD
#define HDR_FIELD

#include <inttypes.h>

#define MODE_DEFAULT (0)
#define MODE_CONST   (1)
#define MODE_RAND    (2)
#define MODE_RANGE   (3)
#define MODE_INC     (4)


/* max val for var int types */
#define ARG_U8BIT		(255       )
#define ARG_U16BIT		(65535     )
#define ARG_U24BIT		(16777215  )
#define ARG_U32BIT		(4294967295)

#define RTAP_HREV    		0x01
#define RTAP_HPAD   		0x02
#define RTAP_HLEN    		0x03
#define RTAP_PFLAGS  		0x04
#define RTAP_RATE    		0x05

#define WLAN_FCTRL    		0x06
#define WLAN_DRTN    		0x07
#define WLAN_SRC    		0x08
#define WLAN_DST    		0x09
#define WLAN_BSSID    		0x0a
#define WLAN_SEQ    		0x0b

#define MGT_INTERVAL 		0x0c
#define MGT_CAPINFO 		0x0d

#define MGT_TAGGED_ID 		0x0e
#define MGT_TAGGED_LEN  	0x0f
#define MGT_TAGGED_COUNT  	0x10

#define LLC_DSAP 			0x11
#define LLC_SSAP 			0x12
#define LLC_CTRL 			0x13
#define LLC_OCODE 			0x14
#define LLC_TYPE 			0x15

#define PAYLOAD_LEN 		0x16


#define __FIELD_CHECK_LEN(param, maxlen) if( !( param < maxlen) ) { fprintf(stderr,"\'%s\' not a valid argument\n",fld);  __EXIT_FAILURE; }


typedef struct FIELD_t {
	uint8_t mode;
	uint32_t cval;
	uint32_t sval;
	uint32_t eval;
	uint8_t maddr[6];
} FIELD_t;

FIELD_t *field_init();

void     field_parse_arg(FIELD_t *f, char *fld, uint32_t maxlen);
uint8_t *field_get_mac(FIELD_t *fld);

uint8_t *field_get_default_mac(uint8_t type);
uint32_t field_get_default_val(uint8_t type);

uint8_t  field_get8 (uint8_t type, FIELD_t *fld) ;
uint16_t field_get16(uint8_t type, FIELD_t *fld);
uint32_t field_get32(uint8_t type, FIELD_t *fld);



#endif


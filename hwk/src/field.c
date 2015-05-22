/*******************************************************************************
 *                ____                     _ __                                *
 *     ___  __ __/ / /__ ___ ______ ______(_) /___ __                          *
 *    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                          *
 *   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                           *
 *                                            /___/ team                       *
 *                                                                             *
 * field.c                                                                     *
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
#include <errno.h>

#include "packet.h"

#include "hwk.h"
#include "field.h"


FIELD_t *
field_init()
{
	FIELD_t *f = calloc(1, sizeof( FIELD_t) );
	f->mode = MODE_DEFAULT;
	
	return( f );
}

uint8_t *
field_get_mac(FIELD_t *fld)
{
	return( fld->maddr );
}


void
field_parse_arg(FIELD_t *f, char *fld, uint32_t maxlen)
{
	char *ptr = NULL;
	
	if( strlen(fld) < 3) {
		__ERROR("field argument to small");
		__EXIT_FAILURE;
	}
	
	if( strcmp(fld, "rnd")==0) {
		f->mode = MODE_RAND;
		return;
	}

	if( strcmp(fld, "default") == 0) {
		f->mode = MODE_DEFAULT;
		return;
	}
	
	
	if( fld[0] == 'h' ) {
		f->mode = MODE_CONST;
		
		ptr = strtok(&fld[2], "");
		f->cval = strtol(ptr, (char **) NULL, 16);
		
		__FIELD_CHECK_LEN(f->cval, maxlen);
	}
	else if( fld[0] == 'd' ) {
		f->mode = MODE_CONST;
		
		ptr = strtok(&fld[2], "");
		f->cval = atoi(ptr);
		__FIELD_CHECK_LEN(f->cval, maxlen);
	}
	else if( fld[0] == 'i' ) {
		f->mode = MODE_INC;
		
		ptr = strtok(&fld[2], "");
		f->cval = atoi(ptr);
		__FIELD_CHECK_LEN(f->cval, maxlen);
	}
	else if( fld[0] == 'r' ) {
		if( strlen(fld) < 5) {
			__ERROR("field argument too small");
			__EXIT_FAILURE;
		}
		else {
			f->mode = MODE_RANGE;

			ptr = strtok(&fld[2], "-");
			f->sval = atoi(ptr);
			__FIELD_CHECK_LEN(f->sval, maxlen);
			
			ptr = strtok(NULL, "");
			f->eval = atoi(ptr);
			__FIELD_CHECK_LEN(f->eval, maxlen);
			
			if( f->eval < f->sval) {
				__ERROR("incorrect argument");
			} 
		}
	}
	else {
		fprintf(stderr,"\'%s\' not a valid argument, setting to default value.\n",fld);
	}
	
	return;
}


uint8_t *
field_get_default_mac(uint8_t type)
{		
	uint8_t *ptr = calloc(1, 6);
	
		if(type == WLAN_SRC) {
			memset(ptr,0x00,6);
		}
		if(type == WLAN_DST) {
			memset(ptr,0xff,6); 
		}
		if(type == WLAN_BSSID) {
			memset(ptr,0xff,6);
		}	
		else {
			memset(ptr,0x00,6);
		}
		
		return( ptr );
}


uint32_t 
field_get_default_val(uint8_t type)
{
	uint32_t val = 0;
	
	switch( type ) {
		case RTAP_HREV:
			val = 0x00;
			break;
		case RTAP_HPAD:
			val = 0x00;
			break;
		case RTAP_HLEN:
			val = 0x000d;
			break;
		case RTAP_PFLAGS:
			val = 0x00028004;
			break;
		case RTAP_RATE:
			val = 0x02 ;
			break;
			
		case WLAN_FCTRL:
			val = 128;
			break;
		case WLAN_DRTN:
			val = 0x013a;
			break;
		case WLAN_SEQ:
			val = __RAND_U16 << 4;
			break;
			
		case MGT_CAPINFO:
			val = 0x0431;
			break;
		case MGT_INTERVAL:
			val = 0xfa00;
			break;
			
		case MGT_TAGGED_ID:
			val = __RAND_U8;
			break;
		case MGT_TAGGED_LEN:
			val = __RAND_U8 % 50;
			break;
		case MGT_TAGGED_COUNT:
			val = __RAND_U8 % 5;
			break;
			
		case LLC_DSAP:
			val = 0xaa;
			break;
		case LLC_SSAP:
			val = 0xaa;
			break;
		case LLC_CTRL:
			val = 0x03;
			break;
		case LLC_OCODE:
			val = 0x000000;
			break;
		case LLC_TYPE:
			val = 0x888e;
			break;
		case PAYLOAD_LEN:
			val = __RAND_U8;
			break;
		
		default:
			val = 0x00;
			break;
	}
	
	return( val );
}


uint8_t 
field_get8(uint8_t type, FIELD_t *fld) 
{
	if( fld->mode == MODE_DEFAULT ) {
		return( (uint8_t) field_get_default_val(type) );
	}

	if( fld->mode == MODE_CONST) {
		return( (uint8_t)fld->cval );
	}
	
	if( fld->mode == MODE_RAND) {
		return( __RAND_U8 );
	}
	
	if( fld->mode == MODE_RANGE) {
		return( (uint8_t) (fld->sval) + rand() % (fld->eval - fld->sval) );
	}
	
	if( fld->mode == MODE_INC) {
		fld->cval++;
		return( fld->cval );
	}
	
	return(0);
}


uint16_t 
field_get16(uint8_t type, FIELD_t *fld) 
{
	if( fld->mode == MODE_DEFAULT ) {
		return( (uint16_t) field_get_default_val(type) );
	}

	if( fld->mode == MODE_CONST) {
		return( (uint16_t)fld->cval );
	}
	
	if( fld->mode == MODE_RAND) {
		return( __RAND_U16 );
	}
	
	if( fld->mode == MODE_RANGE) {
		return( (uint16_t) (fld->sval) + rand() % (fld->eval - fld->sval) );
	}
	
	if( fld->mode == MODE_INC) {
		fld->cval++;
		return( fld->cval );
	}

	return(0);
}


uint32_t 
field_get32(uint8_t type, FIELD_t *fld) 
{
	if( fld->mode == MODE_DEFAULT ) {
		return( (uint32_t) field_get_default_val(type) );
	}

	if( fld->mode == MODE_CONST) {
		return( (uint32_t)fld->cval );
	}
	
	if( fld->mode == MODE_RAND) {
		return( __RAND_U32 );
	}
	
	if( fld->mode == MODE_RANGE) {
		return( (uint32_t) (fld->sval) + rand() % (fld->eval - fld->sval) );
	}
	
	if( fld->mode == MODE_INC) {
		fld->cval++;
		return( fld->cval );
	}
	
	return(0);
}

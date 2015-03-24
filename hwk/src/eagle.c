/*******************************************************************************
 *                ____                     _ __                                *
 *     ___  __ __/ / /__ ___ ______ ______(_) /___ __                          *
 *    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                          *
 *   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                           *
 *                                            /___/ team                       *
 *                                                                             *
 * eagle.c                                                                     *
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
#include <arpa/inet.h>
#include <ctype.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>

#include <getopt.h>

#include "rtap.h"
#include "eagle.h"
#include "packet.h"
#include "iw.h"
#include "hwk.h"
#include "wlan.h"
#include "mgt.h"
#include "llc.h"



pthread_mutex_t seq_mutex = PTHREAD_MUTEX_INITIALIZER;


void 
sig_int() 
{
	__NOTE("Ctrl+C pressed, shutting down...");
	__EXIT_SUCCESS;
}


int8_t 
optget(int argc, char** argv, OPTS_t *opts) 
{
    int32_t index       = -1;
    int32_t result      =  0;
    struct  option *opt =  0;
    
    static const struct option long_options[] = {
        { "help", 				no_argument,     	   0, 0 },
        { "version", 			no_argument,     	   0, 0 },
        { "iface", 				required_argument, 	   0, 0 },
        { "channel", 			required_argument,     0, 0 },
        { "delay", 				required_argument,     0, 0 },
        { "mtu", 				required_argument,     0, 0 },

		{ "rtap",   			      no_argument,     0, 0 },
		{ "rtap.hrev", 			required_argument,     0, 0 },
		{ "rtap.hpad", 			required_argument,     0, 0 },
		{ "rtap.hlen", 			required_argument,     0, 0 },	
		{ "rtap.pflags", 		required_argument,     0, 0 },
		{ "rtap.rate", 			required_argument,     0, 0 },        

		{ "wlan.fctrl", 		required_argument,     0, 0 },
		{ "wlan.drtn", 			required_argument,     0, 0 },
		{ "wlan.dst", 			required_argument,     0, 0 },
		{ "wlan.src", 			required_argument,     0, 0 },
		{ "wlan.bssid", 		required_argument,     0, 0 },
		{ "wlan.seq", 			required_argument,     0, 0 },
		
		{ "mgt.fixed", 			no_argument,     	   0, 0 },
		{ "mgt.fixed.bi", 		required_argument,     0, 0 },
		{ "mgt.fixed.capinf", 	required_argument,     0, 0 },
		
		{ "mgt.tagged.count", 	required_argument,     0, 0 },
		{ "mgt.tagged.id", 		required_argument,     0, 0 },
		{ "mgt.tagged.len", 	required_argument,     0, 0 },
			
		{ "llc.dsap", 			required_argument,     0, 0 },
		{ "llc.ssap", 			required_argument,     0, 0 },
		{ "llc.ctrl", 			required_argument,     0, 0 },
		{ "llc.ocode", 			required_argument,     0, 0 },
		{ "llc.type", 			required_argument,     0, 0 },
		
		{ "payload.len",		required_argument,     0, 0 },
	
        {0,0,0,0} 
    };
    
    while (optind < argc) {
        result = getopt_long(argc, argv, "", long_options, &index);
        
        if (result != 0) 
        {
            __ERROR("getopt failed");
            __EXIT_FAILURE;
        }
        else if( result == 0) 
        {
            opt = (struct option *)&(long_options[index]);
                
            if( strcmp(opt->name,"help") == 0 ) {
				help();
				__EXIT_SUCCESS;
            }
            else if( strcmp(opt->name,"version") == 0 ) {
                printf(VERSION"\n");
                __EXIT_SUCCESS;
            }
            else if( strcmp(opt->name,"iface") == 0 ) {
                opts->iface = optarg;
            }
            else if( strcmp(opt->name, "delay") == 0 ) {
				if( opt->has_arg == required_argument ) {
                    opts->delay = (uint64_t)atoi(optarg);
				}
			}
			else if( strcmp(opt->name,"channel") == 0) {
				if( opt->has_arg == required_argument ) {
			        opts->channel = (uint8_t)atoi(optarg);
				}
			}
			
			else if( strcmp(opt->name,"rtap") == 0) {
				__APPEND_RTAP;
			} 
			else if( strcmp(opt->name,"rtap.hrev") == 0) {
				if( opt->has_arg == required_argument ) { field_parse_arg(opts->rtap_hrev, optarg, ARG_U8BIT); }
			} 
			else if( strcmp(opt->name,"rtap.pad") == 0) {
				if( opt->has_arg == required_argument ) { field_parse_arg(opts->rtap_hpad, optarg, ARG_U8BIT); }
            } 
			else if( strcmp(opt->name,"rtap.hlen") == 0) {
                if( opt->has_arg == required_argument ) { field_parse_arg(opts->rtap_hlen, optarg, ARG_U8BIT); }   
            } 
			else if( strcmp(opt->name,"rtap.pflags") == 0) {
                if( opt->has_arg == required_argument ) { field_parse_arg(opts->rtap_pflags, optarg, ARG_U32BIT); }
            } 
			else if( strcmp(opt->name,"rtap.rate") == 0) {
                if( opt->has_arg == required_argument ) { field_parse_arg(opts->rtap_rate, optarg, ARG_U8BIT); }
            } 
            else if( strcmp(opt->name,"wlan.fctrl") == 0) {
				if( opt->has_arg == required_argument ) { 
					__APPEND_WLAN_HEADER;
					 field_parse_arg(opts->wlan_fctrl, optarg, ARG_U16BIT); 
				}
            } 
            else if( strcmp(opt->name,"wlan.drtn") == 0) {
				if( opt->has_arg == required_argument ) { 
					__APPEND_WLAN_HEADER;
					field_parse_arg(opts->wlan_drtn, optarg, ARG_U16BIT); 
				}
            } 
            else if( strcmp(opt->name,"wlan.seq") == 0) {
				if( opt->has_arg == required_argument ) { 
					__APPEND_WLAN_HEADER;
					field_parse_arg(opts->wlan_seq, optarg, ARG_U16BIT); 
				}
            }
            else if( strcmp(opt->name,"wlan.dst") == 0) {
				if( opt->has_arg == required_argument ) {
					__APPEND_WLAN_HEADER;
                    if( sscanf(
                        optarg,"%02x:%02x:%02x:%02x:%02x:%02x",
                        (uint *)&opts->wlan_dst->maddr[0],
                        (uint *)&opts->wlan_dst->maddr[1],
                        (uint *)&opts->wlan_dst->maddr[2],
                        (uint *)&opts->wlan_dst->maddr[3],
                        (uint *)&opts->wlan_dst->maddr[4],
                        (uint *)&opts->wlan_dst->maddr[5]
						) != 6) {
							__ERROR("sscanf failed");
							__EXIT_FAILURE;
					}
				}
            }
            else if( strcmp(opt->name,"wlan.src") == 0) {
				if( opt->has_arg == required_argument ) {
					__APPEND_WLAN_HEADER;
                    if( sscanf(
                        optarg,"%02x:%02x:%02x:%02x:%02x:%02x",
                        (uint *)&opts->wlan_src->maddr[0],
                        (uint *)&opts->wlan_src->maddr[1],
                        (uint *)&opts->wlan_src->maddr[2],
                        (uint *)&opts->wlan_src->maddr[3],
                        (uint *)&opts->wlan_src->maddr[4],
                        (uint *)&opts->wlan_src->maddr[5]
						) != 6) {
							__ERROR("sscanf failed");
							__EXIT_FAILURE;
					}
				}
            }
            else if( strcmp(opt->name,"wlan.bssid") == 0) {
				if( opt->has_arg == required_argument ) {
					__APPEND_WLAN_HEADER;
                    if( sscanf(
                        optarg,"%02x:%02x:%02x:%02x:%02x:%02x",
                        (uint *)&opts->wlan_bssid->maddr[0],
                        (uint *)&opts->wlan_bssid->maddr[1],
                        (uint *)&opts->wlan_bssid->maddr[2],
                        (uint *)&opts->wlan_bssid->maddr[3],
                        (uint *)&opts->wlan_bssid->maddr[4],
                        (uint *)&opts->wlan_bssid->maddr[5]
						) != 6) {
							__ERROR("sscanf failed");
							__EXIT_FAILURE;
					}
				}
            }
            else if( strcmp(opt->name,"mgt.fixed") == 0) {
				__APPEND_MGT_HEADER;
            }
            else if( strcmp(opt->name,"mgt.fixed.bi") == 0) {
				if( opt->has_arg == required_argument ) {
					__APPEND_MGT_HEADER;
					if( opt->has_arg == required_argument ) { 
						field_parse_arg(opts->mgt_fixed_bi, optarg, ARG_U16BIT); 
					}
				}
            }
            else if( strcmp(opt->name,"mgt.fixed.capinf") == 0) {
				if( opt->has_arg == required_argument ) {
					__APPEND_MGT_HEADER;
					if( opt->has_arg == required_argument ) { 
						field_parse_arg(opts->mgt_fixed_capinf, optarg, ARG_U16BIT); 
					}
				}
            }
            else if( strcmp(opt->name,"mgt.tagged.count") == 0) {
				if( opt->has_arg == required_argument ) {
					__APPEND_MGT_TAGGED_HEADER;
					if( opt->has_arg == required_argument ) { 
						field_parse_arg(opts->mgt_tagged_count, optarg, ARG_U8BIT); 
					}
				}
            }
            else if( strcmp(opt->name,"mgt.tagged.id") == 0) {
				if( opt->has_arg == required_argument ) {
					__APPEND_MGT_TAGGED_HEADER;
					if( opt->has_arg == required_argument ) { 
						field_parse_arg(opts->mgt_tagged_id, optarg, ARG_U8BIT); 
					}
				}
            }
            else if( strcmp(opt->name,"mgt.tagged.len") == 0) {
				if( opt->has_arg == required_argument ) {
					__APPEND_MGT_TAGGED_HEADER;
					if( opt->has_arg == required_argument ) { 
						field_parse_arg(opts->mgt_tagged_len, optarg, ARG_U8BIT); 
					}
				}
            }

			else if( strcmp(opt->name,"llc.dsap") == 0) {
				if( opt->has_arg == required_argument ) {
					__APPEND_LLC_HEADER;
					if( opt->has_arg == required_argument ) { 
						field_parse_arg(opts->llc_dsap, optarg, ARG_U8BIT); 
					}
				}
            }
            else if( strcmp(opt->name,"llc.ssap") == 0) {
				if( opt->has_arg == required_argument ) {
					__APPEND_LLC_HEADER;
					if( opt->has_arg == required_argument ) { 
						field_parse_arg(opts->llc_ssap, optarg, ARG_U8BIT); 
					}
				}
            }
            else if( strcmp(opt->name,"llc.ctrl") == 0) {
				if( opt->has_arg == required_argument ) {
					__APPEND_LLC_HEADER;
					if( opt->has_arg == required_argument ) { 
						field_parse_arg(opts->llc_ctrl, optarg, ARG_U8BIT); 
					}
				}
            }
            else if( strcmp(opt->name,"llc.ocode") == 0) {
				if( opt->has_arg == required_argument ) {
					__APPEND_LLC_HEADER;
					if( opt->has_arg == required_argument ) { 
						field_parse_arg(opts->llc_ocode, optarg, ARG_U24BIT); 
					}
				}
            }
            else if( strcmp(opt->name,"llc.type") == 0) {
				if( opt->has_arg == required_argument ) {
					__APPEND_LLC_HEADER;
					if( opt->has_arg == required_argument ) { 
						field_parse_arg(opts->llc_type, optarg, ARG_U16BIT); 
					}
				}
            }
            else if( strcmp(opt->name,"payload.len") == 0) {
				if( opt->has_arg == required_argument ) {
					__APPEND_PAYLOAD;
					if( opt->has_arg == required_argument ) { 
						field_parse_arg(opts->llc_type, optarg, ARG_U16BIT); 
					}
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
	"\n"
	"--help                     print this help\n"
	"--version                  print program version\n"
	"--iface=<interface>        set interface to open (default: wlan0)\n"
	"--channel=<channel>        set channel to listen/send\n"
	"--delay=<μsec>             specify the time to wait between packets\n"
	"--mtu=<bytes>              set the interface MTU\n"
	"[RADIOTAP]\n"
	"--rtap                     append radiotap header to the packet\n"
	"--rtap.hrev=<arg>          header revision\n"
	"--rtap.hpad=<arg>          header padding\n"
	"--rtap.hlen=<arg>          header length\n"
	"--rtap.pflags=<arg>        present flags\n"
	"--rtap.rate=<arg>          data rate\n"
	"[IEEE 802.11 WLAN]\n"
    "--wlan.fctrl=<arg>         frame control\n"
	"--wlan.drtn=<arg>          duration\n"
	"--wlan.dst=<MAC>           destination MAC address\n"
	"--wlan.src=<MAC>           source MAC address\n"
	"--wlan.bssid=<MAC>         BSSID\n"
	"--wlan.seq=<arg>           sequence number\n"
	"[WLAN MGT]\n" 
	"--mgt.fixed                append the fixed parameters of the WLAN MGT header\n"
	"--mgt.fixed.bi=<arg>       beacon interval\n"
	"--mgt.fixed.capinf=<arg>   capability information\n"
	"\n"
	"--mgt.tagged.count=<arg>   number of tags appended\n"	
	"--mgt.tagged.id=<arg>      tag IDs (e.g. 0x00 for SSID parameter)\n"
	"--mgt.tagged.len=<arg>     tag length\n"
	"\n"
	"[LLC]\n"	
	"--llc.dsap=<arg>\n"
	"--llc.ssap=<arg>\n"
	"--llc.ctrl=<arg>\n"
	"--llc.ocode=<arg>          organization code (e.g. 0x000000 = encapsulated ethernet)\n"
	"--llc.type=<arg>           type (e.g. 0x888e 802.1X Authentication)\n"
	"\n"
	"[PSEUDO PAYLOAD]\n"
	"--payload.len=<arg>        append some random data at given length\n"
	"\n"
	"[<arg>]\n"
	"mode:val1[-val2]\n"
	"MODES  MEANING             EXAMPLE\n"
	"d      constant decimal    1337\n"
	"h      constant hex        ffff\n"
	"i      increasing          val++ ;)\n"
	"r      random in range     1-100\n"
	"rnd    random\n"
	"default\n"
	"\n"
	"--rtap.hrev=h:f1\n"
	"--wlan.seq=d:313\n"
	);
	
	
}



OPTS_t *opts_init()
{	
	OPTS_t *o = calloc(1, sizeof(OPTS_t) );
	
	o->delay            = 100000;
	o->iface            = NULL;
	o->channel          = 0;
	o->mtu              = 0;
	
	o->rtap_append      = 0;
	o->wlan_append      = 0;
	o->mgt_append       = 0;
	o->mgt_append_tagged= 0;
	o->llc_append       = 0;
	o->payload_append   = 0;
	
	o->rtap_hrev        = field_init();
	o->rtap_hpad        = field_init();
	o->rtap_hlen        = field_init();
	o->rtap_pflags      = field_init();
	o->rtap_rate        = field_init();
	
	o->wlan_fctrl       = field_init();
	o->wlan_drtn        = field_init();
	o->wlan_dst         = field_init();
	o->wlan_src         = field_init();
	o->wlan_bssid       = field_init();
	o->wlan_seq         = field_init();
	
	o->mgt_fixed_bi     = field_init();
	o->mgt_fixed_capinf = field_init();
	
	o->mgt_tagged_id    = field_init();
	o->mgt_tagged_len   = field_init();
	o->mgt_tagged_count = field_init();
	
	o->llc_dsap         = field_init();
	o->llc_ssap         = field_init();
	o->llc_ctrl         = field_init();
	o->llc_ocode        = field_init();
	o->llc_type         = field_init();
	
	o->payload_len      = field_init();
	
	return( o );
}


void
start_fuzzing(OPTS_t *opts)
{
	uint32_t j        = 0;
	uint injected     = 0;
	time_t   tlast    = 0;
	
	PACKET_t *mc          = NULL;
	PACKET_t *mgt_fix     = NULL;
	PACKET_t *mgt_tagged  = NULL;
	PACKET_t *llc         = NULL;
	PACKET_t *pkt         = NULL; 
	PACKET_t *payload     = NULL; 
	PACKET_t *rtap        = NULL; 

	tlast = time(NULL);
	
	/* check if there is data to inject */
	if( __DISABLED( opts->rtap_append)       &&
		__DISABLED( opts->wlan_append)       &&
		__DISABLED( opts->mgt_append)        &&
		__DISABLED( opts->mgt_append_tagged) &&
		__DISABLED( opts->llc_append)        &&
		__DISABLED( opts->payload_append) ) 
	{
		__ERROR("there is no data to send!");
		__EXIT_FAILURE;
	}

	while(TRUE) {
		pkt = packet_create(NULL, 0);

		/* append radiotap */
		if( __ENABLED(opts->rtap_append) ) {
			rtap = rtap_build_custom_send(
				field_get8(RTAP_HREV, opts->rtap_hrev),
				field_get8(RTAP_HPAD, opts->rtap_hpad),
				field_get16(RTAP_HLEN, opts->rtap_hlen),
				field_get32(RTAP_PFLAGS, opts->rtap_pflags),
				field_get8(RTAP_RATE, opts->rtap_rate)
			);
			
			pkt = packet_melt_two( pkt, rtap );
		}
		
		
		/* append wlan header */
		if( __ENABLED(opts->wlan_append) ) {
			mc = wlan_build_custom( 
				field_get16(WLAN_FCTRL, opts->wlan_fctrl),
				field_get16(WLAN_DRTN, opts->wlan_drtn),
				field_get_mac(opts->wlan_src),
				field_get_mac(opts->wlan_dst),
				field_get_mac(opts->wlan_bssid),
				field_get16(WLAN_SEQ, opts->wlan_seq)
			);
			
			pkt = packet_melt_two( pkt, mc );
		}
		

		/* append wlan mgt header (fixed) */
		if( __ENABLED(opts->mgt_append) ) {
			mgt_fix = mgt_build_param_fixed(
				field_get16(MGT_INTERVAL, opts->mgt_fixed_bi),
				field_get16(MGT_CAPINFO, opts->mgt_fixed_capinf)
			);
			
			pkt = packet_melt_two( pkt, mgt_fix );
		}
		
		
		/* append wlan mgt header (tags) */
		if( __ENABLED(opts->mgt_append_tagged) ) {
			uint8_t tags = field_get8(MGT_TAGGED_COUNT, opts->mgt_tagged_count);
			
			for(j=0; j < tags; j++ ) {
				mgt_tagged = mgt_build_tagged(
					field_get8(MGT_TAGGED_ID, opts->mgt_tagged_id),
					field_get8(MGT_TAGGED_LEN, opts->mgt_tagged_len)
				);
					
				pkt = packet_melt_two( pkt, mgt_tagged );
			}
		}
		
		
		/* append llc header */
		if( __ENABLED(opts->llc_append) ) {
			llc = llc_build_custom(
				field_get8(LLC_DSAP, opts->llc_dsap),
				field_get8(LLC_SSAP, opts->llc_ssap),
				field_get8(LLC_CTRL, opts->llc_ctrl),
				field_get32(LLC_OCODE, opts->llc_ocode),
				field_get16(LLC_TYPE, opts->llc_type)
			);
			
			pkt = packet_melt_two( pkt, llc);
		}
		
		
		/* append random data */
		if( __ENABLED(opts->payload_append) ) {
			payload = payload_append( 
				field_get16(PAYLOAD_LEN, opts->payload_len)
			);
			
			pkt = packet_melt_two( pkt, payload);
		}
	
		
		if( packet_inject(opts->pcapd, pkt) > 0) {
			injected++;
		}
			
		packet_free(pkt);
		
		usleep(opts->delay);

		if( time(NULL) - tlast > 1) {
			__CLEAR_LINE;
			printf("> status: injected: %u\n", injected);
			tlast = time(NULL);
		}
	}
}


PACKET_t *
payload_append(uint16_t len)
{
	uint8_t *payload = calloc(1, len);
			
	uint16_t i = 0;
			
	for( i=0; i <len; i++) {
		memset(&payload[i], __RAND_U8, 1);
	}
			
	return( packet_create(payload, len) );
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
				__WARNING("monitor mode can't be enabled");
			}
		}
	}
	else 
	{
		__WARNING("monitor mode isn't available on interface");
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
	__BANNER;
	signal(SIGINT, sig_int);
	
	OPTS_t *opts = opts_init();
	
	
	if( optget(argc, argv, opts) < 0) {
        __ERROR("getopt failed");
        __EXIT_FAILURE;
    }
    
    if( __NO_IFACE ) {
		__WARNING("no wlan interface given, using wlan0 as default");
		opts->iface = "wlan0";
	}
	
	printf("> opening %s (monitor mode)\n",opts->iface);
    opts->pcapd = open_interface(opts->iface, opts->pcap_errbuf);
    
    
    
    __NOTE("setting channel");
    if( __DISABLED(opts->channel) ) {
		__WARNING("no channel given. Not performing a channel switch.");
	}
	else {
		iw_set_channel(opts->iface, opts->channel);
    }
    
    
    __NOTE("setting MTU");
    if( __DISABLED(opts->mtu) ) {
		printf("using MTU 2274 as default\n");
		opts->mtu = 2274;
    }
    iw_set_mtu(opts->iface, opts->mtu);
    
    
	printf("\n\n");
	start_fuzzing(opts);

	
	return 0;

}



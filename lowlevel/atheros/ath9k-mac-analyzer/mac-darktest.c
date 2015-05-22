#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <zlib.h>
#include <ctype.h>
#include <inttypes.h>
#include <syslog.h>
#include <error.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include<net/if.h>
#include <assert.h>
#include "ieee80211.h"
#include "create-interface.h"
#include "jigdump.h"
#include "td-util.h"
#include "mgmt.h"
#include "pkts.h" 
#include "nl_funcs.h"
#include "address_table.h"
#include "clients_table.h"
#include "anonymization.h"
int UPDATE_TIME ;
time_t current_timestamp;  
#define NUM_MICROS_PER_SECOND 1e6

unsigned char * snapend; 
sigset_t block_set;
struct timeval start_timeval;
u_int32_t pkt_count[2];
static int prev_phy_err_1;
static int prev_phy_err_0;
static int c=0;

int j_hdr(struct jigdump_hdr *jh , int in_idx, struct rcv_pkt * paket){  
  paket->rssi=jh->rssi_;
  paket-> antenna= jh->antenna_;
  paket-> freq = jh->freq_ ;
  //TODO: What to do with all these flags ? i
  //save or discard ?  RX_FLAG_SHORT_GI, RX_FLAG_HT RX_FLAG_40MHZ 
  if(!jh->rate_ || (jh->flags_ & RX_FLAG_HT )){
    paket->rate=  jh->rate_idx_ & 0x7f  ; //  (.5 * ieee80211_htrates[(jh->rate_idx_) & 0xf]);    	
  }else { 			
    paket->rate = (jh->rate_ & 0x7f) +76 ; //  (float)((.5 * ((jh->rate_) & 0x7f)));
  }
  if(jh->flags_ & RX_FLAG_SHORTPRE ){	
    paket->short_preamble_err=1;
  }
  //	printf(" antenna=%u \nrssi=%d  \nchannel=%d  \nrate=%u \n rate_idx=%u \nflags=%d\n", jh->antenna_, jh->rssi_, jh->channel_, jh->rate_, jh->rate_idx_ , jh->flags_);
  if(in_idx ==0){				
		if(jh->phyerr_ - prev_phy_err_0 >=0 )									// no need to do two' complement ... as counter flip is 1 in 2^32 event
	    paket->ath_phy_err= jh->phyerr_ - prev_phy_err_0;		
  	else{
	    paket->ath_phy_err= 0;		
		}
	  prev_phy_err_0 =jh->phyerr_ ;

  }else  {
		if(jh->phyerr_ - prev_phy_err_1 >=0 )									// no need to do two' complement ... 
	    paket->ath_phy_err= jh->phyerr_ - prev_phy_err_1;
		else {
			paket->ath_phy_err=0;
			}						
    prev_phy_err_1 =jh->phyerr_ ;    
  }
  if (jh->flags_ & (RX_FLAG_FAILED_FCS_CRC | RX_FLAG_FAILED_PLCP_CRC )) {
    paket->ath_crc_err=1;
  }
  int flags = jh->channel_;
  if (IS_CHAN_FHSS(flags)){
    paket->channel_rcv=1;
  }
  if (IS_CHAN_A(flags)) {
    if (flags & IEEE80211_CHAN_HALF){
      paket->channel_rcv=3;
    }
    else if (flags & IEEE80211_CHAN_QUARTER){
      paket->channel_rcv=4;
    }
    else{
      paket->channel_rcv=2;//a
    }
  }
  if (IS_CHAN_ANYG(flags)) {
    if (flags & IEEE80211_CHAN_HALF){
      paket->channel_rcv=7;
    }
    else if (flags & IEEE80211_CHAN_QUARTER){
      paket->channel_rcv=8;
    }
    else{
      paket->channel_rcv=6;//g
    }
  } else if (IS_CHAN_B(flags)){
    paket->channel_rcv=5;//b
  }
  if (flags & IEEE80211_CHAN_TURBO){
    paket->channel_rcv=9;
  }
  if (flags & IEEE80211_CHAN_HT20){
    paket->channel_rcv=10;
  }
  else if (flags & IEEE80211_CHAN_HT40D){
    paket->channel_rcv=11;
  }
  else if (flags & IEEE80211_CHAN_HT40U){
    paket->channel_rcv=12;
  } 
  return 0;
  
}

int update_pkt(struct jigdump_hdr* jh, int pkt_len, int in_idx, struct rcv_pkt * paket){ 
  if (sigprocmask(SIG_BLOCK, &block_set, NULL) < 0) {
    perror("sigprocmask");
    exit(1);
  }
  ++pkt_count[in_idx];
  snapend = (uchar *)((uchar*) jh+jh->caplen_) ;
  
  struct ctrl_ba_t *	c_ba =NULL ;
  struct ctrl_ps_poll_t * c_poll = NULL ;
  struct ctrl_end_ack_t *	c_end_ack = NULL;
  struct ctrl_bar_t * c_bar =NULL;
  struct mgmt_header_t *hp =NULL;
  struct ctrl_rts_t * rts = NULL;
  struct ctrl_cts_t *cts= NULL;
  struct ctrl_ack_t *ack =NULL;;
  struct ctrl_end_t * c_cf_end =NULL; 
  uchar  * ptr2,* ptr ,* p, *none;
  j_hdr(jh , in_idx, paket);  
  c++;
  if(c%800==0){
    query_kernel();
  }
  //  struct  ieee80211_hdr* f = (struct ieee80211_hdr*)(jh+1) ;
  //  u_int16_t fc = EXTRACT_LE_16BITS(&f->frame_control);
  p = (uchar*) ((uchar*) jh+sizeof(struct jigdump_hdr));
  u_int16_t fc =  EXTRACT_LE_16BITS(p);
  if (FC_MORE_DATA(fc))
    paket->more_data =1;
  if (FC_MORE_FLAG(fc))
    paket->more_flag =1;
  if (FC_ORDER(fc))
    paket->strictly_ordered=1;
  if (FC_RETRY(fc))
    paket->retry=1;
  if (FC_WEP(fc))
    paket->wep_enc=1;
  if(paket->ath_crc_err==0){ 
    switch (FC_TYPE(fc)) {
    case MGT_FRAME:
      paket->pkt_type=MGT_FRAME;
      hp = (struct mgmt_header_t *) ((uchar*) jh+ sizeof(struct jigdump_hdr)); 
      memcpy(paket->mac_address,hp->sa,6);
      switch(FC_SUBTYPE(fc)){ 
      case ST_BEACON:
	p = (uchar*) (jh+1) ;
	p+=   MGT_FRAME_HDR_LEN  ;
	paket->p.mgmt_pkt.pkt_subtype=ST_BEACON;		
	handle_beacon(p, pkt_len, paket);
	address_mgmt_table_lookup(&mgmt_address_table,paket);
	//	print_mac(paket->mac_address,"beacon" );
	  break;
      case  ST_PROBE_REQUEST : 
	//	print_mac(  (uchar*) (((struct mgmt_header_t *) (jh+ 1))->sa)  ,"request");
      case ST_PROBE_RESPONSE :
	paket->p.mgmt_pkt.pkt_subtype=ST_PROBE_RESPONSE;		
	hp = (struct mgmt_header_t *) (jh+ 1);
	  //memcpy(paket->p.mgmt_pkt.da,hp->sa,6);
	address_mgmt_table_lookup(&mgmt_address_table,paket);
	break ;
      default :
	address_mgmt_table_lookup(&mgmt_address_table,paket);
      }
      break;
    case CONTROL_FRAME:
      paket->pkt_type= CONTROL_FRAME;
      switch(FC_SUBTYPE(fc)){ 
      case  CTRL_RTS :
	rts =  (struct ctrl_rts_t *) ((uchar*) jh+sizeof(struct jigdump_hdr)) ; 
	memcpy(paket->mac_address,rts->ra,6); 
	paket->p.ctrl_pkt.pkt_subtype = CTRL_RTS;
	memcpy(paket->p.ctrl_pkt.ta,rts->ta,6);
	address_control_table_lookup(&control_address_table,paket);
#if 0 
	print_mac(paket->mac_address,"rts ra " );
	print_mac(paket->p.ctrl_pkt.ta, "rts ta ");
#endif
	break;
      case CTRL_CTS :
	cts=  (struct ctrl_cts_t * ) ((uchar*) jh+ sizeof(struct jigdump_hdr)); 
	paket->p.ctrl_pkt.pkt_subtype = CTRL_CTS;
	memcpy(paket->mac_address,cts->ra,6);
	address_control_table_lookup(&control_address_table,paket);
#if 0			
	print_mac(paket->mac_address,"cts ");
#endif
	break;
      case CTRL_ACK :
	ack=  (struct ctrl_ack_t * ) ((uchar*) jh+sizeof(struct jigdump_hdr)) ;
	paket->p.ctrl_pkt.pkt_subtype = CTRL_ACK;
	memcpy(paket->mac_address,ack->ra,6);
	address_control_table_lookup(&control_address_table,paket);
#if 0
	print_mac(paket->mac_address, "ack ");
#endif 
	break;
      case CTRL_CF_END:		
	c_cf_end= (struct ctrl_end_t *) ((uchar*) jh+sizeof(struct jigdump_hdr)) ;
	memcpy( paket->mac_address,c_cf_end->ra,6) ;
	paket->p.ctrl_pkt.pkt_subtype = 55 ; //random
	address_control_table_lookup(&control_address_table,paket);
	break ;
      case CTRL_BAR:
	c_bar  = (const struct ctrl_bar_t *) ((uchar*) jh+sizeof(struct jigdump_hdr));
	memcpy( paket->mac_address,c_bar->ra,6);
	paket->p.ctrl_pkt.pkt_subtype = 55 ; //random
	address_control_table_lookup(&control_address_table,paket);
	break ;
      case  CTRL_BA:
	c_ba = ( const struct ctrl_ba_t * ) ((uchar*) jh+sizeof(struct jigdump_hdr)) ;
	memcpy( paket->mac_address,c_ba->ra,6) ;
	paket->p.ctrl_pkt.pkt_subtype = 55 ; //random
	address_control_table_lookup(&control_address_table,paket);
	break ;
      case CTRL_END_ACK:
	c_end_ack  = (struct ctrl_end_ack_t *)  ((uchar*) jh+sizeof(struct jigdump_hdr)) ;
	memcpy( paket->mac_address,c_end_ack->ra,6);
	paket->p.ctrl_pkt.pkt_subtype = 55 ; //random
	address_control_table_lookup(&control_address_table,paket);
	break ;
      case CTRL_PS_POLL :
	c_poll =  (struct ctrl_ps_poll_t *)((uchar*) jh+sizeof(struct jigdump_hdr)) ;
	memcpy( paket->mac_address,c_poll->bssid,6);
	paket->p.ctrl_pkt.pkt_subtype = 55 ; //random
	address_control_table_lookup(&control_address_table,paket);
	break ;
      }
      break ;   
    case DATA_FRAME : {
      paket->pkt_type=DATA_FRAME;
      p= (uchar*)(jh+1);
      int hdrlen  = (FC_TO_DS(fc) && FC_FROM_DS(fc)) ? 30 : 24;
      if (DATA_FRAME_IS_QOS(FC_SUBTYPE(fc)))
	hdrlen += 2;
      // but there is 8 bytes offset after mac header of 26 bytes, thats for qos data packet
#define ADDR1  (p + 4)
#define ADDR2  (p + 10)
#define ADDR3  (p + 16)
      if (!FC_TO_DS(fc) && !FC_FROM_DS(fc)) {
	memcpy(paket->mac_address,ADDR2,6);
	memcpy(paket->p.data_pkt.dst,ADDR1,6);
#if 0
	print_mac(ADDR2,"1 addr2");
	print_mac(ADDR1,"1 addr1");
#endif
      } else if (!FC_TO_DS(fc) && FC_FROM_DS(fc)) {
	memcpy(paket->mac_address,ADDR3,6);
	memcpy(paket->p.data_pkt.dst,ADDR1,6);
#if 0
	print_mac(ADDR3,"2 src");
	print_mac(ADDR1,"2 dest");
#endif	
	
      } else if (FC_TO_DS(fc) && !FC_FROM_DS(fc)) {
	memcpy(paket->mac_address,ADDR2,6);
	  memcpy(paket->p.data_pkt.dst,ADDR3,6);
#if 0
	  print_mac(ADDR2,"3 src");
	  print_mac(ADDR3,"3 dest");
#endif
	} else if (FC_TO_DS(fc) && FC_FROM_DS(fc)) {
#define ADDR4  (p + 24)
	memcpy(paket->mac_address,ADDR3,6);
	memcpy(paket->p.data_pkt.dst,ADDR4,6); //TODO : again 
#if 0
	print_mac(ADDR4,"4 src");
	print_mac(ADDR3,"4 dest");
#endif
#undef ADDR4
      }
#undef ADDR1
#undef ADDR2
#undef ADDR3
      handle_data(fc,p,hdrlen,paket); //pass caplen for later checks
      address_data_table_lookup(&data_address_table,paket);
      }
      break;
    default :
      perror("Impossible packet \n");
    }
  }else {
    /*CRC Error packets 
     */
    
      switch (FC_TYPE(fc)) {
      case MGT_FRAME:
	hp = (struct mgmt_header_t *) ((uchar*) jh+ sizeof(struct jigdump_hdr)); 
	memcpy(paket->mac_address,hp->sa,6);
	paket->pkt_type=MGT_FRAME;
	switch(FC_SUBTYPE(fc)){ 
	case ST_BEACON:
	  //print_mac(hp->sa,"beacon " );
	p = (uchar*) (jh+1) ;
	p+=   MGT_FRAME_HDR_LEN  ;
	paket->p.mgmt_pkt.pkt_subtype=ST_BEACON;		
	handle_beacon(p, pkt_len, paket);
	address_mgmt_table_lookup(&mgmt_address_table_err,paket);
	break;
	case  ST_PROBE_REQUEST : 
	  //	print_mac(  (uchar*) (((struct mgmt_header_t *) (jh+ 1))->sa)  ,"request");
	case ST_PROBE_RESPONSE :
	paket->p.mgmt_pkt.pkt_subtype=ST_PROBE_RESPONSE;		
	//memcpy(paket->p.mgmt_pkt.da,hp->sa,6);
	address_mgmt_table_lookup(&mgmt_address_table_err,paket);
	break ;
	default : 
	  address_mgmt_table_lookup(&mgmt_address_table_err,paket);
	}
	break;
      case CONTROL_FRAME:
	paket->pkt_type= CONTROL_FRAME;
	switch(FC_SUBTYPE(fc)){ 
	case  CTRL_RTS :
	  rts =  (struct ctrl_rts_t *) ((uchar*) jh+sizeof(struct jigdump_hdr)) ; 
	  memcpy(paket->mac_address,rts->ra,6); 
	  paket->p.ctrl_pkt.pkt_subtype = CTRL_RTS;
	  memcpy(paket->p.ctrl_pkt.ta,rts->ta,6);
	  address_control_table_lookup(&control_address_table_err,paket);
#if 0 
	  print_mac(paket->mac_address,"rts ra " );
	  print_mac(paket->p.ctrl_pkt.ta, "rts ta ");
#endif
	  break;
	case CTRL_CTS :
	  cts=  (struct ctrl_cts_t * ) ((uchar*) jh+ sizeof(struct jigdump_hdr)); 
	  paket->p.ctrl_pkt.pkt_subtype = CTRL_CTS;
	  memcpy(paket->mac_address,cts->ra,6);
	  address_control_table_lookup(&control_address_table_err,paket);
#if 0			
	  print_mac(paket->mac_address,"cts ");
#endif
	  break;
	case CTRL_ACK :
	  ack=  (struct ctrl_ack_t * ) ((uchar*) jh+sizeof(struct jigdump_hdr)) ;
	  paket->p.ctrl_pkt.pkt_subtype = CTRL_ACK;
	  memcpy(paket->mac_address,ack->ra,6);
	  address_control_table_lookup(&control_address_table_err,paket);
#if 0
	  print_mac(paket->mac_address,"ack ");
#endif
	case CTRL_CF_END:		
	  c_cf_end= (struct ctrl_end_t *) ((uchar*) jh+sizeof(struct jigdump_hdr)) ;
	  memcpy( paket->mac_address,c_cf_end->ra,6) ;
	  paket->p.ctrl_pkt.pkt_subtype = 55 ; //random
	  address_control_table_lookup(&control_address_table,paket);
	  break ;
	case CTRL_BAR:
	  c_bar  = (const struct ctrl_bar_t *) ((uchar*) jh+sizeof(struct jigdump_hdr));
	  memcpy( paket->mac_address,c_bar->ra,6);
	  paket->p.ctrl_pkt.pkt_subtype = 55 ; //random
	  address_control_table_lookup(&control_address_table,paket);
	  break ;
	case  CTRL_BA:
	  c_ba = ( const struct ctrl_ba_t * ) ((uchar*) jh+sizeof(struct jigdump_hdr)) ;
	  memcpy( paket->mac_address,c_ba->ra,6) ;
	  paket->p.ctrl_pkt.pkt_subtype = 55 ; //random
	  address_control_table_lookup(&control_address_table,paket);
	  break ;
	case CTRL_END_ACK:
	  c_end_ack  = (struct ctrl_end_ack_t *)  ((uchar*) jh+sizeof(struct jigdump_hdr)) ;
	  memcpy( paket->mac_address,c_end_ack->ra,6);
	  paket->p.ctrl_pkt.pkt_subtype = 55 ; //random
	  address_control_table_lookup(&control_address_table,paket);
	  break ;
	case CTRL_PS_POLL :
	  c_poll =  (struct ctrl_ps_poll_t *)((uchar*) jh+sizeof(struct jigdump_hdr)) ;
	  memcpy( paket->mac_address,c_poll->bssid,6);
	  paket->p.ctrl_pkt.pkt_subtype = 55 ; //random
	  address_control_table_lookup(&control_address_table,paket);
	  break ;
	}
	break ;   
      case DATA_FRAME : {
      paket->pkt_type=DATA_FRAME;
      p= (uchar*)(jh+1);
      int hdrlen  = (FC_TO_DS(fc) && FC_FROM_DS(fc)) ? 30 : 24;
      if (DATA_FRAME_IS_QOS(FC_SUBTYPE(fc)))
	hdrlen += 2;
#define ADDR1  (p + 4)
#define ADDR2  (p + 10)
#define ADDR3  (p + 16)
      if (!FC_TO_DS(fc) && !FC_FROM_DS(fc)) {
	memcpy(paket->mac_address,ADDR2,6);
	memcpy(paket->p.data_pkt.dst,ADDR1,6);
#if 0
	print_mac(ADDR2,"1 addr2");
	print_mac(ADDR1,"1 addr1");
#endif
	
      } else if (!FC_TO_DS(fc) && FC_FROM_DS(fc)) {
	memcpy(paket->mac_address,ADDR3,6);
	memcpy(paket->p.data_pkt.dst,ADDR1,6);
#if 0
	print_mac(ADDR3,"2 src");
	print_mac(ADDR1,"2 dest");
#endif	
	
      } else if (FC_TO_DS(fc) && !FC_FROM_DS(fc)) {
	memcpy(paket->mac_address,ADDR2,6);
	memcpy(paket->p.data_pkt.dst,ADDR3,6);
#if 0
	print_mac(ADDR2,"3 src");
	print_mac(ADDR3,"3 dest");
#endif
	
      } else if (FC_TO_DS(fc) && FC_FROM_DS(fc)) {
#define ADDR4  (p + 24)
	memcpy(paket->mac_address,ADDR3,6);
	memcpy(paket->p.data_pkt.dst,ADDR4,6); //TODO : again 
	
#if 0
	print_mac(ADDR4,"4 src");
	print_mac(ADDR3,"4 dest");
#endif
#undef ADDR4
      }
#undef ADDR1
#undef ADDR2
#undef ADDR3
      
      // but there is 8 bytes offset after mac header of 26 bytes, thats for qos data packet
      handle_data(fc,p,hdrlen,paket); //pass caplen for later checks
      address_data_table_lookup(&data_address_table_err,paket);
      }
	break;
      default :
	paket->pkt_type= 0x4;
	/* CONTROL PKT SIZE : 41 bytes
	 *  BEACON PKT SIZE : can be as large as (11n) 320 bytes. Atleast 100 bytes (a/g) 110 bytes 
	 *  LAB BEACONS : 156-231 bytes ; check for fffffffff 
	 *  PROBES SIZE : 101,149,219,225 , 204, 83 
	 *  DATA PKT SIZE : anything greater than 400 bytes is data packet
	 *  check the fields of FS,DS to get the mac address offset 
	 *  Can be 55 size packets too ! 
	 */
	if(pkt_len>400 ){ //definitely a data packets 
	  p= (uchar*)(jh+1);			
	  int hdrlen  = (FC_TO_DS(fc) && FC_FROM_DS(fc)) ? 30 : 24;
	  if (DATA_FRAME_IS_QOS(FC_SUBTYPE(fc)))
	    hdrlen += 2;
	  //	data_pkt_tests(p,paket,fc);
#define ADDR1  (p + 4)
#define ADDR2  (p + 10)
#define ADDR3  (p + 16)
	  if (!FC_TO_DS(fc) && !FC_FROM_DS(fc)) {
	    memcpy(paket->mac_address,ADDR2,6);
	    memcpy(paket->p.data_pkt.dst,ADDR1,6);
#if 0
	    print_mac(ADDR2,"1 addr2");
	    print_mac(ADDR1,"1 addr1");
#endif
	    
	  } else if (!FC_TO_DS(fc) && FC_FROM_DS(fc)) {
	    memcpy(paket->mac_address,ADDR3,6);
	    memcpy(paket->p.data_pkt.dst,ADDR1,6);
#if 0
	print_mac(ADDR3,"2 src");
	print_mac(ADDR1,"2 dest");
#endif	
	
	  } else if (FC_TO_DS(fc) && !FC_FROM_DS(fc)) {
	memcpy(paket->mac_address,ADDR2,6);
	memcpy(paket->p.data_pkt.dst,ADDR3,6);
#if 0
	print_mac(ADDR2,"3 src");
	print_mac(ADDR3,"3 dest");
#endif
	
	  } else if (FC_TO_DS(fc) && FC_FROM_DS(fc)) {
#define ADDR4  (p + 24)
	    memcpy(paket->mac_address,ADDR3,6);
	    memcpy(paket->p.data_pkt.dst,ADDR4,6); //TODO : again 
	    
#if 0
	    print_mac(ADDR4,"4 src");
	    print_mac(ADDR3,"4 dest");
#endif
#undef ADDR4
	  }
#undef ADDR1
#undef ADDR2
#undef ADDR3
	  handle_data(fc,p,hdrlen,paket); //pass caplen for later checks
	  address_data_table_lookup(&data_address_table_err,paket);
	}else if(pkt_len>111 && pkt_len <340){ 
	  hp = (struct mgmt_header_t *) ((uchar*) jh+ sizeof(struct jigdump_hdr));
	  if(!memcmp(hp->da,"fffffffffff",6)){
	    memcpy(paket->mac_address,hp->sa,6);
	    paket->p.mgmt_pkt.pkt_subtype=ST_BEACON;
	    handle_beacon(p, pkt_len, paket);
	    address_mgmt_table_lookup(&mgmt_address_table_err,paket);	
	  }
	}else if ( pkt_len <50){
	  //TODO: call it a control packet 
	switch(FC_SUBTYPE(fc)){ 
	case  CTRL_RTS :
	  rts =  (struct ctrl_rts_t *) ((uchar*) jh+sizeof(struct jigdump_hdr)) ; 
	  memcpy(paket->mac_address,rts->ra,6); 
	  paket->p.ctrl_pkt.pkt_subtype = CTRL_RTS;
	  memcpy(paket->p.ctrl_pkt.ta,rts->ta,6);
	  address_control_table_lookup(&control_address_table_err,paket);
#if 0 
	  print_mac(paket->mac_address,"rts ra " );
	  print_mac(paket->p.ctrl_pkt.ta, "rts ta ");
#endif
	  break;
	case CTRL_CTS :
	  cts=  (struct ctrl_cts_t * ) ((uchar*) jh+ sizeof(struct jigdump_hdr)); 
	  paket->p.ctrl_pkt.pkt_subtype = CTRL_CTS;
	  memcpy(paket->mac_address,cts->ra,6);
	  address_control_table_lookup(&control_address_table_err,paket);
#if 0			
	  print_mac(paket->mac_address,"cts ");
#endif
	  break;
	case CTRL_ACK :
	  ack=  (struct ctrl_ack_t * ) ((uchar*) jh+sizeof(struct jigdump_hdr)) ;
	  paket->p.ctrl_pkt.pkt_subtype = CTRL_ACK;
	  memcpy(paket->mac_address,ack->ra,6);
	  address_control_table_lookup(&control_address_table_err,paket);
#if 0
	  print_mac(paket->mac_address,"ack ");
#endif
	case CTRL_CF_END:		
	  c_cf_end= (struct ctrl_end_t *) ((uchar*) jh+sizeof(struct jigdump_hdr)) ;
	  memcpy( paket->mac_address,c_cf_end->ra,6) ;
	  paket->p.ctrl_pkt.pkt_subtype = 55 ; //random
	  address_control_table_lookup(&control_address_table,paket);
	  break ;
	case CTRL_BAR:
	  c_bar  = (const struct ctrl_bar_t *) ((uchar*) jh+sizeof(struct jigdump_hdr));
	  memcpy( paket->mac_address,c_bar->ra,6);
	  paket->p.ctrl_pkt.pkt_subtype = 55 ; //random
	  address_control_table_lookup(&control_address_table,paket);
	  break ;
	case  CTRL_BA:
	  c_ba = ( const struct ctrl_ba_t * ) ((uchar*) jh+sizeof(struct jigdump_hdr)) ;
	  memcpy( paket->mac_address,c_ba->ra,6) ;
	  paket->p.ctrl_pkt.pkt_subtype = 55 ; //random
	  address_control_table_lookup(&control_address_table,paket);
	  break ;
	case CTRL_END_ACK:
	  c_end_ack  = (struct ctrl_end_ack_t *)  ((uchar*) jh+sizeof(struct jigdump_hdr)) ;
	  memcpy( paket->mac_address,c_end_ack->ra,6);
	  paket->p.ctrl_pkt.pkt_subtype = 55 ; //random
	  address_control_table_lookup(&control_address_table,paket);
	  break ;
	case CTRL_PS_POLL :
	  c_poll =  (struct ctrl_ps_poll_t *)((uchar*) jh+sizeof(struct jigdump_hdr)) ;
	  memcpy( paket->mac_address,c_poll->bssid,6);
	  paket->p.ctrl_pkt.pkt_subtype = 55 ; //random
	  address_control_table_lookup(&control_address_table,paket);
	  break ;
	 default : 	  
	p = (uchar*) (jh+1) ;
	paket->mac_address[0]= p[2] ; paket->mac_address[1]= p[3];
	address_none_table_lookup(&none_address_table,paket);
	  
	}
	}else {
	//check for packets with size 52 or more for control or none ? 
	//rest goto none
#if 0
	p=(uchar*)(jh+1);
	int idx=0;
	for(idx=0;idx<20;idx++)
	  printf("%02x ",*(p+idx));
#endif
	p = (uchar*) (jh+1) ;
	paket->mac_address[0]= p[2] ; paket->mac_address[1]= p[3];
	address_none_table_lookup(&none_address_table,paket);
		}
   }
  }
    if (sigprocmask(SIG_UNBLOCK, &block_set, NULL) < 0) {
      perror("sigprocmask");
      exit(1);
    }
    return 1;  
}

#ifdef NON_PACKET_MMAP 
int create_header(uchar *jb, const int jb_len, int in_fd, int in_idx ){
  uchar* b=NULL;
  for(b = jb; b < jb+ jb_len; ) {
    struct jigdump_hdr *jh = (struct jigdump_hdr *)b ;
    if(jh-> version_ != JIGDUMP_HDR_VERSION ){
      syslog(LOG_ERR,"invalid jigdump_hdr (v=%u) snaplen=%u, discard\n",   (uint)jh->version_,  jh->snaplen_);
      return 0;
    }
    if (jh->hdrlen_ != sizeof(*jh)) {
      syslog(LOG_ERR," jigdump hdr_len %d mis-match (%d), discard\n", (int)jh->hdrlen_, (int)sizeof(*jh));
      return 0;
    }
    // test_func_inspection (jh);	
    //TODO: check for channel here ! when you get better
    b += sizeof(*jh) + jh->snaplen_ ;
    if (b > jb + jb_len) {
      syslog(LOG_ERR,"data is mis-aligned %d:%d, caplen=%d discard block\n", (int)(b-jb), jb_len, jh->snaplen_);
      return 0;
    }
    struct rcv_pkt paket ;
    memset(&paket,0, sizeof(struct rcv_pkt));
    update_pkt(jh, jb_len, in_idx, &paket);
  }
  return 1;
}

int rcv_timeo=-1;
int read_raw_socket( uchar*jb, int *jb_len, int in_fd){
  const int jb_sz = *jb_len;  
  int timeout,rcv_bytes=0;
  for(timeout=0;;){
    *jb_len=0;
    rcv_bytes = recvfrom(in_fd, jb, jb_sz, MSG_TRUNC, NULL, NULL);
    if (rcv_bytes > jb_sz) {
      fprintf( stderr,"recvfrom: block is truncated (%d bytes), skip\n", rcv_bytes);
      continue;
    }
    if (rcv_bytes > 0) {
      *jb_len= rcv_bytes;
      break;
    }
    if (0 == rcv_bytes) {
      perror("Interface is down: bail out\n");
      return 1;
    }
    if (EAGAIN == errno) {
      perror("EAGAIN \n");
      //TODO :check for writing into int descriptor; pcap(4.1.1)  doesn't do it ... should I ? 
      if ((++timeout)*rcv_timeo >= 600) { //~10 min
			printf("recvfrom timeout %d times, abort\n", timeout);
			exit(1);					
      }  
    }else if (errno !=0){
			printf("errno =%d\n",errno);
      perror("Error");			
			strerror(errno);
			
      return 1;
    }
  }
  return 0;
}

int capture_(int in_fd, int in_idx)
{
  uchar jb[JIGBLOCK_MAX_SIZE];
  int jb_len= sizeof(jb);
  int ok=0 ;
  ok=read_raw_socket(jb, &jb_len,in_fd);
  if(!ok){
    create_header(jb,jb_len, in_fd, in_idx); 
  }else{
    perror("read_raw_socket failed \n");
  }
  if(pkt_count[in_idx]%50 == 0){     
    k_pkt_stats();
  }
 //  printf("in capture\n");
  return 1;
}
#endif 

void set_next_alarm() {
  alarm(UPDATE_TIME);
}

void handle_signals(int sig) {
  if (sig == SIGINT || sig == SIGTERM) {
    write_update();
#ifndef NON_PACKET_MMAP
	  clean_interfaces();
#endif		
    exit(0);
  } else if (sig == SIGALRM) {
    write_update();
    set_next_alarm();
  }
}

void initialize_signal_handler() {
  struct sigaction action;
  action.sa_handler = handle_signals;
  sigemptyset(&action.sa_mask);
  action.sa_flags = SA_RESTART;
  if (sigaction(SIGINT, &action, NULL) < 0
      || sigaction(SIGTERM, &action, NULL) < 0
      || sigaction(SIGALRM, &action, NULL)) {
    perror("sigaction");
    exit(1);
	}
  sigemptyset(&block_set);
  sigaddset(&block_set, SIGINT);
  sigaddset(&block_set, SIGTERM);
  sigaddset(&block_set, SIGALRM);
}

#ifndef NON_PACKET_MMAP

static int rcv_pkt_n =0;
void pkt_capture(int interface ,const pkthdr * p_h, const uchar* jb){

  uchar* b=NULL;
  int jb_len = p_h->caplen;
  for(b = jb; b < jb+ jb_len; ) {
    struct jigdump_hdr *jh = (struct jigdump_hdr *)b ;
    if(jh-> version_ != JIGDUMP_HDR_VERSION ){
      syslog(LOG_ERR,"invalid jigdump_hdr (v=%u) snaplen=%u, discard\n",   (uint)jh->version_,  jh->snaplen_);
      return ;
    }
    if (jh->hdrlen_ != sizeof(*jh)) {
      syslog(LOG_ERR," jigdump hdr_len %d mis-match (%d), discard\n", (int)jh->hdrlen_, (int)sizeof(*jh));
      return ;
    }
    // test_func_inspection (jh);	
    //TODO: check for channel here ! when you get better
    b += sizeof(*jh) + jh->snaplen_ ;
    if (b > jb + jb_len) {
      syslog(LOG_ERR,"data is mis-aligned %d:%d, caplen=%d discard block\n", (int)(b-jb), jb_len, jh->snaplen_);
      
      return ;
    }
    struct rcv_pkt paket ;
    memset(&paket,0, sizeof(struct rcv_pkt));
    update_pkt(jh, jb_len, interface, &paket);
  }
	rcv_pkt_n++;
	if(rcv_pkt_n%100==0)
		 k_pkt_stats();

}
#endif 

int main(int argc, char* argv[])
{

  if(argc < 3){
    printf("usage : binary <mon interface 1> <mon interface 2> \n");
    exit(1);
  }
  char  *device0= argv[1];
  char  *device1= argv[2];
	UPDATE_TIME = 10 ; //seconds  
	if (UPDATE_TIME >60)
			UPDATE_TIME =60 ;

  initialize_bismark_id();
	current_timestamp=time(NULL);
#ifdef ANONYMIZATION
  if( anonymization_init()){
    perror("Error initializing anonymizer\n");
    return 1; 
  }
#endif
	  
  address_data_table_init(&data_address_table);
  address_data_table_init(&data_address_table_err);
  address_mgmt_table_init(&mgmt_address_table);
  address_mgmt_table_init(&mgmt_address_table_err);
  address_control_table_init(&control_address_table);
  address_control_table_init(&control_address_table_err);
  address_none_table_init(&none_address_table);

  address_client_table_init(&client_address_table);
 
  gettimeofday(&start_timeval, NULL);
  start_timestamp_microseconds  = start_timeval.tv_sec * NUM_MICROS_PER_SECOND + start_timeval.tv_usec;
  
  initialize_signal_handler();
  set_next_alarm( UPDATE_TIME );
  
	  
  int retval;
  int in_fd_0= checkup(device0); 
  int in_fd_1= checkup(device1);
  fd_set fd_wait; 
  printf("in main\n");
  if(in_fd_1 == -1 || in_fd_0 == -1){
    fprintf(stderr,"Can't set the interfaces with required parameters. Exit\n");
    exit(-1);
  }
  struct timeval st;
  for(;;)
    {
      FD_ZERO(&fd_wait);      
      FD_SET(in_fd_0, &fd_wait);
      FD_SET(in_fd_1, &fd_wait);
      st.tv_sec  = 0;
      st.tv_usec = 200;
      retval=select(FD_SETSIZE, &fd_wait, NULL, NULL, &st);
      switch(retval)
	{
	case -1:  //omit case
	  continue;
	case  0:
	  break;
	default:
	  if( FD_ISSET(in_fd_0, &fd_wait)) {
//	    printf("I am in 0\n");
#ifdef NON_PACKET_MMAP
	    capture_(in_fd_0,0);
#else 
	    read_mmap( &handle[0], pkt_capture, 0);
#endif 
	  }
	  if( FD_ISSET(in_fd_1, &fd_wait)) {
//	    printf("I am in 1\n");
#ifdef NON_PACKET_MMAP
	    capture_(in_fd_1,1);
#else			
	    read_mmap( &handle[1], pkt_capture , 1);
#endif
	  }
	}
      // comes here when select times out or when a packet is processed
    }
  return 0 ;
}

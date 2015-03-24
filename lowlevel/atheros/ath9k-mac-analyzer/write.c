#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <zlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <netinet/ip.h>
#include <sys/time.h>
#include <inttypes.h>
#include <assert.h>
#include "ieee80211.h"
#include "td-util.h"

#include "pkts.h"
#include "anonymization.h"
#include "address_table.h"
#include "clients_table.h"
#include "create-interface.h"
int sequence_number = 0 ;
char bismark_id[256] ;
int64_t start_timestamp_microseconds;

mgmt_address_table_t mgmt_address_table ; 
data_address_table_t data_address_table ; 
control_address_table_t control_address_table ; 

mgmt_address_table_t mgmt_address_table_err ; 
data_address_table_t data_address_table_err ; 
control_address_table_t control_address_table_err ; 

client_address_table_t client_address_table ; 
none_address_table_t none_address_table ; 

int initialize_bismark_id() {  
  FILE* handle = fopen(BISMARK_ID_FILENAME, "r");
  if (!handle) {
    perror("Cannot open Bismark ID file " BISMARK_ID_FILENAME);
    return -1;
  }
  if(fscanf(handle, "%255s\n", bismark_id) < 1) {
    perror("Cannot read Bismark ID file " BISMARK_ID_FILENAME);
    return -1;
  }
  fclose(handle);
  return 0;
}

int write_update(){


  gzFile client_handle = gzopen (PENDING_UPDATE_CLIENT_FILENAME, "wb");
  gzFile mgmt_handle = gzopen (PENDING_UPDATE_MGMT_FILENAME, "wb");
  gzFile control_handle = gzopen (PENDING_UPDATE_CONTROL_FILENAME, "wb");
  gzFile data_handle = gzopen (PENDING_UPDATE_DATA_FILENAME, "wb");
  gzFile none_handle = gzopen (PENDING_UPDATE_NONE_FILENAME, "wb");
  current_timestamp = time(NULL);  
  if (!mgmt_handle) {
    perror("Could not open update mgmt file for writing\n");
    exit(1);
  }
  if (!gzprintf(mgmt_handle,"%s %" PRId64 " %d %" PRId64 "\n",bismark_id,start_timestamp_microseconds,sequence_number,(int64_t)current_timestamp)) {
    perror("Error writing mgmt update\n");
    exit(1);
  }

  address_mgmt_table_write_update(&mgmt_address_table,&mgmt_address_table_err,mgmt_handle);
  gzclose(mgmt_handle);  

  char update_mgmt_filename[FILENAME_MAX];
  snprintf(update_mgmt_filename,FILENAME_MAX,UPDATE_MGMT_FILENAME,bismark_id,start_timestamp_microseconds,sequence_number);
  if (rename(PENDING_UPDATE_MGMT_FILENAME, update_mgmt_filename)) {
    perror("Could not stage mgmt update\n");
    exit(1);
  }
  /*done with mgmt update */


  if (!control_handle) {
    perror("Could not open update control file for writing\n");
    exit(1);
  }
  if (!gzprintf(control_handle,"%s %" PRId64 " %d %" PRId64 "\n",bismark_id,start_timestamp_microseconds,sequence_number,(int64_t)current_timestamp)) {
    perror("Error writing control update\n");
    exit(1);
  }

  address_control_table_write_update(&control_address_table,&control_address_table_err,control_handle);
  gzclose(control_handle);  

  char update_control_filename[FILENAME_MAX];
  snprintf(update_control_filename,FILENAME_MAX,UPDATE_CONTROL_FILENAME,bismark_id,start_timestamp_microseconds,sequence_number);
  if (rename(PENDING_UPDATE_CONTROL_FILENAME, update_control_filename)) {
    perror("Could not stage control update\n");
    exit(1);
  }

  /*done with control update */

  if (!data_handle) {
    perror("Could not open update data file for writing\n");
    exit(1);
  }
  if (!gzprintf(data_handle,"%s %" PRId64 " %d %" PRId64 "\n",bismark_id,start_timestamp_microseconds,sequence_number,(int64_t)current_timestamp)) {
    perror("Error writing data update\n");
    exit(1);
  }

  address_data_table_write_update(&data_address_table,&data_address_table_err,data_handle);
  gzclose(data_handle);  

  char update_data_filename[FILENAME_MAX];
  snprintf(update_data_filename,FILENAME_MAX,UPDATE_DATA_FILENAME,bismark_id,start_timestamp_microseconds,sequence_number);
  if (rename(PENDING_UPDATE_DATA_FILENAME, update_data_filename)) {
    perror("Could not stage data update\n");
    exit(1);
  }

  /*done with data update */

  if (!client_handle) {
    perror("Could not open update client file for writing\n");
    exit(1);
  }
  if (!gzprintf(client_handle,"%s %" PRId64 " %d %" PRId64 "\n",bismark_id,start_timestamp_microseconds,sequence_number,(int64_t)current_timestamp)) {
    perror("Error writing client update\n");
    exit(1);
  } 
  address_client_table_write_update(client_handle,&client_address_table);
  gzclose(client_handle);

  char update_client_filename[FILENAME_MAX];
  snprintf(update_client_filename,FILENAME_MAX,UPDATE_CLIENT_FILENAME,bismark_id,start_timestamp_microseconds,sequence_number);
  if (rename(PENDING_UPDATE_CLIENT_FILENAME, update_client_filename)) {
    perror("Could not stage client update\n");
    exit(1);
  } 

  /*done with client update */

  if (!none_handle) {
    perror("Could not open update none file for writing\n");
    exit(1);
  }
  if (!gzprintf(none_handle,"%s %" PRId64 " %d %" PRId64 "\n",bismark_id,start_timestamp_microseconds,sequence_number,(int64_t)current_timestamp)) {
    perror("Error writing none update\n");
    exit(1);
  }

  address_none_table_write_update(&none_address_table,none_handle);
  gzclose(none_handle);  

  char update_none_filename[FILENAME_MAX];
  snprintf(update_none_filename,FILENAME_MAX,UPDATE_NONE_FILENAME,bismark_id,start_timestamp_microseconds,sequence_number);
  if (rename(PENDING_UPDATE_NONE_FILENAME, update_none_filename)) {
    perror("Could not stage data update\n");
    exit(1);
  }
  /*done with none packets*/

#ifdef ANONYMIZATION
    gzFile handle_digest = gzopen (PENDING_UPDATE_FILENAME_DIGEST, "wb");
    if (!handle_digest) {
      perror("Could not open update file for writing\n");
      exit(1);
    }
    if (anonymization_write_update(handle_digest)) {
      perror("Could not write anonymization update");
      exit(1);
    }    
    gzclose(handle_digest);
    char update_filename_digest[FILENAME_MAX];
    snprintf(update_filename_digest,FILENAME_MAX,UPDATE_FILENAME_DIGEST,bismark_id,start_timestamp_microseconds,sequence_number);
    if (rename(PENDING_UPDATE_FILENAME_DIGEST, update_filename_digest)) {
      perror("Could not stage update for anonymized digest key\n");
      exit(1);
    }
    
#endif
    
    ++sequence_number;
    address_control_table_init(&control_address_table);
    address_data_table_init(&data_address_table);
    address_mgmt_table_init(&mgmt_address_table);
    address_none_table_init(&none_address_table);
    
    address_control_table_init(&control_address_table_err);
    address_data_table_init(&data_address_table_err);
    address_mgmt_table_init(&mgmt_address_table_err);
    
    address_client_table_init(&client_address_table);
    return 0;
  
}
void address_mgmt_table_init(mgmt_address_table_t* table) {
  memset(table, '\0', sizeof(*table));
}

void address_data_table_init(data_address_table_t* table) {
  memset(table, '\0', sizeof(*table));
}

void address_client_table_init(client_address_table_t* table) {
  memset(table, '\0', sizeof(*table));
}
void address_control_table_init(control_address_table_t* table) {
  memset(table, '\0', sizeof(*table));
}

void address_none_table_init(none_address_table_t* table) {
  memset(table, '\0', sizeof(*table));
}
#define MODULUS(m, d)  ((((m) % (d)) + (d)) % (d))
#define NORM(m)  (MODULUS(m, MAC_TABLE_ENTRIES))

int address_data_table_lookup(data_address_table_t*  table,struct rcv_pkt * paket) {
  u_int8_t m_address[sizeof(paket->mac_address)];
  u_int8_t dest_m_address[sizeof(paket->p.data_pkt.dst)];
  memset(m_address,'\0',sizeof(paket->mac_address));
  memset(dest_m_address,'\0',sizeof(paket->mac_address));
  memcpy(dest_m_address,paket->p.data_pkt.dst,sizeof(paket->p.data_pkt.dst));
  memcpy(m_address,paket->mac_address,sizeof(paket->mac_address));
  if (table->length > 0) {
    /* Search table starting w/ most recent MAC addresses. */
    int idx;
    for (idx = 0; idx < table->length; ++idx) {
      int mac_id = NORM(table->last - idx);
      if (!memcmp(table->entries[mac_id].dest_mac_address, dest_m_address, sizeof(dest_m_address)) && 
	  !memcmp(table->entries[mac_id].mac_address, m_address, sizeof(m_address))){
	table->entries[mac_id].total_packets++;
	table->entries[mac_id].rssi_lin_sum= table->entries[mac_id].rssi_lin_sum + paket->rssi;
	table->entries[mac_id].rssi_square_lin_sum= table->entries[mac_id].rssi_square_lin_sum + paket->rssi* paket->rssi;
	// TODO : add the antilog values of RSSI ? ? no ! i don't think so. 
		table->entries[mac_id].ath_phy_err_count=table->entries[mac_id].ath_phy_err_count+paket->ath_phy_err;
	  table->entries[mac_id].freq =paket->freq ; 

	  ++table->entries[mac_id].rt_index[paket->rate];

	  table->entries[mac_id].channel_rcv=paket->channel_rcv;	  
	  table->entries[mac_id].antenna = paket->antenna;	  
	if(paket->ath_crc_err ){
	  table->entries[mac_id].ath_crc_err_count++;	 
	}else{
	  if( paket->short_preamble_err)
	    table->entries[mac_id].short_preamble_count++ ;
	  if(paket->more_flag)
	    table->entries[mac_id].more_flag_count++;
	  if(paket->more_data)
	    table->entries[mac_id].more_data_count++;
	  if(paket->retry)  
	    table->entries[mac_id].retry_count ++;
	  if(paket->strictly_ordered)
	    table->entries[mac_id].strictly_ordered_count++;
	  if(paket->pwr_mgmt)
	    table->entries[mac_id].pwr_mgmt_count++ ;
	  if(paket->wep_enc)
	    table->entries[mac_id].phy_wep_count++;
	  if( paket->more_flag)
	    table->entries[mac_id].more_flag_count++;
	  
	  if(paket->p.data_pkt.pkt_subtype == 0x8 || paket->p.data_pkt.pkt_subtype ==  IEEE80211_STYPE_DATA){ // data
	    table->entries[mac_id].st_data_count++;
	    if(paket->p.data_pkt.eth_type== ETHERTYPE_ARP)
	      table->entries[mac_id].arp_count++ ;
	    else if(paket->p.data_pkt.eth_type== ETHERTYPE_IP){
	      table->entries[mac_id].ip_count++;
	      
	      if( paket->p.data_pkt.transport_type==IPPROTO_TCP)
		table->entries[mac_id].tcp_count++ ;
	      
	      if(paket->p.data_pkt.transport_type==IPPROTO_UDP)		
		table->entries[mac_id].udp_count++;
	      
	      if(paket->p.data_pkt.transport_type==IPPROTO_ICMP)
		table->entries[mac_id].icmp_count++ ;
	    }
	  } else if(paket->p.data_pkt.pkt_subtype==IEEE80211_STYPE_NULLFUNC) // no  data
	    table->entries[mac_id].st_no_data_count++ ; 
   }
	return mac_id;
      }
    }
  }
  
  
  if (table->length == MAC_TABLE_ENTRIES) {
    //table is full, write it to a file 
    write_update();
    
  } else {
    ++table->length;
  }
  if (table->length > 1) {
    table->last = NORM(table->last + 1);
  }
  //TODO : add info on the data packets src and destination 
  
  memcpy(table->entries[table->last].mac_address, paket->mac_address, sizeof(paket->mac_address));
  memcpy(table->entries[table->last].dest_mac_address, paket->p.data_pkt.dst, sizeof(paket->p.data_pkt.dst));
  table->entries[table->last].total_packets=  1;
	table->entries[table->last].rssi_square_lin_sum = paket->rssi * paket->rssi;
  table->entries[table->last].rssi_lin_sum=  paket->rssi;
  
  table->entries[table->last].ath_phy_err_count=paket->ath_phy_err;   
    table->entries[table->last].freq =paket->freq ; 
    ++table->entries[table->last].rt_index[paket->rate];
    table->entries[table->last].channel_rcv=paket->channel_rcv ;
    table->entries[table->last].antenna = paket->antenna;	  
  if(paket->ath_crc_err){
    table->entries[table->last].ath_crc_err_count++ ;    
	}else{
    if(paket->short_preamble_err)
      table->entries[table->last].short_preamble_count++;
    if(paket->more_flag)
      table->entries[table->last].more_flag_count++;
    
    if(paket->more_data)
      table->entries[table->last].more_data_count++;
    if(paket->retry )
      table->entries[table->last].retry_count++;
    if(paket->strictly_ordered)
      table->entries[table->last].strictly_ordered_count++;
    if(paket->pwr_mgmt)
      table->entries[table->last].pwr_mgmt_count++ ;
    if(paket->wep_enc)
      table->entries[table->last].phy_wep_count++;
    if( paket->more_flag)
      table->entries[table->last].more_flag_count++;
    
    if(paket->p.data_pkt.pkt_subtype == 0x8 || paket->p.data_pkt.pkt_subtype ==  IEEE80211_STYPE_DATA){ // data
      table->entries[table->last].st_data_count=1;
      if(paket->p.data_pkt.eth_type== ETHERTYPE_ARP)
	table->entries[table->last].arp_count=1 ;
      else if(paket->p.data_pkt.eth_type== ETHERTYPE_IP){
	table->entries[table->last].ip_count=1 ;
	if( paket->p.data_pkt.transport_type==IPPROTO_TCP)
	  table->entries[table->last].tcp_count=1 ;	  
	if(paket->p.data_pkt.transport_type==IPPROTO_UDP)		
	  table->entries[table->last].udp_count=1 ;	  
	if(paket->p.data_pkt.transport_type==IPPROTO_ICMP)
	  table->entries[table->last].icmp_count=1 ;
      }
    }else if(paket->p.data_pkt.pkt_subtype==IEEE80211_STYPE_NULLFUNC) // node data
      table->entries[table->last].st_no_data_count=1  ;   
  }
  
  if (table->added_since_last_update < MAC_TABLE_ENTRIES) {
    ++table->added_since_last_update;
  }  
  return table->last;
  
}

int address_control_table_lookup(control_address_table_t*  table,struct rcv_pkt * paket) {
  u_int8_t m_address[sizeof(paket->mac_address)];
  memset(m_address,'\0',sizeof(paket->mac_address));
  memcpy(m_address,paket->mac_address,sizeof(paket->mac_address));
  if (table->length > 0) {
    /* Search table starting w/ most recent MAC addresses. */
    int idx;
    for (idx = 0; idx < table->length; ++idx) {
      int mac_id = NORM(table->last - idx);
      if (!memcmp(table->entries[mac_id].mac_address, m_address, sizeof(m_address))){
	table->entries[mac_id].total_packets++;
	table->entries[mac_id].rssi_lin_sum= table->entries[mac_id].rssi_lin_sum + paket->rssi;
	table->entries[mac_id].rssi_square_lin_sum= table->entries[mac_id].rssi_square_lin_sum + paket->rssi* paket->rssi;
	  table->entries[mac_id].freq =paket->freq ; 
	  table->entries[mac_id].rate=paket->rate;
	  table->entries[mac_id].channel_rcv=paket->channel_rcv;	  
	  table->entries[mac_id].antenna = paket->antenna;	  
	// TODO : add the antilog of it 
	  table->entries[mac_id].ath_phy_err_count=table->entries[mac_id].ath_phy_err_count+paket->ath_phy_err;
	if(paket->ath_crc_err ){
	  table->entries[mac_id].ath_crc_err_count++;	 	
	}
	else{
	  if( paket->short_preamble_err)
	    table->entries[mac_id].short_preamble_count++ ;
	  
	  if(paket->more_flag)
	    table->entries[mac_id].more_flag_count++;
	  
	  if(paket->more_data)
	    table->entries[mac_id].more_data_count++;
	  
	  if(paket->retry)  
	    table->entries[mac_id].retry_count++;
	  if(paket->strictly_ordered)
	    table->entries[mac_id].strictly_ordered_count++;
	  if(paket->pwr_mgmt)
	    table->entries[mac_id].pwr_mgmt_count++ ;
	  if(paket->wep_enc)
	    table->entries[mac_id].phy_wep_count++;
	  if( paket->more_flag)
	    table->entries[mac_id].more_flag_count++;
	 

	  if(paket->p.ctrl_pkt.pkt_subtype==CTRL_RTS){
	    table->entries[mac_id].rts_count++;
//	   assert( table->entries[mac_id].total_packets > table->entries[mac_id].rts_count) ;
	}
	  else if(paket->p.ctrl_pkt.pkt_subtype==CTRL_CTS){
	    table->entries[mac_id].cts_count++;
	}
	  else if(paket->p.ctrl_pkt.pkt_subtype==CTRL_ACK)
	    table->entries[mac_id].ack_count++;
	 }   
	return mac_id;
      }
    }
  }
  if (table->length == MAC_TABLE_ENTRIES) {
    //table is full, write it to a file 
    write_update();
    
  } else {
    ++table->length;
  }
  if (table->length > 1) {
    table->last = NORM(table->last + 1);
  }

  memcpy(table->entries[table->last].mac_address, paket->mac_address, sizeof(paket->mac_address));
  table->entries[table->last].total_packets= 1;
  table->entries[table->last].rssi_lin_sum=  paket->rssi;
	table->entries[table->last].rssi_square_lin_sum = paket->rssi * paket->rssi;
  table->entries[table->last].ath_phy_err_count=paket->ath_phy_err;   
    table->entries[table->last].freq =paket->freq ; 
    table->entries[table->last].rate=paket->rate;
    table->entries[table->last].channel_rcv=paket->channel_rcv ;
    table->entries[table->last].antenna = paket->antenna;	  
  if(paket->ath_crc_err){
    table->entries[table->last].ath_crc_err_count++ ;    
	}else{
    if(paket->short_preamble_err)
      table->entries[table->last].short_preamble_count++;
    if(paket->more_flag)
      table->entries[table->last].more_flag_count++;
    
    if(paket->more_data)
      table->entries[table->last].more_data_count++;
    if(paket->retry )
      table->entries[table->last].retry_count++;
    if(paket->strictly_ordered)
      table->entries[table->last].strictly_ordered_count++;
    if(paket->pwr_mgmt)
      table->entries[table->last].pwr_mgmt_count++ ;
    if(paket->wep_enc)
      table->entries[table->last].phy_wep_count++;
    if( paket->more_flag)
      table->entries[table->last].more_flag_count++;

    if(paket->p.ctrl_pkt.pkt_subtype==CTRL_RTS)
      table->entries[table->last].rts_count=1;
    else if(paket->p.ctrl_pkt.pkt_subtype==CTRL_CTS)
      table->entries[table->last].cts_count=1;
    else if(paket->p.ctrl_pkt.pkt_subtype==CTRL_ACK)
    table->entries[table->last].ack_count=1;
    }
  
  
  if (table->added_since_last_update < MAC_TABLE_ENTRIES) {
    ++table->added_since_last_update;
  }  
  return table->last;
}
int address_mgmt_table_lookup(mgmt_address_table_t*  table,struct rcv_pkt * paket) {
  u_int8_t m_address[sizeof(paket->mac_address)];
  memset(m_address,'\0',sizeof(paket->mac_address));
  //     printf("mac address %s\n", paket->mac_address);
  //     printf("essid %s \n", paket->essid);
  memcpy(m_address,paket->mac_address,sizeof(paket->mac_address));
  if (table->length > 0) {
    /* Search table starting w/ most recent MAC addresses. */
    int idx;
    for (idx = 0; idx < table->length; ++idx) {
      int mac_id = NORM(table->last - idx);
      if (!memcmp(table->entries[mac_id].mac_address, m_address, sizeof(m_address))){
	table->entries[mac_id].total_packets++;
	table->entries[mac_id].rssi_lin_sum= table->entries[mac_id].rssi_lin_sum + paket->rssi;
	table->entries[mac_id].rssi_square_lin_sum= table->entries[mac_id].rssi_square_lin_sum + paket->rssi* paket->rssi;
	  table->entries[mac_id].freq =paket->freq ; 
	  table->entries[mac_id].rate=paket->rate;
	  table->entries[mac_id].channel_rcv=paket->channel_rcv;	  
	  table->entries[mac_id].antenna = paket->antenna;	  
	// TODO : add the antilog of it 
	  table->entries[mac_id].ath_phy_err_count=table->entries[mac_id].ath_phy_err_count+paket->ath_phy_err;
	if(paket->ath_crc_err ){
	  table->entries[mac_id].ath_crc_err_count++;	 
	}else{
	  if( paket->short_preamble_err)
	    table->entries[mac_id].short_preamble_count++ ;
	  
	  if(paket->more_flag)
	    table->entries[mac_id].more_flag_count++;
	  
	  if(paket->more_data)
	    table->entries[mac_id].more_data_count++;
	  
	  if(paket->retry)  
	    table->entries[mac_id].retry_count ++;
	  if(paket->strictly_ordered)
	    table->entries[mac_id].strictly_ordered_count++;
	  if(paket->pwr_mgmt)
	    table->entries[mac_id].pwr_mgmt_count++ ;
	  if(paket->wep_enc)
	    table->entries[mac_id].phy_wep_count++;
	  if( paket->more_flag)
	    table->entries[mac_id].more_flag_count++;
	  
	  	  
	  //mgmt related
	  if(paket->p.mgmt_pkt.pkt_subtype == ST_BEACON ){	    
	      memcpy(table->entries[mac_id].essid, paket->p.mgmt_pkt.essid, sizeof(paket->p.mgmt_pkt.essid));
	      table->entries[mac_id].beacon_count++;
	      
	      if(paket->p.mgmt_pkt.n_enabled)
		table->entries[mac_id].n_enabled_count++ ;
	      //TODO:   privacy; cap_ess_ibss;  done with the first mgmnt pkt
	      
	      if(paket->p.mgmt_pkt.n_enabled)
		table->entries[mac_id].n_enabled_count++; 
	      table->entries[mac_id].rate_max= paket->p.mgmt_pkt.rate_max;
	  }
	  else if(paket->p.mgmt_pkt.pkt_subtype== ST_PROBE_RESPONSE)
	    table->entries[mac_id].probe_count++; 
	 }   
	return mac_id;
      }
    }
  }
  
  if (table->length == MAC_TABLE_ENTRIES) {
    //table is full, write it to a file 
    write_update();
    
  } else {
    ++table->length;
  }
  if (table->length > 1) {
    table->last = NORM(table->last + 1);
  }
  
  memcpy(table->entries[table->last].mac_address, paket->mac_address, sizeof(paket->mac_address));
  table->entries[table->last].total_packets=  table->entries[table->last].total_packets+1;
	table->entries[table->last].rssi_square_lin_sum = paket->rssi * paket->rssi;
  table->entries[table->last].rssi_lin_sum=  paket->rssi;
  
    table->entries[table->last].ath_phy_err_count=paket->ath_phy_err;   
    table->entries[table->last].freq =paket->freq ; 
    table->entries[table->last].rate=paket->rate;
    table->entries[table->last].channel_rcv=paket->channel_rcv ;
    table->entries[table->last].antenna = paket->antenna;	  
  if(paket->ath_crc_err){
    table->entries[table->last].ath_crc_err_count++ ;    
	}else{
    if(paket->short_preamble_err)
      table->entries[table->last].short_preamble_count++;
    if(paket->more_flag)
      table->entries[table->last].more_flag_count++;
    
    if(paket->more_data)
      table->entries[table->last].more_data_count++;
    if(paket->retry )
      table->entries[table->last].retry_count++;
    if(paket->strictly_ordered)
      table->entries[table->last].strictly_ordered_count++;
    if(paket->pwr_mgmt)
      table->entries[table->last].pwr_mgmt_count++ ;
    if(paket->wep_enc)
      table->entries[table->last].phy_wep_count++;
    if( paket->more_flag)
      table->entries[table->last].more_flag_count++;
        
    
    //mgmt related 
    if(paket->p.mgmt_pkt.pkt_subtype == ST_BEACON ){
      memcpy(table->entries[table->last].essid, paket->p.mgmt_pkt.essid, sizeof(paket->p.mgmt_pkt.essid));
      table->entries[table->last].beacon_count++;
      
      if(paket->p.mgmt_pkt.n_enabled)
	table->entries[table->last].n_enabled_count++ ;
      
      table->entries[table->last].cap_privacy=paket->p.mgmt_pkt.cap_privacy;
      table->entries[table->last].cap_ess_ibss=paket->p.mgmt_pkt.cap_ess_ibss;
      table->entries[table->last].mgmt_channel=paket->p.mgmt_pkt.channel;
      table->entries[table->last].rate_max= paket->p.mgmt_pkt.rate_max;
      
    }
    else if(paket->p.mgmt_pkt.pkt_subtype== ST_PROBE_RESPONSE)
      table->entries[table->last].probe_count=1;
    }
 
  
  if (table->added_since_last_update < MAC_TABLE_ENTRIES) {
    ++table->added_since_last_update;
  }  
  return table->last;
}


int address_data_table_write_update(data_address_table_t* table,data_address_table_t* table_err,gzFile handle) {
  int idx;
//  printf("DP "); 
  for (idx = table->added_since_last_update; idx > 0; --idx) {
    int mac_id = NORM(table->last - idx + 1);

	   float rssi_avg = table->entries[mac_id].rssi_lin_sum/((float)table->entries[mac_id].total_packets);
		 float rssi_std_dev = (table->entries[mac_id].rssi_square_lin_sum/(float)table->entries[mac_id].total_packets)  - (rssi_avg*rssi_avg);

#ifndef ANONYMIZATION
    u_int8_t *a=table->entries[mac_id].mac_address;
    u_int8_t *ab=table->entries[mac_id].dest_mac_address;
#endif
#ifdef DEBUG_CORRECT
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",a[0],a[1],a[2],a[3],a[4],a[5]);
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",ab[0],ab[1],ab[2],ab[3],ab[4],ab[5]);
    printf("pkt|anten|freq|ath_phy|channel|short_preamble|phy_wep|retry|more_flag|more_data|strictly_ordered|pwr_mgmt\n");
    printf("%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u\n",
	   table->entries[mac_id].total_packets,
	   table->entries[mac_id].antenna,
	   table->entries[mac_id].freq,
	   table->entries[mac_id].ath_phy_err_count,
	   table->entries[mac_id].channel_rcv,
	   table->entries[mac_id].short_preamble_count,
	   table->entries[mac_id].phy_wep_count,
	   table->entries[mac_id].retry_count,
	   table->entries[mac_id].more_flag_count,
	   table->entries[mac_id].more_data_count,
	   table->entries[mac_id].strictly_ordered_count,
	   table->entries[mac_id].pwr_mgmt_count,
	   );
    printf("st_data|arp|ip|tcp|udp|icmp|st_no_data_|rate|rssi\n");
    printf("%u|%u|%u|%u|%u|%u|%u|%2.1f|%2.1f\n",
	   table->entries[table->last].st_data_count,
	   table->entries[mac_id].arp_count,
	   table->entries[mac_id].ip_count,
	   table->entries[mac_id].tcp_count,
	   table->entries[mac_id].udp_count,
	   table->entries[mac_id].icmp_count,
	   table->entries[mac_id].st_no_data_count,
	   rssi_avg,
		 rssi_std_dev 
	   );
#endif 

#ifdef ANONYMIZATION    
    uint8_t digest_mac[ETH_ALEN];
    uint8_t digest_mac_dest[ETH_ALEN];
    if(anonymize_mac(table->entries[mac_id].mac_address, digest_mac)) {
      fprintf(stderr, "Error anonymizing MAC mapping\n");
      return -1;
    }
    if(anonymize_mac(table->entries[mac_id].dest_mac_address, digest_mac_dest)) {
      fprintf(stderr, "Error anonymizing MAC mapping\n");
      return -1;
    }
    u_int8_t *a=digest_mac; 
    u_int8_t *ab=digest_mac_dest;
    if(!gzprintf(handle,"%02x%02x%02x%02x%02x%02x|",a[0],a[1],a[2],a[3],a[4],a[5])){
      perror("error writing the client mac address in zip file ");
      exit(1);
    }
    if(!gzprintf(handle,"%02x%02x%02x%02x%02x%02x|",ab[0],ab[1],ab[2],ab[3],ab[4],ab[5])){
      perror("error writing dest mac in the zip file ");
      exit(1);
    }
#else
    if(!gzprintf(handle,"%02x%02x%02x%02x%02x%02x|",a[0],a[1],a[2],a[3],a[4],a[5])){
      perror("error writing the client mac address in zip file ");
      exit(1);
    }
    if(!gzprintf(handle,"%02x%02x%02x%02x%02x%02x|",ab[0],ab[1],ab[2],ab[3],ab[4],ab[5])){
      perror("error writing dest mac in the zip file ");
      exit(1);
    }
#endif
    if(!gzprintf(handle,"%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u",
		 table->entries[mac_id].total_packets,
		 table->entries[mac_id].antenna,
		 table->entries[mac_id].freq,
		 table->entries[mac_id].ath_crc_err_count,
		 table->entries[mac_id].ath_phy_err_count,
		 table->entries[mac_id].channel_rcv,
		 table->entries[mac_id].short_preamble_count,
		 table->entries[mac_id].phy_wep_count,
		 table->entries[mac_id].retry_count,
		 table->entries[mac_id].more_flag_count,
		 table->entries[mac_id].more_data_count,
		 table->entries[mac_id].strictly_ordered_count,
		 table->entries[mac_id].pwr_mgmt_count
		 )){
      perror("error writing the phy data  zip file ");
      exit(1);
    }
    if(!gzprintf(handle,"|%u|%u|%u|%u|%u|%u|%u|%2.1f|%2.1f",
		 table->entries[table->last].st_data_count,
		 table->entries[mac_id].arp_count,
		 table->entries[mac_id].ip_count,
		 table->entries[mac_id].tcp_count,
		 table->entries[mac_id].udp_count,
		 table->entries[mac_id].icmp_count,
		 table->entries[mac_id].st_no_data_count,
		 rssi_avg,
		 rssi_std_dev
		 )){
      perror("error writing the mac data zip file ");
      exit(1);
    }
		int rate_idx =0;
		 // printf("total no : ",table->entries[mac_id].total_packets);
		if(!gzprintf(handle,"|{")){			
      perror("error writing the left bracket data zip file ");
      exit(1);						
		}
		for(rate_idx=0;rate_idx <256; rate_idx++){
			if(table->entries[mac_id].rt_index[rate_idx] !=0) {
				if(!gzprintf(handle,"(%d,%d),",rate_idx, table->entries[mac_id].rt_index[rate_idx])){
								
		      perror("error writing the rates into zip file ");
		      exit(1);						
				}
			}
		}
		if(!gzprintf(handle,"}\n")){
      perror("error writing the right bracket into zip file ");
      exit(1);						
		}
  }
  /*written correct data, now write erroneous data */

if(!gzprintf(handle,"-|-|-\n")){
      perror("error writing src mac in the zip file ");
      exit(1);
    }

  for (idx = table_err->added_since_last_update; idx > 0; --idx) {
    int mac_id = NORM(table_err->last - idx + 1);

	   float rssi_avg = table_err->entries[mac_id].rssi_lin_sum/((float)table_err->entries[mac_id].total_packets);
		 float rssi_std_dev = (table_err->entries[mac_id].rssi_square_lin_sum/(float)table_err->entries[mac_id].total_packets)  - (rssi_avg*rssi_avg);

#ifndef ANONYMIZATION
    u_int8_t *a=table_err->entries[mac_id].mac_address;
    u_int8_t *ab=table_err->entries[mac_id].dest_mac_address;
#endif
#ifdef DEBUG_INCORRECT
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",a[0],a[1],a[2],a[3],a[4],a[5]);
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",ab[0],ab[1],ab[2],ab[3],ab[4],ab[5]);
    printf("pkt|anten|freq|ath_crc|ath_phy|channel|short_preamble|phy_wep|retry|more_flag|more_data|strictly_ordered|pwr_mgmt\n");
    printf("%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u\n",
	   table_err->entries[mac_id].total_packets,
	   table_err->entries[mac_id].antenna,
	   table_err->entries[mac_id].freq,
	   table_err->entries[mac_id].ath_crc_err_count,
	   table_err->entries[mac_id].ath_phy_err_count,
	   table_err->entries[mac_id].channel_rcv,
	   table_err->entries[mac_id].short_preamble_count,
	   table_err->entries[mac_id].phy_wep_count,
	   table_err->entries[mac_id].retry_count,
	   table_err->entries[mac_id].more_flag_count,
	   table_err->entries[mac_id].more_data_count,
	   table_err->entries[mac_id].strictly_ordered_count,
	   table_err->entries[mac_id].pwr_mgmt_count
	   );
    printf("st_data|arp|ip|tcp|udp|icmp|st_no_data_|rate|rssi\n");
    printf("%u|%u|%u|%u|%u|%u|%u|%2.1f|%2.1f\n",
	   table_err->entries[table->last].st_data_count,
	   table_err->entries[mac_id].arp_count,
	   table_err->entries[mac_id].ip_count,
	   table_err->entries[mac_id].tcp_count,
	   table_err->entries[mac_id].udp_count,
	   table_err->entries[mac_id].icmp_count,
	   table_err->entries[mac_id].st_no_data_count,
	   rssi_avg,
		 rssi_std_dev
	   );
#endif 



#ifdef ANONYMIZATION    
    uint8_t digest_mac[ETH_ALEN];
    uint8_t digest_mac_dest[ETH_ALEN];
    if(anonymize_mac(table_err->entries[mac_id].mac_address, digest_mac)) {
      fprintf(stderr, "Error anonymizing MAC mapping\n");
      return -1;
    }
    if(anonymize_mac(table_err->entries[mac_id].dest_mac_address, digest_mac_dest)) {
      fprintf(stderr, "Error anonymizing MAC mapping\n");
      return -1;
    }
    u_int8_t *a=digest_mac; 
    u_int8_t *ab=digest_mac_dest;
    if(!gzprintf(handle,"%02x%02x%02x%02x%02x%02x|",a[0],a[1],a[2],a[3],a[4],a[5])){
      perror("error writing the client mac address in zip file ");
      exit(1);
    }
    if(!gzprintf(handle,"%02x%02x%02x%02x%02x%02x|",ab[0],ab[1],ab[2],ab[3],ab[4],ab[5])){
      perror("error writing dest mac in the zip file ");
      exit(1);
    }
#else
    if(!gzprintf(handle,"%02x%02x%02x%02x%02x%02x|",a[0],a[1],a[2],a[3],a[4],a[5])){
      perror("error writing the client mac address in zip file ");
      exit(1);
    }
    if(!gzprintf(handle,"%02x%02x%02x%02x%02x%02x|",ab[0],ab[1],ab[2],ab[3],ab[4],ab[5])){
      perror("error writing dest mac in the zip file ");
      exit(1);
    }
#endif

    if(!gzprintf(handle,"%u|%u|%u|%u|%u|%u|%u|%2.1f|%2.1f\n",
		 table_err->entries[mac_id].total_packets,
		 table_err->entries[mac_id].antenna,
		 table_err->entries[mac_id].freq,
		 table_err->entries[mac_id].ath_crc_err_count,
		 table_err->entries[mac_id].ath_phy_err_count,
		 table_err->entries[mac_id].channel_rcv,
		 table_err->entries[mac_id].short_preamble_count,
		 table_err->entries[mac_id].rate,
		 rssi_avg,
		 rssi_std_dev
		 )){
      perror("error writing the phy data  zip file ");
      exit(1);
    }
  }
  return 1; 
}



int address_control_table_write_update(control_address_table_t* table,control_address_table_t* table_err,gzFile handle) {

//  printf("CP\n"); 
  int idx;
  for (idx = table->added_since_last_update; idx > 0; --idx) {
    int mac_id = NORM(table->last - idx + 1);
	   float rssi_avg = table->entries[mac_id].rssi_lin_sum/((float)table->entries[mac_id].total_packets);
		 float rssi_std_dev = (table->entries[mac_id].rssi_square_lin_sum/(float)table->entries[mac_id].total_packets)  - (rssi_avg*rssi_avg);
#ifndef ANONYMIZATION
    u_int8_t *a=table->entries[mac_id].mac_address;
#endif 
#ifdef DEBUG_CORRECT    
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",a[0],a[1],a[2],a[3],a[4],a[5]);
    printf("pkt|anten|freq|ath_crc|ath_phy|channel|short_preamble|phy_wep|retry|more_flag|more_data|strictly_ordered|pwr_mgmt|rate\n");
    printf("%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u\n",
	   table->entries[mac_id].total_packets,
	   table->entries[mac_id].antenna,
	   table->entries[mac_id].freq,
	   table->entries[mac_id].ath_crc_err_count,
	   table->entries[mac_id].ath_phy_err_count,
	   table->entries[mac_id].channel_rcv,
	   table->entries[mac_id].short_preamble_count,
	   table->entries[mac_id].phy_wep_count,
	   table->entries[mac_id].retry_count,
	   table->entries[mac_id].more_flag_count,
	   table->entries[mac_id].more_data_count,
	   table->entries[mac_id].strictly_ordered_count,
	   table->entries[mac_id].pwr_mgmt_count
	   );
    printf("cts|rts|ack|rssi\n");
    printf("%u|%u|%u|%u|%2.1f|%2.1f\n",
	   table->entries[mac_id].cts_count,
	   table->entries[mac_id].rts_count,
	   table->entries[mac_id].ack_count,
	   table->entries[mac_id].rate,
	   rssi_avg,
		 rssi_std_dev
	   );
#endif

#ifdef ANONYMIZATION    
    uint8_t digest_mac[ETH_ALEN];
    if(anonymize_mac(table->entries[mac_id].mac_address, digest_mac)) {
      fprintf(stderr, "Error anonymizing MAC mapping\n");
      return -1;
    }
    u_int8_t *a=digest_mac;
    if(!gzprintf(handle,"%02x%02x%02x%02x%02x%02x|",a[0],a[1],a[2],a[3],a[4],a[5])){
      perror("error writing the client mac address in zip file ");
      exit(1);
    }
#else
    if(!gzprintf(handle,"%02x%02x%02x%02x%02x%02x|",a[0],a[1],a[2],a[3],a[4],a[5])){
      perror("error writing the client mac address in zip file ");
      exit(1);
    }
#endif
    if(!gzprintf(handle,"%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u",
		 table->entries[mac_id].total_packets,
		 table->entries[mac_id].antenna,
		 table->entries[mac_id].freq,
		 table->entries[mac_id].ath_crc_err_count,
		 table->entries[mac_id].ath_phy_err_count,
		 table->entries[mac_id].channel_rcv,
		 table->entries[mac_id].short_preamble_count,
		 table->entries[mac_id].phy_wep_count,
		 table->entries[mac_id].retry_count,
		 table->entries[mac_id].more_flag_count,
		 table->entries[mac_id].more_data_count,
		 table->entries[mac_id].strictly_ordered_count,
		 table->entries[mac_id].pwr_mgmt_count
		 )){
      perror("error writing the zip file ");
      exit(1);
    }
    if(!gzprintf(handle,"|%u|%u|%u|%u|%2.1f|%2.1f\n",
		 table->entries[mac_id].cts_count,
		 table->entries[mac_id].rts_count,
		 table->entries[mac_id].ack_count,
		 table->entries[mac_id].rate,
		 rssi_avg,
		 rssi_std_dev
		 )){
      perror("error writing the zip file");
      exit(1);
    }
  }  
  /* finished with non error logs, now error logs */

if(!gzprintf(handle,"-|-|-\n")){
      perror("error writing src mac in the zip file ");
      exit(1);
    }
  
  for (idx = table_err->added_since_last_update; idx > 0; --idx) {
    int mac_id = NORM(table_err->last - idx + 1);
	   float rssi_avg = table_err->entries[mac_id].rssi_lin_sum/((float)table_err->entries[mac_id].total_packets);
		 float rssi_std_dev = (table_err->entries[mac_id].rssi_square_lin_sum/(float)table_err->entries[mac_id].total_packets)  - (rssi_avg*rssi_avg);
#ifndef ANONYMIZATION
    u_int8_t *a=table_err->entries[mac_id].mac_address;
#endif 
#ifdef DEBUG_INCORRECT    
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",a[0],a[1],a[2],a[3],a[4],a[5]);
    printf("pkt|anten|freq|ath_crc|ath_phy|channel|short_preamble|phy_wep|retry|more_flag|more_data|strictly_ordered|pwr_mgmt|\n");
    printf("%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u\n",
	   table_err->entries[mac_id].total_packets,
	   table_err->entries[mac_id].antenna,
	   table_err->entries[mac_id].freq,
	   table_err->entries[mac_id].ath_crc_err_count,
	   table_err->entries[mac_id].ath_phy_err_count,
	   table_err->entries[mac_id].channel_rcv,
	   table_err->entries[mac_id].short_preamble_count,
	   table_err->entries[mac_id].phy_wep_count,
	   table_err->entries[mac_id].retry_count,
	   table_err->entries[mac_id].more_flag_count,
	   table_err->entries[mac_id].more_data_count,
	   table_err->entries[mac_id].strictly_ordered_count,
	   table_err->entries[mac_id].pwr_mgmt_count
	   );
    printf("cts|rts|ack|rate|rssi\n");
    printf("%u|%u|%u|%u|%2.1f|%2.1f\n",
	   table_err->entries[mac_id].cts_count,
	   table_err->entries[mac_id].rts_count,
	   table_err->entries[mac_id].ack_count,
	   table_err->entries[mac_id].rate,
	   rssi_avg,
		 rssi_std_dev
	   );
#endif

#ifdef ANONYMIZATION    
    uint8_t digest_mac[ETH_ALEN];
    if(anonymize_mac(table_err->entries[mac_id].mac_address, digest_mac)) {
      fprintf(stderr, "Error anonymizing MAC mapping\n");
      return -1;
    }
    u_int8_t *a=digest_mac;
    if(!gzprintf(handle,"%02x%02x%02x%02x%02x%02x|",a[0],a[1],a[2],a[3],a[4],a[5])){
      perror("error writing the client mac address in zip file ");
      exit(1);
    }
#else
    if(!gzprintf(handle,"%02x%02x%02x%02x%02x%02x|",a[0],a[1],a[2],a[3],a[4],a[5])){
      perror("error writing the client mac address in zip file ");
      exit(1);
    }
#endif

    if(!gzprintf(handle,"%u|%u|%u|%u|%u|%u|%u|%u|%2.1f\n",
		 table_err->entries[mac_id].total_packets,
		 table_err->entries[mac_id].antenna,
		 table_err->entries[mac_id].freq,
		 table_err->entries[mac_id].ath_crc_err_count,
		 table_err->entries[mac_id].ath_phy_err_count,
		 table_err->entries[mac_id].channel_rcv,
		 table_err->entries[mac_id].short_preamble_count,
		 table_err->entries[mac_id].rate,
		 rssi_avg,
		 rssi_std_dev
		 )){
      perror("error writing the zip file ");
      exit(1);
    }    
  }  

    return 1; 
  
}
  

int address_mgmt_table_write_update(mgmt_address_table_t* table,mgmt_address_table_t* table_err,gzFile handle) {
  int idx;
//   printf("MP "); 
  for (idx = table->added_since_last_update; idx > 0; --idx) {

    int mac_id = NORM(table->last - idx + 1);
	   float rssi_avg = table->entries[mac_id].rssi_lin_sum/((float)table->entries[mac_id].total_packets);
		 float rssi_std_dev = (table->entries[mac_id].rssi_square_lin_sum/(float)table->entries[mac_id].total_packets)  - (rssi_avg*rssi_avg);
#ifndef ANONYMIZATION
    u_int8_t *a=table->entries[mac_id].mac_address;
#endif    
#ifdef DEBUG_CORRECT
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",a[0],a[1],a[2],a[3],a[4],a[5]);
    printf("pkt|anten|freq|ath_crc|ath_phy|channel|short_preamble|phy_wep|retry|more_flag|more_data|strictly_ordered|pwr_mgmt\n");
    printf("%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u\n",
	   table->entries[mac_id].total_packets,
	   table->entries[mac_id].antenna,
	   table->entries[mac_id].freq,
	   table->entries[mac_id].ath_crc_err_count,
	   table->entries[mac_id].ath_phy_err_count,
	   table->entries[mac_id].channel_rcv,
	   table->entries[mac_id].short_preamble_count,
	   table->entries[mac_id].phy_wep_count,
	   table->entries[mac_id].retry_count,
	   table->entries[mac_id].more_flag_count,
	   table->entries[mac_id].more_data_count,
	   table->entries[mac_id].strictly_ordered_count,
	   table->entries[mac_id].pwr_mgmt_count
	   );  
    printf("essid|beacon_|probe|privacy|ibss|rate|rate_max|rssi_avg|std_dev\n");
    printf("%s|%u|%u|%u|%u|%u|%2.1f|%2.1f|%2.1f\n",
	   table->entries[mac_id].essid,
	   table->entries[mac_id].beacon_count,
	   table->entries[mac_id].probe_count,
	   table->entries[mac_id].cap_privacy,
	   table->entries[mac_id].cap_ess_ibss,
	   table->entries[mac_id].rate,
	   table->entries[mac_id].rate_max,
	   rssi_avg,
		 rssi_std_dev
	   );
#endif

#ifdef ANONYMIZATION    
    uint8_t digest_mac[ETH_ALEN];
    if(anonymize_mac(table->entries[mac_id].mac_address, digest_mac)) {
      fprintf(stderr, "Error anonymizing MAC mapping\n");
      return -1;
    }
    u_int8_t *a=digest_mac;
    if(!gzprintf(handle,"%02x%02x%02x%02x%02x%02x|",a[0],a[1],a[2],a[3],a[4],a[5])){
      perror("error writing the client mac address in zip file ");
      exit(1);
    }
#else
    if(!gzprintf(handle,"%02x%02x%02x%02x%02x%02x|",a[0],a[1],a[2],a[3],a[4],a[5])){
      perror("error writing the client mac address in zip file ");
      exit(1);
    }
#endif

    if(!gzprintf(handle,"%s|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u",
		 table->entries[mac_id].essid,
		 table->entries[mac_id].total_packets,
		 table->entries[mac_id].antenna,
		 table->entries[mac_id].freq,
		 table->entries[mac_id].ath_crc_err_count,
		 table->entries[mac_id].ath_phy_err_count,
		 table->entries[mac_id].channel_rcv,
		 table->entries[mac_id].short_preamble_count,
		 table->entries[mac_id].phy_wep_count,
		 table->entries[mac_id].retry_count,
		 table->entries[mac_id].more_flag_count,
		 table->entries[mac_id].more_data_count,
		 table->entries[mac_id].strictly_ordered_count,
		 table->entries[mac_id].pwr_mgmt_count
		 )){
      perror("error writing the zip file ");
      exit(1);
    }
    if(!gzprintf(handle,"|%u|%u|%u|%u|%u|%2.1f|%2.1f|%2.1f\n",
		 table->entries[mac_id].beacon_count,
		 table->entries[mac_id].probe_count,
		 table->entries[mac_id].cap_privacy,
		 table->entries[mac_id].cap_ess_ibss,
		 table->entries[mac_id].rate,
		 table->entries[mac_id].rate_max,
		 rssi_avg,
		 rssi_std_dev
		 )){
      perror("error writing the zip file");
      exit(1);
    }
  }

  /*done with non erroneous logging, now logging erroneous packets */

  if(!gzprintf(handle,"-|-|-\n")){
    perror("error writing src mac in the zip file ");
    exit(1);
  }

  for (idx = table_err->added_since_last_update; idx > 0; --idx) {
    int mac_id = NORM(table_err->last - idx + 1);
	   float rssi_avg = table_err->entries[mac_id].rssi_lin_sum/((float)table_err->entries[mac_id].total_packets);
		 float rssi_std_dev = (table_err->entries[mac_id].rssi_square_lin_sum/(float)table_err->entries[mac_id].total_packets)  - (rssi_avg*rssi_avg);
#ifndef ANONYMIZATION
    u_int8_t *a=table_err->entries[mac_id].mac_address;
#endif    
#ifdef DEBUG_INCORRECT
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",a[0],a[1],a[2],a[3],a[4],a[5]);
    printf("pkt|anten|freq|ath_crc|ath_phy|channel|short_preamble|phy_wep|retry|more_flag|more_data|strictly_ordered|pwr_mgmt\n");
    printf("%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u\n",
	   table_err->entries[mac_id].total_packets,
	   table_err->entries[mac_id].antenna,
	   table_err->entries[mac_id].freq,
	   table_err->entries[mac_id].ath_crc_err_count,
	   table_err->entries[mac_id].ath_phy_err_count,
	   table_err->entries[mac_id].channel_rcv,
	   table_err->entries[mac_id].short_preamble_count,
	   table_err->entries[mac_id].phy_wep_count,
	   table_err->entries[mac_id].retry_count,
	   table_err->entries[mac_id].more_flag_count,
	   table_err->entries[mac_id].more_data_count,
	   table_err->entries[mac_id].strictly_ordered_count,
	   table_err->entries[mac_id].pwr_mgmt_count
	   );  
    printf("essid|beacon_|probe|privacy|ibss|rate|rate_max|rssi_avg|std_dev\n");
    printf("%s|%u|%u|%u|%u|%u|%2.1f|%2.1f|%2.1f\n",
	   table_err->entries[mac_id].essid,
	   table_err->entries[mac_id].beacon_count,
	   table_err->entries[mac_id].probe_count,
	   table_err->entries[mac_id].cap_privacy,
	   table_err->entries[mac_id].cap_ess_ibss,
	   table_err->entries[mac_id].rate,
	   table_err->entries[mac_id].rate_max,
	   rssi_avg,
		 rssi_std_dev
	   );
#endif

#ifdef ANONYMIZATION    
    uint8_t digest_mac[ETH_ALEN];
    if(anonymize_mac(table_err->entries[mac_id].mac_address, digest_mac)) {
      fprintf(stderr, "Error anonymizing MAC mapping\n");
      return -1;
    }
    u_int8_t *a=digest_mac;
    if(!gzprintf(handle,"%02x%02x%02x%02x%02x%02x|",a[0],a[1],a[2],a[3],a[4],a[5])){
      perror("error writing the client mac address in zip file ");
      exit(1);
    }
#else
    if(!gzprintf(handle,"%02x%02x%02x%02x%02x%02x|",a[0],a[1],a[2],a[3],a[4],a[5])){
      perror("error writing the client mac address in zip file ");
      exit(1);
    }
#endif
    if(!gzprintf(handle,"%s|%u|%u|%u|%u|%u|%u|%u|%u|%2.1f|%2.1f|%2.1f\n",
		 table_err->entries[mac_id].essid,
		 table_err->entries[mac_id].total_packets,
		 table_err->entries[mac_id].antenna,
		 table_err->entries[mac_id].freq,
		 table_err->entries[mac_id].ath_crc_err_count,
		 table_err->entries[mac_id].ath_phy_err_count,
		 table_err->entries[mac_id].channel_rcv,
		 table_err->entries[mac_id].short_preamble_count,
		 table_err->entries[mac_id].rate,
		 rssi_avg,
		 rssi_std_dev
		 )){
      perror("error writing the zip file ");
      exit(1);
    }
  }

  return 1; 
}

int address_none_table_lookup(none_address_table_t*  table,struct rcv_pkt * paket) {
  u_int8_t m_address[sizeof(paket->mac_address)];
  memset(m_address,'\0',sizeof(paket->mac_address));
  memcpy(m_address,paket->mac_address,sizeof(paket->mac_address));
  if (table->length > 0) {
    /* Search table starting w/ most recent MAC addresses. */
    int idx;
    for (idx = 0; idx < table->length; ++idx) {
      int mac_id = NORM(table->last - idx);
      if (!memcmp(table->entries[mac_id].mac_address, m_address, sizeof(m_address))){ 
	table->entries[mac_id].total_packets++;
	table->entries[mac_id].rssi_lin_sum= table->entries[mac_id].rssi_lin_sum + paket->rssi;
	// TODO : add the antilog of it 
	  table->entries[mac_id].freq =paket->freq ; 
	  table->entries[mac_id].rate=paket->rate;
	  table->entries[mac_id].channel_rcv=paket->channel_rcv;	  
	  table->entries[mac_id].antenna = paket->antenna;	  
	table->entries[mac_id].ath_phy_err_count=table->entries[mac_id].ath_phy_err_count+paket->ath_phy_err;
	if(paket->ath_crc_err ){
	  table->entries[mac_id].ath_crc_err_count++;	 
	}else{
	  
	    }
	return mac_id;
      }
    } 
  }    
  
  if (table->length == MAC_TABLE_ENTRIES) {
    //table is full, write it to a file 
    write_update();
    
  } else {
    ++table->length;
  }
  if (table->length > 1) {
    table->last = NORM(table->last + 1);
  }
  
  memcpy(table->entries[table->last].mac_address, paket->mac_address, sizeof(paket->mac_address));
  table->entries[table->last].total_packets=  1;
  table->entries[table->last].rssi_lin_sum=  paket->rssi;
  table->entries[table->last].rssi_square_lin_sum = paket->rssi * paket->rssi;

    table->entries[table->last].freq =paket->freq ; 
    table->entries[table->last].rate=paket->rate;
    table->entries[table->last].channel_rcv=paket->channel_rcv ;
    table->entries[table->last].antenna = paket->antenna;	  
  
  table->entries[table->last].ath_phy_err_count=paket->ath_phy_err;   
  if(paket->ath_crc_err){
    table->entries[table->last].ath_crc_err_count++ ;    
  }	
  else{
    
  }
  
  if (table->added_since_last_update < MAC_TABLE_ENTRIES) {
    ++table->added_since_last_update;
  }  
  return table->last;
  
}

int address_none_table_write_update(none_address_table_t* table,gzFile handle) {
  int idx;
//   printf("NP"); 
#if 0
  for (idx = table->added_since_last_update; idx > 0; --idx) {

    int mac_id = NORM(table->last - idx + 1);
    u_int8_t *a=table->entries[mac_id].mac_address;
    
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",a[0],a[1],a[2],a[3],a[4],a[5]);
    printf("pkt|anten|freq|ath_crc|ath_phy|rate|channel|short_preamble|phy_wep|retry|more_flag|more_data|strictly_ordered|pwr_mgmt\n");
    printf("%u|%u|%u|%u|%u|%u|%u|%2.1f|%2.1f\n",
	   table->entries[mac_id].total_packets,
	   table->entries[mac_id].antenna,
	   table->entries[mac_id].freq,
	   table->entries[mac_id].ath_crc_err_count,
	   table->entries[mac_id].ath_phy_err_count,
	   table->entries[mac_id].channel_rcv,
	   table->entries[mac_id].short_preamble_count,
	   table->entries[mac_id].rate
	   );  

  }
#endif
  for (idx = table->added_since_last_update; idx > 0; --idx) {
    int mac_id = NORM(table->last - idx + 1);
	   float rssi_avg = table->entries[mac_id].rssi_lin_sum/((float)table->entries[mac_id].total_packets);
		 float rssi_std_dev = (table->entries[mac_id].rssi_square_lin_sum/(float)table->entries[mac_id].total_packets)  - (rssi_avg*rssi_avg);
    u_int8_t *a=table->entries[mac_id].mac_address;   
    if(!gzprintf(handle,"%02x:%02x|",a[0],a[1])) {
      perror("cannot write mac on  none packets");
      exit(1);
    }
    if(!gzprintf(handle,"%u|%u|%u|%u|%u|%u|%u|%u|%2.1f|%2.1f\n",
		 table->entries[mac_id].total_packets,
		 table->entries[mac_id].antenna,
		 table->entries[mac_id].freq,
		 table->entries[mac_id].ath_crc_err_count,
		 table->entries[mac_id].ath_phy_err_count,
		 table->entries[mac_id].channel_rcv,
		 table->entries[mac_id].short_preamble_count,
		 table->entries[mac_id].rate,
		 rssi_avg,
		 rssi_std_dev
		 )){
      perror("can't write info about none packets \n");
      exit(1);
    }
    
  }
  
  return 1; 
}

int address_client_table_lookup(client_address_table_t*  table, u_int32_t c_tx_failed,
				u_int32_t c_tx_retries , u_int32_t c_tx_pkts,
				u_int32_t c_rx_pkts, const u_int8_t * m_add ,int dev,
				int tx_bitrate, int rx_bitrate) {
  if (table->length > 0) {
    /* Search table starting w/ most recent MAC addresses. */
    int idx;
    for (idx = 0; idx < table->length; ++idx) {
      int mac_id = NORM(table->last - idx);
      if (!memcmp(table->entries[mac_id].mac_address, m_add, 6) && dev==table->entries[mac_id].dev  ){ 

	table->entries[mac_id].rx_bitrate = rx_bitrate ;
	table->entries[mac_id].tx_bitrate = tx_bitrate ; 
	table->entries[mac_id].dev =dev ; 
	table->entries[mac_id].tx_failed = table->entries[mac_id].tx_failed + c_tx_failed - table->entries[mac_id].prev_tx_failed;
	table->entries[mac_id].tx_retries = table->entries[mac_id].tx_retries + c_tx_retries - table->entries[mac_id].prev_tx_retries;
	table->entries[mac_id].tx_pkts = table->entries[mac_id].tx_pkts + c_tx_pkts - table->entries[mac_id].prev_tx_pkts; 
	table->entries[mac_id].rx_pkts = table->entries[mac_id].rx_pkts + c_rx_pkts-table->entries[mac_id].prev_rx_pkts; 
	
	table->entries[mac_id].prev_tx_failed = c_tx_failed;
	table->entries[mac_id].prev_tx_retries= c_tx_retries ;
	table->entries[mac_id].prev_tx_pkts = c_tx_pkts;
	table->entries[mac_id].prev_rx_pkts = c_rx_pkts;

	return mac_id;
      }
    } 
  }    
  
  if (table->length == MAC_TABLE_ENTRIES) {
    //table is full, write it to a file 
    write_update();
  } else {
    ++table->length;
  }
  if (table->length > 1) {
    table->last = NORM(table->last + 1);
  }  
  
  memcpy(table->entries[table->last].mac_address, m_add, 6);
	table->entries[table->last].dev =dev ; 
/*
    u_int8_t *a= table->entries[table->last].mac_address ;
    u_int8_t *ab= m_add ;
    printf(" in lookup %02x:%02x:%02x:%02x:%02x:%02x\n",a[0],a[1],a[2],a[3],a[4],a[5]);
    printf(" original  %02x:%02x:%02x:%02x:%02x:%02x\n",ab[0],ab[1],ab[2],ab[3],ab[4],ab[5]);
*/
  table->entries[table->last].tx_bitrate = tx_bitrate ; 
  table->entries[table->last].rx_bitrate = rx_bitrate ;
    
  table->entries[table->last].prev_tx_failed = c_tx_failed;
  table->entries[table->last].prev_tx_retries= c_tx_retries ;
  table->entries[table->last].prev_tx_pkts = c_tx_pkts;  
  table->entries[table->last].prev_rx_pkts = c_rx_pkts;

  if (table->added_since_last_update < MAC_TABLE_ENTRIES) {
    ++table->added_since_last_update;
  }  
  return table->last;
  
}

int address_client_table_write_update(gzFile handle, client_address_table_t* table) {
  int idx;
//   printf("CI \n"); 
  for (idx = table->added_since_last_update; idx > 0; --idx) {
		
    int mac_id = NORM(table->last - idx + 1);
#ifndef ANONYMIZATION
    u_int8_t *a=table->entries[mac_id].mac_address;
    printf("%02x:%02x:%02x:%02x:%02x:%02x|",a[0],a[1],a[2],a[3],a[4],a[5]);
#endif
#ifdef DEBUG_CORRECT
    printf("%u|%u|%u|%u|%u|%d.%d|%d.%d\n",
	   table->entries[mac_id].tx_pkts,
	   table->entries[mac_id].tx_retries,
	   table->entries[mac_id].tx_failed,
	   table->entries[mac_id].rx_pkts,
	   table->entries[mac_id].dev,
	   table->entries[mac_id].rx_bitrate /10 ,
	   (table->entries[mac_id].rx_bitrate %10),
	   table->entries[mac_id].tx_bitrate /10,
	   (table->entries[mac_id].tx_bitrate %10)
	   );
#endif

#ifdef ANONYMIZATION    
    uint8_t digest_mac[ETH_ALEN];
    if(anonymize_mac(table->entries[mac_id].mac_address, digest_mac)) {
      fprintf(stderr, "Error anonymizing MAC mapping\n");
      return -1;
    }
    u_int8_t *a=digest_mac; 
    if(!gzprintf(handle,"%02x%02x%02x%02x%02x%02x|",a[0],a[1],a[2],a[3],a[4],a[5])){
      perror("error writing the client mac address in zip file ");
      exit(1);
    }
#else
    if(!gzprintf(handle,"%02x%02x%02x%02x%02x%02x|",a[0],a[1],a[2],a[3],a[4],a[5])){
      perror("error writing the client mac address in zip file ");
      exit(1);
    }
#endif
    if(!gzprintf(handle,"%u|%u|%u|%u|%u|%d.%d|%d.%d\n",				 
		 table->entries[mac_id].tx_pkts,
		 table->entries[mac_id].tx_retries,
		 table->entries[mac_id].tx_failed,
		 table->entries[mac_id].rx_pkts,
		 table->entries[mac_id].dev,
		 table->entries[mac_id].rx_bitrate /10 ,
		 (table->entries[mac_id].rx_bitrate %10),
		 table->entries[mac_id].tx_bitrate /10,
		 (table->entries[mac_id].tx_bitrate %10)
		 )){
        perror("error writing the client information in  zip file ");
        exit(1);								
    };
  }
  return 1; 
}


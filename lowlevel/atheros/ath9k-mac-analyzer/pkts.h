#ifndef _PKTS_TABLE_H
#define _PKTS_TABLE_H

struct rcv_pkt {
  u_int8_t mac_address[6];
  // jigdump header 
  int8_t rssi;
  u_int8_t channel_rcv;
  u_int16_t rate;
  u_int16_t  freq ;
  u_int32_t ath_crc_err;
  u_int32_t ath_phy_err;
  u_int8_t antenna;
  u_int8_t short_preamble_err;
  //radiotap header 

  //from the control bits of mac header  
  u_int8_t strictly_ordered;
  u_int8_t pwr_mgmt;
  u_int8_t wep_enc;
  u_int8_t more_data;
  u_int8_t more_flag;
  u_int8_t retry ;

  u_int8_t pkt_type;
  union {
    struct {
      u_int8_t pkt_subtype; 
      char essid[33] ;      
      u_int8_t cap_privacy ;
      u_int8_t cap_ess_ibss ;
      u_int8_t channel;
      u_int8_t n_enabled; // added on 14 feb, 2012        
      float rate_max;
    }mgmt_pkt;
    struct {
      u_int8_t pkt_subtype; // cts, rts, ack
      u_int8_t ta[6];
    }ctrl_pkt;
    struct {
      u_int8_t dst[6];
      u_int8_t pkt_subtype; //data, no data
      u_int32_t eth_type; // ip, arp
      u_int8_t transport_type; //tcp, udp
    }data_pkt;
  }p;

  // I have to fix to get these to get the values 

};


struct ctrl_rts_t {
  u_int16_t       fc;
  u_int16_t       duration;
  u_int8_t        ra[6];
  u_int8_t        ta[6];
  u_int8_t        fcs[4];
};

#define CTRL_RTS_HDRLEN (IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+\
                         IEEE802_11_RA_LEN+IEEE802_11_TA_LEN)

struct ctrl_cts_t {
  u_int16_t       fc;
  u_int16_t       duration;
  u_int8_t        ra[6];
  u_int8_t        fcs[4];
};

#define CTRL_CTS_HDRLEN (IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+IEEE802_11_RA_LEN)

struct ctrl_ack_t {
  u_int16_t       fc;
  u_int16_t       duration;
  u_int8_t        ra[6];
  u_int8_t        fcs[4];
};

struct ctrl_end_t {
  u_int16_t       fc;
  u_int16_t       duration;
  u_int8_t        ra[6];
  u_int8_t        bssid[6];
  u_int8_t        fcs[4];
};
struct ctrl_end_ack_t {
  u_int16_t       fc;
  u_int16_t       duration;
  u_int8_t        ra[6];
  u_int8_t        bssid[6];
  u_int8_t        fcs[4];
};
struct ctrl_ps_poll_t {
  u_int16_t       fc;
  u_int16_t       aid;
  u_int8_t        bssid[6];
  u_int8_t        ta[6];
  u_int8_t        fcs[4];
};

struct ctrl_ba_t {
  u_int16_t       fc;
  u_int16_t       duration;
  u_int8_t        ra[6];
  u_int8_t        fcs[4];
};

struct ctrl_bar_t {
  u_int16_t       fc;
  u_int16_t       dur;
  u_int8_t        ra[6];
  u_int8_t        ta[6];
  u_int16_t       ctl;
  u_int16_t       seq;
  u_int8_t        fcs[4];
};


// end of less significant packets 

struct mgmt_header_t {
  u_int16_t    fc;               /* 2 bytes */
  u_int16_t    duration;         /* 2 bytes */
  u_int8_t     da[6];            /* 6 bytes */
  u_int8_t     sa[6];            /* 6 bytes */
  u_int8_t     bssid[6];         /* 6 bytes */
  u_int16_t    seq_ctrl;         /* 2 bytes */

};

struct rates_t {
  u_int8_t        element_id;
  u_int8_t        length;
  u_int8_t        rate[16];
};

struct challenge_t {
  u_int8_t        element_id;
  u_int8_t        length;
  u_int8_t        text[254]; /* 1-253 + 1 for null */
};

struct fh_t {
  u_int8_t        element_id;
  u_int8_t        length;
  u_int16_t       dwell_time;
  u_int8_t        hop_set;
  u_int8_t        hop_pattern;
  u_int8_t        hop_index;
};

struct ds_t {
  u_int8_t        element_id;
  u_int8_t        length;
  u_int8_t        channel;
};

struct cf_t {
  u_int8_t        element_id;
  u_int8_t        length;
  u_int8_t        count;
  u_int8_t        period;
  u_int16_t       max_duration;
  u_int16_t       dur_remaing;
};

struct tim_t {
  u_int8_t        element_id;
  u_int8_t        length;
  u_int8_t        count;
  u_int8_t        period;
  u_int8_t        bitmap_control;
  u_int8_t        bitmap[251];
};

struct ssid_t {
  u_int8_t        element_id;
  u_int8_t        length;
  u_char          ssid[33];  /* 32 + 1 for null */
};

struct mgmt_body_t {
  u_int8_t        timestamp[IEEE802_11_TSTAMP_LEN];
  u_int16_t       beacon_interval;
  u_int16_t       listen_interval;
  u_int16_t       status_code;
  u_int16_t       aid;
  u_char          ap[IEEE802_11_AP_LEN];
  u_int16_t       reason_code;
  u_int16_t       auth_alg;
  u_int16_t       auth_trans_seq_num;
  int             challenge_present;
  struct challenge_t  challenge;
  u_int16_t       capability_info;
  int             ssid_present;
  struct ssid_t   ssid;
  int             rates_present;
  struct rates_t  rates;
  int             ds_present;
  struct ds_t     ds;
  int             cf_present;
  struct cf_t     cf;
  int             fh_present;
  struct fh_t     fh;
  int             tim_present;
  struct tim_t    tim;
};

/*
 * A somewhat abstracted view of the LLC header
 */

struct llc_hdr {
  u_int8_t dsap;
  u_int8_t ssap;
  struct {
    u_int8_t ui;
    u_int8_t org_code[3];
    u_int16_t ether_type;
  } snap;
};


#endif /* PKTS_TABLE_H*/

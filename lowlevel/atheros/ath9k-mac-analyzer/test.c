
enum mac80211_rx_flags {
  RX_FLAG_MMIC_ERROR      = 1<<0,
  RX_FLAG_DECRYPTED       = 1<<1,
  RX_FLAG_MMIC_STRIPPED   = 1<<3,
  RX_FLAG_IV_STRIPPED     = 1<<4,
  RX_FLAG_FAILED_FCS_CRC  = 1<<5,
  RX_FLAG_FAILED_PLCP_CRC = 1<<6,
  RX_FLAG_MACTIME_MPDU    = 1<<7,
  RX_FLAG_SHORTPRE        = 1<<8,
  RX_FLAG_HT              = 1<<9,
  RX_FLAG_40MHZ           = 1<<10,
  RX_FLAG_SHORT_GI        = 1<<11,
};
void test_func_inspection(struct jigdump_hdr * jh){
  if(jh-> version_ == JIGDUMP_HDR_VERSION ){
    printf("version %d\n ",jh-> version_);
    printf("hdr_len %d \n ",jh-> hdrlen_);
    printf("status %d \n",jh-> status_);
    printf("phy-err %d \n",jh-> phyerr_);
    printf("rssi %d\n ",jh-> rssi_);
    printf("flags %d\n ",jh-> flags_);
    printf("channel %d\n ",jh-> channel_);
    printf("rate %d \n ",jh-> rate_);
    printf("caplen %d \n",jh-> caplen_);
    printf("snaplen %d \n ",jh-> snaplen_);
    printf("prev errs %d \n",jh-> prev_errs_);
    printf("mac time %llu \n",jh-> mac_time_);
    printf("fcs=%d\n",jh-> fcs_);
  }else{
  printf("Error : version not correct !  \n");
  printf("version %d\n ",jh-> version_);
   printf("phy-err %d \n",jh-> phyerr_);
  printf("rssi %d \n",jh-> rssi_);
  }
}


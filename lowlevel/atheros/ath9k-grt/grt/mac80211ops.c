#include "mac80211ops.h"
#include "grt_pci.h"
#include "intr.h"
#include "debug.h"

/**
 * grt_setup_bands() - setup bands information
 * @hw: ieee80211_hw
 * @return: return 0 when success, otherwise return -1
 * Setup bands information in hw->wiphy
 */
int grt_setup_bands(struct ieee80211_hw *hw)
{
  struct grt_hw *gh = hw->priv;
  struct ieee80211_supported_band *sband;
  /*5GHz band setup*/
  sband = &gh->sbands[IEEE80211_BAND_5GHZ];
  sband->band = IEEE80211_BAND_5GHZ;
  sband->bitrates = &gh->rates[IEEE80211_BAND_5GHZ][0];
  memcpy(sband->bitrates, &grt_rates[4], sizeof(struct ieee80211_rate) * 8);
  sband->n_bitrates = 8;
  sband->channels = gh->channels;
  sband->n_channels = 1;
  sband->channels[0].center_freq = ieee80211_channel_to_frequency(36, IEEE80211_BAND_5GHZ);
  sband->channels[0].band = IEEE80211_BAND_5GHZ;
  sband->channels[0].hw_value = 0; /*0 stands for 802.11*/
  sband->channels[0].flags &= ~IEEE80211_CHAN_PASSIVE_SCAN; /*always use active scan*/
  hw->wiphy->bands[IEEE80211_BAND_5GHZ] = sband;
  return 0;
}

/**
 * grt_mac_init() - initialize tx and rx queues
 * @gh: private data of the driver, which contains the pointer to the queues.
 */
int grt_mac_init(struct grt_hw * gh)
{
  struct ieee80211_hw *hw = gh->hw;
    u8 mac[ETH_ALEN] = {MAC_ADDR0, MAC_ADDR1, MAC_ADDR2,
		      MAC_ADDR3, MAC_ADDR4, MAC_ADDR5};
  struct grt_buf *bf;
  int i;
  /*set mac80211*/
  SET_IEEE80211_PERM_ADDR(hw, mac);
  SET_IEEE80211_DEV(hw, gh->dev);
  hw->wiphy->interface_modes = BIT(NL80211_IFTYPE_AP) | BIT(NL80211_IFTYPE_STATION);
  hw->wiphy->available_antennas_tx = 0x1;
  hw->wiphy->available_antennas_rx = 0x1;
  grt_setup_bands(hw);
  /*init locks and queues*/
  spin_lock_init(&gh->txq_lock);
  spin_lock_init(&gh->tx_waiting_q_lock);
  spin_lock_init(&gh->txbuf_lock);
  INIT_LIST_HEAD(&gh->txq);
  INIT_LIST_HEAD(&gh->tx_waiting_q);
  INIT_LIST_HEAD(&gh->txbuf);
  /*alloc tx buffer*/
  for(i = 0; i < TXBUF_SIZE; i++){
    bf = (struct grt_buf *)kmalloc(sizeof(struct grt_buf), GFP_KERNEL);
    if(unlikely(bf == NULL)){
      printk("GRT: grt_mac_init alloc grt_buf error.\n");
      return -1;
    }
    bf->grt_descs = pci_alloc_consistent(gh->pdev, 32, &bf->daddr);
    if(unlikely(NULL == bf->grt_descs)){
      printk("GRT: grt_mac_init alloc txbuf error.\n");
      return -1;
    }
    list_add_tail(&bf->list, &gh->txbuf);
  }
  atomic_set(&gh->tx_stopped, 0);
  /*alloc rx buffer*/
  gh->rxbuf = (struct grt_buf *)kmalloc(sizeof(struct grt_buf), GFP_KERNEL);
  if(unlikely(NULL == gh->rxbuf)){
    printk("GRT: grt_mac_init alloc rxbuf error.\n");
    return -1;
  }
  gh->rxbuf->grt_descs =  pci_alloc_consistent(gh->pdev, 32, &gh->rxbuf->daddr);
  if(unlikely(NULL == gh->rxbuf->grt_descs)){
    printk("GRT: grt_mac_init alloc rxbuf descriptor error.\n");
    return -1;
  }
  /*init dbps_table*/
  gh->dbps_table[GRT_RATE_CODE_6M]  = 24;
  gh->dbps_table[GRT_RATE_CODE_9M]  = 36;
  gh->dbps_table[GRT_RATE_CODE_12M] = 48;
  gh->dbps_table[GRT_RATE_CODE_18M] = 72;
  gh->dbps_table[GRT_RATE_CODE_24M] = 96;
  gh->dbps_table[GRT_RATE_CODE_36M] = 144;
  gh->dbps_table[GRT_RATE_CODE_48M] = 192;
  gh->dbps_table[GRT_RATE_CODE_54M] = 216;
  /*init stats*/
  gh->stats.tx_all_count = 0;
  gh->stats.tx_bytes_count = 0;
  gh->stats.ack_fail = 0;
  gh->stats.rx_all_count = 0;
  gh->stats.rx_bytes_count = 0;
  gh->stats.rxerr_crc = 0;
  return 0;
}

/**
 * grt_mac_exit() - finalize function
 * @gh: private data of the driver, which contains the pointer to the queues.
 */
void grt_mac_exit(struct grt_hw * gh)
{
  struct grt_buf *bf, *bf_temp;
  list_for_each_entry_safe(bf, bf_temp, &gh->txbuf, list){
    pci_free_consistent(gh->pdev, 32, bf->grt_descs, bf->daddr);
    list_del(&bf->list);
    kfree(bf);
  }
  pci_free_consistent(gh->pdev, 32, gh->rxbuf->grt_descs, gh->rxbuf->daddr);
  kfree(gh->rxbuf);
}

/**
 * frame_needs_ack() - check whether the frame needs ack
 * @skb: the socket buffer holding the frame
 * @return: return 0 when ack is not needed, otherwise return 1
 * Broadcast or group-cast frame do not need ack. Normal MAC address's first byte's lowest bit
 * can't be '1'.
 */
static inline int frame_needs_ack(struct sk_buff * skb)
{
  if(skb->data[4] & 0x01)
    return 0;
  else
    return 1;
}

/**
 * grt_tx() - tx function in ieee80211_ops
 */
static void grt_tx(struct ieee80211_hw *hw,
         struct ieee80211_tx_control *control,
         struct sk_buff *skb)
{
  struct grt_hw *gh = hw->priv;
  struct grt_buf *bf;
  struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);
  struct ieee80211_rate *rate;
  /*get tx rates from mac80211*/
  rate = ieee80211_get_tx_rate(hw, info);
  if(!rate){
    dev_kfree_skb_any(skb);
    GRT_PRINT_DEBUG("grt_tx : tx rate error, drop current skb.\n");
    return;
  }
  spin_lock(&gh->txbuf_lock);
  if(list_empty(&gh->txbuf)){
    /*drop this packet and stop queues*/
    atomic_set(&gh->tx_stopped, 1);
    ieee80211_stop_queues(hw);
    spin_unlock(&gh->txbuf_lock);
    dev_kfree_skb_any(skb);
    GRT_PRINT_DEBUG("grt_tx : cannot get free txbuf, drop current skb.\n");
    return;
  }
  bf = list_first_entry(&gh->txbuf, struct grt_buf, list);
  list_del(&bf->list);
  if(list_empty(&gh->txbuf)){
    /*stop queus*/
    atomic_set(&gh->tx_stopped, 1); 
    ieee80211_stop_queues(hw);
    GRT_PRINT_DEBUG("grt_tx : stop tx queue.\n");
  }
  spin_unlock(&gh->txbuf_lock);
  grt_debug_print_skb("grt_tx : put this skb into txq", skb);
  bf->grt_desc_count = 1;
  bf->skb = skb;
  bf->ccw = MAC_aCWmin;
  bf->needs_ack = frame_needs_ack(bf->skb);
  /*like Ath5k in Ubuntu 12.04, we use one rate to send the frame several times*/
#ifdef MAC_TX_FIX_RATE
  bf->rates[0] = MAC_TX_FIX_RATE;
#else
  if(info->control.rates[0].flags & IEEE80211_TX_RC_USE_SHORT_PREAMBLE)
    bf->rates[0] = GRT_RATE_CODE_6M; /*802.11b is not supported, so use BPSK 1/2*/
  else
    if(rate->hw_value == GRT_RATE_CODE_1M || rate->hw_value == GRT_RATE_CODE_2M ||
       rate->hw_value == GRT_RATE_CODE_5_5M || rate->hw_value == GRT_RATE_CODE_11M)
      bf->rates[0] = GRT_RATE_CODE_6M; /*802.11b is not supported, so use BPSK 1/2*/
    else
      bf->rates[0] = rate->hw_value;
#endif
  bf->tries[0] = MAC_MAX_RETRY;
  bf->rates[1] = GRT_RATE_CODE_NUL; /*set it to invalid*/
  bf->tries[1] = 0;
  GRT_PRINT_DEBUG("grt_tx : skb params\n ccw = %d, needs_ack = %d, rates = {(0x%2x, %d), (0x%2x, %d)}\n", 
  bf->ccw, bf->needs_ack, bf->rates[0], bf->tries[0], bf->rates[1], bf->tries[1]);
  /*add bf to txq*/
  spin_lock(&gh->txq_lock);
  list_add_tail(&bf->list, &gh->txq);
  spin_unlock(&gh->txq_lock);
  /*schedule grt_tasklet_tx*/
  tasklet_schedule(&gh->tx_tasklet);
}

/**
 * grt_start() - start function in ieee80211_ops
 */
int grt_start(struct ieee80211_hw * hw)
{
  struct grt_hw *gh = hw->priv;
  /*reset hardware, enable hardware interrupt*/
  u32 status = 0;
  /*set UHD before reset*/
  grt_pio_write(gh, REG_SYSTEM_RESET, 0x0000);
  grt_pio_write(gh, REG_UHD_PROPERTY, UHD_PROPERTY);
  /*reset hardware*/
  grt_pio_write(gh, REG_SYSTEM_RESET, 0x0001);
  while((status & 0x0030) != 0x0030){
    status = grt_pio_read(gh, REG_SYSTEM_RESET);
  }
  grt_pio_write(gh, REG_SYSTEM_RESET, 0x0000);
  /*enable interrupt*/
  grt_pio_write(gh, REG_INT_CTRL, 0x0031);
  grt_pio_write(gh, REG_USR_INT_CTRL, 0x08); /*Set USR_SW_WAITING_INT vector 0*/
  grt_pio_write(gh, REG_USR_INT_CTRL, 0x09); /*Set USR_SW_WAITING_INT vector 1*/
  grt_pio_write(gh, REG_USR_INT_CTRL, 0x0A); /*Set USR_SW_WAITING_INT vector 2*/
  /*init hardware low MAC*/
  grt_pio_write(gh, REG_CCA_THRESHOLD, MAC_CCA_THRESHOLD);
  grt_pio_write(gh, REG_MAC_ADDR_L, 
		( MAC_ADDR5        & 0x000000FF) | 
		((MAC_ADDR4 <<  8) & 0x0000FF00) | 
		((MAC_ADDR3 << 16) & 0x00FF0000));
  grt_pio_write(gh, REG_MAC_ADDR_H,
		( MAC_ADDR2        & 0x000000FF) | 
		((MAC_ADDR1 <<  8) & 0x0000FF00) | 
		((MAC_ADDR0 << 16) & 0x00FF0000));
  grt_pio_write(gh, REG_ACK_TIMEOUT, MAC_ACK_TIMEOUT);
  grt_pio_write(gh, REG_SLOTTIME, SlotTime);
  grt_pio_write(gh, REG_DIFSTIME, DIFSTime);
  grt_pio_write(gh, REG_SIFSTIME, SIFSTime);
  grt_pio_write(gh, REG_MAC_FILTER_FLAG, MACFliterFlag);
  return 0;
}

/**
 * grt_stop() - stop function in ieee80211_ops
 */
void grt_stop(struct ieee80211_hw * hw)
{
  struct grt_hw *gh = hw->priv;
  struct grt_buf *bf, *bf_temp;
  tasklet_kill(&gh->tx_tasklet);
  tasklet_kill(&gh->rx_tasklet);
  /*disable hardware interrupt*/
  grt_pio_write(gh, REG_INT_CTRL, 0x030);
  /* clear all tx data*/
  spin_lock(&gh->txq_lock);
  spin_lock(&gh->txbuf_lock);
  list_for_each_entry_safe(bf, bf_temp, &gh->txq, list){
    list_del(&bf->list);
    dev_kfree_skb_any(bf->skb);
    bf->skb = NULL;
    list_add_tail(&bf->list, &gh->txbuf);
  }
  spin_unlock(&gh->txbuf_lock);
  spin_unlock(&gh->txq_lock);
}

/**
 * grt_add_interface() - add_interface function in ieee80211_ops
 */
static int grt_add_interface(struct ieee80211_hw *hw,
			     struct ieee80211_vif *vif)
{
  struct grt_hw *gh = hw->priv;
  int slot;
  u32 reg;
  switch(vif->type){
  case NL80211_IFTYPE_STATION:
    break;
  case NL80211_IFTYPE_AP:
    spin_lock(&gh->bc_lock);
    /*Look for an empty slot*/
    for(slot = 0; slot < GRT_BCBUF; slot++){
      if(!gh->bslot[slot]){
	gh->bslot[slot] = vif;
	break;
      }
    }
    /*No empty slot left, add interface failed*/
    if(slot == GRT_BCBUF){
      spin_unlock(&gh->bc_lock);
      return -ELNRNG; /*link number out of range*/
    }
	/*Set timeout threshold*/
	switch(slot){
	case 0:
		grt_pio_write(gh, REG_BSLOT0_TIMEOUT_THRESHOLD, MAC_BEACON_TIMEOUT_THRESHOLD);
		break;
	case 1:
		grt_pio_write(gh, REG_BSLOT1_TIMEOUT_THRESHOLD, MAC_BEACON_TIMEOUT_THRESHOLD);
		break;
	case 2:
		grt_pio_write(gh, REG_BSLOT2_TIMEOUT_THRESHOLD, MAC_BEACON_TIMEOUT_THRESHOLD);
		break;
	case 3:
		grt_pio_write(gh, REG_BSLOT3_TIMEOUT_THRESHOLD, MAC_BEACON_TIMEOUT_THRESHOLD);
		break;
	}
    /*Set AP enable*/
    reg = grt_pio_read(gh, REG_BSLOT_ACT);
    reg |= (0x0001 << slot);
    grt_pio_write(gh, REG_BSLOT_ACT, reg);
    spin_unlock(&gh->bc_lock);
    break;
  default:
    return -EOPNOTSUPP; /* Operation not supported on transport endpoint */
  }
    return 0;
}

/**
 * grt_remove_interface() - remove_interface function in ieee80211_ops
 */
static void grt_remove_interface(struct ieee80211_hw *hw,
				 struct ieee80211_vif *vif)
{
  struct grt_hw * gh = hw->priv;
  int slot;
  u32 reg;
  spin_lock(&gh->bc_lock);
  /*look for vif*/
  for(slot = 0; slot < GRT_BCBUF; slot++){
    if(vif == gh->bslot[slot]){
      gh->bslot[slot] = NULL;
      break;
    }
  }
  /*vif not found*/
  if(slot == GRT_BCBUF){
    spin_unlock(&gh->bc_lock);
    return;
  }
  /*Set AP disable*/
  reg = grt_pio_read(gh, REG_BSLOT_ACT);
  reg &= (~(0x0001 << slot));
  grt_pio_write(gh, REG_BSLOT_ACT, reg);
  spin_unlock(&gh->bc_lock);
  return;
}

/**
 * grt_config() - config function in ieee80211_ops
 */
static int grt_config(struct ieee80211_hw *hw, u32 changed)
{
  /*Do nothing*/
  return 0;  
}

/**
 * grt_configure_filter() - configure_filter function in ieee80211_ops
 */
static void grt_configure_filter(struct ieee80211_hw *hw, unsigned int changed_flags,
				 unsigned int *new_flags, u64 multicast)
{
#define SUPPORTED_FIF_FLAGS \
  (FIF_PROMISC_IN_BSS |  FIF_ALLMULTI | FIF_FCSFAIL | \
    FIF_PLCPFAIL | FIF_CONTROL | FIF_OTHER_BSS | \
   FIF_BCN_PRBRESP_PROMISC)
  /* Only deal with supported flags */
  changed_flags &= SUPPORTED_FIF_FLAGS;
  *new_flags &= SUPPORTED_FIF_FLAGS;
}

/**
 * grt_sw_scan_start() - software scan start
 */
static void grt_sw_scan_start(struct ieee80211_hw *hw)
{
  struct grt_hw *gh = hw->priv;
  /*always use active scan, so dis-set the IEEE80211_CHAN_PASSIVE_SCAN bit*/
  gh->channels[0].flags &= ~IEEE80211_CHAN_PASSIVE_SCAN;
  return;
}

/**
 * grt_sw_scan_complete() - software scan complete
 */
static void grt_sw_scan_complete(struct ieee80211_hw *hw)
{
  return;
}

/**
 * grt_get_stats() - get status
 */
static int grt_get_stats(struct ieee80211_hw *hw,
		struct ieee80211_low_level_stats *stats)
{
  struct grt_hw *gh = hw->priv;

  stats->dot11ACKFailureCount = gh->stats.ack_fail;
  // stats->dot11RTSFailureCount = gh->stats.rts_fail;
  // stats->dot11RTSSuccessCount = gh->stats.rts_ok;
  stats->dot11FCSErrorCount = gh->stats.rxerr_crc;

  return 0;
}

const struct ieee80211_ops grt_80211_ops = {
  .tx = grt_tx,
  .start = grt_start,
  .stop = grt_stop,
  .add_interface = grt_add_interface,
  .remove_interface = grt_remove_interface,
  .config = grt_config,
  .configure_filter = grt_configure_filter,
  .sw_scan_start = grt_sw_scan_start,
  .sw_scan_complete = grt_sw_scan_complete,
  .get_stats = grt_get_stats,
};


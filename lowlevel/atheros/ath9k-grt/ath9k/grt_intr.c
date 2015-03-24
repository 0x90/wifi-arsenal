#include "grt_intr.h"
#include "grt_pci.h"
#include "grt_debug.h"

/**
 * @brief grt_tasklet_tx_int() - software interrupt call back for tx interrupt
 * @param data : pointer to private data of this driver
 * @note
 * The TX interrupt will call this. This function will deal with the TX interrupt. For succeeded
 * frame, it will report it to mac80211; for failed frame, it will prepare for its resend.
 */
void grt_tasklet_tx_int(unsigned long data)
{
	struct grt_hw *gh = (void *)data;
	struct grt_buf *bf;
	struct ieee80211_tx_info *info;
	u32 status;
	int i;/*for loop*/
	GRT_PRINT_DEBUG(">>grt_tasklet_tx_int : called\n");
	spin_lock(&gh->tx_lock);
	spin_lock(&gh->tx_waiting_q_lock);
	status = grt_pio_read(gh, REG_PDU_RESPONSE);
	GRT_PRINT_DEBUG("grt_tasklet_tx_int : PDU_RESPONSE status = 0x%x.\n", status);
/*assert low MAC's PDU_RESPONSE is dealt with in SW*/
	grt_pio_write(gh, REG_PDU_RESPONSE_SERVED, 0x01);
	if(likely((status & 0x03) != 0) && (!list_empty(&gh->tx_waiting_q))){
/*Get the first item in txq. This item is the one transferred last time*/
		bf = list_first_entry(&gh->tx_waiting_q, struct grt_buf, list);
		info = IEEE80211_SKB_CB(bf->skb);
		GRT_PRINT_DEBUG("grt_tasklet_tx_int : will send the next frame.\n");
/* TODO : information return to mac80211, hardware currently only support the first rate */
		info->status.rates[0].count = bf->tries[0];
		for(i = 1; i < IEEE80211_TX_MAX_RATES; i++){
			info->status.rates[i].count = -1;
		}
		if((status & 0x02) != 0){ /*Last frame sent successfully*/
			info->flags |= ((bf->needs_ack) ? IEEE80211_TX_STAT_ACK : 0);
			/*TODO : ACK RSSI, hardware not supported currently*/
			info->status.ack_signal = 0; 
		}
		else{
			if(bf->needs_ack != 0)/*Last frame sent failed*/
				grt_info_print_bf("grt_tasklet_tx_int : Sending skb failed:", bf);
		}
		ieee80211_tx_status(gh->hw, bf->skb);
/*update driver statistics*/
		gh->stats.tx_all_count++;
		gh->stats.tx_bytes_count += bf->skb->len;
		gh->stats.ack_fail += (((status & 0x02) == 0) ? 0 : 1);
/*tx buffer operations*/
		list_del(&bf->list);
		bf->skb = NULL;
		spin_lock(&gh->txbuf_lock);
		list_add_tail(&bf->list, &gh->txbuf);
		if(atomic_read(&gh->tx_stopped) == 1){
			ieee80211_wake_queues(gh->hw);
			atomic_set(&gh->tx_stopped, 0);
		}
		spin_unlock(&gh->txbuf_lock);
	}
	spin_unlock(&gh->tx_waiting_q_lock);
	spin_unlock(&gh->tx_lock);
	tasklet_schedule(&gh->tx_tasklet);
}

/**
 * @brief grt_tasklet_tx() - software interrupt call back for tx
 * @param data: pointer to private data of this driver
 * @note
 * Both grt_tasklet_tx_int, grt_tasklet_bc and grt_tx can cause this function to be active. It 
 * will generate a send request to hardware if it is not busy.
 */
void grt_tasklet_tx(unsigned long data)
{
	struct grt_hw *gh = (void *)data;
	struct grt_buf *bf;
	u32 status;
	u32 phy_framebody_bit_len;
	u32 n_dbps;
	u32 backoff_time;
	u32 grt_reg_tx_ctrl;
	u32 complex_count;
	int i;
	u32 PDU_REQUEST_REGS[] = {REG_PDU_REQUEST1, REG_PDU_REQUEST2, REG_PDU_REQUEST3, \
								REG_PDU_REQUEST4, REG_PDU_REQUEST5};
	GRT_PRINT_DEBUG(">>grt_tasklet_tx : called\n");
	// spin_lock(&gh->tx_lock);
/*Send frame*/
	while(!list_empty(&gh->txq)){
/*Check if HW is busy*/
		status = grt_pio_read(gh, REG_PDU_RAM_STATUS);
		GRT_PRINT_DEBUG("grt_tasklet_tx : REG_PDU_RAM_STATUS = 0x%x.\n", status); 
		if(status & 0x01){ /*REG_PDU_RAM_STATUS's 0th bit == 1'b1 stands for hardware available*/
			GRT_PRINT_DEBUG("grt_tasklet_tx : TX hardware is busy.\n"); 
			break;
		}
/*Get the frame, delete it from txq and insert it to tx_waiting_q*/
		spin_lock(&gh->txq_lock);
		bf = list_first_entry(&gh->txq, struct grt_buf, list);
		grt_debug_print_skb("grt_tasklet_tx : sending frame", bf->skb);
		GRT_PRINT_DEBUG("grt_tasklet_tx : sending with rate = 0x%x\n", bf->rates[0]);
		list_del(&bf->list);
		spin_unlock(&gh->txq_lock);
/*prepare control registers and send it to HW*/
/*TODO: Due to hardware issues, here we fix the all 5 retry registers to bf->rates[0], but not the rates from OS.*/
		for(i = 0; /*i < IEEE80211_TX_MAX_RATES &&*/ i < 5; i++){
			/*prepare grt_reg_tx_ctrl*/
			grt_reg_tx_ctrl = 0;
			grt_reg_tx_ctrl |= (((bf->skb->len) << 16) & 0x0FFF0000);/*len, CRC not included*/
			/* TODO: We have to fix all re-transfer's rate to the same due to 
			         hardware limitations*/
			grt_reg_tx_ctrl |= ((bf->rates[0] << 12) & 0x0000F000);/*rate*/
			if(i != 0) /*set retry bit*/
				grt_reg_tx_ctrl |= 0x0800;
			if(bf->needs_ack)
				grt_reg_tx_ctrl |= 0x0400; /*needs ack*/
			else
				grt_reg_tx_ctrl |= 0x0000; /*don't need ack*/
			/*Random a backoff time*/
			get_random_bytes((char *)&backoff_time, 4); /*random function by kernel*/
			backoff_time = ((backoff_time < 0) ? (-1) * backoff_time : backoff_time);
			backoff_time %= (bf->ccw + 1);
			grt_reg_tx_ctrl = (backoff_time & 0x03FF) | (grt_reg_tx_ctrl & 0xFFFFFC00);
			/*compute the complex count of the frame*/
			phy_framebody_bit_len = (bf->skb->len + 4) * 8 + 22; /*CRC's 4 bytes should be included*/
			n_dbps =  gh->dbps_table[bf->rates[0]];
			if(phy_framebody_bit_len % n_dbps)
				complex_count = 80 * (1 + 5 + (phy_framebody_bit_len - (phy_framebody_bit_len % n_dbps)) / n_dbps);
			else
				complex_count = 80 * (5 + phy_framebody_bit_len / n_dbps);
			complex_count += 80;
			grt_pio_write(gh, REG_PDU_COMPLEX_COUNT, complex_count);
			grt_pio_write(gh, PDU_REQUEST_REGS[i], grt_reg_tx_ctrl);
		}
		spin_lock(&gh->tx_waiting_q_lock);
		list_add_tail(&bf->list, &gh->tx_waiting_q);
		spin_unlock(&gh->tx_waiting_q_lock);
		/* TODO: This retry count is shared by the last four retries by hardware.
				 We fix it to bf->tries[0] currently */
		// grt_pio_write(gh, REG_PDU_RETRY_COUNT, bf->tries[0]);
		grt_pio_write(gh, REG_PDU_RETRY_COUNT, 7);
		/*confirm and submit tx*/
		grt_pio_write(gh, REG_PDU_REQ_VALID, 0x01);
		do{
			status = grt_pio_read(gh, REG_PDU_REQ_CLR);
		}while(status == 0);
		grt_pio_write(gh, REG_PDU_REQ_VALID, 0x00);
		grt_dma_skb_to_device(gh, bf);
		GRT_PRINT_DEBUG("grt_tasklet_tx : send frame PDU_REQUEST = 0x%x, PDU_COMPLEX_COUNT = 0x%x\n", grt_reg_tx_ctrl, complex_count);
	}
	GRT_PRINT_DEBUG("grt_tasklet_tx : exit.\n");
	// spin_unlock(&gh->tx_lock);
}

/**
 * grt_tasklet_rx() - software interrupt call back for rx
 * @data: pointer to private data of this driver
 */
void grt_tasklet_rx(unsigned long data)
{
	struct grt_hw * gh = (void *)data;
	struct grt_buf * bf;
	struct ieee80211_rx_status *rxs;
	int skb_size;
	u32 status;
	GRT_PRINT_DEBUG("grt_tasklet_rx : called\n");
	spin_lock(&gh->rx_lock);
	status = grt_pio_read(gh, REG_RX_INDICATE);
	grt_pio_write(gh, REG_RX_INDICATE_SERVED, 0x01);
	if(status){
		bf = gh->rxbuf;
/*Alloc a new sk_buff*/
		skb_size = roundup(IEEE80211_MAX_FRAME_LEN, grt_pci_read_cachesize(gh));
		bf->skb = dev_alloc_skb(skb_size);
		if(bf->skb == NULL){
			printk("GRT: grt_tasklet_rx alloc sk_buff error.\n");
			goto err;
		}
		bf->skb->len = (status & 0x0FFF);
/*DMA data from device*/ 
		if(unlikely(grt_dma_skb_from_device(gh, bf))){
			printk("GRT: grt_tasklet_rx dma error.\n");
			dev_kfree_skb_any(bf->skb);
			goto err;
		}
/*currently the PHY's frame length includes CRC. We have to DMA the frame with CRC. But the CRC shouldn't be submitted to upper layer*/
		bf->skb->len -= 4;
		grt_debug_print_skb("grt_tasklet_rx : recv skb", bf->skb);
/*Fill the status field of the skb, these fields are not supported by HW currently*/
		rxs = IEEE80211_SKB_RXCB(bf->skb);
		rxs->freq = gh->hw->wiphy->bands[IEEE80211_BAND_5GHZ]->channels[0].center_freq;
		rxs->band = gh->hw->wiphy->bands[IEEE80211_BAND_5GHZ]->channels[0].band;
		rxs->signal = -30; /*Signal strength in dbm*/
		rxs->antenna = 0; /*Antenna*/
		rxs->rate_idx = 0; /*xxx : currently hardware not supported*/
		rxs->flag = 0; /*xxx : currently hardware hasn't give me this info*/
/*Submit the received frame to mac80211*/
		ieee80211_rx(gh->hw, bf->skb);
/*update driver statistics*/
		gh->stats.rx_all_count++;
		gh->stats.rx_bytes_count += bf->skb->len;
		gh->stats.rxerr_crc += 0;/*xxx : currently hardware hasn't give me the crc wrong info*/
	}
err:
	spin_unlock(&gh->rx_lock);
}

/**
 * grt_tasklet_bc() - tasklet to generate beacon
 */
void grt_tasklet_bc(unsigned long data)
{
	struct grt_hw * gh = (void *)data;
	struct grt_buf * bf = NULL;
	struct sk_buff * skb;
	int slot;
	static unsigned int beacon_seq = 0;
	struct timeval cur_time_struct;
	u64 cur_time;
	int i;
	GRT_PRINT_DEBUG(">>grt_tasklet_bc : called.\n");
	spin_lock(&gh->bc_lock);
	slot = grt_pio_read(gh, REG_BSLOT_TIMEOUT_INDI);
	if(gh->bslot[slot] == NULL)
		goto out;
/*generate beacon*/
	skb = ieee80211_beacon_get(gh->hw, gh->bslot[slot]);
	if(skb == NULL){
		printk("GRT: grt_beacon_gen generate beacon error.\n"); 
		goto out;
	}
	else{
		GRT_PRINT_DEBUG("grt_tasklet_bc : generate beacon done.\n");
	}
/*modify seq and timestamp in beacon*/
	/*seq*/
	skb->data[22] = ((beacon_seq << 4) & 0x0FF);
	skb->data[23] = ((beacon_seq >> 4) & 0x0FF);
	beacon_seq++;
	/*timestamp*/
	do_gettimeofday(&cur_time_struct);
	cur_time = cur_time_struct.tv_sec * 1000000 + cur_time_struct.tv_usec; 
	for(i = 0; i < 8; i++)
		skb->data[24+i] = ((cur_time >> (i*8)) & 0x0FF);
	/*TODO: currently fix to channel in 2.457GHz*/
	i = 36;
	while((skb->data[i] & 0x0FF) != 0x03){
		i++;
		i+= skb->data[i];
		i++;
	}
	i += 2; // find channel byte
	skb->data[i] = 0x0a;
/*get a new grt_buf for beacon*/
	spin_lock(&gh->txbuf_lock);
	if(list_empty(&gh->txbuf)){
		printk("GRT: grt_beacon_gen can't find grt_buf for beacon, drop this beacon.\n");
		spin_unlock(&gh->txbuf_lock);
		dev_kfree_skb_any(skb);
		goto out;
	}
	bf = list_first_entry(&gh->txbuf, struct grt_buf, list);
	list_del(&bf->list);
	spin_unlock(&gh->txbuf_lock);

	if(skb != NULL){
		grt_debug_print_skb("grt_tasklet_bc : generated beacon", skb);
	}

/*prepare the beacon*/
	bf->skb = skb;
	bf->ccw = MAC_aCWmin;
	bf->grt_desc_count = 1;
	bf->rates[0] = GRT_RATE_CODE_6M;
	bf->tries[0] = 1;
	bf->rates[1] = GRT_RATE_CODE_NUL; /*set it to invalid*/
	bf->tries[1] = 0;
	bf->needs_ack = 0;
/*add bf to txq*/
	spin_lock(&gh->txq_lock);
	list_add_tail(&bf->list, &gh->txq);
	spin_unlock(&gh->txq_lock);
/*schedule grt_tasklet_tx*/
	tasklet_schedule(&gh->tx_tasklet);

out:
/*Set served bit for HW, then unlock*/
	grt_pio_write(gh, REG_BSLOT_TIMEOUT_SERVE, 0x01);
	spin_unlock(&gh->bc_lock);
}

/**
 * grt_intr() - interrupt handler of grt driver
 * @irq: IRQ number of the interrupt
 * @dev_id: Device ID
 * @return: Return IRQ_HANDLED when success, otherwise return IRQ_NONE
 * This function handles TX and RX interrupts
 */
irqreturn_t grt_intr(int irq, void *dev_id)
{
	struct grt_hw *gh = dev_id;
	u32 status;
	status = grt_pio_read(gh, REG_HW_STATE);
	GRT_PRINT_DEBUG("grt_intr : intr occurred with status = 0x%x.\n", status);
/*This interrupt is not for us*/
	if((status & 0x4000) == 0)
		return IRQ_NONE;
/*We need to deal with this interrupt*/
	status = (status >> 23) & 0x07;
/*TX interrupt*/
	if(status == 0)
		tasklet_schedule(&gh->tx_tasklet_int);    
/*RX interrupt*/
	if(status == 1)
		tasklet_schedule(&gh->rx_tasklet);
/*Beacon interrupt*/
	if(status == 2)
		tasklet_schedule(&gh->bc_tasklet);
	GRT_PRINT_DEBUG("grt_intr : intr is for us (status = %d). tasklet has been actived.\n", status);
/*Clear interrupt*/
	grt_pio_write(gh, REG_INT_CTRL, 0x039);
/*Assert USER_SW_WAITING_INT*/
	grt_pio_write(gh, REG_USR_INT_CTRL, 0x08 | (status & 0x07));
	return IRQ_HANDLED;
}

/**
 * grt_intr_init() - initialize interrupt
 * @gh: The private data of the driver
 * @return: return 0 when success, otherwise return -1
 * Initialize interrupt, including register the IRQ and software interrupt (tasklet)
 */
int grt_intr_init(struct grt_hw * gh)
{
	int ret;
/*Request IRQ*/
	ret = request_irq(gh->irq, &grt_intr, IRQF_SHARED, GRT_MODNAME, gh);
	if(ret){
		printk("GRT: error requesting irq.\n");
		goto err;
	}
/*Request software interrupt*/
	spin_lock_init(&gh->tx_lock);
	spin_lock_init(&gh->rx_lock);
	spin_lock_init(&gh->bc_lock);
	tasklet_init(&gh->tx_tasklet_int, grt_tasklet_tx_int, (unsigned long)gh);
	tasklet_init(&gh->tx_tasklet, grt_tasklet_tx, (unsigned long)gh);
	tasklet_init(&gh->rx_tasklet, grt_tasklet_rx, (unsigned long)gh);
	tasklet_init(&gh->bc_tasklet, grt_tasklet_bc, (unsigned long)gh);
/*Set hardware registers*/
	grt_pio_write(gh, REG_INT_CTRL, 0x0030); /*disable interrupt, enable later when grt_start*/
err:
	return ret;
}

/**
 * grt_intr_exit() - interrupt finalize
 * @gh: The private data of the driver
 * Finalize the interrupt
 */
void grt_intr_exit(struct grt_hw * gh)
{
	free_irq(gh->irq, gh);
}


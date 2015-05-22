#ifndef __GRT_H_
#define __GRT_H_

#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <net/mac80211.h>

#define GRT_MODNAME "grt"

/**
 * Register defination and location
 */
/****PCIe Registers****/
#define REG_SYSTEM_INFO                0x0000
#define REG_SYSTEM_RESET               0x0004
#define REG_DMA_R_DESCRIPTOR_ADDR_L    0x0008
#define REG_DMA_R_DESCRIPTOR_ADDR_H    0x000C
#define REG_DMA_W_DESCRIPTOR_ADDR_L    0x0010
#define REG_DMA_W_DESCRIPTOR_ADDR_H    0x0014
#define REG_DMA_R_CTRL                 0x0018
#define REG_DMA_W_CTRL                 0x001C
#define REG_HW_STATE                   0x0020
#define REG_INT_CTRL                   0x0024
#define REG_USR_INT_CTRL               0x0028
#define REG_HOST2BOARD_DATA_COUNT      0x002C
#define REG_BOARD2HOST_DATA_COUNT      0x0030
#define REG_DMA_R_TIMEOUT_THRESHOLD_L  0x0034
#define REG_DMA_R_TIMEOUT_THRESHOLD_H  0x0038
#define REG_DMA_W_TIMEOUT_THRESHOLD_L  0x003C
#define REG_DMA_W_TIMEOUT_THRESHOLD_H  0x0040

/****MAC Registers****/
#define MAC_REG_BASE   (1024 * 1024 / 2)
/*Configuration*/
#define REG_CCA_THRESHOLD  (MAC_REG_BASE + 0x001C)
#define REG_MAC_ADDR_L (MAC_REG_BASE + 0x0020)
#define REG_MAC_ADDR_H (MAC_REG_BASE + 0x0024)
#define REG_ACK_TIMEOUT (MAC_REG_BASE + 0x002C)
#define REG_SLOTTIME (MAC_REG_BASE + 0x030)
#define REG_DIFSTIME (MAC_REG_BASE + 0x034)
#define REG_SIFSTIME (MAC_REG_BASE + 0x038)
#define REG_MAC_FILTER_FLAG (MAC_REG_BASE + 0x03c)
/*UHD configuration*/
#define REG_UHD_PROPERTY (MAC_REG_BASE + 0x0080)
/*TX registers*/
#define REG_PDU_RAM_STATUS (MAC_REG_BASE + 0x0050)
#define REG_PDU_REQUEST1 (MAC_REG_BASE + 0x0054)
#define REG_PDU_REQUEST2 (MAC_REG_BASE + 0x0058)
#define REG_PDU_REQUEST3 (MAC_REG_BASE + 0x005C)
#define REG_PDU_REQUEST4 (MAC_REG_BASE + 0x0060)
#define REG_PDU_REQUEST5 (MAC_REG_BASE + 0x0064)
#define REG_PDU_COMPLEX_COUNT (MAC_REG_BASE + 0x0028)
#define REG_PDU_RETRY_COUNT (MAC_REG_BASE + 0x0000)
#define REG_PDU_REQ_VALID (MAC_REG_BASE + 0x0004)
#define REG_PDU_REQ_CLR (MAC_REG_BASE + 0x0008)
#define REG_PDU_RESPONSE (MAC_REG_BASE + 0x000C)
#define REG_PDU_RESPONSE_SERVED (MAC_REG_BASE + 0x0010)
/*RX registers*/
#define REG_RX_INDICATE (MAC_REG_BASE + 0x0014)
#define REG_RX_INDICATE_SERVED (MAC_REG_BASE + 0x0018)
/*Beacon Slot*/
#define REG_BSLOT_TIMEOUT_INDI (MAC_REG_BASE + 0x0800)
#define REG_BSLOT_ACT  (MAC_REG_BASE + 0x0804)
#define REG_BSLOT_TIMEOUT_SERVE (MAC_REG_BASE + 0x0808)
#define REG_BSLOT0_TIMEOUT_THRESHOLD (MAC_REG_BASE + 0x080C)
#define REG_BSLOT1_TIMEOUT_THRESHOLD (MAC_REG_BASE + 0x0810)
#define REG_BSLOT2_TIMEOUT_THRESHOLD (MAC_REG_BASE + 0x0814)
#define REG_BSLOT3_TIMEOUT_THRESHOLD (MAC_REG_BASE + 0x0818)
/*HW UHD sample rate register*/
#define REG_HW_UHD_CONF (MAC_REG_BASE + 0x0080)

/**
 * Rates defination
 */
#define GRT_RATE_CODE_NUL  0x00 /*not a rate*/
/* 802.11 B mode Rates*/
#define GRT_RATE_CODE_1M   0x1B
#define GRT_RATE_CODE_2M   0x1A
#define GRT_RATE_CODE_5_5M 0x19
#define GRT_RATE_CODE_11M  0x18
/* 802.11 A and G mode Rates*/
#define GRT_RATE_CODE_6M  0x0B /*BPSK 1/2*/
#define GRT_RATE_CODE_9M  0x0F /*BPSK 3/4*/
#define GRT_RATE_CODE_12M 0x0A
#define GRT_RATE_CODE_18M 0x0E
#define GRT_RATE_CODE_24M 0x09
#define GRT_RATE_CODE_36M 0x0D
#define GRT_RATE_CODE_48M 0x08
#define GRT_RATE_CODE_54M 0x0C
/* Enable short preambler in 802.11 B mode */
#define GRT_SET_SHORT_PREAMBLE 0x04

/**
 * 802.11 MAC parameters
 */
#define MAC_ADDR0 0x3E
#define MAC_ADDR1 0xFF
#define MAC_ADDR2 0xAC
#define MAC_ADDR3 0xFF
#define MAC_ADDR4 0xAC
#define MAC_ADDR5 0x44
#define MAC_CCA_THRESHOLD 0xFFFF
#define MAC_BEACON_TIMEOUT_THRESHOLD 4000000 /*for 40MHz, 100ms*/
#define MAC_ACK_TIMEOUT 50000 /*for 40MHz, 0.1?ms*/
#define MAC_aCWmin 15
#define MAC_aCWmax 1023
#define SlotTime 900 /*addr 0xc << 2 */
#define DIFSTime 3400 /*addr 0xd << 2*/
#define SIFSTime 0  /*addr 0xe << 2*/
#define MACFliterFlag 0x08F7  /*addr 0xf << 2 */

/* if MAC_TX_FIX_RATE is defined, fix all frame's TX rate to it */
#define MAC_TX_FIX_RATE GRT_RATE_CODE_36M
#define MAC_MAX_RETRY 6

/** UHD properties, I don't know whether the follow lines' description is right as Xiaoguang
 *  didn't tell me about it.
 */
#define UHD_CENTRAL_FREQ_DEFAULT 0X00
#define UHD_TX_GAIN 0x02 /* 0x00: 0dB, 0x01: 20dB, 0x02: 30dB */
#define UHD_RX_GAIN 0x01 /* 0x00: 0dB, 0x01: 20dB, 0x02: 40dB, 0x03: 60dB */
#define UHD_SAMPLE_RATE 0x01 /* 0x00: 12.5M, 0x01: 20M, 0x02: 25M, 0x03: 6.25M, 0x04: 3.125M, 0x05: 1M, 0x06: 500k, 0x07: 300k */ 
#define UHD_PROPERTY ((UHD_CENTRAL_FREQ_DEFAULT << 24)  | ((UHD_TX_GAIN << 16) & 0x00FF0000) \
						| ((UHD_RX_GAIN << 8) & 0x0000FF00) | (UHD_SAMPLE_RATE & 0x0FF))

#define GRT_CHAN_MAX 14
#define GRT_MAX_RATES  32

#define GRT_BCBUF 4 /*beacon buffer number*/

#define TXBUF_SIZE 128 /*how many tx_buf will be used*/

/**
 * DMA mask, 48 bits
 */
#define GRT_DMA_MASK 0x00FFFFFFFFFFFF

/**
 * We don't support 802.11b currently, so for 802.11b frames, BPSK 1/2 will be used instead
 */
static const struct ieee80211_rate grt_rates[] = {
  { .bitrate = 10,
    .hw_value = GRT_RATE_CODE_1M, },
  { .bitrate = 20,
    .hw_value = GRT_RATE_CODE_2M,
    .hw_value_short = GRT_RATE_CODE_2M | GRT_SET_SHORT_PREAMBLE,
    .flags = IEEE80211_RATE_SHORT_PREAMBLE },
  { .bitrate = 55,
    .hw_value = GRT_RATE_CODE_5_5M,
    .hw_value_short = GRT_RATE_CODE_5_5M | GRT_SET_SHORT_PREAMBLE,
    .flags = IEEE80211_RATE_SHORT_PREAMBLE },
  { .bitrate = 110,
    .hw_value = GRT_RATE_CODE_11M,
    .hw_value_short = GRT_RATE_CODE_11M | GRT_SET_SHORT_PREAMBLE,
    .flags = IEEE80211_RATE_SHORT_PREAMBLE },
  { .bitrate = 60,
    .hw_value = GRT_RATE_CODE_6M,
    .flags = 0 },
  { .bitrate = 90,
    .hw_value = GRT_RATE_CODE_9M,
    .flags = 0 },
  { .bitrate = 120,
    .hw_value = GRT_RATE_CODE_12M,
    .flags = 0 },
  { .bitrate = 180,
    .hw_value = GRT_RATE_CODE_18M,
    .flags = 0 },
  { .bitrate = 240,
    .hw_value = GRT_RATE_CODE_24M,
    .flags = 0 },
  { .bitrate = 360,
    .hw_value = GRT_RATE_CODE_36M,
    .flags = 0 },
  { .bitrate = 480,
    .hw_value = GRT_RATE_CODE_48M,
    .flags = 0 },
  { .bitrate = 540,
    .hw_value = GRT_RATE_CODE_54M,
    .flags = 0 },
};

/**
 * struct grt_buf - Buffer for sending and receiving frames. It can be used to make queues.
 * @list: This struct is used for making bi-direction linked list
 * @grt_descs: The DMA descriptors of the frame data in ``skb''. It can hold two descriptors. 
 *             This array should be 4 bytes aligned.
 * @grt_desc_count: Number of desctiptors in grt_descs, data in skb will not be lager than
 *             8192 byte, so two desctiptors is enough.
 * @daddr: DMA address of descriptor's start address
 * @skb: Socket buffer of the frame
 * @skbaddr: DMA address of the frame (not the DMA address of the whole skb)
 * @ccw: CCA random time window, it should between MAC_aCWmin and MAC_aCWmax
 * @rates: TX rates (if Macro MAC_TX_FIX_RATE is defined, fix the rates to it. Otherwise get
 *              TX rate from mac80211). Values of it is defined by GRT_RATE_CODE_6M .etc.
 * @tries: How many times to try each rate.
 * @needs_ack: If this frame requires ack.
 * ccw, rates, needs_ack, next_sending_rate_index , and cur_rate_retried_count are not used 
 * in rx process
 */
struct grt_buf {
  struct list_head list;
  char * grt_descs;
  int grt_desc_count;
  dma_addr_t daddr;
  struct sk_buff * skb;
  dma_addr_t skbaddr;
  int ccw;
  u8  rates[IEEE80211_TX_MAX_RATES];
  int tries[IEEE80211_TX_MAX_RATES];
  int needs_ack;
};

/**
 * struct grt_statistics - The struct for driver status
 * @tx_all_count: How many frames have been sent (including success & fail frames)
 * @tx_bytes_count: How many bytes have been sent (including success & fail frames)
 * @ack_fail: How many times we do not received ACK, same as send fail in current implementation
 * @rx_all_count: How many frames have been received by RX in total
 * @rx_bytes_count: How many bytes have been received by RX in total
 * @rxerr_crc: How many frames have been received with CRC error. It is enabled only when 
 *               filter FIF_FCSFAIL is on.
 */
struct grt_statistics{
  /*TX Statistics*/
  unsigned int tx_all_count;
  unsigned int tx_bytes_count;
  unsigned int ack_fail;
  /*RX Statistics*/
  unsigned int rx_all_count;
  unsigned int rx_bytes_count;
  unsigned int rxerr_crc;
};

/**
 * struct grt_hw - The struct to hold the private data of the device
 * @pdev: PCI device of the hardware in OS
 * @dev: Device of the hardware in OS
 * @irq: Interrupt number
 * @hw: ieee80211_hw
 * @sbands: supported bands of hardware
 * @channels: channels of 802.11a
 * @rates: supported rates of 802.11a
 * @pci_bar_hw_addr: Hardware bar(base address register) address
 * @pci_bar_size: Bar space size
 * @pci_bar_vir_addr: Virtual address of bar space
 * @txq: The queue holding sk_buff (within grt_buf) to be send
 * @txq_lock: The lock of txq, txq should be locked when adding/ deleting items
 * @tx_waiting_q: This queue contains frames that have been sent to hardware and waiting for tx
 *            to be completed.
 * @tx_waiting_q_lock: The lock to tx_waiting_q.
 * @tx_stopped: Set to 1 when tx is stopped. Tx is stopped because there is not enough buffers.
 * @txbuf: It is a list of grt_buf, used as empty entry for tx sk_buffs.
 * @rxbuf: Rx buffer, it is a queue whose size is 1.
 * @tx_tasklet_int: TX interrupt tasklet, which is used to deal with tx interrupt.
 * @tx_tasklet: TX tasklet, which is used for software interrupt in tx process (sending aframe)
 * @tx_lock: Lock used by the function in tx_tasklet. When sending a frame, the hardware can 
 *           only used by one software process
 * @rx_tasklet: RX tasklet, which is used for software interrupt in rx process
 * @rx_lock: Lock used by the function in rx_tasklet. When receiving a frame, the hardware can
 *           only used by one software process
 * @bc_lock: Lock for beacon, should be locked when doing beacon stuff.
 * @bslot: Beacon slot, used to record virtual interface who needs to send beacon.
 * @dma_read_lock: Lock for DMA read operation.
 * @dma_write_lock: Lock for DMA write operation
 */
struct grt_hw{
  /*device infomation*/
  struct pci_dev *pdev;
  struct device *dev;
  int irq;
  struct ieee80211_hw *hw;
  struct ieee80211_supported_band sbands[IEEE80211_NUM_BANDS];
  struct ieee80211_channel channels[GRT_MAX_RATES];
  struct ieee80211_rate rates[IEEE80211_NUM_BANDS][GRT_MAX_RATES];
  /*base address of pci device*/
  unsigned long pci_bar_size;
  void __iomem * pci_bar_vir_addr;
  /*tx and rx queues*/
  struct list_head txq;
  spinlock_t txq_lock;
  struct list_head tx_waiting_q;
  spinlock_t tx_waiting_q_lock;
  struct list_head txbuf;
  spinlock_t txbuf_lock;
  atomic_t tx_stopped;
  struct grt_buf * rxbuf;
  /*tx and rx tasklets*/
  struct tasklet_struct tx_tasklet_int;
  struct tasklet_struct tx_tasklet;
  spinlock_t tx_lock;
  struct tasklet_struct rx_tasklet;
  spinlock_t rx_lock;
  /*beacon*/
  struct tasklet_struct bc_tasklet;
  spinlock_t bc_lock;
  struct ieee80211_vif * bslot[GRT_BCBUF];
  /*dma locks*/
  spinlock_t dma_read_lock;
  spinlock_t dma_write_lock;
  /*dma buffers*/
  char * dma_to_device_buf;
  dma_addr_t dma_to_device_dma;
  char * dma_from_device_buf;
  dma_addr_t dma_from_device_dma;
  /* Use this table to look up for N_dbps */
  unsigned int dbps_table[128];
  /*GRT driver status*/
  struct grt_statistics stats;
};

#endif

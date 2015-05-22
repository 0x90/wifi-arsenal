/*
 * Definitions for RTL8187 hardware
 *
 * Adaped by pr0gg3d from linux-kernel source
 *
 * Original copyrights:
 *
 * Copyright 2007 Michael Wu <flamingice@sourmilk.net>
 * Copyright 2007 Andrea Merello <andreamrl@tiscali.it>
 *
 * Based on the r8187 driver, which is:
 * Copyright 2005 Andrea Merello <andreamrl@tiscali.it>, et al.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/*
 * Little kernel adaption
 *
 */



// all fields are little-endian

#ifndef RTL8187_H
#define RTL8187_H

#import "USBJack.h"
#include "rtl818x.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define RTL8187_EEPROM_TXPWR_BASE	0x05
#define RTL8187_EEPROM_MAC_ADDR		0x07
#define RTL8187_EEPROM_TXPWR_CHAN_1	0x16	/* 3 channels */
#define RTL8187_EEPROM_TXPWR_CHAN_6	0x1B	/* 2 channels */
#define RTL8187_EEPROM_TXPWR_CHAN_4	0x3D	/* 2 channels */

#define RTL8187_REQT_READ	0xC0
#define RTL8187_REQT_WRITE	0x40
#define RTL8187_REQ_GET_REG	0x05
#define RTL8187_REQ_SET_REG	0x05

#define RTL8187_MAX_RX		0x9C4

struct rtl8187_rx_info {
	struct urb *urb;
	struct ieee80211_hw *dev;
};
struct rtl8187_rx_hdr {
	UInt32 flags;
	UInt8 noise;
	UInt8 signal;
	UInt8 agc;
	UInt8 reserved;
	UInt64 mac_time;
} __attribute__((packed));
struct rtl8187_tx_info {
	struct ieee80211_tx_control *control;
	struct urb *urb;
	struct ieee80211_hw *dev;
};
struct rtl8187_tx_hdr {
	UInt32 flags;
#define RTL8187_TX_FLAG_NO_ENCRYPT	(1 << 15)
#define RTL8187_TX_FLAG_MORE_FRAG	(1 << 17)
#define RTL8187_TX_FLAG_CTS		(1 << 18)
#define RTL8187_TX_FLAG_RTS		(1 << 23)
	UInt16 rts_duration;
	UInt16 len;
	UInt32 retry;
} __attribute__((packed));

struct ieee80211_channel {
	short chan; /* channel number (IEEE 802.11) */
	short freq; /* frequency in MHz */
	int val; /* hw specific value for the channel */
	int flag; /* flag for hostapd use (IEEE80211_CHAN_*) */
	unsigned char power_level;
	unsigned char antenna_max;
};

struct rtl8187_priv {
	/* common between rtl818x drivers */
	struct rtl818x_csr *map;
	void (*rf_init)(struct rtl8187_priv *);
	int mode;
	int if_id;
    
	/* rtl8187 specific */
	struct ieee80211_channel channels[14];
//	struct ieee80211_rate rates[12];
//	struct ieee80211_hw_mode modes[2];
    IOUSBInterfaceInterface220**   _interface;
	UInt32 rx_conf;
	UInt16 txpwr_base;
	UInt8 asic_rev;
//	struct sk_buff_head rx_queue;
};

static const struct ieee80211_channel rtl818x_channels[] = {
	{ 1, 2412, 0, 0, 0, 0},
	{ 2, 2417, 0, 0, 0, 0},
	{ 3, 2422, 0, 0, 0, 0},
	{ 4, 2427, 0, 0, 0, 0},
	{ 5, 2432, 0, 0, 0, 0},
	{ 6, 2437, 0, 0, 0, 0},
	{ 7, 2442, 0, 0, 0, 0},
	{ 8, 2447, 0, 0, 0, 0},
	{ 9, 2452, 0, 0, 0, 0},
	{ 10, 2457, 0, 0, 0, 0},
	{ 11, 2462, 0, 0, 0, 0},
	{ 12, 2467, 0, 0, 0, 0},
	{ 13, 2472, 0, 0, 0, 0},
	{ 14, 2484, 0, 0, 0, 0}
};

class RTL8187Jack: public USBJack {
public:
    
    RTL8187Jack();
    ~RTL8187Jack();
    char *getPlistFile();
    IOReturn _init();
    bool setChannel(UInt16 channel);
    bool startCapture(UInt16 channel);    
    bool getAllowedChannels(UInt16* channels);
    bool _massagePacket(void *inBuf, void *outBuf, UInt16 len);
    bool stopCapture();
    
    int         WriteTxDescriptor(void* theFrame, UInt16 length, UInt8 rate);
    bool        sendKFrame(KFrame* frame);
    IOReturn    _sendFrame(UInt8* data, IOByteCount size);
    void dumpFrame(UInt8 *data, UInt16 size);
    
private:
    struct rtl8187_priv *_priv;
    
    int rtl8187_probe(void);
    bool	NICInitialized;        
};


#endif /* RTL8187_H */

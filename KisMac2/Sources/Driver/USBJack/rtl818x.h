/*
 * Definitions for RTL818x hardware
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

#ifndef RTL818X_H
#define RTL818X_H

#define RTL8225_ANAPARAM_ON     0xa0000a59
#define RTL8225_ANAPARAM2_ON	0x860c7312
#define RTL8225_ANAPARAM_OFF	0xa00beb59
#define RTL8225_ANAPARAM2_OFF	0x840dec11

// pr0gg3d: All fields are in little endian
#define RTL818X_ADDR_RX_CONF        0xff44
#define RTL818X_ADDR_EEPROM_CMD     0xff50
#define RTL818X_ADDR_PGSELECT       0xff5e
#define RTL818X_ADDR_RFPinsOutput   0xff80
#define RTL818X_ADDR_RFPinsEnable   0xff82
#define RTL818X_ADDR_RFPinsSelect   0xff84
#define RTL818X_ADDR_RFPinsInput    0xff86
#define RTL818X_ADDR_TESTR          0xff5b
#define RTL818X_ADDR_TX_ANTENNA     0xff9f
#define RTL818X_ADDR_PHY3           0xff7f
#define RTL818X_ADDR_PHY2           0xff7e
#define RTL818X_ADDR_PHY1           0xff7d
#define RTL818X_ADDR_PHY0           0xff7c
#define RTL818X_ADDR_TX_GAIN_CCK    0xff9d
#define RTL818X_ADDR_CONFIG3        0xff59
#define RTL818X_ADDR_ANAPARAM2      0xff60
#define RTL818X_ADDR_TX_GAIN_OFDM   0xff9e

#define RTL818X_ADDR_ANAPARAM       0xff54
#define RTL818X_ADDR_INT_MASK       0xff3c
#define RTL818X_ADDR_CMD            0xff37
#define RTL818X_ADDR_GPIO           0xff91
#define RTL818X_ADDR_GP_ENABLE      0xff90
#define RTL818X_ADDR_CONFIG1        0xff52
#define RTL818X_ADDR_INT_TIMEOUT    0xff48
#define RTL818X_ADDR_WPA_CONF       0xffb0
#define RTL818X_ADDR_RATE_FALLBACK  0xffbe
#define RTL818X_ADDR_RESP_RATE      0xff34
#define RTL818X_ADDR_BRSR           0xff2c
#define RTL818X_ADDR_RF_TIMING      0xff8c
#define RTL818X_ADDR_RF_PARA        0xff88
#define RTL818X_ADDR_TALLY_SEL      0xfffc
#define RTL818X_ADDR_INT_MASK       0xff3c
#define RTL818X_ADDR_MAR0           0xff08
#define RTL818X_ADDR_MAR1           0xff0c
#define RTL818X_ADDR_CW_CONF        0xffbc
#define RTL818X_ADDR_TX_AGC_CTL     0xff9c
#define RTL818X_ADDR_TX_CONF        0xff40
#define RTL818X_ADDR_CMD            0xff37
#define RTL818X_ADDR_CONFIG4        0xff5a

struct rtl818x_csr {
	UInt8	MAC[6];
	UInt8	reserved_0[2];
	UInt32	MAR[2];
	UInt8	RX_FIFO_COUNT;
	UInt8	reserved_1;
	UInt8	TX_FIFO_COUNT;
	UInt8	BQREQ;
	UInt8	reserved_2[4];
	UInt32	TSFT[2];
	UInt32	TLPDA;
	UInt32	TNPDA;
	UInt32	THPDA;
	UInt16	BRSR;
	UInt8	BSSID[6];
	UInt8	RESP_RATE;
	UInt8	EIFS;
	UInt8	reserved_3[1];
	UInt8	CMD;
#define RTL818X_CMD_TX_ENABLE		(1 << 2)
#define RTL818X_CMD_RX_ENABLE		(1 << 3)
#define RTL818X_CMD_RESET		(1 << 4)
	UInt8	reserved_4[4];
	UInt16	INT_MASK;
	UInt16	INT_STATUS;
#define RTL818X_INT_RX_OK		(1 <<  0)
#define RTL818X_INT_RX_ERR		(1 <<  1)
#define RTL818X_INT_TXL_OK		(1 <<  2)
#define RTL818X_INT_TXL_ERR		(1 <<  3)
#define RTL818X_INT_RX_DU		(1 <<  4)
#define RTL818X_INT_RX_FO		(1 <<  5)
#define RTL818X_INT_TXN_OK		(1 <<  6)
#define RTL818X_INT_TXN_ERR		(1 <<  7)
#define RTL818X_INT_TXH_OK		(1 <<  8)
#define RTL818X_INT_TXH_ERR		(1 <<  9)
#define RTL818X_INT_TXB_OK		(1 << 10)
#define RTL818X_INT_TXB_ERR		(1 << 11)
#define RTL818X_INT_ATIM		(1 << 12)
#define RTL818X_INT_BEACON		(1 << 13)
#define RTL818X_INT_TIME_OUT		(1 << 14)
#define RTL818X_INT_TX_FO		(1 << 15)
	UInt32	TX_CONF;
#define RTL818X_TX_CONF_LOOPBACK_MAC	(1 << 17)
#define RTL818X_TX_CONF_NO_ICV		(1 << 19)
#define RTL818X_TX_CONF_DISCW		(1 << 20)
#define RTL818X_TX_CONF_R8180_ABCD	(2 << 25)
#define RTL818X_TX_CONF_R8180_F		(3 << 25)
#define RTL818X_TX_CONF_R8185_ABC	(4 << 25)
#define RTL818X_TX_CONF_R8185_D		(5 << 25)
#define RTL818X_TX_CONF_HWVER_MASK	(7 << 25)
#define RTL818X_TX_CONF_CW_MIN		(1 << 31)
	UInt32	RX_CONF;
#define RTL818X_RX_CONF_MONITOR		(1 <<  0)
#define RTL818X_RX_CONF_NICMAC		(1 <<  1)
#define RTL818X_RX_CONF_MULTICAST	(1 <<  2)
#define RTL818X_RX_CONF_BROADCAST	(1 <<  3)
#define RTL818X_RX_CONF_FCS		(1 <<  5)
#define RTL818X_RX_CONF_DATA		(1 << 18)
#define RTL818X_RX_CONF_CTRL		(1 << 19)
#define RTL818X_RX_CONF_MGMT		(1 << 20)
#define RTL818X_RX_CONF_BSSID		(1 << 23)
#define RTL818X_RX_CONF_RX_AUTORESETPHY	(1 << 28)
#define RTL818X_RX_CONF_ONLYERLPKT	(1 << 31)
	UInt32	INT_TIMEOUT;
	UInt32	TBDA;
	UInt8	EEPROM_CMD;
#define RTL818X_EEPROM_CMD_READ		(1 << 0)
#define RTL818X_EEPROM_CMD_WRITE	(1 << 1)
#define RTL818X_EEPROM_CMD_CK		(1 << 2)
#define RTL818X_EEPROM_CMD_CS		(1 << 3)
#define RTL818X_EEPROM_CMD_NORMAL	(0 << 6)
#define RTL818X_EEPROM_CMD_LOAD		(1 << 6)
#define RTL818X_EEPROM_CMD_PROGRAM	(2 << 6)
#define RTL818X_EEPROM_CMD_CONFIG	(3 << 6)
	UInt8	CONFIG0;
	UInt8	CONFIG1;
	UInt8	CONFIG2;
	UInt32	ANAPARAM;
	UInt8	MSR;
#define RTL818X_MSR_NO_LINK		(0 << 2)
#define RTL818X_MSR_ADHOC		(1 << 2)
#define RTL818X_MSR_INFRA		(2 << 2)
	UInt8	CONFIG3;
#define RTL818X_CONFIG3_ANAPARAM_WRITE	(1 << 6)
	UInt8	CONFIG4;
#define RTL818X_CONFIG4_POWEROFF	(1 << 6)
#define RTL818X_CONFIG4_VCOOFF		(1 << 7)
	UInt8	TESTR;
	UInt8	reserved_9[2];
	UInt8	PGSELECT;
	UInt32	ANAPARAM2;
	UInt8	reserved_10[12];
	UInt16	BEACON_INTERVAL;
	UInt16	ATIM_WND;
	UInt16	BEACON_INTERVAL_TIME;
	UInt16	ATIMTR_INTERVAL;
	UInt8	reserved_11[4];
	UInt8	PHY[4];
	UInt16	RFPinsOutput;
	UInt16	RFPinsEnable;
	UInt16	RFPinsSelect;
	UInt16	RFPinsInput;
	UInt32	RF_PARA;
	UInt32	RF_TIMING;
	UInt8	GP_ENABLE;
	UInt8	GPIO;
	UInt8	reserved_12[10];
	UInt8	TX_AGC_CTL;
#define RTL818X_TX_AGC_CTL_PERPACKET_GAIN_SHIFT		(1 << 0)
#define RTL818X_TX_AGC_CTL_PERPACKET_ANTSEL_SHIFT	(1 << 1)
#define RTL818X_TX_AGC_CTL_FEEDBACK_ANT			(1 << 2)
	UInt8	TX_GAIN_CCK;
	UInt8	TX_GAIN_OFDM;
	UInt8	TX_ANTENNA;
	UInt8	reserved_13[16];
	UInt8	WPA_CONF;
	UInt8	reserved_14[3];
	UInt8	SIFS;
	UInt8	DIFS;
	UInt8	SLOT;
	UInt8	reserved_15[5];
	UInt8	CW_CONF;
#define RTL818X_CW_CONF_PERPACKET_CW_SHIFT	(1 << 0)
#define RTL818X_CW_CONF_PERPACKET_RETRY_SHIFT	(1 << 1)
	UInt8	CW_VAL;
	UInt8	RATE_FALLBACK;
	UInt8	reserved_16[25];
	UInt8	CONFIG5;
	UInt8	TX_DMA_POLLING;
	UInt8	reserved_17[2];
	UInt16	CWR;
	UInt8	RETRY_CTR;
	UInt8	reserved_18[5];
	UInt32	RDSAR;
	UInt8	reserved_19[18];
	UInt16	TALLY_CNT;
	UInt8	TALLY_SEL;
} __attribute__((packed));

#endif /* RTL818X_H */

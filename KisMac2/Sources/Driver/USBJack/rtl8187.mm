/*
 *  rtl8187.mm
 *  KisMAC
 *
 *  Created by pr0gg3d on 02/24/08.
 *
 */

#include "rtl8187.h"
#include "eeprom_93cx6.h"

/*
 Copyright (C) 2004 - 2006 rt2x00 SourceForge Project
 <http://rt2x00.serialmonkey.com>
 
 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the
 Free Software Foundation, Inc.,
 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/*
 Module: eeprom_93cx6
 Abstract: EEPROM reader routines for 93cx6 chipsets.
 Supported chipsets: 93c46 & 93c66.
 */

#include "eeprom_93cx6.h"

static const UInt16 rtl8225bcd_rxgain[] = {
	0x0400, 0x0401, 0x0402, 0x0403, 0x0404, 0x0405, 0x0408, 0x0409,
	0x040a, 0x040b, 0x0502, 0x0503, 0x0504, 0x0505, 0x0540, 0x0541,
	0x0542, 0x0543, 0x0544, 0x0545, 0x0580, 0x0581, 0x0582, 0x0583,
	0x0584, 0x0585, 0x0588, 0x0589, 0x058a, 0x058b, 0x0643, 0x0644,
	0x0645, 0x0680, 0x0681, 0x0682, 0x0683, 0x0684, 0x0685, 0x0688,
	0x0689, 0x068a, 0x068b, 0x068c, 0x0742, 0x0743, 0x0744, 0x0745,
	0x0780, 0x0781, 0x0782, 0x0783, 0x0784, 0x0785, 0x0788, 0x0789,
	0x078a, 0x078b, 0x078c, 0x078d, 0x0790, 0x0791, 0x0792, 0x0793,
	0x0794, 0x0795, 0x0798, 0x0799, 0x079a, 0x079b, 0x079c, 0x079d,
	0x07a0, 0x07a1, 0x07a2, 0x07a3, 0x07a4, 0x07a5, 0x07a8, 0x07a9,
	0x07aa, 0x07ab, 0x07ac, 0x07ad, 0x07b0, 0x07b1, 0x07b2, 0x07b3,
	0x07b4, 0x07b5, 0x07b8, 0x07b9, 0x07ba, 0x07bb, 0x07bb
};
static const UInt8 rtl8225_agc[] = {
	0x9e, 0x9e, 0x9e, 0x9e, 0x9e, 0x9e, 0x9e, 0x9e,
	0x9d, 0x9c, 0x9b, 0x9a, 0x99, 0x98, 0x97, 0x96,
	0x95, 0x94, 0x93, 0x92, 0x91, 0x90, 0x8f, 0x8e,
	0x8d, 0x8c, 0x8b, 0x8a, 0x89, 0x88, 0x87, 0x86,
	0x85, 0x84, 0x83, 0x82, 0x81, 0x80, 0x3f, 0x3e,
	0x3d, 0x3c, 0x3b, 0x3a, 0x39, 0x38, 0x37, 0x36,
	0x35, 0x34, 0x33, 0x32, 0x31, 0x30, 0x2f, 0x2e,
	0x2d, 0x2c, 0x2b, 0x2a, 0x29, 0x28, 0x27, 0x26,
	0x25, 0x24, 0x23, 0x22, 0x21, 0x20, 0x1f, 0x1e,
	0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18, 0x17, 0x16,
	0x15, 0x14, 0x13, 0x12, 0x11, 0x10, 0x0f, 0x0e,
	0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06,
	0x05, 0x04, 0x03, 0x02, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
};
static const UInt8 rtl8225_gain[] = {
	0x23, 0x88, 0x7c, 0xa5,	/* -82dBm */
	0x23, 0x88, 0x7c, 0xb5,	/* -82dBm */
	0x23, 0x88, 0x7c, 0xc5,	/* -82dBm */
	0x33, 0x80, 0x79, 0xc5,	/* -78dBm */
	0x43, 0x78, 0x76, 0xc5,	/* -74dBm */
	0x53, 0x60, 0x73, 0xc5,	/* -70dBm */
	0x63, 0x58, 0x70, 0xc5,	/* -66dBm */
};
static const UInt8 rtl8225_threshold[] = {
	0x8d, 0x8d, 0x8d, 0x8d, 0x9d, 0xad, 0xbd
};
static const UInt8 rtl8225_tx_gain_cck_ofdm[] = {
	0x02, 0x06, 0x0e, 0x1e, 0x3e, 0x7e
};
static const UInt8 rtl8225_tx_power_cck[] = {
	0x18, 0x17, 0x15, 0x11, 0x0c, 0x08, 0x04, 0x02,
	0x1b, 0x1a, 0x17, 0x13, 0x0e, 0x09, 0x04, 0x02,
	0x1f, 0x1e, 0x1a, 0x15, 0x10, 0x0a, 0x05, 0x02,
	0x22, 0x21, 0x1d, 0x18, 0x11, 0x0b, 0x06, 0x02,
	0x26, 0x25, 0x21, 0x1b, 0x14, 0x0d, 0x06, 0x03,
	0x2b, 0x2a, 0x25, 0x1e, 0x16, 0x0e, 0x07, 0x03
};
static const UInt8 rtl8225_tx_power_cck_ch14[] = {
	0x18, 0x17, 0x15, 0x0c, 0x00, 0x00, 0x00, 0x00,
	0x1b, 0x1a, 0x17, 0x0e, 0x00, 0x00, 0x00, 0x00,
	0x1f, 0x1e, 0x1a, 0x0f, 0x00, 0x00, 0x00, 0x00,
	0x22, 0x21, 0x1d, 0x11, 0x00, 0x00, 0x00, 0x00,
	0x26, 0x25, 0x21, 0x13, 0x00, 0x00, 0x00, 0x00,
	0x2b, 0x2a, 0x25, 0x15, 0x00, 0x00, 0x00, 0x00
};
static const UInt8 rtl8225_tx_power_ofdm[] = {
	0x80, 0x90, 0xa2, 0xb5, 0xcb, 0xe4
};
static const UInt32 rtl8225_chan[] = {
	0x085c, 0x08dc, 0x095c, 0x09dc, 0x0a5c, 0x0adc, 0x0b5c,
	0x0bdc, 0x0c5c, 0x0cdc, 0x0d5c, 0x0ddc, 0x0e5c, 0x0f72
};

static const UInt8 rtl8225z2_tx_power_cck_ch14[] = {
	0x36, 0x35, 0x2e, 0x1b, 0x00, 0x00, 0x00, 0x00
};
static const UInt8 rtl8225z2_tx_power_cck[] = {
	0x36, 0x35, 0x2e, 0x25, 0x1c, 0x12, 0x09, 0x04
};
/*static const UInt8 rtl8225z2_tx_power_ofdm[] = {
	0x42, 0x00, 0x40, 0x00, 0x40
};*/
static const UInt8 rtl8225z2_tx_gain_cck_ofdm[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
	0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
	0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
	0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23
};
static const UInt16 rtl8225z2_rxgain[] = {
	0x0400, 0x0401, 0x0402, 0x0403, 0x0404, 0x0405, 0x0408, 0x0409,
	0x040a, 0x040b, 0x0502, 0x0503, 0x0504, 0x0505, 0x0540, 0x0541,
	0x0542, 0x0543, 0x0544, 0x0545, 0x0580, 0x0581, 0x0582, 0x0583,
	0x0584, 0x0585, 0x0588, 0x0589, 0x058a, 0x058b, 0x0643, 0x0644,
	0x0645, 0x0680, 0x0681, 0x0682, 0x0683, 0x0684, 0x0685, 0x0688,
	0x0689, 0x068a, 0x068b, 0x068c, 0x0742, 0x0743, 0x0744, 0x0745,
	0x0780, 0x0781, 0x0782, 0x0783, 0x0784, 0x0785, 0x0788, 0x0789,
	0x078a, 0x078b, 0x078c, 0x078d, 0x0790, 0x0791, 0x0792, 0x0793,
	0x0794, 0x0795, 0x0798, 0x0799, 0x079a, 0x079b, 0x079c, 0x079d,
	0x07a0, 0x07a1, 0x07a2, 0x07a3, 0x07a4, 0x07a5, 0x07a8, 0x07a9,
	0x03aa, 0x03ab, 0x03ac, 0x03ad, 0x03b0, 0x03b1, 0x03b2, 0x03b3,
	0x03b4, 0x03b5, 0x03b8, 0x03b9, 0x03ba, 0x03bb, 0x03bb
};
static const UInt8 rtl8225z2_gain_bg[] = {
	0x23, 0x15, 0xa5, /* -82-1dBm */
	0x23, 0x15, 0xb5, /* -82-2dBm */
	0x23, 0x15, 0xc5, /* -82-3dBm */
	0x33, 0x15, 0xc5, /* -78dBm */
	0x43, 0x15, 0xc5, /* -74dBm */
	0x53, 0x15, 0xc5, /* -70dBm */
	0x63, 0x15, 0xc5  /* -66dBm */
};

static void eeprom_93cx6_pulse_high(struct eeprom_93cx6 *eeprom) {
	eeprom->reg_data_clock = 1;
	eeprom->register_write(eeprom);
    
	/*
	 * Add a short delay for the pulse to work.
	 * According to the specifications the "maximum minimum"
	 * time should be 450ns.
	 */
//	ndelay(450);
	usleep(1);
}
static void eeprom_93cx6_pulse_low(struct eeprom_93cx6 *eeprom) {
	eeprom->reg_data_clock = 0;
	eeprom->register_write(eeprom);
    
	/*
	 * Add a short delay for the pulse to work.
	 * According to the specifications the "maximum minimum"
	 * time should be 450ns.
	 */
//	ndelay(450);
    usleep(1);
}
static void eeprom_93cx6_startup(struct eeprom_93cx6 *eeprom) {
	/*
	 * Clear all flags, and enable chip select.
	 */
	eeprom->register_read(eeprom);
	eeprom->reg_data_in = 0;
	eeprom->reg_data_out = 0;
	eeprom->reg_data_clock = 0;
	eeprom->reg_chip_select = 1;
	eeprom->register_write(eeprom);
    
	/*
	 * kick a pulse.
	 */
	eeprom_93cx6_pulse_high(eeprom);
	eeprom_93cx6_pulse_low(eeprom);
}
static void eeprom_93cx6_cleanup(struct eeprom_93cx6 *eeprom) {
	/*
	 * Clear chip_select and data_in flags.
	 */
	eeprom->register_read(eeprom);
	eeprom->reg_data_in = 0;
	eeprom->reg_chip_select = 0;
	eeprom->register_write(eeprom);
    
	/*
	 * kick a pulse.
	 */
	eeprom_93cx6_pulse_high(eeprom);
	eeprom_93cx6_pulse_low(eeprom);
}
static void eeprom_93cx6_write_bits(struct eeprom_93cx6 *eeprom, const UInt16 data, const UInt16 count) {
	unsigned int i;
    
	eeprom->register_read(eeprom);
    
	/*
	 * Clear data flags.
	 */
	eeprom->reg_data_in = 0;
	eeprom->reg_data_out = 0;
    
	/*
	 * Start writing all bits.
	 */
	for (i = count; i > 0; i--) {
		/*
		 * Check if this bit needs to be set.
		 */
		eeprom->reg_data_in = !!(data & (1 << (i - 1)));
        
		/*
		 * Write the bit to the eeprom register.
		 */
		eeprom->register_write(eeprom);
        
		/*
		 * Kick a pulse.
		 */
		eeprom_93cx6_pulse_high(eeprom);
		eeprom_93cx6_pulse_low(eeprom);
	}
    
	eeprom->reg_data_in = 0;
	eeprom->register_write(eeprom);
}
static void eeprom_93cx6_read_bits(struct eeprom_93cx6 *eeprom, UInt16 *data, const UInt16 count) {
	unsigned int i;
	UInt16 buf = 0;
    
	eeprom->register_read(eeprom);
    
	/*
	 * Clear data flags.
	 */
	eeprom->reg_data_in = 0;
	eeprom->reg_data_out = 0;
    
	/*
	 * Start reading all bits.
	 */
	for (i = count; i > 0; i--) {
		eeprom_93cx6_pulse_high(eeprom);
        
		eeprom->register_read(eeprom);
        
		/*
		 * Clear data_in flag.
		 */
		eeprom->reg_data_in = 0;
        
		/*
		 * Read if the bit has been set.
		 */
		if (eeprom->reg_data_out)
			buf |= (1 << (i - 1));
        
		eeprom_93cx6_pulse_low(eeprom);
	}
    
	*data = buf;
}
void eeprom_93cx6_read(struct eeprom_93cx6 *eeprom, const UInt8 word, UInt16 *data) {
	UInt16 command;
    
	/*
	 * Initialize the eeprom register
	 */
	eeprom_93cx6_startup(eeprom);
    
	/*
	 * Select the read opcode and the word to be read.
	 */
	command = (PCI_EEPROM_READ_OPCODE << eeprom->width) | word;
	eeprom_93cx6_write_bits(eeprom, command,
                            PCI_EEPROM_WIDTH_OPCODE + eeprom->width);
    
	/*
	 * Read the requested 16 bits.
	 */
	eeprom_93cx6_read_bits(eeprom, data, 16);
    
	/*
	 * Cleanup eeprom register.
	 */
	eeprom_93cx6_cleanup(eeprom);
}
void eeprom_93cx6_multiread(struct eeprom_93cx6 *eeprom, const UInt8 word, UInt16 *data, const UInt16 words) {
	unsigned int i;
	UInt16 tmp;
    
	for (i = 0; i < words; ++i) {
		tmp = 0;
		eeprom_93cx6_read(eeprom, word + i, &tmp);
//		DBNSLog(@"%s %.4x %.4x", __func__, word+i, CFSwapInt16HostToLittle(tmp));
        data[i] = CFSwapInt16HostToLittle(tmp);
	}
}

/* rtl818x part */

UInt8 rtl818x_ioread8(struct rtl8187_priv *priv, UInt16 addr) {
	UInt8 val;

    IOReturn ret;
    IOUSBDevRequest theRequest;
    theRequest.bmRequestType = USBmakebmRequestType(kUSBIn, kUSBVendor, kUSBDevice);
    theRequest.bRequest = 0x05;
    theRequest.wValue = addr; 
    theRequest.wIndex = 0; 
    theRequest.pData = &val;
    theRequest.wLength = sizeof(val);
    ret = (*(priv->_interface))->ControlRequest(priv->_interface, 0, &theRequest);
    if (ret != kIOReturnSuccess) {
        DBNSLog(@"%s addr %x %x", __func__, addr, ret);
    }
//    DBNSLog(@"<<< 8 addr %x data %x", addr, val);
    return val;
}
UInt16 rtl818x_ioread16(struct rtl8187_priv *priv, UInt16 addr) {
	UInt16 val;
    
    IOReturn ret;
    IOUSBDevRequest theRequest;
    theRequest.bmRequestType = USBmakebmRequestType(kUSBIn, kUSBVendor, kUSBDevice);
    theRequest.bRequest = 0x05;
    theRequest.wValue = addr; 
    theRequest.wIndex = 0; 
    theRequest.pData = &val;
    theRequest.wLength = sizeof(val);
    ret = (*(priv->_interface))->ControlRequest(priv->_interface, 0, &theRequest);
    if (ret != kIOReturnSuccess) {
        DBNSLog(@"%s addr %x %x", __func__, addr, ret);
    }
//    DBNSLog(@"<<< 16 addr %x data %x (%x)", addr, val, CFSwapInt16LittleToHost(val));
	return CFSwapInt16LittleToHost(val);
}
UInt32 rtl818x_ioread32(struct rtl8187_priv *priv, UInt16 addr) {
	UInt32 val = 0;
    
    IOReturn ret = 0;
    IOUSBDevRequest theRequest;
    
    if(priv->_interface != NULL)
    {
        theRequest.bmRequestType = USBmakebmRequestType(kUSBIn, kUSBVendor, kUSBDevice);
        theRequest.bRequest = 0x05;
        theRequest.wValue = addr; 
        theRequest.wIndex = 0; 
        theRequest.pData = &val;
        theRequest.wLength = sizeof(val);
        ret = (*(priv->_interface))->ControlRequest(priv->_interface, 0, &theRequest);
    }
    if (ret != kIOReturnSuccess)
    {
        DBNSLog(@"%s addr %x %x", __func__, addr, ret);
    }
	return CFSwapInt32LittleToHost(val);
}

void rtl818x_iowrite8(struct rtl8187_priv *priv, UInt16 addr, UInt8 val) {
    IOReturn ret;
    IOUSBDevRequest theRequest;
    theRequest.bmRequestType = USBmakebmRequestType(kUSBOut, kUSBVendor, kUSBDevice);
    theRequest.bRequest = 0x05;
    theRequest.wValue = addr; 
    theRequest.wIndex = 0; 
    theRequest.pData = &val;
    theRequest.wLength = sizeof(val);
    ret = (*(priv->_interface))->ControlRequest(priv->_interface, 0, &theRequest);
	if (ret != kIOReturnSuccess)
    {
        DBNSLog(@"%s addr %x %x", __func__, addr, ret);
    }
    return;
}
void rtl818x_iowrite16(struct rtl8187_priv *priv, UInt16 addr, UInt16 val) {
	UInt16 buf = CFSwapInt16HostToLittle(val);
    
    IOReturn ret;
    IOUSBDevRequest theRequest;
    theRequest.bmRequestType = USBmakebmRequestType(kUSBOut, kUSBVendor, kUSBDevice);
    theRequest.bRequest = 0x05;
    theRequest.wValue = addr; 
    theRequest.wIndex = 0; 
    theRequest.pData = &buf;
    theRequest.wLength = sizeof(val);
    ret = (*(priv->_interface))->ControlRequest(priv->_interface, 0, &theRequest);
	if (ret != kIOReturnSuccess)
    {
        DBNSLog(@"%s addr %x %x", __func__, addr, ret);
    }
    return;
}
void rtl818x_iowrite32(struct rtl8187_priv *priv, UInt16 addr, UInt32 val) {
	UInt32 buf = CFSwapInt32HostToLittle(val);
    
    IOReturn ret;
    IOUSBDevRequest theRequest;
    theRequest.bmRequestType = USBmakebmRequestType(kUSBOut, kUSBVendor, kUSBDevice);
    theRequest.bRequest = 0x05;
    theRequest.wValue = addr; 
    theRequest.wIndex = 0; 
    theRequest.pData = &buf;
    theRequest.wLength = sizeof(val);
    ret = (*(priv->_interface))->ControlRequest(priv->_interface, 0, &theRequest);
	if (ret != kIOReturnSuccess)
    {
        DBNSLog(@"%s addr %x %x", __func__, addr, ret);
    }
    return;
}

void rtl8187_eeprom_register_read(struct eeprom_93cx6 *eeprom) {
	struct rtl8187_priv *priv = (struct rtl8187_priv *)(eeprom->data);
	UInt8 reg = rtl818x_ioread8(priv, RTL818X_ADDR_EEPROM_CMD);
    
	eeprom->reg_data_in = reg & RTL818X_EEPROM_CMD_WRITE;
	eeprom->reg_data_out = reg & RTL818X_EEPROM_CMD_READ;
	eeprom->reg_data_clock = reg & RTL818X_EEPROM_CMD_CK;
	eeprom->reg_chip_select = reg & RTL818X_EEPROM_CMD_CS;
}
void rtl8187_eeprom_register_write(struct eeprom_93cx6 *eeprom) {
	struct rtl8187_priv *priv = (struct rtl8187_priv *)(eeprom->data);
	UInt8 reg = RTL818X_EEPROM_CMD_PROGRAM;
    
	if (eeprom->reg_data_in)
		reg |= RTL818X_EEPROM_CMD_WRITE;
	if (eeprom->reg_data_out)
		reg |= RTL818X_EEPROM_CMD_READ;
	if (eeprom->reg_data_clock)
		reg |= RTL818X_EEPROM_CMD_CK;
	if (eeprom->reg_chip_select)
		reg |= RTL818X_EEPROM_CMD_CS;
    
	rtl818x_iowrite8(priv, RTL818X_ADDR_EEPROM_CMD, reg);
	usleep(10);
}

void rtl8187_write_phy(struct rtl8187_priv *priv, UInt8 addr, UInt32 data) {
	data <<= 8;
	data |= addr | 0x80;
    
	rtl818x_iowrite8(priv, RTL818X_ADDR_PHY3, (data >> 24) & 0xFF);
	rtl818x_iowrite8(priv, RTL818X_ADDR_PHY2, (data >> 16) & 0xFF);
	rtl818x_iowrite8(priv, RTL818X_ADDR_PHY1, (data >> 8) & 0xFF);
	rtl818x_iowrite8(priv, RTL818X_ADDR_PHY0, data & 0xFF);
    
	usleep(1000);
}
static void rtl8225_write_phy_ofdm(struct rtl8187_priv *priv, UInt8 addr, UInt32 data) {
	rtl8187_write_phy(priv, addr, data);
}
static void rtl8225_write_phy_cck(struct rtl8187_priv *priv, UInt8 addr, UInt32 data) {
	rtl8187_write_phy(priv, addr, data | 0x10000);
}

static void rtl8225_rf_set_tx_power(struct rtl8187_priv *priv, int channel) {
	UInt8 cck_power, ofdm_power;
	const UInt8 *tmp;
	UInt32 reg;
	int i;
    
	cck_power = priv->channels[channel - 1].val & 0xF;
	ofdm_power = priv->channels[channel - 1].val >> 4;
    
	cck_power = MIN(cck_power, (UInt8)11);
	ofdm_power = MIN(ofdm_power, (UInt8)35);
    
	rtl818x_iowrite8(priv, RTL818X_ADDR_TX_GAIN_CCK, rtl8225_tx_gain_cck_ofdm[cck_power / 6] >> 1);
    
	if (channel == 14)
		tmp = &rtl8225_tx_power_cck_ch14[(cck_power % 6) * 8];
	else
		tmp = &rtl8225_tx_power_cck[(cck_power % 6) * 8];
    
	for (i = 0; i < 8; ++i)
		rtl8225_write_phy_cck(priv, 0x44 + i, *tmp++);
    
	usleep(1000); // FIXME: optional?
    
	/* anaparam2 on */
	rtl818x_iowrite8(priv, RTL818X_ADDR_EEPROM_CMD, RTL818X_EEPROM_CMD_CONFIG);
	reg = rtl818x_ioread8(priv, RTL818X_ADDR_CONFIG3);
	rtl818x_iowrite8(priv, RTL818X_ADDR_CONFIG3, reg | RTL818X_CONFIG3_ANAPARAM_WRITE);
	rtl818x_iowrite32(priv, RTL818X_ADDR_ANAPARAM2, RTL8225_ANAPARAM2_ON);
	rtl818x_iowrite8(priv, RTL818X_ADDR_CONFIG3, reg & ~RTL818X_CONFIG3_ANAPARAM_WRITE);
	rtl818x_iowrite8(priv, RTL818X_ADDR_EEPROM_CMD, RTL818X_EEPROM_CMD_NORMAL);
    
	rtl8225_write_phy_ofdm(priv, 2, 0x42);
	rtl8225_write_phy_ofdm(priv, 6, 0x00);
	rtl8225_write_phy_ofdm(priv, 8, 0x00);
    
	rtl818x_iowrite8(priv, RTL818X_ADDR_TX_GAIN_OFDM, rtl8225_tx_gain_cck_ofdm[ofdm_power / 6] >> 1);
    
	tmp = &rtl8225_tx_power_ofdm[ofdm_power % 6];
    
	rtl8225_write_phy_ofdm(priv, 5, *tmp);
	rtl8225_write_phy_ofdm(priv, 7, *tmp);
    
	usleep(1000);
}
static void rtl8225z2_rf_set_tx_power(struct rtl8187_priv *priv, int channel) {
	UInt8 cck_power, ofdm_power;
	const UInt8 *tmp;
	UInt32 reg;
	int i;
    
	cck_power = priv->channels[channel - 1].val & 0xF;
	ofdm_power = priv->channels[channel - 1].val >> 4;
    
	cck_power = MIN(cck_power, (UInt8)15);
	cck_power += priv->txpwr_base & 0xF;
	cck_power = MIN(cck_power, (UInt8)35);
    
	ofdm_power = MIN(ofdm_power, (UInt8)15);
	ofdm_power += priv->txpwr_base >> 4;
	ofdm_power = MIN(ofdm_power, (UInt8)35);
    
	if (channel == 14)
		tmp = rtl8225z2_tx_power_cck_ch14;
	else
		tmp = rtl8225z2_tx_power_cck;
    
	for (i = 0; i < 8; ++i)
		rtl8225_write_phy_cck(priv, 0x44 + i, *tmp++);
    
	rtl818x_iowrite8(priv, RTL818X_ADDR_TX_GAIN_CCK, rtl8225z2_tx_gain_cck_ofdm[cck_power]);
	usleep(1000);
    
	/* anaparam2 on */
	rtl818x_iowrite8(priv, RTL818X_ADDR_EEPROM_CMD, RTL818X_EEPROM_CMD_CONFIG);
	reg = rtl818x_ioread8(priv, RTL818X_ADDR_CONFIG3);
	rtl818x_iowrite8(priv, RTL818X_ADDR_CONFIG3, reg | RTL818X_CONFIG3_ANAPARAM_WRITE);
	rtl818x_iowrite32(priv, RTL818X_ADDR_ANAPARAM2, RTL8225_ANAPARAM2_ON);
	rtl818x_iowrite8(priv, RTL818X_ADDR_CONFIG3, reg & ~RTL818X_CONFIG3_ANAPARAM_WRITE);
	rtl818x_iowrite8(priv, RTL818X_ADDR_EEPROM_CMD, RTL818X_EEPROM_CMD_NORMAL);
    
	rtl8225_write_phy_ofdm(priv, 2, 0x42);
	rtl8225_write_phy_ofdm(priv, 5, 0x00);
	rtl8225_write_phy_ofdm(priv, 6, 0x40);
	rtl8225_write_phy_ofdm(priv, 7, 0x00);
	rtl8225_write_phy_ofdm(priv, 8, 0x40);
    
	rtl818x_iowrite8(priv, RTL818X_ADDR_TX_GAIN_OFDM, rtl8225z2_tx_gain_cck_ofdm[ofdm_power]);
	usleep(1000);
}

static void rtl8225_write_8051(struct rtl8187_priv *priv, UInt8 addr, UInt16 data) {
	UInt16 reg80, reg82, reg84;
	reg80 = rtl818x_ioread16(priv, RTL818X_ADDR_RFPinsOutput);
	reg82 = rtl818x_ioread16(priv, RTL818X_ADDR_RFPinsEnable);
	reg84 = rtl818x_ioread16(priv, RTL818X_ADDR_RFPinsSelect);
    
//    DBNSLog(@"%s:%d %x %x %x", __func__, __LINE__, reg80, reg82, reg84);

	reg80 &= ~(0x3 << 2);
	reg84 &= ~0xF;
    
	rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsEnable, reg82 | 0x0007);
	rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsSelect, reg84 | 0x0007);
	usleep(10);
    
	rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsOutput, reg80 | (1 << 2));
	usleep(2);
    
	rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsOutput, reg80);
	usleep(10);
    
    IOReturn ret;
    IOUSBDevRequest theRequest;
    theRequest.bmRequestType = USBmakebmRequestType(kUSBOut, kUSBVendor, kUSBDevice);
    theRequest.bRequest = 0x05;
    theRequest.wValue = addr; 
    theRequest.wIndex = 0x8225; 
    theRequest.pData = &data;
    theRequest.wLength = sizeof(data);
    ret = (*(priv->_interface))->ControlRequest(priv->_interface, 0, &theRequest);

	if (ret != kIOReturnSuccess)
    {
        DBNSLog(@"%s addr %x %x", __func__, addr, ret);
    }

	rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsOutput, reg80 | (1 << 2));
	usleep(10);
    
	rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsOutput, reg80 | (1 << 2));
	rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsSelect, reg84);
//    DBNSLog(@"%s:%d %x %x %x", __func__, __LINE__, reg80, reg82, reg84);
	usleep(2000);
}
static void rtl8225_write_bitbang(struct rtl8187_priv *priv, UInt8 addr, UInt16 data) {
	UInt16 reg80, reg84, reg82;
	UInt32 bangdata;
	int i;
    
	bangdata = (data << 4) | (addr & 0xf);
    
	reg80 = rtl818x_ioread16(priv, RTL818X_ADDR_RFPinsOutput) & 0xfff3;
	reg82 = rtl818x_ioread16(priv, RTL818X_ADDR_RFPinsEnable);
    
	rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsEnable, reg82 | 0x7);
    
	reg84 = rtl818x_ioread16(priv, RTL818X_ADDR_RFPinsSelect);
	rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsSelect, reg84 | 0x7);
	usleep(10);
    
	rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsOutput, reg80 | (1 << 2));
	usleep(2);
	rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsOutput, reg80);
	usleep(10);
    
	for (i = 15; i >= 0; i--) {
		UInt16 reg = reg80 | (bangdata & (1 << i)) >> i;
        
		if (i & 1)
			rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsOutput, reg);
        
		rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsOutput, reg | (1 << 1));
		rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsOutput, reg | (1 << 1));
        
		if (!(i & 1))
			rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsOutput, reg);
	}
    
	rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsOutput, reg80 | (1 << 2));
	usleep(10);
    
	rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsOutput, reg80 | (1 << 2));
	rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsSelect, reg84);
	usleep(2);
}
void rtl8225_write(struct rtl8187_priv *priv, UInt8 addr, UInt16 data) {
	if (priv->asic_rev)
        rtl8225_write_8051(priv, addr, CFSwapInt16HostToLittle(data));
	else
		rtl8225_write_bitbang(priv, addr, data);
}

UInt16 rtl8225_read(struct rtl8187_priv *priv, UInt8 addr) {
	UInt16 reg80, reg82, reg84, out;
	int i;
    
	reg80 = rtl818x_ioread16(priv, RTL818X_ADDR_RFPinsOutput);
	reg82 = rtl818x_ioread16(priv, RTL818X_ADDR_RFPinsEnable);
	reg84 = rtl818x_ioread16(priv, RTL818X_ADDR_RFPinsSelect);
    
//    DBNSLog(@"%s:%d %x %x %x", __func__, __LINE__, reg80, reg82, reg84);
    
	reg80 &= ~0xF;
    
	rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsEnable, reg82 | 0x000F);
	rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsSelect, reg84 | 0x000F);
    
	rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsOutput, reg80 | (1 << 2));
	usleep(4);
	rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsOutput, reg80);
	usleep(5);
    
	for (i = 4; i >= 0; i--) {
		UInt16 reg = reg80 | ((addr >> i) & 1);
        
		if (!(i & 1)) {
			rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsOutput, reg);
			usleep(1);
		}
        
		rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsOutput, reg | (1 << 1));
		usleep(2);
		rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsOutput, reg | (1 << 1));
		usleep(2);
        
		if (i & 1) {
			rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsOutput, reg);
			usleep(1);
		}
	}
    
	rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsOutput, reg80 | (1 << 3) | (1 << 1));
	usleep(2);
	rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsOutput, reg80 | (1 << 3));
	usleep(2);
	rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsOutput, reg80 | (1 << 3));
	usleep(2);
    
	out = 0;
	for (i = 11; i >= 0; i--) {
		rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsOutput, reg80 | (1 << 3));
		usleep(1);
		rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsOutput, reg80 | (1 << 3) | (1 << 1));
		usleep(2);
		rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsOutput, reg80 | (1 << 3) | (1 << 1));
		usleep(2);
		rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsOutput, reg80 | (1 << 3) | (1 << 1));
		usleep(2);
        
		if (rtl818x_ioread16(priv, RTL818X_ADDR_RFPinsInput) & (1 << 1))
			out |= 1 << i;
        
		rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsOutput, reg80 | (1 << 3));
		usleep(2);
	}
    
	rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsOutput, reg80 | (1 << 3) | (1 << 2));
	usleep(2);
    
	rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsEnable, reg82);
	rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsSelect, reg84);
	rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsOutput, 0x03A0);
//    DBNSLog(@"out %u", out);
	return out;
}

void rtl8225_rf_init(struct rtl8187_priv *priv) {
	unsigned int i;
//    DBNSLog(@"rf_init");
	rtl8225_write(priv, 0x0, 0x067); usleep(1000);
	rtl8225_write(priv, 0x1, 0xFE0); usleep(1000);
	rtl8225_write(priv, 0x2, 0x44D); usleep(1000);
	rtl8225_write(priv, 0x3, 0x441); usleep(1000);
	rtl8225_write(priv, 0x4, 0x486); usleep(1000);
	rtl8225_write(priv, 0x5, 0xBC0); usleep(1000);
	rtl8225_write(priv, 0x6, 0xAE6); usleep(1000);
	rtl8225_write(priv, 0x7, 0x82A); usleep(1000);
	rtl8225_write(priv, 0x8, 0x01F); usleep(1000);
	rtl8225_write(priv, 0x9, 0x334); usleep(1000);
	rtl8225_write(priv, 0xA, 0xFD4); usleep(1000);
	rtl8225_write(priv, 0xB, 0x391); usleep(1000);
	rtl8225_write(priv, 0xC, 0x050); usleep(1000);
	rtl8225_write(priv, 0xD, 0x6DB); usleep(1000);
	rtl8225_write(priv, 0xE, 0x029); usleep(1000);
	rtl8225_write(priv, 0xF, 0x914); usleep(100000);
    
	rtl8225_write(priv, 0x2, 0xC4D); usleep(200000);
	rtl8225_write(priv, 0x2, 0x44D); usleep(200000);
//    DBNSLog(@"read1");
	if (!(rtl8225_read(priv, 6) & (1 << 7))) {
		rtl8225_write(priv, 0x02, 0x0c4d);
		usleep(200000);
		rtl8225_write(priv, 0x02, 0x044d);
		usleep(100000);
//        DBNSLog(@"read2");
		if (!(rtl8225_read(priv, 6) & (1 << 7)))
			DBNSLog(@"RF Calibration Failed! %x\n", rtl8225_read(priv, 6));
	}
    
	rtl8225_write(priv, 0x0, 0x127);
    
	for (i = 0; i < ARRAY_SIZE(rtl8225bcd_rxgain); ++i) {
		rtl8225_write(priv, 0x1, i + 1);
		rtl8225_write(priv, 0x2, rtl8225bcd_rxgain[i]);
	}
    
	rtl8225_write(priv, 0x0, 0x027);
	rtl8225_write(priv, 0x0, 0x22F);
    
	for (i = 0; i < ARRAY_SIZE(rtl8225_agc); ++i) {
		rtl8225_write_phy_ofdm(priv, 0xB, rtl8225_agc[i]);
		usleep(1000);
		rtl8225_write_phy_ofdm(priv, 0xA, 0x80 + i);
		usleep(1000);
	}
    
	usleep(1000);
    
	rtl8225_write_phy_ofdm(priv, 0x00, 0x01); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x01, 0x02); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x02, 0x42); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x03, 0x00); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x04, 0x00); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x05, 0x00); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x06, 0x40); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x07, 0x00); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x08, 0x40); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x09, 0xfe); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x0a, 0x09); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x0b, 0x80); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x0c, 0x01); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x0e, 0xd3); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x0f, 0x38); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x10, 0x84); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x11, 0x06); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x12, 0x20); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x13, 0x20); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x14, 0x00); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x15, 0x40); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x16, 0x00); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x17, 0x40); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x18, 0xef); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x19, 0x19); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x1a, 0x20); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x1b, 0x76); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x1c, 0x04); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x1e, 0x95); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x1f, 0x75); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x20, 0x1f); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x21, 0x27); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x22, 0x16); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x24, 0x46); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x25, 0x20); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x26, 0x90); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x27, 0x88); usleep(1000);
    
	rtl8225_write_phy_ofdm(priv, 0x0d, rtl8225_gain[2 * 4]);
	rtl8225_write_phy_ofdm(priv, 0x1b, rtl8225_gain[2 * 4 + 2]);
	rtl8225_write_phy_ofdm(priv, 0x1d, rtl8225_gain[2 * 4 + 3]);
	rtl8225_write_phy_ofdm(priv, 0x23, rtl8225_gain[2 * 4 + 1]);
    
	rtl8225_write_phy_cck(priv, 0x00, 0x98); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x03, 0x20); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x04, 0x7e); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x05, 0x12); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x06, 0xfc); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x07, 0x78); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x08, 0x2e); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x10, 0x9b); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x11, 0x88); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x12, 0x47); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x13, 0xd0);
	rtl8225_write_phy_cck(priv, 0x19, 0x00);
	rtl8225_write_phy_cck(priv, 0x1a, 0xa0);
	rtl8225_write_phy_cck(priv, 0x1b, 0x08);
	rtl8225_write_phy_cck(priv, 0x40, 0x86);
	rtl8225_write_phy_cck(priv, 0x41, 0x8d); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x42, 0x15); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x43, 0x18); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x44, 0x1f); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x45, 0x1e); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x46, 0x1a); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x47, 0x15); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x48, 0x10); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x49, 0x0a); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x4a, 0x05); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x4b, 0x02); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x4c, 0x05); usleep(1000);
    
	rtl818x_iowrite8(priv, RTL818X_ADDR_TESTR, 0x0D);
    
	rtl8225_rf_set_tx_power(priv, 1);
    
	/* RX antenna default to A */
	rtl8225_write_phy_cck(priv, 0x10, 0x9b); usleep(1000);	/* B: 0xDB */
	rtl8225_write_phy_ofdm(priv, 0x26, 0x90); usleep(1000);	/* B: 0x10 */
    
	rtl818x_iowrite8(priv, RTL818X_ADDR_TX_ANTENNA, 0x03);	/* B: 0x00 */
	usleep(1000);
	rtl818x_iowrite32(priv, 0xFF94, 0x3dc00002);
    
	/* set sensitivity */
	rtl8225_write(priv, 0x0c, 0x50);
	rtl8225_write_phy_ofdm(priv, 0x0d, rtl8225_gain[2 * 4]);
	rtl8225_write_phy_ofdm(priv, 0x1b, rtl8225_gain[2 * 4 + 2]);
	rtl8225_write_phy_ofdm(priv, 0x1d, rtl8225_gain[2 * 4 + 3]);
	rtl8225_write_phy_ofdm(priv, 0x23, rtl8225_gain[2 * 4 + 1]);
	rtl8225_write_phy_cck(priv, 0x41, rtl8225_threshold[2]);
}
void rtl8225z2_rf_init(struct rtl8187_priv *priv) {
	unsigned int i;
    
	rtl8225_write(priv, 0x0, 0x2BF); usleep(1000);
	rtl8225_write(priv, 0x1, 0xEE0); usleep(1000);
	rtl8225_write(priv, 0x2, 0x44D); usleep(1000);
	rtl8225_write(priv, 0x3, 0x441); usleep(1000);
	rtl8225_write(priv, 0x4, 0x8C3); usleep(1000);
	rtl8225_write(priv, 0x5, 0xC72); usleep(1000);
	rtl8225_write(priv, 0x6, 0x0E6); usleep(1000);
	rtl8225_write(priv, 0x7, 0x82A); usleep(1000);
	rtl8225_write(priv, 0x8, 0x03F); usleep(1000);
	rtl8225_write(priv, 0x9, 0x335); usleep(1000);
	rtl8225_write(priv, 0xa, 0x9D4); usleep(1000);
	rtl8225_write(priv, 0xb, 0x7BB); usleep(1000);
	rtl8225_write(priv, 0xc, 0x850); usleep(1000);
	rtl8225_write(priv, 0xd, 0xCDF); usleep(1000);
	rtl8225_write(priv, 0xe, 0x02B); usleep(1000);
	rtl8225_write(priv, 0xf, 0x114); usleep(100000);
    
	rtl8225_write(priv, 0x0, 0x1B7);
    
	for (i = 0; i < ARRAY_SIZE(rtl8225z2_rxgain); ++i) {
		rtl8225_write(priv, 0x1, i + 1);
		rtl8225_write(priv, 0x2, rtl8225z2_rxgain[i]);
	}
    
	rtl8225_write(priv, 0x3, 0x080);
	rtl8225_write(priv, 0x5, 0x004);
	rtl8225_write(priv, 0x0, 0x0B7);
	rtl8225_write(priv, 0x2, 0xc4D);
    
	usleep(200000);
	rtl8225_write(priv, 0x2, 0x44D);
	usleep(100000);
    
	if (!(rtl8225_read(priv, 6) & (1 << 7))) {
		rtl8225_write(priv, 0x02, 0x0C4D);
		usleep(200000);
		rtl8225_write(priv, 0x02, 0x044D);
		usleep(100000);
		if (!(rtl8225_read(priv, 6) & (1 << 7)))
			DBNSLog(@"RF Calibration Failed! %x\n", rtl8225_read(priv, 6));
	}
    
	usleep(200000);
    
	rtl8225_write(priv, 0x0, 0x2BF);
    
	for (i = 0; i < ARRAY_SIZE(rtl8225_agc); ++i) {
		rtl8225_write_phy_ofdm(priv, 0xB, rtl8225_agc[i]);
		usleep(1000);
		rtl8225_write_phy_ofdm(priv, 0xA, 0x80 + i);
		usleep(1000);
	}
    
	usleep(1000);
    
	rtl8225_write_phy_ofdm(priv, 0x00, 0x01); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x01, 0x02); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x02, 0x42); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x03, 0x00); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x04, 0x00); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x05, 0x00); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x06, 0x40); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x07, 0x00); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x08, 0x40); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x09, 0xfe); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x0a, 0x08); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x0b, 0x80); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x0c, 0x01); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x0d, 0x43);
	rtl8225_write_phy_ofdm(priv, 0x0e, 0xd3); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x0f, 0x38); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x10, 0x84); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x11, 0x07); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x12, 0x20); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x13, 0x20); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x14, 0x00); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x15, 0x40); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x16, 0x00); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x17, 0x40); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x18, 0xef); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x19, 0x19); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x1a, 0x20); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x1b, 0x15); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x1c, 0x04); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x1d, 0xc5); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x1e, 0x95); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x1f, 0x75); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x20, 0x1f); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x21, 0x17); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x22, 0x16); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x23, 0x80); usleep(1000); //FIXME: not needed?
	rtl8225_write_phy_ofdm(priv, 0x24, 0x46); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x25, 0x00); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x26, 0x90); usleep(1000);
	rtl8225_write_phy_ofdm(priv, 0x27, 0x88); usleep(1000);
    
	rtl8225_write_phy_ofdm(priv, 0x0b, rtl8225z2_gain_bg[4 * 3]);
	rtl8225_write_phy_ofdm(priv, 0x1b, rtl8225z2_gain_bg[4 * 3 + 1]);
	rtl8225_write_phy_ofdm(priv, 0x1d, rtl8225z2_gain_bg[4 * 3 + 2]);
	rtl8225_write_phy_ofdm(priv, 0x21, 0x37);
    
	rtl8225_write_phy_cck(priv, 0x00, 0x98); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x03, 0x20); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x04, 0x7e); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x05, 0x12); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x06, 0xfc); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x07, 0x78); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x08, 0x2e); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x10, 0x9b); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x11, 0x88); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x12, 0x47); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x13, 0xd0);
	rtl8225_write_phy_cck(priv, 0x19, 0x00);
	rtl8225_write_phy_cck(priv, 0x1a, 0xa0);
	rtl8225_write_phy_cck(priv, 0x1b, 0x08);
	rtl8225_write_phy_cck(priv, 0x40, 0x86);
	rtl8225_write_phy_cck(priv, 0x41, 0x8d); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x42, 0x15); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x43, 0x18); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x44, 0x36); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x45, 0x35); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x46, 0x2e); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x47, 0x25); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x48, 0x1c); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x49, 0x12); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x4a, 0x09); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x4b, 0x04); usleep(1000);
	rtl8225_write_phy_cck(priv, 0x4c, 0x05); usleep(1000);
    
	rtl818x_iowrite8(priv, 0xFF5B, 0x0D); usleep(1000);
    
	rtl8225z2_rf_set_tx_power(priv, 1);
    
	/* RX antenna default to A */
	rtl8225_write_phy_cck(priv, 0x10, 0x9b); usleep(1000);	/* B: 0xDB */
	rtl8225_write_phy_ofdm(priv, 0x26, 0x90); usleep(1000);	/* B: 0x10 */
    
	rtl818x_iowrite8(priv, RTL818X_ADDR_TX_ANTENNA, 0x03);	/* B: 0x00 */
	usleep(1000);
	rtl818x_iowrite32(priv, 0xFF94, 0x3dc00002);
}

static int rtl8187_init_hw(struct rtl8187_priv *priv) {
	UInt8 reg;
	int i;
    
	/* reset */
	rtl818x_iowrite8(priv, RTL818X_ADDR_EEPROM_CMD, RTL818X_EEPROM_CMD_CONFIG);
	reg = rtl818x_ioread8(priv, RTL818X_ADDR_CONFIG3);
	rtl818x_iowrite8(priv, RTL818X_ADDR_CONFIG3, reg | RTL818X_CONFIG3_ANAPARAM_WRITE);
	rtl818x_iowrite32(priv, RTL818X_ADDR_ANAPARAM, RTL8225_ANAPARAM_ON);
	rtl818x_iowrite32(priv, RTL818X_ADDR_ANAPARAM2, RTL8225_ANAPARAM2_ON);
	rtl818x_iowrite8(priv, RTL818X_ADDR_CONFIG3, reg & ~RTL818X_CONFIG3_ANAPARAM_WRITE);
	rtl818x_iowrite8(priv, RTL818X_ADDR_EEPROM_CMD, RTL818X_EEPROM_CMD_NORMAL);
    
	rtl818x_iowrite16(priv, RTL818X_ADDR_INT_MASK, 0);
    
	usleep(200000);
	rtl818x_iowrite8(priv, 0xFE18, 0x10);
	rtl818x_iowrite8(priv, 0xFE18, 0x11);
	rtl818x_iowrite8(priv, 0xFE18, 0x00);
	usleep(200000);
    
	reg = rtl818x_ioread8(priv, RTL818X_ADDR_CMD);
	reg &= (1 << 1);
	reg |= RTL818X_CMD_RESET;
	rtl818x_iowrite8(priv, RTL818X_ADDR_CMD, reg);
    
	i = 10;
	do {
		usleep(2000);
		if (!(rtl818x_ioread8(priv, RTL818X_ADDR_CMD) &
		      RTL818X_CMD_RESET))
			break;
	} while (--i);
    
	if (!i) {
		DBNSLog(@"Reset timeout!\n");
		return -ETIMEDOUT;
	}
    
	/* reload registers from eeprom */
	rtl818x_iowrite8(priv, RTL818X_ADDR_EEPROM_CMD, RTL818X_EEPROM_CMD_LOAD);
    
	i = 10;
	do {
		usleep(4000);
		if (!(rtl818x_ioread8(priv, RTL818X_ADDR_EEPROM_CMD) &
		      RTL818X_EEPROM_CMD_CONFIG))
			break;
	} while (--i);
    
	if (!i) {
		DBNSLog(@"eeprom reset timeout!\n");
		return -ETIMEDOUT;
	}
    
	rtl818x_iowrite8(priv, RTL818X_ADDR_EEPROM_CMD, RTL818X_EEPROM_CMD_CONFIG);
	reg = rtl818x_ioread8(priv, RTL818X_ADDR_CONFIG3);
	rtl818x_iowrite8(priv, RTL818X_ADDR_CONFIG3, reg | RTL818X_CONFIG3_ANAPARAM_WRITE);
	rtl818x_iowrite32(priv, RTL818X_ADDR_ANAPARAM, RTL8225_ANAPARAM_ON);
	rtl818x_iowrite32(priv, RTL818X_ADDR_ANAPARAM2, RTL8225_ANAPARAM2_ON);
	rtl818x_iowrite8(priv, RTL818X_ADDR_CONFIG3, reg & ~RTL818X_CONFIG3_ANAPARAM_WRITE);
	rtl818x_iowrite8(priv, RTL818X_ADDR_EEPROM_CMD, RTL818X_EEPROM_CMD_NORMAL);
    
	/* setup card */
	rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsSelect, 0);
	rtl818x_iowrite8(priv, RTL818X_ADDR_GPIO, 0);
    
	rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsSelect, (4 << 8));
	rtl818x_iowrite8(priv, RTL818X_ADDR_GPIO, 1);
	rtl818x_iowrite8(priv, RTL818X_ADDR_GP_ENABLE, 0);
    
	rtl818x_iowrite8(priv, RTL818X_ADDR_EEPROM_CMD, RTL818X_EEPROM_CMD_CONFIG);
    
	rtl818x_iowrite16(priv, 0xFFF4, 0xFFFF);
	reg = rtl818x_ioread8(priv, RTL818X_ADDR_CONFIG1);
	reg &= 0x3F;
	reg |= 0x80;
	rtl818x_iowrite8(priv, RTL818X_ADDR_CONFIG1, reg);
    
	rtl818x_iowrite8(priv, RTL818X_ADDR_EEPROM_CMD, RTL818X_EEPROM_CMD_NORMAL);
    
	rtl818x_iowrite32(priv, RTL818X_ADDR_INT_TIMEOUT, 0);
	rtl818x_iowrite8(priv, RTL818X_ADDR_WPA_CONF, 0);
	rtl818x_iowrite8(priv, RTL818X_ADDR_RATE_FALLBACK, 0x81);
    
	// TODO: set RESP_RATE and BRSR properly
	rtl818x_iowrite8(priv, RTL818X_ADDR_RESP_RATE, (8 << 4) | 0);
	rtl818x_iowrite16(priv, RTL818X_ADDR_BRSR, 0x01F3);
    
	/* host_usb_init */
	rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsSelect, 0);
	rtl818x_iowrite8(priv, RTL818X_ADDR_GPIO, 0);
	reg = rtl818x_ioread8(priv, 0xFE53);
	rtl818x_iowrite8(priv, 0xFE53, reg | (1 << 7));
	rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsSelect, (4 << 8));
	rtl818x_iowrite8(priv, RTL818X_ADDR_GPIO, 0x20);
	rtl818x_iowrite8(priv, RTL818X_ADDR_GP_ENABLE, 0);
	rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsOutput, 0x80);
	rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsSelect, 0x80);
	rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsEnable, 0x80);

	usleep(100000);
    
	rtl818x_iowrite32(priv, RTL818X_ADDR_RF_TIMING, 0x000a8008);
	rtl818x_iowrite16(priv, RTL818X_ADDR_BRSR, 0xFFFF);
	rtl818x_iowrite32(priv, RTL818X_ADDR_RF_PARA, 0x00100044);
	rtl818x_iowrite8(priv, RTL818X_ADDR_EEPROM_CMD, RTL818X_EEPROM_CMD_CONFIG);
	rtl818x_iowrite8(priv, RTL818X_ADDR_CONFIG3, 0x44);
	rtl818x_iowrite8(priv, RTL818X_ADDR_EEPROM_CMD, RTL818X_EEPROM_CMD_NORMAL);
	rtl818x_iowrite16(priv, RTL818X_ADDR_RFPinsEnable, 0x1FF7);
	usleep(100000);
    
	priv->rf_init(priv);
    
	rtl818x_iowrite16(priv, RTL818X_ADDR_BRSR, 0x01F3);
	reg = rtl818x_ioread8(priv, RTL818X_ADDR_PGSELECT) & ~1;
	rtl818x_iowrite8(priv, RTL818X_ADDR_PGSELECT, reg | 1);
	rtl818x_iowrite16(priv, 0xFFFE, 0x10);
	rtl818x_iowrite8(priv, RTL818X_ADDR_TALLY_SEL, 0x80);
	rtl818x_iowrite8(priv, 0xFFFF, 0x60);
	rtl818x_iowrite8(priv, RTL818X_ADDR_PGSELECT, reg);
    
	return 0;
}
void rtl8225_rf_stop(struct rtl8187_priv *priv) {
	UInt8 reg;
    
	rtl8225_write(priv, 0x4, 0x1f); usleep(1000);
    
	rtl818x_iowrite8(priv, RTL818X_ADDR_EEPROM_CMD, RTL818X_EEPROM_CMD_CONFIG);
	reg = rtl818x_ioread8(priv, RTL818X_ADDR_CONFIG3);
	rtl818x_iowrite8(priv, RTL818X_ADDR_CONFIG3, reg | RTL818X_CONFIG3_ANAPARAM_WRITE);
	rtl818x_iowrite32(priv, RTL818X_ADDR_ANAPARAM2, RTL8225_ANAPARAM2_OFF);
	rtl818x_iowrite32(priv, RTL818X_ADDR_ANAPARAM, RTL8225_ANAPARAM_OFF);
	rtl818x_iowrite8(priv, RTL818X_ADDR_CONFIG3, reg & ~RTL818X_CONFIG3_ANAPARAM_WRITE);
	rtl818x_iowrite8(priv, RTL818X_ADDR_EEPROM_CMD, RTL818X_EEPROM_CMD_NORMAL);
}

void rtl8225_rf_set_channel(struct rtl8187_priv *priv, int channel) {
	if (priv->rf_init == rtl8225_rf_init)
		rtl8225_rf_set_tx_power(priv, channel);
	else
		rtl8225z2_rf_set_tx_power(priv, channel);
    
	rtl8225_write(priv, 0x7, rtl8225_chan[channel - 1]);
	usleep(10000);
}

static void rtl8187_set_channel(struct rtl8187_priv *priv, int channel) {
	UInt32 reg;
    
	reg = rtl818x_ioread32(priv, RTL818X_ADDR_TX_CONF);
	/* Enable TX loopback on MAC level to avoid TX during channel
	 * changes, as this has be seen to causes problems and the
	 * card will stop work until next reset
	 */
	rtl818x_iowrite32(priv, RTL818X_ADDR_TX_CONF, reg | RTL818X_TX_CONF_LOOPBACK_MAC);
	usleep(10000);
	rtl8225_rf_set_channel(priv, channel);
	usleep(10000);
	rtl818x_iowrite32(priv, RTL818X_ADDR_TX_CONF, reg);
}

static int rtl8187_start(struct rtl8187_priv *priv) {
	UInt32 reg;
	int ret;
    
	ret = rtl8187_init_hw(priv);
	if (ret)
		return ret;
    
	rtl818x_iowrite16(priv, RTL818X_ADDR_INT_MASK, 0xFFFF);
    
	rtl818x_iowrite32(priv, RTL818X_ADDR_MAR0, ~0);
	rtl818x_iowrite32(priv, RTL818X_ADDR_MAR1, ~0);
    
//	rtl8187_init_urbs(dev);
    
	reg = RTL818X_RX_CONF_ONLYERLPKT |
    RTL818X_RX_CONF_RX_AUTORESETPHY |
    RTL818X_RX_CONF_BSSID |
    RTL818X_RX_CONF_MGMT |
    RTL818X_RX_CONF_DATA |
    RTL818X_RX_CONF_CTRL |
    (7 << 13 /* RX FIFO threshold NONE */) |
    (7 << 10 /* MAX RX DMA */) |
    RTL818X_RX_CONF_BROADCAST |
    RTL818X_RX_CONF_NICMAC |
    RTL818X_RX_CONF_MONITOR;
	priv->rx_conf = reg;
	rtl818x_iowrite32(priv, RTL818X_ADDR_RX_CONF, reg);
    
	reg = rtl818x_ioread8(priv, RTL818X_ADDR_CW_CONF);
	reg &= ~RTL818X_CW_CONF_PERPACKET_CW_SHIFT;
	reg |= RTL818X_CW_CONF_PERPACKET_RETRY_SHIFT;
	rtl818x_iowrite8(priv, RTL818X_ADDR_CW_CONF, reg);
    
	reg = rtl818x_ioread8(priv, RTL818X_ADDR_TX_AGC_CTL);
	reg &= ~RTL818X_TX_AGC_CTL_PERPACKET_GAIN_SHIFT;
	reg &= ~RTL818X_TX_AGC_CTL_PERPACKET_ANTSEL_SHIFT;
	reg &= ~RTL818X_TX_AGC_CTL_FEEDBACK_ANT;
	rtl818x_iowrite8(priv, RTL818X_ADDR_TX_AGC_CTL, reg);
    
	reg  = RTL818X_TX_CONF_CW_MIN |
    (7 << 21 /* MAX TX DMA */) |
    RTL818X_TX_CONF_NO_ICV;
	rtl818x_iowrite32(priv, RTL818X_ADDR_TX_CONF, reg);
    
	reg = rtl818x_ioread8(priv, RTL818X_ADDR_CMD);
	reg |= RTL818X_CMD_TX_ENABLE;
	reg |= RTL818X_CMD_RX_ENABLE;
	rtl818x_iowrite8(priv, RTL818X_ADDR_CMD, reg);
    
	return 0;
}
static void rtl8187_stop(struct rtl8187_priv *priv) {
	UInt32 reg;
    
	rtl818x_iowrite16(priv, RTL818X_ADDR_INT_MASK, 0);
    
	reg = rtl818x_ioread8(priv, RTL818X_ADDR_CMD);
	reg &= ~RTL818X_CMD_TX_ENABLE;
	reg &= ~RTL818X_CMD_RX_ENABLE;
	rtl818x_iowrite8(priv, RTL818X_ADDR_CMD, reg);
    
	rtl8225_rf_stop(priv);
    
	rtl818x_iowrite8(priv, RTL818X_ADDR_EEPROM_CMD, RTL818X_EEPROM_CMD_CONFIG);
	reg = rtl818x_ioread8(priv, RTL818X_ADDR_CONFIG4);
	rtl818x_iowrite8(priv, RTL818X_ADDR_CONFIG4, reg | RTL818X_CONFIG4_VCOOFF);
	rtl818x_iowrite8(priv, RTL818X_ADDR_EEPROM_CMD, RTL818X_EEPROM_CMD_NORMAL);
    
	return;
}

char *RTL8187Jack::getPlistFile()
{
    return (char*)"UsbVendorsRTL8187";
}

IOReturn RTL8187Jack::_init() {
    DBNSLog(@"_init");

	NICInitialized = false;
    
    if(!_attachDevice()){
        DBNSLog(@"Device could not be opened");
        return kIOReturnNoDevice;
    }
    // Allocate _priv;
    _priv = (struct rtl8187_priv *)malloc(sizeof(struct rtl8187_priv));
    bzero(_priv, sizeof(struct rtl8187_priv));

    rtl8187_probe();
    NICInitialized = true;
    _deviceInit = true;
    DBNSLog(@"_init exit");
    return kIOReturnSuccess;
}

int  RTL8187Jack::rtl8187_probe(void) {
//	struct usb_device *udev = interface_to_usbdev(intf);
//	struct ieee80211_hw *dev;
	struct rtl8187_priv *priv = _priv;
	struct eeprom_93cx6 eeprom;
	struct ieee80211_channel *channel;
	UInt16 txpwr, reg;
	int i;
//	DECLARE_MAC_BUF(mac);
    
//	dev = ieee80211_alloc_hw(sizeof(*priv), &rtl8187_ops);
//	if (!dev) {
//		printk(KERN_ERR "rtl8187: ieee80211 alloc failed\n");
//		return -ENOMEM;
//	}
    
//	priv = dev->priv;
    
//	SET_IEEE80211_DEV(dev, &intf->dev);
//	usb_set_intfdata(intf, dev);
	priv->_interface = _interface;
    
//	usb_get_dev(udev);
    
//	skb_queue_head_init(&priv->rx_queue);

	memcpy(priv->channels, rtl818x_channels, sizeof(rtl818x_channels));
//	memcpy(priv->rates, rtl818x_rates, sizeof(rtl818x_rates));
	priv->map = (struct rtl818x_csr *)0xFF00;

//	priv->modes[0].mode = MODE_IEEE80211G;
//	priv->modes[0].num_rates = ARRAY_SIZE(rtl818x_rates);
//	priv->modes[0].rates = priv->rates;
//	priv->modes[0].num_channels = ARRAY_SIZE(rtl818x_channels);
//	priv->modes[0].channels = priv->channels;
	
//    priv->modes[1].mode = MODE_IEEE80211B;
//	priv->modes[1].num_rates = 4;
//	priv->modes[1].rates = priv->rates;
//	priv->modes[1].num_channels = ARRAY_SIZE(rtl818x_channels);
//	priv->modes[1].channels = priv->channels;
	
//    priv->mode = IEEE80211_IF_TYPE_MNTR;
//	dev->flags = IEEE80211_HW_HOST_BROADCAST_PS_BUFFERING | IEEE80211_HW_RX_INCLUDES_FCS;
	
//    dev->extra_tx_headroom = sizeof(struct rtl8187_tx_hdr);
//	dev->queues = 1;
//	dev->max_rssi = 65;
//	dev->max_signal = 64;
    
//	for (i = 0; i < 2; i++)
//		if ((err = ieee80211_register_hwmode(dev, &priv->modes[i])))
//			goto err_free_dev;
    
	eeprom.data = priv;
	eeprom.register_read = rtl8187_eeprom_register_read;
	eeprom.register_write = rtl8187_eeprom_register_write;
    if (rtl818x_ioread32(priv, RTL818X_ADDR_RX_CONF) & (1 << 6))
		eeprom.width = PCI_EEPROM_WIDTH_93C66;
	else
		eeprom.width = PCI_EEPROM_WIDTH_93C46;
    
	rtl818x_iowrite8(priv, RTL818X_ADDR_EEPROM_CMD, RTL818X_EEPROM_CMD_CONFIG);
	usleep(10);
    UInt16 perm_addr[3];
    eeprom_93cx6_multiread(&eeprom, RTL8187_EEPROM_MAC_ADDR, perm_addr, 3);

    DBNSLog(@"%.4x%.4x%.4x", perm_addr[0], perm_addr[1], perm_addr[2]);
//	if (!is_valid_ether_addr(dev->wiphy->perm_addr)) {
//		printk(KERN_WARNING "rtl8187: Invalid hwaddr! Using randomly "
//		       "generated MAC address\n");
//		random_ether_addr(dev->wiphy->perm_addr);
//	}
    
	channel = priv->channels;
	for (i = 0; i < 3; ++i) {
		eeprom_93cx6_read(&eeprom, RTL8187_EEPROM_TXPWR_CHAN_1 + i,
                          &txpwr);
		(*channel++).val = txpwr & 0xFF;
		(*channel++).val = txpwr >> 8;
	}
	for (i = 0; i < 2; ++i) {
		eeprom_93cx6_read(&eeprom, RTL8187_EEPROM_TXPWR_CHAN_4 + i,
                          &txpwr);
		(*channel++).val = txpwr & 0xFF;
		(*channel++).val = txpwr >> 8;
	}
	for (i = 0; i < 2; ++i) {
		eeprom_93cx6_read(&eeprom, RTL8187_EEPROM_TXPWR_CHAN_6 + i,
                          &txpwr);
		(*channel++).val = txpwr & 0xFF;
		(*channel++).val = txpwr >> 8;
	}
    
	eeprom_93cx6_read(&eeprom, RTL8187_EEPROM_TXPWR_BASE,
                      &priv->txpwr_base);

    reg = rtl818x_ioread8(priv, RTL818X_ADDR_PGSELECT) & ~1;
	rtl818x_iowrite8(priv, RTL818X_ADDR_PGSELECT, reg | 1);
	/* 0 means asic B-cut, we should use SW 3 wire
	 * bit-by-bit banging for radio. 1 means we can use
	 * USB specific request to write radio registers */
	priv->asic_rev = rtl818x_ioread8(priv, 0xFFFE) & 0x3;
	rtl818x_iowrite8(priv, RTL818X_ADDR_PGSELECT, reg);
	rtl818x_iowrite8(priv, RTL818X_ADDR_EEPROM_CMD, RTL818X_EEPROM_CMD_NORMAL);
    
    rtl8225_write(priv, 0, 0x1B7);
    
    if (rtl8225_read(priv, 8) != 0x588 || rtl8225_read(priv, 9) != 0x700)
        priv->rf_init = rtl8225_rf_init;
    else
        priv->rf_init = rtl8225z2_rf_init;

    rtl8225_write(priv, 0, 0x0B7);

    DBNSLog(@"hwaddr %.4x%.4x%.4x, rtl8187 V%d + %s\n",
           perm_addr[0],
           perm_addr[1],
           perm_addr[2],
           priv->asic_rev,
           priv->rf_init == rtl8225_rf_init ? "rtl8225" : "rtl8225z2");

    return 0;
}
bool RTL8187Jack::setChannel(UInt16 channel) {
    rtl8187_set_channel(_priv, channel);
    _channel = channel;
    return YES;
}
bool RTL8187Jack::getAllowedChannels(UInt16* channels) {
    if (!_devicePresent) return false;
    if (!_deviceInit) return false;
    
    *channels = 0xFFFF;
    
    return true;
}

bool RTL8187Jack::startCapture(UInt16 channel) {
    DBNSLog(@"Start capture");
	if (NICInitialized) {
        //		DBNSLog(@"Done.\n");
        rtl8187_start(_priv);
        setChannel(channel);
		return true;
	}
	else {
        //		DBNSLog(@"NIC not initialized. Canceled.\n");
		return false;
	}
}
bool RTL8187Jack::stopCapture() {
    //	DBNSLog(@"Stop capture : ");
	if (NICInitialized) {
        //		DBNSLog(@"Done.\n");
        rtl8187_stop(_priv);
		return true;
	}
	else {
        //		DBNSLog(@"NIC not initialized. Canceled.\n");
		return false;
	}
}

bool RTL8187Jack::_massagePacket(void *inBuf, void *outBuf, UInt16 len) {
    
    unsigned char* pData = (unsigned char *)inBuf;    
    KFrame *pFrame = (KFrame *)outBuf;
    
    struct rtl8187_rx_hdr *hdr;
    UInt32 flags;
    int signal;
    
    if (len < sizeof(struct rtl8187_rx_hdr))
        return false;
    
    bzero(pFrame, sizeof(KFrame));
    
    hdr = (struct rtl8187_rx_hdr *)(pData + (len-sizeof(struct rtl8187_rx_hdr)));
    flags = CFSwapInt32LittleToHost(hdr->flags);
	if (flags & (1 << 13)) {
//        DBNSLog(@"Bad CRC\n");
        return false;
    }
    pFrame->ctrl.len = (flags & 0xFFF) - 4;
    pFrame->ctrl.rate = (flags >> 20) & 0xF;
	signal = hdr->agc >> 1;
	if (pFrame->ctrl.rate > 3) {	/* OFDM rate */
		if (signal > 90)
			signal = 90;
		else if (signal < 25)
			signal = 25;
		signal = 90 - signal;
	} else {	/* CCK rate */
		if (signal > 95)
			signal = 95;
		else if (signal < 30)
			signal = 30;
		signal = 95 - signal;
	}
    pFrame->ctrl.signal = (UInt8)((100.0 / 65.0) * signal);
    pFrame->ctrl.silence = 0;

//    dumpFrame(pData, len);
            
    // Copy entire packet
    memcpy(pFrame->data, pData, pFrame->ctrl.len);
    
    //	dumpFrame(frame.data, len);
	return true;
}

int RTL8187Jack::WriteTxDescriptor(void* theFrame, UInt16 length, UInt8 rate) {
    struct rtl8187_tx_hdr *hdr = (struct rtl8187_tx_hdr *)(theFrame);
    memset(hdr, 0, sizeof(struct rtl8187_tx_hdr));
    UInt32 flags = length;
    flags |= RTL8187_TX_FLAG_NO_ENCRYPT;
//	flags |= control->rts_cts_rate << 19;
	flags |= rate << 24;
    hdr->flags = CFSwapInt32HostToLittle(flags);
    hdr->rts_duration = 0;
    hdr->len = 0;
    hdr->retry = 3; // CWMIN
	hdr->retry |= (7<<4); //CMAX
	hdr->retry |= (0<<8); //retry lim
    hdr->retry = CFSwapInt32HostToLittle(hdr->retry);
    return sizeof(struct rtl8187_tx_hdr);
}

bool RTL8187Jack::sendKFrame(KFrame* frame) {
    UInt8 aData[MAX_FRAME_BYTES];
    unsigned int descriptorLength;
    //    DBNSLog(@"sendKFrame %d", size);
    //    dumpFrame(data, size);
    descriptorLength = WriteTxDescriptor(aData, frame->ctrl.len, frame->ctrl.tx_rate);
    memcpy(aData+descriptorLength, frame->data, frame->ctrl.len);
    //send the frame
    if (_sendFrame(aData, frame->ctrl.len + descriptorLength) != kIOReturnSuccess)
        return NO;
    return YES;
}

IOReturn RTL8187Jack::_sendFrame(UInt8* data, IOByteCount size) {
    UInt32      numBytes;
    IOReturn    kr;
    
    if (!_devicePresent) return kIOReturnError;
    
    if (_interface == NULL) {
        DBNSLog(@"RTL8187Jack::_sendFrame called with NULL interface this is prohibited!\n");
        return kIOReturnError;
    }
    
//    DBNSLog(@"RT73Jack::_sendFrame");
//    dumpFrame(data, size);
    
    _lockDevice();
    
    memcpy(&_outputBuffer, data, size);

//    numBytes =  (((size)+63)&~63);
    numBytes = size;
//    DBNSLog(@"NumBytes %d", numBytes);
    kr = (*_interface)->WritePipe(_interface, 3, &_outputBuffer, numBytes);
    if (kr) {
        DBNSLog(@"kr %x", kr);
    }
    _unlockDevice();
    
    return kr;
}

void RTL8187Jack::dumpFrame(UInt8 *data, UInt16 size) {
    DBNSLog(@"--FRAME LENGTH %d--", size);
    int idx = 0;
    int i,j;
	for (i=0;i<size;i=i+8) {
        fprintf(stderr, "0x%.4x ", i);
        for (j=0;j<8;++j) {
            if (idx < size)
                fprintf(stderr, "%.2x ", data[idx]);
            else
                fprintf(stderr, "   ");
            idx += 1;
        }
        fprintf(stderr, "\n");
    }
}

RTL8187Jack::RTL8187Jack() {
}
RTL8187Jack::~RTL8187Jack() {
}

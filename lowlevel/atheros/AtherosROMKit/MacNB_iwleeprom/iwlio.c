/*
****************************************************************************
*
* iwleeprom - EEPROM reader/writer for intel wifi cards.
* Copyright (C) 2010, Alexander "ittrium" Kalinichenko <alexander@kalinichenko.org>
* ICQ: 152322, Skype: ittr1um		
* Copyright (C) 2010, Gennady "ShultZ" Kozlov <qpxtool@mail.ru>
*
* 
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
****************************************************************************
*/

#include "iwlio.h"

#define IWL_EEPROM_SIZE_4965 0x400
#define IWL_EEPROM_SIZE_5K   0x800

#define IWL_EEPROM_SIGNATURE   0x5a40
#define IWL_MMAP_LENGTH 0x1000

#define IWL_REG_OFFS_ADDR    0x0CC
#define IWL_CAL_OFFS_ADDR    0x0CE


#define CSR_WH_IF_CONFIG_REG 0x000
#define CSR_EEPROM_REG       0x02c
#define CSR_OTP_GP_REG       0x034

#define CSR_OTP_GP_REG_DEVICE_SELECT 0x00010000


#define PARSE_SHOW_CHANNELS

struct iwl_regulatory_item
{
	unsigned int offs;
	uint16_t	 data;
	uint16_t	 chn;
};

#define CHN_MASK 0x00FF
#define CHN_HT	 0x0100
#define CHN_2G   0x0200



const struct iwl_regulatory_item iwl_regulatory[] =
{
/*
	BAND 2.4GHz (@15e-179 with regulatory base @156)
*/
	{ 0x08, 0x0f6f,  1 | CHN_2G },
	{ 0x0A, 0x0f6f,  2 | CHN_2G },
	{ 0x0C, 0x0f6f,  3 | CHN_2G },
	{ 0x0E, 0x0f6f,  4 | CHN_2G },
	{ 0x10, 0x0f6f,  5 | CHN_2G },
	{ 0x12, 0x0f6f,  6 | CHN_2G },
	{ 0x14, 0x0f6f,  7 | CHN_2G },
	{ 0x16, 0x0f6f,  8 | CHN_2G },
	{ 0x18, 0x0f6f,  9 | CHN_2G },
	{ 0x1A, 0x0f6f, 10 | CHN_2G },
	{ 0x1C, 0x0f6f, 11 | CHN_2G },

	{ 0x1E, 0x0f21, 12 | CHN_2G },
	{ 0x20, 0x0f21, 13 | CHN_2G },
	{ 0x22, 0x0f21, 14 | CHN_2G },

/*
	BAND 5GHz
*/
// subband 5170-5320 MHz (@198-1af)
//	{ 0x42, 0x0fe1, 34 },
	{ 0x44, 0x0fe1, 36 },
//	{ 0x46, 0x0fe1, 38 },
	{ 0x48, 0x0fe1, 40 },
//	{ 0x4a, 0x0fe1, 42 },
	{ 0x4c, 0x0fe1, 44 },
//	{ 0x4e, 0x0fe1, 46 },
	{ 0x50, 0x0fe1, 48 },
	{ 0x52, 0x0f31, 52 },
	{ 0x54, 0x0f31, 56 },
	{ 0x56, 0x0f31, 60 },
	{ 0x58, 0x0f31, 64 },

// subband 5500-5700 MHz (@1b2-1c7)
	{ 0x5c, 0x0f31, 100 },
	{ 0x5e, 0x0f31, 104 },
	{ 0x60, 0x0f31, 108 },
	{ 0x62, 0x0f31, 112 },
	{ 0x64, 0x0f31, 116 },
	{ 0x66, 0x0f31, 120 },
	{ 0x68, 0x0f31, 124 },
	{ 0x6a, 0x0f31, 128 },
	{ 0x6c, 0x0f31, 132 },
	{ 0x6e, 0x0f31, 136 },
	{ 0x70, 0x0f31, 140 },

// subband 5725-5825 MHz (@1ca-1d5)
//	{ 0x74, 0x0fa1, 145 },
	{ 0x76, 0x0fa1, 149 },
	{ 0x78, 0x0fa1, 153 },
	{ 0x7a, 0x0fa1, 157 },
	{ 0x7c, 0x0fa1, 161 },
	{ 0x7e, 0x0fa1, 165 },

/*
	BAND 2.4GHz, HT40 channels (@1d8-1e5)
*/
	{ 0x82, 0x0e6f, 1 | CHN_HT | CHN_2G },
	{ 0x84, 0x0f6f, 2 | CHN_HT | CHN_2G },
	{ 0x86, 0x0f6f, 3 | CHN_HT | CHN_2G },
	{ 0x88, 0x0f6f, 4 | CHN_HT | CHN_2G },
	{ 0x8a, 0x0f6f, 5 | CHN_HT | CHN_2G },
	{ 0x8c, 0x0f6f, 6 | CHN_HT | CHN_2G },
	{ 0x8e, 0x0f6f, 7 | CHN_HT | CHN_2G },

/*
	BAND 5GHz, HT40 channels (@1e8-1fd)
*/
	{ 0x92, 0x0fe1,  36 | CHN_HT },
	{ 0x94, 0x0fe1,  44 | CHN_HT },
	{ 0x96, 0x0f31,  52 | CHN_HT },
	{ 0x98, 0x0f31,  60 | CHN_HT },
	{ 0x9a, 0x0f31, 100 | CHN_HT },
	{ 0x9c, 0x0f31, 108 | CHN_HT },
	{ 0x9e, 0x0f31, 116 | CHN_HT },
	{ 0xa0, 0x0f31, 124 | CHN_HT },
	{ 0xa2, 0x0f31, 132 | CHN_HT },
	{ 0xa4, 0x0f61, 149 | CHN_HT },
	{ 0xa6, 0x0f61, 157 | CHN_HT },

	{ 0, 0}
};


/* Intel 4965 devices */
const struct pci_id iwl4965_ids[] = {
	{ INTEL_PCI_VID,   0x4229, "PRO/Wireless 4965 AG or AGN [Kedron] Network Connection"},
	{ INTEL_PCI_VID,   0x4230, "PRO/Wireless 4965 AG or AGN [Kedron] Network Connection"},

	{ 0, 0, "" }
};

/* Intel 5x00/5x50 devices */
const struct pci_id iwl5k_ids[] = {
	{ INTEL_PCI_VID,   0x4232, "WiFi Link 5100"},
	{ INTEL_PCI_VID,   0x4235, "Ultimate N WiFi Link 5300"},
	{ INTEL_PCI_VID,   0x4236, "Ultimate N WiFi Link 5300"},
	{ INTEL_PCI_VID,   0x4237, "PRO/Wireless 5100 AGN [Shiloh] Network Connection"},
	{ INTEL_PCI_VID,   0x423a, "PRO/Wireless 5350 AGN [Echo Peak] Network Connection"},
	{ INTEL_PCI_VID,   0x423b, "PRO/Wireless 5350 AGN [Echo Peak] Network Connection"},
	{ INTEL_PCI_VID,   0x423c, "WiMAX/WiFi Link 5150"},
	{ INTEL_PCI_VID,   0x423d, "WiMAX/WiFi Link 5150"},

	{ 0, 0, "" }
};

/* Intel 6x00/6x50 devices */
const struct pci_id iwl6k_ids[] = {
	{ INTEL_PCI_VID,   0x0082, "6000 Series Gen2 (6x05)"},
	{ INTEL_PCI_VID,   0x0083, "Centrino Wireless-N 1000"},
	{ INTEL_PCI_VID,   0x0084, "Centrino Wireless-N 1000"},
	{ INTEL_PCI_VID,   0x0085, "6000 Series Gen2 (6x05)"},
	{ INTEL_PCI_VID,   0x0087, "Centrino Advanced-N + WiMAX 6250"},
	{ INTEL_PCI_VID,   0x0089, "Centrino Advanced-N + WiMAX 6250"},
	{ INTEL_PCI_VID,   0x008A, "Centrino Wireless-N 1030"},
	{ INTEL_PCI_VID,   0x008B, "Centrino Wireless-N 1030"},
	{ INTEL_PCI_VID,   0x0090, "Centrino Wireless-N 6x30"},
	{ INTEL_PCI_VID,   0x0091, "Centrino Wireless-N 6x30"},
	{ INTEL_PCI_VID,   0x0885, "WiFi+WiMAX 6050 Series Gen2"},
	{ INTEL_PCI_VID,   0x0886, "WiFi+WiMAX 6050 Series Gen2"},
	{ INTEL_PCI_VID,   0x088e, "Centrino Wireless-N 6x35"},
	{ INTEL_PCI_VID,   0x088f, "Centrino Wireless-N 6x35"},
	{ INTEL_PCI_VID,   0x422b, "Centrino Ultimate-N 6300"},
	{ INTEL_PCI_VID,   0x422c, "Centrino Advanced-N 6200"},
	{ INTEL_PCI_VID,   0x4238, "Centrino Ultimate-N 6300"},
	{ INTEL_PCI_VID,   0x4239, "Centrino Advanced-N 6200"},

	{ 0, 0, "" }
};

#define IWL_RF_CONFIG_TYPE_MSK 0x03
static const char* iwl_rf_config_type[4] = { "3x3", "2x2", "1x2", "MAX" };

static bool iwl_init_device(struct pcidev *dev)
{
	uint16_t data;

retry_init:
	if (!dev->ops->eeprom_release(dev)) return false;

	PCI_OUT32(0x100, PCI_IN32(0x100) | 0x20000000);
	usleep(20);

	PCI_OUT32(0x100, PCI_IN32(0x100) | 0x00800000);
	usleep(20);

	PCI_OUT32(0x240, PCI_IN32(0x240) | 0xFFFF0000);
	usleep(20);

	PCI_OUT32(0, PCI_IN32(0) | 0x00080000);
	usleep(20);
	
	PCI_OUT32(0x20c, PCI_IN32(0x20c) | 0x00880300);
	usleep(20);

	PCI_OUT32(0x24, PCI_IN32(0x24) | 0x00000004);
	usleep(50);

	if (!dev->ops->eeprom_lock(dev))
		return false;
	if (!dev->ops->eeprom_read16(dev, 0, &data))
		goto retry_init;

	if (!dev->ops->eeprom_release(dev))
		return false;
	if (debug)
		printf("Device init successfull.\n");
	return true;
}

static bool iwl6k_eeprom_check(struct pcidev *dev)
{
	if ( PCI_IN32(CSR_OTP_GP_REG) & CSR_OTP_GP_REG_DEVICE_SELECT)
		dev->ops->eeprom_writable = 1;
	printf("IWL 6k device NVM type: %s\n", dev->ops->eeprom_writable ? "EEPROM" : "OTP");
	return true;
}

static bool iwl_eeprom_lock(struct pcidev *dev)
{
	unsigned long data;
	if (!dev->mem) return false;
	PCI_OUT32(0, PCI_IN32(0) | 0x00200000);
	usleep(5);
	data = PCI_IN32(0);

	dev->eeprom_locked = ( 0x00200000 == (data & 0x00200000));
	if (!dev->eeprom_locked)
		printf("\nerr! ucode is using eeprom!\n");
	return (dev->eeprom_locked);
}

static bool iwl_eeprom_release(struct pcidev *dev)
{
	unsigned long data;
	if (!dev->mem) return false;
	PCI_OUT32(0, PCI_IN32(0) & ~0x00200000);
	usleep(5);
	data = PCI_IN32(0);

	dev->eeprom_locked = ( 0x00200000 == (data & 0x00200000));
	if (dev->eeprom_locked)
		printf("\nerr! software is still using eeprom!\n");
	dev->eeprom_locked = 0;
	return (!dev->eeprom_locked);
}

static bool iwl_eeprom_read16(struct pcidev *dev, uint32_t addr, uint16_t *value)
{
	unsigned int data = 0x0000FFFC & (addr << 1);

	PCI_OUT32(CSR_EEPROM_REG, data);
	usleep(50);
	data = PCI_IN32(CSR_EEPROM_REG);
	if ((data & 1) != 1) {
		printf("\nRead not complete! Timeout at %04x\n", addr);
		return false;
	}

	*value = (data & 0xFFFF0000) >> 16;
	return true;
}

static bool iwl_eeprom_write16(struct pcidev *dev, uint32_t addr, uint16_t value)
{
	uint32_t data = value;

	if (preserve_mac && ((addr>=0x2A && addr<0x30) || (addr>=0x92 && addr<0x97)))
		return true;
	if (preserve_calib && (addr >= 0x200))
		return true;

	data <<= 16;
	data |= 0x0000FFFC & (addr << 1);
	data |= 0x2;

	PCI_OUT32(CSR_EEPROM_REG, data);
	usleep(5000);

	PCI_OUT32(CSR_EEPROM_REG, 0x0000FFC & (addr << 1));
	usleep(50);
	data = PCI_IN32(CSR_EEPROM_REG);
	if ((data & 1) != 1) {
		printf("\nRead not complete! Timeout at %04x\n", addr);
		return false;
	}

	if (value != (data >> 16)) {
		printf("\nVerification error at %04x\n", addr);
		return false;
	}
	return true;
}

static void iwl_eeprom_patch11n(struct pcidev *dev)
{
	int idx;
	bool     is4965 = false;

	uint16_t value;
	uint16_t sig_offs,
			 sig[2],
			 reg_offs,
			 chn_offs,
			 chn_data,
			 new_data;

	if (dev->ops->eeprom_size == IWL_EEPROM_SIZE_4965) {
		is4965 = true;
		sig_offs = 0xC0;
	}


	printf("Patching card EEPROM...\n");

	if (dev->mem && !dev->ops->eeprom_lock(dev))
		return;

	printf("-> Changing subdev ID\n");

	dev->ops->eeprom_read16(dev, 0x14, &value);
	if (0x0006 == (value & 0x000F)) {
		dev->ops->eeprom_write16(dev, 0x14, (value & 0xFFF0) | 0x0001);
	}
/*
enabling .11n

W @8A << 00F0 (00B0) <- xxxx xxxx x1xx xxxx
W @8C << 103E (603F) <- x001 xxxx xxxx xxx0
*/

	printf("-> Enabling 11n mode\n");
// SKU_CAP
	dev->ops->eeprom_read16(dev, 0x8A, &value);
	if (0x0040 != (value & 0x0040)) {
		printf("  SKU CAP\n");
		dev->ops->eeprom_write16(dev, 0x8A, value | 0x0040);
	}

// OEM_MODE
	dev->ops->eeprom_read16(dev, 0x8C, &value);
//	if (0x1000 != (value & 0x7001)) {  // 4965 & 5k
	if (0x1000 != (value & 0x7000)) {  // 6k
		printf("  OEM MODE\n");
//		dev->ops->eeprom_write16(dev, 0x8C, (value & 0x9FFE) | 0x1000); // 4965 & 5k
		dev->ops->eeprom_write16(dev, 0x8C, (value & 0x9FFF) | 0x1000); // 6k
	}

	printf("-> Checking regulatory and adding channels...\n");
// reading regulatory offset
	if (is4965)
		reg_offs = 0x005f;
	else
		dev->ops->eeprom_read16(dev, 0xCC, &reg_offs);
	reg_offs <<= 1;
	printf("Regulatory base: %04x\n", reg_offs);
	sig_offs = reg_offs+2;

/*
writing SKU ID - 'MoW' signature
*/
	dev->ops->eeprom_read16(dev, sig_offs, sig );
	dev->ops->eeprom_read16(dev, sig_offs+2, sig+1 );

	if (0x6f4d != sig[0])
		dev->ops->eeprom_write16(dev, sig_offs, 0x6f4d);
	if (0x0057 != (sig[1] & 0x00FF))
		dev->ops->eeprom_write16(dev, sig_offs+2, (sig[1] & 0xFF00) | 0x0057);

/*
writing channels regulatory...
*/
	for (idx=0; iwl_regulatory[idx].offs; idx++) {
		chn_offs = reg_offs + iwl_regulatory[idx].offs;
		new_data = iwl_regulatory[idx].data;
		dev->ops->eeprom_read16(dev, chn_offs, &chn_data);

		if (new_data != chn_data) {
			printf("  %3d (%s%s)   %2d->%2d dBm, flags %02x->%02x\n",
					 iwl_regulatory[idx].chn & CHN_MASK,
					(iwl_regulatory[idx].chn & CHN_2G) ? "2.4G" : "5G",
					(iwl_regulatory[idx].chn & CHN_HT) ? ", HT40" : "",
					chn_data >> 8, new_data >> 8,
					chn_data & 0xFF, new_data & 0xFF
			);
			dev->ops->eeprom_write16(dev, chn_offs, new_data);
		}
	}

	if (dev->mem)
		dev->ops->eeprom_release(dev);
	printf("\nCard EEPROM patched successfully\n");
}


#ifdef PARSE_SHOW_CHANNELS
static void iwl_eeprom_parse_channels(struct pcidev *dev, uint16_t reg_offs)
{
	uint16_t chn_data;
	int idx;

	printf("Enabled channels:\n");

	for (idx=0; iwl_regulatory[idx].offs; idx++) {
		dev->ops->eeprom_read16(dev, reg_offs + iwl_regulatory[idx].offs, &chn_data);
		if (chn_data) {
			printf("  %3d (%s%s) %d dBm, flags %02x\n",
					iwl_regulatory[idx].chn & CHN_MASK,
					(iwl_regulatory[idx].chn & CHN_2G) ? "2.4G" : "5G",
					(iwl_regulatory[idx].chn & CHN_HT) ? ", HT" : "",
					chn_data >> 8,
					chn_data & 0xFF
			);
		}
	}
}
#endif


static void iwl_eeprom_parse(struct pcidev *dev)
{
	uint16_t vid,did,svid,sdid,ver;

	bool mode11n;
	uint16_t sku_cap,
			 oem_mode,
			 sig[2],
			 mac[3],
			 radio;

	bool     is4965 = false;
	uint16_t sig_offs = 0x158;
	uint16_t reg_offs,
			 cal_offs;

	if (dev->ops->eeprom_size == IWL_EEPROM_SIZE_4965) {
		is4965 = true;
		sig_offs = 0xC0;
	}
	
	dev->ops->eeprom_read16(dev, 0x0e, &vid);
	dev->ops->eeprom_read16(dev, 0x10, &did);
	dev->ops->eeprom_read16(dev, 0x12, &svid);
	dev->ops->eeprom_read16(dev, 0x14, &sdid);
	dev->ops->eeprom_read16(dev, 0x88, &ver);

	printf("\nDevice ID   : %04x:%04x, %04x:%04x\n",	vid, did, svid, sdid);
	printf("EEPROM ver  : %04x\n", ver);

	dev->ops->eeprom_read16(dev, 0x8A, &sku_cap);
	dev->ops->eeprom_read16(dev, 0x8C, &oem_mode);

	if (is4965)
		reg_offs = 0x005f;
	else
		dev->ops->eeprom_read16(dev, IWL_REG_OFFS_ADDR, &reg_offs);
	reg_offs <<= 1;
	printf("Regulatory data  @%04x\n", reg_offs);


	dev->ops->eeprom_read16(dev, IWL_CAL_OFFS_ADDR, &cal_offs);
	cal_offs <<= 1;
	printf("Calibration data @%04x\n", cal_offs);


	sig_offs = reg_offs+2;
	dev->ops->eeprom_read16(dev, sig_offs, sig);
	dev->ops->eeprom_read16(dev, sig_offs+2, sig+1);

	mode11n = (0x0040 == ( sku_cap & 0x0040)) &&
//	 		  (0x1000 == ( oem_mode & 0x7001)) && // 4965 & 5k cards
	 		  (0x1000 == ( oem_mode & 0x7000)) && // 6k cards
			  (0x6f4d == sig[0]) &&
			  (0x0057 == (sig[1] & 0x00FF));

	printf("\nSKU CAP : %04x\n", sku_cap);
	printf("OEM MODE: %04x\n", oem_mode);
	printf("SIG [0] : %04x\n", sig[0]);
	printf("SIG [1] : %04x\n", sig[1]);

	dev->ops->eeprom_read16(dev, 0x2a, mac);
	dev->ops->eeprom_read16(dev, 0x2c, mac+1);
	dev->ops->eeprom_read16(dev, 0x2e, mac+2);
	dev->ops->eeprom_read16(dev, 0x90, &radio);


	printf("MAC address : %02x:%02x:%02x:%02x:%02x:%02x\n",
			mac[0] & 0xFF,  mac[0] >> 8, 
			mac[1] & 0xFF,  mac[1] >> 8, 
			mac[2] & 0xFF,  mac[2] >> 8);
	printf("RF config [%04X]: %s\n  Tx antenna: %s%s%s\n  Rx antenna: %s%s%s\n",
		radio, iwl_rf_config_type[radio & IWL_RF_CONFIG_TYPE_MSK],
		((radio >> 8) & 1) ? "A" : "",
		((radio >> 8) & 2) ? "B" : "",
		((radio >> 8) & 4) ? "C" : "",
		((radio >>12) & 1) ? "A" : "",
		((radio >>12) & 2) ? "B" : "",
		((radio >>12) & 4) ? "C" : ""
	);
	printf("Mode 802.11n: %sabled\n", mode11n ? "en" : "dis");


// 6k checksum...

	uint16_t c=0, b;
	int16_t i;

	for (i=0; i<0x580; i+=2) {
	//for (i=2; i<dev->ops->eeprom_size-2; i+=2) {
		dev->ops->eeprom_read16(dev, i+2, &b);
		c ^= b;
	}
	dev->ops->eeprom_read16(dev, dev->ops->eeprom_size-2, &b);
	printf("CSUM test  : %04x\n", c);
	printf("CSUM stored: %04x\n", b);

#ifdef PARSE_SHOW_CHANNELS
	if (!debug) return;
	iwl_eeprom_parse_channels(dev, reg_offs);
#endif
}

struct io_driver io_iwl4965 = {
	.name             = "iwl4965",
	.valid_ids		  = (struct pci_id*) &iwl4965_ids,
	.mmap_size        = IWL_MMAP_LENGTH,
	.eeprom_size      = IWL_EEPROM_SIZE_4965,
	.eeprom_signature = IWL_EEPROM_SIGNATURE,
	.eeprom_writable  = true,

	.init_device     = &iwl_init_device,
	.eeprom_init     = NULL,
	.eeprom_check    = NULL,
	.eeprom_lock     = &iwl_eeprom_lock,
	.eeprom_release  = &iwl_eeprom_release,
	.eeprom_read16   = &iwl_eeprom_read16,
	.eeprom_write16  = &iwl_eeprom_write16,
	.eeprom_patch11n = &iwl_eeprom_patch11n,
	.eeprom_parse    = &iwl_eeprom_parse,
	.pdata			 = NULL
};

struct io_driver io_iwl5k = {
	.name             = "iwl5k",
	.valid_ids		  = (struct pci_id*) &iwl5k_ids,
	.mmap_size        = IWL_MMAP_LENGTH,
	.eeprom_size      = IWL_EEPROM_SIZE_5K,
	.eeprom_signature = IWL_EEPROM_SIGNATURE,
	.eeprom_writable  = true,

	.init_device     = &iwl_init_device,
	.eeprom_init     = NULL,
	.eeprom_check    = NULL,
	.eeprom_lock     = &iwl_eeprom_lock,
	.eeprom_release  = &iwl_eeprom_release,
	.eeprom_read16   = &iwl_eeprom_read16,
	.eeprom_write16  = &iwl_eeprom_write16,
	.eeprom_patch11n = &iwl_eeprom_patch11n,
	.eeprom_parse    = &iwl_eeprom_parse,
	.pdata			 = NULL
};

struct io_driver io_iwl6k = {
	.name             = "iwl6k",
	.valid_ids		  = (struct pci_id*) &iwl6k_ids,
	.mmap_size        = IWL_MMAP_LENGTH,
	.eeprom_size      = IWL_EEPROM_SIZE_5K,
	.eeprom_signature = IWL_EEPROM_SIGNATURE,
	.eeprom_writable  = true,

	.init_device     = &iwl_init_device,
	.eeprom_init     = NULL,
	.eeprom_check    = &iwl6k_eeprom_check,
	.eeprom_lock     = &iwl_eeprom_lock,
	.eeprom_release  = &iwl_eeprom_release,
	.eeprom_read16   = &iwl_eeprom_read16,
	.eeprom_write16  = &iwl_eeprom_write16,
	.eeprom_patch11n = &iwl_eeprom_patch11n,
	.eeprom_parse    = &iwl_eeprom_parse,
	.pdata			 = NULL
};


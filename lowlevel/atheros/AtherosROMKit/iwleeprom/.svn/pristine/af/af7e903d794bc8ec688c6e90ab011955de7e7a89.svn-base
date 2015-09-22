/*
****************************************************************************
*
* iwleeprom - EEPROM reader/writer for intel wifi cards.
* Copyright (C) 2010, Alexander "ittrium" Kalinichenko <alexander@kalinichenko.org>
* ICQ: 152322, Skype: ittr1um		
* Copyright (C) 2010,2012, Gennady "ShultZ" Kozlov <qpxtool@mail.ru>
*
*
* some values and HW identify code got from Atheros ath9k Linux driver
* Copyright (c) 2008-2012 Atheros Communications Inc.
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

#include <linux/types.h>
#include "ath9kio.h"

#define LE16(x) (x)

#define AR9300_PWR_TABLE_OFFSET		0
#define ATH9K_EEPROM_SIZE           0x1000
#define ATH9K_EEPROM_SIGNATURE      0xA55A
#define ATH9K_MMAP_LENGTH          0x10000
#define ATH9300_MMAP_LENGTH        0x20000

#define ATH9300_EEPROM_SIZE			0x400
#define COMP_HDR_LEN				4
#define COMP_CKSUM_LEN				2
#define EEPROM_DATA_LEN_9485		1088

#define AR5416_EEPROM_S             2
#define AR5416_EEPROM_OFFSET        0x2000

#define AR5416_OPFLAGS_11A          0x01
#define AR5416_OPFLAGS_11G          0x02
#define AR5416_OPFLAGS_N_5G_HT40    0x04
#define AR5416_OPFLAGS_N_2G_HT40    0x08
#define AR5416_OPFLAGS_N_5G_HT20    0x10
#define AR5416_OPFLAGS_N_2G_HT20    0x20


#define AR_SREV_VERSION_5416_PCI    0x00D
#define AR_SREV_VERSION_5416_PCIE   0x00C
#define AR_SREV_VERSION_9100        0x014
#define AR_SREV_VERSION_9160        0x040
#define AR_SREV_VERSION_9280        0x080
#define AR_SREV_VERSION_9285        0x0C0
#define AR_SREV_VERSION_9287        0x180
#define AR_SREV_VERSION_9271        0x140
#define AR_SREV_VERSION_9300        0x1c0
#define AR_SREV_REVISION_9300_20    2 /* 2.0 and 2.1 */
#define AR_SREV_VERSION_9330        0x200
#define AR_SREV_VERSION_9485        0x240
#define AR_SREV_VERSION_9340        0x300
#define AR_SREV_VERSION_9580        0x1c0
#define AR_SREV_VERSION_9462        0x280

#define AR_RADIO_SREV_MAJOR         0xf0
#define AR_RAD5133_SREV_MAJOR       0x30
#define AR_RAD2133_SREV_MAJOR       0xb0
#define AR_RAD5122_SREV_MAJOR       0x70
#define AR_RAD2122_SREV_MAJOR       0xf0

#define AR_PHY_BASE     0x9800
#define AR_PHY(_n)      (AR_PHY_BASE + ((_n)<<2))


#define AR_SREV_9100 \
	(macVer == AR_SREV_VERSION_9100)
#define AR_SREV_9280_10_OR_LATER \
	(macVer >= AR_SREV_VERSION_9280)
#define AR_SREV_9300_20_OR_LATER \
	((macVer > AR_SREV_VERSION_9300) || \
	 ((macVer == AR_SREV_VERSION_9300) && \
	  (macRev >= AR_SREV_REVISION_9300_20)))
#define AR_SREV_9330 \
	(macVer == AR_SREV_VERSION_9330)
#define AR_SREV_9485 \
	(macVer == AR_SREV_VERSION_9485)

#define AR_SREV                     ((AR_SREV_9100) ? 0x0600 : 0x4020)
#define AR_SREV_ID                  ((AR_SREV_9100) ? 0x00000FFF : 0x000000FF)
#define AR_SREV_VERSION             0x000000F0
#define AR_SREV_VERSION_S           4
#define AR_SREV_REVISION            0x00000007
#define AR_SREV_VERSION2            0xFFFC0000
#define AR_SREV_VERSION2_S          18
#define AR_SREV_TYPE2               0x0003F000
#define AR_SREV_TYPE2_S             12
#define AR_SREV_TYPE2_CHAIN         0x00001000
#define AR_SREV_TYPE2_HOST_MODE     0x00002000
#define AR_SREV_REVISION2           0x00000F00
#define AR_SREV_REVISION2_S         8


#define AR_GPIO_IN_OUT              0x4048
#define AR_GPIO_OE_OUT              (AR_SREV_9300_20_OR_LATER ? 0x4050 : 0x404c)
#define AR_GPIO_OE_OUT_DRV          0x3
#define AR_GPIO_OE_OUT_DRV_NO       0x0
#define AR_GPIO_OE_OUT_DRV_LOW      0x1
#define AR_GPIO_OE_OUT_DRV_HI       0x2
#define AR_GPIO_OE_OUT_DRV_ALL      0x3

#define AR_GPIO_OUTPUT_MUX1                      (AR_SREV_9300_20_OR_LATER ? 0x4068 : 0x4060)

#define AR_EEPROM_STATUS_DATA                    (AR_SREV_9300_20_OR_LATER ? 0x4084 : 0x407c)
#define AR_EEPROM_STATUS_DATA_VAL                0x0000ffff
#define AR_EEPROM_STATUS_DATA_VAL_S              0
#define AR_EEPROM_STATUS_DATA_BUSY               0x00010000
#define AR_EEPROM_STATUS_DATA_BUSY_ACCESS        0x00020000
#define AR_EEPROM_STATUS_DATA_PROT_ACCESS        0x00040000
#define AR_EEPROM_STATUS_DATA_ABSENT_ACCESS      0x00080000

#define AR9300_BASE_ADDR_4K		0xfff
#define AR9300_BASE_ADDR		0x3ff
#define AR9300_BASE_ADDR_512	0x1ff

#define AR9300_OTP_SIZE          0x1000
#define AR9300_OTP_BASE			0x14000
#define AR9300_OTP_STATUS		0x15f18
#define AR9300_OTP_STATUS_TYPE		0x7
#define AR9300_OTP_STATUS_VALID		0x4
#define AR9300_OTP_STATUS_ACCESS_BUSY	0x2
#define AR9300_OTP_STATUS_SM_BUSY	0x1
#define AR9300_OTP_READ_DATA		0x15f1c

#define AR9300_CUSTOMER_DATA_SIZE    20

// AR9300 eeprom data compression type from ath9k driver
enum AR9300_CompressAlgorithm {
	AR9300_CompressNone = 0,
	AR9300_CompressLzma,
	AR9300_CompressPairs,
	AR9300_CompressBlock,
	AR9300_Compress4,
	AR9300_Compress5,
	AR9300_Compress6,
	AR9300_Compress7,
};

struct eepFlags {
	uint8_t opFlags;
	uint8_t eepMisc;
}; // __packed;

struct ar9300_base_eep_hdr {
	__le16 regDmn[2];
	/* 4 bits tx and 4 bits rx */
	uint8_t txrxMask;
	struct eepFlags opCapFlags;
	uint8_t rfSilent;
	uint8_t blueToothOptions;
	uint8_t deviceCap;
	/* takes lower byte in eeprom location */
	uint8_t deviceType;
	/* offset in dB to be added to beginning
	 * of pdadc table in calibration
	 */
	int8_t pwrTableOffset;
	uint8_t params_for_tuning_caps[2];
	/*
	 * bit0 - enable tx temp comp
	 * bit1 - enable tx volt comp
	 * bit2 - enable fastClock - default to 1
	 * bit3 - enable doubling - default to 1
	 * bit4 - enable internal regulator - default to 1
	 */
	uint8_t featureEnable;
	/* misc flags: bit0 - turn down drivestrength */
	uint8_t miscConfiguration;
	uint8_t eepromWriteEnableGpio;
	uint8_t wlanDisableGpio;
	uint8_t wlanLedGpio;
	uint8_t rxBandSelectGpio;
	uint8_t txrxgain;
	/* SW controlled internal regulator fields */
	__le32 swreg;
}; // __packed;

struct ar9300_eeprom {
	uint8_t eepromVersion;
	uint8_t templateVersion;
	uint8_t macAddr[6];
	uint8_t custData[AR9300_CUSTOMER_DATA_SIZE];

	struct ar9300_base_eep_hdr baseEepHeader;
};

static const struct ar9300_eeprom ar9300_default = {
	.eepromVersion = 2,
	.templateVersion = 2,
	.macAddr = {0, 2, 3, 4, 5, 6},
	.custData = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	.baseEepHeader = {
		.regDmn = { LE16(0), LE16(0x1f) },
		.txrxMask =  0x77, /* 4 bits tx and 4 bits rx */
		.opCapFlags = {
			.opFlags = AR5416_OPFLAGS_11G | AR5416_OPFLAGS_11A,
			.eepMisc = 0,
		},
		.rfSilent = 0,
		.blueToothOptions = 0,
		.deviceCap = 0,
		.deviceType = 5, /* takes lower byte in eeprom location */
		.pwrTableOffset = AR9300_PWR_TABLE_OFFSET,
		.params_for_tuning_caps = {0, 0},
		.featureEnable = 0x0c,
		 /*
		  * bit0 - enable tx temp comp - disabled
		  * bit1 - enable tx volt comp - disabled
		  * bit2 - enable fastClock - enabled
		  * bit3 - enable doubling - enabled
		  * bit4 - enable internal regulator - disabled
		  * bit5 - enable pa predistortion - disabled
		  */
		.miscConfiguration = 0, /* bit0 - turn down drivestrength */
		.eepromWriteEnableGpio = 3,
		.wlanDisableGpio = 0,
		.wlanLedGpio = 8,
		.rxBandSelectGpio = 0xff,
		.txrxgain = 0,
		.swreg = 0,
	 }
};

static const struct ar9300_eeprom ar9300_x113 = {
	.eepromVersion = 2,
	.templateVersion = 6,
	.macAddr = {0x00, 0x03, 0x7f, 0x0, 0x0, 0x0},
	.custData = {"x113-023-f0000"},
	.baseEepHeader = {
		.regDmn = { LE16(0), LE16(0x1f) },
		.txrxMask =  0x77, /* 4 bits tx and 4 bits rx */
		.opCapFlags = {
			.opFlags = AR5416_OPFLAGS_11A,
			.eepMisc = 0,
		},
		.rfSilent = 0,
		.blueToothOptions = 0,
		.deviceCap = 0,
		.deviceType = 5, /* takes lower byte in eeprom location */
		.pwrTableOffset = AR9300_PWR_TABLE_OFFSET,
		.params_for_tuning_caps = {0, 0},
		.featureEnable = 0x0d,
		 /*
		  * bit0 - enable tx temp comp - disabled
		  * bit1 - enable tx volt comp - disabled
		  * bit2 - enable fastClock - enabled
		  * bit3 - enable doubling - enabled
		  * bit4 - enable internal regulator - disabled
		  * bit5 - enable pa predistortion - disabled
		  */
		.miscConfiguration = 0, /* bit0 - turn down drivestrength */
		.eepromWriteEnableGpio = 6,
		.wlanDisableGpio = 0,
		.wlanLedGpio = 8,
		.rxBandSelectGpio = 0xff,
		.txrxgain = 0x21,
		.swreg = 0,
	 }
};


static const struct ar9300_eeprom ar9300_h112 = {
	.eepromVersion = 2,
	.templateVersion = 3,
	.macAddr = {0x00, 0x03, 0x7f, 0x0, 0x0, 0x0},
	.custData = {"h112-241-f0000"},
	.baseEepHeader = {
		.regDmn = { LE16(0), LE16(0x1f) },
		.txrxMask =  0x77, /* 4 bits tx and 4 bits rx */
		.opCapFlags = {
			.opFlags = AR5416_OPFLAGS_11G | AR5416_OPFLAGS_11A,
			.eepMisc = 0,
		},
		.rfSilent = 0,
		.blueToothOptions = 0,
		.deviceCap = 0,
		.deviceType = 5, /* takes lower byte in eeprom location */
		.pwrTableOffset = AR9300_PWR_TABLE_OFFSET,
		.params_for_tuning_caps = {0, 0},
		.featureEnable = 0x0d,
		/*
		 * bit0 - enable tx temp comp - disabled
		 * bit1 - enable tx volt comp - disabled
		 * bit2 - enable fastClock - enabled
		 * bit3 - enable doubling - enabled
		 * bit4 - enable internal regulator - disabled
		 * bit5 - enable pa predistortion - disabled
		 */
		.miscConfiguration = 0, /* bit0 - turn down drivestrength */
		.eepromWriteEnableGpio = 6,
		.wlanDisableGpio = 0,
		.wlanLedGpio = 8,
		.rxBandSelectGpio = 0xff,
		.txrxgain = 0x10,
		.swreg = 0,
	}
};


static const struct ar9300_eeprom ar9300_x112 = {
	.eepromVersion = 2,
	.templateVersion = 5,
	.macAddr = {0x00, 0x03, 0x7f, 0x0, 0x0, 0x0},
	.custData = {"x112-041-f0000"},
	.baseEepHeader = {
		.regDmn = { LE16(0), LE16(0x1f) },
		.txrxMask =  0x77, /* 4 bits tx and 4 bits rx */
		.opCapFlags = {
			.opFlags = AR5416_OPFLAGS_11G | AR5416_OPFLAGS_11A,
			.eepMisc = 0,
		},
		.rfSilent = 0,
		.blueToothOptions = 0,
		.deviceCap = 0,
		.deviceType = 5, /* takes lower byte in eeprom location */
		.pwrTableOffset = AR9300_PWR_TABLE_OFFSET,
		.params_for_tuning_caps = {0, 0},
		.featureEnable = 0x0d,
		/*
		 * bit0 - enable tx temp comp - disabled
		 * bit1 - enable tx volt comp - disabled
		 * bit2 - enable fastclock - enabled
		 * bit3 - enable doubling - enabled
		 * bit4 - enable internal regulator - disabled
		 * bit5 - enable pa predistortion - disabled
		 */
		.miscConfiguration = 0, /* bit0 - turn down drivestrength */
		.eepromWriteEnableGpio = 6,
		.wlanDisableGpio = 0,
		.wlanLedGpio = 8,
		.rxBandSelectGpio = 0xff,
		.txrxgain = 0x0,
		.swreg = 0,
	}
};

static const struct ar9300_eeprom ar9300_h116 = {
	.eepromVersion = 2,
	.templateVersion = 4,
	.macAddr = {0x00, 0x03, 0x7f, 0x0, 0x0, 0x0},
	.custData = {"h116-041-f0000"},
	.baseEepHeader = {
		.regDmn = { LE16(0), LE16(0x1f) },
		.txrxMask =  0x33, /* 4 bits tx and 4 bits rx */
		.opCapFlags = {
			.opFlags = AR5416_OPFLAGS_11G | AR5416_OPFLAGS_11A,
			.eepMisc = 0,
		},
		.rfSilent = 0,
		.blueToothOptions = 0,
		.deviceCap = 0,
		.deviceType = 5, /* takes lower byte in eeprom location */
		.pwrTableOffset = AR9300_PWR_TABLE_OFFSET,
		.params_for_tuning_caps = {0, 0},
		.featureEnable = 0x0d,
		 /*
		  * bit0 - enable tx temp comp - disabled
		  * bit1 - enable tx volt comp - disabled
		  * bit2 - enable fastClock - enabled
		  * bit3 - enable doubling - enabled
		  * bit4 - enable internal regulator - disabled
		  * bit5 - enable pa predistortion - disabled
		  */
		.miscConfiguration = 0, /* bit0 - turn down drivestrength */
		.eepromWriteEnableGpio = 6,
		.wlanDisableGpio = 0,
		.wlanLedGpio = 8,
		.rxBandSelectGpio = 0xff,
		.txrxgain = 0x10,
		.swreg = 0,
	 }
};

static const struct ar9300_eeprom *ar9300_eep_templates[] = {
	&ar9300_default,
	&ar9300_x112,
	&ar9300_h116,
	&ar9300_h112,
	&ar9300_x113,
};

static const struct ar9300_eeprom *ar9003_eeprom_struct_find_by_id(int id)
{
#define N_LOOP (sizeof(ar9300_eep_templates) / sizeof(ar9300_eep_templates[0]))
	int it;

	for (it = 0; it < N_LOOP; it++)
		if (ar9300_eep_templates[it]->templateVersion == id)
			return ar9300_eep_templates[it];
	return NULL;
#undef N_LOOP
}

/* Atheros 9k devices */
const struct pci_id ath9k_ids[] = {
	{ ATHEROS_PCI_VID, 0x0023, "AR5416 (AR5008 family) Wireless Adapter (PCI)" },
	{ ATHEROS_PCI_VID, 0x0024, "AR5416 (AR5008 family) Wireless Adapter (PCI-E)" },
	{ ATHEROS_PCI_VID, 0x0027, "AR9160 802.11abgn Wireless Adapter (PCI)" },
	{ ATHEROS_PCI_VID, 0x0029, "AR922X Wireless Adapter (PCI)" },
	{ ATHEROS_PCI_VID, 0x002A, "AR928X Wireless Adapter (PCI-E)" },
	{ ATHEROS_PCI_VID, 0x002B, "AR9285 Wireless Adapter (PCI-E)" },
	{ ATHEROS_PCI_VID, 0x002C, "AR2427 Wireless Adapter (PCI-E)" }, /* PCI-E 802.11n bonded out */
	{ ATHEROS_PCI_VID, 0x002D, "AR9287 Wireless Adapter (PCI)" },
	{ ATHEROS_PCI_VID, 0x002E, "AR9287 Wireless Adapter (PCI-E)" },
	{ 0, 0, "" }
};

/* AR9300 devices */
const struct pci_id ath9300_ids[] = {
	{ ATHEROS_PCI_VID, 0x0030, "AR9300 Wireless Adapter (PCI-E)" },
	{ ATHEROS_PCI_VID, 0x0031, "AR9340 Wireless Adapter (PCI-E)" },
	{ ATHEROS_PCI_VID, 0x0032, "AR9485 Wireless Adapter (PCI-E)" },
	{ ATHEROS_PCI_VID, 0x0033, "AR9580 Wireless Adapter (PCI-E)" },
	{ ATHEROS_PCI_VID, 0x0034, "AR9462 Wireless Adapter (PCI-E)" },
	{ 0, 0, "" }
};

static struct {
	uint32_t version;
	const char * name;
} ath_mac_bb_names[] = {
	/* Devices with external radios */
	{ AR_SREV_VERSION_5416_PCI,  "5416" },
	{ AR_SREV_VERSION_5416_PCIE, "5418" },
	{ AR_SREV_VERSION_9100,      "9100" },
	{ AR_SREV_VERSION_9160,      "9160" },
	/* Single-chip solutions */
	{ AR_SREV_VERSION_9280,      "9280" },
	{ AR_SREV_VERSION_9285,      "9285" },
	{ AR_SREV_VERSION_9287,      "9287" },
	{ AR_SREV_VERSION_9271,      "9271" },
	{ AR_SREV_VERSION_9300,      "9300" },
	{ AR_SREV_VERSION_9330,      "9330" },
	{ AR_SREV_VERSION_9485,      "9485" },
	{ AR_SREV_VERSION_9340,      "9340" },
	{ AR_SREV_VERSION_9462,      "9462" },
	{ 0, ""}
};

struct ath9300_private {
	bool eeprom_filled;
	uint8_t eeprom_raw[ATH9300_EEPROM_SIZE];
	bool otp_filled;
	uint8_t otp_raw[AR9300_OTP_SIZE];
	struct ar9300_eeprom eeprom;
};

static const char *ath9k_hw_name(uint16_t mac_bb_version)
{
	int i;
	for (i=0; ath_mac_bb_names[i].version; i++)
		if (ath_mac_bb_names[i].version == mac_bb_version)
			return ath_mac_bb_names[i].name;
	return "????";
}

/* For devices with external radios */
static struct {
	uint16_t version;
	const char * name;
} ath_rf_names[] = {
	{ AR_RAD5133_SREV_MAJOR,	"5133" },
	{ AR_RAD5122_SREV_MAJOR,	"5122" },
	{ AR_RAD2133_SREV_MAJOR,	"2133" },
	{ AR_RAD2122_SREV_MAJOR,	"2122" },
	{ 0, ""}
};

static const char *ath9k_rf_name(uint16_t rf_version)
{
	int i;
	for (i=0; ath_rf_names[i].version; i++)
		if (ath_rf_names[i].version == rf_version)
			return ath_rf_names[i].name;
	return "????";
}

#define WAIT_TIMEOUT 10000 /* x10 us */

int32_t	 short_eeprom_base,
		 short_eeprom_size;
uint16_t macVer,
		 macRev,
		 rfVer,
		 rfRev;
bool	 isPCIE;

static bool ath9k_eeprom_read16(struct pcidev *dev, uint32_t addr, uint16_t *value);
static bool ath9k_eeprom_write16(struct pcidev *dev, uint32_t addr, uint16_t value);

static void ath9k_get_hw_version(struct pcidev *dev)
{
	uint32_t val;

	val = PCI_IN32(AR_SREV) & AR_SREV_ID;
	if (val == 0xFF) {
		val = PCI_IN32(AR_SREV);
		macVer = (val & AR_SREV_VERSION2) >> AR_SREV_TYPE2_S;
		macRev = (val & AR_SREV_REVISION2) >> AR_SREV_REVISION2_S;
		isPCIE = (val & AR_SREV_TYPE2_HOST_MODE) ? 0 : 1;
	} else {
		if (!AR_SREV_9100)
			macVer = (val & AR_SREV_VERSION) >> AR_SREV_VERSION_S;
		macRev = val & AR_SREV_REVISION;
		if (macVer == AR_SREV_VERSION_5416_PCIE)
			isPCIE = 1;
	}
}

// ************************************

static void ath9k_get_rf_version(struct pcidev *dev)
{
	int i;
	PCI_OUT32(AR_PHY(0), 0x00000007);
//	ENABLE_REGWRITE_BUFFER(ah);
	PCI_OUT32(AR_PHY(0x36), 0x00007058);
	for (i = 0; i < 8; i++)
		PCI_OUT32(AR_PHY(0x20), 0x00010000);
//	REGWRITE_BUFFER_FLUSH(ah);
//	DISABLE_REGWRITE_BUFFER(ah);
	rfVer = (PCI_IN32(AR_PHY(0x100)) >> 24) & 0xff;
	if (!(rfVer & AR_RADIO_SREV_MAJOR))
		rfVer = AR_RAD5133_SREV_MAJOR;
}

// ************************************

static bool ath9k_eeprom_lock(struct pcidev *dev) {
	return true;
}

static bool ath9k_eeprom_init(struct pcidev *dev) {
// for device-less operation
	if (!dev->mem)
		return true;
// reading HW version, some register addresses depends on it
	ath9k_get_hw_version(dev);
	printf("HW: AR%s (PCI%s) rev %04x\n", ath9k_hw_name(macVer), isPCIE ? "-E" : "", macRev);
	if (AR_SREV_9280_10_OR_LATER) {
		printf("RF: integrated\n");
	} else {
		ath9k_get_rf_version(dev);
		printf("RF: AR%s\n", ath9k_rf_name(rfVer & AR_RADIO_SREV_MAJOR));
	}
	return true;
}

static bool ath9300_eeprom_init(struct pcidev *dev) {
	ath9k_eeprom_init(dev);
	struct ath9300_private *pdata = (struct ath9300_private*) malloc(sizeof(struct ath9300_private));
	if (!pdata) {
		printf("Can't allocate memory for ath9300_private structure!\n");
		return false;
	}
	dev->ops->pdata = (void*) pdata;
	pdata->eeprom_filled = false;
	pdata->otp_filled = false;
	return true;
}

static bool ath9300_nvm_read(struct pcidev *dev, uint32_t addr, uint16_t len, uint8_t *buf)
{
	uint16_t tval;
	uint16_t tlen = len;
	while (tlen) {
		dev->ops->eeprom_read16(dev, addr & ~1, &tval);
		buf[len-tlen] =  (addr & 1) ? (tval >> 8) & 0xFF : tval & 0xFF;
		addr--;
		tlen--;
	}
	return true;
}

static bool ath9k_eeprom_crc_calc(struct pcidev *dev, uint16_t *crcp)
{
	uint16_t crc = 0, data;
	int i;

	if (!short_eeprom_size)
		return false;
	printf("Calculating EEPROM CRC");

	for (i=0; i<short_eeprom_size; i+=2) {
		if (2 == i) continue;
		if (!dev->ops->eeprom_read16(dev, short_eeprom_base + i, &data)) {
			printf(" !ERROR!\n");
			return false;
		}
		crc ^= data;
		if (!(i & 0xFFC0)) printf(".");
	}
	crc ^= 0xFFFF;
	if (crcp)
		*crcp = crc;
	printf("\n");
	return true;
}

static bool ath9300_eeprom_crc_calc(struct pcidev *dev, uint32_t addr, uint16_t len, uint16_t *crcp)
{
	uint16_t crc = 0;
	uint8_t *buf = (uint8_t*) malloc(len * sizeof(uint8_t));
	bool r = false;

	if (!len)
		return false;
	printf("Calculating EEPROM CRC...\n");

	if (!ath9300_nvm_read(dev, addr, len, buf)) 
		goto crc_done;
		
	while(len) {
		len--;
		crc += buf[len];
	}
	if (crcp)
		*crcp = crc;
	r = true;

crc_done:
	free(buf);
	return r;
}

static bool ath9k_eeprom_crc_update(struct pcidev *dev)
{
	uint16_t crc, crc_n;
	if (short_eeprom_base) {
		dev->ops->eeprom_read16(dev, short_eeprom_base+2, &crc);
		ath9k_eeprom_crc_calc(dev, &crc_n);
		if (crc != crc_n) {
			printf("Updating CRC: %04x -> %04x\n", crc, crc_n);
			dev->ops->eeprom_write16(dev, short_eeprom_base+2, crc_n);
		}
	}
	return true;
}

static bool ath9k_eeprom_release(struct pcidev *dev) {
	return true;
}

static bool ath9300_eeprom_release(struct pcidev *dev) {
	if (dev->ops->pdata) {
		free((struct ath9300_private*)dev->ops->pdata);
		dev->ops->pdata = NULL;
	}
	return true;
}

static bool ath9k_eeprom_read16(struct pcidev *dev, uint32_t addr, uint16_t *value)
{
	int32_t data;
	int i;

// requesting data
	data = PCI_IN32(AR5416_EEPROM_OFFSET + ((addr >> 1) << AR5416_EEPROM_S));

// waiting...
	for(i = WAIT_TIMEOUT; i; i--) {
		usleep(10);
		data = PCI_IN32(AR_EEPROM_STATUS_DATA);
		if ( 0 == (data & (AR_EEPROM_STATUS_DATA_BUSY | AR_EEPROM_STATUS_DATA_PROT_ACCESS))) {
			*value = data & AR_EEPROM_STATUS_DATA_VAL;
//			if (addr < 0x10) printf("[%04x] %04x %04x\n", addr, *value, data);
			return true;
		}
	}
	printf("timeout reading ath9k eeprom at %04x!\n", addr);
	return false;
}

static bool ath9300_eeprom_fill(struct pcidev *dev)
{
	int addr;
	bool (*read16_op)(struct pcidev *dev, uint32_t addr, uint16_t *value);
	struct ath9300_private *pdata = (struct ath9300_private*) dev->ops->pdata;
	if (!dev->mem)
		read16_op = &buf_read16;
	else
		read16_op = &ath9k_eeprom_read16;

	printf("Filling ath9300 EEPROM...");
	for (addr=0; addr<ATH9300_EEPROM_SIZE; addr+=2) {
		if (!read16_op(dev, addr, (uint16_t*)(pdata->eeprom_raw + addr)))
			return false;
	}
	pdata->eeprom_filled = true;
	printf(" DONE\n");
	return true;
}

static bool ath9300_eeprom_read16(struct pcidev *dev, uint32_t addr, uint16_t *value)
{
	struct ath9300_private *pdata = (struct ath9300_private*) dev->ops->pdata;
	if (addr > ATH9300_EEPROM_SIZE) {
		printf("OTP address out of range: %04x\n", addr);
		return false;
	}
	if (!pdata) {
		printf("ath9300 EEPROM not initialized yet!");
		return false;
	}
	if (!pdata->eeprom_filled && !ath9300_eeprom_fill(dev)) {
		printf("error filling ath9300 EEPROM");
		return false;
	}
	*value = *(uint16_t*)(pdata->eeprom_raw + addr);
	return true;
}

static bool ath9300_otp_read32(struct pcidev *dev, uint32_t addr, uint32_t *value)
{
	int32_t data;
	int i;
	if (addr > AR9300_OTP_SIZE) {
		printf("OTP address out of range: %04x\n", addr);
		return false;
	}

	data = PCI_IN32(AR9300_OTP_BASE + addr);
	for(i = WAIT_TIMEOUT; i; i--) {
		usleep(10);
		data = PCI_IN32(AR9300_OTP_STATUS);
		if (AR9300_OTP_STATUS_VALID == (data & AR9300_OTP_STATUS_TYPE)) {
			*value = PCI_IN32(AR9300_OTP_READ_DATA);
			return true;
		}
	}
	printf("timeout reading ath9300 OTP at %04x!\n", addr);
	return false;
}

static bool ath9300_otp_fill(struct pcidev *dev)
{
	uint32_t addr;
	struct ath9300_private *pdata = (struct ath9300_private*) dev->ops->pdata;
	if (!dev->mem)
	printf("Filling ath9300 OTP...");
	for (addr=0; addr<AR9300_OTP_SIZE; addr+=4) {
		if (!ath9300_otp_read32(dev, addr, (uint32_t*)(pdata->otp_raw + addr)))
			return false;
	}
	pdata->otp_filled = true;
	printf(" DONE\n");
	return true;
}

static bool ath9300_otp_read16(struct pcidev *dev, uint32_t addr, uint16_t *value)
{
	struct ath9300_private *pdata = (struct ath9300_private*) dev->ops->pdata;
	if (addr > AR9300_OTP_SIZE) {
		printf("OTP address out of range: %04x\n", addr);
		return false;
	}
	if (!dev->mem) {
		printf("OTP functions can't be used in device-less mode!\n");
		return false;
	}
	if (!pdata) {
		printf("ath9300 OTP not initialized yet!\n");
		return false;
	}
	if (!pdata->otp_filled && !ath9300_otp_fill(dev)) {
		printf("error filling ath9300 OTP data\n");
		return false;
	}
	*value = *(uint16_t*)(pdata->otp_raw + addr);
	return true;
}

static bool ath9k_eeprom_check(struct pcidev *dev)
{
	uint16_t data;
	printf("Checking NVM size...\n");

// reading EEPROM size and setting it's base address
// thanks to Inv from forum.ixbt.com
	if (dev->ops->eeprom_read16(dev, 128, &data) && (376 == data)) {
		short_eeprom_base = 128;
		short_eeprom_size = 376;
		goto ssize_ok;
	}
	if (dev->ops->eeprom_read16(dev, 512, &data) && (3256 == data)) {
		short_eeprom_base =  512;
		short_eeprom_size = 3256;
		goto ssize_ok;
	}
	if (dev->ops->eeprom_read16(dev, 256, &data) && (727 == data)) {
		short_eeprom_base = 256;
		short_eeprom_size = 727;
		goto ssize_ok;
	}

	short_eeprom_base = 0;
	short_eeprom_size = 0;
	printf("Can't get ath9k eeprom size!\n");
	return false;
ssize_ok:
	printf("ath9k short eeprom base: %d  size: %d\n",
		short_eeprom_base,
		short_eeprom_size);
	return true;
}

static bool ath9300_eeprom_check_header(struct pcidev *dev, uint32_t addr)
{
	uint16_t data[2] = { 0, 0 };
	bool r;
	dev->ops->eeprom_read16(dev, addr,   data);
	dev->ops->eeprom_read16(dev, addr+2, data+1);
	r = (data[0] != 0 || data[1] !=0) && (data[0] != 0xFFFF || data[1] != 0xFFFF);
	if (r)
		short_eeprom_base = addr;
	printf("%s %04x%04x  @%04x r=%d\n", __func__, data[0], data[1], addr, r);
	return r;
}

static void ath9300_unpack_header(uint8_t *data, int *code, int *reference,
				   int *length, int *major, int *minor)
{
	unsigned long value[4];

	value[0] = data[0];
	value[1] = data[1];
	value[2] = data[2];
	value[3] = data[3];
	*code = ((value[0] >> 5) & 0x0007);
	*reference = (value[0] & 0x001f) | ((value[1] >> 2) & 0x0020);
	*length = ((value[1] << 4) & 0x07f0) | ((value[2] >> 4) & 0x000f);
	*major = (value[2] & 0x000f);
	*minor = (value[3] & 0x00ff);
}

static bool ath9300_uncompress_block(uint8_t *mptr,
				    int mdataSize,
				    uint8_t *block,
				    int size)
{
	int it;
	int spot;
	int offset;
	int length;

	spot = 0;

	for (it = 0; it < size; it += (length+2)) {
		offset = block[it];
		offset &= 0xff;
		spot += offset;
		length = block[it+1];
		length &= 0xff;

		if (length > 0 && spot >= 0 && spot+length <= mdataSize) {
#if 0
			printf("Restore at %d: spot=%d offset=%d length=%d\n",
				it, spot, offset, length);
#endif
			memcpy(&mptr[spot], &block[it+2], length);
			spot += length;
		} else if (length > 0) {
#if 0
			printf("Bad restore at %d: spot=%d offset=%d length=%d\n",
				it, spot, offset, length);
#endif
			return false;
		}
	}
	return true;
}

static bool ath9300_eeprom_decompress(struct pcidev *dev, int code, int reference, uint32_t addr, int length)
{
	struct ath9300_private *pdata = dev->ops->pdata;
	uint8_t *buf = (uint8_t*) malloc (length * sizeof(uint8_t) + COMP_HDR_LEN);
	int elen = (sizeof(struct ar9300_eeprom) > length) ? length : sizeof(struct ar9300_eeprom);
	const struct ar9300_eeprom *eep = NULL;

	if (!ath9300_nvm_read(dev, addr, length + COMP_HDR_LEN, buf))
		return false;
#if 0
	printf("ar9300_eeprom structure size: %d\n", sizeof(struct ar9300_eeprom));
#endif
	switch(code) {
		case AR9300_CompressNone:
			printf("eeprom uncompressed\n");
			//memcpy((void*)pdata->eeprom, (void*) (buf + COMP_HDR_LEN), length);
			memcpy(&pdata->eeprom, buf + COMP_HDR_LEN, elen);
			break;
		case AR9300_CompressBlock:
			printf("compression : block\n");
			if (reference) {
				eep = ar9003_eeprom_struct_find_by_id(reference);
				if (eep == NULL) {
					printf("can't find reference eeprom struct %d\n", reference);
					free(buf);
					return false;
				}
				memcpy(&pdata->eeprom, eep, sizeof(struct ar9300_eeprom));
			}
			ath9300_uncompress_block((uint8_t*)&pdata->eeprom, sizeof(struct ar9300_eeprom),
					buf + COMP_HDR_LEN, length);
			break;
		default:
			printf("unknown compression type!\n");
			free(buf);
			return false;
	}
	free(buf);
	return true;
}

static bool ath9300_eeprom_check(struct pcidev *dev)
{
//	uint32_t addr;
	printf("Trying EEPROM access...\n");
	dev->ops->eeprom_read16  = &ath9300_eeprom_read16;
/*
//  this code invalid for device-less operation

	if (AR_SREV_9485)
		addr = AR9300_BASE_ADDR_4K;
	else if (AR_SREV_9330)
		addr = AR9300_BASE_ADDR_512;
	else
		addr = AR9300_BASE_ADDR;

	if (ath9300_eeprom_check_header(dev, addr) ||
		ath9300_eeprom_check_header(dev, AR9300_BASE_ADDR_512))
*/
	if (ath9300_eeprom_check_header(dev, AR9300_BASE_ADDR_4K) ||
		ath9300_eeprom_check_header(dev, AR9300_BASE_ADDR) ||
		ath9300_eeprom_check_header(dev, AR9300_BASE_ADDR_512))
	{
		dev->ops->eeprom_writable = 1;
		goto found;
	}
	if (!dev->mem) {
		printf("Header not found in buffer!\n");
		return false;
	}

	printf("Trying OTP access...\n");
	dev->ops->eeprom_read16  = &ath9300_otp_read16;
	if (
		ath9300_eeprom_check_header(dev, AR9300_BASE_ADDR) ||
		ath9300_eeprom_check_header(dev, AR9300_BASE_ADDR_512))
	{
		dev->ops->eeprom_writable = 0;
		dev->ops->eeprom_size = AR9300_OTP_SIZE;
		goto found;
	}
	printf("NVM type identification failed!\n");
	return false;

found:
//	printf("NVM found at: %04x\n", short_eeprom_base);
	printf("AR9300 device NVM type: %s  (data block @%04x)\n",
		dev->ops->eeprom_writable ? "EEPROM" : "OTP",
		short_eeprom_base);

	uint8_t header[4];
	int code;
	int reference, length, major, minor;
	uint16_t crc, scrc;

	while (!short_eeprom_size && short_eeprom_base>0) {
		ath9300_nvm_read(dev, short_eeprom_base, COMP_HDR_LEN, header);

		ath9300_unpack_header(header, &code, &reference,
			    &length, &major, &minor);
		printf("Found block at %x: code=%d ref=%d length=%d major=%d minor=%d (RAW: %08x)\n",
				short_eeprom_base, code, reference, length, major, minor, *(uint32_t*)header);

		if ((!AR_SREV_9485 && length >= 1024) ||
		    (AR_SREV_9485 && length > EEPROM_DATA_LEN_9485) ||
			(length > short_eeprom_base) ||
			!length) {
			printf("Bad header!!!\n");
			short_eeprom_base -= COMP_HDR_LEN;
			continue;
		}
		ath9300_eeprom_crc_calc(dev, short_eeprom_base - COMP_HDR_LEN, length, &crc);
		ath9300_nvm_read(dev, short_eeprom_base - length - COMP_HDR_LEN, 2, (uint8_t*)&scrc);
		printf("CRC (stored): %04x\n", scrc);
		printf("CRC (eval)  : %04x\n", crc);

		if (crc != scrc) {
			printf("Bad checksum!\n");
//			short_eeprom_base -= (6 + length);
//			continue;
			short_eeprom_base = 0;
			short_eeprom_size = 0;
			goto eeprom_check_done;
		}
		ath9300_eeprom_decompress(dev, code, reference, short_eeprom_base, length);

		short_eeprom_size = length + COMP_HDR_LEN + COMP_CKSUM_LEN;
		short_eeprom_base -= short_eeprom_size - 1;
	}

eeprom_check_done:
	printf("ath9300 short eeprom base: %d (0x%04x) size: %d\n",
		short_eeprom_base,
		short_eeprom_base,
		short_eeprom_size);
	return true;
}

static bool ath9k_eeprom_write16(struct pcidev *dev, uint32_t addr, uint16_t value)
{
	int i;
	uint32_t data;
	uint32_t
			gpio_out_mux1,
			gpio_oe_out,
			gpio_in_out;

	if (preserve_mac && short_eeprom_base && (addr>=(short_eeprom_base+0x0c) && addr<(short_eeprom_base+0x12)))
		return true;

// selecting GPIO
	gpio_out_mux1 = PCI_IN32(AR_GPIO_OUTPUT_MUX1);
	PCI_OUT32(AR_GPIO_OUTPUT_MUX1, gpio_out_mux1 & 0xFFF07FFF);
	usleep(10);

// setting GPIO pin direction
	gpio_oe_out = PCI_IN32(AR_GPIO_OE_OUT);
	PCI_OUT32(AR_GPIO_OE_OUT, (gpio_oe_out & 0xFFFFFF3F) | 0x000000C0);
	usleep(10);

// setting GPIO pin level
	gpio_in_out = PCI_IN32(AR_GPIO_IN_OUT);
	PCI_OUT32(AR_GPIO_IN_OUT, gpio_in_out & 0xFFFFFFF7);
	usleep(10);

// sending data
	PCI_OUT16(AR5416_EEPROM_OFFSET + ((addr >> 1) << AR5416_EEPROM_S), value);

// waiting...
	for(i = WAIT_TIMEOUT; i; i--) {
		usleep(10);
		memcpy(&data, dev->mem + AR_EEPROM_STATUS_DATA, 4);
		if ( 0 == (data & ( AR_EEPROM_STATUS_DATA_BUSY | 
							AR_EEPROM_STATUS_DATA_BUSY_ACCESS | 
							AR_EEPROM_STATUS_DATA_PROT_ACCESS | 
							AR_EEPROM_STATUS_DATA_ABSENT_ACCESS)) )
			break;
	}

// restoring GPIO state...
	PCI_OUT32(AR_GPIO_IN_OUT, gpio_in_out);
	PCI_OUT32(AR_GPIO_OE_OUT, gpio_oe_out);
	PCI_OUT32(AR_GPIO_OUTPUT_MUX1, gpio_out_mux1);

	if (!i)
		printf("timeout writing ath9k eeprom at %04x!\n", addr);
	return !!i;
}

static bool ath9k_eeprom_write16_short(struct pcidev *dev, uint32_t addr, uint16_t value)
{
	// just return, if address out of 'short' eeprom bounds
	if ((addr <= short_eeprom_base) || (addr >= (short_eeprom_base + short_eeprom_size)))
		return false;
	return ath9k_eeprom_write16(dev, addr, value);
}

static void ath9k_eeprom_patch11n(struct pcidev *dev)
{
	uint16_t
		opCap,
		regDmn;
	if (!short_eeprom_size) {
		printf("Unknown short EEPROM size -> can't patch!\n");
		return;
	}

	printf("Patching card EEPROM...\n");

	dev->ops->eeprom_read16(dev, short_eeprom_base + 6, &opCap);
	dev->ops->eeprom_read16(dev, short_eeprom_base + 8, &regDmn);

	printf("Reg. domain : %04x\n", regDmn);
	printf("       Bands: %s%s\n",
		(opCap & AR5416_OPFLAGS_11A) ? " 5GHz" : "",
		(opCap & AR5416_OPFLAGS_11G) ? " 2.4GHz" : "");

	regDmn = 0x6A;
	if (opCap & AR5416_OPFLAGS_11G)
		opCap &= ~(AR5416_OPFLAGS_N_2G_HT20 | AR5416_OPFLAGS_N_2G_HT40);
	if (opCap & AR5416_OPFLAGS_11A)
		opCap &= ~(AR5416_OPFLAGS_N_5G_HT20 | AR5416_OPFLAGS_N_5G_HT40);

	dev->ops->eeprom_write16(dev, short_eeprom_base + 6, opCap);
	dev->ops->eeprom_write16(dev, short_eeprom_base + 8, regDmn);

	ath9k_eeprom_crc_update(dev);
}

static void ath9k_eeprom_parse(struct pcidev *dev)
{
	uint16_t
		crc, crc_n,
		opCap,
		regDmn,
		mac[3];

	dev->ops->eeprom_read16(dev, short_eeprom_base + 2, &crc);
	dev->ops->eeprom_read16(dev, short_eeprom_base + 6, &opCap);
	dev->ops->eeprom_read16(dev, short_eeprom_base + 8, &regDmn);

	dev->ops->eeprom_read16(dev, short_eeprom_base +12, mac);
	dev->ops->eeprom_read16(dev, short_eeprom_base +14, mac+1);
	dev->ops->eeprom_read16(dev, short_eeprom_base +16, mac+2);

	printf("MAC address : %02x:%02x:%02x:%02x:%02x:%02x\n",
			mac[0] & 0xFF,  mac[0] >> 8, 
			mac[1] & 0xFF,  mac[1] >> 8, 
			mac[2] & 0xFF,  mac[2] >> 8);

	printf("Reg. domain : %04x\n", regDmn);
	printf("Capabilities: %04x\n"
		   "       Bands: %s%s\n", opCap,
		(opCap & AR5416_OPFLAGS_11A) ? " 5GHz" : "",
		(opCap & AR5416_OPFLAGS_11G) ? " 2.4GHz" : "");

	printf("       HT 2G: %s%s\n",
		(opCap & AR5416_OPFLAGS_N_2G_HT20) ? "":" HT20",
		(opCap & AR5416_OPFLAGS_N_2G_HT40) ? "":" HT40");
	printf("       HT 5G: %s%s\n",
		(opCap & AR5416_OPFLAGS_N_5G_HT20) ? "":" HT20",
		(opCap & AR5416_OPFLAGS_N_5G_HT40) ? "":" HT40");

	printf("CRC (stored): %04x\n", crc);

	if (ath9k_eeprom_crc_calc(dev, &crc_n))
		printf("CRC (eval)  : %04x\n", crc_n);
	else
		printf("error calculating CRC!\n");
}

static void ath9300_eeprom_parse(struct pcidev *dev)
{
	struct ath9300_private *pdata = (struct ath9300_private*) dev->ops->pdata;
	printf("\n==== BASE ====\n");
	printf("Version     : %02x\n", pdata->eeprom.eepromVersion);
	printf("Template    : %02x\n", pdata->eeprom.templateVersion);
	printf("Cust data   : %s\n", pdata->eeprom.custData);
	printf("MAC address : %02x:%02x:%02x:%02x:%02x:%02x\n",
			pdata->eeprom.macAddr[0],
			pdata->eeprom.macAddr[1],
			pdata->eeprom.macAddr[2],
			pdata->eeprom.macAddr[3],
			pdata->eeprom.macAddr[4],
			pdata->eeprom.macAddr[5]);
	printf("Reg. domain : %04x %04x\n",
		pdata->eeprom.baseEepHeader.regDmn[0],
		pdata->eeprom.baseEepHeader.regDmn[1]);
	printf("Tx mask     : %d%d%d%d\n",
		(pdata->eeprom.baseEepHeader.txrxMask & 0x80)?1:0,
		(pdata->eeprom.baseEepHeader.txrxMask & 0x40)?1:0,
		(pdata->eeprom.baseEepHeader.txrxMask & 0x20)?1:0,
		(pdata->eeprom.baseEepHeader.txrxMask & 0x10)?1:0);
	printf("Rx mask     : %d%d%d%d\n",
		(pdata->eeprom.baseEepHeader.txrxMask & 0x08)?1:0,
		(pdata->eeprom.baseEepHeader.txrxMask & 0x04)?1:0,
		(pdata->eeprom.baseEepHeader.txrxMask & 0x02)?1:0,
		(pdata->eeprom.baseEepHeader.txrxMask & 0x01)?1:0);
	printf("Capabilities: %02x\n"
		   "       Bands:%s%s\n", pdata->eeprom.baseEepHeader.opCapFlags.opFlags,
		(pdata->eeprom.baseEepHeader.opCapFlags.opFlags & AR5416_OPFLAGS_11A) ? " 5GHz" : "",
		(pdata->eeprom.baseEepHeader.opCapFlags.opFlags & AR5416_OPFLAGS_11G) ? " 2.4GHz" : "");

	printf("       HT 2G:%s%s\n",
		(pdata->eeprom.baseEepHeader.opCapFlags.opFlags & AR5416_OPFLAGS_N_2G_HT20) ? "":" HT20",
		(pdata->eeprom.baseEepHeader.opCapFlags.opFlags & AR5416_OPFLAGS_N_2G_HT40) ? "":" HT40");
	printf("       HT 5G:%s%s\n",
		(pdata->eeprom.baseEepHeader.opCapFlags.opFlags & AR5416_OPFLAGS_N_5G_HT20) ? "":" HT20",
		(pdata->eeprom.baseEepHeader.opCapFlags.opFlags & AR5416_OPFLAGS_N_5G_HT40) ? "":" HT40");


	printf("Misc flags  : %02x\n", pdata->eeprom.baseEepHeader.opCapFlags.eepMisc);
	printf("Big endian  :  %x\n", pdata->eeprom.baseEepHeader.opCapFlags.eepMisc & 0x01);

	printf("\n==== MISC ====\n");
	printf("rfSilent       : %02x\n", pdata->eeprom.baseEepHeader.rfSilent);
	printf("BT options     : %02x\n", pdata->eeprom.baseEepHeader.blueToothOptions);
	printf("deviceCap      : %02x\n", pdata->eeprom.baseEepHeader.deviceCap);
	printf("deviceType     : %02x\n", pdata->eeprom.baseEepHeader.deviceType);
	printf("pwrTableOffset : %02x\n", pdata->eeprom.baseEepHeader.pwrTableOffset);
	printf("tuning params  : %02x %02x\n",
		pdata->eeprom.baseEepHeader.params_for_tuning_caps[0],
		pdata->eeprom.baseEepHeader.params_for_tuning_caps[1]);
	printf("featureEnable  : %02x\n", pdata->eeprom.baseEepHeader.featureEnable);
	printf("miscConfig     : %02x\n", pdata->eeprom.baseEepHeader.miscConfiguration);
	printf("txrxgain       : %02x\n", pdata->eeprom.baseEepHeader.txrxgain);
	printf("swreg          : %08x\n", pdata->eeprom.baseEepHeader.swreg);
	printf("\n==== GPIO ====\n");
	printf("EEPROM WE      : %02x\n", pdata->eeprom.baseEepHeader.eepromWriteEnableGpio);
	printf("WLAN disable   : %02x\n", pdata->eeprom.baseEepHeader.wlanDisableGpio);
	printf("WLAN LED       : %02x\n", pdata->eeprom.baseEepHeader.wlanLedGpio);
	printf("Rx band select : %02x\n", pdata->eeprom.baseEepHeader.rxBandSelectGpio);
}

struct io_driver io_ath9k = {
	.name             = "ath9k",
	.valid_ids        = (struct pci_id*) &ath9k_ids,
	.mmap_size        = ATH9K_MMAP_LENGTH,
	.eeprom_size	  = ATH9K_EEPROM_SIZE,
	.eeprom_signature = ATH9K_EEPROM_SIGNATURE,
	.eeprom_writable  = true,

	.init_device	 = NULL,
	.eeprom_init     = &ath9k_eeprom_init,
	.eeprom_check    = &ath9k_eeprom_check,
	.eeprom_lock     = &ath9k_eeprom_lock,
	.eeprom_release  = &ath9k_eeprom_release,
	.eeprom_read16   = &ath9k_eeprom_read16,
	.eeprom_write16  = &ath9k_eeprom_write16_short,
	.eeprom_patch11n = &ath9k_eeprom_patch11n,
	.eeprom_parse    = &ath9k_eeprom_parse,
	.pdata			 = NULL
};

struct io_driver io_ath9300 = {
	.name             = "ath9300",
	.valid_ids        = (struct pci_id*) &ath9300_ids,
	.mmap_size        = ATH9300_MMAP_LENGTH,
	.eeprom_size	  = ATH9300_EEPROM_SIZE,
	.eeprom_signature = ATH9K_EEPROM_SIGNATURE,
	.eeprom_writable  = true,

	.init_device	 = NULL,
	.eeprom_init     = &ath9300_eeprom_init,
	.eeprom_check    = &ath9300_eeprom_check,
	.eeprom_lock     = &ath9k_eeprom_lock,
	.eeprom_release  = &ath9300_eeprom_release,
	.eeprom_read16   = &ath9300_eeprom_read16,
	.eeprom_write16  = &ath9k_eeprom_write16_short,
	.eeprom_patch11n = NULL, // &ath9k_eeprom_patch11n,
	.eeprom_parse    = &ath9300_eeprom_parse,
	.pdata			 = NULL
};


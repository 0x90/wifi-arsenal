/*
 * Copyright (c) 2012 Qualcomm Atheros, Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef AR9003_EEPROM_H
#define AR9003_EEPROM_H

#include <linux/types.h>
#include <endian.h>

/* 16-bit offset location start of calibration struct */
#define AR9300_NUM_5G_CAL_PIERS      8
#define AR9300_NUM_2G_CAL_PIERS      3
#define AR9300_NUM_5G_20_TARGET_POWERS  8
#define AR9300_NUM_5G_40_TARGET_POWERS  8
#define AR9300_NUM_2G_CCK_TARGET_POWERS 2
#define AR9300_NUM_2G_20_TARGET_POWERS  3
#define AR9300_NUM_2G_40_TARGET_POWERS  3
/* #define AR9300_NUM_CTLS              21 */
#define AR9300_NUM_CTLS_5G           9
#define AR9300_NUM_CTLS_2G           12
#define AR9300_NUM_BAND_EDGES_5G     8
#define AR9300_NUM_BAND_EDGES_2G     4
#define AR9300_CUSTOMER_DATA_SIZE    20

#define AR9300_MAX_CHAINS            3

#define FREQ2FBIN(x, y)         ((y) ? ((x) - 2300) : (((x) - 4800) / 5))

/* Delta from which to start power to pdadc table */
/* This offset is used in both open loop and closed loop power control
 * schemes. In open loop power control, it is not really needed, but for
 * the "sake of consistency" it was kept. For certain AP designs, this
 * value is overwritten by the value in the flag "pwrTableOffset" just
 * before writing the pdadc vs pwr into the chip registers.
 */
#define AR9300_PWR_TABLE_OFFSET  0

/* byte addressable */
#define AR9300_EEPROM_SIZE (16*1024)

#define AR9300_BASE_ADDR_4K  0xfff
#define AR9300_BASE_ADDR     0x3ff
#define AR9300_BASE_ADDR_512 0x1ff

#define AR9300_OTP_BASE			0x14000
#define AR9300_OTP_STATUS		0x15f18
#define AR9300_OTP_STATUS_TYPE		0x7
#define AR9300_OTP_STATUS_VALID		0x4
#define AR9300_OTP_STATUS_ACCESS_BUSY	0x2
#define AR9300_OTP_STATUS_SM_BUSY	0x1
#define AR9300_OTP_READ_DATA		0x15f1c

struct eepFlags {
	uint8_t opFlags;
	uint8_t eepMisc;
} __attribute__ ((packed));

enum CompressAlgorithm {
	_CompressNone = 0,
	_CompressLzma,
	_CompressPairs,
	_CompressBlock,
	_Compress4,
	_Compress5,
	_Compress6,
	_Compress7,
};

struct ar9300_base_eep_hdr {
	int16_t regDmn[2];
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
	int32_t swreg;
} __attribute__ ((packed));

struct ar9300_modal_eep_header {
	/* 4 idle, t1, t2, b (4 bits per setting) */
	int32_t antCtrlCommon;
	/* 4 ra1l1, ra2l1, ra1l2, ra2l2, ra12 */
	int32_t antCtrlCommon2;
	/* 6 idle, t, r, rx1, rx12, b (2 bits each) */
	int16_t antCtrlChain[AR9300_MAX_CHAINS];
	/* 3 xatten1_db for AR9280 (0xa20c/b20c 5:0) */
	uint8_t xatten1DB[AR9300_MAX_CHAINS];
	/* 3  xatten1_margin for merlin (0xa20c/b20c 16:12 */
	uint8_t xatten1Margin[AR9300_MAX_CHAINS];
	int8_t tempSlope;
	int8_t voltSlope;
	/* spur channels in usual fbin coding format */
	uint8_t spurChans[AR_EEPROM_MODAL_SPURS];
	/* 3  Check if the register is per chain */
	int8_t noiseFloorThreshCh[AR9300_MAX_CHAINS];
	uint8_t reserved[11];
	int8_t quick_drop;
	uint8_t xpaBiasLvl;
	uint8_t txFrameToDataStart;
	uint8_t txFrameToPaOn;
	uint8_t txClip;
	int8_t antennaGain;
	uint8_t switchSettling;
	int8_t adcDesiredSize;
	uint8_t txEndToXpaOff;
	uint8_t txEndToRxOn;
	uint8_t txFrameToXpaOn;
	uint8_t thresh62;
	int32_t papdRateMaskHt20;
	int32_t papdRateMaskHt40;
	int16_t switchcomspdt;
	uint8_t xlna_bias_strength;
	uint8_t futureModal[7];
} __attribute__ ((packed));

struct ar9300_cal_data_per_freq_op_loop {
	int8_t refPower;
	/* pdadc voltage at power measurement */
	uint8_t voltMeas;
	/* pcdac used for power measurement   */
	uint8_t tempMeas;
	/* range is -60 to -127 create a mapping equation 1db resolution */
	int8_t rxNoisefloorCal;
	/*range is same as noisefloor */
	int8_t rxNoisefloorPower;
	/* temp measured when noisefloor cal was performed */
	uint8_t rxTempMeas;
} __attribute__ ((packed));

struct cal_tgt_pow_legacy {
	uint8_t tPow2x[4];
} __attribute__ ((packed));

struct cal_tgt_pow_ht {
	uint8_t tPow2x[14];
} __attribute__ ((packed));

struct cal_ctl_data_2g {
	uint8_t ctlEdges[AR9300_NUM_BAND_EDGES_2G];
} __attribute__ ((packed));

struct cal_ctl_data_5g {
	uint8_t ctlEdges[AR9300_NUM_BAND_EDGES_5G];
} __attribute__ ((packed));

struct ar9300_BaseExtension_1 {
	uint8_t ant_div_control;
	uint8_t future[3];
	uint8_t tempslopextension[8];
	int8_t quick_drop_low;
	int8_t quick_drop_high;
} __attribute__ ((packed));

struct ar9300_BaseExtension_2 {
	int8_t    tempSlopeLow;
	int8_t    tempSlopeHigh;
	uint8_t   xatten1DBLow[AR9300_MAX_CHAINS];
	uint8_t   xatten1MarginLow[AR9300_MAX_CHAINS];
	uint8_t   xatten1DBHigh[AR9300_MAX_CHAINS];
	uint8_t   xatten1MarginHigh[AR9300_MAX_CHAINS];
} __attribute__ ((packed));

struct ar9300_eeprom {
	uint8_t eepromVersion;
	uint8_t templateVersion;
	uint8_t macAddr[6];
	uint8_t custData[AR9300_CUSTOMER_DATA_SIZE];

	struct ar9300_base_eep_hdr baseEepHeader;

	struct ar9300_modal_eep_header modalHeader2G;
	struct ar9300_BaseExtension_1 base_ext1;
	uint8_t calFreqPier2G[AR9300_NUM_2G_CAL_PIERS];
	struct ar9300_cal_data_per_freq_op_loop
	 calPierData2G[AR9300_MAX_CHAINS][AR9300_NUM_2G_CAL_PIERS];
	uint8_t calTarget_freqbin_Cck[AR9300_NUM_2G_CCK_TARGET_POWERS];
	uint8_t calTarget_freqbin_2G[AR9300_NUM_2G_20_TARGET_POWERS];
	uint8_t calTarget_freqbin_2GHT20[AR9300_NUM_2G_20_TARGET_POWERS];
	uint8_t calTarget_freqbin_2GHT40[AR9300_NUM_2G_40_TARGET_POWERS];
	struct cal_tgt_pow_legacy
	 calTargetPowerCck[AR9300_NUM_2G_CCK_TARGET_POWERS];
	struct cal_tgt_pow_legacy
	 calTargetPower2G[AR9300_NUM_2G_20_TARGET_POWERS];
	struct cal_tgt_pow_ht
	 calTargetPower2GHT20[AR9300_NUM_2G_20_TARGET_POWERS];
	struct cal_tgt_pow_ht
	 calTargetPower2GHT40[AR9300_NUM_2G_40_TARGET_POWERS];
	uint8_t ctlIndex_2G[AR9300_NUM_CTLS_2G];
	uint8_t ctl_freqbin_2G[AR9300_NUM_CTLS_2G][AR9300_NUM_BAND_EDGES_2G];
	struct cal_ctl_data_2g ctlPowerData_2G[AR9300_NUM_CTLS_2G];
	struct ar9300_modal_eep_header modalHeader5G;
	struct ar9300_BaseExtension_2 base_ext2;
	uint8_t calFreqPier5G[AR9300_NUM_5G_CAL_PIERS];
	struct ar9300_cal_data_per_freq_op_loop
	 calPierData5G[AR9300_MAX_CHAINS][AR9300_NUM_5G_CAL_PIERS];
	uint8_t calTarget_freqbin_5G[AR9300_NUM_5G_20_TARGET_POWERS];
	uint8_t calTarget_freqbin_5GHT20[AR9300_NUM_5G_20_TARGET_POWERS];
	uint8_t calTarget_freqbin_5GHT40[AR9300_NUM_5G_40_TARGET_POWERS];
	struct cal_tgt_pow_legacy
	 calTargetPower5G[AR9300_NUM_5G_20_TARGET_POWERS];
	struct cal_tgt_pow_ht
	 calTargetPower5GHT20[AR9300_NUM_5G_20_TARGET_POWERS];
	struct cal_tgt_pow_ht
	 calTargetPower5GHT40[AR9300_NUM_5G_40_TARGET_POWERS];
	uint8_t ctlIndex_5G[AR9300_NUM_CTLS_5G];
	uint8_t ctl_freqbin_5G[AR9300_NUM_CTLS_5G][AR9300_NUM_BAND_EDGES_5G];
	struct cal_ctl_data_5g ctlPowerData_5G[AR9300_NUM_CTLS_5G];
} __attribute__ ((packed));

#endif

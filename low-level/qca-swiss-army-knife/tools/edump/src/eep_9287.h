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

#ifndef EEP_9287_H
#define EEP_9287_H

#define AR9287_EEP_VER                  0xE
#define AR9287_EEP_START_LOC            128
#define AR9287_DATA_SZ                  32
#define AR9287_MAX_CHAINS               2
#define AR9287_NUM_2G_CAL_PIERS         3
#define AR9287_NUM_2G_CCK_TARGET_POWERS 3
#define AR9287_NUM_2G_20_TARGET_POWERS  3
#define AR9287_NUM_2G_40_TARGET_POWERS  3
#define AR9287_NUM_CTLS              	12
#define AR9287_NUM_BAND_EDGES        	4
#define AR9287_PD_GAIN_ICEPTS           1
#define AR9287_EEPMISC_WOW              0x02

struct base_eep_ar9287_header {
	uint16_t length;
	uint16_t checksum;
	uint16_t version;
	uint8_t opCapFlags;
	uint8_t eepMisc;
	uint16_t regDmn[2];
	uint8_t macAddr[6];
	uint8_t rxMask;
	uint8_t txMask;
	uint16_t rfSilent;
	uint16_t blueToothOptions;
	uint16_t deviceCap;
	uint32_t binBuildNumber;
	uint8_t deviceType;
	uint8_t openLoopPwrCntl;
	int8_t pwrTableOffset;
	int8_t tempSensSlope;
	int8_t tempSensSlopePalOn;
	uint8_t futureBase[29];
} __attribute__ ((packed));

struct modal_eep_ar9287_header {
	uint32_t antCtrlChain[AR9287_MAX_CHAINS];
	uint32_t antCtrlCommon;
	int8_t antennaGainCh[AR9287_MAX_CHAINS];
	uint8_t switchSettling;
	uint8_t txRxAttenCh[AR9287_MAX_CHAINS];
	uint8_t rxTxMarginCh[AR9287_MAX_CHAINS];
	int8_t adcDesiredSize;
	uint8_t txEndToXpaOff;
	uint8_t txEndToRxOn;
	uint8_t txFrameToXpaOn;
	uint8_t thresh62;
	int8_t noiseFloorThreshCh[AR9287_MAX_CHAINS];
	uint8_t xpdGain;
	uint8_t xpd;
	int8_t iqCalICh[AR9287_MAX_CHAINS];
	int8_t iqCalQCh[AR9287_MAX_CHAINS];
	uint8_t pdGainOverlap;
	uint8_t xpaBiasLvl;
	uint8_t txFrameToDataStart;
	uint8_t txFrameToPaOn;
	uint8_t ht40PowerIncForPdadc;
	uint8_t bswAtten[AR9287_MAX_CHAINS];
	uint8_t bswMargin[AR9287_MAX_CHAINS];
	uint8_t swSettleHt40;
	uint8_t version;
	uint8_t db1;
	uint8_t db2;
	uint8_t ob_cck;
	uint8_t ob_psk;
	uint8_t ob_qam;
	uint8_t ob_pal_off;
	uint8_t futureModal[30];
	struct spur_chan spurChans[AR_EEPROM_MODAL_SPURS];
} __attribute__ ((packed));

struct cal_data_op_loop_ar9287 {
	uint8_t pwrPdg[2][5];
	uint8_t vpdPdg[2][5];
	uint8_t pcdac[2][5];
	uint8_t empty[2][5];
} __attribute__ ((packed));

struct cal_data_per_freq_ar9287 {
	uint8_t pwrPdg[AR5416_NUM_PD_GAINS][AR9287_PD_GAIN_ICEPTS];
	uint8_t vpdPdg[AR5416_NUM_PD_GAINS][AR9287_PD_GAIN_ICEPTS];
} __attribute__ ((packed));

union cal_data_per_freq_ar9287_u {
	struct cal_data_op_loop_ar9287 calDataOpen;
	struct cal_data_per_freq_ar9287 calDataClose;
} __attribute__ ((packed));

struct cal_ctl_data_ar9287 {
	struct cal_ctl_edges
	ctlEdges[AR9287_MAX_CHAINS][AR9287_NUM_BAND_EDGES];
} __attribute__ ((packed));

struct ar9287_eeprom {
	struct base_eep_ar9287_header baseEepHeader;
	uint8_t custData[AR9287_DATA_SZ];
	struct modal_eep_ar9287_header modalHeader;
	uint8_t calFreqPier2G[AR9287_NUM_2G_CAL_PIERS];
	union cal_data_per_freq_ar9287_u
	calPierData2G[AR9287_MAX_CHAINS][AR9287_NUM_2G_CAL_PIERS];
	struct cal_target_power_leg
	calTargetPowerCck[AR9287_NUM_2G_CCK_TARGET_POWERS];
	struct cal_target_power_leg
	calTargetPower2G[AR9287_NUM_2G_20_TARGET_POWERS];
	struct cal_target_power_ht
	calTargetPower2GHT20[AR9287_NUM_2G_20_TARGET_POWERS];
	struct cal_target_power_ht
	calTargetPower2GHT40[AR9287_NUM_2G_40_TARGET_POWERS];
	uint8_t ctlIndex[AR9287_NUM_CTLS];
	struct cal_ctl_data_ar9287 ctlData[AR9287_NUM_CTLS];
	uint8_t padding;
} __attribute__ ((packed));

#endif /* EEP_9287_H */

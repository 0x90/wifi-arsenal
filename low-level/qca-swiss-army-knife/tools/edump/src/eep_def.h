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

#ifndef EEP_DEF_H
#define EEP_DEF_H

#define AR5416_MAX_CHAINS       3
#define AR5416_NUM_PD_GAINS     4
#define AR5416_NUM_BAND_EDGES   8
#define AR5416_NUM_5G_CAL_PIERS 8
#define AR5416_NUM_2G_CAL_PIERS 4
#define AR5416_NUM_CTLS         24
#define AR5416_NUM_5G_20_TARGET_POWERS  8
#define AR5416_NUM_5G_40_TARGET_POWERS  8
#define AR5416_NUM_2G_CCK_TARGET_POWERS 3
#define AR5416_NUM_2G_20_TARGET_POWERS  4
#define AR5416_NUM_2G_40_TARGET_POWERS  4

struct base_eep_header {
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
	uint8_t pwdclkind;
	uint8_t futureBase_1[2];
	uint8_t rxGainType;
	uint8_t dacHiPwrMode_5G;
	uint8_t openLoopPwrCntl;
	uint8_t dacLpMode;
	uint8_t txGainType;
	uint8_t rcChainMask;
	uint8_t desiredScaleCCK;
	uint8_t power_table_offset;
	uint8_t frac_n_5g;
	uint8_t futureBase_3[21];
} __attribute__ ((packed));

struct spur_chan {
	uint16_t spurChan;
	uint8_t spurRangeLow;
	uint8_t spurRangeHigh;
} __attribute__ ((packed));

struct modal_eep_header {
	uint32_t antCtrlChain[AR5416_MAX_CHAINS];
	uint32_t antCtrlCommon;
	uint8_t antennaGainCh[AR5416_MAX_CHAINS];
	uint8_t switchSettling;
	uint8_t txRxAttenCh[AR5416_MAX_CHAINS];
	uint8_t rxTxMarginCh[AR5416_MAX_CHAINS];
	uint8_t adcDesiredSize;
	uint8_t pgaDesiredSize;
	uint8_t xlnaGainCh[AR5416_MAX_CHAINS];
	uint8_t txEndToXpaOff;
	uint8_t txEndToRxOn;
	uint8_t txFrameToXpaOn;
	uint8_t thresh62;
	uint8_t noiseFloorThreshCh[AR5416_MAX_CHAINS];
	uint8_t xpdGain;
	uint8_t xpd;
	uint8_t iqCalICh[AR5416_MAX_CHAINS];
	uint8_t iqCalQCh[AR5416_MAX_CHAINS];
	uint8_t pdGainOverlap;
	uint8_t ob;
	uint8_t db;
	uint8_t xpaBiasLvl;
	uint8_t pwrDecreaseFor2Chain;
	uint8_t pwrDecreaseFor3Chain;
	uint8_t txFrameToDataStart;
	uint8_t txFrameToPaOn;
	uint8_t ht40PowerIncForPdadc;
	uint8_t bswAtten[AR5416_MAX_CHAINS];
	uint8_t bswMargin[AR5416_MAX_CHAINS];
	uint8_t swSettleHt40;
	uint8_t xatten2Db[AR5416_MAX_CHAINS];
	uint8_t xatten2Margin[AR5416_MAX_CHAINS];
	uint8_t ob_ch1;
	uint8_t db_ch1;
	uint8_t lna_ctl;
	uint8_t miscBits;
	uint16_t xpaBiasLvlFreq[3];
	uint8_t futureModal[6];
	struct spur_chan spurChans[AR_EEPROM_MODAL_SPURS];
} __attribute__ ((packed));

struct cal_data_per_freq {
	uint8_t pwrPdg[AR5416_NUM_PD_GAINS][AR5416_PD_GAIN_ICEPTS];
	uint8_t vpdPdg[AR5416_NUM_PD_GAINS][AR5416_PD_GAIN_ICEPTS];
} __attribute__ ((packed));

struct cal_ctl_data {
	struct cal_ctl_edges
	ctlEdges[AR5416_MAX_CHAINS][AR5416_NUM_BAND_EDGES];
} __attribute__ ((packed));

struct ar5416_eeprom_def {
	struct base_eep_header baseEepHeader;
	uint8_t custData[64];
	struct modal_eep_header modalHeader[2];
	uint8_t calFreqPier5G[AR5416_NUM_5G_CAL_PIERS];
	uint8_t calFreqPier2G[AR5416_NUM_2G_CAL_PIERS];
	struct cal_data_per_freq
	 calPierData5G[AR5416_MAX_CHAINS][AR5416_NUM_5G_CAL_PIERS];
	struct cal_data_per_freq
	 calPierData2G[AR5416_MAX_CHAINS][AR5416_NUM_2G_CAL_PIERS];
	struct cal_target_power_leg
	 calTargetPower5G[AR5416_NUM_5G_20_TARGET_POWERS];
	struct cal_target_power_ht
	 calTargetPower5GHT20[AR5416_NUM_5G_20_TARGET_POWERS];
	struct cal_target_power_ht
	 calTargetPower5GHT40[AR5416_NUM_5G_40_TARGET_POWERS];
	struct cal_target_power_leg
	 calTargetPowerCck[AR5416_NUM_2G_CCK_TARGET_POWERS];
	struct cal_target_power_leg
	 calTargetPower2G[AR5416_NUM_2G_20_TARGET_POWERS];
	struct cal_target_power_ht
	 calTargetPower2GHT20[AR5416_NUM_2G_20_TARGET_POWERS];
	struct cal_target_power_ht
	 calTargetPower2GHT40[AR5416_NUM_2G_40_TARGET_POWERS];
	uint8_t ctlIndex[AR5416_NUM_CTLS];
	struct cal_ctl_data ctlData[AR5416_NUM_CTLS];
	uint8_t padding;
} __attribute__ ((packed));

#endif /* EEP_DEF_H */

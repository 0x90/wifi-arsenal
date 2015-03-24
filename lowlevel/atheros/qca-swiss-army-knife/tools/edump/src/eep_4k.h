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

#ifndef EEP_4K_H
#define EEP_4K_H

#define AR5416_EEP4K_START_LOC                64
#define AR5416_EEP4K_NUM_2G_CAL_PIERS         3
#define AR5416_EEP4K_NUM_2G_CCK_TARGET_POWERS 3
#define AR5416_EEP4K_NUM_2G_20_TARGET_POWERS  3
#define AR5416_EEP4K_NUM_2G_40_TARGET_POWERS  3
#define AR5416_EEP4K_NUM_CTLS                 12
#define AR5416_EEP4K_NUM_BAND_EDGES           4
#define AR5416_EEP4K_NUM_PD_GAINS             2
#define AR5416_EEP4K_MAX_CHAINS               1

struct base_eep_header_4k {
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
	uint8_t txGainType;
} __attribute__ ((packed));

struct modal_eep_4k_header {
	uint32_t antCtrlChain[AR5416_EEP4K_MAX_CHAINS];
	uint32_t antCtrlCommon;
	uint8_t antennaGainCh[AR5416_EEP4K_MAX_CHAINS];
	uint8_t switchSettling;
	uint8_t txRxAttenCh[AR5416_EEP4K_MAX_CHAINS];
	uint8_t rxTxMarginCh[AR5416_EEP4K_MAX_CHAINS];
	uint8_t adcDesiredSize;
	uint8_t pgaDesiredSize;
	uint8_t xlnaGainCh[AR5416_EEP4K_MAX_CHAINS];
	uint8_t txEndToXpaOff;
	uint8_t txEndToRxOn;
	uint8_t txFrameToXpaOn;
	uint8_t thresh62;
	uint8_t noiseFloorThreshCh[AR5416_EEP4K_MAX_CHAINS];
	uint8_t xpdGain;
	uint8_t xpd;
	uint8_t iqCalICh[AR5416_EEP4K_MAX_CHAINS];
	uint8_t iqCalQCh[AR5416_EEP4K_MAX_CHAINS];
	uint8_t pdGainOverlap;
#if __BYTE_ORDER == __BIG_ENDIAN
	uint8_t ob_1:4, ob_0:4;
	uint8_t db1_1:4, db1_0:4;
#else
	uint8_t ob_0:4, ob_1:4;
	uint8_t db1_0:4, db1_1:4;
#endif
	uint8_t xpaBiasLvl;
	uint8_t txFrameToDataStart;
	uint8_t txFrameToPaOn;
	uint8_t ht40PowerIncForPdadc;
	uint8_t bswAtten[AR5416_EEP4K_MAX_CHAINS];
	uint8_t bswMargin[AR5416_EEP4K_MAX_CHAINS];
	uint8_t swSettleHt40;
	uint8_t xatten2Db[AR5416_EEP4K_MAX_CHAINS];
	uint8_t xatten2Margin[AR5416_EEP4K_MAX_CHAINS];
#if __BYTE_ORDER == __BIG_ENDIAN
	uint8_t db2_1:4, db2_0:4;
#else
	uint8_t db2_0:4, db2_1:4;
#endif
	uint8_t version;
#if __BYTE_ORDER == __BIG_ENDIAN
	uint8_t ob_3:4, ob_2:4;
	uint8_t antdiv_ctl1:4, ob_4:4;
	uint8_t db1_3:4, db1_2:4;
	uint8_t antdiv_ctl2:4, db1_4:4;
	uint8_t db2_2:4, db2_3:4;
	uint8_t reserved:4, db2_4:4;
#else
	uint8_t ob_2:4, ob_3:4;
	uint8_t ob_4:4, antdiv_ctl1:4;
	uint8_t db1_2:4, db1_3:4;
	uint8_t db1_4:4, antdiv_ctl2:4;
	uint8_t db2_2:4, db2_3:4;
	uint8_t db2_4:4, reserved:4;
#endif
	uint8_t tx_diversity;
	uint8_t flc_pwr_thresh;
	uint8_t bb_scale_smrt_antenna;
	uint8_t futureModal[1];
	struct spur_chan spurChans[AR_EEPROM_MODAL_SPURS];
} __attribute__ ((packed));

struct cal_data_per_freq_4k {
	uint8_t pwrPdg[AR5416_EEP4K_NUM_PD_GAINS][AR5416_PD_GAIN_ICEPTS];
	uint8_t vpdPdg[AR5416_EEP4K_NUM_PD_GAINS][AR5416_PD_GAIN_ICEPTS];
} __attribute__ ((packed));

struct cal_ctl_data_4k {
	struct cal_ctl_edges
	ctlEdges[AR5416_EEP4K_MAX_CHAINS][AR5416_EEP4K_NUM_BAND_EDGES];
} __attribute__ ((packed));

struct ar5416_eeprom_4k {
	struct base_eep_header_4k baseEepHeader;
	uint8_t custData[20];
	struct modal_eep_4k_header modalHeader;
	uint8_t calFreqPier2G[AR5416_EEP4K_NUM_2G_CAL_PIERS];
	struct cal_data_per_freq_4k
	calPierData2G[AR5416_EEP4K_MAX_CHAINS][AR5416_EEP4K_NUM_2G_CAL_PIERS];
	struct cal_target_power_leg
	calTargetPowerCck[AR5416_EEP4K_NUM_2G_CCK_TARGET_POWERS];
	struct cal_target_power_leg
	calTargetPower2G[AR5416_EEP4K_NUM_2G_20_TARGET_POWERS];
	struct cal_target_power_ht
	calTargetPower2GHT20[AR5416_EEP4K_NUM_2G_20_TARGET_POWERS];
	struct cal_target_power_ht
	calTargetPower2GHT40[AR5416_EEP4K_NUM_2G_40_TARGET_POWERS];
	uint8_t ctlIndex[AR5416_EEP4K_NUM_CTLS];
	struct cal_ctl_data_4k ctlData[AR5416_EEP4K_NUM_CTLS];
	uint8_t padding;
} __attribute__ ((packed));

#endif /* EEP_4K_H */

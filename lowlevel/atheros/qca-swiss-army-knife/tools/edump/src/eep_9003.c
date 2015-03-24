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

#include "edump.h"

#define COMP_HDR_LEN 4
#define COMP_CKSUM_LEN 2

#define CTL(_tpower, _flag) ((_tpower) | ((_flag) << 6))

#define EEPROM_DATA_LEN_9485	1088

static struct ar9300_eeprom ar9300_default = {
	.eepromVersion = 2,
	.templateVersion = 2,
	.macAddr = {0, 2, 3, 4, 5, 6},
	.custData = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		     0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	.baseEepHeader = {
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
	 },
	.modalHeader2G = {
	/* ar9300_modal_eep_header  2g */
		/*
		 * xatten1DB[AR9300_MAX_CHAINS];  3 xatten1_db
		 * for ar9280 (0xa20c/b20c 5:0)
		 */
		.xatten1DB = {0, 0, 0},

		/*
		 * xatten1Margin[AR9300_MAX_CHAINS]; 3 xatten1_margin
		 * for ar9280 (0xa20c/b20c 16:12
		 */
		.xatten1Margin = {0, 0, 0},
		.tempSlope = 36,
		.voltSlope = 0,

		/*
		 * spurChans[OSPREY_EEPROM_MODAL_SPURS]; spur
		 * channels in usual fbin coding format
		 */
		.spurChans = {0, 0, 0, 0, 0},

		/*
		 * noiseFloorThreshCh[AR9300_MAX_CHAINS]; 3 Check
		 * if the register is per chain
		 */
		.noiseFloorThreshCh = {-1, 0, 0},
		.reserved = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.quick_drop = 0,
		.xpaBiasLvl = 0,
		.txFrameToDataStart = 0x0e,
		.txFrameToPaOn = 0x0e,
		.txClip = 3, /* 4 bits tx_clip, 4 bits dac_scale_cck */
		.antennaGain = 0,
		.switchSettling = 0x2c,
		.adcDesiredSize = -30,
		.txEndToXpaOff = 0,
		.txEndToRxOn = 0x2,
		.txFrameToXpaOn = 0xe,
		.thresh62 = 28,
		.xlna_bias_strength = 0,
		.futureModal = {
			0, 0, 0, 0, 0, 0, 0,
		},
	 },
	.base_ext1 = {
		.ant_div_control = 0,
		.future = {0, 0, 0},
		.tempslopextension = {0, 0, 0, 0, 0, 0, 0, 0}
	},
	.calFreqPier2G = {
		FREQ2FBIN(2412, 1),
		FREQ2FBIN(2437, 1),
		FREQ2FBIN(2472, 1),
	 },
	/* ar9300_cal_data_per_freq_op_loop 2g */
	.calPierData2G = {
		{ {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0} },
		{ {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0} },
		{ {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0} },
	 },
	.calTarget_freqbin_Cck = {
		FREQ2FBIN(2412, 1),
		FREQ2FBIN(2484, 1),
	 },
	.calTarget_freqbin_2G = {
		FREQ2FBIN(2412, 1),
		FREQ2FBIN(2437, 1),
		FREQ2FBIN(2472, 1)
	 },
	.calTarget_freqbin_2GHT20 = {
		FREQ2FBIN(2412, 1),
		FREQ2FBIN(2437, 1),
		FREQ2FBIN(2472, 1)
	 },
	.calTarget_freqbin_2GHT40 = {
		FREQ2FBIN(2412, 1),
		FREQ2FBIN(2437, 1),
		FREQ2FBIN(2472, 1)
	 },
	.calTargetPowerCck = {
		 /* 1L-5L,5S,11L,11S */
		 { {36, 36, 36, 36} },
		 { {36, 36, 36, 36} },
	},
	.calTargetPower2G = {
		 /* 6-24,36,48,54 */
		 { {32, 32, 28, 24} },
		 { {32, 32, 28, 24} },
		 { {32, 32, 28, 24} },
	},
	.calTargetPower2GHT20 = {
		{ {32, 32, 32, 32, 28, 20, 32, 32, 28, 20, 32, 32, 28, 20} },
		{ {32, 32, 32, 32, 28, 20, 32, 32, 28, 20, 32, 32, 28, 20} },
		{ {32, 32, 32, 32, 28, 20, 32, 32, 28, 20, 32, 32, 28, 20} },
	},
	.calTargetPower2GHT40 = {
		{ {32, 32, 32, 32, 28, 20, 32, 32, 28, 20, 32, 32, 28, 20} },
		{ {32, 32, 32, 32, 28, 20, 32, 32, 28, 20, 32, 32, 28, 20} },
		{ {32, 32, 32, 32, 28, 20, 32, 32, 28, 20, 32, 32, 28, 20} },
	},
	.ctlIndex_2G =  {
		0x11, 0x12, 0x15, 0x17, 0x41, 0x42,
		0x45, 0x47, 0x31, 0x32, 0x35, 0x37,
	},
	.ctl_freqbin_2G = {
		{
			FREQ2FBIN(2412, 1),
			FREQ2FBIN(2417, 1),
			FREQ2FBIN(2457, 1),
			FREQ2FBIN(2462, 1)
		},
		{
			FREQ2FBIN(2412, 1),
			FREQ2FBIN(2417, 1),
			FREQ2FBIN(2462, 1),
			0xFF,
		},

		{
			FREQ2FBIN(2412, 1),
			FREQ2FBIN(2417, 1),
			FREQ2FBIN(2462, 1),
			0xFF,
		},
		{
			FREQ2FBIN(2422, 1),
			FREQ2FBIN(2427, 1),
			FREQ2FBIN(2447, 1),
			FREQ2FBIN(2452, 1)
		},

		{
			/* Data[4].ctlEdges[0].bChannel */ FREQ2FBIN(2412, 1),
			/* Data[4].ctlEdges[1].bChannel */ FREQ2FBIN(2417, 1),
			/* Data[4].ctlEdges[2].bChannel */ FREQ2FBIN(2472, 1),
			/* Data[4].ctlEdges[3].bChannel */ FREQ2FBIN(2484, 1),
		},

		{
			/* Data[5].ctlEdges[0].bChannel */ FREQ2FBIN(2412, 1),
			/* Data[5].ctlEdges[1].bChannel */ FREQ2FBIN(2417, 1),
			/* Data[5].ctlEdges[2].bChannel */ FREQ2FBIN(2472, 1),
			0,
		},

		{
			/* Data[6].ctlEdges[0].bChannel */ FREQ2FBIN(2412, 1),
			/* Data[6].ctlEdges[1].bChannel */ FREQ2FBIN(2417, 1),
			FREQ2FBIN(2472, 1),
			0,
		},

		{
			/* Data[7].ctlEdges[0].bChannel */ FREQ2FBIN(2422, 1),
			/* Data[7].ctlEdges[1].bChannel */ FREQ2FBIN(2427, 1),
			/* Data[7].ctlEdges[2].bChannel */ FREQ2FBIN(2447, 1),
			/* Data[7].ctlEdges[3].bChannel */ FREQ2FBIN(2462, 1),
		},

		{
			/* Data[8].ctlEdges[0].bChannel */ FREQ2FBIN(2412, 1),
			/* Data[8].ctlEdges[1].bChannel */ FREQ2FBIN(2417, 1),
			/* Data[8].ctlEdges[2].bChannel */ FREQ2FBIN(2472, 1),
		},

		{
			/* Data[9].ctlEdges[0].bChannel */ FREQ2FBIN(2412, 1),
			/* Data[9].ctlEdges[1].bChannel */ FREQ2FBIN(2417, 1),
			/* Data[9].ctlEdges[2].bChannel */ FREQ2FBIN(2472, 1),
			0
		},

		{
			/* Data[10].ctlEdges[0].bChannel */ FREQ2FBIN(2412, 1),
			/* Data[10].ctlEdges[1].bChannel */ FREQ2FBIN(2417, 1),
			/* Data[10].ctlEdges[2].bChannel */ FREQ2FBIN(2472, 1),
			0
		},

		{
			/* Data[11].ctlEdges[0].bChannel */ FREQ2FBIN(2422, 1),
			/* Data[11].ctlEdges[1].bChannel */ FREQ2FBIN(2427, 1),
			/* Data[11].ctlEdges[2].bChannel */ FREQ2FBIN(2447, 1),
			/* Data[11].ctlEdges[3].bChannel */ FREQ2FBIN(2462, 1),
		}
	 },
	.ctlPowerData_2G = {
		 { { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },
		 { { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },
		 { { CTL(60, 1), CTL(60, 0), CTL(60, 0), CTL(60, 1) } },

		 { { CTL(60, 1), CTL(60, 0), CTL(60, 0), CTL(60, 0) } },
		 { { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },
		 { { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },

		 { { CTL(60, 0), CTL(60, 1), CTL(60, 1), CTL(60, 0) } },
		 { { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },
		 { { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },

		 { { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },
		 { { CTL(60, 0), CTL(60, 1), CTL(60, 1), CTL(60, 1) } },
		 { { CTL(60, 0), CTL(60, 1), CTL(60, 1), CTL(60, 1) } },
	 },
	.modalHeader5G = {
		 /* xatten1DB 3 xatten1_db for AR9280 (0xa20c/b20c 5:0) */
		.xatten1DB = {0, 0, 0},

		/*
		 * xatten1Margin[AR9300_MAX_CHAINS]; 3 xatten1_margin
		 * for merlin (0xa20c/b20c 16:12
		 */
		.xatten1Margin = {0, 0, 0},
		.tempSlope = 68,
		.voltSlope = 0,
		/* spurChans spur channels in usual fbin coding format */
		.spurChans = {0, 0, 0, 0, 0},
		/* noiseFloorThreshCh Check if the register is per chain */
		.noiseFloorThreshCh = {-1, 0, 0},
		.reserved = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.quick_drop = 0,
		.xpaBiasLvl = 0,
		.txFrameToDataStart = 0x0e,
		.txFrameToPaOn = 0x0e,
		.txClip = 3, /* 4 bits tx_clip, 4 bits dac_scale_cck */
		.antennaGain = 0,
		.switchSettling = 0x2d,
		.adcDesiredSize = -30,
		.txEndToXpaOff = 0,
		.txEndToRxOn = 0x2,
		.txFrameToXpaOn = 0xe,
		.thresh62 = 28,
		.xlna_bias_strength = 0,
		.futureModal = {
			0, 0, 0, 0, 0, 0, 0,
		},
	 },
	.base_ext2 = {
		.tempSlopeLow = 0,
		.tempSlopeHigh = 0,
		.xatten1DBLow = {0, 0, 0},
		.xatten1MarginLow = {0, 0, 0},
		.xatten1DBHigh = {0, 0, 0},
		.xatten1MarginHigh = {0, 0, 0}
	},
	.calFreqPier5G = {
		FREQ2FBIN(5180, 0),
		FREQ2FBIN(5220, 0),
		FREQ2FBIN(5320, 0),
		FREQ2FBIN(5400, 0),
		FREQ2FBIN(5500, 0),
		FREQ2FBIN(5600, 0),
		FREQ2FBIN(5725, 0),
		FREQ2FBIN(5825, 0)
	},
	.calPierData5G = {
			{
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
			},
			{
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
			},
			{
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
			},

	},
	.calTarget_freqbin_5G = {
		FREQ2FBIN(5180, 0),
		FREQ2FBIN(5220, 0),
		FREQ2FBIN(5320, 0),
		FREQ2FBIN(5400, 0),
		FREQ2FBIN(5500, 0),
		FREQ2FBIN(5600, 0),
		FREQ2FBIN(5725, 0),
		FREQ2FBIN(5825, 0)
	},
	.calTarget_freqbin_5GHT20 = {
		FREQ2FBIN(5180, 0),
		FREQ2FBIN(5240, 0),
		FREQ2FBIN(5320, 0),
		FREQ2FBIN(5500, 0),
		FREQ2FBIN(5700, 0),
		FREQ2FBIN(5745, 0),
		FREQ2FBIN(5725, 0),
		FREQ2FBIN(5825, 0)
	},
	.calTarget_freqbin_5GHT40 = {
		FREQ2FBIN(5180, 0),
		FREQ2FBIN(5240, 0),
		FREQ2FBIN(5320, 0),
		FREQ2FBIN(5500, 0),
		FREQ2FBIN(5700, 0),
		FREQ2FBIN(5745, 0),
		FREQ2FBIN(5725, 0),
		FREQ2FBIN(5825, 0)
	 },
	.calTargetPower5G = {
		/* 6-24,36,48,54 */
		{ {20, 20, 20, 10} },
		{ {20, 20, 20, 10} },
		{ {20, 20, 20, 10} },
		{ {20, 20, 20, 10} },
		{ {20, 20, 20, 10} },
		{ {20, 20, 20, 10} },
		{ {20, 20, 20, 10} },
		{ {20, 20, 20, 10} },
	 },
	.calTargetPower5GHT20 = {
		/*
		 * 0_8_16,1-3_9-11_17-19,
		 * 4,5,6,7,12,13,14,15,20,21,22,23
		 */
		{ {20, 20, 10, 10, 0, 0, 10, 10, 0, 0, 10, 10, 0, 0} },
		{ {20, 20, 10, 10, 0, 0, 10, 10, 0, 0, 10, 10, 0, 0} },
		{ {20, 20, 10, 10, 0, 0, 10, 10, 0, 0, 10, 10, 0, 0} },
		{ {20, 20, 10, 10, 0, 0, 10, 10, 0, 0, 10, 10, 0, 0} },
		{ {20, 20, 10, 10, 0, 0, 10, 10, 0, 0, 10, 10, 0, 0} },
		{ {20, 20, 10, 10, 0, 0, 10, 10, 0, 0, 10, 10, 0, 0} },
		{ {20, 20, 10, 10, 0, 0, 10, 10, 0, 0, 10, 10, 0, 0} },
		{ {20, 20, 10, 10, 0, 0, 10, 10, 0, 0, 10, 10, 0, 0} },
	 },
	.calTargetPower5GHT40 =  {
		/*
		 * 0_8_16,1-3_9-11_17-19,
		 * 4,5,6,7,12,13,14,15,20,21,22,23
		 */
		{ {20, 20, 10, 10, 0, 0, 10, 10, 0, 0, 10, 10, 0, 0} },
		{ {20, 20, 10, 10, 0, 0, 10, 10, 0, 0, 10, 10, 0, 0} },
		{ {20, 20, 10, 10, 0, 0, 10, 10, 0, 0, 10, 10, 0, 0} },
		{ {20, 20, 10, 10, 0, 0, 10, 10, 0, 0, 10, 10, 0, 0} },
		{ {20, 20, 10, 10, 0, 0, 10, 10, 0, 0, 10, 10, 0, 0} },
		{ {20, 20, 10, 10, 0, 0, 10, 10, 0, 0, 10, 10, 0, 0} },
		{ {20, 20, 10, 10, 0, 0, 10, 10, 0, 0, 10, 10, 0, 0} },
		{ {20, 20, 10, 10, 0, 0, 10, 10, 0, 0, 10, 10, 0, 0} },
	 },
	.ctlIndex_5G =  {
		0x10, 0x16, 0x18, 0x40, 0x46,
		0x48, 0x30, 0x36, 0x38
	},
	.ctl_freqbin_5G =  {
		{
			/* Data[0].ctlEdges[0].bChannel */ FREQ2FBIN(5180, 0),
			/* Data[0].ctlEdges[1].bChannel */ FREQ2FBIN(5260, 0),
			/* Data[0].ctlEdges[2].bChannel */ FREQ2FBIN(5280, 0),
			/* Data[0].ctlEdges[3].bChannel */ FREQ2FBIN(5500, 0),
			/* Data[0].ctlEdges[4].bChannel */ FREQ2FBIN(5600, 0),
			/* Data[0].ctlEdges[5].bChannel */ FREQ2FBIN(5700, 0),
			/* Data[0].ctlEdges[6].bChannel */ FREQ2FBIN(5745, 0),
			/* Data[0].ctlEdges[7].bChannel */ FREQ2FBIN(5825, 0)
		},
		{
			/* Data[1].ctlEdges[0].bChannel */ FREQ2FBIN(5180, 0),
			/* Data[1].ctlEdges[1].bChannel */ FREQ2FBIN(5260, 0),
			/* Data[1].ctlEdges[2].bChannel */ FREQ2FBIN(5280, 0),
			/* Data[1].ctlEdges[3].bChannel */ FREQ2FBIN(5500, 0),
			/* Data[1].ctlEdges[4].bChannel */ FREQ2FBIN(5520, 0),
			/* Data[1].ctlEdges[5].bChannel */ FREQ2FBIN(5700, 0),
			/* Data[1].ctlEdges[6].bChannel */ FREQ2FBIN(5745, 0),
			/* Data[1].ctlEdges[7].bChannel */ FREQ2FBIN(5825, 0)
		},

		{
			/* Data[2].ctlEdges[0].bChannel */ FREQ2FBIN(5190, 0),
			/* Data[2].ctlEdges[1].bChannel */ FREQ2FBIN(5230, 0),
			/* Data[2].ctlEdges[2].bChannel */ FREQ2FBIN(5270, 0),
			/* Data[2].ctlEdges[3].bChannel */ FREQ2FBIN(5310, 0),
			/* Data[2].ctlEdges[4].bChannel */ FREQ2FBIN(5510, 0),
			/* Data[2].ctlEdges[5].bChannel */ FREQ2FBIN(5550, 0),
			/* Data[2].ctlEdges[6].bChannel */ FREQ2FBIN(5670, 0),
			/* Data[2].ctlEdges[7].bChannel */ FREQ2FBIN(5755, 0)
		},

		{
			/* Data[3].ctlEdges[0].bChannel */ FREQ2FBIN(5180, 0),
			/* Data[3].ctlEdges[1].bChannel */ FREQ2FBIN(5200, 0),
			/* Data[3].ctlEdges[2].bChannel */ FREQ2FBIN(5260, 0),
			/* Data[3].ctlEdges[3].bChannel */ FREQ2FBIN(5320, 0),
			/* Data[3].ctlEdges[4].bChannel */ FREQ2FBIN(5500, 0),
			/* Data[3].ctlEdges[5].bChannel */ FREQ2FBIN(5700, 0),
			/* Data[3].ctlEdges[6].bChannel */ 0xFF,
			/* Data[3].ctlEdges[7].bChannel */ 0xFF,
		},

		{
			/* Data[4].ctlEdges[0].bChannel */ FREQ2FBIN(5180, 0),
			/* Data[4].ctlEdges[1].bChannel */ FREQ2FBIN(5260, 0),
			/* Data[4].ctlEdges[2].bChannel */ FREQ2FBIN(5500, 0),
			/* Data[4].ctlEdges[3].bChannel */ FREQ2FBIN(5700, 0),
			/* Data[4].ctlEdges[4].bChannel */ 0xFF,
			/* Data[4].ctlEdges[5].bChannel */ 0xFF,
			/* Data[4].ctlEdges[6].bChannel */ 0xFF,
			/* Data[4].ctlEdges[7].bChannel */ 0xFF,
		},

		{
			/* Data[5].ctlEdges[0].bChannel */ FREQ2FBIN(5190, 0),
			/* Data[5].ctlEdges[1].bChannel */ FREQ2FBIN(5270, 0),
			/* Data[5].ctlEdges[2].bChannel */ FREQ2FBIN(5310, 0),
			/* Data[5].ctlEdges[3].bChannel */ FREQ2FBIN(5510, 0),
			/* Data[5].ctlEdges[4].bChannel */ FREQ2FBIN(5590, 0),
			/* Data[5].ctlEdges[5].bChannel */ FREQ2FBIN(5670, 0),
			/* Data[5].ctlEdges[6].bChannel */ 0xFF,
			/* Data[5].ctlEdges[7].bChannel */ 0xFF
		},

		{
			/* Data[6].ctlEdges[0].bChannel */ FREQ2FBIN(5180, 0),
			/* Data[6].ctlEdges[1].bChannel */ FREQ2FBIN(5200, 0),
			/* Data[6].ctlEdges[2].bChannel */ FREQ2FBIN(5220, 0),
			/* Data[6].ctlEdges[3].bChannel */ FREQ2FBIN(5260, 0),
			/* Data[6].ctlEdges[4].bChannel */ FREQ2FBIN(5500, 0),
			/* Data[6].ctlEdges[5].bChannel */ FREQ2FBIN(5600, 0),
			/* Data[6].ctlEdges[6].bChannel */ FREQ2FBIN(5700, 0),
			/* Data[6].ctlEdges[7].bChannel */ FREQ2FBIN(5745, 0)
		},

		{
			/* Data[7].ctlEdges[0].bChannel */ FREQ2FBIN(5180, 0),
			/* Data[7].ctlEdges[1].bChannel */ FREQ2FBIN(5260, 0),
			/* Data[7].ctlEdges[2].bChannel */ FREQ2FBIN(5320, 0),
			/* Data[7].ctlEdges[3].bChannel */ FREQ2FBIN(5500, 0),
			/* Data[7].ctlEdges[4].bChannel */ FREQ2FBIN(5560, 0),
			/* Data[7].ctlEdges[5].bChannel */ FREQ2FBIN(5700, 0),
			/* Data[7].ctlEdges[6].bChannel */ FREQ2FBIN(5745, 0),
			/* Data[7].ctlEdges[7].bChannel */ FREQ2FBIN(5825, 0)
		},

		{
			/* Data[8].ctlEdges[0].bChannel */ FREQ2FBIN(5190, 0),
			/* Data[8].ctlEdges[1].bChannel */ FREQ2FBIN(5230, 0),
			/* Data[8].ctlEdges[2].bChannel */ FREQ2FBIN(5270, 0),
			/* Data[8].ctlEdges[3].bChannel */ FREQ2FBIN(5510, 0),
			/* Data[8].ctlEdges[4].bChannel */ FREQ2FBIN(5550, 0),
			/* Data[8].ctlEdges[5].bChannel */ FREQ2FBIN(5670, 0),
			/* Data[8].ctlEdges[6].bChannel */ FREQ2FBIN(5755, 0),
			/* Data[8].ctlEdges[7].bChannel */ FREQ2FBIN(5795, 0)
		}
	 },
	.ctlPowerData_5G = {
		{
			{
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 1),
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 0),
			}
		},
		{
			{
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 1),
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 0),
			}
		},
		{
			{
				CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 1),
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 1),
			}
		},
		{
			{
				CTL(60, 0), CTL(60, 1), CTL(60, 1), CTL(60, 0),
				CTL(60, 1), CTL(60, 0), CTL(60, 0), CTL(60, 0),
			}
		},
		{
			{
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 0),
				CTL(60, 0), CTL(60, 0), CTL(60, 0), CTL(60, 0),
			}
		},
		{
			{
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 1),
				CTL(60, 1), CTL(60, 0), CTL(60, 0), CTL(60, 0),
			}
		},
		{
			{
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 1),
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 1),
			}
		},
		{
			{
				CTL(60, 1), CTL(60, 1), CTL(60, 0), CTL(60, 1),
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 0),
			}
		},
		{
			{
				CTL(60, 1), CTL(60, 0), CTL(60, 1), CTL(60, 1),
				CTL(60, 1), CTL(60, 1), CTL(60, 0), CTL(60, 1),
			}
		},
	 }
};

static struct ar9300_eeprom ar9300_x113 = {
	.eepromVersion = 2,
	.templateVersion = 6,
	.macAddr = {0x00, 0x03, 0x7f, 0x0, 0x0, 0x0},
	.custData = {"x113-023-f0000"},
	.baseEepHeader = {
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
	 },
	.modalHeader2G = {
	/* ar9300_modal_eep_header  2g */
		/*
		 * xatten1DB[AR9300_MAX_CHAINS];  3 xatten1_db
		 * for ar9280 (0xa20c/b20c 5:0)
		 */
		.xatten1DB = {0, 0, 0},

		/*
		 * xatten1Margin[AR9300_MAX_CHAINS]; 3 xatten1_margin
		 * for ar9280 (0xa20c/b20c 16:12
		 */
		.xatten1Margin = {0, 0, 0},
		.tempSlope = 25,
		.voltSlope = 0,

		/*
		 * spurChans[OSPREY_EEPROM_MODAL_SPURS]; spur
		 * channels in usual fbin coding format
		 */
		.spurChans = {FREQ2FBIN(2464, 1), 0, 0, 0, 0},

		/*
		 * noiseFloorThreshCh[AR9300_MAX_CHAINS]; 3 Check
		 * if the register is per chain
		 */
		.noiseFloorThreshCh = {-1, 0, 0},
		.reserved = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.quick_drop = 0,
		.xpaBiasLvl = 0,
		.txFrameToDataStart = 0x0e,
		.txFrameToPaOn = 0x0e,
		.txClip = 3, /* 4 bits tx_clip, 4 bits dac_scale_cck */
		.antennaGain = 0,
		.switchSettling = 0x2c,
		.adcDesiredSize = -30,
		.txEndToXpaOff = 0,
		.txEndToRxOn = 0x2,
		.txFrameToXpaOn = 0xe,
		.thresh62 = 28,
		.xlna_bias_strength = 0,
		.futureModal = {
			0, 0, 0, 0, 0, 0, 0,
		},
	 },
	 .base_ext1 = {
		.ant_div_control = 0,
		.future = {0, 0, 0},
		.tempslopextension = {0, 0, 0, 0, 0, 0, 0, 0}
	 },
	.calFreqPier2G = {
		FREQ2FBIN(2412, 1),
		FREQ2FBIN(2437, 1),
		FREQ2FBIN(2472, 1),
	 },
	/* ar9300_cal_data_per_freq_op_loop 2g */
	.calPierData2G = {
		{ {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0} },
		{ {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0} },
		{ {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0} },
	 },
	.calTarget_freqbin_Cck = {
		FREQ2FBIN(2412, 1),
		FREQ2FBIN(2472, 1),
	 },
	.calTarget_freqbin_2G = {
		FREQ2FBIN(2412, 1),
		FREQ2FBIN(2437, 1),
		FREQ2FBIN(2472, 1)
	 },
	.calTarget_freqbin_2GHT20 = {
		FREQ2FBIN(2412, 1),
		FREQ2FBIN(2437, 1),
		FREQ2FBIN(2472, 1)
	 },
	.calTarget_freqbin_2GHT40 = {
		FREQ2FBIN(2412, 1),
		FREQ2FBIN(2437, 1),
		FREQ2FBIN(2472, 1)
	 },
	.calTargetPowerCck = {
		 /* 1L-5L,5S,11L,11S */
		 { {34, 34, 34, 34} },
		 { {34, 34, 34, 34} },
	},
	.calTargetPower2G = {
		 /* 6-24,36,48,54 */
		 { {34, 34, 32, 32} },
		 { {34, 34, 32, 32} },
		 { {34, 34, 32, 32} },
	},
	.calTargetPower2GHT20 = {
		{ {32, 32, 32, 32, 32, 28, 32, 32, 30, 28, 0, 0, 0, 0} },
		{ {32, 32, 32, 32, 32, 28, 32, 32, 30, 28, 0, 0, 0, 0} },
		{ {32, 32, 32, 32, 32, 28, 32, 32, 30, 28, 0, 0, 0, 0} },
	},
	.calTargetPower2GHT40 = {
		{ {30, 30, 30, 30, 30, 28, 30, 30, 28, 26, 0, 0, 0, 0} },
		{ {30, 30, 30, 30, 30, 28, 30, 30, 28, 26, 0, 0, 0, 0} },
		{ {30, 30, 30, 30, 30, 28, 30, 30, 28, 26, 0, 0, 0, 0} },
	},
	.ctlIndex_2G =  {
		0x11, 0x12, 0x15, 0x17, 0x41, 0x42,
		0x45, 0x47, 0x31, 0x32, 0x35, 0x37,
	},
	.ctl_freqbin_2G = {
		{
			FREQ2FBIN(2412, 1),
			FREQ2FBIN(2417, 1),
			FREQ2FBIN(2457, 1),
			FREQ2FBIN(2462, 1)
		},
		{
			FREQ2FBIN(2412, 1),
			FREQ2FBIN(2417, 1),
			FREQ2FBIN(2462, 1),
			0xFF,
		},

		{
			FREQ2FBIN(2412, 1),
			FREQ2FBIN(2417, 1),
			FREQ2FBIN(2462, 1),
			0xFF,
		},
		{
			FREQ2FBIN(2422, 1),
			FREQ2FBIN(2427, 1),
			FREQ2FBIN(2447, 1),
			FREQ2FBIN(2452, 1)
		},

		{
			/* Data[4].ctlEdges[0].bChannel */ FREQ2FBIN(2412, 1),
			/* Data[4].ctlEdges[1].bChannel */ FREQ2FBIN(2417, 1),
			/* Data[4].ctlEdges[2].bChannel */ FREQ2FBIN(2472, 1),
			/* Data[4].ctlEdges[3].bChannel */ FREQ2FBIN(2484, 1),
		},

		{
			/* Data[5].ctlEdges[0].bChannel */ FREQ2FBIN(2412, 1),
			/* Data[5].ctlEdges[1].bChannel */ FREQ2FBIN(2417, 1),
			/* Data[5].ctlEdges[2].bChannel */ FREQ2FBIN(2472, 1),
			0,
		},

		{
			/* Data[6].ctlEdges[0].bChannel */ FREQ2FBIN(2412, 1),
			/* Data[6].ctlEdges[1].bChannel */ FREQ2FBIN(2417, 1),
			FREQ2FBIN(2472, 1),
			0,
		},

		{
			/* Data[7].ctlEdges[0].bChannel */ FREQ2FBIN(2422, 1),
			/* Data[7].ctlEdges[1].bChannel */ FREQ2FBIN(2427, 1),
			/* Data[7].ctlEdges[2].bChannel */ FREQ2FBIN(2447, 1),
			/* Data[7].ctlEdges[3].bChannel */ FREQ2FBIN(2462, 1),
		},

		{
			/* Data[8].ctlEdges[0].bChannel */ FREQ2FBIN(2412, 1),
			/* Data[8].ctlEdges[1].bChannel */ FREQ2FBIN(2417, 1),
			/* Data[8].ctlEdges[2].bChannel */ FREQ2FBIN(2472, 1),
		},

		{
			/* Data[9].ctlEdges[0].bChannel */ FREQ2FBIN(2412, 1),
			/* Data[9].ctlEdges[1].bChannel */ FREQ2FBIN(2417, 1),
			/* Data[9].ctlEdges[2].bChannel */ FREQ2FBIN(2472, 1),
			0
		},

		{
			/* Data[10].ctlEdges[0].bChannel */ FREQ2FBIN(2412, 1),
			/* Data[10].ctlEdges[1].bChannel */ FREQ2FBIN(2417, 1),
			/* Data[10].ctlEdges[2].bChannel */ FREQ2FBIN(2472, 1),
			0
		},

		{
			/* Data[11].ctlEdges[0].bChannel */ FREQ2FBIN(2422, 1),
			/* Data[11].ctlEdges[1].bChannel */ FREQ2FBIN(2427, 1),
			/* Data[11].ctlEdges[2].bChannel */ FREQ2FBIN(2447, 1),
			/* Data[11].ctlEdges[3].bChannel */ FREQ2FBIN(2462, 1),
		}
	 },
	.ctlPowerData_2G = {
		 { { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },
		 { { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },
		 { { CTL(60, 1), CTL(60, 0), CTL(60, 0), CTL(60, 1) } },

		 { { CTL(60, 1), CTL(60, 0), CTL(60, 0), CTL(60, 0) } },
		 { { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },
		 { { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },

		 { { CTL(60, 0), CTL(60, 1), CTL(60, 1), CTL(60, 0) } },
		 { { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },
		 { { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },

		 { { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },
		 { { CTL(60, 0), CTL(60, 1), CTL(60, 1), CTL(60, 1) } },
		 { { CTL(60, 0), CTL(60, 1), CTL(60, 1), CTL(60, 1) } },
	 },
	.modalHeader5G = {
		/* 4 idle,t1,t2,b (4 bits per setting) */
		.xatten1DB = {0, 0, 0},

		/*
		 * xatten1Margin[AR9300_MAX_CHAINS]; 3 xatten1_margin
		 * for merlin (0xa20c/b20c 16:12
		 */
		.xatten1Margin = {0, 0, 0},
		.tempSlope = 68,
		.voltSlope = 0,
		/* spurChans spur channels in usual fbin coding format */
		.spurChans = {FREQ2FBIN(5500, 0), 0, 0, 0, 0},
		/* noiseFloorThreshCh Check if the register is per chain */
		.noiseFloorThreshCh = {-1, 0, 0},
		.reserved = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.quick_drop = 0,
		.xpaBiasLvl = 0xf,
		.txFrameToDataStart = 0x0e,
		.txFrameToPaOn = 0x0e,
		.txClip = 3, /* 4 bits tx_clip, 4 bits dac_scale_cck */
		.antennaGain = 0,
		.switchSettling = 0x2d,
		.adcDesiredSize = -30,
		.txEndToXpaOff = 0,
		.txEndToRxOn = 0x2,
		.txFrameToXpaOn = 0xe,
		.thresh62 = 28,
		.xlna_bias_strength = 0,
		.futureModal = {
			0, 0, 0, 0, 0, 0, 0,
		},
	 },
	.base_ext2 = {
		.tempSlopeLow = 72,
		.tempSlopeHigh = 105,
		.xatten1DBLow = {0, 0, 0},
		.xatten1MarginLow = {0, 0, 0},
		.xatten1DBHigh = {0, 0, 0},
		.xatten1MarginHigh = {0, 0, 0}
	 },
	.calFreqPier5G = {
		FREQ2FBIN(5180, 0),
		FREQ2FBIN(5240, 0),
		FREQ2FBIN(5320, 0),
		FREQ2FBIN(5400, 0),
		FREQ2FBIN(5500, 0),
		FREQ2FBIN(5600, 0),
		FREQ2FBIN(5745, 0),
		FREQ2FBIN(5785, 0)
	},
	.calPierData5G = {
			{
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
			},
			{
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
			},
			{
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
			},

	},
	.calTarget_freqbin_5G = {
		FREQ2FBIN(5180, 0),
		FREQ2FBIN(5220, 0),
		FREQ2FBIN(5320, 0),
		FREQ2FBIN(5400, 0),
		FREQ2FBIN(5500, 0),
		FREQ2FBIN(5600, 0),
		FREQ2FBIN(5745, 0),
		FREQ2FBIN(5785, 0)
	},
	.calTarget_freqbin_5GHT20 = {
		FREQ2FBIN(5180, 0),
		FREQ2FBIN(5240, 0),
		FREQ2FBIN(5320, 0),
		FREQ2FBIN(5400, 0),
		FREQ2FBIN(5500, 0),
		FREQ2FBIN(5700, 0),
		FREQ2FBIN(5745, 0),
		FREQ2FBIN(5825, 0)
	},
	.calTarget_freqbin_5GHT40 = {
		FREQ2FBIN(5190, 0),
		FREQ2FBIN(5230, 0),
		FREQ2FBIN(5320, 0),
		FREQ2FBIN(5410, 0),
		FREQ2FBIN(5510, 0),
		FREQ2FBIN(5670, 0),
		FREQ2FBIN(5755, 0),
		FREQ2FBIN(5825, 0)
	 },
	.calTargetPower5G = {
		/* 6-24,36,48,54 */
		{ {42, 40, 40, 34} },
		{ {42, 40, 40, 34} },
		{ {42, 40, 40, 34} },
		{ {42, 40, 40, 34} },
		{ {42, 40, 40, 34} },
		{ {42, 40, 40, 34} },
		{ {42, 40, 40, 34} },
		{ {42, 40, 40, 34} },
	 },
	.calTargetPower5GHT20 = {
		/*
		 * 0_8_16,1-3_9-11_17-19,
		 * 4,5,6,7,12,13,14,15,20,21,22,23
		 */
		{ {40, 40, 40, 40, 32, 28, 40, 40, 32, 28, 40, 40, 32, 20} },
		{ {40, 40, 40, 40, 32, 28, 40, 40, 32, 28, 40, 40, 32, 20} },
		{ {40, 40, 40, 40, 32, 28, 40, 40, 32, 28, 40, 40, 32, 20} },
		{ {40, 40, 40, 40, 32, 28, 40, 40, 32, 28, 40, 40, 32, 20} },
		{ {40, 40, 40, 40, 32, 28, 40, 40, 32, 28, 40, 40, 32, 20} },
		{ {40, 40, 40, 40, 32, 28, 40, 40, 32, 28, 40, 40, 32, 20} },
		{ {38, 38, 38, 38, 32, 28, 38, 38, 32, 28, 38, 38, 32, 26} },
		{ {36, 36, 36, 36, 32, 28, 36, 36, 32, 28, 36, 36, 32, 26} },
	 },
	.calTargetPower5GHT40 =  {
		/*
		 * 0_8_16,1-3_9-11_17-19,
		 * 4,5,6,7,12,13,14,15,20,21,22,23
		 */
		{ {40, 40, 40, 38, 30, 26, 40, 40, 30, 26, 40, 40, 30, 24} },
		{ {40, 40, 40, 38, 30, 26, 40, 40, 30, 26, 40, 40, 30, 24} },
		{ {40, 40, 40, 38, 30, 26, 40, 40, 30, 26, 40, 40, 30, 24} },
		{ {40, 40, 40, 38, 30, 26, 40, 40, 30, 26, 40, 40, 30, 24} },
		{ {40, 40, 40, 38, 30, 26, 40, 40, 30, 26, 40, 40, 30, 24} },
		{ {40, 40, 40, 38, 30, 26, 40, 40, 30, 26, 40, 40, 30, 24} },
		{ {36, 36, 36, 36, 30, 26, 36, 36, 30, 26, 36, 36, 30, 24} },
		{ {34, 34, 34, 34, 30, 26, 34, 34, 30, 26, 34, 34, 30, 24} },
	 },
	.ctlIndex_5G =  {
		0x10, 0x16, 0x18, 0x40, 0x46,
		0x48, 0x30, 0x36, 0x38
	},
	.ctl_freqbin_5G =  {
		{
			/* Data[0].ctlEdges[0].bChannel */ FREQ2FBIN(5180, 0),
			/* Data[0].ctlEdges[1].bChannel */ FREQ2FBIN(5260, 0),
			/* Data[0].ctlEdges[2].bChannel */ FREQ2FBIN(5280, 0),
			/* Data[0].ctlEdges[3].bChannel */ FREQ2FBIN(5500, 0),
			/* Data[0].ctlEdges[4].bChannel */ FREQ2FBIN(5600, 0),
			/* Data[0].ctlEdges[5].bChannel */ FREQ2FBIN(5700, 0),
			/* Data[0].ctlEdges[6].bChannel */ FREQ2FBIN(5745, 0),
			/* Data[0].ctlEdges[7].bChannel */ FREQ2FBIN(5825, 0)
		},
		{
			/* Data[1].ctlEdges[0].bChannel */ FREQ2FBIN(5180, 0),
			/* Data[1].ctlEdges[1].bChannel */ FREQ2FBIN(5260, 0),
			/* Data[1].ctlEdges[2].bChannel */ FREQ2FBIN(5280, 0),
			/* Data[1].ctlEdges[3].bChannel */ FREQ2FBIN(5500, 0),
			/* Data[1].ctlEdges[4].bChannel */ FREQ2FBIN(5520, 0),
			/* Data[1].ctlEdges[5].bChannel */ FREQ2FBIN(5700, 0),
			/* Data[1].ctlEdges[6].bChannel */ FREQ2FBIN(5745, 0),
			/* Data[1].ctlEdges[7].bChannel */ FREQ2FBIN(5825, 0)
		},

		{
			/* Data[2].ctlEdges[0].bChannel */ FREQ2FBIN(5190, 0),
			/* Data[2].ctlEdges[1].bChannel */ FREQ2FBIN(5230, 0),
			/* Data[2].ctlEdges[2].bChannel */ FREQ2FBIN(5270, 0),
			/* Data[2].ctlEdges[3].bChannel */ FREQ2FBIN(5310, 0),
			/* Data[2].ctlEdges[4].bChannel */ FREQ2FBIN(5510, 0),
			/* Data[2].ctlEdges[5].bChannel */ FREQ2FBIN(5550, 0),
			/* Data[2].ctlEdges[6].bChannel */ FREQ2FBIN(5670, 0),
			/* Data[2].ctlEdges[7].bChannel */ FREQ2FBIN(5755, 0)
		},

		{
			/* Data[3].ctlEdges[0].bChannel */ FREQ2FBIN(5180, 0),
			/* Data[3].ctlEdges[1].bChannel */ FREQ2FBIN(5200, 0),
			/* Data[3].ctlEdges[2].bChannel */ FREQ2FBIN(5260, 0),
			/* Data[3].ctlEdges[3].bChannel */ FREQ2FBIN(5320, 0),
			/* Data[3].ctlEdges[4].bChannel */ FREQ2FBIN(5500, 0),
			/* Data[3].ctlEdges[5].bChannel */ FREQ2FBIN(5700, 0),
			/* Data[3].ctlEdges[6].bChannel */ 0xFF,
			/* Data[3].ctlEdges[7].bChannel */ 0xFF,
		},

		{
			/* Data[4].ctlEdges[0].bChannel */ FREQ2FBIN(5180, 0),
			/* Data[4].ctlEdges[1].bChannel */ FREQ2FBIN(5260, 0),
			/* Data[4].ctlEdges[2].bChannel */ FREQ2FBIN(5500, 0),
			/* Data[4].ctlEdges[3].bChannel */ FREQ2FBIN(5700, 0),
			/* Data[4].ctlEdges[4].bChannel */ 0xFF,
			/* Data[4].ctlEdges[5].bChannel */ 0xFF,
			/* Data[4].ctlEdges[6].bChannel */ 0xFF,
			/* Data[4].ctlEdges[7].bChannel */ 0xFF,
		},

		{
			/* Data[5].ctlEdges[0].bChannel */ FREQ2FBIN(5190, 0),
			/* Data[5].ctlEdges[1].bChannel */ FREQ2FBIN(5270, 0),
			/* Data[5].ctlEdges[2].bChannel */ FREQ2FBIN(5310, 0),
			/* Data[5].ctlEdges[3].bChannel */ FREQ2FBIN(5510, 0),
			/* Data[5].ctlEdges[4].bChannel */ FREQ2FBIN(5590, 0),
			/* Data[5].ctlEdges[5].bChannel */ FREQ2FBIN(5670, 0),
			/* Data[5].ctlEdges[6].bChannel */ 0xFF,
			/* Data[5].ctlEdges[7].bChannel */ 0xFF
		},

		{
			/* Data[6].ctlEdges[0].bChannel */ FREQ2FBIN(5180, 0),
			/* Data[6].ctlEdges[1].bChannel */ FREQ2FBIN(5200, 0),
			/* Data[6].ctlEdges[2].bChannel */ FREQ2FBIN(5220, 0),
			/* Data[6].ctlEdges[3].bChannel */ FREQ2FBIN(5260, 0),
			/* Data[6].ctlEdges[4].bChannel */ FREQ2FBIN(5500, 0),
			/* Data[6].ctlEdges[5].bChannel */ FREQ2FBIN(5600, 0),
			/* Data[6].ctlEdges[6].bChannel */ FREQ2FBIN(5700, 0),
			/* Data[6].ctlEdges[7].bChannel */ FREQ2FBIN(5745, 0)
		},

		{
			/* Data[7].ctlEdges[0].bChannel */ FREQ2FBIN(5180, 0),
			/* Data[7].ctlEdges[1].bChannel */ FREQ2FBIN(5260, 0),
			/* Data[7].ctlEdges[2].bChannel */ FREQ2FBIN(5320, 0),
			/* Data[7].ctlEdges[3].bChannel */ FREQ2FBIN(5500, 0),
			/* Data[7].ctlEdges[4].bChannel */ FREQ2FBIN(5560, 0),
			/* Data[7].ctlEdges[5].bChannel */ FREQ2FBIN(5700, 0),
			/* Data[7].ctlEdges[6].bChannel */ FREQ2FBIN(5745, 0),
			/* Data[7].ctlEdges[7].bChannel */ FREQ2FBIN(5825, 0)
		},

		{
			/* Data[8].ctlEdges[0].bChannel */ FREQ2FBIN(5190, 0),
			/* Data[8].ctlEdges[1].bChannel */ FREQ2FBIN(5230, 0),
			/* Data[8].ctlEdges[2].bChannel */ FREQ2FBIN(5270, 0),
			/* Data[8].ctlEdges[3].bChannel */ FREQ2FBIN(5510, 0),
			/* Data[8].ctlEdges[4].bChannel */ FREQ2FBIN(5550, 0),
			/* Data[8].ctlEdges[5].bChannel */ FREQ2FBIN(5670, 0),
			/* Data[8].ctlEdges[6].bChannel */ FREQ2FBIN(5755, 0),
			/* Data[8].ctlEdges[7].bChannel */ FREQ2FBIN(5795, 0)
		}
	 },
	.ctlPowerData_5G = {
		{
			{
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 1),
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 0),
			}
		},
		{
			{
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 1),
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 0),
			}
		},
		{
			{
				CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 1),
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 1),
			}
		},
		{
			{
				CTL(60, 0), CTL(60, 1), CTL(60, 1), CTL(60, 0),
				CTL(60, 1), CTL(60, 0), CTL(60, 0), CTL(60, 0),
			}
		},
		{
			{
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 0),
				CTL(60, 0), CTL(60, 0), CTL(60, 0), CTL(60, 0),
			}
		},
		{
			{
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 1),
				CTL(60, 1), CTL(60, 0), CTL(60, 0), CTL(60, 0),
			}
		},
		{
			{
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 1),
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 1),
			}
		},
		{
			{
				CTL(60, 1), CTL(60, 1), CTL(60, 0), CTL(60, 1),
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 0),
			}
		},
		{
			{
				CTL(60, 1), CTL(60, 0), CTL(60, 1), CTL(60, 1),
				CTL(60, 1), CTL(60, 1), CTL(60, 0), CTL(60, 1),
			}
		},
	 }
};


static struct ar9300_eeprom ar9300_h112 = {
	.eepromVersion = 2,
	.templateVersion = 3,
	.macAddr = {0x00, 0x03, 0x7f, 0x0, 0x0, 0x0},
	.custData = {"h112-241-f0000"},
	.baseEepHeader = {
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
	},
	.modalHeader2G = {
		/* ar9300_modal_eep_header  2g */
		/*
		 * xatten1DB[AR9300_MAX_CHAINS];  3 xatten1_db
		 * for ar9280 (0xa20c/b20c 5:0)
		 */
		.xatten1DB = {0, 0, 0},

		/*
		 * xatten1Margin[AR9300_MAX_CHAINS]; 3 xatten1_margin
		 * for ar9280 (0xa20c/b20c 16:12
		 */
		.xatten1Margin = {0, 0, 0},
		.tempSlope = 25,
		.voltSlope = 0,

		/*
		 * spurChans[OSPREY_EEPROM_MODAL_SPURS]; spur
		 * channels in usual fbin coding format
		 */
		.spurChans = {FREQ2FBIN(2464, 1), 0, 0, 0, 0},

		/*
		 * noiseFloorThreshCh[AR9300_MAX_CHAINS]; 3 Check
		 * if the register is per chain
		 */
		.noiseFloorThreshCh = {-1, 0, 0},
		.reserved = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.quick_drop = 0,
		.xpaBiasLvl = 0,
		.txFrameToDataStart = 0x0e,
		.txFrameToPaOn = 0x0e,
		.txClip = 3, /* 4 bits tx_clip, 4 bits dac_scale_cck */
		.antennaGain = 0,
		.switchSettling = 0x2c,
		.adcDesiredSize = -30,
		.txEndToXpaOff = 0,
		.txEndToRxOn = 0x2,
		.txFrameToXpaOn = 0xe,
		.thresh62 = 28,
		.xlna_bias_strength = 0,
		.futureModal = {
			0, 0, 0, 0, 0, 0, 0,
		},
	},
	.base_ext1 = {
		.ant_div_control = 0,
		.future = {0, 0, 0},
		.tempslopextension = {0, 0, 0, 0, 0, 0, 0, 0}
	},
	.calFreqPier2G = {
		FREQ2FBIN(2412, 1),
		FREQ2FBIN(2437, 1),
		FREQ2FBIN(2462, 1),
	},
	/* ar9300_cal_data_per_freq_op_loop 2g */
	.calPierData2G = {
		{ {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0} },
		{ {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0} },
		{ {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0} },
	},
	.calTarget_freqbin_Cck = {
		FREQ2FBIN(2412, 1),
		FREQ2FBIN(2472, 1),
	},
	.calTarget_freqbin_2G = {
		FREQ2FBIN(2412, 1),
		FREQ2FBIN(2437, 1),
		FREQ2FBIN(2472, 1)
	},
	.calTarget_freqbin_2GHT20 = {
		FREQ2FBIN(2412, 1),
		FREQ2FBIN(2437, 1),
		FREQ2FBIN(2472, 1)
	},
	.calTarget_freqbin_2GHT40 = {
		FREQ2FBIN(2412, 1),
		FREQ2FBIN(2437, 1),
		FREQ2FBIN(2472, 1)
	},
	.calTargetPowerCck = {
		/* 1L-5L,5S,11L,11S */
		{ {34, 34, 34, 34} },
		{ {34, 34, 34, 34} },
	},
	.calTargetPower2G = {
		/* 6-24,36,48,54 */
		{ {34, 34, 32, 32} },
		{ {34, 34, 32, 32} },
		{ {34, 34, 32, 32} },
	},
	.calTargetPower2GHT20 = {
		{ {32, 32, 32, 32, 32, 30, 32, 32, 30, 28, 28, 28, 28, 24} },
		{ {32, 32, 32, 32, 32, 30, 32, 32, 30, 28, 28, 28, 28, 24} },
		{ {32, 32, 32, 32, 32, 30, 32, 32, 30, 28, 28, 28, 28, 24} },
	},
	.calTargetPower2GHT40 = {
		{ {30, 30, 30, 30, 30, 28, 30, 30, 28, 26, 26, 26, 26, 22} },
		{ {30, 30, 30, 30, 30, 28, 30, 30, 28, 26, 26, 26, 26, 22} },
		{ {30, 30, 30, 30, 30, 28, 30, 30, 28, 26, 26, 26, 26, 22} },
	},
	.ctlIndex_2G =  {
		0x11, 0x12, 0x15, 0x17, 0x41, 0x42,
		0x45, 0x47, 0x31, 0x32, 0x35, 0x37,
	},
	.ctl_freqbin_2G = {
		{
			FREQ2FBIN(2412, 1),
			FREQ2FBIN(2417, 1),
			FREQ2FBIN(2457, 1),
			FREQ2FBIN(2462, 1)
		},
		{
			FREQ2FBIN(2412, 1),
			FREQ2FBIN(2417, 1),
			FREQ2FBIN(2462, 1),
			0xFF,
		},

		{
			FREQ2FBIN(2412, 1),
			FREQ2FBIN(2417, 1),
			FREQ2FBIN(2462, 1),
			0xFF,
		},
		{
			FREQ2FBIN(2422, 1),
			FREQ2FBIN(2427, 1),
			FREQ2FBIN(2447, 1),
			FREQ2FBIN(2452, 1)
		},

		{
			/* Data[4].ctlEdges[0].bChannel */ FREQ2FBIN(2412, 1),
			/* Data[4].ctlEdges[1].bChannel */ FREQ2FBIN(2417, 1),
			/* Data[4].ctlEdges[2].bChannel */ FREQ2FBIN(2472, 1),
			/* Data[4].ctlEdges[3].bChannel */ FREQ2FBIN(2484, 1),
		},

		{
			/* Data[5].ctlEdges[0].bChannel */ FREQ2FBIN(2412, 1),
			/* Data[5].ctlEdges[1].bChannel */ FREQ2FBIN(2417, 1),
			/* Data[5].ctlEdges[2].bChannel */ FREQ2FBIN(2472, 1),
			0,
		},

		{
			/* Data[6].ctlEdges[0].bChannel */ FREQ2FBIN(2412, 1),
			/* Data[6].ctlEdges[1].bChannel */ FREQ2FBIN(2417, 1),
			FREQ2FBIN(2472, 1),
			0,
		},

		{
			/* Data[7].ctlEdges[0].bChannel */ FREQ2FBIN(2422, 1),
			/* Data[7].ctlEdges[1].bChannel */ FREQ2FBIN(2427, 1),
			/* Data[7].ctlEdges[2].bChannel */ FREQ2FBIN(2447, 1),
			/* Data[7].ctlEdges[3].bChannel */ FREQ2FBIN(2462, 1),
		},

		{
			/* Data[8].ctlEdges[0].bChannel */ FREQ2FBIN(2412, 1),
			/* Data[8].ctlEdges[1].bChannel */ FREQ2FBIN(2417, 1),
			/* Data[8].ctlEdges[2].bChannel */ FREQ2FBIN(2472, 1),
		},

		{
			/* Data[9].ctlEdges[0].bChannel */ FREQ2FBIN(2412, 1),
			/* Data[9].ctlEdges[1].bChannel */ FREQ2FBIN(2417, 1),
			/* Data[9].ctlEdges[2].bChannel */ FREQ2FBIN(2472, 1),
			0
		},

		{
			/* Data[10].ctlEdges[0].bChannel */ FREQ2FBIN(2412, 1),
			/* Data[10].ctlEdges[1].bChannel */ FREQ2FBIN(2417, 1),
			/* Data[10].ctlEdges[2].bChannel */ FREQ2FBIN(2472, 1),
			0
		},

		{
			/* Data[11].ctlEdges[0].bChannel */ FREQ2FBIN(2422, 1),
			/* Data[11].ctlEdges[1].bChannel */ FREQ2FBIN(2427, 1),
			/* Data[11].ctlEdges[2].bChannel */ FREQ2FBIN(2447, 1),
			/* Data[11].ctlEdges[3].bChannel */ FREQ2FBIN(2462, 1),
		}
	},
	.ctlPowerData_2G = {
		{ { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },
		{ { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },
		{ { CTL(60, 1), CTL(60, 0), CTL(60, 0), CTL(60, 1) } },

		{ { CTL(60, 1), CTL(60, 0), CTL(60, 0), CTL(60, 0) } },
		{ { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },
		{ { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },

		{ { CTL(60, 0), CTL(60, 1), CTL(60, 1), CTL(60, 0) } },
		{ { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },
		{ { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },

		{ { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },
		{ { CTL(60, 0), CTL(60, 1), CTL(60, 1), CTL(60, 1) } },
		{ { CTL(60, 0), CTL(60, 1), CTL(60, 1), CTL(60, 1) } },
	},
	.modalHeader5G = {
		/* xatten1DB 3 xatten1_db for AR9280 (0xa20c/b20c 5:0) */
		.xatten1DB = {0, 0, 0},

		/*
		 * xatten1Margin[AR9300_MAX_CHAINS]; 3 xatten1_margin
		 * for merlin (0xa20c/b20c 16:12
		 */
		.xatten1Margin = {0, 0, 0},
		.tempSlope = 45,
		.voltSlope = 0,
		/* spurChans spur channels in usual fbin coding format */
		.spurChans = {0, 0, 0, 0, 0},
		/* noiseFloorThreshCh Check if the register is per chain */
		.noiseFloorThreshCh = {-1, 0, 0},
		.reserved = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.quick_drop = 0,
		.xpaBiasLvl = 0,
		.txFrameToDataStart = 0x0e,
		.txFrameToPaOn = 0x0e,
		.txClip = 3, /* 4 bits tx_clip, 4 bits dac_scale_cck */
		.antennaGain = 0,
		.switchSettling = 0x2d,
		.adcDesiredSize = -30,
		.txEndToXpaOff = 0,
		.txEndToRxOn = 0x2,
		.txFrameToXpaOn = 0xe,
		.thresh62 = 28,
		.xlna_bias_strength = 0,
		.futureModal = {
			0, 0, 0, 0, 0, 0, 0,
		},
	},
	.base_ext2 = {
		.tempSlopeLow = 40,
		.tempSlopeHigh = 50,
		.xatten1DBLow = {0, 0, 0},
		.xatten1MarginLow = {0, 0, 0},
		.xatten1DBHigh = {0, 0, 0},
		.xatten1MarginHigh = {0, 0, 0}
	},
	.calFreqPier5G = {
		FREQ2FBIN(5180, 0),
		FREQ2FBIN(5220, 0),
		FREQ2FBIN(5320, 0),
		FREQ2FBIN(5400, 0),
		FREQ2FBIN(5500, 0),
		FREQ2FBIN(5600, 0),
		FREQ2FBIN(5700, 0),
		FREQ2FBIN(5785, 0)
	},
	.calPierData5G = {
		{
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
		},
		{
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
		},
		{
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
		},

	},
	.calTarget_freqbin_5G = {
		FREQ2FBIN(5180, 0),
		FREQ2FBIN(5240, 0),
		FREQ2FBIN(5320, 0),
		FREQ2FBIN(5400, 0),
		FREQ2FBIN(5500, 0),
		FREQ2FBIN(5600, 0),
		FREQ2FBIN(5700, 0),
		FREQ2FBIN(5825, 0)
	},
	.calTarget_freqbin_5GHT20 = {
		FREQ2FBIN(5180, 0),
		FREQ2FBIN(5240, 0),
		FREQ2FBIN(5320, 0),
		FREQ2FBIN(5400, 0),
		FREQ2FBIN(5500, 0),
		FREQ2FBIN(5700, 0),
		FREQ2FBIN(5745, 0),
		FREQ2FBIN(5825, 0)
	},
	.calTarget_freqbin_5GHT40 = {
		FREQ2FBIN(5180, 0),
		FREQ2FBIN(5240, 0),
		FREQ2FBIN(5320, 0),
		FREQ2FBIN(5400, 0),
		FREQ2FBIN(5500, 0),
		FREQ2FBIN(5700, 0),
		FREQ2FBIN(5745, 0),
		FREQ2FBIN(5825, 0)
	},
	.calTargetPower5G = {
		/* 6-24,36,48,54 */
		{ {30, 30, 28, 24} },
		{ {30, 30, 28, 24} },
		{ {30, 30, 28, 24} },
		{ {30, 30, 28, 24} },
		{ {30, 30, 28, 24} },
		{ {30, 30, 28, 24} },
		{ {30, 30, 28, 24} },
		{ {30, 30, 28, 24} },
	},
	.calTargetPower5GHT20 = {
		/*
		 * 0_8_16,1-3_9-11_17-19,
		 * 4,5,6,7,12,13,14,15,20,21,22,23
		 */
		{ {30, 30, 30, 28, 24, 20, 30, 28, 24, 20, 20, 20, 20, 16} },
		{ {30, 30, 30, 28, 24, 20, 30, 28, 24, 20, 20, 20, 20, 16} },
		{ {30, 30, 30, 26, 22, 18, 30, 26, 22, 18, 18, 18, 18, 16} },
		{ {30, 30, 30, 26, 22, 18, 30, 26, 22, 18, 18, 18, 18, 16} },
		{ {30, 30, 30, 24, 20, 16, 30, 24, 20, 16, 16, 16, 16, 14} },
		{ {30, 30, 30, 24, 20, 16, 30, 24, 20, 16, 16, 16, 16, 14} },
		{ {30, 30, 30, 22, 18, 14, 30, 22, 18, 14, 14, 14, 14, 12} },
		{ {30, 30, 30, 22, 18, 14, 30, 22, 18, 14, 14, 14, 14, 12} },
	},
	.calTargetPower5GHT40 =  {
		/*
		 * 0_8_16,1-3_9-11_17-19,
		 * 4,5,6,7,12,13,14,15,20,21,22,23
		 */
		{ {28, 28, 28, 26, 22, 18, 28, 26, 22, 18, 18, 18, 18, 14} },
		{ {28, 28, 28, 26, 22, 18, 28, 26, 22, 18, 18, 18, 18, 14} },
		{ {28, 28, 28, 24, 20, 16, 28, 24, 20, 16, 16, 16, 16, 12} },
		{ {28, 28, 28, 24, 20, 16, 28, 24, 20, 16, 16, 16, 16, 12} },
		{ {28, 28, 28, 22, 18, 14, 28, 22, 18, 14, 14, 14, 14, 10} },
		{ {28, 28, 28, 22, 18, 14, 28, 22, 18, 14, 14, 14, 14, 10} },
		{ {28, 28, 28, 20, 16, 12, 28, 20, 16, 12, 12, 12, 12, 8} },
		{ {28, 28, 28, 20, 16, 12, 28, 20, 16, 12, 12, 12, 12, 8} },
	},
	.ctlIndex_5G =  {
		0x10, 0x16, 0x18, 0x40, 0x46,
		0x48, 0x30, 0x36, 0x38
	},
	.ctl_freqbin_5G =  {
		{
			/* Data[0].ctlEdges[0].bChannel */ FREQ2FBIN(5180, 0),
			/* Data[0].ctlEdges[1].bChannel */ FREQ2FBIN(5260, 0),
			/* Data[0].ctlEdges[2].bChannel */ FREQ2FBIN(5280, 0),
			/* Data[0].ctlEdges[3].bChannel */ FREQ2FBIN(5500, 0),
			/* Data[0].ctlEdges[4].bChannel */ FREQ2FBIN(5600, 0),
			/* Data[0].ctlEdges[5].bChannel */ FREQ2FBIN(5700, 0),
			/* Data[0].ctlEdges[6].bChannel */ FREQ2FBIN(5745, 0),
			/* Data[0].ctlEdges[7].bChannel */ FREQ2FBIN(5825, 0)
		},
		{
			/* Data[1].ctlEdges[0].bChannel */ FREQ2FBIN(5180, 0),
			/* Data[1].ctlEdges[1].bChannel */ FREQ2FBIN(5260, 0),
			/* Data[1].ctlEdges[2].bChannel */ FREQ2FBIN(5280, 0),
			/* Data[1].ctlEdges[3].bChannel */ FREQ2FBIN(5500, 0),
			/* Data[1].ctlEdges[4].bChannel */ FREQ2FBIN(5520, 0),
			/* Data[1].ctlEdges[5].bChannel */ FREQ2FBIN(5700, 0),
			/* Data[1].ctlEdges[6].bChannel */ FREQ2FBIN(5745, 0),
			/* Data[1].ctlEdges[7].bChannel */ FREQ2FBIN(5825, 0)
		},

		{
			/* Data[2].ctlEdges[0].bChannel */ FREQ2FBIN(5190, 0),
			/* Data[2].ctlEdges[1].bChannel */ FREQ2FBIN(5230, 0),
			/* Data[2].ctlEdges[2].bChannel */ FREQ2FBIN(5270, 0),
			/* Data[2].ctlEdges[3].bChannel */ FREQ2FBIN(5310, 0),
			/* Data[2].ctlEdges[4].bChannel */ FREQ2FBIN(5510, 0),
			/* Data[2].ctlEdges[5].bChannel */ FREQ2FBIN(5550, 0),
			/* Data[2].ctlEdges[6].bChannel */ FREQ2FBIN(5670, 0),
			/* Data[2].ctlEdges[7].bChannel */ FREQ2FBIN(5755, 0)
		},

		{
			/* Data[3].ctlEdges[0].bChannel */ FREQ2FBIN(5180, 0),
			/* Data[3].ctlEdges[1].bChannel */ FREQ2FBIN(5200, 0),
			/* Data[3].ctlEdges[2].bChannel */ FREQ2FBIN(5260, 0),
			/* Data[3].ctlEdges[3].bChannel */ FREQ2FBIN(5320, 0),
			/* Data[3].ctlEdges[4].bChannel */ FREQ2FBIN(5500, 0),
			/* Data[3].ctlEdges[5].bChannel */ FREQ2FBIN(5700, 0),
			/* Data[3].ctlEdges[6].bChannel */ 0xFF,
			/* Data[3].ctlEdges[7].bChannel */ 0xFF,
		},

		{
			/* Data[4].ctlEdges[0].bChannel */ FREQ2FBIN(5180, 0),
			/* Data[4].ctlEdges[1].bChannel */ FREQ2FBIN(5260, 0),
			/* Data[4].ctlEdges[2].bChannel */ FREQ2FBIN(5500, 0),
			/* Data[4].ctlEdges[3].bChannel */ FREQ2FBIN(5700, 0),
			/* Data[4].ctlEdges[4].bChannel */ 0xFF,
			/* Data[4].ctlEdges[5].bChannel */ 0xFF,
			/* Data[4].ctlEdges[6].bChannel */ 0xFF,
			/* Data[4].ctlEdges[7].bChannel */ 0xFF,
		},

		{
			/* Data[5].ctlEdges[0].bChannel */ FREQ2FBIN(5190, 0),
			/* Data[5].ctlEdges[1].bChannel */ FREQ2FBIN(5270, 0),
			/* Data[5].ctlEdges[2].bChannel */ FREQ2FBIN(5310, 0),
			/* Data[5].ctlEdges[3].bChannel */ FREQ2FBIN(5510, 0),
			/* Data[5].ctlEdges[4].bChannel */ FREQ2FBIN(5590, 0),
			/* Data[5].ctlEdges[5].bChannel */ FREQ2FBIN(5670, 0),
			/* Data[5].ctlEdges[6].bChannel */ 0xFF,
			/* Data[5].ctlEdges[7].bChannel */ 0xFF
		},

		{
			/* Data[6].ctlEdges[0].bChannel */ FREQ2FBIN(5180, 0),
			/* Data[6].ctlEdges[1].bChannel */ FREQ2FBIN(5200, 0),
			/* Data[6].ctlEdges[2].bChannel */ FREQ2FBIN(5220, 0),
			/* Data[6].ctlEdges[3].bChannel */ FREQ2FBIN(5260, 0),
			/* Data[6].ctlEdges[4].bChannel */ FREQ2FBIN(5500, 0),
			/* Data[6].ctlEdges[5].bChannel */ FREQ2FBIN(5600, 0),
			/* Data[6].ctlEdges[6].bChannel */ FREQ2FBIN(5700, 0),
			/* Data[6].ctlEdges[7].bChannel */ FREQ2FBIN(5745, 0)
		},

		{
			/* Data[7].ctlEdges[0].bChannel */ FREQ2FBIN(5180, 0),
			/* Data[7].ctlEdges[1].bChannel */ FREQ2FBIN(5260, 0),
			/* Data[7].ctlEdges[2].bChannel */ FREQ2FBIN(5320, 0),
			/* Data[7].ctlEdges[3].bChannel */ FREQ2FBIN(5500, 0),
			/* Data[7].ctlEdges[4].bChannel */ FREQ2FBIN(5560, 0),
			/* Data[7].ctlEdges[5].bChannel */ FREQ2FBIN(5700, 0),
			/* Data[7].ctlEdges[6].bChannel */ FREQ2FBIN(5745, 0),
			/* Data[7].ctlEdges[7].bChannel */ FREQ2FBIN(5825, 0)
		},

		{
			/* Data[8].ctlEdges[0].bChannel */ FREQ2FBIN(5190, 0),
			/* Data[8].ctlEdges[1].bChannel */ FREQ2FBIN(5230, 0),
			/* Data[8].ctlEdges[2].bChannel */ FREQ2FBIN(5270, 0),
			/* Data[8].ctlEdges[3].bChannel */ FREQ2FBIN(5510, 0),
			/* Data[8].ctlEdges[4].bChannel */ FREQ2FBIN(5550, 0),
			/* Data[8].ctlEdges[5].bChannel */ FREQ2FBIN(5670, 0),
			/* Data[8].ctlEdges[6].bChannel */ FREQ2FBIN(5755, 0),
			/* Data[8].ctlEdges[7].bChannel */ FREQ2FBIN(5795, 0)
		}
	},
	.ctlPowerData_5G = {
		{
			{
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 1),
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 0),
			}
		},
		{
			{
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 1),
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 0),
			}
		},
		{
			{
				CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 1),
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 1),
			}
		},
		{
			{
				CTL(60, 0), CTL(60, 1), CTL(60, 1), CTL(60, 0),
				CTL(60, 1), CTL(60, 0), CTL(60, 0), CTL(60, 0),
			}
		},
		{
			{
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 0),
				CTL(60, 0), CTL(60, 0), CTL(60, 0), CTL(60, 0),
			}
		},
		{
			{
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 1),
				CTL(60, 1), CTL(60, 0), CTL(60, 0), CTL(60, 0),
			}
		},
		{
			{
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 1),
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 1),
			}
		},
		{
			{
				CTL(60, 1), CTL(60, 1), CTL(60, 0), CTL(60, 1),
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 0),
			}
		},
		{
			{
				CTL(60, 1), CTL(60, 0), CTL(60, 1), CTL(60, 1),
				CTL(60, 1), CTL(60, 1), CTL(60, 0), CTL(60, 1),
			}
		},
	}
};


static struct ar9300_eeprom ar9300_x112 = {
	.eepromVersion = 2,
	.templateVersion = 5,
	.macAddr = {0x00, 0x03, 0x7f, 0x0, 0x0, 0x0},
	.custData = {"x112-041-f0000"},
	.baseEepHeader = {
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
	},
	.modalHeader2G = {
		/* ar9300_modal_eep_header  2g */
		/*
		 * xatten1DB[AR9300_max_chains];  3 xatten1_db
		 * for ar9280 (0xa20c/b20c 5:0)
		 */
		.xatten1DB = {0x1b, 0x1b, 0x1b},

		/*
		 * xatten1Margin[ar9300_max_chains]; 3 xatten1_margin
		 * for ar9280 (0xa20c/b20c 16:12
		 */
		.xatten1Margin = {0x15, 0x15, 0x15},
		.tempSlope = 50,
		.voltSlope = 0,

		/*
		 * spurChans[OSPrey_eeprom_modal_sPURS]; spur
		 * channels in usual fbin coding format
		 */
		.spurChans = {FREQ2FBIN(2464, 1), 0, 0, 0, 0},

		/*
		 * noiseFloorThreshch[ar9300_max_cHAINS]; 3 Check
		 * if the register is per chain
		 */
		.noiseFloorThreshCh = {-1, 0, 0},
		.reserved = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.quick_drop = 0,
		.xpaBiasLvl = 0,
		.txFrameToDataStart = 0x0e,
		.txFrameToPaOn = 0x0e,
		.txClip = 3, /* 4 bits tx_clip, 4 bits dac_scale_cck */
		.antennaGain = 0,
		.switchSettling = 0x2c,
		.adcDesiredSize = -30,
		.txEndToXpaOff = 0,
		.txEndToRxOn = 0x2,
		.txFrameToXpaOn = 0xe,
		.thresh62 = 28,
		.xlna_bias_strength = 0,
		.futureModal = {
			0, 0, 0, 0, 0, 0, 0,
		},
	},
	.base_ext1 = {
		.ant_div_control = 0,
		.future = {0, 0, 0},
		.tempslopextension = {0, 0, 0, 0, 0, 0, 0, 0}
	},
	.calFreqPier2G = {
		FREQ2FBIN(2412, 1),
		FREQ2FBIN(2437, 1),
		FREQ2FBIN(2472, 1),
	},
	/* ar9300_cal_data_per_freq_op_loop 2g */
	.calPierData2G = {
		{ {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0} },
		{ {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0} },
		{ {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0} },
	},
	.calTarget_freqbin_Cck = {
		FREQ2FBIN(2412, 1),
		FREQ2FBIN(2472, 1),
	},
	.calTarget_freqbin_2G = {
		FREQ2FBIN(2412, 1),
		FREQ2FBIN(2437, 1),
		FREQ2FBIN(2472, 1)
	},
	.calTarget_freqbin_2GHT20 = {
		FREQ2FBIN(2412, 1),
		FREQ2FBIN(2437, 1),
		FREQ2FBIN(2472, 1)
	},
	.calTarget_freqbin_2GHT40 = {
		FREQ2FBIN(2412, 1),
		FREQ2FBIN(2437, 1),
		FREQ2FBIN(2472, 1)
	},
	.calTargetPowerCck = {
		/* 1L-5L,5S,11L,11s */
		{ {38, 38, 38, 38} },
		{ {38, 38, 38, 38} },
	},
	.calTargetPower2G = {
		/* 6-24,36,48,54 */
		{ {38, 38, 36, 34} },
		{ {38, 38, 36, 34} },
		{ {38, 38, 34, 32} },
	},
	.calTargetPower2GHT20 = {
		{ {36, 36, 36, 36, 36, 34, 34, 32, 30, 28, 28, 28, 28, 26} },
		{ {36, 36, 36, 36, 36, 34, 36, 34, 32, 30, 30, 30, 28, 26} },
		{ {36, 36, 36, 36, 36, 34, 34, 32, 30, 28, 28, 28, 28, 26} },
	},
	.calTargetPower2GHT40 = {
		{ {36, 36, 36, 36, 34, 32, 32, 30, 28, 26, 26, 26, 26, 24} },
		{ {36, 36, 36, 36, 34, 32, 34, 32, 30, 28, 28, 28, 28, 24} },
		{ {36, 36, 36, 36, 34, 32, 32, 30, 28, 26, 26, 26, 26, 24} },
	},
	.ctlIndex_2G =  {
		0x11, 0x12, 0x15, 0x17, 0x41, 0x42,
		0x45, 0x47, 0x31, 0x32, 0x35, 0x37,
	},
	.ctl_freqbin_2G = {
		{
			FREQ2FBIN(2412, 1),
			FREQ2FBIN(2417, 1),
			FREQ2FBIN(2457, 1),
			FREQ2FBIN(2462, 1)
		},
		{
			FREQ2FBIN(2412, 1),
			FREQ2FBIN(2417, 1),
			FREQ2FBIN(2462, 1),
			0xFF,
		},

		{
			FREQ2FBIN(2412, 1),
			FREQ2FBIN(2417, 1),
			FREQ2FBIN(2462, 1),
			0xFF,
		},
		{
			FREQ2FBIN(2422, 1),
			FREQ2FBIN(2427, 1),
			FREQ2FBIN(2447, 1),
			FREQ2FBIN(2452, 1)
		},

		{
			/* Data[4].ctledges[0].bchannel */ FREQ2FBIN(2412, 1),
			/* Data[4].ctledges[1].bchannel */ FREQ2FBIN(2417, 1),
			/* Data[4].ctledges[2].bchannel */ FREQ2FBIN(2472, 1),
			/* Data[4].ctledges[3].bchannel */ FREQ2FBIN(2484, 1),
		},

		{
			/* Data[5].ctledges[0].bchannel */ FREQ2FBIN(2412, 1),
			/* Data[5].ctledges[1].bchannel */ FREQ2FBIN(2417, 1),
			/* Data[5].ctledges[2].bchannel */ FREQ2FBIN(2472, 1),
			0,
		},

		{
			/* Data[6].ctledges[0].bchannel */ FREQ2FBIN(2412, 1),
			/* Data[6].ctledges[1].bchannel */ FREQ2FBIN(2417, 1),
			FREQ2FBIN(2472, 1),
			0,
		},

		{
			/* Data[7].ctledges[0].bchannel */ FREQ2FBIN(2422, 1),
			/* Data[7].ctledges[1].bchannel */ FREQ2FBIN(2427, 1),
			/* Data[7].ctledges[2].bchannel */ FREQ2FBIN(2447, 1),
			/* Data[7].ctledges[3].bchannel */ FREQ2FBIN(2462, 1),
		},

		{
			/* Data[8].ctledges[0].bchannel */ FREQ2FBIN(2412, 1),
			/* Data[8].ctledges[1].bchannel */ FREQ2FBIN(2417, 1),
			/* Data[8].ctledges[2].bchannel */ FREQ2FBIN(2472, 1),
		},

		{
			/* Data[9].ctledges[0].bchannel */ FREQ2FBIN(2412, 1),
			/* Data[9].ctledges[1].bchannel */ FREQ2FBIN(2417, 1),
			/* Data[9].ctledges[2].bchannel */ FREQ2FBIN(2472, 1),
			0
		},

		{
			/* Data[10].ctledges[0].bchannel */ FREQ2FBIN(2412, 1),
			/* Data[10].ctledges[1].bchannel */ FREQ2FBIN(2417, 1),
			/* Data[10].ctledges[2].bchannel */ FREQ2FBIN(2472, 1),
			0
		},

		{
			/* Data[11].ctledges[0].bchannel */ FREQ2FBIN(2422, 1),
			/* Data[11].ctledges[1].bchannel */ FREQ2FBIN(2427, 1),
			/* Data[11].ctledges[2].bchannel */ FREQ2FBIN(2447, 1),
			/* Data[11].ctledges[3].bchannel */ FREQ2FBIN(2462, 1),
		}
	},
	.ctlPowerData_2G = {
		{ { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },
		{ { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },
		{ { CTL(60, 1), CTL(60, 0), CTL(60, 0), CTL(60, 1) } },

		{ { CTL(60, 1), CTL(60, 0), CTL(60, 0), CTL(60, 0) } },
		{ { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },
		{ { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },

		{ { CTL(60, 0), CTL(60, 1), CTL(60, 1), CTL(60, 0) } },
		{ { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },
		{ { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },

		{ { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },
		{ { CTL(60, 0), CTL(60, 1), CTL(60, 1), CTL(60, 1) } },
		{ { CTL(60, 0), CTL(60, 1), CTL(60, 1), CTL(60, 1) } },
	},
	.modalHeader5G = {
		/* xatten1DB 3 xatten1_db for ar9280 (0xa20c/b20c 5:0) */
		.xatten1DB = {0x13, 0x19, 0x17},

		/*
		 * xatten1Margin[ar9300_max_chains]; 3 xatten1_margin
		 * for merlin (0xa20c/b20c 16:12
		 */
		.xatten1Margin = {0x19, 0x19, 0x19},
		.tempSlope = 70,
		.voltSlope = 15,
		/* spurChans spur channels in usual fbin coding format */
		.spurChans = {0, 0, 0, 0, 0},
		/* noiseFloorThreshch check if the register is per chain */
		.noiseFloorThreshCh = {-1, 0, 0},
		.reserved = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.quick_drop = 0,
		.xpaBiasLvl = 0,
		.txFrameToDataStart = 0x0e,
		.txFrameToPaOn = 0x0e,
		.txClip = 3, /* 4 bits tx_clip, 4 bits dac_scale_cck */
		.antennaGain = 0,
		.switchSettling = 0x2d,
		.adcDesiredSize = -30,
		.txEndToXpaOff = 0,
		.txEndToRxOn = 0x2,
		.txFrameToXpaOn = 0xe,
		.thresh62 = 28,
		.xlna_bias_strength = 0,
		.futureModal = {
			0, 0, 0, 0, 0, 0, 0,
		},
	},
	.base_ext2 = {
		.tempSlopeLow = 72,
		.tempSlopeHigh = 105,
		.xatten1DBLow = {0x10, 0x14, 0x10},
		.xatten1MarginLow = {0x19, 0x19 , 0x19},
		.xatten1DBHigh = {0x1d, 0x20, 0x24},
		.xatten1MarginHigh = {0x10, 0x10, 0x10}
	},
	.calFreqPier5G = {
		FREQ2FBIN(5180, 0),
		FREQ2FBIN(5220, 0),
		FREQ2FBIN(5320, 0),
		FREQ2FBIN(5400, 0),
		FREQ2FBIN(5500, 0),
		FREQ2FBIN(5600, 0),
		FREQ2FBIN(5700, 0),
		FREQ2FBIN(5785, 0)
	},
	.calPierData5G = {
		{
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
		},
		{
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
		},
		{
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
			{0, 0, 0, 0, 0},
		},

	},
	.calTarget_freqbin_5G = {
		FREQ2FBIN(5180, 0),
		FREQ2FBIN(5220, 0),
		FREQ2FBIN(5320, 0),
		FREQ2FBIN(5400, 0),
		FREQ2FBIN(5500, 0),
		FREQ2FBIN(5600, 0),
		FREQ2FBIN(5725, 0),
		FREQ2FBIN(5825, 0)
	},
	.calTarget_freqbin_5GHT20 = {
		FREQ2FBIN(5180, 0),
		FREQ2FBIN(5220, 0),
		FREQ2FBIN(5320, 0),
		FREQ2FBIN(5400, 0),
		FREQ2FBIN(5500, 0),
		FREQ2FBIN(5600, 0),
		FREQ2FBIN(5725, 0),
		FREQ2FBIN(5825, 0)
	},
	.calTarget_freqbin_5GHT40 = {
		FREQ2FBIN(5180, 0),
		FREQ2FBIN(5220, 0),
		FREQ2FBIN(5320, 0),
		FREQ2FBIN(5400, 0),
		FREQ2FBIN(5500, 0),
		FREQ2FBIN(5600, 0),
		FREQ2FBIN(5725, 0),
		FREQ2FBIN(5825, 0)
	},
	.calTargetPower5G = {
		/* 6-24,36,48,54 */
		{ {32, 32, 28, 26} },
		{ {32, 32, 28, 26} },
		{ {32, 32, 28, 26} },
		{ {32, 32, 26, 24} },
		{ {32, 32, 26, 24} },
		{ {32, 32, 24, 22} },
		{ {30, 30, 24, 22} },
		{ {30, 30, 24, 22} },
	},
	.calTargetPower5GHT20 = {
		/*
		 * 0_8_16,1-3_9-11_17-19,
		 * 4,5,6,7,12,13,14,15,20,21,22,23
		 */
		{ {32, 32, 32, 32, 28, 26, 32, 28, 26, 24, 24, 24, 22, 22} },
		{ {32, 32, 32, 32, 28, 26, 32, 28, 26, 24, 24, 24, 22, 22} },
		{ {32, 32, 32, 32, 28, 26, 32, 28, 26, 24, 24, 24, 22, 22} },
		{ {32, 32, 32, 32, 28, 26, 32, 26, 24, 22, 22, 22, 20, 20} },
		{ {32, 32, 32, 32, 28, 26, 32, 26, 24, 22, 20, 18, 16, 16} },
		{ {32, 32, 32, 32, 28, 26, 32, 24, 20, 16, 18, 16, 14, 14} },
		{ {30, 30, 30, 30, 28, 26, 30, 24, 20, 16, 18, 16, 14, 14} },
		{ {30, 30, 30, 30, 28, 26, 30, 24, 20, 16, 18, 16, 14, 14} },
	},
	.calTargetPower5GHT40 =  {
		/*
		 * 0_8_16,1-3_9-11_17-19,
		 * 4,5,6,7,12,13,14,15,20,21,22,23
		 */
		{ {32, 32, 32, 30, 28, 26, 30, 28, 26, 24, 24, 24, 22, 22} },
		{ {32, 32, 32, 30, 28, 26, 30, 28, 26, 24, 24, 24, 22, 22} },
		{ {32, 32, 32, 30, 28, 26, 30, 28, 26, 24, 24, 24, 22, 22} },
		{ {32, 32, 32, 30, 28, 26, 30, 26, 24, 22, 22, 22, 20, 20} },
		{ {32, 32, 32, 30, 28, 26, 30, 26, 24, 22, 20, 18, 16, 16} },
		{ {32, 32, 32, 30, 28, 26, 30, 22, 20, 16, 18, 16, 14, 14} },
		{ {30, 30, 30, 30, 28, 26, 30, 22, 20, 16, 18, 16, 14, 14} },
		{ {30, 30, 30, 30, 28, 26, 30, 22, 20, 16, 18, 16, 14, 14} },
	},
	.ctlIndex_5G =  {
		0x10, 0x16, 0x18, 0x40, 0x46,
		0x48, 0x30, 0x36, 0x38
	},
	.ctl_freqbin_5G =  {
		{
			/* Data[0].ctledges[0].bchannel */ FREQ2FBIN(5180, 0),
			/* Data[0].ctledges[1].bchannel */ FREQ2FBIN(5260, 0),
			/* Data[0].ctledges[2].bchannel */ FREQ2FBIN(5280, 0),
			/* Data[0].ctledges[3].bchannel */ FREQ2FBIN(5500, 0),
			/* Data[0].ctledges[4].bchannel */ FREQ2FBIN(5600, 0),
			/* Data[0].ctledges[5].bchannel */ FREQ2FBIN(5700, 0),
			/* Data[0].ctledges[6].bchannel */ FREQ2FBIN(5745, 0),
			/* Data[0].ctledges[7].bchannel */ FREQ2FBIN(5825, 0)
		},
		{
			/* Data[1].ctledges[0].bchannel */ FREQ2FBIN(5180, 0),
			/* Data[1].ctledges[1].bchannel */ FREQ2FBIN(5260, 0),
			/* Data[1].ctledges[2].bchannel */ FREQ2FBIN(5280, 0),
			/* Data[1].ctledges[3].bchannel */ FREQ2FBIN(5500, 0),
			/* Data[1].ctledges[4].bchannel */ FREQ2FBIN(5520, 0),
			/* Data[1].ctledges[5].bchannel */ FREQ2FBIN(5700, 0),
			/* Data[1].ctledges[6].bchannel */ FREQ2FBIN(5745, 0),
			/* Data[1].ctledges[7].bchannel */ FREQ2FBIN(5825, 0)
		},

		{
			/* Data[2].ctledges[0].bchannel */ FREQ2FBIN(5190, 0),
			/* Data[2].ctledges[1].bchannel */ FREQ2FBIN(5230, 0),
			/* Data[2].ctledges[2].bchannel */ FREQ2FBIN(5270, 0),
			/* Data[2].ctledges[3].bchannel */ FREQ2FBIN(5310, 0),
			/* Data[2].ctledges[4].bchannel */ FREQ2FBIN(5510, 0),
			/* Data[2].ctledges[5].bchannel */ FREQ2FBIN(5550, 0),
			/* Data[2].ctledges[6].bchannel */ FREQ2FBIN(5670, 0),
			/* Data[2].ctledges[7].bchannel */ FREQ2FBIN(5755, 0)
		},

		{
			/* Data[3].ctledges[0].bchannel */ FREQ2FBIN(5180, 0),
			/* Data[3].ctledges[1].bchannel */ FREQ2FBIN(5200, 0),
			/* Data[3].ctledges[2].bchannel */ FREQ2FBIN(5260, 0),
			/* Data[3].ctledges[3].bchannel */ FREQ2FBIN(5320, 0),
			/* Data[3].ctledges[4].bchannel */ FREQ2FBIN(5500, 0),
			/* Data[3].ctledges[5].bchannel */ FREQ2FBIN(5700, 0),
			/* Data[3].ctledges[6].bchannel */ 0xFF,
			/* Data[3].ctledges[7].bchannel */ 0xFF,
		},

		{
			/* Data[4].ctledges[0].bchannel */ FREQ2FBIN(5180, 0),
			/* Data[4].ctledges[1].bchannel */ FREQ2FBIN(5260, 0),
			/* Data[4].ctledges[2].bchannel */ FREQ2FBIN(5500, 0),
			/* Data[4].ctledges[3].bchannel */ FREQ2FBIN(5700, 0),
			/* Data[4].ctledges[4].bchannel */ 0xFF,
			/* Data[4].ctledges[5].bchannel */ 0xFF,
			/* Data[4].ctledges[6].bchannel */ 0xFF,
			/* Data[4].ctledges[7].bchannel */ 0xFF,
		},

		{
			/* Data[5].ctledges[0].bchannel */ FREQ2FBIN(5190, 0),
			/* Data[5].ctledges[1].bchannel */ FREQ2FBIN(5270, 0),
			/* Data[5].ctledges[2].bchannel */ FREQ2FBIN(5310, 0),
			/* Data[5].ctledges[3].bchannel */ FREQ2FBIN(5510, 0),
			/* Data[5].ctledges[4].bchannel */ FREQ2FBIN(5590, 0),
			/* Data[5].ctledges[5].bchannel */ FREQ2FBIN(5670, 0),
			/* Data[5].ctledges[6].bchannel */ 0xFF,
			/* Data[5].ctledges[7].bchannel */ 0xFF
		},

		{
			/* Data[6].ctledges[0].bchannel */ FREQ2FBIN(5180, 0),
			/* Data[6].ctledges[1].bchannel */ FREQ2FBIN(5200, 0),
			/* Data[6].ctledges[2].bchannel */ FREQ2FBIN(5220, 0),
			/* Data[6].ctledges[3].bchannel */ FREQ2FBIN(5260, 0),
			/* Data[6].ctledges[4].bchannel */ FREQ2FBIN(5500, 0),
			/* Data[6].ctledges[5].bchannel */ FREQ2FBIN(5600, 0),
			/* Data[6].ctledges[6].bchannel */ FREQ2FBIN(5700, 0),
			/* Data[6].ctledges[7].bchannel */ FREQ2FBIN(5745, 0)
		},

		{
			/* Data[7].ctledges[0].bchannel */ FREQ2FBIN(5180, 0),
			/* Data[7].ctledges[1].bchannel */ FREQ2FBIN(5260, 0),
			/* Data[7].ctledges[2].bchannel */ FREQ2FBIN(5320, 0),
			/* Data[7].ctledges[3].bchannel */ FREQ2FBIN(5500, 0),
			/* Data[7].ctledges[4].bchannel */ FREQ2FBIN(5560, 0),
			/* Data[7].ctledges[5].bchannel */ FREQ2FBIN(5700, 0),
			/* Data[7].ctledges[6].bchannel */ FREQ2FBIN(5745, 0),
			/* Data[7].ctledges[7].bchannel */ FREQ2FBIN(5825, 0)
		},

		{
			/* Data[8].ctledges[0].bchannel */ FREQ2FBIN(5190, 0),
			/* Data[8].ctledges[1].bchannel */ FREQ2FBIN(5230, 0),
			/* Data[8].ctledges[2].bchannel */ FREQ2FBIN(5270, 0),
			/* Data[8].ctledges[3].bchannel */ FREQ2FBIN(5510, 0),
			/* Data[8].ctledges[4].bchannel */ FREQ2FBIN(5550, 0),
			/* Data[8].ctledges[5].bchannel */ FREQ2FBIN(5670, 0),
			/* Data[8].ctledges[6].bchannel */ FREQ2FBIN(5755, 0),
			/* Data[8].ctledges[7].bchannel */ FREQ2FBIN(5795, 0)
		}
	},
	.ctlPowerData_5G = {
		{
			{
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 1),
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 0),
			}
		},
		{
			{
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 1),
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 0),
			}
		},
		{
			{
				CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 1),
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 1),
			}
		},
		{
			{
				CTL(60, 0), CTL(60, 1), CTL(60, 1), CTL(60, 0),
				CTL(60, 1), CTL(60, 0), CTL(60, 0), CTL(60, 0),
			}
		},
		{
			{
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 0),
				CTL(60, 0), CTL(60, 0), CTL(60, 0), CTL(60, 0),
			}
		},
		{
			{
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 1),
				CTL(60, 1), CTL(60, 0), CTL(60, 0), CTL(60, 0),
			}
		},
		{
			{
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 1),
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 1),
			}
		},
		{
			{
				CTL(60, 1), CTL(60, 1), CTL(60, 0), CTL(60, 1),
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 0),
			}
		},
		{
			{
				CTL(60, 1), CTL(60, 0), CTL(60, 1), CTL(60, 1),
				CTL(60, 1), CTL(60, 1), CTL(60, 0), CTL(60, 1),
			}
		},
	}
};

static struct ar9300_eeprom ar9300_h116 = {
	.eepromVersion = 2,
	.templateVersion = 4,
	.macAddr = {0x00, 0x03, 0x7f, 0x0, 0x0, 0x0},
	.custData = {"h116-041-f0000"},
	.baseEepHeader = {
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
	 },
	.modalHeader2G = {
	/* ar9300_modal_eep_header  2g */
		/*
		 * xatten1DB[AR9300_MAX_CHAINS];  3 xatten1_db
		 * for ar9280 (0xa20c/b20c 5:0)
		 */
		.xatten1DB = {0x1f, 0x1f, 0x1f},

		/*
		 * xatten1Margin[AR9300_MAX_CHAINS]; 3 xatten1_margin
		 * for ar9280 (0xa20c/b20c 16:12
		 */
		.xatten1Margin = {0x12, 0x12, 0x12},
		.tempSlope = 25,
		.voltSlope = 0,

		/*
		 * spurChans[OSPREY_EEPROM_MODAL_SPURS]; spur
		 * channels in usual fbin coding format
		 */
		.spurChans = {FREQ2FBIN(2464, 1), 0, 0, 0, 0},

		/*
		 * noiseFloorThreshCh[AR9300_MAX_CHAINS]; 3 Check
		 * if the register is per chain
		 */
		.noiseFloorThreshCh = {-1, 0, 0},
		.reserved = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.quick_drop = 0,
		.xpaBiasLvl = 0,
		.txFrameToDataStart = 0x0e,
		.txFrameToPaOn = 0x0e,
		.txClip = 3, /* 4 bits tx_clip, 4 bits dac_scale_cck */
		.antennaGain = 0,
		.switchSettling = 0x2c,
		.adcDesiredSize = -30,
		.txEndToXpaOff = 0,
		.txEndToRxOn = 0x2,
		.txFrameToXpaOn = 0xe,
		.thresh62 = 28,
		.xlna_bias_strength = 0,
		.futureModal = {
			0, 0, 0, 0, 0, 0, 0,
		},
	 },
	 .base_ext1 = {
		.ant_div_control = 0,
		.future = {0, 0, 0},
		.tempslopextension = {0, 0, 0, 0, 0, 0, 0, 0}
	 },
	.calFreqPier2G = {
		FREQ2FBIN(2412, 1),
		FREQ2FBIN(2437, 1),
		FREQ2FBIN(2462, 1),
	 },
	/* ar9300_cal_data_per_freq_op_loop 2g */
	.calPierData2G = {
		{ {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0} },
		{ {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0} },
		{ {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0} },
	 },
	.calTarget_freqbin_Cck = {
		FREQ2FBIN(2412, 1),
		FREQ2FBIN(2472, 1),
	 },
	.calTarget_freqbin_2G = {
		FREQ2FBIN(2412, 1),
		FREQ2FBIN(2437, 1),
		FREQ2FBIN(2472, 1)
	 },
	.calTarget_freqbin_2GHT20 = {
		FREQ2FBIN(2412, 1),
		FREQ2FBIN(2437, 1),
		FREQ2FBIN(2472, 1)
	 },
	.calTarget_freqbin_2GHT40 = {
		FREQ2FBIN(2412, 1),
		FREQ2FBIN(2437, 1),
		FREQ2FBIN(2472, 1)
	 },
	.calTargetPowerCck = {
		 /* 1L-5L,5S,11L,11S */
		 { {34, 34, 34, 34} },
		 { {34, 34, 34, 34} },
	},
	.calTargetPower2G = {
		 /* 6-24,36,48,54 */
		 { {34, 34, 32, 32} },
		 { {34, 34, 32, 32} },
		 { {34, 34, 32, 32} },
	},
	.calTargetPower2GHT20 = {
		{ {32, 32, 32, 32, 32, 30, 32, 32, 30, 28, 0, 0, 0, 0} },
		{ {32, 32, 32, 32, 32, 30, 32, 32, 30, 28, 0, 0, 0, 0} },
		{ {32, 32, 32, 32, 32, 30, 32, 32, 30, 28, 0, 0, 0, 0} },
	},
	.calTargetPower2GHT40 = {
		{ {30, 30, 30, 30, 30, 28, 30, 30, 28, 26, 0, 0, 0, 0} },
		{ {30, 30, 30, 30, 30, 28, 30, 30, 28, 26, 0, 0, 0, 0} },
		{ {30, 30, 30, 30, 30, 28, 30, 30, 28, 26, 0, 0, 0, 0} },
	},
	.ctlIndex_2G =  {
		0x11, 0x12, 0x15, 0x17, 0x41, 0x42,
		0x45, 0x47, 0x31, 0x32, 0x35, 0x37,
	},
	.ctl_freqbin_2G = {
		{
			FREQ2FBIN(2412, 1),
			FREQ2FBIN(2417, 1),
			FREQ2FBIN(2457, 1),
			FREQ2FBIN(2462, 1)
		},
		{
			FREQ2FBIN(2412, 1),
			FREQ2FBIN(2417, 1),
			FREQ2FBIN(2462, 1),
			0xFF,
		},

		{
			FREQ2FBIN(2412, 1),
			FREQ2FBIN(2417, 1),
			FREQ2FBIN(2462, 1),
			0xFF,
		},
		{
			FREQ2FBIN(2422, 1),
			FREQ2FBIN(2427, 1),
			FREQ2FBIN(2447, 1),
			FREQ2FBIN(2452, 1)
		},

		{
			/* Data[4].ctlEdges[0].bChannel */ FREQ2FBIN(2412, 1),
			/* Data[4].ctlEdges[1].bChannel */ FREQ2FBIN(2417, 1),
			/* Data[4].ctlEdges[2].bChannel */ FREQ2FBIN(2472, 1),
			/* Data[4].ctlEdges[3].bChannel */ FREQ2FBIN(2484, 1),
		},

		{
			/* Data[5].ctlEdges[0].bChannel */ FREQ2FBIN(2412, 1),
			/* Data[5].ctlEdges[1].bChannel */ FREQ2FBIN(2417, 1),
			/* Data[5].ctlEdges[2].bChannel */ FREQ2FBIN(2472, 1),
			0,
		},

		{
			/* Data[6].ctlEdges[0].bChannel */ FREQ2FBIN(2412, 1),
			/* Data[6].ctlEdges[1].bChannel */ FREQ2FBIN(2417, 1),
			FREQ2FBIN(2472, 1),
			0,
		},

		{
			/* Data[7].ctlEdges[0].bChannel */ FREQ2FBIN(2422, 1),
			/* Data[7].ctlEdges[1].bChannel */ FREQ2FBIN(2427, 1),
			/* Data[7].ctlEdges[2].bChannel */ FREQ2FBIN(2447, 1),
			/* Data[7].ctlEdges[3].bChannel */ FREQ2FBIN(2462, 1),
		},

		{
			/* Data[8].ctlEdges[0].bChannel */ FREQ2FBIN(2412, 1),
			/* Data[8].ctlEdges[1].bChannel */ FREQ2FBIN(2417, 1),
			/* Data[8].ctlEdges[2].bChannel */ FREQ2FBIN(2472, 1),
		},

		{
			/* Data[9].ctlEdges[0].bChannel */ FREQ2FBIN(2412, 1),
			/* Data[9].ctlEdges[1].bChannel */ FREQ2FBIN(2417, 1),
			/* Data[9].ctlEdges[2].bChannel */ FREQ2FBIN(2472, 1),
			0
		},

		{
			/* Data[10].ctlEdges[0].bChannel */ FREQ2FBIN(2412, 1),
			/* Data[10].ctlEdges[1].bChannel */ FREQ2FBIN(2417, 1),
			/* Data[10].ctlEdges[2].bChannel */ FREQ2FBIN(2472, 1),
			0
		},

		{
			/* Data[11].ctlEdges[0].bChannel */ FREQ2FBIN(2422, 1),
			/* Data[11].ctlEdges[1].bChannel */ FREQ2FBIN(2427, 1),
			/* Data[11].ctlEdges[2].bChannel */ FREQ2FBIN(2447, 1),
			/* Data[11].ctlEdges[3].bChannel */ FREQ2FBIN(2462, 1),
		}
	 },
	.ctlPowerData_2G = {
		 { { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },
		 { { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },
		 { { CTL(60, 1), CTL(60, 0), CTL(60, 0), CTL(60, 1) } },

		 { { CTL(60, 1), CTL(60, 0), CTL(60, 0), CTL(60, 0) } },
		 { { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },
		 { { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },

		 { { CTL(60, 0), CTL(60, 1), CTL(60, 1), CTL(60, 0) } },
		 { { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },
		 { { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },

		 { { CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 0) } },
		 { { CTL(60, 0), CTL(60, 1), CTL(60, 1), CTL(60, 1) } },
		 { { CTL(60, 0), CTL(60, 1), CTL(60, 1), CTL(60, 1) } },
	 },
	.modalHeader5G = {
		 /* xatten1DB 3 xatten1_db for AR9280 (0xa20c/b20c 5:0) */
		.xatten1DB = {0x19, 0x19, 0x19},

		/*
		 * xatten1Margin[AR9300_MAX_CHAINS]; 3 xatten1_margin
		 * for merlin (0xa20c/b20c 16:12
		 */
		.xatten1Margin = {0x14, 0x14, 0x14},
		.tempSlope = 70,
		.voltSlope = 0,
		/* spurChans spur channels in usual fbin coding format */
		.spurChans = {0, 0, 0, 0, 0},
		/* noiseFloorThreshCh Check if the register is per chain */
		.noiseFloorThreshCh = {-1, 0, 0},
		.reserved = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		.quick_drop = 0,
		.xpaBiasLvl = 0,
		.txFrameToDataStart = 0x0e,
		.txFrameToPaOn = 0x0e,
		.txClip = 3, /* 4 bits tx_clip, 4 bits dac_scale_cck */
		.antennaGain = 0,
		.switchSettling = 0x2d,
		.adcDesiredSize = -30,
		.txEndToXpaOff = 0,
		.txEndToRxOn = 0x2,
		.txFrameToXpaOn = 0xe,
		.thresh62 = 28,
		.xlna_bias_strength = 0,
		.futureModal = {
			0, 0, 0, 0, 0, 0, 0,
		},
	 },
	.base_ext2 = {
		.tempSlopeLow = 35,
		.tempSlopeHigh = 50,
		.xatten1DBLow = {0, 0, 0},
		.xatten1MarginLow = {0, 0, 0},
		.xatten1DBHigh = {0, 0, 0},
		.xatten1MarginHigh = {0, 0, 0}
	 },
	.calFreqPier5G = {
		FREQ2FBIN(5160, 0),
		FREQ2FBIN(5220, 0),
		FREQ2FBIN(5320, 0),
		FREQ2FBIN(5400, 0),
		FREQ2FBIN(5500, 0),
		FREQ2FBIN(5600, 0),
		FREQ2FBIN(5700, 0),
		FREQ2FBIN(5785, 0)
	},
	.calPierData5G = {
			{
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
			},
			{
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
			},
			{
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
				{0, 0, 0, 0, 0},
			},

	},
	.calTarget_freqbin_5G = {
		FREQ2FBIN(5180, 0),
		FREQ2FBIN(5240, 0),
		FREQ2FBIN(5320, 0),
		FREQ2FBIN(5400, 0),
		FREQ2FBIN(5500, 0),
		FREQ2FBIN(5600, 0),
		FREQ2FBIN(5700, 0),
		FREQ2FBIN(5825, 0)
	},
	.calTarget_freqbin_5GHT20 = {
		FREQ2FBIN(5180, 0),
		FREQ2FBIN(5240, 0),
		FREQ2FBIN(5320, 0),
		FREQ2FBIN(5400, 0),
		FREQ2FBIN(5500, 0),
		FREQ2FBIN(5700, 0),
		FREQ2FBIN(5745, 0),
		FREQ2FBIN(5825, 0)
	},
	.calTarget_freqbin_5GHT40 = {
		FREQ2FBIN(5180, 0),
		FREQ2FBIN(5240, 0),
		FREQ2FBIN(5320, 0),
		FREQ2FBIN(5400, 0),
		FREQ2FBIN(5500, 0),
		FREQ2FBIN(5700, 0),
		FREQ2FBIN(5745, 0),
		FREQ2FBIN(5825, 0)
	 },
	.calTargetPower5G = {
		/* 6-24,36,48,54 */
		{ {30, 30, 28, 24} },
		{ {30, 30, 28, 24} },
		{ {30, 30, 28, 24} },
		{ {30, 30, 28, 24} },
		{ {30, 30, 28, 24} },
		{ {30, 30, 28, 24} },
		{ {30, 30, 28, 24} },
		{ {30, 30, 28, 24} },
	 },
	.calTargetPower5GHT20 = {
		/*
		 * 0_8_16,1-3_9-11_17-19,
		 * 4,5,6,7,12,13,14,15,20,21,22,23
		 */
		{ {30, 30, 30, 28, 24, 20, 30, 28, 24, 20, 0, 0, 0, 0} },
		{ {30, 30, 30, 28, 24, 20, 30, 28, 24, 20, 0, 0, 0, 0} },
		{ {30, 30, 30, 26, 22, 18, 30, 26, 22, 18, 0, 0, 0, 0} },
		{ {30, 30, 30, 26, 22, 18, 30, 26, 22, 18, 0, 0, 0, 0} },
		{ {30, 30, 30, 24, 20, 16, 30, 24, 20, 16, 0, 0, 0, 0} },
		{ {30, 30, 30, 24, 20, 16, 30, 24, 20, 16, 0, 0, 0, 0} },
		{ {30, 30, 30, 22, 18, 14, 30, 22, 18, 14, 0, 0, 0, 0} },
		{ {30, 30, 30, 22, 18, 14, 30, 22, 18, 14, 0, 0, 0, 0} },
	 },
	.calTargetPower5GHT40 =  {
		/*
		 * 0_8_16,1-3_9-11_17-19,
		 * 4,5,6,7,12,13,14,15,20,21,22,23
		 */
		{ {28, 28, 28, 26, 22, 18, 28, 26, 22, 18, 0, 0, 0, 0} },
		{ {28, 28, 28, 26, 22, 18, 28, 26, 22, 18, 0, 0, 0, 0} },
		{ {28, 28, 28, 24, 20, 16, 28, 24, 20, 16, 0, 0, 0, 0} },
		{ {28, 28, 28, 24, 20, 16, 28, 24, 20, 16, 0, 0, 0, 0} },
		{ {28, 28, 28, 22, 18, 14, 28, 22, 18, 14, 0, 0, 0, 0} },
		{ {28, 28, 28, 22, 18, 14, 28, 22, 18, 14, 0, 0, 0, 0} },
		{ {28, 28, 28, 20, 16, 12, 28, 20, 16, 12, 0, 0, 0, 0} },
		{ {28, 28, 28, 20, 16, 12, 28, 20, 16, 12, 0, 0, 0, 0} },
	 },
	.ctlIndex_5G =  {
		0x10, 0x16, 0x18, 0x40, 0x46,
		0x48, 0x30, 0x36, 0x38
	},
	.ctl_freqbin_5G =  {
		{
			/* Data[0].ctlEdges[0].bChannel */ FREQ2FBIN(5180, 0),
			/* Data[0].ctlEdges[1].bChannel */ FREQ2FBIN(5260, 0),
			/* Data[0].ctlEdges[2].bChannel */ FREQ2FBIN(5280, 0),
			/* Data[0].ctlEdges[3].bChannel */ FREQ2FBIN(5500, 0),
			/* Data[0].ctlEdges[4].bChannel */ FREQ2FBIN(5600, 0),
			/* Data[0].ctlEdges[5].bChannel */ FREQ2FBIN(5700, 0),
			/* Data[0].ctlEdges[6].bChannel */ FREQ2FBIN(5745, 0),
			/* Data[0].ctlEdges[7].bChannel */ FREQ2FBIN(5825, 0)
		},
		{
			/* Data[1].ctlEdges[0].bChannel */ FREQ2FBIN(5180, 0),
			/* Data[1].ctlEdges[1].bChannel */ FREQ2FBIN(5260, 0),
			/* Data[1].ctlEdges[2].bChannel */ FREQ2FBIN(5280, 0),
			/* Data[1].ctlEdges[3].bChannel */ FREQ2FBIN(5500, 0),
			/* Data[1].ctlEdges[4].bChannel */ FREQ2FBIN(5520, 0),
			/* Data[1].ctlEdges[5].bChannel */ FREQ2FBIN(5700, 0),
			/* Data[1].ctlEdges[6].bChannel */ FREQ2FBIN(5745, 0),
			/* Data[1].ctlEdges[7].bChannel */ FREQ2FBIN(5825, 0)
		},

		{
			/* Data[2].ctlEdges[0].bChannel */ FREQ2FBIN(5190, 0),
			/* Data[2].ctlEdges[1].bChannel */ FREQ2FBIN(5230, 0),
			/* Data[2].ctlEdges[2].bChannel */ FREQ2FBIN(5270, 0),
			/* Data[2].ctlEdges[3].bChannel */ FREQ2FBIN(5310, 0),
			/* Data[2].ctlEdges[4].bChannel */ FREQ2FBIN(5510, 0),
			/* Data[2].ctlEdges[5].bChannel */ FREQ2FBIN(5550, 0),
			/* Data[2].ctlEdges[6].bChannel */ FREQ2FBIN(5670, 0),
			/* Data[2].ctlEdges[7].bChannel */ FREQ2FBIN(5755, 0)
		},

		{
			/* Data[3].ctlEdges[0].bChannel */ FREQ2FBIN(5180, 0),
			/* Data[3].ctlEdges[1].bChannel */ FREQ2FBIN(5200, 0),
			/* Data[3].ctlEdges[2].bChannel */ FREQ2FBIN(5260, 0),
			/* Data[3].ctlEdges[3].bChannel */ FREQ2FBIN(5320, 0),
			/* Data[3].ctlEdges[4].bChannel */ FREQ2FBIN(5500, 0),
			/* Data[3].ctlEdges[5].bChannel */ FREQ2FBIN(5700, 0),
			/* Data[3].ctlEdges[6].bChannel */ 0xFF,
			/* Data[3].ctlEdges[7].bChannel */ 0xFF,
		},

		{
			/* Data[4].ctlEdges[0].bChannel */ FREQ2FBIN(5180, 0),
			/* Data[4].ctlEdges[1].bChannel */ FREQ2FBIN(5260, 0),
			/* Data[4].ctlEdges[2].bChannel */ FREQ2FBIN(5500, 0),
			/* Data[4].ctlEdges[3].bChannel */ FREQ2FBIN(5700, 0),
			/* Data[4].ctlEdges[4].bChannel */ 0xFF,
			/* Data[4].ctlEdges[5].bChannel */ 0xFF,
			/* Data[4].ctlEdges[6].bChannel */ 0xFF,
			/* Data[4].ctlEdges[7].bChannel */ 0xFF,
		},

		{
			/* Data[5].ctlEdges[0].bChannel */ FREQ2FBIN(5190, 0),
			/* Data[5].ctlEdges[1].bChannel */ FREQ2FBIN(5270, 0),
			/* Data[5].ctlEdges[2].bChannel */ FREQ2FBIN(5310, 0),
			/* Data[5].ctlEdges[3].bChannel */ FREQ2FBIN(5510, 0),
			/* Data[5].ctlEdges[4].bChannel */ FREQ2FBIN(5590, 0),
			/* Data[5].ctlEdges[5].bChannel */ FREQ2FBIN(5670, 0),
			/* Data[5].ctlEdges[6].bChannel */ 0xFF,
			/* Data[5].ctlEdges[7].bChannel */ 0xFF
		},

		{
			/* Data[6].ctlEdges[0].bChannel */ FREQ2FBIN(5180, 0),
			/* Data[6].ctlEdges[1].bChannel */ FREQ2FBIN(5200, 0),
			/* Data[6].ctlEdges[2].bChannel */ FREQ2FBIN(5220, 0),
			/* Data[6].ctlEdges[3].bChannel */ FREQ2FBIN(5260, 0),
			/* Data[6].ctlEdges[4].bChannel */ FREQ2FBIN(5500, 0),
			/* Data[6].ctlEdges[5].bChannel */ FREQ2FBIN(5600, 0),
			/* Data[6].ctlEdges[6].bChannel */ FREQ2FBIN(5700, 0),
			/* Data[6].ctlEdges[7].bChannel */ FREQ2FBIN(5745, 0)
		},

		{
			/* Data[7].ctlEdges[0].bChannel */ FREQ2FBIN(5180, 0),
			/* Data[7].ctlEdges[1].bChannel */ FREQ2FBIN(5260, 0),
			/* Data[7].ctlEdges[2].bChannel */ FREQ2FBIN(5320, 0),
			/* Data[7].ctlEdges[3].bChannel */ FREQ2FBIN(5500, 0),
			/* Data[7].ctlEdges[4].bChannel */ FREQ2FBIN(5560, 0),
			/* Data[7].ctlEdges[5].bChannel */ FREQ2FBIN(5700, 0),
			/* Data[7].ctlEdges[6].bChannel */ FREQ2FBIN(5745, 0),
			/* Data[7].ctlEdges[7].bChannel */ FREQ2FBIN(5825, 0)
		},

		{
			/* Data[8].ctlEdges[0].bChannel */ FREQ2FBIN(5190, 0),
			/* Data[8].ctlEdges[1].bChannel */ FREQ2FBIN(5230, 0),
			/* Data[8].ctlEdges[2].bChannel */ FREQ2FBIN(5270, 0),
			/* Data[8].ctlEdges[3].bChannel */ FREQ2FBIN(5510, 0),
			/* Data[8].ctlEdges[4].bChannel */ FREQ2FBIN(5550, 0),
			/* Data[8].ctlEdges[5].bChannel */ FREQ2FBIN(5670, 0),
			/* Data[8].ctlEdges[6].bChannel */ FREQ2FBIN(5755, 0),
			/* Data[8].ctlEdges[7].bChannel */ FREQ2FBIN(5795, 0)
		}
	 },
	.ctlPowerData_5G = {
		{
			{
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 1),
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 0),
			}
		},
		{
			{
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 1),
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 0),
			}
		},
		{
			{
				CTL(60, 0), CTL(60, 1), CTL(60, 0), CTL(60, 1),
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 1),
			}
		},
		{
			{
				CTL(60, 0), CTL(60, 1), CTL(60, 1), CTL(60, 0),
				CTL(60, 1), CTL(60, 0), CTL(60, 0), CTL(60, 0),
			}
		},
		{
			{
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 0),
				CTL(60, 0), CTL(60, 0), CTL(60, 0), CTL(60, 0),
			}
		},
		{
			{
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 1),
				CTL(60, 1), CTL(60, 0), CTL(60, 0), CTL(60, 0),
			}
		},
		{
			{
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 1),
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 1),
			}
		},
		{
			{
				CTL(60, 1), CTL(60, 1), CTL(60, 0), CTL(60, 1),
				CTL(60, 1), CTL(60, 1), CTL(60, 1), CTL(60, 0),
			}
		},
		{
			{
				CTL(60, 1), CTL(60, 0), CTL(60, 1), CTL(60, 1),
				CTL(60, 1), CTL(60, 1), CTL(60, 0), CTL(60, 1),
			}
		},
	 }
};


static struct ar9300_eeprom *ar9300_eep_templates[] = {
	&ar9300_default,
	&ar9300_x112,
	&ar9300_h116,
	&ar9300_h112,
	&ar9300_x113,
};

static struct ar9300_eeprom *ar9003_eeprom_struct_find_by_id(int id)
{
#define N_LOOP (sizeof(ar9300_eep_templates) / sizeof(ar9300_eep_templates[0]))
	int it;

	for (it = 0; it < N_LOOP; it++)
		if (ar9300_eep_templates[it]->templateVersion == id)
			return ar9300_eep_templates[it];
	return NULL;
#undef N_LOOP
}

static bool ar9300_eeprom_read_byte(struct edump *edump, int address,
				    uint8_t *buffer)
{
	uint16_t val;

	if (!pci_eeprom_read(edump, address / 2, &val))
		return false;

	*buffer = (val >> (8 * (address % 2))) & 0xff;
	return true;
}

static bool ar9300_eeprom_read_word(struct edump *edump, int address,
				    uint8_t *buffer)
{
	uint16_t val;

	if (!pci_eeprom_read(edump, address / 2, &val))
		return false;

	buffer[0] = val >> 8;
	buffer[1] = val & 0xff;
	return true;
}

static bool ar9300_read_eeprom(struct edump *edump, int address,
			       uint8_t *buffer, int count)
{
	int i;

	if ((address < 0) || ((address + count) / 2 > AR9300_EEPROM_SIZE - 1)) {
		fprintf(stderr, "eeprom address not in range\n");
		return false;
	}

	/*
	 * Since we're reading the bytes in reverse order from a little-endian
	 * word stream, an even address means we only use the lower half of
	 * the 16-bit word at that address
	 */
	if (address % 2 == 0) {
		if (!ar9300_eeprom_read_byte(edump, address--, buffer++))
			goto error;

		count--;
	}

	for (i = 0; i < count / 2; i++) {
		if (!ar9300_eeprom_read_word(edump, address, buffer))
			goto error;

		address -= 2;
		buffer += 2;
	}

	if (count % 2)
		if (!ar9300_eeprom_read_byte(edump, address, buffer))
			goto error;

	return true;

error:
	fprintf(stderr, "unable to read eeprom region at offset %d\n",
		address);
	return false;
}

static bool ar9300_otp_read_word(struct edump *edump, int addr, uint32_t *data)
{
	REG_READ(AR9300_OTP_BASE + (4 * addr));

	if (!hw_wait(edump, AR9300_OTP_STATUS, AR9300_OTP_STATUS_TYPE,
		     AR9300_OTP_STATUS_VALID, 1000))
		return false;

	*data = REG_READ(AR9300_OTP_READ_DATA);
	return true;
}

static bool ar9300_read_otp(struct edump *edump, int address, uint8_t *buffer,
			    int count)
{
	uint32_t data;
	int i;

	for (i = 0; i < count; i++) {
		int offset = 8 * ((address - i) % 4);
		if (!ar9300_otp_read_word(edump, (address - i) / 4, &data))
			return false;

		buffer[i] = (data >> offset) & 0xff;
	}

	return true;
}


static void ar9300_comp_hdr_unpack(uint8_t *best, int *code, int *reference,
				   int *length, int *major, int *minor)
{
	unsigned long value[4];

	value[0] = best[0];
	value[1] = best[1];
	value[2] = best[2];
	value[3] = best[3];
	*code = ((value[0] >> 5) & 0x0007);
	*reference = (value[0] & 0x001f) | ((value[1] >> 2) & 0x0020);
	*length = ((value[1] << 4) & 0x07f0) | ((value[2] >> 4) & 0x000f);
	*major = (value[2] & 0x000f);
	*minor = (value[3] & 0x00ff);
}

static uint16_t ar9300_comp_cksum(uint8_t *data, int dsize)
{
	int it, checksum = 0;

	for (it = 0; it < dsize; it++) {
		checksum += data[it];
		checksum &= 0xffff;
	}

	return checksum;
}

static bool ar9300_uncompress_block(uint8_t *mptr,
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
			printf("Restore at %d: spot=%d offset=%d length=%d\n",
				it, spot, offset, length);
			memcpy(&mptr[spot], &block[it+2], length);
			spot += length;
		} else if (length > 0) {
			fprintf(stderr,
				"Bad restore at %d: spot=%d offset=%d length=%d\n",
				it, spot, offset, length);
			return false;
		}
	}
	return true;
}

static int ar9300_compress_decision(int it,
				    int code,
				    int reference,
				    uint8_t *mptr,
				    uint8_t *word, int length, int mdata_size)
{
	struct ar9300_eeprom *eep = NULL;

	switch (code) {
	case _CompressNone:
		if (length != mdata_size) {
			fprintf(stderr,
				"EEPROM structure size mismatch memory=%d eeprom=%d\n",
				mdata_size, length);
			return -1;
		}
		memcpy(mptr, word + COMP_HDR_LEN, length);
		printf("restored eeprom %d: uncompressed, length %d\n",
			it, length);
		break;
	case _CompressBlock:
		if (reference != 0) {
			eep = ar9003_eeprom_struct_find_by_id(reference);
			if (eep == NULL) {
				fprintf(stderr,
					"can't find reference eeprom struct %d\n",
					reference);
				return -1;
			}
			memcpy(mptr, eep, mdata_size);
		}
		printf("restore eeprom %d: block, reference %d, length %d\n",
			it, reference, length);
		ar9300_uncompress_block(mptr, mdata_size,
					(word + COMP_HDR_LEN), length);
		break;
	default:
		fprintf(stderr, "unknown compression code %d\n", code);
		return -1;
	}
	return 0;
}

typedef bool (*eeprom_read_op)(struct edump *edump, int address,
			       uint8_t *buffer, int count);

static bool ar9300_check_header(void *data)
{
	uint32_t *word = data;
	return !(*word == 0 || *word == ~0);
}

static bool ar9300_check_eeprom_header(struct edump *edump, eeprom_read_op read,
				       int base_addr)
{
	uint8_t header[4] = { 0 };

	if (!read(edump, base_addr, header, 4))
		return false;

	return ar9300_check_header(header);
}

void ar9003_fill_regdmn(void)
{
	struct ar9300_eeprom *eep;
	int it;

#define N_LOOP (sizeof(ar9300_eep_templates) / sizeof(ar9300_eep_templates[0]))
	for (it = 0; it < N_LOOP; it++) {
		eep = ar9300_eep_templates[it];
		eep->baseEepHeader.regDmn[0] = 0;
		eep->baseEepHeader.regDmn[1] = htole16(0x1f);
	}
#undef N_LOOP
}

void ar9300_fill_antctrl_template(bool is_2g)
{
	struct ar9300_eeprom *eep;
	struct ar9300_modal_eep_header *pModal;
	int it;

#define N_LOOP (sizeof(ar9300_eep_templates) / sizeof(ar9300_eep_templates[0]))
	for (it = 0; it < N_LOOP; it++) {
		eep = ar9300_eep_templates[it];
		pModal = (is_2g) ? &eep->modalHeader2G : &eep->modalHeader5G;
		if (is_2g && ((eep->templateVersion == 5) ||
			      (eep->templateVersion == 4))) {
			pModal->antCtrlChain[0] = htole16(0x10);
			pModal->antCtrlChain[1] = htole16(0x10);
			pModal->antCtrlChain[2] = htole16(0x10);
			continue;
		} else if (!is_2g && ((eep->templateVersion == 2) ||
				      (eep->templateVersion == 5)))
			continue;

		pModal->antCtrlChain[0] = htole16(0x150);
		pModal->antCtrlChain[1] = htole16(0x150);
		pModal->antCtrlChain[2] = htole16(0x150);
	}
#undef N_LOOP
}

void ar9300_fill_antctlcmn_template(bool is_2g)
{
	struct ar9300_eeprom *eep;
	struct ar9300_modal_eep_header *pModal;
	int it;

#define N_LOOP (sizeof(ar9300_eep_templates) / sizeof(ar9300_eep_templates[0]))
	for (it = 0; it < N_LOOP; it++) {
		eep = ar9300_eep_templates[it];
		pModal = (is_2g) ? &eep->modalHeader2G : &eep->modalHeader5G;

		if (is_2g) {
			pModal->antCtrlCommon = htole32(0x110);
			if ((eep->templateVersion == 2) ||
			    (eep->templateVersion == 5))
				pModal->antCtrlCommon2 = htole32(0x22222);
			else
				pModal->antCtrlCommon2 = htole32(0x44444);
		} else {
			if ((eep->templateVersion == 2) ||
			    (eep->templateVersion == 5)) {
				pModal->antCtrlCommon = htole32(0x110);
				pModal->antCtrlCommon2 = htole32(0x22222);
			} else {
				pModal->antCtrlCommon = htole32(0x220);
				pModal->antCtrlCommon2 =
					(eep->templateVersion == 6) ?
					htole32(0x11111) : htole32(0x44444);
			}
		}
	}
#undef N_LOOP
}
/*
 * Read the configuration data from the eeprom.
 * The data can be put in any specified memory buffer.
 *
 * Returns -1 on error.
 * Returns address of next memory location on success.
 */
static int ar9300_eeprom_restore_internal(struct edump *edump,
					  uint8_t *mptr, int mdata_size)
{
#define MDEFAULT 15
#define MSTATE 100
	int cptr;
	uint8_t *word, *ptr;
	int code;
	int reference, length, major, minor;
	int osize;
	int it;
	uint16_t checksum, mchecksum;
	eeprom_read_op read;

	word = calloc(1, 2048);
	if (!word)
		return -ENOMEM;

	ar9003_fill_regdmn();
	for (it = 1; it >= 0; it--) {
		ar9300_fill_antctlcmn_template(it);
		ar9300_fill_antctrl_template(it);
	}
	memcpy(mptr, &ar9300_default, mdata_size);

	read = ar9300_read_eeprom;
	if (AR_SREV_9485(edump))
		cptr = AR9300_BASE_ADDR_4K;
	else if (AR_SREV_9330(edump))
		cptr = AR9300_BASE_ADDR_512;
	else
		cptr = AR9300_BASE_ADDR;
	printf("Trying EEPROM access at Address 0x%04x\n", cptr);
	if (ar9300_check_eeprom_header(edump, read, cptr))
		goto found;

	cptr = AR9300_BASE_ADDR_512;
	printf("Trying EEPROM access at Address 0x%04x\n", cptr);
	if (ar9300_check_eeprom_header(edump, read, cptr))
		goto found;

	read = ar9300_read_otp;
	cptr = AR9300_BASE_ADDR;
	printf("Trying OTP access at Address 0x%04x\n", cptr);
	if (ar9300_check_eeprom_header(edump, read, cptr))
		goto found;

	cptr = AR9300_BASE_ADDR_512;
	printf("Trying OTP access at Address 0x%04x\n", cptr);
	if (ar9300_check_eeprom_header(edump, read, cptr))
		goto found;

	goto fail;

found:
	printf("Found valid EEPROM data\n");

	for (it = 0; it < MSTATE; it++) {
		if (!read(edump, cptr, word, COMP_HDR_LEN))
			goto fail;

		if (!ar9300_check_header(word))
			break;

		ar9300_comp_hdr_unpack(word, &code, &reference,
				       &length, &major, &minor);
		printf("Found block at %x: code=%d ref=%d length=%d \
			major=%d minor=%d\n",
			cptr, code, reference, length, major, minor);
		if ((!AR_SREV_9485(edump) && length >= 1024) ||
		    (AR_SREV_9485(edump) && length > EEPROM_DATA_LEN_9485)) {
			printf("Skipping bad header\n");
			cptr -= COMP_HDR_LEN;
			continue;
		}

		osize = length;
		read(edump, cptr, word, COMP_HDR_LEN + osize + COMP_CKSUM_LEN);
		checksum = ar9300_comp_cksum(&word[COMP_HDR_LEN], length);
		ptr = &word[COMP_HDR_LEN + osize];
		mchecksum = ptr[0] | (ptr[1] << 8);
		printf("checksum %x %x\n", checksum, mchecksum);
		if (checksum == mchecksum) {
			ar9300_compress_decision(it, code, reference, mptr,
						 word, length, mdata_size);
		} else {
			printf("skipping block with bad checksum\n");
		}
		cptr -= (COMP_HDR_LEN + osize + COMP_CKSUM_LEN);
	}

	free(word);
	return cptr;

fail:
	free(word);
	return -1;
}

/*
 * Restore the configuration structure by reading the eeprom.
 * This function destroys any existing in-memory structure
 * content.
 */
static bool fill_eeprom_9003(struct edump *edump)
{
	uint8_t *mptr = (uint8_t *) &edump->eeprom.eep_93k;

	if (ar9300_eeprom_restore_internal(edump, mptr,
			sizeof(struct ar9300_eeprom)) < 0)
		return false;

	return true;
}

static int check_eeprom_9003(struct edump *edump)
{
	return 1;
}

/* XXX: review hardware docs */
static int get_eeprom_ver_9003(struct edump *edump)
{
	return edump->eeprom.eep_93k.eepromVersion;
}

/* XXX: could be read from the eepromVersion, not sure yet */
static int get_eeprom_rev_9003(struct edump *edump)
{
	return 0;
}

static void base_eeprom_9003(struct edump *edump)
{
	struct ar9300_eeprom *eep = &edump->eeprom.eep_93k;
	struct ar9300_base_eep_hdr *pBase;

	pBase = &eep->baseEepHeader;

	printf("\n----------------------\n");
	printf("| EEPROM Base Header |\n");
	printf("----------------------\n\n");

	printf("%-30s : %2d\n", "Version", eep->eepromVersion);
	printf("%-30s : 0x%04X\n", "RegDomain1", pBase->regDmn[0]);
	printf("%-30s : 0x%04X\n", "RegDomain2", pBase->regDmn[1]);
	printf("%-30s : %02X:%02X:%02X:%02X:%02X:%02X\n", "MacAddress",
			eep->macAddr[0], eep->macAddr[1], eep->macAddr[2],
			eep->macAddr[3], eep->macAddr[4], eep->macAddr[5]);
	printf("%-30s : 0x%04X\n", "TX Mask", pBase->txrxMask >> 4);
	printf("%-30s : 0x%04X\n", "RX Mask", pBase->txrxMask & 0x0f);
	printf("%-30s : %d\n", "Allow 5GHz",
			!!(pBase->opCapFlags.opFlags & AR5416_OPFLAGS_11A));
	printf("%-30s : %d\n", "Allow 2GHz",
			!!(pBase->opCapFlags.opFlags & AR5416_OPFLAGS_11G));
	printf("%-30s : %d\n", "Disable 2GHz HT20",
		!!(pBase->opCapFlags.opFlags & AR5416_OPFLAGS_N_2G_HT20));
	printf("%-30s : %d\n", "Disable 2GHz HT40",
		!!(pBase->opCapFlags.opFlags & AR5416_OPFLAGS_N_2G_HT40));
	printf("%-30s : %d\n", "Disable 5Ghz HT20",
		!!(pBase->opCapFlags.opFlags & AR5416_OPFLAGS_N_5G_HT20));
	printf("%-30s : %d\n", "Disable 5Ghz HT40",
		!!(pBase->opCapFlags.opFlags & AR5416_OPFLAGS_N_5G_HT40));
	printf("%-30s : %d\n", "Big Endian",
			!!(pBase->opCapFlags.eepMisc & 0x01));
	printf("%-30s : %x\n", "RF Silent", pBase->rfSilent);
	printf("%-30s : %x\n", "BT option", pBase->blueToothOptions);
	printf("%-30s : %x\n", "Device Cap", pBase->deviceCap);
	printf("%-30s : %s\n", "Device Type",
			sDeviceType[pBase->deviceType & 0x7]);
	printf("%-30s : %x\n", "Power Table Offset", pBase->pwrTableOffset);
	printf("%-30s : %x\n", "Tuning Caps1",
			pBase->params_for_tuning_caps[0]);
	printf("%-30s : %x\n", "Tuning Caps2",
			pBase->params_for_tuning_caps[1]);
	printf("%-30s : %x\n", "Enable Tx Temp Comp",
			!!(pBase->featureEnable & (1 << 0)));
	printf("%-30s : %d\n", "Enable Tx Volt Comp",
			!!(pBase->featureEnable & (1 << 1)));
	printf("%-30s : %d\n", "Enable fast clock",
			!!(pBase->featureEnable & (1 << 2)));
	printf("%-30s : %d\n", "Enable doubling",
			!!(pBase->featureEnable & (1 << 3)));
	printf("%-30s : %d\n", "Internal regulator",
			!!(pBase->featureEnable & (1 << 4)));
	printf("%-30s : %d\n", "Enable Paprd",
			!!(pBase->featureEnable & (1 << 5)));
	printf("%-30s : %d\n", "Driver Strength",
			!!(pBase->miscConfiguration & (1 << 0)));
	printf("%-30s : %d\n", "Quick Drop",
			!!(pBase->miscConfiguration & (1 << 1)));
	printf("%-30s : %d\n", "Chain mask Reduce",
			(pBase->miscConfiguration >> 0x3) & 0x1);
	printf("%-30s : %d\n", "Write enable Gpio",
			pBase->eepromWriteEnableGpio);
	printf("%-30s : %d\n", "WLAN Disable Gpio", pBase->wlanDisableGpio);
	printf("%-30s : %d\n", "WLAN LED Gpio", pBase->wlanLedGpio);
	printf("%-30s : %d\n", "Rx Band Select Gpio", pBase->rxBandSelectGpio);
	printf("%-30s : %d\n", "Tx Gain", pBase->txrxgain >> 4);
	printf("%-30s : %d\n", "Rx Gain", pBase->txrxgain & 0xf);
	printf("%-30s : %d\n", "SW Reg", pBase->swreg);
}

static void modal_eeprom_9003(struct edump *edump)
{
#define PR(_token, _p, _val_fmt, _val)				\
	do {							\
		printf("%-23s %-8s", (_token), ":");		\
		if (pBase->opCapFlags.opFlags & AR5416_OPFLAGS_11G) {	\
			pModal = &eep->modalHeader2G;		\
			printf("%s%-6"_val_fmt, _p, (_val));	\
		}						\
		if (pBase->opCapFlags.opFlags & AR5416_OPFLAGS_11A) {	\
			pModal = &eep->modalHeader5G;		\
			printf("%8s%"_val_fmt"\n", _p, (_val)); \
		} else {					\
			printf("\n");				\
		}						\
	} while (0)

	struct ar9300_eeprom *eep = &edump->eeprom.eep_93k;
	struct ar9300_base_eep_hdr *pBase = &eep->baseEepHeader;
	struct ar9300_modal_eep_header *pModal = NULL;

	printf("\n\n-----------------------\n");
	printf("| EEPROM Modal Header |\n");
	printf("-----------------------\n\n");

	if (pBase->opCapFlags.opFlags & AR5416_OPFLAGS_11G)
		printf("%34s", "2G");
	if (pBase->opCapFlags.opFlags & AR5416_OPFLAGS_11A)
		printf("%16s", "5G\n\n");
	else
		printf("\n\n");

	printf("%-23s %-8s", "Ant Chain 0", ":");
	if (pBase->opCapFlags.opFlags & AR5416_OPFLAGS_11G) {
		pModal = &eep->modalHeader2G;
		printf("%-6d", le16toh(pModal->antCtrlChain[0]));
	}
	if (pBase->opCapFlags.opFlags & AR5416_OPFLAGS_11A) {
		pModal = &eep->modalHeader5G;
		printf("%10d\n", le16toh(pModal->antCtrlChain[0]));
	} else
		 printf("\n");
	printf("%-23s %-8s", "Ant Chain 1", ":");
	if (pBase->opCapFlags.opFlags & AR5416_OPFLAGS_11G) {
		pModal = &eep->modalHeader2G;
		printf("%-6d", le16toh(pModal->antCtrlChain[1]));
	}
	if (pBase->opCapFlags.opFlags & AR5416_OPFLAGS_11A) {
		pModal = &eep->modalHeader5G;
		printf("%10d\n", le16toh(pModal->antCtrlChain[1]));
	} else
		 printf("\n");
	printf("%-23s %-8s", "Ant Chain 2", ":");
	if (pBase->opCapFlags.opFlags & AR5416_OPFLAGS_11G) {
		pModal = &eep->modalHeader2G;
		printf("%-6d", le16toh(pModal->antCtrlChain[2]));
	}
	if (pBase->opCapFlags.opFlags & AR5416_OPFLAGS_11A) {
		pModal = &eep->modalHeader5G;
		printf("%10d\n", le16toh(pModal->antCtrlChain[2]));
	} else
		 printf("\n");
	printf("%-23s %-8s", "Antenna Common", ":");
	if (pBase->opCapFlags.opFlags & AR5416_OPFLAGS_11G) {
		pModal = &eep->modalHeader2G;
		printf("%-6d", le32toh(pModal->antCtrlCommon));
	}
	if (pBase->opCapFlags.opFlags & AR5416_OPFLAGS_11A) {
		pModal = &eep->modalHeader5G;
		printf("%10d\n", le32toh(pModal->antCtrlCommon));
	} else
		 printf("\n");
	printf("%-23s %-8s", "Antenna Common2", ":");
	if (pBase->opCapFlags.opFlags & AR5416_OPFLAGS_11G) {
		pModal = &eep->modalHeader2G;
		printf("%-6d", le32toh(pModal->antCtrlCommon2));
	}
	if (pBase->opCapFlags.opFlags & AR5416_OPFLAGS_11A) {
		pModal = &eep->modalHeader5G;
		printf("%10d\n", le32toh(pModal->antCtrlCommon2));
	} else
		 printf("\n");
	PR("Antenna Gain", "", "d", pModal->antennaGain);
	PR("Switch Settling", "", "d", pModal->switchSettling);
	PR("xatten1DB Ch 0", "", "d", pModal->xatten1DB[0]);
	PR("xatten1DB Ch 1", "", "d", pModal->xatten1DB[1]);
	PR("xatten1DB Ch 2", "", "d", pModal->xatten1DB[2]);
	PR("xatten1Margin Chain 0", "", "d", pModal->xatten1Margin[0]);
	PR("xatten1Margin Chain 1", "", "d", pModal->xatten1Margin[1]);
	PR("xatten1Margin Chain 2", "", "d", pModal->xatten1Margin[2]);
	PR("Temp Slope", "", "d", pModal->tempSlope);
	PR("Volt Slope", "", "d", pModal->voltSlope);
	PR("spur Channels0", "", "d", pModal->spurChans[0]);
	PR("spur Channels1", "", "d", pModal->spurChans[1]);
	PR("spur Channels2", "", "d", pModal->spurChans[2]);
	PR("spur Channels3", "", "d", pModal->spurChans[3]);
	PR("spur Channels4", "", "d", pModal->spurChans[4]);
	PR("NF Thresh 0", "", "d", pModal->noiseFloorThreshCh[0]);
	PR("NF Thresh 1", "", "d", pModal->noiseFloorThreshCh[1]);
	PR("NF Thresh 2", "", "d", pModal->noiseFloorThreshCh[2]);
	PR("Quick Drop", "", "d", pModal->quick_drop);
	PR("TX end to xpa off", "", "d", pModal->txEndToXpaOff);
	PR("Xpa bias level", "", "d", pModal->xpaBiasLvl);
	PR("txFrameToDataStart", "", "d", pModal->txFrameToDataStart);
	PR("txFrameToPaOn", "", "d", pModal->txFrameToPaOn);
	PR("TX frame to xpa on", "", "d", pModal->txFrameToXpaOn);
	PR("TxClip", "", "d", pModal->txClip);
	PR("ADC Desired Size", "", "d", pModal->adcDesiredSize);

#undef PR
}

static void power_info_eeprom_9003(struct edump *edump)
{
}

struct eeprom_ops eep_9003_ops = {
	.fill_eeprom = fill_eeprom_9003,
	.check_eeprom = check_eeprom_9003,
	.get_eeprom_ver = get_eeprom_ver_9003,
	.get_eeprom_rev = get_eeprom_rev_9003,
	.dump_base_header = base_eeprom_9003,
	.dump_modal_header = modal_eeprom_9003,
	.dump_power_info = power_info_eeprom_9003,
};

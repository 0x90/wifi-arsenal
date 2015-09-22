template "Atheros 9285 EEPROM"
description "Atheros WiFi adapter 9285 series EEPROM"
//multiple
hexadecimal
fixed_start 0
begin
	section base_eep_header
	{
	uint16 length
	uint16 checksum
	uint16 version
	uint8 opCapFlags
	uint8 eepMisc
	uint16[2] regDmn
	hex 6 macAddr
	uint8 rxMask
	uint8 txMask
	uint16 rfSilent
	uint16 blueToothOptions
	uint16 deviceCap
	uint32 binBuildNumber
	uint8 deviceType
	uint8 txGainType
	}

	hex 20 custData

	section modal_eep_4k_header
	uint32[1] antCtrlChain
	uint32 antCtrlCommon
	uint8[1] antennaGainCh
	uint8 switchSettling
	uint8[1] txRxAttenCh
	uint8[1] rxTxMarginCh
	uint8 adcDesiredSize
	uint8 pgaDesiredSize
	uint8[1] xlnaGainCh
	uint8 txEndToXpaOff
	uint8 txEndToRxOn
	uint8 txFrameToXpaOn
	uint8 thresh62
	uint8[1] noiseFloorThreshCh
	uint8 xpdGain
	uint8 xpd
	uint8[1] iqCalICh
	uint8[1] iqCalQCh
	uint8 pdGainOverlap
	uint8 "ob_1:4, ob_0:4"
	uint8 "db1_1:4, db1_0:4"
	uint8 xpaBiasLvl
	uint8 txFrameToDataStart
	uint8 txFrameToPaOn
	uint8 ht40PowerIncForPdadc
	uint8[1] bswAtten
	uint8[1] bswMargin
	uint8 swSettleHt40
	uint8[1] xatten2Db
	uint8[1] xatten2Margin
	uint8 "db2_1:4, db2_0:4"
	uint8 version
	uint8 "ob_3:4, ob_2:4"
	uint8 "antdiv_ctl1:4, ob_4:4"
	uint8 "db1_3:4, db1_2:4"
	uint8 "antdiv_ctl2:4, db1_4:4"
	uint8 "db2_2:4, db2_3:4"
	uint8 "reserved:4, db2_4:4"
	uint8[4] futureModal
	
	//struct spur_chan spurChans[AR5416_EEPROM_MODAL_SPURS]
	{
		section spur_chan
		uint16 spurChan
		uint8 spurRangeLow
		uint8 spurRangeHigh
	}[5]
	
	section "power tables"
	uint8[3] calFreqPier2G //[AR5416_EEP4K_NUM_2G_CAL_PIERS]

	section calPierData2G
	{
		section cal_data_per_freq_4k
		hex 10 pwrPdg //[AR5416_EEP4K_NUM_PD_GAINS][AR5416_EEP4K_PD_GAIN_ICEPTS];
		hex 10 vpdPdg //[AR5416_EEP4K_NUM_PD_GAINS][AR5416_EEP4K_PD_GAIN_ICEPTS];
	}[3]

	section calTargetPowerCck
	{
		section cal_target_power_leg
		hex 1 bChannel
		hex 4 tPow2x
	}[3] //[AR5416_EEP4K_NUM_2G_CCK_TARGET_POWERS]

	section calTargetPower2G
	{
		section cal_target_power_leg
		hex 1 bChannel
		hex 4 tPow2x
	}[3] //[AR5416_EEP4K_NUM_2G_20_TARGET_POWERS]

	section calTargetPower2GHT20
	{
		section cal_target_power_ht
		hex 1 bChannel
		hex 8 tPow2x
	}[3] //[AR5416_EEP4K_NUM_2G_20_TARGET_POWERS]                                                           

	section calTargetPower2GHT40
	{
		section cal_target_power_ht
		hex 1 bChannel
		hex 8 tPow2x
	}[3] //[AR5416_EEP4K_NUM_2G_40_TARGET_POWERS]

	section "ctl table"
	hex 12 ctlIndex //[AR5416_EEP4K_NUM_CTLS]

	section ctlData
	{
		section cal_ctl_data_4k
		uint16[4] cal_ctl_edges
	}[12] //[AR5416_EEP4K_NUM_CTLS]

	uint8 padding

end
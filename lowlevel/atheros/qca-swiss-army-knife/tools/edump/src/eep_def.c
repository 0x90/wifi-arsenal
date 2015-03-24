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

static int get_eeprom_ver_def(struct edump *edump)
{
	return ((edump->eeprom.def.baseEepHeader.version >> 12) & 0xF);
}

static int get_eeprom_rev_def(struct edump *edump)
{
	return ((edump->eeprom.def.baseEepHeader.version) & 0xFFF);
}

static bool fill_eeprom_def(struct edump *edump)
{
#define SIZE_EEPROM_DEF (sizeof(struct ar5416_eeprom_def) / sizeof(uint16_t))

	uint16_t *eep_data = (uint16_t *)&edump->eeprom.def;
	int addr, ar5416_eep_start_loc = 0x100;

	for (addr = 0; addr < SIZE_EEPROM_DEF; addr++) {
		if (!pci_eeprom_read(edump, addr + ar5416_eep_start_loc,
				     eep_data)) {
			fprintf(stderr, "Unable to read eeprom region\n");
			return false;
		}
		eep_data++;
	}
	return true;

#undef SIZE_EEPROM_DEF
}

static bool check_eeprom_def(struct edump *edump)
{
	struct ar5416_eeprom_def *eep = (struct ar5416_eeprom_def *)&edump->eeprom.def;
	uint16_t *eepdata, temp, magic, magic2;
	uint32_t sum = 0, el;
	bool need_swap = false;
	int i, addr, size;

	if (!pci_eeprom_read(edump, AR5416_EEPROM_MAGIC_OFFSET, &magic)) {
		fprintf(stderr, "Reading Magic # failed\n");
		return false;
	}

	if (magic != AR5416_EEPROM_MAGIC) {
		printf("Read Magic = 0x%04X\n", magic);

		magic2 = bswap_16(magic);

		if (magic2 == AR5416_EEPROM_MAGIC) {
			size = sizeof(struct ar5416_eeprom_def);
			need_swap = true;
			eepdata = (uint16_t *) (&edump->eeprom);

			for (addr = 0; addr < size / sizeof(uint16_t); addr++) {
				temp = bswap_16(*eepdata);
				*eepdata = temp;
				eepdata++;
			}
		} else {
			fprintf(stderr, "Invalid EEPROM Magic, endianness mismatch\n");
			return false;
		}
	}

	if (need_swap)
		el = bswap_16(edump->eeprom.def.baseEepHeader.length);
	else
		el = edump->eeprom.def.baseEepHeader.length;

	if (el > sizeof(struct ar5416_eeprom_def))
		el = sizeof(struct ar5416_eeprom_def) / sizeof(uint16_t);
	else
		el = el / sizeof(uint16_t);

	eepdata = (uint16_t *)(&edump->eeprom);

	for (i = 0; i < el; i++)
		sum ^= *eepdata++;

	if (need_swap) {
		uint32_t integer, j;
		uint16_t word;

		printf("EEPROM Endianness is not native.. Changing.\n");

		word = bswap_16(eep->baseEepHeader.length);
		eep->baseEepHeader.length = word;

		word = bswap_16(eep->baseEepHeader.checksum);
		eep->baseEepHeader.checksum = word;

		word = bswap_16(eep->baseEepHeader.version);
		eep->baseEepHeader.version = word;

		word = bswap_16(eep->baseEepHeader.regDmn[0]);
		eep->baseEepHeader.regDmn[0] = word;

		word = bswap_16(eep->baseEepHeader.regDmn[1]);
		eep->baseEepHeader.regDmn[1] = word;

		word = bswap_16(eep->baseEepHeader.rfSilent);
		eep->baseEepHeader.rfSilent = word;

		word = bswap_16(eep->baseEepHeader.blueToothOptions);
		eep->baseEepHeader.blueToothOptions = word;

		word = bswap_16(eep->baseEepHeader.deviceCap);
		eep->baseEepHeader.deviceCap = word;

		for (j = 0; j < ARRAY_SIZE(eep->modalHeader); j++) {
			struct modal_eep_header *pModal = &eep->modalHeader[j];

			integer = bswap_32(pModal->antCtrlCommon);
			pModal->antCtrlCommon = integer;

			for (i = 0; i < AR5416_MAX_CHAINS; i++) {
				integer = bswap_32(pModal->antCtrlChain[i]);
				pModal->antCtrlChain[i] = integer;
			}

			for (i = 0; i < AR_EEPROM_MODAL_SPURS; i++) {
				word = bswap_16(pModal->spurChans[i].spurChan);
				pModal->spurChans[i].spurChan = word;
			}
		}
	}

	if (sum != 0xffff || edump->eep_ops->get_eeprom_ver(edump) != AR5416_EEP_VER ||
	    edump->eep_ops->get_eeprom_rev(edump) < AR5416_EEP_NO_BACK_VER) {
		fprintf(stderr, "Bad EEPROM checksum 0x%x or revision 0x%04x\n",
			sum, edump->eep_ops->get_eeprom_ver(edump));
		return false;
	}

	return true;
}

static void base_eeprom_def(struct edump *edump)
{
	struct ar5416_eeprom_def *ar5416Eep = &edump->eeprom.def;
	struct base_eep_header *pBase = &ar5416Eep->baseEepHeader;
	uint16_t i;

	pBase = &(ar5416Eep->baseEepHeader);

	printf("\n----------------------\n");
	printf("| EEPROM Base Header |\n");
	printf("----------------------\n\n");

	printf("%-30s : %2d\n", "Major Version",
	       pBase->version >> 12);
	printf("%-30s : %2d\n", "Minor Version",
	       pBase->version & 0xFFF);
	printf("%-30s : 0x%04X\n", "Checksum",
	       pBase->checksum);
	printf("%-30s : 0x%04X\n", "Length",
	       pBase->length);
	printf("%-30s : 0x%04X\n", "RegDomain1",
	       pBase->regDmn[0]);
	printf("%-30s : 0x%04X\n", "RegDomain2",
	       pBase->regDmn[1]);
	printf("%-30s : %02X:%02X:%02X:%02X:%02X:%02X\n",
	       "MacAddress",
	       pBase->macAddr[0], pBase->macAddr[1], pBase->macAddr[2],
	       pBase->macAddr[3], pBase->macAddr[4], pBase->macAddr[5]);
	printf("%-30s : 0x%04X\n",
	       "TX Mask", pBase->txMask);
	printf("%-30s : 0x%04X\n",
	       "RX Mask", pBase->rxMask);
	printf("%-30s : %d\n",
	       "OpFlags(5GHz)",
	       !!(pBase->opCapFlags & AR5416_OPFLAGS_11A));
	printf("%-30s : %d\n",
	       "OpFlags(2GHz)",
	       !!(pBase->opCapFlags & AR5416_OPFLAGS_11G));
	printf("%-30s : %d\n",
	       "OpFlags(Disable 2GHz HT20)",
	       !!(pBase->opCapFlags & AR5416_OPFLAGS_N_2G_HT20));
	printf("%-30s : %d\n",
	       "OpFlags(Disable 2GHz HT40)",
	       !!(pBase->opCapFlags & AR5416_OPFLAGS_N_2G_HT40));
	printf("%-30s : %d\n",
	       "OpFlags(Disable 5Ghz HT20)",
	       !!(pBase->opCapFlags & AR5416_OPFLAGS_N_5G_HT20));
	printf("%-30s : %d\n",
	       "OpFlags(Disable 5Ghz HT40)",
	       !!(pBase->opCapFlags & AR5416_OPFLAGS_N_5G_HT40));
	printf("%-30s : %d\n",
	       "Big Endian",
	       !!(pBase->eepMisc & AR5416_EEPMISC_BIG_ENDIAN));
	printf("%-30s : %d\n",
	       "Cal Bin Major Ver",
	       (pBase->binBuildNumber >> 24) & 0xFF);
	printf("%-30s : %d\n",
	       "Cal Bin Minor Ver",
	       (pBase->binBuildNumber >> 16) & 0xFF);
	printf("%-30s : %d\n",
	       "Cal Bin Build",
	       (pBase->binBuildNumber >> 8) & 0xFF);

	if (edump->eep_ops->get_eeprom_rev(edump) >= AR5416_EEP_MINOR_VER_3) {
		printf("%-30s : %s\n",
		       "Device Type",
		       sDeviceType[(pBase->deviceType & 0x7)]);
	}

	printf("\nCustomer Data in hex:\n");
	for (i = 0; i < 64; i++) {
		printf("%02X ", ar5416Eep->custData[i]);
		if ((i % 16) == 15)
			printf("\n");
	}
}

static void modal_eeprom_def(struct edump *edump)
{
#define PR(_token, _p, _val_fmt, _val)				\
	do {							\
		printf("%-23s %-8s", (_token), ":");		\
		if (pBase->opCapFlags & AR5416_OPFLAGS_11G) {	\
			pModal = &(ar5416Eep->modalHeader[1]);	\
			printf("%s%-6"_val_fmt, _p, (_val));	\
		}						\
		if (pBase->opCapFlags & AR5416_OPFLAGS_11A) {	\
			pModal = &(ar5416Eep->modalHeader[0]);	\
			printf("%8s%"_val_fmt"\n", _p, (_val)); \
		} else {					\
			printf("\n");				\
		}						\
	} while(0)

	struct ar5416_eeprom_def *ar5416Eep = &edump->eeprom.def;
	struct base_eep_header *pBase = &ar5416Eep->baseEepHeader;
	struct modal_eep_header *pModal = NULL;

	pBase = &(ar5416Eep->baseEepHeader);

	printf("\n\n-----------------------\n");
	printf("| EEPROM Modal Header |\n");
	printf("-----------------------\n\n");

	if (pBase->opCapFlags & AR5416_OPFLAGS_11G)
		printf("%34s", "2G");
	if (pBase->opCapFlags & AR5416_OPFLAGS_11A)
		printf("%16s", "5G\n\n");
	else
		printf("\n\n");

	PR("Ant Chain 0", "0x", "X", pModal->antCtrlChain[0]);
	PR("Ant Chain 1", "0x", "X", pModal->antCtrlChain[1]);
	PR("Ant Chain 2", "0x", "X", pModal->antCtrlChain[2]);
	PR("Antenna Common", "0x", "X", pModal->antCtrlCommon);
	PR("Antenna Gain Chain 0", "", "d", pModal->antennaGainCh[0]);
	PR("Antenna Gain Chain 1", "", "d", pModal->antennaGainCh[1]);
	PR("Antenna Gain Chain 2", "", "d", pModal->antennaGainCh[2]);
	PR("Switch Settling", "", "d", pModal->switchSettling);
	PR("TxRxAttenuation Ch 0", "", "d", pModal->txRxAttenCh[0]);
	PR("TxRxAttenuation Ch 1", "", "d", pModal->txRxAttenCh[1]);
	PR("TxRxAttenuation Ch 2", "", "d", pModal->txRxAttenCh[2]);
	PR("RxTxMargin Chain 0", "", "d", pModal->rxTxMarginCh[0]);
	PR("RxTxMargin Chain 1", "", "d", pModal->rxTxMarginCh[1]);
	PR("RxTxMargin Chain 2", "", "d", pModal->rxTxMarginCh[2]);
	PR("ADC Desired Size", "", "d", pModal->adcDesiredSize);
	PR("PGA Desired Size", "", "d", pModal->pgaDesiredSize);
	PR("TX end to xlna on", "", "d", pModal->txEndToRxOn);
	PR("xlna gain Chain 0", "", "d", pModal->xlnaGainCh[0]);
	PR("xlna gain Chain 1", "", "d", pModal->xlnaGainCh[1]);
	PR("xlna gain Chain 2", "", "d", pModal->xlnaGainCh[2]);
	PR("TX end to xpa off", "", "d", pModal->txEndToXpaOff);
	PR("TX frame to xpa on", "", "d", pModal->txFrameToXpaOn);
	PR("THRESH62", "", "d", pModal->thresh62);
	PR("NF Thresh 0", "", "d", pModal->noiseFloorThreshCh[0]);
	PR("NF Thresh 1", "", "d", pModal->noiseFloorThreshCh[1]);
	PR("NF Thresh 2", "", "d", pModal->noiseFloorThreshCh[2]);
	PR("Xpd Gain Mask", "0x", "X", pModal->xpdGain);
	PR("Xpd", "", "d", pModal->xpd);
	PR("IQ Cal I Chain 0", "", "d", pModal->iqCalICh[0]);
	PR("IQ Cal I Chain 1", "", "d", pModal->iqCalICh[1]);
	PR("IQ Cal I Chain 2", "", "d", pModal->iqCalICh[2]);
	PR("IQ Cal Q Chain 0", "", "d", pModal->iqCalQCh[0]);
	PR("IQ Cal Q Chain 1", "", "d", pModal->iqCalQCh[1]);
	PR("IQ Cal Q Chain 2", "", "d", pModal->iqCalQCh[2]);
	PR("Analog Output Bias(ob)", "", "d", pModal->ob);
	PR("Analog Driver Bias(db)", "", "d", pModal->db);
	PR("Xpa bias level", "", "d", pModal->xpaBiasLvl);
	PR("Xpa bias level Freq 0", "", "d", pModal->xpaBiasLvlFreq[0]);
	PR("Xpa bias level Freq 1", "", "d", pModal->xpaBiasLvlFreq[1]);
	PR("Xpa bias level Freq 2", "", "d", pModal->xpaBiasLvlFreq[2]);
	PR("LNA Control", "0x", "X", pModal->lna_ctl);

	printf("%-23s %-7s", "pdGain Overlap (dB)", ":");
	if (pBase->opCapFlags & AR5416_OPFLAGS_11G) {
		pModal = &(ar5416Eep->modalHeader[1]);
		printf("%2d.%-6d", pModal->pdGainOverlap / 2,
		       (pModal->pdGainOverlap % 2) * 5);
	}
	if (pBase->opCapFlags & AR5416_OPFLAGS_11A) {
		pModal = &(ar5416Eep->modalHeader[0]);
		printf("%7d.%d\n", pModal->pdGainOverlap / 2,
		       (pModal->pdGainOverlap % 2) * 5);
	} else {
		printf("\n");
	}

	printf("%-23s %-7s", "PWR dec 2 chain", ":");
	if (pBase->opCapFlags & AR5416_OPFLAGS_11G) {
		pModal = &(ar5416Eep->modalHeader[1]);
		printf("%2d.%-6d", pModal->pwrDecreaseFor2Chain / 2,
		       (pModal->pwrDecreaseFor2Chain % 2) * 5);
	}
	if (pBase->opCapFlags & AR5416_OPFLAGS_11A) {
		pModal = &(ar5416Eep->modalHeader[0]);
		printf("%7d.%d\n", pModal->pwrDecreaseFor2Chain / 2,
		       (pModal->pwrDecreaseFor2Chain % 2) * 5);
	} else {
		printf("\n");
	}

	printf("%-23s %-7s", "PWR dec 3 chain", ":");
	if (pBase->opCapFlags & AR5416_OPFLAGS_11G) {
		pModal = &(ar5416Eep->modalHeader[1]);
		printf("%2d.%-6d", pModal->pwrDecreaseFor3Chain / 2,
		       (pModal->pwrDecreaseFor3Chain % 2) * 5);
	}
	if (pBase->opCapFlags & AR5416_OPFLAGS_11A) {
		pModal = &(ar5416Eep->modalHeader[0]);
		printf("%7d.%d\n", pModal->pwrDecreaseFor3Chain / 2,
		       (pModal->pwrDecreaseFor3Chain % 2) * 5);
	} else {
		printf("\n");
	}

	if (AR_SREV_9280_20_OR_LATER(edump)) {
		PR("xatten2Db Chain 0", "", "d", pModal->xatten2Db[0]);
		PR("xatten2Db Chain 1", "", "d", pModal->xatten2Db[1]);
		PR("xatten2Margin Chain 0", "", "d", pModal->xatten2Margin[0]);
		PR("xatten2Margin Chain 1", "", "d", pModal->xatten2Margin[1]);
		PR("ob_ch1", "", "d", pModal->ob_ch1);
		PR("db_ch1", "", "d", pModal->db_ch1);
	}

	if (edump->eep_ops->get_eeprom_rev(edump) >= AR5416_EEP_MINOR_VER_3) {
		PR("txFrameToDataStart", "", "d", pModal->txFrameToDataStart);
		PR("txFrameToPaOn", "", "d", pModal->txFrameToPaOn);
		PR("HT40PowerIncForPDADC", "", "d", pModal->ht40PowerIncForPdadc);
		PR("bswAtten Chain 0", "", "d", pModal->bswAtten[0]);
	}

#undef PR
}

static void power_info_eeprom_def(struct edump *edump)
{
}

struct eeprom_ops eep_def_ops = {
	.fill_eeprom  = fill_eeprom_def,
	.check_eeprom = check_eeprom_def,
	.get_eeprom_ver = get_eeprom_ver_def,
	.get_eeprom_rev = get_eeprom_rev_def,
	.dump_base_header = base_eeprom_def,
	.dump_modal_header = modal_eeprom_def,
	.dump_power_info = power_info_eeprom_def,
};

/* Atheros ROM information dump tool */

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef __APPLE__
#include <MacTypes.h>
#endif

#include "eeprom.h"

static void ath9k_dump_4k_modal_eeprom(struct modal_eep_4k_header *modal_hdr)
{
	PR_EEP("Chain0 Ant. Control", modal_hdr->antCtrlChain[0]);
	PR_EEP("Ant. Common Control", modal_hdr->antCtrlCommon);
	PR_EEP("Chain0 Ant. Gain", modal_hdr->antennaGainCh[0]);
	PR_EEP("Switch Settle", modal_hdr->switchSettling);
	PR_EEP("Chain0 TxRxAtten", modal_hdr->txRxAttenCh[0]);
	PR_EEP("Chain0 RxTxMargin", modal_hdr->rxTxMarginCh[0]);
	PR_EEP("ADC Desired size", modal_hdr->adcDesiredSize);
	PR_EEP("PGA Desired size", modal_hdr->pgaDesiredSize);
	PR_EEP("Chain0 xlna Gain", modal_hdr->xlnaGainCh[0]);
	PR_EEP("txEndToXpaOff", modal_hdr->txEndToXpaOff);
	PR_EEP("txEndToRxOn", modal_hdr->txEndToRxOn);
	PR_EEP("txFrameToXpaOn", modal_hdr->txFrameToXpaOn);
	PR_EEP("CCA Threshold)", modal_hdr->thresh62);
	PR_EEP("Chain0 NF Threshold", modal_hdr->noiseFloorThreshCh[0]);
	PR_EEP("xpdGain", modal_hdr->xpdGain);
	PR_EEP("External PD", modal_hdr->xpd);
	PR_EEP("Chain0 I Coefficient", modal_hdr->iqCalICh[0]);
	PR_EEP("Chain0 Q Coefficient", modal_hdr->iqCalQCh[0]);
	PR_EEP("pdGainOverlap", modal_hdr->pdGainOverlap);
	PR_EEP("O/D Bias Version", modal_hdr->version);
	PR_EEPS("CCK OutputBias", modal_hdr->ob_0, 1);
	PR_EEPS("BPSK OutputBias", modal_hdr->ob_1, 1);
	PR_EEPS("QPSK OutputBias", modal_hdr->ob_2, 1);
	PR_EEPS("16QAM OutputBias", modal_hdr->ob_3, 1);
	PR_EEPS("64QAM OutputBias", modal_hdr->ob_4, 1);
	PR_EEPS("CCK Driver1_Bias", modal_hdr->db1_0, 1);
	PR_EEPS("BPSK Driver1_Bias", modal_hdr->db1_1, 1);
	PR_EEPS("QPSK Driver1_Bias", modal_hdr->db1_2, 1);
	PR_EEPS("16QAM Driver1_Bias", modal_hdr->db1_3, 1);
	PR_EEPS("64QAM Driver1_Bias", modal_hdr->db1_4, 1);
	PR_EEPS("CCK Driver2_Bias", modal_hdr->db2_0, 1);
	PR_EEPS("BPSK Driver2_Bias", modal_hdr->db2_1, 1);
	PR_EEPS("QPSK Driver2_Bias", modal_hdr->db2_2, 1);
	PR_EEPS("16QAM Driver2_Bias", modal_hdr->db2_3, 1);
	PR_EEPS("64QAM Driver2_Bias", modal_hdr->db2_4, 1);
	PR_EEP("xPA Bias Level", modal_hdr->xpaBiasLvl);
	PR_EEP("txFrameToDataStart", modal_hdr->txFrameToDataStart);
	PR_EEP("txFrameToPaOn", modal_hdr->txFrameToPaOn);
	PR_EEP("HT40 Power Inc.", modal_hdr->ht40PowerIncForPdadc);
	PR_EEP("Chain0 bswAtten", modal_hdr->bswAtten[0]);
	PR_EEP("Chain0 bswMargin", modal_hdr->bswMargin[0]);
	PR_EEP("HT40 Switch Settle", modal_hdr->swSettleHt40);
	PR_EEP("Chain0 xatten2Db", modal_hdr->xatten2Db[0]);
	PR_EEP("Chain0 xatten2Margin", modal_hdr->xatten2Margin[0]);
	PR_EEPS("Ant. Diversity ctl1", modal_hdr->antdiv_ctl1, 1);
	PR_EEPS("Ant. Diversity ctl2", modal_hdr->antdiv_ctl2, 1);
	PR_EEP("TX Diversity", modal_hdr->tx_diversity);
}

static bool valid_eeprom_chksum(u16 *eepdata)
{
    u16 sum = 0;
    int i = 0;

    for (i=0; i < EEPROM_4K_SIZE; i++)
	{
		sum ^= eepdata[i];
	}

    if (sum == 0xFFFF)
    {
        return true;
    }

    return false;
}

static u16 calc_eeprom_chksum(u16 *eepdata)
{
    u16 correctsum = 0;
    int i = 0;

    for (i=0; i < EEPROM_4K_SIZE; i++)
	{
        if (i == 1)
            continue;

		correctsum ^= eepdata[i];
	}

    correctsum ^= 0xFFFF;

    return correctsum;
}

static void change_eeprom_endianness(struct ar5416_eeprom_4k *eep)
{
    u32 integer = 0;
    u16 word = 0;
    int i = 0;

    word = swab16(eep->baseEepHeader.length);
    eep->baseEepHeader.length = word;
    
    word = swab16(eep->baseEepHeader.checksum);
    eep->baseEepHeader.checksum = word;
    
    word = swab16(eep->baseEepHeader.version);
    eep->baseEepHeader.version = word;
    
    word = swab16(eep->baseEepHeader.regDmn[0]);
    eep->baseEepHeader.regDmn[0] = word;
    
    word = swab16(eep->baseEepHeader.regDmn[1]);
    eep->baseEepHeader.regDmn[1] = word;
    
    word = swab16(eep->baseEepHeader.rfSilent);
    eep->baseEepHeader.rfSilent = word;
    
    word = swab16(eep->baseEepHeader.blueToothOptions);
    eep->baseEepHeader.blueToothOptions = word;
    
    word = swab16(eep->baseEepHeader.deviceCap);
    eep->baseEepHeader.deviceCap = word;
    
    integer = swab32(eep->modalHeader.antCtrlCommon);
    eep->modalHeader.antCtrlCommon = integer;
    
    for (i = 0; i < AR5416_EEP4K_MAX_CHAINS; i++)
    {
        integer = swab32(eep->modalHeader.antCtrlChain[i]);
        eep->modalHeader.antCtrlChain[i] = integer;
    }
    
    for (i = 0; i < AR_EEPROM_MODAL_SPURS; i++)
    {
        word = swab16(eep->modalHeader.spurChans[i].spurChan);
        eep->modalHeader.spurChans[i].spurChan = word;
    }
}

static void ath9k_hw_4k_dump_eeprom(struct ar5416_eeprom_4k *eep)
{
	struct base_eep_header_4k *pBase = &eep->baseEepHeader;
    u16 *eepdata = (u16 *)eep;
    u32 correctsum = calc_eeprom_chksum(eepdata);
    int i=0;

#ifdef __BIG_ENDIAN__
    if ((pBase->eepMisc & 0x1) != 0x1)
    {
        printf("INFO: ROM Endianness is not native... Changing from Little Endian to Big Endian.\n");

        change_eeprom_endianness(eep);
    }
#else
    if ((pBase->eepMisc & 0x1) == 0x1)
    {
        printf("INFO: ROM Endianness is not native... Changing from Big Endian to Little Endian.\n");
        
        change_eeprom_endianness(eep);
    }
#endif

    printf("<Base Header>\n");

    printf("-Version: 0x%.4x\n", pBase->version);
	PR_EEP(" Major Version", pBase->version >> 12);
	PR_EEP(" Minor Version", pBase->version & 0xFFF);
    printf("\n");

	printf("-Checksum: 0x%.4x\n", pBase->checksum);
    printf(" Correct Checksum: 0x%.4x\n", correctsum);
    if (pBase->checksum != correctsum)
    {
        printf(" WARNING: Invalid checksum... you need to correct it to the checkum above!\n");
    }
    printf("\n");

	PR_EEP("-Length", pBase->length);
    printf("\n");

    printf("-RegDomain: 0x%.4x\n", *(unsigned int *)pBase->regDmn);
	PR_EEP(" RegDomain1", pBase->regDmn[0]);
	PR_EEP(" RegDomain2", pBase->regDmn[1]);
    printf("\n");

    printf("-Mac Address: ");
    for (i=0; i < 6; i++)
    {
        printf("%.2x", pBase->macAddr[i]);

        if (i < 5)
        {
            printf(":");
        }
    }
    printf("\n\n");

    printf("-RX/TX Masks\n");
	PR_EEP(" TX Mask", pBase->txMask);
	PR_EEP(" RX Mask", pBase->rxMask);
    printf("\n");

    printf("-Options Capapable: 0x%.2x\n", pBase->opCapFlags);
	PR_EEP(" Allow 5GHz", !!(pBase->opCapFlags & AR5416_OPFLAGS_11A));
	PR_EEP(" Allow 2.4GHz", !!(pBase->opCapFlags & AR5416_OPFLAGS_11G));
	PR_EEP(" Disable 2.4GHz HT20 (802.11n - 20MHz)", !!(pBase->opCapFlags &
                                      AR5416_OPFLAGS_N_2G_HT20));
	PR_EEP(" Disable 2.4GHz HT40 (802.11n - 40MHz)", !!(pBase->opCapFlags &
                                      AR5416_OPFLAGS_N_2G_HT40));
	PR_EEP(" Disable 5Ghz HT20 (802.11n - 20MHz)", !!(pBase->opCapFlags &
                                    AR5416_OPFLAGS_N_5G_HT20));
	PR_EEP(" Disable 5Ghz HT40 (802.11n - 40MHz)", !!(pBase->opCapFlags &
                                    AR5416_OPFLAGS_N_5G_HT40));
    printf("\n");

	PR_EEP("-Endiannes", !!(pBase->eepMisc & 0x01));
    if (pBase->eepMisc & 0x01)
    {
        printf(" Big Endian (MSB first, example: 17 = 0x00000011)\n");
    } else {
        printf(" Little Endian (LSB first, example: 17 = 0x1100000000)\n");
    }
    printf("\n");

    printf("-Cal Bin: 0x%.8x\n", pBase->binBuildNumber);
	PR_EEP(" Cal Bin Major Ver", (pBase->binBuildNumber >> 24) & 0xFF);
	PR_EEP(" Cal Bin Minor Ver", (pBase->binBuildNumber >> 16) & 0xFF);
	PR_EEP(" Cal Bin Build", (pBase->binBuildNumber >> 8) & 0xFF);
    printf("\n");

	PR_EEP("-TX Gain type", pBase->txGainType);
    printf("\n");

	printf("<2GHz modal Header>\n");
	ath9k_dump_4k_modal_eeprom(&eep->modalHeader);
}

int main(int argc, char **argv)
{
    FILE *f = NULL;
    struct ar5416_eeprom_4k *romdata;
    unsigned char *buffer = NULL;
    int fSize = 0;
    int newsize = 0;

    if ((argc != 2) || (!strncmp(argv[1], "--help", strlen(argv[1]))) || (!strncmp(argv[1], "-h", strlen(argv[1]))))
    {
        printf("AnV Atheros ROM Tool V1.0 (AR928X/AR9285 edition)\n");
        printf("Usage: %s <infile>\n\n", argv[0]);
        printf("Copyright (C) 2014 AnV Software, all rights reserved.\n");

        return 1;
    }

    f = fopen(argv[1], "rb");

    if (f == NULL)
    {
        printf("ERROR: File open failed!\n");

        return 2;
    }

    fseek(f, 0, SEEK_END);
    fSize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if ((fSize != 376) && (fSize != 512) && (fSize != 4096))
    {
        fclose(f);

        printf("ERROR: Invalid size, %d is not 376, 512 or 4096!\n", fSize);

        return 3;
    }

    buffer = malloc(fSize);

    if (buffer == NULL)
    {
        fclose(f);

        printf("ERROR: Memory allocation of %d bytes failed!\n", fSize);

        return 4;
    }

    newsize = fread(buffer, 1, fSize, f);

    if (fSize != newsize)
    {
        fclose(f);
        free(buffer);

        printf("ERROR: Reading file \"%s\" into buffer (%d bytes total, %d bytes read) failed!\n", argv[1], fSize, newsize);

        return 5;
    }

    fclose(f);

    switch(fSize)
    {
        case 376:
            romdata = (struct ar5416_eeprom_4k *)buffer;
            break;

        case 512:
        case 4096:
            romdata = (struct ar5416_eeprom_4k *)(buffer + 128);
            break;

        default:
            free(buffer);

            printf("ERROR: Internal error... invalid size (%d)!\n", fSize);

            return 6;

            /* NOT_REACHED */
            break;
    }

    ath9k_hw_4k_dump_eeprom(romdata);

    free(buffer);

    return 0;
}

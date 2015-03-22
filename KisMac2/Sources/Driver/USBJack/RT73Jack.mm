/*
 *  RT73Jack.mm
 *  KisMAC
 *
 *  Created by Vincent Borrel on 10/11/06.
 *
 */

#include "RT73Jack.h"
#include "RT73.h"

#define align64(a)      (((a)+63)&~63)

unsigned char   RT73_RateIdToPlcpSignal[12] = { 
    0, /* RATE_1 */        1, /* RATE_2 */         2, /* RATE_5_5 */       3, /* RATE_11 */        // see BBP spec
    11, /* RATE_6 */   15, /* RATE_9 */    10, /* RATE_12 */   14, /* RATE_18 */    // see IEEE802.11a-1999 p.14
9, /* RATE_24 */  13, /* RATE_36 */    8, /* RATE_48 */   12  /* RATE_54 */ }; // see IEEE802.11a-1999 p.14

void RT73Jack::dumpFrame(UInt8 *data, UInt16 size) {
    DBNSLog(@"--FRAME LENGTH %d--", size);
    int idx = 0;
    int i,j;
	for (i=0;i<size;i=i+8) {
        fprintf(stderr, "0x%.4x ", i);
        for (j=0;j<8;++j) {
            if (idx < size)
                fprintf(stderr, "%.2x ", data[idx]);
            else
                fprintf(stderr, "   ");
            idx += 1;
        }
        fprintf(stderr, "\n");
    }
}

char *RT73Jack::getPlistFile() {
    return (char*)"UsbVendorsRT73";
}

IOReturn RT73Jack::_init() {
	ULONG	temp;
	unsigned int	i;
    IOReturn	ret;
	
	NICInitialized = false;
    
    if(!_attachDevice()){
        DBNSLog(@"Device could not be opened");
        return kIOReturnNoDevice;
    }

	// Wait for hardware stable

	DBNSLog(@"Waiting for Asic to power up...");
	i = 0;
	//check and see if asic has powered up
	RTUSBReadMACRegister(MAC_CSR0, &temp);
	while ((temp == 0) && (i < 50))
	{
		DBNSLog(@".");
		sleep(1);
		RTUSBReadMACRegister(MAC_CSR0, &temp);

		++i;
	}
	DBNSLog(@"\n");
	DBNSLog(@"Init: MAC_CSR0=0x%08lx\n", (unsigned long)temp);

	// Load firmware
	
	ret = NICLoadFirmware();
    if(ret != kIOReturnSuccess){
        return kIOReturnIOError;
    }

	// Initialize Asics

	NICInitializeAsic();
	NICInitialized = true;
	
	// Read additional info from NIC such as MAC address
	NICReadEEPROMParameters();
	NICInitAsicFromEEPROM();

	RTUSBWriteHWMACAddress();

//	RTMPSetLED(LED_LNK_ON);
/*
	// external LNA has different R17 base
	if (NicConfig2.field.ExternalLNA)
	{
		BbpTuning.R17LowerBoundA += 0x10;
		BbpTuning.R17UpperBoundA += 0x10;
		BbpTuning.R17LowerBoundG += 0x10;
		BbpTuning.R17UpperBoundG += 0x10;
	}

	// hardware initialization after all parameters are acquired from
	// Registry or E2PROM
	unsigned char TmpPhy = PortCfg.PhyMode;
	PortCfg.PhyMode = 0xff;
	RTMPSetPhyMode(pAd, TmpPhy);
*/
/*
	if (!RTMP_TEST_FLAG(pAd, fRTMP_ADAPTER_RADIO_OFF))
	{
		RTUSBBulkReceive(pAd);
*/

	RTUSBWriteMACRegister(TXRX_CSR0, 0x025eb032);    // enable RX of MAC block, Staion not drop control frame, Station not drop not to me unicast frame
	RTUSBWriteMACRegister(TXRX_CSR5, 0x0000015f);    // enable RX of MAC block, Staion not drop control frame, Station not drop not to me unicast frame
/*
        // Initialize RF register to default value
	    AsicSwitchChannel(pAd, pAd->PortCfg.Channel);
	    AsicLockChannel(pAd, pAd->PortCfg.Channel);
	}
*/
    currentRate = RATE_54;
	return ret;
}

IOReturn	RT73Jack::RTUSB_VendorRequest(UInt8 direction,
                        UInt8 bRequest, 
                        UInt16 wValue, 
                        UInt16 wIndex, 
                        void *pData,
                        UInt16 wLength) {
    
    IOReturn ret;
    
	if (!_devicePresent || (NULL == _interface))
	{
		DBNSLog(@"device not connected");
		return kIOReturnNoDevice;
	}
	else
	{
        IOUSBDevRequest theRequest;
        theRequest.bmRequestType = USBmakebmRequestType(direction, kUSBVendor, kUSBEndpoint);
        theRequest.bRequest = bRequest;
        theRequest.wValue = wValue; 
        theRequest.wIndex = wIndex; 
        theRequest.pData = pData;
        theRequest.wLength = wLength;
        
        ret = (*_interface)->ControlRequest(_interface, 0, &theRequest);
    }
	return ret;    
}

IOReturn	RT73Jack::RTUSBMultiRead(
				unsigned short	Offset,
				unsigned char	*pData,
				unsigned short	length)
{
	IOReturn	Status;

	Status = RTUSB_VendorRequest(
		kUSBOut,
		0x7,
		0,
		Offset,
		pData,
		length);

	return Status;
}

IOReturn	RT73Jack::RTUSBMultiWrite(
				unsigned short	Offset,
				unsigned char	*pData,
				unsigned short	length)
{
	IOReturn	Status;

	Status = RTUSB_VendorRequest(
		kUSBOut,
		0x6,
		0,
		Offset,
		pData,
		length);

	return Status;
}

IOReturn	RT73Jack::RTUSBFirmwareRun()
{
	IOReturn	Status;

	Status = RTUSB_VendorRequest(
		kUSBOut,
		0x1,
		0x8,
		0,
		NULL,
		0);

	return Status;
}

IOReturn	RT73Jack::RTUSBWriteHWMACAddress()
{
    IOReturn        Status = kIOReturnSuccess;
    
    MAC_CSR2_STRUC             StaMacReg0;
    MAC_CSR3_STRUC             StaMacReg1;
 
    // Write New MAC address to MAC_CSR2 & MAC_CSR3 & let ASIC know our new MAC
    StaMacReg0.field.Byte0 = PermanentAddress[0];
    StaMacReg0.field.Byte1 = PermanentAddress[1];
    StaMacReg0.field.Byte2 = PermanentAddress[2];
    StaMacReg0.field.Byte3 = PermanentAddress[3];
    StaMacReg1.field.Byte4 = PermanentAddress[4];
    StaMacReg1.field.Byte5 = PermanentAddress[5];
    StaMacReg1.field.U2MeMask = 0xff;

    DBNSLog(@"Local MAC = %02x:%02x:%02x:%02x:%02x:%02x\n",
        PermanentAddress[0], PermanentAddress[1], PermanentAddress[2],
        PermanentAddress[3], PermanentAddress[4], PermanentAddress[5]);

    RTUSBWriteMACRegister(MAC_CSR2, StaMacReg0.word);
    RTUSBWriteMACRegister(MAC_CSR3, StaMacReg1.word);

    return Status;
}

IOReturn	RT73Jack::RTUSBSetLED(
				MCU_LEDCS_STRUC	LedStatus,
				unsigned short	LedIndicatorStrength)
{
	IOReturn	Status;

	Status = RTUSB_VendorRequest(
		kUSBOut,
		0xa,
		LedStatus.word,
		LedIndicatorStrength,
		NULL,
		0);
//	DBNSLog(@"Set LED, status=%x & indicatorstrength=%x\n", LedStatus.word, LedIndicatorStrength);

	return	Status;
}

IOReturn	RT73Jack::RTMPSetLED(
				unsigned char	LEDStatus)
{
	IOReturn	Status;

	switch (LEDStatus)
	{
		case LED_LNK_ON:
			if (true)//(pAd->PortCfg.Channel <= 14)
			{
				// 11 G mode
				LedCntl.field.LinkGStatus = 1;
				LedCntl.field.LinkAStatus = 0;
				if (LedCntl.field.PolarityGPIO_0 == 0) {
					LedCntl.field.RadioStatus = 1;
				}
				else {
					LedCntl.field.RadioStatus = 0;
				}
			}
			else
			{ 
				//11 A mode
				LedCntl.field.LinkGStatus = 0;
				LedCntl.field.LinkAStatus = 1;
				if (LedCntl.field.PolarityGPIO_0==0) {
					LedCntl.field.RadioStatus = 1;
				}
				else {
					LedCntl.field.RadioStatus = 0;
				}
			}			
			Status = RTUSBSetLED(LedCntl, LedIndicatorStrength);			
			break;
		case LED_LNK_OFF:
		    if (LedCntl.field.PolarityGPIO_0 == 0) {
				LedCntl.field.RadioStatus = 0;
			}
			else {
				LedCntl.field.LinkGStatus = 1;
				LedCntl.field.LinkAStatus = 1;
				LedCntl.field.RadioStatus = 1;
			}
			Status = RTUSBSetLED(LedCntl, LedIndicatorStrength);
			break;
		case LED_ACT_ON:
			if (LedCntl.field.PolarityGPIO_0 == 0)
			{
				LedCntl.field.LinkAStatus = !LedCntl.field.LinkAStatus;
				LedCntl.field.LinkGStatus = !LedCntl.field.LinkGStatus;
				LedCntl.field.RadioStatus = !LedCntl.field.RadioStatus;
				LedCntl.field.PolarityGPIO_0 = 1;
			}
			Status = RTUSBSetLED(LedCntl, LedIndicatorStrength);			
			break;
		case LED_ACT_OFF:
			if (LedCntl.field.PolarityGPIO_0 == 1)
			{
				LedCntl.field.LinkAStatus = !LedCntl.field.LinkAStatus;
				LedCntl.field.LinkGStatus = !LedCntl.field.LinkGStatus;
				LedCntl.field.RadioStatus = !LedCntl.field.RadioStatus;
				LedCntl.field.PolarityGPIO_0 = 0;
			}
			Status = RTUSBSetLED(LedCntl, LedIndicatorStrength);			
			break;
		case LED_NONE:
			LedCntl.field.LinkAStatus = 0;
			LedCntl.field.LinkGStatus = 0;
			LedCntl.field.RadioStatus = 0;
			LedCntl.field.PolarityGPIO_0 = 0;
			Status = RTUSBSetLED(LedCntl, LedIndicatorStrength);
			break;
		default:
			DBNSLog(@"RTMPSetLED::Unknown Status %d\n", LEDStatus);
			Status = kIOReturnError;
			break;
	}

	return	Status;
}

IOReturn RT73Jack::RTUSBWriteMACRegister(
			unsigned short	Offset,
			unsigned long	Value)
{
	IOReturn Status;
//	if (Offset == TXRX_CSR2)
//        DBNSLog(@" !!!!!set Rx control = %x\n", Value);
    UInt32 reg = CFSwapInt32HostToLittle(Value);
	Status = RTUSB_VendorRequest(kUSBOut,
                                 0x6,
                                 0,
                                 Offset,
                                 &reg,
                                 4);	
	return Status;
}

IOReturn	RT73Jack::RTUSBReadMACRegister(
				USHORT	Offset,
				ULONG	*pValue)
{
	IOReturn Status = kIOReturnSuccess;
	UInt32 reg = 0;
	Status = RTUSB_VendorRequest(kUSBIn,
                                 0x7,
                                 0,
                                 Offset,
                                 &reg,
                                 4);	
    *pValue = CFSwapInt32LittleToHost(reg);
	return Status;
}

IOReturn	RT73Jack::RTUSBReadBBPRegister(
				unsigned char	Id,
				unsigned char	*pValue)
{
	PHY_CSR3_STRUC	PhyCsr3;
	unsigned int			i = 0;
    IOReturn ret;
    
	// Verify the busy condition
	do
	{
		RTUSBReadMACRegister(PHY_CSR3, &PhyCsr3.word);
		if (!(PhyCsr3.field.Busy == BUSY)) {
			break;
		}
		++i;
	}
	while (i < RETRY_LIMIT);

	if (i == RETRY_LIMIT)
	{
		DBNSLog(@"Retry count exhausted or device removed!!!\n");
		return kIOReturnNotResponding;
	}

	// Prepare for write material
	PhyCsr3.word 				= 0;
	PhyCsr3.field.fRead			= 1;
	PhyCsr3.field.Busy			= 1;
	PhyCsr3.field.RegNum 		= Id;
	ret = RTUSBWriteMACRegister(PHY_CSR3, PhyCsr3.word);
    
    if (ret!= kIOReturnSuccess) {
        DBNSLog(@"Error Reading the BBP Register.");
        return ret;
    }

	// Verify the busy condition
	i = 0;
	do
	{
		ret = RTUSBReadMACRegister(PHY_CSR3, &PhyCsr3.word);
		if (!(PhyCsr3.field.Busy == BUSY)) {
			*pValue = (unsigned char)PhyCsr3.field.Value;
			break;
		}
		++i;
	}
	while (i < RETRY_LIMIT);
    
	if (i == RETRY_LIMIT)
	{
		DBNSLog(@"Retry count exhausted or device removed!!!\n");
		return kIOReturnNotResponding;
	}
	
	return ret;
}

IOReturn	RT73Jack::RTUSBWriteBBPRegister(
				unsigned char	Id,
				unsigned char	Value)
{
	PHY_CSR3_STRUC	PhyCsr3;
	unsigned int	i = 0;

	// Verify the busy condition
	do
	{
		RTUSBReadMACRegister(PHY_CSR3, &PhyCsr3.word);
		if (!(PhyCsr3.field.Busy == BUSY))
			break;
		++i;
	}
	while (i < RETRY_LIMIT);
    
	if (i == RETRY_LIMIT)
	{
		DBNSLog(@"Retry count exhausted or device removed!!!\n");
		return kIOReturnNoDevice;
	}
    

	// Prepare for write material
	PhyCsr3.word 				= 0;
	PhyCsr3.field.fRead			= 0;
	PhyCsr3.field.Value			= Value;
	PhyCsr3.field.Busy			= 1;
	PhyCsr3.field.RegNum 		= Id;
	RTUSBWriteMACRegister(PHY_CSR3, PhyCsr3.word);
	
	return kIOReturnSuccess;
}

IOReturn	RT73Jack::RTUSBWriteRFRegister(
				unsigned long	Value)
{
	PHY_CSR4_STRUC	PhyCsr4;
	unsigned int	i = 0;
    
	do
	{
		RTUSBReadMACRegister(PHY_CSR4, &PhyCsr4.word);
		if (!(PhyCsr4.field.Busy))
			break;
		++i;
	}
	while (i < RETRY_LIMIT);
    
	if (i == RETRY_LIMIT)
	{
		DBNSLog(@"Retry count exhausted or device removed!!!\n");
		return kIOReturnNoDevice;
	}
    
	RTUSBWriteMACRegister(PHY_CSR4, Value);
	
	return kIOReturnSuccess;
}

IOReturn	RT73Jack::RTUSBReadEEPROM(
				unsigned short	Offset,
				unsigned char	*pData,
				unsigned short	length)
{
	IOReturn	Status;

#ifdef __BIG_ENDIAN__
    char *buf;
#endif

	Status = RTUSB_VendorRequest(kUSBIn,
                                 0x9,
                                 0,
                                 Offset,
                                 pData,
                                 length);

#ifdef __BIG_ENDIAN__
    // EEPROM data is returned in little endian format (16 bit).
    buf = (char*) malloc(sizeof(char) * length);
    swab(pData, buf, length);
    memcpy(pData, buf,length);
    free(buf);
#endif

	return Status;
}

IOReturn	RT73Jack::RTUSBReadMacAddress(unsigned char	*pData)
{
	IOReturn	Status;

	Status = RTUSB_VendorRequest(kUSBIn,
                                 0x9,
                                 0,
                                 EEPROM_MAC_ADDRESS_BASE_OFFSET,
                                 pData,
                                 MAC_ADDR_LEN);

	return Status;
}

//
//  Initialize RT73 Asic
//
IOReturn RT73Jack::NICInitializeAsic()
{
	IOReturn	Status = kIOReturnSuccess;
	ULONG	Index, Counter;
	unsigned char	Value = 0xff;
	ULONG	Version;
	MAC_CSR12_STRUC	MacCsr12;

	DBNSLog(@"--> NICInitializeAsic\n");

	RTUSBReadMACRegister(MAC_CSR0, &Version);
	
	// Initialize MAC register to default value
	for (Index = 0; Index < NUM_MAC_REG_PARMS; ++Index)
	{
		RTUSBWriteMACRegister((unsigned short)MACRegTable[Index].Register, MACRegTable[Index].Value);
	}
	
	// Set Host ready before kicking Rx
	RTUSBWriteMACRegister(MAC_CSR1, 0x3);
	RTUSBWriteMACRegister(MAC_CSR1, 0x0);		

	//
	// Before program BBP, we need to wait for BBP/RF to get awaken.
	//
	Index = 0;
	do
	{
		RTUSBReadMACRegister(MAC_CSR12, &MacCsr12.word);

		if (MacCsr12.field.BbpRfStatus == 1)
			break;

		RTUSBWriteMACRegister(MAC_CSR12, 0x4); //Force wake up.
		sleep(1);
	} while (Index++ < 1000);

	// Read BBP register, make sure BBP is up and running before writing new data
	Index = 0;
	do 
	{
		RTUSBReadBBPRegister(BBP_R0, &Value);
		DBNSLog(@"BBP version = %d\n", Value);
        
	} while ((++Index < 100) && ((Value == 0xff) || (Value == 0x00)));
		  
	// Initialize BBP register to default value
	for (Index = 0; Index < NUM_BBP_REG_PARMS; ++Index)
	{
		RTUSBWriteBBPRegister(RT73BBPRegTable[Index].Register, RT73BBPRegTable[Index].Value);
	}

	// Clear raw counters
	RTUSBReadMACRegister(STA_CSR0, &Counter);
	RTUSBReadMACRegister(STA_CSR1, &Counter);
	RTUSBReadMACRegister(STA_CSR2, &Counter);

	// assert HOST ready bit
	RTUSBWriteMACRegister(MAC_CSR1, 0x4);

	DBNSLog(@"<-- NICInitializeAsic\n");

	return Status;
}

//
// Load RT73 firmware into adapter.
//
IOReturn RT73Jack::NICLoadFirmware()
{
	IOReturn				Status = kIOReturnSuccess;
	unsigned int 					i;

	DBNSLog(@"--> NICLoadFirmware\n");
		
    // select 8051 program bank; write entire firmware image
	for (i = 0; i < FIRMWAREIMAGE_LENGTH; i = i + 4)
	{
		if(RTUSBMultiWrite(FIRMWARE_IMAGE_BASE + i, &FirmwareImage[i], 4) != kIOReturnSuccess){
            DBNSLog(@"Firmware load failed!");
            Status = kIOReturnNotResponding;
            break;
        }
    }
        
	if (Status == kIOReturnSuccess)
	{
		//
		// Send LED command to Firmare after RTUSBFirmwareRun;
		//
		DBNSLog(@"Firmware loaded, starting firmware...\n");
		RTUSBFirmwareRun();
		RTMPSetLED(LED_NONE);
	}
    
	DBNSLog(@"<-- NICLoadFirmware (src=hardcoded, V1.8)\n");  

	return Status;
}

void	RT73Jack::NICReadEEPROMParameters()
{
	unsigned short	i, value;
	EEPROM_ANTENNA_STRUC	Antenna;
	EEPROM_VERSION_STRUC	Version;
	char	ChannelTxPower[MAX_NUM_OF_CHANNELS];
	EEPROM_LED_STRUC	LedSetting;

	DBNSLog(@"--> NICReadEEPROMParameters\n");

	//Read MAC address.
	RTUSBReadMacAddress(PermanentAddress);
	DBNSLog(@"Local MAC = %02x:%02x:%02x:%02x:%02x:%02x\n",
			PermanentAddress[0], PermanentAddress[1], PermanentAddress[2],
			PermanentAddress[3], PermanentAddress[4], PermanentAddress[5]);

	// Init the channel number for TX channel power
	// 0. 11b/g
	for (i = 0; i < 14; ++i)
		TxPower[i].Channel = i + 1;
	// 1. UNI 36 - 64
	for (i = 0; i < 8; ++i)
		TxPower[i + 14].Channel = 36 + i * 4;
	// 2. HipperLAN 2 100 - 140
	for (i = 0; i < 11; ++i)
		TxPower[i + 22].Channel = 100 + i * 4;
	// 3. UNI 140 - 165
	for (i = 0; i < 5; ++i)
		TxPower[i + 33].Channel = 149 + i * 4; 	   

	// 34/38/42/46
	for (i = 0; i < 4; ++i)
		TxPower[i + 38].Channel = 34 + i * 4;

	// if E2PROM version mismatch with driver's expectation, then skip
	// all subsequent E2RPOM retieval and set a system error bit to notify GUI
	RTUSBReadEEPROM(EEPROM_VERSION_OFFSET, (unsigned char *)&Version.word, 2);
	EepromVersion = Version.field.Version + Version.field.FaeReleaseNumber * LAST_BIT;
	DBNSLog(@"E2PROM: Version = %d, FAE release #%d\n", Version.field.Version, Version.field.FaeReleaseNumber);

	// Read BBP default value from EEPROM and store to array(EEPROMDefaultValue) in pAd
	RTUSBReadEEPROM(EEPROM_BBP_BASE_OFFSET, (unsigned char *)(EEPROMDefaultValue), 2 * NUM_EEPROM_BBP_PARMS);

	// We have to parse NIC configuration 0 at here.
	// If TSSI did not have preloaded value, it should reset the TxAutoAgc to false
	// Therefore, we have to read TxAutoAgc control beforehand.
	// Read Tx AGC control bit
	Antenna.word = EEPROMDefaultValue[0];
	if (Antenna.field.DynamicTxAgcControl == 1)
		bAutoTxAgcA = bAutoTxAgcG = TRUE;
	else
		bAutoTxAgcA = bAutoTxAgcG = FALSE;		

/*
	//
	// Reset PhyMode if we don't support 802.11a
	//
	if ((pAd->PortCfg.PhyMode == PHY_11ABG_MIXED) || (pAd->PortCfg.PhyMode == PHY_11A))
	{
		//
		// Only RFIC_5226, RFIC_5225 suport 11a
		//
		if ((Antenna.field.RfIcType == RFIC_2528) || (Antenna.field.RfIcType == RFIC_2527))
			pAd->PortCfg.PhyMode = PHY_11BG_MIXED;

		//
		// Reset Adhoc Mode if we don't support 802.11a
		//
		if ((pAd->PortCfg.AdhocMode == ADHOC_11A) || (pAd->PortCfg.AdhocMode == ADHOC_11ABG_MIXED))
		{
			//
			// Only RFIC_5226, RFIC_5225 suport 11a
			//
			if ((Antenna.field.RfIcType == RFIC_2528) || (Antenna.field.RfIcType == RFIC_2527))
				pAd->PortCfg.AdhocMode = ADHOC_11BG_MIXED;
		}

    }
*/
	
	// Read Tx power value for all 14 channels
	// Value from 1 - 0x7f. Default value is 24.
	// 0. 11b/g
	// Power value 0xFA (-6) ~ 0x24 (36)
	RTUSBReadEEPROM(EEPROM_G_TX_PWR_OFFSET, (unsigned char *)ChannelTxPower, 2 * NUM_EEPROM_TX_G_PARMS);
	for (i = 0; i < 2 * NUM_EEPROM_TX_G_PARMS; ++i)
	{
		if ((ChannelTxPower[i] > 36) || (ChannelTxPower[i] < -6))
			TxPower[i].Power = 24;			
		else
			TxPower[i].Power = ChannelTxPower[i];

		DBNSLog(@"Tx power for channel %d : %0x\n", TxPower[i].Channel, TxPower[i].Power);
	}

	// 1. UNI 36 - 64, HipperLAN 2 100 - 140, UNI 140 - 165
	// Power value 0xFA (-6) ~ 0x24 (36)
	RTUSBReadEEPROM(EEPROM_A_TX_PWR_OFFSET, (unsigned char *)ChannelTxPower, MAX_NUM_OF_A_CHANNELS);
	for (i = 0; i < MAX_NUM_OF_A_CHANNELS; ++i)
	{
		if ((ChannelTxPower[i] > 36) || (ChannelTxPower[i] < -6))
			TxPower[i + 14].Power = 24;
		else			
			TxPower[i + 14].Power = ChannelTxPower[i];
		DBNSLog(@"Tx power for channel %d : %0x\n", TxPower[i + 14].Channel, TxPower[i + 14].Power);
	}

	//
	// Please note, we must skip frist value, so we get TxPower as ChannelTxPower[i + 1];
	// because the TxPower was stored from 0x7D, but we need to read EEPROM from 0x7C. (Word alignment)
	//
	// for J52, 34/38/42/46
	RTUSBReadEEPROM(EEPROM_J52_TX_PWR_OFFSET, (unsigned char *)ChannelTxPower, 6); //must Read even valuse

	for (i = 0; i < 4; ++i)
	{
//		ASSERT(TxPower[J52_CHANNEL_START_OFFSET + i].Channel == 34 + i * 4);
		if ((ChannelTxPower[i] > 36) || (ChannelTxPower[i] < -6))
			TxPower[J52_CHANNEL_START_OFFSET + i].Power = 24;
		else			
			TxPower[J52_CHANNEL_START_OFFSET + i].Power = ChannelTxPower[i + 1];

		DBNSLog(@"Tx power for channel %d : %0x\n", TxPower[J52_CHANNEL_START_OFFSET + i].Channel, TxPower[J52_CHANNEL_START_OFFSET + i].Power);
	}

	// Read TSSI reference and TSSI boundary for temperature compensation.
	// 0. 11b/g
	{
		RTUSBReadEEPROM(EEPROM_BG_TSSI_CALIBRAION, (unsigned char *)ChannelTxPower, 10);
		TssiMinusBoundaryG[4] = ChannelTxPower[0];
		TssiMinusBoundaryG[3] = ChannelTxPower[1];
		TssiMinusBoundaryG[2] = ChannelTxPower[2];
		TssiMinusBoundaryG[1] = ChannelTxPower[3];
		TssiPlusBoundaryG[1] = ChannelTxPower[4];
		TssiPlusBoundaryG[2] = ChannelTxPower[5];
		TssiPlusBoundaryG[3] = ChannelTxPower[6];
		TssiPlusBoundaryG[4] = ChannelTxPower[7];
		TssiRefG	= ChannelTxPower[8];
		TxAgcStepG = ChannelTxPower[9];  
		TxAgcCompensateG = 0;
		TssiMinusBoundaryG[0] = TssiRefG;
		TssiPlusBoundaryG[0]  = TssiRefG;

		// Disable TxAgc if the based value is not right
		if (TssiRefG == 0xff)
			bAutoTxAgcG = FALSE;

		DBNSLog(@"E2PROM: G Tssi[-4 .. +4] = %d %d %d %d - %d -%d %d %d %d, step=%d, tuning=%d\n",
			TssiMinusBoundaryG[4], TssiMinusBoundaryG[3], TssiMinusBoundaryG[2], TssiMinusBoundaryG[1],
			TssiRefG,
			TssiPlusBoundaryG[1], TssiPlusBoundaryG[2], TssiPlusBoundaryG[3], TssiPlusBoundaryG[4],
			TxAgcStepG, bAutoTxAgcG);
	}	
	// 1. 11a
	{
		RTUSBReadEEPROM(EEPROM_A_TSSI_CALIBRAION, (unsigned char *)ChannelTxPower, 10);
		TssiMinusBoundaryA[4] = ChannelTxPower[0];
		TssiMinusBoundaryA[3] = ChannelTxPower[1];
		TssiMinusBoundaryA[2] = ChannelTxPower[2];
		TssiMinusBoundaryA[1] = ChannelTxPower[3];
		TssiPlusBoundaryA[1] = ChannelTxPower[4];
		TssiPlusBoundaryA[2] = ChannelTxPower[5];
		TssiPlusBoundaryA[3] = ChannelTxPower[6];
		TssiPlusBoundaryA[4] = ChannelTxPower[7];
		TssiRefA	= ChannelTxPower[8];
		TxAgcStepA = ChannelTxPower[9]; 
		TxAgcCompensateA = 0;
		TssiMinusBoundaryA[0] = TssiRefA;
		TssiPlusBoundaryA[0]  = TssiRefA;

		// Disable TxAgc if the based value is not right
		if (TssiRefA == 0xff)
			bAutoTxAgcA = FALSE;

		DBNSLog(@"E2PROM: A Tssi[-4 .. +4] = %d %d %d %d - %d -%d %d %d %d, step=%d, tuning=%d\n",
			TssiMinusBoundaryA[4], TssiMinusBoundaryA[3], TssiMinusBoundaryA[2], TssiMinusBoundaryA[1],
			TssiRefA,
			TssiPlusBoundaryA[1], TssiPlusBoundaryA[2], TssiPlusBoundaryA[3], TssiPlusBoundaryA[4],
			TxAgcStepA, bAutoTxAgcA);
	}	
	BbpRssiToDbmDelta = 0x79;

	RTUSBReadEEPROM(EEPROM_FREQ_OFFSET, (unsigned char *) &value, 2);
	if ((value & 0xFF00) == 0xFF00)
	{
		RFProgSeq = 0;
	}
	else
	{
		RFProgSeq = (value & 0x0300) >> 8;	// bit 8,9
	}

	value &= 0x00FF;
	if (value != 0x00FF)
		RfFreqOffset = (ULONG) value;
	else
		RfFreqOffset = 0;
	DBNSLog(@"E2PROM: RF freq offset=%lu\n", RfFreqOffset);

/*
	//CountryRegion byte offset = 0x25
	value = EEPROMDefaultValue[2] >> 8;
	value2 = EEPROMDefaultValue[2] & 0x00FF;
    if ((value <= REGION_MAXIMUM_BG_BAND) && (value2 <= REGION_MAXIMUM_A_BAND))
	{
		pAd->PortCfg.CountryRegion = ((UCHAR) value) | 0x80;
		pAd->PortCfg.CountryRegionForABand = ((UCHAR) value2) | 0x80;
	}
*/

	//
	// Get RSSI Offset on EEPROM 0x9Ah & 0x9Ch.
	// The valid value are (-10 ~ 10) 
	// 
	RTUSBReadEEPROM(EEPROM_RSSI_BG_OFFSET, (unsigned char *) &value, 2);
	BGRssiOffset1 = value & 0x00ff;
	BGRssiOffset2 = (value >> 8);

	// Validate 11b/g RSSI_1 offset.
	if ((BGRssiOffset1 < -10) || (BGRssiOffset1 > 10))
		BGRssiOffset1 = 0;

	// Validate 11b/g RSSI_2 offset.
	if ((BGRssiOffset2 < -10) || (BGRssiOffset2 > 10))
		BGRssiOffset2 = 0;
		
	RTUSBReadEEPROM(EEPROM_RSSI_A_OFFSET, (unsigned char *) &value, 2);
	ARssiOffset1 = value & 0x00ff;
	ARssiOffset2 = (value >> 8);

	// Validate 11a RSSI_1 offset.
	if ((ARssiOffset1 < -10) || (ARssiOffset1 > 10))
		ARssiOffset1 = 0;

	//Validate 11a RSSI_2 offset.
	if ((ARssiOffset2 < -10) || (ARssiOffset2 > 10))
		ARssiOffset2 = 0;

	//
	// Get LED Setting.
	//
	RTUSBReadEEPROM(EEPROM_LED_OFFSET, (unsigned char *)&LedSetting.word, 2);
	if (LedSetting.word == 0xFFFF)
	{
		//
		// Set it to Default.
		//
		LedSetting.field.PolarityRDY_G = 0;   // Active High.
		LedSetting.field.PolarityRDY_A = 0;   // Active High.
		LedSetting.field.PolarityACT = 0;	 // Active High.
		LedSetting.field.PolarityGPIO_0 = 0; // Active High.
		LedSetting.field.PolarityGPIO_1 = 0; // Active High.
		LedSetting.field.PolarityGPIO_2 = 0; // Active High.
		LedSetting.field.PolarityGPIO_3 = 0; // Active High.
		LedSetting.field.PolarityGPIO_4 = 0; // Active High.
		LedSetting.field.LedMode = LED_MODE_DEFAULT;		
	}
	LedCntl.word = 0;
	LedCntl.field.LedMode = LedSetting.field.LedMode;
	LedCntl.field.PolarityRDY_G = LedSetting.field.PolarityRDY_G;
	LedCntl.field.PolarityRDY_A = LedSetting.field.PolarityRDY_A;
	LedCntl.field.PolarityACT = LedSetting.field.PolarityACT;
	LedCntl.field.PolarityGPIO_0 = LedSetting.field.PolarityGPIO_0;
	LedCntl.field.PolarityGPIO_1 = LedSetting.field.PolarityGPIO_1;
	LedCntl.field.PolarityGPIO_2 = LedSetting.field.PolarityGPIO_2;
	LedCntl.field.PolarityGPIO_3 = LedSetting.field.PolarityGPIO_3;
	LedCntl.field.PolarityGPIO_4 = LedSetting.field.PolarityGPIO_4;

	RTUSBReadEEPROM(EEPROM_TXPOWER_DELTA_OFFSET, (unsigned char *)&value, 2);
	value = value & 0x00ff;
	if (value != 0xff)
	{
		TxPowerDeltaConfig.value = (unsigned char) value;
		if (TxPowerDeltaConfig.field.DeltaValue > 0x04)
			TxPowerDeltaConfig.field.DeltaValue = 0x04;
	}
	else
		TxPowerDeltaConfig.field.TxPowerEnable = FALSE;
	
	DBNSLog(@"<-- NICReadEEPROMParameters\n");

/*v
	USHORT			i;
	int			value;
    unsigned char PermanentAddress[ETH_LENGTH_OF_ADDRESS];
	EEPROM_ANTENNA_STRUC	Antenna;//blue
    //	EEPROM_VERSION_STRUC	Version;
        
        DBNSLog(@"--> NICReadEEPROMParameters\n");
        
        //Read MAC address.
        RTUSBReadEEPROM(EEPROM_MAC_ADDRESS_BASE_OFFSET, PermanentAddress, ETH_LENGTH_OF_ADDRESS);
        DBNSLog(@"Permanent MAC is: %02x:%02x:%02x:%02x:%02x:%02x.", PermanentAddress[0], PermanentAddress[1], PermanentAddress[2], PermanentAddress[3], PermanentAddress[4], PermanentAddress[5]);
        // Read BBP default value from EEPROM and store to array(EEPROMDefaultValue) in 
        RTUSBReadEEPROM(EEPROM_BBP_BASE_OFFSET, (unsigned char *)(EEPROMDefaultValue), 2 * NUM_EEPROM_BBP_PARMS);
        
        // We have to parse NIC configuration 0 at here.
        // If TSSI did not have preloaded value, it should reset the TxAutoAgc to false
        // Therefore, we have to read TxAutoAgc control beforehand.
        // Read Tx AGC control bit
        Antenna.word = EEPROMDefaultValue[0];
//        if (Antenna.field.DynamicTxAgcControl == 1)  //auto tx control
		
	
    
	// Read Tx power value for all 14 channels
	// Value from 1 - 0x7f. Default value is 24.
    char ChannelTxPower[14];
	RTUSBReadEEPROM(EEPROM_TX_PWR_OFFSET, (unsigned char *)ChannelTxPower, 2 * NUM_EEPROM_TX_PARMS);
	for (i = 0; i < 2 * NUM_EEPROM_TX_PARMS; i++)
	{
        
		if (ChannelTxPower[i] > 31)
			ChannelTxPower[i] = 24;
		DBNSLog(@"Tx power for channel %d : %0x\n", i+1, ChannelTxPower[i]);
	}
        
v*/     /*   
    
	// Read Tx TSSI reference value, OK to reuse Power data structure
	RTUSBReadEEPROM(EEPROM_TSSI_REF_OFFSET, PortCfg.ChannelTssiRef, 2 * NUM_EEPROM_TX_PARMS);
	for (i = 0; i < 2 * NUM_EEPROM_TX_PARMS; i++)
	{
		if (PortCfg.ChannelTssiRef[i] == 0xff)
			PortCfg.bAutoTxAgc = FALSE;					
		DBNSLog(@"TSSI reference for channel %d : %0x\n", i, PortCfg.ChannelTssiRef[i]);
	}
	
	// Tx Tssi delta offset 0x24
	RTUSBReadEEPROM(EEPROM_TSSI_DELTA_OFFSET, (unsigned char)(&(Power.word)), 2);
	PortCfg.ChannelTssiDelta = Power.field.Byte0;
*//*v	
	//CountryRegion byte offset = 0x35
	value = EEPROMDefaultValue[2] >> 8;
	DBNSLog(@"  CountryRegion= 0x%x \n",value);
v*//*
	if ((value >= 0) && (value <= 7))
	{
		PortCfg.CountryRegion = (unsigned char) value;
		TmpPhy = PortCfg.PhyMode;
		PortCfg.PhyMode = 0xff;
		RTMPSetPhyMode(TmpPhy);
	}
	else
	{
		// set default country region 
		PortCfg.CountryRegion = 6;
		TmpPhy = PortCfg.PhyMode;
		PortCfg.PhyMode = 0xff;
		RTMPSetPhyMode(TmpPhy);
	}
*//*v    
	RTUSBReadEEPROM(EEPROM_BBP_TUNING_OFFSET, (unsigned char *)(EEPROMBBPTuningParameters), 2 * NUM_EEPROM_BBP_TUNING_PARMS);
	if ((EEPROMBBPTuningParameters[0] != 0xffff) && (EEPROMBBPTuningParameters[0] != 0))
	{
		RT73_BBPTuningParameters.BBPTuningThreshold = (unsigned char)((EEPROMBBPTuningParameters[0]) & 0xff);
		//DBNSLog(@"BBPTuningThreshold = %d\n", BBPTuningParameters.BBPTuningThreshold);
	}
	if ((EEPROMBBPTuningParameters[1] != 0xffff) && (EEPROMBBPTuningParameters[1] != 0))
	{
		RT73_BBPTuningParameters.R24LowerValue = (unsigned char)(EEPROMBBPTuningParameters[1] & 0xff);
		RT73_BBPTuningParameters.R24HigherValue = (unsigned char)((EEPROMBBPTuningParameters[1] & 0xff00) >> 8);
		DBNSLog(@"R24LowerValue = 0x%x\n", RT73_BBPTuningParameters.R24LowerValue);
		DBNSLog(@"R24HigherValue = 0x%x\n", RT73_BBPTuningParameters.R24HigherValue);
	}
	if ((EEPROMBBPTuningParameters[2] != 0xffff) && (EEPROMBBPTuningParameters[2] != 0))
	{
		RT73_BBPTuningParameters.R25LowerValue = (unsigned char)(EEPROMBBPTuningParameters[2] & 0xff);
		RT73_BBPTuningParameters.R25HigherValue = (unsigned char)((EEPROMBBPTuningParameters[2] & 0xff00) >> 8);
		DBNSLog(@"R25LowerValue = 0x%x\n", RT73_BBPTuningParameters.R25LowerValue);
		DBNSLog(@"R25HigherValue = 0x%x\n", RT73_BBPTuningParameters.R25HigherValue);
	}
	if ((EEPROMBBPTuningParameters[3] != 0xffff) && (EEPROMBBPTuningParameters[3] != 0))
	{
		RT73_BBPTuningParameters.R61LowerValue = (unsigned char)(EEPROMBBPTuningParameters[3] & 0xff);
		RT73_BBPTuningParameters.R61HigherValue = (unsigned char)((EEPROMBBPTuningParameters[3] & 0xff00) >> 8);
		DBNSLog(@"R61LowerValue = 0x%x\n", RT73_BBPTuningParameters.R61LowerValue);
		DBNSLog(@"R61HigherValue = 0x%x\n", RT73_BBPTuningParameters.R61HigherValue);
	}
v*//*	if ((EEPROMBBPTuningParameters[4] != 0xffff) && (EEPROMBBPTuningParameters[4] != 0))
	{
		PortCfg.BbpTuning.VgcUpperBound = (unsigned char)(EEPROMBBPTuningParameters[4] & 0xff);
		DBNSLog(@"VgcUpperBound = 0x%x\n", PortCfg.BbpTuning.VgcUpperBound);
	}*//*v
	if ((EEPROMBBPTuningParameters[5] != 0xffff) && (EEPROMBBPTuningParameters[5] != 0))
	{
		RT73_BBPTuningParameters.BBPR17LowSensitivity = (unsigned char)(EEPROMBBPTuningParameters[5] & 0xff);
		RT73_BBPTuningParameters.BBPR17MidSensitivity = (unsigned char)((EEPROMBBPTuningParameters[5] & 0xff00) >> 8);
		DBNSLog(@"BBPR17LowSensitivity = 0x%x\n", RT73_BBPTuningParameters.BBPR17LowSensitivity);
		DBNSLog(@"BBPR17MidSensitivity = 0x%x\n", RT73_BBPTuningParameters.BBPR17MidSensitivity);
	}
	if ((EEPROMBBPTuningParameters[6] != 0xffff) && (EEPROMBBPTuningParameters[6] != 0))
	{
		RT73_BBPTuningParameters.RSSIToDbmOffset = (unsigned char)(EEPROMBBPTuningParameters[6] & 0xff);
		DBNSLog(@"RSSIToDbmOffset = 0x%x\n", RT73_BBPTuningParameters.RSSIToDbmOffset);
	}
    
	DBNSLog(@"<-- NICReadEEPROMParameters\n");
v*/
}

void RT73Jack::NICInitAsicFromEEPROM()
{
	ULONG					data;
	USHORT					i;
	ULONG					MiscMode;
	EEPROM_ANTENNA_STRUC	Antenna;
	EEPROM_NIC_CONFIG2_STRUC	NicConfig2;

	DBNSLog(@"--> NICInitAsicFromEEPROM\n");

	for(i = 3; i < NUM_EEPROM_BBP_PARMS; ++i)
	{
		UCHAR BbpRegIdx, BbpValue;
	
		if ((EEPROMDefaultValue[i] != 0xFFFF) && (EEPROMDefaultValue[i] != 0))
		{
			BbpRegIdx = (UCHAR)(EEPROMDefaultValue[i] >> 8);
			BbpValue  = (UCHAR)(EEPROMDefaultValue[i] & 0xff);
			RTUSBWriteBBPRegister(BbpRegIdx, BbpValue);
		}
	}
	
	Antenna.word = EEPROMDefaultValue[0];

	if (Antenna.word == 0xFFFF)
	{
		Antenna.word = 0;
		Antenna.field.RfIcType = RFIC_5226;
		Antenna.field.HardwareRadioControl = 0; 	// no hardware control
		Antenna.field.DynamicTxAgcControl = 0;
		Antenna.field.FrameType = 0;
		Antenna.field.RxDefaultAntenna = 2; 		// Ant-B
		Antenna.field.TxDefaultAntenna = 2; 		// Ant-B
		Antenna.field.NumOfAntenna = 2;
		DBNSLog(@"E2PROM error, hard code as 0x%04x\n", Antenna.word);
	}

	RfIcType = (unsigned char) Antenna.field.RfIcType;
	DBNSLog(@"RfIcType = %d\n", RfIcType);

	//
	// For RFIC RFIC_5225 & RFIC_2527
	// Must enable RF RPI mode on PHY_CSR1 bit 16.
	//
	if ((RfIcType == RFIC_5225) || (RfIcType == RFIC_2527))
	{
		RTUSBReadMACRegister(PHY_CSR1, &MiscMode);
		MiscMode |= 0x10000;
		RTUSBWriteMACRegister(PHY_CSR1, MiscMode);
	}
	
	// Save the antenna for future use
	Antenna.word = Antenna.word;
	
	// Read Hardware controlled Radio state enable bit
	if (Antenna.field.HardwareRadioControl == 1)
	{
//		pAd->PortCfg.bHardwareRadio = TRUE;
		
		// Read GPIO pin7 as Hardware controlled radio state
		RTUSBReadMACRegister(MAC_CSR13, &data);

		//
		// The GPIO pin7 default is 1:Pull-High, means HW Radio Enable.
		// When the value is 0, means HW Radio disable.
		//
		if ((data & 0x80) == 0)
		{
//			pAd->PortCfg.bHwRadio = FALSE;
			// Update extra information to link is up
//			ExtraInfo = HW_RADIO_OFF;
		}
	}
	else {
//		pAd->PortCfg.bHardwareRadio = FALSE;
	}

//	pAd->PortCfg.bRadio = pAd->PortCfg.bSwRadio && pAd->PortCfg.bHwRadio;
	
/*
	if (pAd->PortCfg.bRadio == FALSE)
	{
		RTUSBWriteMACRegister(pAd, MAC_CSR10, 0x00001818);
		RTMP_SET_FLAG(pAd, fRTMP_ADAPTER_RADIO_OFF);
	
		RTMPSetLED(pAd, LED_RADIO_OFF);
	}
	else
	{
		RTMPSetLED(pAd, LED_RADIO_ON);
	}
*/
	
	NicConfig2.word = EEPROMDefaultValue[1];
	if (NicConfig2.word == 0xffff)
	{
		NicConfig2.word = 0;
	}
	// Save the antenna for future use
	NicConfig2.word = NicConfig2.word;

//	DBNSLog(@"Use Hw Radio Control Pin=%d; if used Pin=%d;\n",
//		pAd->PortCfg.bHardwareRadio, pAd->PortCfg.bHardwareRadio);
	
	DBNSLog(@"RFIC=%d, LED mode=%d\n", RfIcType, LedCntl.field.LedMode);

//	pAd->PortCfg.BandState = UNKNOWN_BAND;

	DBNSLog(@"<-- NICInitAsicFromEEPROM\n");


/*v
    unsigned short i, value;
	unsigned short Value5, Value6;
	unsigned char  TxValue,RxValue;
	EEPROM_ANTENNA_STRUC	Antenna;
	EEPROM_NIC_CONFIG2_STRUC	NicConfig2;
    
	DBNSLog(@"--> NICInitAsicFromEEPROM\n");
    
	//Initialize BBP registers.
	for(i = 3; i < NUM_EEPROM_BBP_PARMS; i++)
	{
		value = EEPROMDefaultValue[i];
		
		if((value != 0xFFFF) && (value != 0))
		{
			//blue,RTUSBWriteMACRegister(PHY_CSR7, value);
			USHORT	ID;
			ID = ((value & 0xff00) >> 8);
			{
				unsigned short	temp;
				unsigned int	j = 0;
				do
				{
					RTUSBReadMACRegister(PHY_CSR8, &temp);
					if (!(temp & BUSY))
						break;
					j++;
				}
				while (j < RETRY_LIMIT);
				
				RTUSBWriteMACRegister(PHY_CSR7, value);
			}
            
		}
	}
    
	DBNSLog(@"RT73_BBPTuningParameters.R24LowerValue = %x\n", RT73_BBPTuningParameters.R24LowerValue);
	DBNSLog(@ "RT73_BBPTuningParameters.R25LowerValue = %x\n", RT73_BBPTuningParameters.R25LowerValue);
	DBNSLog(@ "RT73_BBPTuningParameters.R61LowerValue = %x\n", RT73_BBPTuningParameters.R61LowerValue);
	RTUSBWriteBBPRegister(24, RT73_BBPTuningParameters.R24LowerValue);
	RTUSBWriteBBPRegister(25, RT73_BBPTuningParameters.R25LowerValue);
	RTUSBWriteBBPRegister(61, RT73_BBPTuningParameters.R61LowerValue);
    
    
	//Select antennas.
	Antenna.word = EEPROMDefaultValue[0];
    
	if ((Antenna.word == 0xFFFF) || (Antenna.field.TxDefaultAntenna > 2) || (Antenna.field.RxDefaultAntenna > 2))
	{
		DBNSLog(@"E2PROM error(=0x%04x), hard code as 0x0002\n", Antenna.word);
		Antenna.word = 0x0002;
	}
    
	DBNSLog(@"Antenna.word = 0x%x \n", Antenna.word);
//	PortCfg.NumberOfAntenna = 2;	// (UCHAR)Antenna.field.NumOfAntenna;
//	PortCfg.CurrentTxAntenna = (UCHAR)Antenna.field.TxDefaultAntenna;
//	PortCfg.CurrentRxAntenna = (UCHAR)Antenna.field.RxDefaultAntenna;
    RfType = (unsigned char) Antenna.field.RfType;//blue
//           DBNSLog(@"PortCfg.RfType = 0x%x \n", PortCfg.RfType);
           RTUSBReadBBPRegister(BBP_Tx_Configure, &TxValue);
           RTUSBReadBBPRegister(BBP_Rx_Configure, &RxValue);
           RTUSBReadMACRegister(PHY_CSR5, &Value5);
           RTUSBReadMACRegister(PHY_CSR6, &Value6);
           
           // Tx antenna select
           if(Antenna.field.TxDefaultAntenna == 1)   
           {
               TxValue = (TxValue & 0xFC) | 0x00; // Antenna A
               Value5 = (Value5 & 0xFFFC) | 0x0000;
               Value6 = (Value6 & 0xFFFC) | 0x0000;
           }
           else if(Antenna.field.TxDefaultAntenna == 2)  
           {
               TxValue = (TxValue & 0xFC) | 0x02; // Antenna B
               Value5 = (Value5 & 0xFFFC) | 0x0002;
               Value6 = (Value6 & 0xFFFC) | 0x0002;
           }
           else
           {
               TxValue = (TxValue & 0xFC) | 0x01; // Antenna Diversity
               Value5 = (Value5 & 0xFFFC) | 0x0001;
               Value6 = (Value6 & 0xFFFC) | 0x0001;
           }
           
           
           // Rx antenna select
           if(Antenna.field.RxDefaultAntenna == 1)
               RxValue = (RxValue & 0xFC) | 0x00; // Antenna A
	else if(Antenna.field.RxDefaultAntenna == 2)
		RxValue = (RxValue & 0xFC) | 0x02; // Antenna B
	else
		RxValue = (RxValue & 0xFC) | 0x01; // Antenna Diversity
    
    
	DBNSLog(@"<-- NICInitAsicFromEEPROM RfType = %d\n", RfType);
	// RT5222 needs special treatment to swap TX I/Q
	if (RfType == RFIC_5222)
	{
		Value5 |= 0x0004;
		Value6 |= 0x0004;
		TxValue |= 0x04;		 // TX I/Q flip
	}
	// RT2525E need to flip TX I/Q but not RX I/Q
	else if (RfType == RFIC_2525E)	
	{
		Value5 |= 0x0004;
		Value6 |= 0x0004;
		TxValue |= 0x04;		 // TX I/Q flip
		RxValue &= 0xfb;		 // RX I/Q no flip
	}
	
	RTUSBWriteMACRegister(PHY_CSR5, Value5);
	RTUSBWriteMACRegister(PHY_CSR6, Value6);
    
	// Change to match microsoft definition, 0xff: diversity, 0: A, 1: B
	//PortCfg.CurrentTxAntenna--;
	//PortCfg.CurrentRxAntenna--;
    
	RTUSBWriteBBPRegister(BBP_Tx_Configure, TxValue);
	RTUSBWriteBBPRegister(BBP_Rx_Configure, RxValue);
    
v*/	/*
	//Set LED mode.
	if (Antenna.field.LedMode == LED_MODE_TXRX_ACTIVITY)
		PortCfg.LedMode = LED_MODE_TXRX_ACTIVITY;
	else if (Antenna.field.LedMode == LED_MODE_SINGLE)
	{
		PortCfg.LedMode = LED_MODE_SINGLE;
		ASIC_LED_ACT_ON();
	}
	else if (Antenna.field.LedMode == LED_MODE_ASUS)
	{
		PortCfg.LedMode = LED_MODE_ASUS;
		RTUSBWriteMACRegister(MAC_CSR20, 0x0002);
	}
	else if (Antenna.field.LedMode == LED_MODE_ALPHA)
	{
		PortCfg.LedMode = LED_MODE_ALPHA;
		RTUSBWriteMACRegister(MAC_CSR20, 1);
		PortCfg.LedCntl.fOdd = FALSE;
	}	 
	else
		PortCfg.LedMode = LED_MODE_DEFAULT;
   
    
	// Read Hardware controlled Radio state enable bit
	if (Antenna.field.HardwareRadioControl == 1)
	{
//		PortCfg.bHardwareRadio = TRUE;
		RTUSBWriteMACRegister(MAC_CSR19, 0);
        
		// Read GPIO pin0 as Hardware controlled radio state
		RTUSBReadMACRegister(MAC_CSR19, &value);
		if ((value & 0x80) == 0)
		{
			PortCfg.bHwRadio = FALSE;
			PortCfg.bRadio = FALSE;
			RTUSBWriteMACRegister(MAC_CSR13, 0);
			RTUSBWriteMACRegister(MAC_CSR14, 0);
			RTMP_SET_FLAG(fRTMP_ADAPTER_RADIO_OFF);
//        	DBGPRINT(RT_DEBUG_ERROR, "2Set fRTMP_ADAPTER_RADIO_OFF ");
			if (PortCfg.LedMode == LED_MODE_ASUS)
			{
				// Turn bit 17 for Radio OFF
				RTUSBWriteMACRegister(MAC_CSR20, 1);
			}
         
		}
	}
	else
		PortCfg.bHardwareRadio = FALSE;		
*//*v	
	NicConfig2.word = EEPROMDefaultValue[1];
	if (NicConfig2.word == 0xffff)
		NicConfig2.word = 0;	// empty E2PROM, use default
	
	// for dynamic BBP R17:RX sensibility tuning
	{
		UCHAR r17;
		RTUSBReadBBPRegister(17, &r17);
	//	PortCfg.BbpTuningEnable = (NicConfig2.field.DynamicBbpTuning==0)? 1:0;
	//	PortCfg.VgcLowerBound   = r17;
        
		// 2004-3-4 per David's request, R7 starts at upper bound
        DBNSLog(@"It is this %d,", r17);
		r17 = 128;
	    DBNSLog(@"It is this %d,", r17);
		RTUSBWriteBBPRegister(17, r17);
        
		// 2004-2-2 per David's request, lower R17 low-bound for very good quality NIC
	//	PortCfg.VgcLowerBound -= 6;  
	//	DBNSLog(@"R17 tuning enable=%d, R17=0x%02x, range=<0x%02x, 0x%02x>\n",
      //           PortCfg.BbpTuningEnable, r17, PortCfg.VgcLowerBound, PortCfg.BbpTuning.VgcUpperBound);
	}
    
//    AsicSwitchChannel(PortCfg.Channel);
//	DBNSLog(@"RF IC=%d, LED mode=%d\n", PortCfg.RfType, PortCfg.LedMode);
    _deviceInit = true;
	DBNSLog(@"<-- NICInitAsicFromEEPROM\n");
v*/
}

bool    RT73Jack::setChannel(UInt16 channel){
	unsigned long	R3 = DEFAULT_RF_TX_POWER, R4;
	char			Bbp94 = BBPR94_DEFAULT;	
	unsigned char	index = 0, BbpReg = 0;

/*
	// Select antenna
	AsicAntennaSelect(pAd, Channel);
	
	// Search Tx power value
	for (index = 0; index < pAd->ChannelListNum; index++)
	{
		if (Channel == pAd->ChannelList[index].Channel)
		{
			TxPwer = pAd->ChannelList[index].Power;
			break;
		}
	}
	
	if (TxPwer > 31)  
	{
		//
		// R3 can't large than 36 (0x24), 31 ~ 36 used by BBP 94
		//
		R3 = 31;
		if (TxPwer <= 36)
			Bbp94 = BBPR94_DEFAULT + (UCHAR) (TxPwer - 31);		
	}
	else if (TxPwer < 0)
	{
		//
		// R3 can't less than 0, -1 ~ -6 used by BBP 94
		//	
		R3 = 0;
		if (TxPwer >= -6)
			Bbp94 = BBPR94_DEFAULT + TxPwer;
	}
	else
	{  
		// 0 ~ 31
		R3 = (ULONG) TxPwer;
	}
	

	// E2PROM setting is calibrated for maximum TX power (i.e. 100%)
	// We lower TX power here according to the percentage specified from UI
	if (pAd->PortCfg.TxPowerPercentage > 90)	   // 91 ~ 100%, treat as 100% in terms of mW
		;
	else if (pAd->PortCfg.TxPowerPercentage > 60)  // 61 ~ 90%, treat as 75% in terms of mW    
	{
		if (R3 > 2)
			R3 -= 2;
		else 
			R3 = 0;
	}
	else if (pAd->PortCfg.TxPowerPercentage > 30)  // 31 ~ 60%, treat as 50% in terms of mW
	{
		if (R3 > 6)
			R3 -= 6;
		else 
			R3 = 0;
	}
	else if (pAd->PortCfg.TxPowerPercentage > 15)  // 16 ~ 30%, treat as 25% in terms of mW
	{
		if (R3 > 12)
			R3 -= 12;
		else 
			R3 = 0;
	}
	else if (pAd->PortCfg.TxPowerPercentage > 9)   // 10 ~ 15%, treat as 12.5% in terms of mW
	{
		if (R3 > 18)
			R3 -= 18;
		else 
			R3 = 0;
	}
	else											 // 0 ~ 9 %, treat as 6.25% in terms of mW
	{
		if (R3 > 24)
			R3 -= 24;
		else 
			R3 = 0;
	}
  
	if (R3 > 31)  R3 = 31;	// Maximum value 31
      
	if (Bbp94 < 0) Bbp94 = 0; 

	R3 = R3 << 9; // shift TX power control to correct RF R3 bit position
*/
	switch (RfIcType)
	{
		case RFIC_2528:
			
			for (index = 0; index < NUM_OF_2528_CHNL; ++index)
			{
				if (channel == RF2528RegTable[index].Channel)
				{
					R3 = R3 | (RF2528RegTable[index].R3 & 0xffffc1ff); // set TX power
					R4 = (RF2528RegTable[index].R4 & (~0x0003f000)) | (RfFreqOffset << 12);
					
					// Update variables
					LatchRfRegs.Channel = channel;
					LatchRfRegs.R1 = RF2528RegTable[index].R1;
					LatchRfRegs.R2 = RF2528RegTable[index].R2;
					LatchRfRegs.R3 = R3;
					LatchRfRegs.R4 = R4;
					
					break;
				}
			}
			break;

		case RFIC_5226:
			for (index = 0; index < NUM_OF_5226_CHNL; ++index)
			{
				if (channel == RF5226RegTable[index].Channel)
				{
					R3 = R3 | (RF5226RegTable[index].R3 & 0xffffc1ff); // set TX power
					R4 = (RF5226RegTable[index].R4 & (~0x0003f000)) | (RfFreqOffset << 12);
					
					// Update variables
					LatchRfRegs.Channel = channel;
					LatchRfRegs.R1 = RF5226RegTable[index].R1;
					LatchRfRegs.R2 = RF5226RegTable[index].R2;
					LatchRfRegs.R3 = R3;
					LatchRfRegs.R4 = R4;
					
					break;
				}
			}
			break;
			
		case RFIC_5225:
		case RFIC_2527:
			for (index = 0; index < NUM_OF_5225_CHNL; ++index)
			{
				if (channel == RF5225RegTable[index].Channel)
				{
					R3 = R3 | (RF5225RegTable[index].R3 & 0xffffc1ff); // set TX power
					R4 = (RF5225RegTable[index].R4 & (~0x0003f000)) | (RfFreqOffset << 12);

					// Update variables
					LatchRfRegs.Channel = channel;
					LatchRfRegs.R1 = RF5225RegTable[index].R1;
					LatchRfRegs.R2 = RF5225RegTable[index].R2;
					LatchRfRegs.R3 = R3;
					LatchRfRegs.R4 = R4;
					
					break;
				}
			}

			RTUSBReadBBPRegister(BBP_R3, &BbpReg);
			if ((RfIcType == RFIC_5225) || (RfIcType == RFIC_2527))
				BbpReg &= 0xFE;    // b0=0 for none Smart mode
			else
				BbpReg |= 0x01;    // b0=1 for Smart mode
			RTUSBWriteBBPRegister(BBP_R3, BbpReg);
			break;
			
		default:
			DBNSLog(@"Gne ?\n");
			return (false);
			break;
	}

	if (Bbp94 != BBPR94_DEFAULT)
	{
		RTUSBWriteBBPRegister(BBP_R94, Bbp94);
		//Bbp94 = Bbp94;
	}

/*
//	if (!OPSTATUS_TEST_FLAG(fOP_STATUS_MEDIA_STATE_CONNECTED))
//	{
		if (channel <= 14)
		{
			if (BbpTuning.R17LowerUpperSelect == 0)
				RTUSBWriteBBPRegister(BBP_R17, BbpTuning.R17LowerBoundG);
			else
				RTUSBWriteBBPRegister(BBP_R17, BbpTuning.R17UpperBoundG);
		}
		else
		{
			if (BbpTuning.R17LowerUpperSelect == 0)
				RTUSBWriteBBPRegister(BBP_R17, BbpTuning.R17LowerBoundA);
			else
				RTUSBWriteBBPRegister(BBP_R17, BbpTuning.R17UpperBoundA);
		}
//	}
*/
	
	// Set RF value 1's set R3[bit2] = [0]
	RTUSBWriteRFRegister(LatchRfRegs.R1);
	RTUSBWriteRFRegister(LatchRfRegs.R2);
	RTUSBWriteRFRegister((LatchRfRegs.R3 & (~0x04)));
	RTUSBWriteRFRegister(LatchRfRegs.R4);

	// Set RF value 2's set R3[bit2] = [1]
	RTUSBWriteRFRegister(LatchRfRegs.R1);
	RTUSBWriteRFRegister(LatchRfRegs.R2);
	RTUSBWriteRFRegister((LatchRfRegs.R3 | 0x04));
	RTUSBWriteRFRegister(LatchRfRegs.R4);

	// Set RF value 3's set R3[bit2] = [0]
	RTUSBWriteRFRegister(LatchRfRegs.R1);
	RTUSBWriteRFRegister(LatchRfRegs.R2);
	RTUSBWriteRFRegister((LatchRfRegs.R3 & (~0x04)));
	RTUSBWriteRFRegister(LatchRfRegs.R4);
	
/*
	//
	// On 11A/11G, We should delay and wait RF/BBP to be stable
	// and the appropriate time should be 10 micro seconds 
	// It's not recommend to use NdisStallExecution on PASSIVE_LEVEL
	// use NdisMSleep to dealy 10 microsecond instead.
	//
	RTMPusecDelay(10);
*/
	
/*
	DBNSLog(@"AsicSwitchChannel(RF=%d) to #%d, TXPwr=%d%%, R1=0x%08x, R2=0x%08x, R3=0x%08x, R4=0x%08x\n",
		RfIcType, 
		LatchRfRegs.Channel, 
		(R3 & 0x00003e00) >> 9,
		LatchRfRegs.R1, 
		LatchRfRegs.R2, 
		LatchRfRegs.R3, 
		LatchRfRegs.R4);
*/

    _channel = channel;

	return (true);

/*v
	ULONG R3;
	UCHAR index;
    
    //set tx power to 100%
    R3 = 31;
    
	R3 = R3 << 9; // shift TX power control to correct RF R3 bit position
	switch (RfType)
	{
		case RFIC_2522:
			for (index = 0; index < NUM_OF_2522_CHNL; index++)
			{
				if (channel == RF2522RegTable[index].Channel)
				{
					R3 = R3 | RF2522RegTable[index].R3; // set TX power
					RTUSBWriteRFRegister(RF2522RegTable[index].R1);
					RTUSBWriteRFRegister(RF2522RegTable[index].R2);
					RTUSBWriteRFRegister(R3);
					break;
				}
			}
			break;
            
		case RFIC_2523:
			for (index = 0; index < NUM_OF_2523_CHNL; index++)
			{
				if (channel == RF2523RegTable[index].Channel)
				{
					R3 = R3 | RF2523RegTable[index].R3; // set TX power
					RTUSBWriteRFRegister(RF2523RegTable[index].R1);
					RTUSBWriteRFRegister(RF2523RegTable[index].R2);
					RTUSBWriteRFRegister(R3);
					RTUSBWriteRFRegister(RF2523RegTable[index].R4);
					//pAd->PortCfg.LatchRfRegs.Channel = Channel;
					//pAd->PortCfg.LatchRfRegs.R1 = RF2523RegTable[index].R1;
					//pAd->PortCfg.LatchRfRegs.R2 = RF2523RegTable[index].R2;
					//pAd->PortCfg.LatchRfRegs.R3 = R3;
					//pAd->PortCfg.LatchRfRegs.R4 = RF2523RegTable[index].R4;
					break;
				}
			}
			break;
            
		case RFIC_2524:
			for (index = 0; index < NUM_OF_2524_CHNL; index++)
			{
				if (channel == RF2524RegTable[index].Channel)
				{
					R3 = R3 | RF2524RegTable[index].R3; // set TX power
					RTUSBWriteRFRegister(RF2524RegTable[index].R1);
					RTUSBWriteRFRegister(RF2524RegTable[index].R2);
					RTUSBWriteRFRegister(R3);
					RTUSBWriteRFRegister(RF2524RegTable[index].R4);
					//pAd->PortCfg.LatchRfRegs.Channel = Channel;
					//pAd->PortCfg.LatchRfRegs.R1 = RF2524RegTable[index].R1;
					//pAd->PortCfg.LatchRfRegs.R2 = RF2524RegTable[index].R2;
					//pAd->PortCfg.LatchRfRegs.R3 = R3;
					//pAd->PortCfg.LatchRfRegs.R4 = RF2524RegTable[index].R4;
					break;
				}
			}
			break;
			
		case RFIC_2525:
			for (index = 0; index < NUM_OF_2525_CHNL; index++)
			{
				if (channel == RF2525RegTable[index].Channel)
				{
					R3 = R3 | RF2525RegTable[index].R3; // set TX power
					RTUSBWriteRFRegister(RF2525RegTable[index].R1);
                    
					RTUSBWriteRFRegister(RF2525RegTable[index].R2);
                    
					RTUSBWriteRFRegister(R3);
                    
					RTUSBWriteRFRegister(RF2525RegTable[index].R4);
                    
					//pAd->PortCfg.LatchRfRegs.Channel = Channel;
					//pAd->PortCfg.LatchRfRegs.R1 = RF2525RegTable[index].R1;
					//pAd->PortCfg.LatchRfRegs.R2 = RF2525RegTable[index].R2;
					//pAd->PortCfg.LatchRfRegs.R3 = R3;
					//pAd->PortCfg.LatchRfRegs.R4 = RF2525RegTable[index].R4;
					break;
				}
			}
			break;
			
		case RFIC_2525E:
			for (index = 0; index < NUM_OF_2525E_CHNL; index++)
			{
				if (channel == RF2525eRegTable[index].Channel)
				{
					RTUSBWriteRFRegister(RF2525eRegTable[index].TempR2);
					RTUSBWriteRFRegister(RF2525eRegTable[index].R4);
					R3 = R3 | RF2525eRegTable[index].R3; // set TX power
					RTUSBWriteRFRegister(RF2525eRegTable[index].R1);
					RTUSBWriteRFRegister(RF2525eRegTable[index].R2);
					RTUSBWriteRFRegister(R3);
					RTUSBWriteRFRegister(RF2525eRegTable[index].R4);
					//pAd->PortCfg.LatchRfRegs.Channel = Channel;
					//pAd->PortCfg.LatchRfRegs.R1 = RF2525eRegTable[index].R1;
					//pAd->PortCfg.LatchRfRegs.R2 = RF2525eRegTable[index].R2;
					//pAd->PortCfg.LatchRfRegs.R3 = R3;
					//pAd->PortCfg.LatchRfRegs.R4 = RF2525eRegTable[index].R4;
					break;
				}
			}
			break;
			
		case RFIC_5222:
			for (index = 0; index < NUM_OF_5222_CHNL; index++)
			{
				if (channel == RF5222RegTable[index].Channel)
				{
					R3 = R3 | RF5222RegTable[index].R3; // set TX power
					RTUSBWriteRFRegister(RF5222RegTable[index].R1);
					RTUSBWriteRFRegister(RF5222RegTable[index].R2);
					RTUSBWriteRFRegister(R3);
					RTUSBWriteRFRegister(RF5222RegTable[index].R4);
					//pAd->PortCfg.LatchRfRegs.Channel = Channel;
					//pAd->PortCfg.LatchRfRegs.R1 = RF5222RegTable[index].R1;
					//pAd->PortCfg.LatchRfRegs.R2 = RF5222RegTable[index].R2;
					//pAd->PortCfg.LatchRfRegs.R3 = R3;
					//pAd->PortCfg.LatchRfRegs.R4 = RF5222RegTable[index].R4;
					break;
				}
			}
			break;
            
		default:
			return false;
	}
    _channel = channel;
    DBNSLog(@"RT73Jack::Switched to channel %d", channel);
    //lock channel seems to be an empty function
    return true;
	
v*/
}

bool RT73Jack::getAllowedChannels(UInt16* channels) {
    if (!_devicePresent) return false;
    if (!_deviceInit) return false;
    
    * channels = 0xFFFF;
    
    return true;
}
bool    RT73Jack::startCapture(UInt16 channel) {
//	DBNSLog(@"Start capture : ");
	if (NICInitialized) {
//		DBNSLog(@"Done.\n");
		setChannel(channel);
		RTMPSetLED(LED_LNK_ON);
		// RTUSBWriteMACRegister(TXRX_CSR2, 0x004e/*0x0046*/); //enable monitor mode?
//		RTUSBWriteMACRegister(TXRX_CSR0, 0x024eb032);    // enable RX of MAC block, Staion not drop control frame, Station not drop not to me unicast frame
		RTUSBWriteMACRegister(TXRX_CSR0, 0x0046b032);    // enable RX of MAC block, Staion not drop control frame, Station not drop not to me unicast frame
		return true;
	}
	else {
//		DBNSLog(@"NIC not initialized. Canceled.\n");
		return false;
	}
}



bool RT73Jack::stopCapture(){
//	DBNSLog(@"Stop capture : ");
	if (NICInitialized) {
//		DBNSLog(@"Done.\n");
		RTMPSetLED(LED_LNK_OFF);
		RTUSBWriteMACRegister(TXRX_CSR0, 0x025FB032);
		// RTUSBWriteMACRegister(TXRX_CSR2, BAD_ADDRESS); //disable rx
		return true;
	}
	else {
//		DBNSLog(@"NIC not initialized. Canceled.\n");
		return false;
	}
}


bool RT73Jack::_massagePacket(void *inBuf, void *outBuf, UInt16 len) {
/*  pr0gg3d: A notice... {len} field that is passed
    is rounded at power of two. Don't use this for
        packet length.
*/
    unsigned char* pData = (unsigned char *)inBuf;
    KFrame *pFrame = (KFrame *)outBuf;
    PRXD_STRUC pRxD = (PRXD_STRUC)pData;

    bzero(outBuf, sizeof(KFrame));
    
    if (len < sizeof(RXD_STRUC)) {
        DBNSLog(@"WTF, packet len %d shorter than footer %lu!", len, sizeof(RXD_STRUC));
        return false;
    }
    
    // flash the led for fun
    //RTMPSetLED(LED_ACT_ON);
    
    // We needs to do some magic here, for endiannes
#ifdef __BIG_ENDIAN__
    RTMPDescriptorEndianChange((unsigned char *)pData, TYPE_RXD);
#endif
    
    // This is real length of packet (descriptor not included)
    pFrame->ctrl.len = pRxD->DataByteCnt;
    
    // this is probablty not the most efficient way to do this
    pFrame->ctrl.signal = pRxD->PlcpRssi;    //rssi is the signal level
    
    // Copy entire packet
    memcpy(pFrame->data, pData + sizeof(RXD_STRUC), pFrame->ctrl.len);
    
// if (len > 24) {
//      DBNSLog(@"Normal packet %d", len);
//  }
//  else {
//      DBNSLog(@"RT73Jack::Really short packet! %d", len);
//      return false;
//  }

    // flash LED off
	//RTMPSetLED(LED_ACT_OFF);

	return true;
}
void    RT73Jack::RTMPDescriptorEndianChange(unsigned char *  pData, unsigned long DescriptorType) {
    int size = (DescriptorType == TYPE_TXD) ? TXD_SIZE : RXD_SIZE;
    int i;
    for (i=1; i<size/4; ++i) {
        /*
         * Handle IV and EIV with little endian
         */
        if (DescriptorType == TYPE_TXD) {
             /* Skip Word 3 IV and Word 4 EIV of TXD */
            if (i==3||i==4)  
                continue; 
        } else {
             /* Skip Word 2 IV and Word 3 EIV of RXD */
            if (i==2||i==3)  
                continue; 
        }
        *((unsigned long *)(pData + i*4)) = SWAP32(*((unsigned long *)(pData + i*4))); 
    }
    *(unsigned long *)pData = SWAP32(*(unsigned long *)pData);  // Word 0; this must be swapped last
}
void    RT73Jack::WriteBackToDescriptor(unsigned char *Dest, unsigned char *Src, bool DoEncrypt, unsigned long DescriptorType) {
        unsigned long *p1, *p2;
        unsigned char i;
        int size = (DescriptorType == TYPE_TXD) ? TXD_SIZE : RXD_SIZE;

        p1 = ((unsigned long *)Dest) + 1;
        p2 = ((unsigned long *)Src) + 1;
        for (i = 1; i < size/4 ; ++i)
                *p1++ = *p2++;
        *(unsigned long *)Dest = *(unsigned long *)Src;         // Word 0; this must be written back last
}

void    RT73Jack::RTUSBWriteTxDescriptor(
        void *pptxd,
        unsigned char CipherAlg,
        unsigned char KeyTable,
        unsigned char KeyIdx,
        bool Ack,
        bool Fragment,
        bool InsTimestamp,
        unsigned char RetryMode,
        unsigned char Ifs,
        unsigned int Rate,
        unsigned long Length,
        unsigned char QueIdx,
        unsigned char PID,
        bool bAfterRTSCTS) {

    unsigned int Residual;
    TXD_STRUC * pSourceTxD = (TXD_STRUC *)pptxd;
    TXD_STRUC * pTxD = pSourceTxD; 

    pTxD->HostQId       = QueIdx;
    pTxD->MoreFrag      = Fragment;
    pTxD->ACK           = Ack;
    pTxD->Timestamp     = InsTimestamp;
    pTxD->RetryMd       = RetryMode;
    pTxD->Ofdm          = (Rate < RATE_FIRST_OFDM_RATE)? 0:1;
    pTxD->IFS           = Ifs;
    pTxD->PktId         = PID;
    pTxD->Drop          = 1;   // 1:valid, 0:drop
    pTxD->HwSeq         = 1;    // (QueIdx == QID_MGMT)? 1:0; 
    pTxD->BbpTxPower    = DEFAULT_BBP_TX_POWER; // TODO: to be modified
    pTxD->DataByteCnt   = Length;
/*
        RTMPCckBbpTuning(pAd, Rate);
*/
    // fill encryption related information, if required
    pTxD->CipherAlg   = CipherAlg;
    pTxD->Cwmin = CW_MIN_IN_BITS;
    pTxD->Cwmax = CW_MAX_IN_BITS;
    pTxD->Aifsn = 2;
    
    // fill up PLCP SIGNAL field
    pTxD->PlcpSignal = RT73_RateIdToPlcpSignal[Rate];
    // fill up PLCP SERVICE field, not used for OFDM rates
    pTxD->PlcpService = 4; // Service;
    
    // fill up PLCP LENGTH_LOW and LENGTH_HIGH fields
    Length += LENGTH_CRC;   // CRC length
    
    if (Rate < RATE_FIRST_OFDM_RATE) {
    // 11b - RATE_1, RATE_2, RATE_5_5, RATE_11
        if ((Rate == RATE_1) || ( Rate == RATE_2)) {
                Length = Length * 8 / (Rate + 1);
        } else {
            Residual = ((Length * 16) % (11 * (1 + Rate - RATE_5_5)));
            Length = Length * 16 / (11 * (1 + Rate - RATE_5_5));
            if (Residual != 0) {
                    ++Length;
            }
            if ((Residual <= (3 * (1 + Rate - RATE_5_5))) && (Residual != 0)) {
                if (Rate == RATE_11)                    // Only 11Mbps require length extension bit
                    pTxD->PlcpService |= 0x80; // 11b's PLCP Length extension bit
            }
        }
        pTxD->PlcpLengthHigh = Length >> 8; // 256;
        pTxD->PlcpLengthLow = Length % LAST_BIT;
    } else {
        // OFDM - RATE_6, RATE_9, RATE_12, RATE_18, RATE_24, RATE_36, RATE_48, RATE_54
        pTxD->PlcpLengthHigh = Length >> 6; // 64;      // high 6-bit of total byte count
        pTxD->PlcpLengthLow = Length % 64;       // low 6-bit of total byte count
    }
    pTxD->Burst  = Fragment;
    pTxD->Burst2 = pTxD->Burst;
}

int RT73Jack::WriteTxDescriptor(void* theFrame, UInt16 length, UInt8 rate){
    memset(theFrame, 0, sizeof(TXD_STRUC));
    RTUSBWriteTxDescriptor(
        (TXD_STRUC *)theFrame,
        CIPHER_NONE,
        0,
        0,
        0,
        0,
        0,
        1,
        1,
        rate,
        length,
        0,
        0,
        0
    );
#ifdef __BIG_ENDIAN__
    RTMPDescriptorEndianChange((unsigned char *)theFrame, TYPE_TXD);
#endif
    return sizeof(TXD_STRUC);
}


bool RT73Jack::sendKFrame(KFrame *frame) {
    UInt8 *data = frame->data;
    int size = frame->ctrl.len;
    UInt8 aData[MAX_FRAME_BYTES];
    unsigned int descriptorLength;
//    DBNSLog(@"sendFrame %d", size);
//    dumpFrame(data, size);
    descriptorLength = WriteTxDescriptor(aData, size, frame->ctrl.tx_rate);
    memcpy(aData+descriptorLength, data, size);
    //send the frame
//	dumpFrame(aData, size + descriptorLength);
	if (_sendFrame(aData, size + descriptorLength) != kIOReturnSuccess)
        return NO;
    return YES;
}
IOReturn RT73Jack::_sendFrame(UInt8* data, IOByteCount size) {
    UInt32      numBytes;
    IOReturn    kr;
  
    if (!_devicePresent) return kIOReturnError;
    
    if (_interface == NULL) {
        DBNSLog(@"RT73Jack::_sendFrame called with NULL interface this is prohibited!\n");
        return kIOReturnError;
    }

    _lockDevice();

    memcpy(&_outputBuffer, data, size);
    
    numBytes =  align64(size);

    kr = (*_interface)->WritePipe(_interface, kOutPipe, &_outputBuffer, numBytes);

    _unlockDevice();
        
    return kr;
}

RT73Jack::RT73Jack() {
}

RT73Jack::~RT73Jack() {
    /*
    stopRun();
    _interface = NULL;
    
    pthread_mutex_destroy(&_wait_mutex);
    pthread_cond_destroy(&_wait_cond);
    pthread_mutex_destroy(&_recv_mutex);
    pthread_cond_destroy(&_recv_cond);
     */
}

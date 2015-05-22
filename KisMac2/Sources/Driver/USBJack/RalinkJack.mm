/*
 *  RalinkJack.mm
 *  KisMAC
 *
 *  Created by Geoffrey Kruse on 5/28/06.
 *  Copyright 2006 __MyCompanyName__. All rights reserved.
 *
 */

#include "RalinkJack.h"
#include "rt2570.h"

#define align64(a)      (((a)+63)&~63)

unsigned char   RT2570_RateIdToPlcpSignal[12] = {
    // see BBP spec
    0,  /* RATE_1   */
    1,  /* RATE_2   */
    2,  /* RATE_5_5 */
    3,  /* RATE_11  */
    // see IEEE802.11a-1999 p.14
    11, /* RATE_6   */
    15, /* RATE_9   */
    10, /* RATE_12  */
    14, /* RATE_18  */
    9,  /* RATE_24  */
    13, /* RATE_36  */
    8,  /* RATE_48  */
    12  /* RATE_54  */
};

char *RalinkJack::getPlistFile() 
{
    return (char*)"UsbVendorsRT2570";
}

IOReturn RalinkJack::_init() {
    unsigned long			Index = 0;
	unsigned short			temp = 0;
	unsigned char			Value = 0xff;
	unsigned int			i = 0;
    IOReturn                ret = kIOReturnSuccess;
    
    if(!_attachDevice()){
        DBNSLog(@"Device could not be opened");
        return kIOReturnNoDevice;
    }
    
	DBNSLog(@"--> NICInitializeAsic");

	do
	{
        
		RTUSB_VendorRequest(kUSBOut,
                            0x1,
                            0x4,
                            0x1,
                            NULL,
                            0,
                            TRUE);
        
		RTUSBSingleWrite(0x308, 0xf0); //asked by MAX
            
        // Disable RX at first beginning. Before BulkInReceive, we will enable RX.
        RTUSBWriteMACRegister(TXRX_CSR2, 1);
        RTUSBWriteMACRegister(MAC_CSR13, 0x1111); //requested by Jerry
        RTUSBWriteMACRegister(MAC_CSR14, 0x1E11);
        RTUSBWriteMACRegister(MAC_CSR1, 3); // reset MAC state machine, requested by Kevin 2003-2-11
        RTUSBWriteMACRegister(MAC_CSR1, 0); // reset MAC state machine, requested by Kevin 2003-2-11
        RTUSBWriteMACRegister(TXRX_CSR5, 0x8C8D);
        RTUSBWriteMACRegister(TXRX_CSR6, 0x8B8A);
        RTUSBWriteMACRegister(TXRX_CSR7, 0x8687);
        RTUSBWriteMACRegister(TXRX_CSR8, 0x0085);
        RTUSBWriteMACRegister(TXRX_CSR21, 0xe78f);
        RTUSBWriteMACRegister(MAC_CSR9, 0xFF1D);
                
        i = 0;
        //check and see if asic has powered up
        RTUSBReadMACRegister(MAC_CSR17, &temp);
        while (((temp & 0x01e0 ) != 0x01e0) && (i < 50))
        {
            sleep(1);
            RTUSBReadMACRegister(MAC_CSR17, &temp);
                    
            ++i;
        }
        if (i == 50)
        {
/*                    if (RTUSB_ResetDevice() == FALSE)
                    {
                        //RTMP_SET_FLAG( fRTMP_ADAPTER_REMOVE_IN_PROGRESS);
                        DBNSLog(@"<== NICInitializeAsic ERROR\n");
                        return;
                    }
                    else
                        continue;
                    */
        }
        
        //lets mess with the leds to verify we have control
        RTUSBWriteMACRegister(MAC_CSR20, 0x0000);        //put led under software control
        RTUSBWriteMACRegister(MAC_CSR1, 4);              //host is ready to work
        
        //this is how we dertermine chip type?
        RTUSBReadMACRegister(MAC_CSR0, &temp);             //read the asic version number
        DBNSLog(@"Found Ralink Asic Version %d", temp);
        if ( temp >= 3) {
            RTUSBReadMACRegister (PHY_CSR2, &temp);
            RTUSBWriteMACRegister(PHY_CSR2, temp & 0xFFFD);		   
        } else {
            DBNSLog(@"LNA 3 mode\n");
            RTUSBWriteMACRegister(PHY_CSR2, 0x3002); // LNA 3 mode
        }
        
        //power save stuff
        RTUSBWriteMACRegister(MAC_CSR11, 2);
        RTUSBWriteMACRegister(MAC_CSR22, 0x53);
        RTUSBWriteMACRegister(MAC_CSR15, 0x01ee);
        RTUSBWriteMACRegister(MAC_CSR16, 0);
        RTUSBWriteMACRegister(MAC_CSR8,  0x0780);//steven:limit the maximum frame length
            
        RTUSBReadMACRegister(TXRX_CSR0, &temp);
        temp &= 0xe007;
        temp |= ((LENGTH_802_11 << 3) | (0x000f << 9));
        RTUSBWriteMACRegister(TXRX_CSR0, temp);
                    
        RTUSBWriteMACRegister(TXRX_CSR19, 0);
        RTUSBWriteMACRegister(MAC_CSR18, 0x5a);
                    
        //set RF_LE to low when standby
        RTUSBReadMACRegister(PHY_CSR4, &temp);
        RTUSBWriteMACRegister(PHY_CSR4, temp | 1);
        NdisMSleep(100);//wait for PLL to become stable
                  
        i = 0;
        do
        {
            ret = RTUSBReadBBPRegister(BBP_Version, &Value);
            if (Value == 0) {
                DBNSLog(@"This is probably an rt73 chipset, please report your vendor and product id to http://trac.kismac-ng.org");
                return ret;
            }
            DBNSLog(@"Read BBP_Version Value = %d\n", Value);
            ++i;
        } while (((Value == 0xff) || (Value == 0x00)) && (i < 50));
        if (i < 50)//BBP ready
        {
            break;
        }
                    /*
        else
        {
            if ( RTUSB_ResetDevice() == FALSE)
            {
                RTMP_SET_FLAG( fRTMP_ADAPTER_REMOVE_IN_PROGRESS);
                return;
            }
        }*/
	}while (1);
    
	// Initialize BBP register to default value
	for (Index = 0; Index < NUM_BBP_REG_PARMS; ++Index)
	{
		i = 0;
		do
		{
			RTUSBReadMACRegister(PHY_CSR8, &temp);
			if (!(temp & BUSY))
				break;
			++i;
		}
		while (i < RETRY_LIMIT);
		
		RTUSBWriteMACRegister(PHY_CSR7, RT2570BBPRegTable[Index]);
    }
    
    
	// Initialize RF register to default value
	//AsicSwitchChannel(PortCfg.Channel);
	//AsicLockChannel(PortCfg.Channel);
    
	//RTUSBMultiRead(STA_CSR0, buffer, 22);
	DBNSLog(@"<-- NICInitializeAsic\n");
    
    NICReadEEPROMParameters();
    NICInitAsicFromEEPROM();
    currentRate = RATE_11;
    return kIOReturnSuccess;
}

IOReturn	RalinkJack::RTUSB_VendorRequest(UInt8 direction,
                        UInt8 bRequest, 
                        UInt16 wValue, 
                        UInt16 wIndex, 
                        void *pData,
                        UInt16 wLength,
                        bool swap) {
    
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

IOReturn RalinkJack::RTUSBSingleRead(unsigned short Offset,
                                     unsigned short * pValue)
{
	IOReturn	Status;
    
	Status = RTUSB_VendorRequest(kUSBIn,
                                 0x3,
                                 0,
                                 Offset,
                                 pValue,
                                 2,
                                 TRUE);
	return Status;
}

IOReturn	RalinkJack::RTUSBSingleWrite(unsigned short	Offset,
                                         unsigned short Value)
{
	IOReturn	Status;
	
	Status = RTUSB_VendorRequest(
                                 kUSBOut,
                                 0x2,
                                 Value,
                                 Offset,
                                 NULL,
                                 0,
                                 TRUE);	
	return Status;
}

IOReturn RalinkJack::RTUSBWriteMACRegister(unsigned short Offset,
                                  unsigned short Value)
{
	IOReturn Status;
	if (Offset == TXRX_CSR2)
        DBNSLog(@" !!!!!set Rx control = %x\n", Value);
    
	Status = RTUSB_VendorRequest(kUSBOut,
                                 0x2,
                                 Value,
                                 Offset + 0x400,
                                 NULL,
                                 0,
                                 TRUE);	
	return Status;
}

IOReturn	RalinkJack::RTUSBReadMACRegister(unsigned short Offset,
                                             unsigned short * pValue)
{
	IOReturn Status;
	
	Status = RTUSB_VendorRequest(kUSBIn,
                                 0x3,
                                 0,
                                 Offset + 0x400,
                                 pValue,
                                 2,
                                 TRUE);	
	return Status;
}

IOReturn	RalinkJack::RTUSBReadBBPRegister(unsigned char Id,
                                 unsigned char * pValue)
{
	PHY_CSR7_STRUC	PhyCsr7;
	unsigned short			temp;
	unsigned int			i = 0;
    IOReturn ret;
    
	PhyCsr7.value				= 0;
	PhyCsr7.field.WriteControl	= 1;
	PhyCsr7.field.RegID 		= Id;
	ret = RTUSBWriteMACRegister(PHY_CSR7, PhyCsr7.value);
    
    if (ret!= kIOReturnSuccess) {
        DBNSLog(@"Error Reading the BBP Register.");
        return ret;
    }
	
	do
	{
		RTUSBReadMACRegister(PHY_CSR8, &temp);
		if (!(temp & BUSY))
			break;
		++i;
	}
	while (i < RETRY_LIMIT);
    
	if (i == RETRY_LIMIT)
	{
		DBNSLog(@"Retry count exhausted or device removed!!!\n");
		return kIOReturnNotResponding;
	}
    
	ret = RTUSBReadMACRegister(PHY_CSR7, (unsigned short*)&PhyCsr7);
	*pValue = (unsigned char)PhyCsr7.field.Data;
	
	return ret;
}

IOReturn	RalinkJack::RTUSBWriteBBPRegister(unsigned char Id,
                                  unsigned char Value)
{
	PHY_CSR7_STRUC	PhyCsr7;
	unsigned short	temp = 0;
	unsigned int	i = 0;

	do
	{
		RTUSBReadMACRegister(PHY_CSR8, &temp);
		if (!(temp & BUSY))
			break;
		++i;
	}
	while (i < RETRY_LIMIT);
    
	if (i == RETRY_LIMIT)
	{
		DBNSLog(@"Retry count exhausted or device removed!!!\n");
		return kIOReturnNoDevice;
	}
    
	PhyCsr7.value				= 0;
	PhyCsr7.field.WriteControl	= 0;
	PhyCsr7.field.RegID 		= Id;
	PhyCsr7.field.Data			= Value;
	RTUSBWriteMACRegister(PHY_CSR7, PhyCsr7.value);
	//pAdapter->PortCfg.BbpWriteLatch[Id] = Value;
	
	return kIOReturnSuccess;
}

IOReturn	RalinkJack::RTUSBWriteRFRegister(unsigned long Value)
{
	PHY_CSR10_STRUC	PhyCsr10;
	unsigned int			i = 0;
    
	do
	{
		RTUSBReadMACRegister(PHY_CSR10, (unsigned short*)&PhyCsr10);
		if (!(PhyCsr10.field.Busy))
			break;
		++i;
	}
	while (i < RETRY_LIMIT);
    
	if (i == RETRY_LIMIT)
	{
		DBNSLog(@"Retry count exhausted or device removed!!!\n");
		return kIOReturnNoDevice;
	}
    
	RTUSBWriteMACRegister(PHY_CSR9, (USHORT)(Value & 0x0000ffff));
	
	PhyCsr10.value = (unsigned short)(Value >> 16);
	RTUSBWriteMACRegister(PHY_CSR10, PhyCsr10.value);
	
	return kIOReturnSuccess;
}

IOReturn NICLoadFirmware()
{
	IOReturn				Status = kIOReturnSuccess;
	//mm_segment_t			orgfs;
    
	
	DBNSLog(@"--> NICLoadFirmware\n");
/*	//pAd->FirmwareVersion = (FIRMWARE_MAJOR_VERSION << 8) + FIRMWARE_MINOR_VERSION; //default version.
    
	src = RT2573_IMAGE_FILE_NAME;
    
	// Save uid and gid used for filesystem access.
	// Set user and group to 0 (root)	
	//orgfsuid = current->fsuid;
	//orgfsgid = current->fsgid;
	//current->fsuid=current->fsgid = 0;
	//orgfs = get_fs();
	//set_fs(KERNEL_DS);
    
	pFirmwareImage = kmalloc(MAX_FIRMWARE_IMAGE_SIZE, MEM_ALLOC_FLAG);
	if (pFirmwareImage == NULL) 
	{
		DBGPRINT(RT_DEBUG_ERROR, "NICLoadFirmware-Memory allocate fail\n");
		Status = NDIS_STATUS_FAILURE;
		goto out;
	}
   
	if (src && *src) 
	{
		srcf = filp_open(src, O_RDONLY, 0);
		if (IS_ERR(srcf)) 
		{
			Status = NDIS_STATUS_FAILURE;
			DBGPRINT(RT_DEBUG_ERROR, "--> Error %ld opening %s\n", -PTR_ERR(srcf),src);    
		}
		else 
		{
			// The object must have a read method
			if (srcf->f_op && srcf->f_op->read) 
			{
				memset(pFirmwareImage, 0x00, MAX_FIRMWARE_IMAGE_SIZE);
                
				FileLength = srcf->f_op->read(srcf, pFirmwareImage, MAX_FIRMWARE_IMAGE_SIZE, &srcf->f_pos);
				if (FileLength != MAX_FIRMWARE_IMAGE_SIZE)
				{
					DBGPRINT_ERR("NICLoadFirmware: error file length (=%d) in rt73.bin\n",FileLength);
					Status = NDIS_STATUS_FAILURE;
				}
				else
				{  //FileLength == MAX_FIRMWARE_IMAGE_SIZE
					PUCHAR ptr = pFirmwareImage;
					USHORT crc = 0;
					
					for (i=0; i<(MAX_FIRMWARE_IMAGE_SIZE-2); i++, ptr++)
						crc = ByteCRC16(*ptr, crc);
					crc = ByteCRC16(0x00, crc);
					crc = ByteCRC16(0x00, crc);
					
					if ((pFirmwareImage[MAX_FIRMWARE_IMAGE_SIZE-2] != (UCHAR)(crc>>8)) ||
						(pFirmwareImage[MAX_FIRMWARE_IMAGE_SIZE-1] != (UCHAR)(crc)))
					{
						DBGPRINT_ERR("NICLoadFirmware: CRC = 0x%02x 0x%02x error, should be 0x%02x 0x%02x\n",
                                     pFirmwareImage[MAX_FIRMWARE_IMAGE_SIZE-2], pFirmwareImage[MAX_FIRMWARE_IMAGE_SIZE-1],
                                     (UCHAR)(crc>>8), (UCHAR)(crc) );
                        
						if (retval)
						{
							DBGPRINT(RT_DEBUG_ERROR, "--> Error %d closing %s\n", -retval, src);
						}
                        
						Status = NDIS_STATUS_FAILURE;
					}
					else
					{
                        
						if ((pAd->FirmwareVersion) > ((pFirmwareImage[MAX_FIRMWARE_IMAGE_SIZE-4] << 8) + pFirmwareImage[MAX_FIRMWARE_IMAGE_SIZE-3]))
						{
							DBGPRINT_ERR("NICLoadFirmware: Ver=%d.%d, local Ver=%d.%d, used FirmwareImage talbe instead\n",
                                         pFirmwareImage[MAX_FIRMWARE_IMAGE_SIZE-4], pFirmwareImage[MAX_FIRMWARE_IMAGE_SIZE-3],
                                         FIRMWARE_MAJOR_VERSION, FIRMWARE_MINOR_VERSION);
                            
							Status = NDIS_STATUS_FAILURE;
						}
						else
						{
							pAd->FirmwareVersion = (pFirmwareImage[MAX_FIRMWARE_IMAGE_SIZE-4] << 8) + pFirmwareImage[MAX_FIRMWARE_IMAGE_SIZE-3];
							DBGPRINT(RT_DEBUG_TRACE,"NICLoadFirmware OK: CRC = 0x%04x ver=%d.%d\n", crc,
                                     pFirmwareImage[MAX_FIRMWARE_IMAGE_SIZE-4], pFirmwareImage[MAX_FIRMWARE_IMAGE_SIZE-3]);
						}
                        
					}
				}
			}
			else
			{
				Status = NDIS_STATUS_FAILURE;
				DBGPRINT(RT_DEBUG_ERROR, "--> %s does not have a write method\n", src);
			}
			
			retval = filp_close(srcf, NULL);			
			if (retval)
			{
				Status = NDIS_STATUS_FAILURE;
				DBGPRINT(RT_DEBUG_ERROR, "--> Error %d closing %s\n", -retval, src);
			}
		}
	}
	else
	{
		Status = NDIS_STATUS_FAILURE;
		DBGPRINT(RT_DEBUG_ERROR, "Error src not available\n");
	}
    
    
	if (Status != NDIS_STATUS_SUCCESS)
	{	
		FileLength = FIRMAREIMAGE_LENGTH;
		memset(pFirmwareImage, 0x00, FileLength);
		NdisMoveMemory(pFirmwareImage, &FirmwareImage[0], FileLength);
		Status = NDIS_STATUS_SUCCESS; // change to success
		
		DBGPRINT(RT_DEBUG_ERROR, "NICLoadFirmware failed, used local Firmware(v %d.%d) instead\n", 
                 FIRMWARE_MAJOR_VERSION, FIRMWARE_MINOR_VERSION);		
	}
    
	// select 8051 program bank; write entire firmware image
	for (i = 0; i < FileLength; i = i + 4)
	{
		ret = RTUSBMultiWrite(pAd, FIRMWARE_IMAGE_BASE + i, pFirmwareImage + i, 4);
        
		if (ret < 0)
		{
			Status = NDIS_STATUS_FAILURE;
			break;
		}
	}
    
    
out:	
        if (pFirmwareImage != NULL)
            kfree(pFirmwareImage);
    
	set_fs(orgfs);
	current->fsuid = orgfsuid;
	current->fsgid = orgfsgid;
    
	if (Status == NDIS_STATUS_SUCCESS)
	{
		RTUSBFirmwareRun(pAd);
		
		//
		// Send LED command to Firmare after RTUSBFirmwareRun;
		//
		RTMPSetLED(pAd, LED_LINK_DOWN);
        
	}		
    
	DBGPRINT(RT_DEBUG_TRACE,"<-- NICLoadFirmware (src=%s)\n", src);  
	
    */
	return Status;
}


IOReturn	RalinkJack::RTUSBReadEEPROM(unsigned short Offset,
                                        unsigned char * pData,
                                        unsigned short length)
{
	IOReturn	Status = kIOReturnSuccess;
	
	Status = RTUSB_VendorRequest(kUSBIn,
                                 0x9,
                                 0,
                                 Offset,
                                 pData,
                                 length,
                                 TRUE);
	return Status;
}


void	RalinkJack::NICReadEEPROMParameters()
{
	USHORT		i = 0;
	int			value = 0;
    unsigned char PermanentAddress[ETH_LENGTH_OF_ADDRESS] = {0, 0, 0, 0, 0, 0};
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
    char ChannelTxPower[14] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	RTUSBReadEEPROM(EEPROM_TX_PWR_OFFSET, (unsigned char *)ChannelTxPower, 2 * NUM_EEPROM_TX_PARMS);
	for (i = 0; i < 2 * NUM_EEPROM_TX_PARMS; ++i)
	{
        
		if (ChannelTxPower[i] > 31)
			ChannelTxPower[i] = 24;
		DBNSLog(@"Tx power for channel %d : %0x\n", i+1, ChannelTxPower[i]);
	}
        
     /*   
    
	// Read Tx TSSI reference value, OK to reuse Power data structure
	RTUSBReadEEPROM(EEPROM_TSSI_REF_OFFSET, PortCfg.ChannelTssiRef, 2 * NUM_EEPROM_TX_PARMS);
	for (i = 0; i < 2 * NUM_EEPROM_TX_PARMS; ++i)
	{
		if (PortCfg.ChannelTssiRef[i] == 0xff)
			PortCfg.bAutoTxAgc = FALSE;					
		DBNSLog(@"TSSI reference for channel %d : %0x\n", i, PortCfg.ChannelTssiRef[i]);
	}
	
	// Tx Tssi delta offset 0x24
	RTUSBReadEEPROM(EEPROM_TSSI_DELTA_OFFSET, (unsigned char)(&(Power.word)), 2);
	PortCfg.ChannelTssiDelta = Power.field.Byte0;
*/	
	//CountryRegion byte offset = 0x35
	value = EEPROMDefaultValue[2] >> 8;
	DBNSLog(@"  CountryRegion= 0x%x \n",value);
/*
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
*/    
	RTUSBReadEEPROM(EEPROM_BBP_TUNING_OFFSET, (unsigned char *)(EEPROMBBPTuningParameters), 2 * NUM_EEPROM_BBP_TUNING_PARMS);
	if ((EEPROMBBPTuningParameters[0] != 0xffff) && (EEPROMBBPTuningParameters[0] != 0))
	{
		BBPTuningParameters.BBPTuningThreshold = (unsigned char)((EEPROMBBPTuningParameters[0]) & 0xff);
		DBNSLog(@"BBPTuningThreshold = %d\n", BBPTuningParameters.BBPTuningThreshold);
	}
	if ((EEPROMBBPTuningParameters[1] != 0xffff) && (EEPROMBBPTuningParameters[1] != 0))
	{
		BBPTuningParameters.R24LowerValue = (unsigned char)(EEPROMBBPTuningParameters[1] & 0xff);
		BBPTuningParameters.R24HigherValue = (unsigned char)((EEPROMBBPTuningParameters[1] & 0xff00) >> 8);
		DBNSLog(@"R24LowerValue = 0x%x\n", BBPTuningParameters.R24LowerValue);
		DBNSLog(@"R24HigherValue = 0x%x\n", BBPTuningParameters.R24HigherValue);
	}
	if ((EEPROMBBPTuningParameters[2] != 0xffff) && (EEPROMBBPTuningParameters[2] != 0))
	{
		BBPTuningParameters.R25LowerValue = (unsigned char)(EEPROMBBPTuningParameters[2] & 0xff);
		BBPTuningParameters.R25HigherValue = (unsigned char)((EEPROMBBPTuningParameters[2] & 0xff00) >> 8);
		DBNSLog(@"R25LowerValue = 0x%x\n", BBPTuningParameters.R25LowerValue);
		DBNSLog(@"R25HigherValue = 0x%x\n", BBPTuningParameters.R25HigherValue);
	}
	if ((EEPROMBBPTuningParameters[3] != 0xffff) && (EEPROMBBPTuningParameters[3] != 0))
	{
		BBPTuningParameters.R61LowerValue = (unsigned char)(EEPROMBBPTuningParameters[3] & 0xff);
		BBPTuningParameters.R61HigherValue = (unsigned char)((EEPROMBBPTuningParameters[3] & 0xff00) >> 8);
		DBNSLog(@"R61LowerValue = 0x%x\n", BBPTuningParameters.R61LowerValue);
		DBNSLog(@"R61HigherValue = 0x%x\n", BBPTuningParameters.R61HigherValue);
	}
	if ((EEPROMBBPTuningParameters[4] != 0xffff) && (EEPROMBBPTuningParameters[4] != 0))
	{
//		PortCfg.BbpTuning.VgcUpperBound = (unsigned char)(EEPROMBBPTuningParameters[4] & 0xff);
		DBNSLog(@"VgcUpperBound = 0x%x\n", (EEPROMBBPTuningParameters[4] & 0xff));
	}
	if ((EEPROMBBPTuningParameters[5] != 0xffff) && (EEPROMBBPTuningParameters[5] != 0))
	{
		BBPTuningParameters.BBPR17LowSensitivity = (unsigned char)(EEPROMBBPTuningParameters[5] & 0xff);
		BBPTuningParameters.BBPR17MidSensitivity = (unsigned char)((EEPROMBBPTuningParameters[5] & 0xff00) >> 8);
		DBNSLog(@"BBPR17LowSensitivity = 0x%x\n", BBPTuningParameters.BBPR17LowSensitivity);
		DBNSLog(@"BBPR17MidSensitivity = 0x%x\n", BBPTuningParameters.BBPR17MidSensitivity);
	}
	if ((EEPROMBBPTuningParameters[6] != 0xffff) && (EEPROMBBPTuningParameters[6] != 0))
	{
		BBPTuningParameters.RSSIToDbmOffset = (unsigned char)(EEPROMBBPTuningParameters[6] & 0xff);
		DBNSLog(@"RSSIToDbmOffset = 0x%x\n", BBPTuningParameters.RSSIToDbmOffset);
	}
    
	DBNSLog(@"<-- NICReadEEPROMParameters\n");
}

void RalinkJack::NICInitAsicFromEEPROM()
{
    unsigned short i, value;
	unsigned short Value5, Value6;
	unsigned char  TxValue,RxValue;
	EEPROM_ANTENNA_STRUC	Antenna;
	EEPROM_NIC_CONFIG2_STRUC	NicConfig2;
    
	DBNSLog(@"--> NICInitAsicFromEEPROM\n");
    
	//Initialize BBP registers.
	for(i = 3; i < NUM_EEPROM_BBP_PARMS; ++i)
	{
		value = EEPROMDefaultValue[i];
		
		if((value != 0xFFFF) && (value != 0))
		{
			//blue,RTUSBWriteMACRegister(PHY_CSR7, value);
			//USHORT	ID;
			//ID = ((value & 0xff00) >> 8);
			{
				unsigned short	temp = 0;
				unsigned int	j = 0;
				do
				{
					RTUSBReadMACRegister(PHY_CSR8, &temp);
					if (!(temp & BUSY))
						break;
					++j;
				}
				while (j < RETRY_LIMIT);
				
				RTUSBWriteMACRegister(PHY_CSR7, value);
			}
            
		}
	}
    
	DBNSLog(@"BBPTuningParameters.R24LowerValue = %x\n", BBPTuningParameters.R24LowerValue);
	DBNSLog(@ "BBPTuningParameters.R25LowerValue = %x\n", BBPTuningParameters.R25LowerValue);
	DBNSLog(@ "BBPTuningParameters.R61LowerValue = %x\n", BBPTuningParameters.R61LowerValue);
	RTUSBWriteBBPRegister(24, BBPTuningParameters.R24LowerValue);
	RTUSBWriteBBPRegister(25, BBPTuningParameters.R25LowerValue);
	RTUSBWriteBBPRegister(61, BBPTuningParameters.R61LowerValue);
    
    
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
    
	/*
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
*/	
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
		r17 = 64;
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
}

bool RalinkJack::setChannel(UInt16 channel){
	ULONG R3;
	UCHAR index;
    
    //set tx power to 100%
    R3 = 31;
    
	R3 = R3 << 9; // shift TX power control to correct RF R3 bit position
	switch (RfType)
	{
		case RFIC_2522:
			for (index = 0; index < NUM_OF_2522_CHNL; ++index)
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
			for (index = 0; index < NUM_OF_2523_CHNL; ++index)
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
			for (index = 0; index < NUM_OF_2524_CHNL; ++index)
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
			for (index = 0; index < NUM_OF_2525_CHNL; ++index)
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
			for (index = 0; index < NUM_OF_2525E_CHNL; ++index)
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
			for (index = 0; index < NUM_OF_5222_CHNL; ++index)
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
    DBNSLog(@"RalinkJack::Switched to channel %d", channel);
    //lock channel seems to be an empty function
    return true;
	
}

bool RalinkJack::getAllowedChannels(UInt16* channels) {
    if (!_devicePresent) return false;
    if (!_deviceInit) return false;
    
    *channels = 0xFFFF;
    
    return true;
}

bool RalinkJack::startCapture(UInt16 channel) {
    setChannel(channel);
    RTUSBWriteMACRegister(MAC_CSR20, 0x0002); //turn on led
    RTUSBWriteMACRegister(TXRX_CSR2, 0x0046/*0x0046*/); //enable monitor mode?
    return true;   
}

bool RalinkJack::stopCapture()
{
    RTUSBWriteMACRegister(MAC_CSR20, 0x0000); //turn off led
    RTUSBWriteMACRegister(TXRX_CSR2, 0xffff); //disable rx
    return true;
}

bool RalinkJack::sendKFrame(KFrame *frame) {
    UInt8 *data = frame->data;
    int size = frame->ctrl.len;
    UInt8 aData[MAX_FRAME_BYTES];
    unsigned int descriptorLength;
    descriptorLength = WriteTxDescriptor(aData, size);
    memcpy(aData+descriptorLength, data, size);
    //send the frame
    if (_sendFrame(aData, size + descriptorLength) != kIOReturnSuccess)
        return NO;
    return YES;
}
void    RalinkJack::RTMPDescriptorEndianChange(unsigned char *  pData, unsigned long DescriptorType) {
    int size = (DescriptorType == TYPE_TXD) ? TXD_SIZE : RXD_SIZE;
    int i;
	int _size = size/4;
    for (i=1; i<_size; ++i) {
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

int RalinkJack::WriteTxDescriptor(void* theFrame, UInt16 length) {
    
    unsigned int Residual;
    TXD_STRUC *pTxD;
    pTxD = (TXD_STRUC *)theFrame;
    
    memset(pTxD, 0, sizeof(TXD_STRUC));
    
    pTxD->RetryLimit  = 0;
    pTxD->MoreFrag    = 0;
    pTxD->ACK         = 0;
	pTxD->Timestamp   = 0;
	pTxD->newseq      = 1;
	pTxD->IFS         = 0;
	pTxD->DataByteCnt = length;
	pTxD->Cipher	  = 0;
	pTxD->KeyID		  = 0;
	pTxD->CWmin       = 3;   // = 31
	pTxD->CWmax       = 5;   // = 1023
	pTxD->Aifs        = 2;   // TC0: SIFS + 2*Slot + Random(CWmin,CWmax)*Slot
    
    if (currentRate < RATE_FIRST_OFDM_RATE)
        pTxD->Ofdm = 0;
    else
        pTxD->Ofdm = 1;
    
    // fill up PLCP SIGNAL field
    pTxD->PlcpSignal = RT2570_RateIdToPlcpSignal[currentRate];
    // fill up PLCP SERVICE field, not used for OFDM rates
    pTxD->PlcpService = 4; // Service;
    
    length += 4;
    
    if (currentRate < RATE_FIRST_OFDM_RATE) {
        // 11b - RATE_1, RATE_2, RATE_5_5, RATE_11
        if ((currentRate == RATE_1) || ( currentRate == RATE_2)) {
            length = length * 8 / (currentRate + 1);
        } else {
            Residual = ((length * 16) % (11 * (1 + currentRate - RATE_5_5)));
            length = length * 16 / (11 * (1 + currentRate - RATE_5_5));
            if (Residual != 0) {
                length++;
            }
            if (currentRate == RATE_11) {
                if ((Residual <= (3 * (1 + currentRate - RATE_5_5))) && (Residual != 0)) {
                    pTxD->PlcpService |= 0x80; // 11b's PLCP length extension bit
                }
            }
        }
        pTxD->PlcpLengthHigh = length / LAST_BIT; // 256;
        pTxD->PlcpLengthLow = length % LAST_BIT;
    } else {
        // OFDM - RATE_6, RATE_9, RATE_12, RATE_18, RATE_24, RATE_36, RATE_48, RATE_54
        pTxD->PlcpLengthHigh = length / 64; // 64;      // high 6-bit of total byte count
        pTxD->PlcpLengthLow = length % 64;       // low 6-bit of total byte count
    }

    
#ifdef __BIG_ENDIAN__
    RTMPDescriptorEndianChange((unsigned char *)pTxD, TYPE_TXD);
#endif
    return sizeof(TXD_STRUC);
}

bool RalinkJack::_massagePacket(void *inBuf, void *outBuf, UInt16 len){
    unsigned char* pData = (unsigned char *)inBuf;
    KFrame *pFrame = (KFrame *)outBuf;
    PRXD_STRUC pRxD;
    if (len < sizeof(RXD_STRUC)) {
        DBNSLog(@"WTF, packet len %d shorter than footer %lu!", len, sizeof(RXD_STRUC));
        return false;
    }
    
    //flash the led for fun
    RTUSBWriteMACRegister(MAC_CSR20, 0x0007);        //put led under software control

    bzero(pFrame, sizeof(KFrame));

    pRxD = (PRXD_STRUC)(pData + len - sizeof(RXD_STRUC));

#ifdef __BIG_ENDIAN__
    RTMPDescriptorEndianChange((unsigned char *)pRxD, TYPE_RXD);
#endif
    
//    DBNSLog(@"DataByteCnt %d len %d", pRxD->DataByteCnt, len);
    if (pRxD->Crc) {
        DBNSLog(@"Bad CRC");
        return false;  //its a bad packet, signal the interrupt to continue
    }
    else if(pRxD->CiErr) {
        DBNSLog(@"CiErr");
        return false;  //its a bad packet, signal the interrupt to continue
    }
    else if(pRxD->PhyErr) {
        DBNSLog(@"PhyErr");
        return false;  //its a bad packet, signal the interrupt to continue
    }
    // this is probablty not the most efficient way to do this
    pFrame->ctrl.signal = pRxD->BBR1;
    if (pRxD->Ofdm) {
        
    } else {
        pFrame->ctrl.rate = pRxD->BBR0 / 5;
    }
    pFrame->ctrl.len = pRxD->DataByteCnt - 4;
    
    memcpy(pFrame->data, pData, pFrame->ctrl.len); 

    // flash LED off
    RTUSBWriteMACRegister(MAC_CSR20, 0x0002);  
    return true;         //override if needed
}

IOReturn RalinkJack::_sendFrame(UInt8* data, IOByteCount size) {
    UInt32      numBytes;
    IOReturn    kr;
    
    if (!_devicePresent) return kIOReturnError;
    
    if (_interface == NULL) {
        DBNSLog(@"RalinkJack::_sendFrame called with NULL interface this is prohibited!\n");
        return kIOReturnError;
    }
    
    _lockDevice();

    memcpy(&_outputBuffer, data, size);
    
    numBytes = ((size % 2) == 1) ? size + 1 : size;

    kr = (*_interface)->WritePipe(_interface, kOutPipe, &_outputBuffer, numBytes);
    _unlockDevice();
    
    return kr;
}

RalinkJack::RalinkJack() {
}
RalinkJack::~RalinkJack() {
  /*  stopRun();
    _interface = NULL;
    
    pthread_mutex_destroy(&_wait_mutex);
    pthread_cond_destroy(&_wait_cond);
    pthread_mutex_destroy(&_recv_mutex);
    pthread_cond_destroy(&_recv_cond);
    */
}

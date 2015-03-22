/*
 *  RT73Jack.h
 *  KisMAC
 *
 *  Created by Vincent Borrel on 10/11/06.
 *
 */
#ifndef	__RT73JACK_H__
#define	__RT73JACK_H__

#import <Cocoa/Cocoa.h>
#import "USBJack.h"
#import "ralink.h"

//temporary to fix linking errors
#define	NUM_EEPROM_BBP_PARMS		19
#define	NUM_EEPROM_BBP_TUNING_PARMS	7

#ifdef __BIG_ENDIAN__
typedef union  _MCU_LEDCS_STRUC {
	struct	{
		USHORT		PolarityRDY_A:1;
		USHORT		PolarityRDY_G:1;
		USHORT		PolarityACT:1;
		USHORT		PolarityGPIO_4:1;
		USHORT		PolarityGPIO_3:1;
		USHORT		PolarityGPIO_2:1;
		USHORT		PolarityGPIO_1:1;
		USHORT		PolarityGPIO_0:1;
		USHORT		LinkAStatus:1;
		USHORT		LinkGStatus:1;
		USHORT		RadioStatus:1;
		USHORT		LedMode:5;		
	} field;
	USHORT			word;
} MCU_LEDCS_STRUC, *PMCU_LEDCS_STRUC;
#else
typedef union  _MCU_LEDCS_STRUC {
	struct	{
		USHORT		LedMode:5;
		USHORT		RadioStatus:1;
		USHORT		LinkGStatus:1;
		USHORT		LinkAStatus:1;
		USHORT		PolarityGPIO_0:1;
		USHORT		PolarityGPIO_1:1;
		USHORT		PolarityGPIO_2:1;
		USHORT		PolarityGPIO_3:1;
		USHORT		PolarityGPIO_4:1;
		USHORT		PolarityACT:1;
		USHORT		PolarityRDY_G:1;
		USHORT		PolarityRDY_A:1;
	} field;
	USHORT			word;
} MCU_LEDCS_STRUC, *PMCU_LEDCS_STRUC;
#endif

#define ETH_LENGTH_OF_ADDRESS	6
// structure to store channel TX power
typedef struct _CHANNEL_TX_POWER {
	unsigned char	Channel;
	char	Power;
}	CHANNEL_TX_POWER, *PCHANNEL_TX_POWER;

#ifdef __BIG_ENDIAN__
typedef	union	_EEPROM_TXPOWER_DELTA_STRUC	{
	struct	{
		UCHAR	TxPowerEnable:1;// Enable
		UCHAR	Type:1;			// 1: plus the delta value, 0: minus the delta value
		UCHAR	DeltaValue:6;	// Tx Power dalta value (MAX=4)
	}	field;
	UCHAR	value;
}	EEPROM_TXPOWER_DELTA_STRUC, *PEEPROM_TXPOWER_DELTA_STRUC;
#else
typedef	union	_EEPROM_TXPOWER_DELTA_STRUC	{
	struct	{
		UCHAR	DeltaValue:6;	// Tx Power dalta value (MAX=4)
		UCHAR	Type:1;			// 1: plus the delta value, 0: minus the delta value
		UCHAR	TxPowerEnable:1;// Enable
	}	field;
	UCHAR	value;
}	EEPROM_TXPOWER_DELTA_STRUC, *PEEPROM_TXPOWER_DELTA_STRUC;
#endif

typedef struct	_RTMP_RF_REGS
{
	UCHAR	Channel;
	ULONG	R1;
	ULONG	R2;
	ULONG	R3;
	ULONG	R4;
}	RTMP_RF_REGS, *PRTMP_RF_REGS;

#define MAX_NUM_OF_CHANNELS		43	//1-14, 36/40/44/48/52/56/60/64/100/104/108/112/116/120/124/ 
									//128/132/136/140/149/153/157/161/165/34/38/42/46 + 1 as NULL termination
//end temp

class RT73Jack: public USBJack
{
public:
    
    RT73Jack();
    ~RT73Jack();

    void dumpFrame(UInt8 *data, UInt16 size);

    IOReturn _init();
    char *      getPlistFile();
    IOReturn	RTUSB_VendorRequest(
                                    UInt8 direction,
                                    UInt8 bRequest, 
                                    UInt16 wValue, 
                                    UInt16 wIndex, 
                                    void *pData,
                                    UInt16 wLength);
    
    IOReturn	RTUSBMultiRead(
                               unsigned short	Offset,
                               unsigned char	*pData,
                               unsigned short	length);
    
    IOReturn	RTUSBMultiWrite(
                                unsigned short	Offset,
                                unsigned char	*pData,
                                unsigned short 	length);
    
	IOReturn	RTUSBFirmwareRun();
    
	IOReturn	RTUSBWriteHWMACAddress();
    
	IOReturn	RTUSBSetLED(
                            MCU_LEDCS_STRUC	LedStatus,
                            unsigned short	LedIndicatorStrength);
    
	IOReturn	RTMPSetLED(
                           unsigned char	LEDStatus);
    
    IOReturn    RTUSBWriteMACRegister(
                                      unsigned short	Offset,
                                      unsigned long	Value);
    
    IOReturn	RTUSBReadMACRegister(
                                     USHORT	Offset,
                                     ULONG	*pValue);
    
    IOReturn	RTUSBReadBBPRegister(
                                     unsigned char	Id,
                                     unsigned char	*pValue);
    
    IOReturn	RTUSBWriteBBPRegister(
                                      unsigned char	Id,
                                      unsigned char	Value);
    
    IOReturn	RTUSBWriteRFRegister(
                                     unsigned long	Value);
    
    IOReturn	RTUSBReadEEPROM(
                                unsigned short	Offset,
                                unsigned char	*pData,
                                unsigned short	length);
    
	IOReturn	RTUSBReadMacAddress(unsigned char	*pData);

	IOReturn	NICInitializeAsic();
    
	IOReturn	NICLoadFirmware();
    
    
    void	NICReadEEPROMParameters();
    void	NICInitAsicFromEEPROM();
    
    bool setChannel(UInt16 channel);
    bool getAllowedChannels(UInt16* channels);
    bool startCapture(UInt16 channel);
    bool stopCapture();
    
    bool _massagePacket(void *inBuf, void *outBuf, UInt16 len);

    int         WriteTxDescriptor(void* theFrame, UInt16 length, UInt8 rate);
    bool        sendKFrame(KFrame *frame);
    IOReturn    _sendFrame(UInt8* data, IOByteCount size);
    
    void RTMPDescriptorEndianChange(unsigned char *  pData, unsigned long DescriptorType);
    void WriteBackToDescriptor(unsigned char *Dest, unsigned char *Src, bool DoEncrypt, unsigned long DescriptorType);
    void   RTUSBWriteTxDescriptor(
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
            bool bAfterRTSCTS);
    UInt32 currentRate;

private:
        
        //    int temp;
        //    unsigned short	EEPROMDefaultValue[NUM_EEPROM_BBP_PARMS];
        //    unsigned short	EEPROMBBPTuningParameters[NUM_EEPROM_BBP_TUNING_PARMS];
        //    RT73_BBP_TUNING_PARAMETERS_STRUC	RT73_BBPTuningParameters;
        //    unsigned char	RfType;
        
        bool	NICInitialized;
    
    unsigned char	PermanentAddress[ETH_LENGTH_OF_ADDRESS];
	CHANNEL_TX_POWER	TxPower[MAX_NUM_OF_CHANNELS];	// Store Tx power value for all channels.
	unsigned long	EepromVersion;	// byte 0: version, byte 1: revision, byte 2~3: unused
	unsigned short	EEPROMDefaultValue[NUM_EEPROM_BBP_PARMS];
	bool 	bAutoTxAgcA;				// Enable driver auto Tx Agc control
	unsigned char		TssiRefA;					// Store Tssi reference value as 25 tempature.	
	unsigned char		TssiPlusBoundaryA[5];		// Tssi boundary for increase Tx power to compensate.
	unsigned char		TssiMinusBoundaryA[5];		// Tssi boundary for decrease Tx power to compensate.
	unsigned char		TxAgcStepA;					// Store Tx TSSI delta increment / decrement value
	char		TxAgcCompensateA;			// Store the compensation (TxAgcStep * (idx-1))
	bool 	bAutoTxAgcG;				// Enable driver auto Tx Agc control
	unsigned char		TssiRefG;					// Store Tssi reference value as 25 tempature.	
	unsigned char		TssiPlusBoundaryG[5];		// Tssi boundary for increase Tx power to compensate.
	unsigned char		TssiMinusBoundaryG[5];		// Tssi boundary for decrease Tx power to compensate.
	unsigned char		TxAgcStepG;					// Store Tx TSSI delta increment / decrement value
	char	TxAgcCompensateG;			// Store the compensation (TxAgcStep * (idx-1))
	unsigned char					BbpRssiToDbmDelta;
	unsigned char	RFProgSeq;
	unsigned long					RfFreqOffset;	// Frequency offset for channel switching
	char	BGRssiOffset1;				// Store B/G RSSI#1 Offset value on EEPROM 0x9Ah
	char	BGRssiOffset2;				// Store B/G RSSI#2 Offset value 
	char	ARssiOffset1;				// Store A RSSI#1 Offset value on EEPROM 0x9Ch
	char	ARssiOffset2;
    EEPROM_TXPOWER_DELTA_STRUC  TxPowerDeltaConfig;				// Compensate the Tx power BBP94 with this configurate value
	unsigned char					RfIcType;		// RFIC_xxx
	//unsigned long					ExtraInfo;				// Extra information for displaying status
    
	RTMP_RF_REGS			LatchRfRegs;	// latch th latest RF programming value since RF IC doesn't support READ
    
    
	MCU_LEDCS_STRUC	LedCntl;
	unsigned short	LedIndicatorStrength;
};
#endif

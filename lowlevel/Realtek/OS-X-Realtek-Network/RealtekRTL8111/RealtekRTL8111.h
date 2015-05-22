/* RealtekRTL8111.h -- RTL8111 driver class definition.
 *
 * Copyright (c) 2013 Laura Müller <laura-mueller@uni-duesseldorf.de>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * Driver for Realtek RTL8111x PCIe ethernet controllers.
 *
 * This driver is based on Realtek's r8168 Linux driver (8.037.0).
 */

#include "RealtekRTL8111Linux-803700.h"

#define EXPORT __attribute__((visibility("default")))
#define PRIVATE __attribute__((visibility("hidden")))

#ifdef DEBUG
#define DebugLog(args...) IOLog("Ethernet [RealtekRTL8111]: " args)
#else
#define DebugLog(args...) 
#endif
#define AlwaysLog(args...) IOLog("Ethernet [RealtekRTL8111]: " args)

#define	RELEASE(x)	if(x){(x)->release();(x)=NULL;}

#define WriteReg8(reg, val8)    _OSWriteInt8((baseAddr), (reg), (val8))
#define WriteReg16(reg, val16)  OSWriteLittleInt16((baseAddr), (reg), (val16))
#define WriteReg32(reg, val32)  OSWriteLittleInt32((baseAddr), (reg), (val32))
#define ReadReg8(reg)           _OSReadInt8((baseAddr), (reg))
#define ReadReg16(reg)          OSReadLittleInt16((baseAddr), (reg))
#define ReadReg32(reg)          OSReadLittleInt32((baseAddr), (reg))

#if 0 //DISABLE_ALL_HACKS
#define HACK_OSMetaClassDefineReservedUnused(classNameReal, classNameSuper, index) \
void classNameReal ::_RESERVED ## classNameSuper ## index () { gMetaClass.reservedCalled(index); }

#define HACK_OSMetaClassDeclareReservedUnused(className, index)        \
private:                                                      \
virtual void _RESERVED ## className ## index ()
#endif//DISABLE_ALL_HACKS

#include <Availability.h>

#define MakeKernelVersion(maj,min,rev) (maj<<16|min<<8|rev)
#include <libkern/version.h>
#define GetKernelVersion() MakeKernelVersion(version_major,version_minor,version_revision)

enum
{
	MEDIUM_INDEX_AUTO = 0,
	MEDIUM_INDEX_10HD,
	MEDIUM_INDEX_10FD,
	MEDIUM_INDEX_100HD,
	MEDIUM_INDEX_100FD,
	MEDIUM_INDEX_1000FD,
	MEDIUM_INDEX_COUNT
};

#define MBit 1000000

enum {
    kSpeed1000MBit = 1000*MBit,
    kSpeed100MBit = 100*MBit,
    kSpeed10MBit = 10*MBit,
};

/* RTL8111's dma descriptor. */
typedef struct RtlDmaDesc {
    UInt32 opts1;
    UInt32 opts2;
    UInt64 addr;
} RtlDmaDesc;

/* RTL8111's statistics dump data structure */
typedef struct RtlStatData {
	UInt64	txPackets;
	UInt64	rxPackets;
	UInt64	txErrors;
	UInt32	rxErrors;
	UInt16	rxMissed;
	UInt16	alignErrors;
	UInt32	txOneCollision;
	UInt32	txMultiCollision;
	UInt64	rxUnicast;
	UInt64	rxBroadcast;
	UInt32	rxMulticast;
	UInt16	txAborted;
	UInt16	txUnderun;
} RtlStatData;

#define kTransmitQueueCapacity  1024

/* With up to 40 segments we should be on the save side. */
#define kMaxSegs 40

/* The number of descriptors must be a power of 2. */
#define kNumTxDesc	1024	/* Number of Tx descriptors */
#define kNumRxDesc	512     /* Number of Rx descriptors */
#define kTxLastDesc    (kNumTxDesc - 1)
#define kRxLastDesc    (kNumRxDesc - 1)
#define kTxDescMask    (kNumTxDesc - 1)
#define kRxDescMask    (kNumRxDesc - 1)
#define kTxDescSize    (kNumTxDesc*sizeof(struct RtlDmaDesc))
#define kRxDescSize    (kNumRxDesc*sizeof(struct RtlDmaDesc))

/* This is the receive buffer size (must be large enough to hold a packet). */
#define kRxBufferPktSize    2000
#define kRxNumSpareMbufs    100
#define kMCFilterLimit  32

/* statitics timer period in ms. */
#define kTimeoutMS 1000

/* Treshhold value in ns for the modified interrupt sequence. */
#define kFastIntrTreshhold 200000

/* transmitter deadlock treshhold in seconds. */
#define kTxDeadlockTreshhold 3
#define kTxCheckTreshhold (kTxDeadlockTreshhold - 1)

/* IPv4 specific stuff */
#define kMinL4HdrOffsetV4 34

/* IPv6 specific stuff */
#define kMinL4HdrOffsetV6 54

/* This definitions should have been in IOPCIDevice.h. */
enum
{
    kIOPCIPMCapability = 2,
};

enum
{
    kIOPCIELinkCapability = 12,
    kIOPCIELinkControl = 16,
};

enum
{
    kIOPCIELinkCtlASPM = 0x0003,    /* ASPM Control */
    kIOPCIELinkCtlL0s = 0x0001,     /* L0s Enable */
    kIOPCIELinkCtlL1 = 0x0002,      /* L1 Enable */
    kIOPCIELinkCtlCcc = 0x0040,     /* Common Clock Configuration */
    kIOPCIELinkCtlClkReqEn = 0x100, /* Enable clkreq */
};

enum
{
    kPowerStateOff = 0,
    kPowerStateOn,
    kPowerStateCount
};

#define kEnableEeeName "enableEEE"
#define kEnableCSO6Name "enableCSO6"
#define kEnableTSO4Name "enableTSO4"
#define kEnableTSO6Name "enableTSO6"
#define kIntrMitigateName "intrMitigate"
#define kDisableASPMName "disableASPM"
#define kDriverVersionName "Driver_Version"
#define kNameLenght 64

extern const struct RTLChipInfo rtl_chip_info[];

class EXPORT RTL8111 : public IOEthernetController
{
    typedef IOEthernetController super;
	OSDeclareDefaultStructors(RTL8111)
	
public:
	/* IOService (or its superclass) methods. */
	virtual bool start(IOService *provider);
	virtual void stop(IOService *provider);
	virtual bool init(OSDictionary *properties);
	virtual void free();
	
	/* Power Management Support */
	virtual IOReturn registerWithPolicyMaker(IOService *policyMaker);
    virtual IOReturn setPowerState(unsigned long powerStateOrdinal, IOService *policyMaker );
	virtual void systemWillShutdown(IOOptionBits specifier);
#if 0 //DISABLE_ALL_HACKS
#if __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ < 1070
    virtual IOReturn message(UInt32 type, IOService * provider, void * argument);
#endif
#endif//DISABLE_ALL_HACKS

	/* IONetworkController methods. */
	virtual IOReturn enable(IONetworkInterface *netif);
	virtual IOReturn disable(IONetworkInterface *netif);
	
	virtual UInt32 outputPacket(mbuf_t m, void *param);
	
	virtual void getPacketBufferConstraints(IOPacketBufferConstraints *constraints) const;
	
	virtual IOOutputQueue* createOutputQueue();
	
	virtual const OSString* newVendorString() const;
	virtual const OSString* newModelString() const;
	
	virtual IOReturn selectMedium(const IONetworkMedium *medium);
	virtual bool configureInterface(IONetworkInterface *interface);
	
	virtual bool createWorkLoop();
	virtual IOWorkLoop* getWorkLoop() const;

#if 0 //DISABLE_ALL_HACKS
#ifdef __MAC_10_7   // compiling SDK 10.7 or greater
#if __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ < 1070
    //HACK: needed to avoid unresolved externals loading on SL 10.6.8
    virtual UInt32 getDebuggerLinkStatus(void);
    virtual bool setDebuggerMode(bool active);
#endif
#else // compiling SDK 10.6
    //HACK: needed to avoid unresolved externals loading on ML 10.8.3
    HACK_OSMetaClassDeclareReservedUnused(IONetworkController, 0);
    HACK_OSMetaClassDeclareReservedUnused(IONetworkController, 1);
#endif
    //HACK: needed to avoid unresolved externals loading on ML 10.8.3
    HACK_OSMetaClassDeclareReservedUnused(IONetworkController, 2);
    HACK_OSMetaClassDeclareReservedUnused(IONetworkController, 3);
    HACK_OSMetaClassDeclareReservedUnused(IONetworkController, 4);
#endif//DISABLE_ALL_HACKS

	/* Methods inherited from IOEthernetController. */
	virtual IOReturn getHardwareAddress(IOEthernetAddress *addr);
	virtual IOReturn setHardwareAddress(const IOEthernetAddress *addr);
	virtual IOReturn setPromiscuousMode(bool active);
	virtual IOReturn setMulticastMode(bool active);
	virtual IOReturn setMulticastList(IOEthernetAddress *addrs, UInt32 count);
	virtual IOReturn getChecksumSupport(UInt32 *checksumMask, UInt32 checksumFamily, bool isOutput);
    virtual IOReturn setWakeOnMagicPacket(bool active);
    virtual IOReturn getPacketFilters(const OSSymbol *group, UInt32 *filters) const;
    
    virtual UInt32 getFeatures() const;
    
    virtual IOReturn setProperties(OSObject* props);

private:
    PRIVATE bool initPCIConfigSpace(IOPCIDevice *provider);
    PRIVATE static IOReturn setPowerStateWakeAction(OSObject *owner, void *arg1, void *arg2, void *arg3, void *arg4);
    PRIVATE static IOReturn setPowerStateSleepAction(OSObject *owner, void *arg1, void *arg2, void *arg3, void *arg4);
    PRIVATE bool setupMediumDict();
    PRIVATE bool initEventSources(IOService *provider);
    PRIVATE void interruptOccurred(OSObject *client, IOInterruptEventSource *src, int count);
    PRIVATE void pciErrorInterrupt();
    PRIVATE void txInterrupt();
    PRIVATE void rxInterrupt();
    PRIVATE bool setupDMADescriptors();
    PRIVATE void freeDMADescriptors();
    PRIVATE void txClearDescriptors();
    PRIVATE void checkLinkStatus();
    PRIVATE void updateStatitics();
    PRIVATE void setLinkUp(UInt8 linkState);
    PRIVATE void setLinkDown();
    PRIVATE bool checkForDeadlock();

    /* Hardware initialization methods. */
    PRIVATE bool initRTL8111();
    PRIVATE void enableRTL8111();
    PRIVATE void disableRTL8111();
    PRIVATE void startRTL8111(UInt16 newIntrMitigate, bool enableInterrupts);
    PRIVATE void setOffset79(UInt8 setting);
    PRIVATE void restartRTL8111();
    
    PRIVATE UInt8 csiFun0ReadByte(UInt32 addr);
    PRIVATE void csiFun0WriteByte(UInt32 addr, UInt8 value);
    PRIVATE void disablePCIOffset99();
    PRIVATE void setPCI99_180ExitDriverPara();
    PRIVATE void hardwareD3Para();

    PRIVATE IOReturn setPropertiesGated(OSObject* props);

#if CLEAR_STATUS_IN_INTERRUPT
    /* Raw interrupt handler */
    PRIVATE static void rawInterruptHandler(OSObject*, void* refCon, IOService*, int);
    PRIVATE void handleInterrupt();
    volatile UInt16 _status;
    int _msiIndex;
#endif

    /* Hardware specific methods */
    //PRIVATE void getDescCommand(UInt32 *cmd1, UInt32 *cmd2, mbuf_csum_request_flags_t checksums, UInt32 mssValue, mbuf_tso_request_flags_t tsoFlags);
    PRIVATE inline void getChecksumCommand(UInt32 *cmd1, UInt32 *cmd2, mbuf_csum_request_flags_t checksums);
    PRIVATE inline void getTso4Command(UInt32 *cmd1, UInt32 *cmd2, UInt32 mssValue, mbuf_tso_request_flags_t tsoFlags);
    PRIVATE inline void getTso6Command(UInt32 *cmd1, UInt32 *cmd2, UInt32 mssValue, mbuf_tso_request_flags_t tsoFlags);
    PRIVATE inline void getChecksumResult(mbuf_t m, UInt32 status1, UInt32 status2);
    
    /* RTL8111C specific methods */
    PRIVATE void timerActionRTL8111C(IOTimerEventSource *timer);

    /* RTL8111B/8168B specific methods */
    PRIVATE void timerActionRTL8111B(IOTimerEventSource *timer);
    
private:
	IOWorkLoop *workLoop;
    IOCommandGate *commandGate;
	IOPCIDevice *pciDevice;
	OSDictionary *mediumDict;
	IONetworkMedium *mediumTable[MEDIUM_INDEX_COUNT];
	IOBasicOutputQueue *txQueue;
	
	IOInterruptEventSource *interruptSource;
	IOTimerEventSource *timerSource;
	IOEthernetInterface *netif;
	IOMemoryMap *baseMap;
    volatile void *baseAddr;
    
    /* transmitter data */
    mbuf_t txNext2FreeMbuf;
    IOBufferMemoryDescriptor *txBufDesc;
    IOPhysicalAddress64 txPhyAddr;
    struct RtlDmaDesc *txDescArray;
    IOMbufNaturalMemoryCursor *txMbufCursor;
    UInt64 txDescDoneCount;
    UInt64 txDescDoneLast;
    UInt32 txNextDescIndex;
    UInt32 txDirtyDescIndex;
    SInt32 txNumFreeDesc;

    /* receiver data */
    IOBufferMemoryDescriptor *rxBufDesc;
    IOPhysicalAddress64 rxPhyAddr;
    struct RtlDmaDesc *rxDescArray;
	IOMbufNaturalMemoryCursor *rxMbufCursor;
    UInt64 multicastFilter;
    UInt32 rxNextDescIndex;
    UInt32 rxConfigReg;
    UInt32 rxConfigMask;

    /* power management data */
    unsigned long powerState;
    
    /* statistics data */
    UInt32 deadlockWarn;
    IONetworkStats *netStats;
	IOEthernetStats *etherStats;
    IOBufferMemoryDescriptor *statBufDesc;
    IOPhysicalAddress64 statPhyAddr;
    struct RtlStatData *statData;

    UInt32 mtu;
    UInt32 speed;
    UInt32 duplex;
    UInt32 autoneg;
    struct pci_dev pciDeviceData;
    struct rtl8168_private linuxData;
    struct IOEthernetAddress currMacAddr;
    struct IOEthernetAddress origMacAddr;
    
    UInt64 lastIntrTime;
    UInt16 intrMask;
    UInt16 intrMitigateValue;
    
    /* flags */
    bool isEnabled;
	bool promiscusMode;
	bool multicastMode;
    bool linkUp;
    bool stalled;
    bool useMSI;
    bool needsUpdate;
    bool wolCapable;
    bool wolActive;
    bool revisionC;
    bool enableTSO4;
    bool enableTSO6;
    bool enableCSO6;
    bool disableASPM;
    
    /* mbuf_t arrays */
    mbuf_t txMbufArray[kNumTxDesc];
    mbuf_t rxMbufArray[kNumRxDesc];
};

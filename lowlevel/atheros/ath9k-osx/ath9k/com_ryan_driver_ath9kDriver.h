//
//  com_ryan_driver_ath9kDriver.h
//  ath9k
//
//  Created by Ryan Wang on 13-9-27.
//  Copyright (c) 2013年 Ryan Wang. All rights reserved.
//

#ifndef __ath9k__com_ryan_driver_ath9kDriver__
#define __ath9k__com_ryan_driver_ath9kDriver__

#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/network/IOEthernetController.h>
#include <IOKit/network/IOEthernetInterface.h>
#include <IOKit/network/IOGatedOutputQueue.h>
#include <IOKit/network/IOMbufMemoryCursor.h>
#include <IOKit/network/IOPacketQueue.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOFilterInterruptEventSource.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/assert.h>


/*
 * Adapter activation levels.
 */
enum {
    kActivationLevelNone = 0,  /* adapter shut off */
    kActivationLevelKDP,       /* adapter partially up to support KDP */
    kActivationLevelBSD        /* adapter fully up to support KDP and BSD */
};


class com_ryan_driver_ath9kDriver : public IOEthernetController
{
    OSDeclareDefaultStructors( com_ryan_driver_ath9kDriver )	;
    
public:
    virtual bool                init(OSDictionary *properties);
    virtual bool				start( IOService *provider );
    virtual void				stop ( IOService *provider );
    virtual void				free( void );
    
    
    virtual IOReturn			enable(  IONetworkInterface *netif );
    virtual IOReturn			disable( IONetworkInterface *netif );
    virtual IOReturn			enable(  IOKernelDebugger   *debugger );
    virtual IOReturn			disable( IOKernelDebugger   *debugger );
    
    virtual IOReturn			getHardwareAddress( IOEthernetAddress * address );
    virtual IOReturn			setHardwareAddress( const IOEthernetAddress * address);
    virtual IOReturn			setPromiscuousMode ( bool active);
    virtual IOReturn			setMulticastMode (bool active);
    virtual IOReturn			setMulticastList ( IOEthernetAddress *mcAddrList, UInt32 mcAddrCount);
    
//    virtual IOOutputQueue *		createOutputQueue ( void );
//    virtual bool				createWorkLoop( void );
//    virtual IOWorkLoop *		getWorkLoop( void ) const;
//    
//    virtual bool				configureInterface( IONetworkInterface * interface );
//    virtual IOReturn			selectMedium( const IONetworkMedium * medium );
    
    virtual const OSString *	newVendorString( void ) const;
    virtual const OSString *	newModelString( void ) const;
    
//    virtual void				receivePacket( void * pkt_data, UInt32 * pkt_size, UInt32 timeoutMS );
//    virtual UInt32				outputPacket(mbuf_t m, void * param);
//    virtual void				getPacketBufferConstraints (IOPacketBufferConstraints * constraints) const;
//    
//    static void					interruptHandler (OSObject * target, IOInterruptEventSource * src, int count);
//    static bool					interruptFilter (OSObject * target, IOFilterInterruptEventSource * src);
//    static void					timeoutHandler (OSObject * target, IOTimerEventSource * src);
//    void						timeoutOccurred (IOTimerEventSource * src);
//    
//    void						interruptOccurred( IOInterruptEventSource * src, int count );
//    bool						receiveInterruptOccurred();
//    void						transmitInterruptOccurred();
    
    
    
    IOEthernetAddress           fEnetAddr;
    IOEthernetInterface *       fNetif;
    IOPCIDevice *               fPCIDevice;
    IOWorkLoop *                fWorkLoop;

  
    UInt32                      fActivationLevel;
    bool                        fEnabledForBSD;
    bool                        fEnabledForKDP;
    bool                        fSelectMediumOverride;
    bool                        fInterruptEnabled;
    mbuf_t						fKDPMbuf;
    IOPhysicalSegment			fKDPMbufSeg;

};


#endif /* defined(__ath9k__com_ryan_driver_ath9kDriver__) */

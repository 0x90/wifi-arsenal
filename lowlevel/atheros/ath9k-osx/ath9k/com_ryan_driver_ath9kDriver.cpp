//
//  com_ryan_driver_ath9kDriver.cpp
//  ath9k
//
//  Created by Ryan Wang on 13-9-27.
//  Copyright (c) 2013年 Ryan Wang. All rights reserved.
//

#include "com_ryan_driver_ath9kDriver.h"

#define super IOEthernetController

OSDefineMetaClassAndStructors( com_ryan_driver_ath9kDriver, IOEthernetController );

bool com_ryan_driver_ath9kDriver::init(OSDictionary *properties)
{
    printf("[%d]: %s\n" , __LINE__,__FUNCTION__);

	if (!super::init(properties))
	{
		return false;
	}
    dIOLog(<#level#>, <#a#>, <#b...#>)
    
//	memset(&adapter_, 0, sizeof(at_adapter));
//	adapter_.pdev = NULL;
//	netIface_ = NULL;
//	hw_addr_ = NULL;
//	adapter_.pci_using_64 = false;
//	adapter_.hw.mmr_base = NULL;
    
	return true;
}


bool com_ryan_driver_ath9kDriver:: start(IOService *provider) {

    printf("[%d]: %s\n" , __LINE__,__FUNCTION__);
    super::start(provider);
    return true;
}


void com_ryan_driver_ath9kDriver:: stop(IOService *provider) {
    printf("[%d]: %s\n" , __LINE__,__FUNCTION__);
    super::stop(provider);
}


void com_ryan_driver_ath9kDriver::free( void ) {
    printf("[%d]: %s\n" , __LINE__,__FUNCTION__);
    super::free();
}


IOReturn com_ryan_driver_ath9kDriver::enable(  IONetworkInterface *netif ) {
//    if (fEnabledForBSD) return kIOReturnSuccess;
//	
//    fEnabledForBSD = setActivationLevel(kActivationLevelBSD);
//	
//    return fEnabledForBSD ? kIOReturnSuccess : kIOReturnIOError;

    super::enable(netif);
    return true;
}


IOReturn com_ryan_driver_ath9kDriver::disable( IONetworkInterface *netif ) {
    return false;
}

IOReturn com_ryan_driver_ath9kDriver::enable(  IOKernelDebugger   *debugger ) {
    return true;
}


IOReturn com_ryan_driver_ath9kDriver::disable( IOKernelDebugger   *debugger ) {
    return false;
}


#pragma mark -
#pragma mark MAC Address Functions
#pragma mark -

IOReturn com_ryan_driver_ath9kDriver::getHardwareAddress( IOEthernetAddress *address )
{
	address->bytes[0] = fEnetAddr.bytes[0];
	address->bytes[1] = fEnetAddr.bytes[1];
	address->bytes[2] = fEnetAddr.bytes[2];
	address->bytes[3] = fEnetAddr.bytes[3];
	address->bytes[4] = fEnetAddr.bytes[4];
	address->bytes[5] = fEnetAddr.bytes[5];
	
	return kIOReturnSuccess;
}

IOReturn com_ryan_driver_ath9kDriver::setHardwareAddress( const IOEthernetAddress * address )
{
	fEnetAddr.bytes[0] = address->bytes[0];
	fEnetAddr.bytes[1] = address->bytes[1];
	fEnetAddr.bytes[2] = address->bytes[2];
	fEnetAddr.bytes[3] = address->bytes[3];
	fEnetAddr.bytes[4] = address->bytes[4];
	fEnetAddr.bytes[5] = address->bytes[5];
	
	return kIOReturnSuccess;
}


IOReturn com_ryan_driver_ath9kDriver::setPromiscuousMode ( bool active)
{
	//ifnet_t *ifp;
    //
    //	BGE_LOCK_ASSERT(sc);
    //
    //	ifp = sc->bge_ifp;
    //
    //	/* Enable or disable promiscuous mode as needed. */
    //	if (ifp->if_flags & IFF_PROMISC)
    //		BGE_SETBIT(sc, BGE_RX_MODE, BGE_RXMODE_RX_PROMISC);
    //	else
    //		BGE_CLRBIT(sc, BGE_RX_MODE, BGE_RXMODE_RX_PROMISC);
	
	return kIOReturnSuccess;
}

IOReturn com_ryan_driver_ath9kDriver::setMulticastMode (bool active)
{
	return kIOReturnSuccess;
}

IOReturn com_ryan_driver_ath9kDriver::setMulticastList ( IOEthernetAddress *mcAddrList, UInt32 mcAddrCount)
{
    return kIOReturnSuccess;
}

#pragma mark -
#pragma mark Work Loop
#pragma mark -

//bool com_ryan_driver_ath9kDriver::createWorkLoop( void )
//{
//    fWorkLoop = IOWorkLoop::workLoop();
//    return (fWorkLoop != 0);
//}
//
//IOWorkLoop * com_ryan_driver_ath9kDriver::getWorkLoop( void ) const
//{
//    return fWorkLoop;
//}
//

//bool com_ryan_driver_ath9kDriver::atProbe()
//{
//    
//}

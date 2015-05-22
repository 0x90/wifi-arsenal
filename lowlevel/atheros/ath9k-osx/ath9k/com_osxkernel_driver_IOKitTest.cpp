//
//  com_osxkernel_driver_IOKitTest.cpp
//  ath9k
//
//  Created by Ryan Wang on 13-9-28.
//  Copyright (c) 2013年 Ryan Wang. All rights reserved.
//

#include "com_osxkernel_driver_IOKitTest.h"
#include <IOKit/IOLib.h>

#define super IOService

OSDefineMetaClassAndStructors(com_osxkernel_driver_IOKitTest, IOService);


bool com_osxkernel_driver_IOKitTest::init(OSDictionary *dic)
{
    bool res = super::init(dic);
    IOLog("[%d]:%s\n", __LINE__, __FUNCTION__);
    return res;
}


void com_osxkernel_driver_IOKitTest::free() {
    IOLog("[%d]:%s\n", __LINE__, __FUNCTION__);
    super::free();
}


IOService * com_osxkernel_driver_IOKitTest::probe (IOService *provider, SInt32 * score)
{
    IOLog("[%d]:%s\n %d", __LINE__, __FUNCTION__, *score);
    IOService *res = super::probe(provider, score);
    return res;
}


bool com_osxkernel_driver_IOKitTest::start(IOService * provider)
{
    bool res = super::start(provider);
    IOLog("[%d]:%s\n", __LINE__, __FUNCTION__);
    return res;
}


void com_osxkernel_driver_IOKitTest::stop(IOService * provider)
{
    IOLog("[%d]:%s\n", __LINE__, __FUNCTION__);
    super::stop(provider);
}


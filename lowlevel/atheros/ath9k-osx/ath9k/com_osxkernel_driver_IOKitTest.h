//
//  com_osxkernel_driver_IOKitTest.h
//  ath9k
//
//  Created by Ryan Wang on 13-9-28.
//  Copyright (c) 2013年 Ryan Wang. All rights reserved.
//

#ifndef __ath9k__com_osxkernel_driver_IOKitTest__
#define __ath9k__com_osxkernel_driver_IOKitTest__

#include <IOKit/IOService.h>

class com_osxkernel_driver_IOKitTest : public IOService
{
    OSDeclareDefaultStructors(com_osxkernel_driver_IOKitTest);
    
public:
    virtual bool init(OSDictionary *dic = NULL);
    virtual void free(void);
    
    virtual IOService * probe (IOService *provider, SInt32* score);
    virtual bool start(IOService * provider);
    virtual void stop(IOService * provider);
};


#endif /* defined(__ath9k__com_osxkernel_driver_IOKitTest__) */

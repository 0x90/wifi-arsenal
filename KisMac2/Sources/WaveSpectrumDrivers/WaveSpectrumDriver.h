//
//  WaveSpectrumDriver.h
//  KisMAC
//
//  Created by Francesco Del Degan on 5/5/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>

#include <IOKit/IOKitLib.h>
#include <IOKit/usb/IOUSBLib.h>

@interface WaveSpectrumDriver : NSObject
{
    bool _initialized;
    bool _calibrated;
    
    bool _loopRun;

    IONotificationPortRef   _notifyPort;
    io_iterator_t			_gRawAddedIter;
    IOUSBDeviceInterface	**_dev;
}

- (void) wispy_init;
- (void) rawDeviceAdded: (io_iterator_t)iterator;
- (void) getData: (NSTimer *)time;

@end

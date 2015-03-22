/*
        
        File:			WaveDriverUSBIntersil.m
        Program:		KisMAC
		Author:			Michael Rossberg
						mick@binaervarianz.de
		Description:	KisMAC is a wireless stumbler for MacOS X.
                
        This file is part of KisMAC.

    KisMAC is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License, version 2,
    as published by the Free Software Foundation;

    KisMAC is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with KisMAC; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
#import "WaveDriverUSBIntersil.h"
#import "WaveHelper.h"

@implementation WaveDriverUSB

- (id)init {
    self=[super init];

    if (!self)
        return nil;
    
    _driver = nil;
    
    if(![self wakeDriver])
    {
        //we didn't find a card, we can't proceed
        //destroy the driver
        
        delete(_driver);
        _driver = nil;
        return nil;
    }
    
    return self;
}

#pragma mark -

+ (enum WaveDriverType) type {
    return passiveDriver;
}

+ (bool) allowsInjection {
    return YES;
}

+ (bool) allowsChannelHopping {
    return YES;
}

+ (bool) allowsMultipleInstances {
    return YES;  //may be later
}

+ (NSString*) description {
    return NSLocalizedString(@"USB device, passive mode", "long driver description");
}

+ (NSString*) deviceName {
    return NSLocalizedString(@"USB device", "short driver description");
}

#pragma mark -

+ (bool) loadBackend {
    return YES;
}

+ (bool) unloadBackend {
       return YES;
}

#pragma mark -

- (unsigned short) getChannelUnCached
{
    UInt16 channel = 0;
    bool success = FALSE;
    
    //make sure we have a driver before we ask it for its channel
    if(_driver)
    {
        success = _driver->getChannel(&channel);
    }
    
    //channel 0 indicates error
    if(!success) channel = 0;
    
    return channel;
}

- (bool) setChannel:(unsigned short)newChannel {
    if (((_allowedChannels >> (newChannel - 1)) & 0x0001) == 0)
        return NO;
    
    return _driver->setChannel(newChannel);
}

- (bool) startCapture:(unsigned short)newChannel
{
    bool success = FALSE;
    
    if (newChannel == 0) newChannel = _firstChannel;
    
    //if there is no driver, success will remain false
    if(_driver)
    {
        //if the usb device is not there, see if we can find it
        if(!_driver->devicePresent())
        {
            [self wakeDriver];
        }
        success = _driver->startCapture(newChannel);
    }
    
    return success;
}

- (bool) stopCapture
{
    bool success = FALSE;
    
    //if there is no driver, success will remain false
    if(_driver)
    {
        success = _driver->stopCapture();
    }
        
    return success; 
}

- (bool) sleepDriver
{
    if(_driver) delete(_driver);
    _driver = nil;
    return YES;
}

- (bool) wakeDriver
{
    return YES;
}

#pragma mark -

- (KFrame *) nextFrame {
    KFrame *f = NULL;
    bool success;
    
    //make sure we have _driver and the device is actually there
    success = (_driver && _driver->devicePresent());
    
    if(success) {
         f = _driver->receiveFrame();
    }

    if (!f) {
        //there was a driver error, usb device is probably gone
        NSRunCriticalAlertPanel(NSLocalizedString(@"USB device error", "Error box title"),
                                NSLocalizedString(@"USB device error description", "LONG Error description"),
                                //@"A driver error occured with your USB device, make sure it is properly connected. Scanning will "
                                //"be canceled. Errors may have be printed to console.log."
                                OK, nil, nil);
    }
    else
    {
        ++_packets;
    }
    
    return f;
}

#pragma mark -
#pragma mark Injection
#pragma mark -

- (void)doInjection:(NSDictionary *)d {

	@autoreleasepool {
		NSData *data = d[@"data"];
		KFrame *f = (KFrame *)[data bytes];
		NSNumber *howM = d[@"howMany"];
		NSString *sel = d[@"selector"];
		SEL selector = NSSelectorFromString(sel);
		id target = d[@"target"];
		NSThread *thr = d[@"thread"];
		int howMany = [howM intValue];
		DBNSLog(@"doInj HowMany %d", howMany);
		if (howMany == -1) {
			while(_transmitting) {
				_driver->sendKFrame(f);
				[NSThread sleepUntilDate:[NSDate dateWithTimeIntervalSinceNow:_interval]];
			}
		} else {
			while(_transmitting && howMany) {
				_driver->sendKFrame(f);
				[NSThread sleepUntilDate:[NSDate dateWithTimeIntervalSinceNow:_interval]];
				howMany--;
			}
		}
		if (target && selector) {
			[target performSelector:selector onThread:thr withObject:nil waitUntilDone:NO];
		}
	}
}

-(bool) sendKFrame:(KFrame *)f howMany:(int)howMany atInterval:(int)interval notifyTarget:(id)target notifySelectorString:(NSString *)selector {
    NSThread *thr = [NSThread currentThread];
    if (howMany != 0) {
        NSData *data = [NSData dataWithBytes:f length:sizeof(KFrame)];
        NSNumber *howM = @(howMany);
        NSDictionary *d = [[NSDictionary alloc] initWithObjectsAndKeys: data, @"data", howM, @"howMany", thr, @"thread", target, @"target", selector, @"selector", nil];
        [self stopSendingFrames];
        _transmitting = YES;
        _interval = (float)interval / 1000.0;
        [NSThread detachNewThreadSelector:@selector(doInjection:) toTarget:self withObject:d];
    } else {
        _driver->sendKFrame(f);
        if (target && selector) {
            SEL sel = NSSelectorFromString(selector);
			NSMethodSignature *methodSignature = [target methodSignatureForSelector:sel];
			NSInvocation *invocation = [NSInvocation invocationWithMethodSignature:methodSignature];
			[invocation setSelector:sel];
			[invocation invoke];
        }
    }
    return YES;
}

-(bool) sendKFrame:(KFrame *)f howMany:(int)howMany atInterval:(int)interval {
    return [self sendKFrame:f howMany:howMany atInterval:interval notifyTarget:nil notifySelectorString:nil];
}
-(bool) stopSendingFrames {
    _transmitting = NO;
    [NSThread sleepUntilDate:[NSDate dateWithTimeIntervalSinceNow:_interval]];
    return YES;
}

#pragma mark -

- (int) allowedChannels {
    UInt16 channels;
    
    if (_allowedChannels)
        return _allowedChannels;
    
    if (_driver->getAllowedChannels(&channels)) {
        _allowedChannels = channels;
        return channels;
    } else return 0xFFFF;
}

#pragma mark -

-(void) dealloc {
    [self stopSendingFrames];
    
    [self sleepDriver];

    if (_driver)
        delete (_driver);
}

@end

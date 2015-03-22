//
//  WavePlugin.m
//  KisMAC
//
//  Created by pr0gg3d on 12/09/08.
//  Copyright 2008 __MyCompanyName__. All rights reserved.
//

#import "WavePlugin.h"

@implementation WavePlugin

#pragma mark -

- (id) initWithDriver:(WaveDriver *)driver
{
    if (!driver)
	{
        return nil;
    }
	
    self = [super init];
    
    if (!self)
	{
        return nil;
    }
    _driver = driver;
    
    _status = WavePluginIdle;
    _stopFlag = NO;
    
    return self;
}

- (void) dealloc
{
    
    _driver = nil;
}

#pragma mark -
#pragma mark Test control
#pragma mark -

- (bool) startTest
{
    // Checks if test is idle, otherwise return a problem
    if (_status != WavePluginIdle)
	{
        return NO;
    }
    
	_status = WavePluginRunning;
    // Perform test
    
	return YES;
}

- (bool) stopTest
{
    // Checks if test is running, otherwise ignore
    if (_status != WavePluginRunning)
	{
        return NO;
	}
    
	_stopFlag = YES;
    
	return YES;
}

- (WavePluginPacketResponse) gotPacket:(WavePacket *)packet fromDriver:(WaveDriver *)driver
{
    // Override in subclasses
    return WavePluginPacketResponseContinue;
}

- (WavePluginStatus) status
{
    return _status;
}

#pragma mark -

@end

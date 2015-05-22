//
//  WavePlugin.h
//  KisMAC
//
//  Created by pr0gg3d on 12/09/08.
//  Copyright 2008 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>

@class WaveDriver;
@class WaveNet;
@class WavePacket;

typedef enum _WavePluginStatus
{
    WavePluginIdle            = 0,
    WavePluginRunning         = 1,
} WavePluginStatus;

typedef enum _WavePluginPacketResponse {
    WavePluginPacketResponseContinue = 1,
    WavePluginPacketResponseCatched  = 2,
} WavePluginPacketResponse;

@interface WavePlugin : NSObject
{
    WavePluginStatus	_status;
    WaveDriver			*_driver;
    bool				_stopFlag;
    
    WaveNet				*_networkInTest;
}

- (id) initWithDriver:(WaveDriver *)driver;
- (bool) startTest;
- (WavePluginStatus) status;
- (bool) stopTest;
- (WavePluginPacketResponse) gotPacket:(WavePacket *)packet fromDriver:(WaveDriver *)driver;

@end

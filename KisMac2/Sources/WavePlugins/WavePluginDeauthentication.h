//
//  WavePluginDeauthentication.h
//  KisMAC
//
//  Created by pr0gg3d on 27/12/08.
//  Copyright 2008 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "WavePlugin.h"

@class WaveContainer;

@interface WavePluginDeauthentication : WavePlugin
{
    WaveContainer	*_container;
    bool			_deauthing;
}

- (id) initWithDriver:(WaveDriver *)driver andContainer:(WaveContainer *)container;
- (bool) startTest: (WaveNet *)net atInterval:(int)interval;
- (bool) deauthenticateClient:(UInt8*)client inNetworkWithBSSID:(UInt8*)bssid;
- (void) setDeauthingAll:(BOOL)deauthing;
@end

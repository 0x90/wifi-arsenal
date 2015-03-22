//
//  WavePluginAuthenticationFlood.h
//  KisMAC
//
//  Created by pr0gg3d on 28/12/08.
//  Copyright 2008 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "WavePlugin.h"
#import "KisMAC80211.h"

@class WaveNet;

@interface WavePluginAuthenticationFlood : WavePlugin {
    KFrame _authFrame;
}

- (bool) startTest:(WaveNet*)net;

@end

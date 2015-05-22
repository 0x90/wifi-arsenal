//
//  WavePluginBeaconFlood.h
//  KisMAC
//
//  Created by pr0gged on 28/12/08.
//  Copyright 2008 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "WavePlugin.h"
#import "KisMAC80211.h"

@interface WavePluginBeaconFlood : WavePlugin {
    KFrame _beaconFrame;
}

- (void)doBeaconFloodNetwork;

@end

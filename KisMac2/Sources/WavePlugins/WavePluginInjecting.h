//
//  WavePluginInjecting.h
//  KisMAC
//
//  Created by pr0gg3d on 27/12/08.
//  Copyright 2008 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "WavePlugin.h"
#import "KisMAC80211.h"

@interface WavePluginInjecting : WavePlugin {
    int  _injReplies;
    
	UInt8 _addr1[ETH_ALEN];
    UInt8 _addr2[ETH_ALEN];
    UInt8 _addr3[ETH_ALEN];
	
    int			aPacketType;
    NSTimer		*_timer;
    KFrame		_kframe;
    BOOL	_checkInjectedPackets;
    
    IBOutlet NSWindow *probeSheet;
    IBOutlet NSButton *cancelButton;
    IBOutlet NSTextField *ssid;
    IBOutlet NSTextField *operation;
    IBOutlet NSTextField *responses;
    IBOutlet NSProgressIndicator *progIndicator;
}

- (BOOL) startTest: (WaveNet *)net;
- (void) stepPerformInjection:(NSTimer *)timer;
- (void) stepCheckInjected;
- (void) checkStopInjecting: (NSTimer *)timer;
- (IBAction) endProbeSheet: (id) sender;

@end

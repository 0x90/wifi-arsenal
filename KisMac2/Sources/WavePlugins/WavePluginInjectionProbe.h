//
//  WavePluginInjectionProbe.h
//  KisMAC
//
//  Created by pr0gg3d on 26/12/08.
//  Copyright 2008 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "WavePlugin.h"

@class WaveClient;

@interface WavePluginInjectionProbe : WavePlugin 
{
    IBOutlet NSWindow *probeSheet;
    
    IBOutlet NSImageView *statusRate1;
    IBOutlet NSImageView *statusRate2;
    IBOutlet NSImageView *statusRate5_5;
    IBOutlet NSImageView *statusRate11;
    IBOutlet NSImageView *statusRate6;
    IBOutlet NSImageView *statusRate9;
    IBOutlet NSImageView *statusRate12;
    IBOutlet NSImageView *statusRate18;
    IBOutlet NSImageView *statusRate24;
    IBOutlet NSImageView *statusRate36;
    IBOutlet NSImageView *statusRate48;
    IBOutlet NSImageView *statusRate54;
    
    IBOutlet NSButton *button;
    IBOutlet NSTextField *textFieldAP;
    
	WaveClient *_clientInTest;
	
    NSImage *statusOK;
    NSImage *statusNOK;
    NSImage *statusSPIN;
    
    NSEnumerator	*_currentRateEnumerator;
    NSNumber		*_currentRate;
    NSTimer			*_timer;
    bool			_catchedPacket;
    
    UInt8 _randomSourceMAC[6];
    UInt8 _checks;

}

- (bool) startTest: (WaveNet *)net withClient:(WaveClient *)client;
- (void) stepTestProbeRequest;
- (void) stepTestRTS;
- (void) checkResponse;
- (IBAction) endProbeSheet: (id) sender;
- (id) imageCellForRate: (NSNumber*) rate;

@end

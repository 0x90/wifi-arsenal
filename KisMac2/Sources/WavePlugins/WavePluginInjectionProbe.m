//
//  WavePluginInjectionProbe.m
//  KisMAC
//
//  Created by pr0gg3d on 26/12/08.
//  Copyright 2008 __MyCompanyName__. All rights reserved.
//

#import "WavePluginInjectionProbe.h"

#import "WaveDriver.h"
#import "WaveNet.h"
#import "WaveClient.h"
#import "WaveHelper.h"
#import "KisMAC80211.h"
#import "../Core/80211b.h"

@implementation WavePluginInjectionProbe

- (bool) startTest: (WaveNet *)net withClient:(WaveClient *)client 
{
    int i;
    
    // No vaild network, return
    if (!net)
        return NO;
    
    // A test is already running, return
    if (_status == WavePluginRunning)
        return NO;
    
    // Only test managed networks (for now, FIXME)
    if ([net type] != networkTypeManaged)
        return NO;
    
    // Store network reference
    _networkInTest = net;
	_clientInTest = client;

    // Load nib file
    if (!probeSheet)
	{
        if(![[NSBundle mainBundle] loadNibNamed:@"injectionProbe" owner:self topLevelObjects:nil])
        {
            DBNSLog(@"injectionProbe.xib failed to load!");
            
            return NO;
        }
    }
    
    _status = WavePluginRunning;
    
    // set source MAC for this test
    for (i=0;i<6;++i) {
        _randomSourceMAC[i] = random() & 0xFF;
    }
    
    _timer = nil;
    
    [probeSheet orderOut:nil];
    [statusRate1 setImage:nil];
    [statusRate2 setImage:nil];
    [statusRate5_5 setImage:nil];
    [statusRate11 setImage:nil];
    [statusRate6 setImage:nil];
    [statusRate9 setImage:nil];
    [statusRate12 setImage:nil];
    [statusRate18 setImage:nil];
    [statusRate24 setImage:nil];
    [statusRate36 setImage:nil];
    [statusRate48 setImage:nil];
    [statusRate54 setImage:nil];
	
    [button setTitle:@"Cancel"];
	
	if (_clientInTest)
	{
		[textFieldAP setStringValue:[client ID]];
	} else {
		[textFieldAP setStringValue:[net BSSID]];
	}
    [NSApp beginSheet:probeSheet modalForWindow:[WaveHelper mainWindow] modalDelegate:[WaveHelper mainWindow] didEndSelector:nil contextInfo:nil];
    
    statusOK = [NSImage imageNamed:@"greengem.pdf"];
    statusNOK = [NSImage imageNamed:@"redgem.pdf"];
    statusSPIN = [NSImage imageNamed:@"spin.gif"];
    DBNSLog(@"%@", statusSPIN);
    _currentRateEnumerator = [[_driver permittedRates] objectEnumerator];
//    [self stepTestProbeRequest];
    [self stepTestRTS];
    return YES;
}

- (id) imageCellForRate: (NSNumber *)rate
{
    id imageCell = nil;
    KMRate r = [rate unsignedIntValue];
    switch (r) {
        case KMRate1:
            imageCell = statusRate1;
            break;
        case KMRate2:
            imageCell = statusRate2;
            break;
        case KMRate5_5:
            imageCell = statusRate5_5;
            break;
        case KMRate11:
            imageCell = statusRate11;
            break;
        case KMRate6:
            imageCell = statusRate6;
            break;
        case KMRate9:
            imageCell = statusRate9;
            break;
        case KMRate12:
            imageCell = statusRate12;
            break;
        case KMRate18:
            imageCell = statusRate18;
            break;
        case KMRate24:
            imageCell = statusRate24;
            break;
        case KMRate36:
            imageCell = statusRate36;
            break;
        case KMRate48:
            imageCell = statusRate48;
            break;
        case KMRate54:
            imageCell = statusRate54;
            break;
    }
    return imageCell;
}
- (void) stepTestProbeRequest
{
    // Get next rate
    _currentRate = [_currentRateEnumerator nextObject];
    if (_currentRate == nil) {
        [button setTitle:@"Close"];
        return;
    }

    NSImageView *imageCell = [self imageCellForRate:_currentRate];
    [imageCell setImage:statusSPIN];
    
    DBNSLog(@"Try to inject at %@", _currentRate);
    
    // sends some broadcast probes to see if card is ok
    int frameSize = sizeof(struct ieee80211_probe_request) + 18;
    
    // Allocate a frame to host probe_request and 18 bytes of info_elements (only rates)
    KFrame frame;
    memset(&frame, 0, sizeof(KFrame));
    
    struct ieee80211_probe_request *probe_req = (struct ieee80211_probe_request *)(frame.data);
    
    // fill ieee frame
    probe_req->header.frame_ctl = IEEE80211_TYPE_MGT | IEEE80211_SUBTYPE_PROBE_REQ;
    probe_req->header.duration_id = 0x0000;
	if (_clientInTest) {
		memcpy(probe_req->header.addr1, [[_clientInTest rawID] bytes], 6);
	} else {
		memcpy(probe_req->header.addr1, [_networkInTest rawBSSID], 6);
	}

    memcpy(probe_req->header.addr2, _randomSourceMAC, 6);
    memcpy(probe_req->header.addr3, "\xff\xff\xff\xff\xff\xff", 6);
    probe_req->header.seq_ctl = random() & 0x0FFF;
    
    // rates and ssid
    memcpy(probe_req->info_element, "\x00\x00\x01\x04\x02\x04\x0B\x16\x32\x08\x0C\x12\x18\x24\x30\x48\x60\x6C", 16);
    
    frame.ctrl.len = frameSize;
    frame.ctrl.tx_rate = (UInt8)[_currentRate unsignedIntValue];
    
    _catchedPacket = NO;
    _checks = 0;
    [_driver sendKFrame:&frame howMany:10 atInterval:200 notifyTarget:self notifySelectorString:@"checkResponse"];
}

- (void) stepTestRTS
{
    
    // Get next rate
    _currentRate = [_currentRateEnumerator nextObject];
    if (_currentRate == nil) {
        [button setTitle:@"Close"];
        return;
    }
    NSImageView *imageCell = [self imageCellForRate:_currentRate];
    [imageCell setImage:statusSPIN];

    DBNSLog(@"Try to inject at %@", _currentRate);
    
    // sends some RTS frame to see if card is ok
    int frameSize = sizeof(struct ieee80211_rts);
    
    // Allocate a frame to host RTS
    KFrame frame;
    memset(&frame, 0, sizeof(KFrame));
    
    struct ieee80211_rts *rts = (struct ieee80211_rts *)(frame.data);
    
    // fill ieee frame
    rts->header.frame_ctl = IEEE80211_TYPE_CTL | IEEE80211_SUBTYPE_RTS;
    rts->header.duration_id = 0x0000;
	if (_clientInTest) {
		memcpy(rts->header.addr1, [[_clientInTest rawID] bytes], 6);
	} else {
		memcpy(rts->header.addr1, [_networkInTest rawBSSID], 6);
	}
    memcpy(rts->header.addr2, _randomSourceMAC, 6);
    
    frame.ctrl.len = frameSize;
    frame.ctrl.tx_rate = (UInt8)[_currentRate unsignedIntValue];
    
    _catchedPacket = NO;
    _checks = 0;
    [_driver sendKFrame:&frame howMany:10 atInterval:200 notifyTarget:self notifySelectorString:@"checkResponse"];
}

- (void) checkResponse
{
    NSImageView *imageCell = [self imageCellForRate:_currentRate];
	
    if (_catchedPacket == YES)
	{
        [imageCell setImage:statusOK];
    } else {
		[imageCell setImage:statusNOK];
    }

    [self stepTestRTS];
}

- (WavePluginPacketResponse) gotPacket:(WavePacket *)packet fromDriver:(WaveDriver *)driver
{
    // Check if packet is received from our driver
    // else ignore it.
    if (driver != _driver)
	{
        return WavePluginPacketResponseContinue;
    }
	
    UInt8 *rawReceiverID = [packet rawReceiverID];
    if (!rawReceiverID)
	{
        return WavePluginPacketResponseContinue;
    }
	
    if (!memcmp(rawReceiverID, _randomSourceMAC, 6))
	{
        DBNSLog(@"Catch Injected packet response from %@ with a signal of %d", [packet stringSenderID], [packet signal]);
        _catchedPacket = YES;
        
		return WavePluginPacketResponseCatched;
    } else {
        return WavePluginPacketResponseContinue;
    }
}

- (IBAction) endProbeSheet: (id) sender
{
    [NSApp endSheet:probeSheet];
    [probeSheet orderOut:sender];
    [self stopTest];
}

- (bool) stopTest
{
    bool stop = [super stopTest];
    if (!stop)
        return NO;
	[_driver stopSendingFrames];
    if (_timer) {
        [_timer invalidate];
    }
    if (_networkInTest) {
        _networkInTest = nil;
    }
	if (_clientInTest) {
        _clientInTest = nil;

	}
    if (_currentRateEnumerator) {
        _currentRateEnumerator = nil;
    }
    _status = WavePluginIdle;
	
    return YES;
}

@end

//
//  WavePluginInjecting.m
//  KisMAC
//
//  Created by pr0gg3d on 27/12/08. 
//  Copyright 2008 __MyCompanyName__. All rights reserved.
//

#import "WavePluginInjecting.h"
#import "WaveNet.h"
#import "WaveHelper.h"
#import "WaveDriver.h"
#import "../Core/80211b.h"

@implementation WavePluginInjecting

- (id) initWithDriver:(WaveDriver *)driver
{
    self = [super initWithDriver:driver];
    
    if (!self)
	{
        return nil;
    }
	
    _checkInjectedPackets = NO;
    
    return self;
}

- (BOOL) startTest: (WaveNet *)net
{
    // No vaild network, return
    if (!net)
	{
        return NO;
    }
    
	// A test is already running, return
    if (_status == WavePluginRunning)
	{
        return NO;
    }
	
    // Only test managed networks
//    if ([net type] != networkTypeManaged)
//        return NO;
    
    // Only test WEP
    if (([net wep] != encryptionTypeWEP) && ([net wep] == encryptionTypeWEP40))
	{
        return NO;
    }
	
    // Load nib file, probeSheet will be assigned by File's Owner (see xib file) method
    if (!probeSheet)
    {
        if(![[NSBundle mainBundle] loadNibNamed:@"wepInjection" owner:self topLevelObjects:nil])
		{
            DBNSLog(@"wepInjection.xib failed to load!");
            
            return NO;
        }
    }
    
    // Set injection replies counters
    _injReplies = 0;
    [responses setIntValue:_injReplies];
    
    [probeSheet orderOut:nil];
    [operation setStringValue:@"Injecting..."];
    [progIndicator setUsesThreadedAnimation:YES];
    [ssid setStringValue:[net BSSID]];
	NSWindow *window = [WaveHelper mainWindow];
    [NSApp beginSheet:probeSheet
	   modalForWindow:window
		modalDelegate:window
	   didEndSelector:nil contextInfo:nil];
    
    // Store network reference
    _networkInTest = net;
    _status = WavePluginRunning;
    _stopFlag = NO;
    
    [self stepPerformInjection:nil];
	
    return YES;
}

- (void) stepPerformInjection: (NSTimer *)timer
{
    int q;
    NSMutableArray *p;
    NSData *f;

    struct ieee80211_hdr_3addr *frame = (struct ieee80211_hdr_3addr *)(_kframe.data);
    
    aPacketType = 1;
    
    // Checks if we have fired cancellation
    if (_stopFlag == YES) {
        _stopFlag = NO;
        _status = WavePluginIdle;
        return;
    }

    p = [_networkInTest arpPacketsLog];

    // if we haven't... Wait a little more
    if ([p count] <= 0)
	{
        [operation setStringValue:@"Waiting for interesting packets..."];
        [progIndicator setIndeterminate:YES];
        [progIndicator startAnimation:self];
        _timer = [NSTimer scheduledTimerWithTimeInterval:0.5
												  target:self
												selector:@selector(stepPerformInjection:)
												userInfo:nil
												 repeats:NO];
        return;
    }

    [operation setStringValue:@"Injecting..."];
    [progIndicator stopAnimation:self];
    [progIndicator setIndeterminate:NO];
    // Yes, we have a packet to inject
    // Zeroize kframe
    memset(&_kframe, 0, sizeof(KFrame));
            
    // Get last packet from buffer
    f = [p lastObject];
    q = [f length];
    [f getBytes:(char *)frame length:q];
            
    // Reset injection replies to 0
    _injReplies = 0;
    [responses setIntValue:_injReplies];
            
    if (frame->frame_ctl & IEEE80211_DIR_TODS)
	{
        memcpy(_addr1, frame->addr1, 6); //this is the BSSID
        memcpy(_addr2, frame->addr2, 6); //this is the source
        if (memcmp(frame->addr3, "\xff\xff\xff\xff\xff\xff", 6) != 0) {
            [p removeLastObject];
            _timer = [NSTimer scheduledTimerWithTimeInterval:0.5
													  target:self
													selector:@selector(stepPerformInjection:)
													userInfo:nil
													 repeats:NO];
			return;
        }
    } else {
        memcpy(_addr1, frame->addr2, 6); //BSSID
        memcpy(_addr2, frame->addr3, 6); //source
        if (memcmp(frame->addr1, "\xff\xff\xff\xff\xff\xff", 6) != 0) {
            [p removeLastObject];
            _timer = [NSTimer scheduledTimerWithTimeInterval:0.5
													  target:self
													selector:@selector(stepPerformInjection:)
													userInfo:nil
													 repeats:NO];
			return;
        }
    }
    frame->frame_ctl |= IEEE80211_WEP;
    frame->seq_ctl += (1<<4);
    //			frame->duration_id = 0;
    
    _kframe.ctrl.tx_rate = [_driver currentRate];
    _kframe.ctrl.len = q;
        
    DBNSLog(@"SEND INJECTION PACKET");
    _checkInjectedPackets = YES;
    [_driver sendKFrame:&_kframe
				howMany:100
			 atInterval:50
		   notifyTarget:self
   notifySelectorString:@"stepCheckInjected"];
    return;
}

- (void) stepCheckInjected {
    NSMutableArray *p;
    p = [_networkInTest arpPacketsLog];
    _checkInjectedPackets = NO;
    if (_injReplies<20) {
        // This packet isn't so good
        [p removeLastObject];
        [self stepPerformInjection:nil];
    } else {
        [operation setStringValue:@"Got a valid packet! Injecting...."];
        [progIndicator setIndeterminate:YES];
        [progIndicator startAnimation:self];
        [_driver sendKFrame:&_kframe howMany:-1 atInterval:5];
        _timer = [NSTimer scheduledTimerWithTimeInterval:1
												  target:self
												selector:@selector(checkStopInjecting:)
												userInfo:nil
												 repeats:NO];
    }
    return;
}

-(void) checkStopInjecting: (NSTimer *)timer {
    if (_stopFlag == YES) {
        _stopFlag = NO;
        _status = WavePluginIdle;
        [_driver stopSendingFrames];
        return;
    } else {
        _timer = [NSTimer scheduledTimerWithTimeInterval:1
												  target:self
												selector:@selector(checkStopInjecting:)
												userInfo:nil
												 repeats:NO];
    }
}

- (bool) stopTest {
    _stopFlag = YES;
    return YES;
}

- (WavePluginPacketResponse) gotPacket:(WavePacket *)packet fromDriver:(WaveDriver *)driver {
    int payloadLength = [packet payloadLength];
    
    if (_checkInjectedPackets == NO)
        return WavePluginPacketResponseContinue;
    
    // If packet isn't a data packet, ignore it (and continue)
    if ([packet type] != IEEE80211_TYPE_DATA)
        return WavePluginPacketResponseContinue;
    
	bool isBrokenData = false;
    if (aPacketType == 0) {        //do rst handling here
        if ((payloadLength == TCPRST_SIZE) && 
            IS_EQUAL_MACADDR([packet addr1], _addr1) && 
            IS_EQUAL_MACADDR([packet addr2], _addr2) &&
            IS_EQUAL_MACADDR([packet addr3], _addr3)) {
            isBrokenData = true;
        }
    } else if (payloadLength == ARP_SIZE || payloadLength == ARP_SIZE_PADDING || payloadLength == ARP_SIZE + 4) {

		if ([packet toDS]) {
			if (!IS_EQUAL_MACADDR([packet addr1], _addr1))
                return WavePluginPacketResponseContinue; //check BSSID
			if (IS_BCAST_MACADDR([packet addr2]) || IS_BCAST_MACADDR([packet addr3]))
                return WavePluginPacketResponseContinue; //arp replies are no broadcasts
		} else if ([packet fromDS]) {
			if (!IS_EQUAL_MACADDR([packet addr2], _addr1))
                return WavePluginPacketResponseContinue; //check BSSID
			if (IS_BCAST_MACADDR([packet addr1]) || IS_BCAST_MACADDR([packet addr3]))
                return WavePluginPacketResponseContinue;
		}		
		isBrokenData = true;
    }
	if (!isBrokenData) {
		return WavePluginPacketResponseContinue;
	}

    ++_injReplies;
    [responses setIntValue:_injReplies];
    [progIndicator setDoubleValue:(double)_injReplies];
    return WavePluginPacketResponseContinue;
}

- (IBAction) endProbeSheet: (id) sender {
    [progIndicator stopAnimation:sender];
    [NSApp endSheet:probeSheet];
    [probeSheet orderOut:sender];
    [self stopTest];
}

@end

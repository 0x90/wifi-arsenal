//
//  PrefsTraffic.m
//  KisMAC
//
//  Created by mick on Tue Sep 16 2003.
//  Copyright (c) 2003 __MyCompanyName__. All rights reserved.
//

#import "PrefsTraffic.h"
#import "PrefsController.h"

@implementation PrefsTraffic

-(void)updateUI {
    [_showSSID setState:[[controller objectForKey:@"TrafficViewShowSSID"] intValue]];
    [_showBSSID setState:[[controller objectForKey:@"TrafficViewShowBSSID"] intValue]];
    [_avgSignalTime setIntValue:[[controller objectForKey:@"WaveNetAvgTime"] intValue]];
}

-(BOOL)updateDictionary {    
    [_avgSignalTime validateEditing];

    [controller setObject:@([_avgSignalTime intValue]) forKey:@"WaveNetAvgTime"];
    return YES;
}

-(IBAction)setValueForSender:(id)sender {
    if(sender == _showSSID) {
        [controller setObject:[NSNumber numberWithInt:[_showSSID state]] forKey:@"TrafficViewShowSSID"];
    } else if(sender == _showBSSID) {
        [controller setObject:[NSNumber numberWithInt:[_showBSSID state]] forKey:@"TrafficViewShowBSSID"];
    } else if(sender == _avgSignalTime) {
        [controller setObject:@([_avgSignalTime intValue]) forKey:@"WaveNetAvgTime"];
    } else {
        DBNSLog(@"Error: Invalid sender(%@) in setValueForSender:",sender);
    }
}

@end

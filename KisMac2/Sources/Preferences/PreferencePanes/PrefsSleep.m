//
//  PrefsSleep.m
//  KisMAC
//
//  Created by Michael Thole on Mon Jan 20 2003.
//  Copyright (c) 2003 Michael Thole. All rights reserved.
//

#import "PrefsSleep.h"
#import "WaveHelper.h"

@implementation PrefsSleep


-(void)updateUI {
    [aNoSleep setState:[[controller objectForKey:@"disableSleepMode"] boolValue]];
}

-(IBAction)setValueForSender:(id)sender {
    if(sender == aNoSleep) {
        [controller setObject:[NSNumber numberWithBool:[sender state]] forKey:@"disableSleepMode"];
    }
    else {
        NSLog(@"Error: Invalid sender(%@) in setValueForSender:",sender);
    }
}

@end

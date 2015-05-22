//
//  PrefsMap.m
//  KisMAC
//
//  Created by Michael Thole on Mon Jan 20 2003.
//  Copyright (c) 2003 Michael Thole. All rights reserved.
//

#import "PrefsMap.h"
#import "WaveHelper.h"
#import "PrefsController.h"

@implementation PrefsMap

-(void)updateUI {
    [_cpColor setColor:[WaveHelper intToColor:[controller objectForKey:@"CurrentPositionColor"]]];
    [_traceColor setColor:[WaveHelper intToColor:[controller objectForKey:@"TraceColor"]]];
    [_wpColor setColor:[WaveHelper intToColor:[controller objectForKey:@"WayPointColor"]]];
    [_areaColorGood setColor:[WaveHelper intToColor:[controller objectForKey:@"NetAreaColorGood"]]];
    [_areaColorBad setColor:[WaveHelper intToColor:[controller objectForKey:@"NetAreaColorBad"]]];
    [_areaQual setFloatValue:[[controller objectForKey:@"NetAreaQuality"] floatValue]];
    [_areaSens setIntValue:[[controller objectForKey:@"NetAreaSensitivity"] intValue]];
    [[NSColorPanel sharedColorPanel] setShowsAlpha:YES];
}

-(BOOL)updateDictionary {
    [controller setObject:@([_areaQual floatValue]) forKey:@"NetAreaQuality"];
    [controller setObject:@([_areaSens intValue]) forKey:@"NetAreaSensitivity"];
    
    return YES;
}

-(IBAction)setValueForSender:(id)sender {
    if(sender == _cpColor) {
        [controller setObject:[WaveHelper colorToInt:[_cpColor color]] forKey:@"CurrentPositionColor"];
    } else if(sender == _traceColor) {
        [controller setObject:[WaveHelper colorToInt:[_traceColor color]] forKey:@"TraceColor"];
    } else if(sender == _wpColor) {
        [controller setObject:[WaveHelper colorToInt:[_wpColor color]] forKey:@"WayPointColor"];
    } else if(sender == _areaColorGood) {
        [controller setObject:[WaveHelper colorToInt:[sender color]] forKey:@"NetAreaColorGood"];
    } else if(sender == _areaColorBad) {
        [controller setObject:[WaveHelper colorToInt:[sender color]] forKey:@"NetAreaColorBad"];
    } else if(sender == _areaQual) {
        [controller setObject:@([sender floatValue]) forKey:@"NetAreaQuality"];
    } else if(sender == _areaSens) {
        [controller setObject:@([sender intValue]) forKey:@"NetAreaSensitivity"];
    }
    else {
        DBNSLog(@"Error: Invalid sender(%@) in setValueForSender:",sender);
    }
}


@end

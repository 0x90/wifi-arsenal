//
//  PrefsAdvanced.h
//  KisMAC
//
//  Created by themacuser on Mon Apr 3 2006.
//

#import "PrefsAdvanced.h"
#import "WaveHelper.h"

@implementation PrefsAdvanced

-(void)updateUI {
    [ac_ff setIntValue:[[controller objectForKey:@"ac_ff"]intValue]];
	[bf_interval setFloatValue:[[controller objectForKey:@"bf_interval"] intValue]];
	[pr_interval setIntValue:[[controller objectForKey:@"pr_interval"] intValue]];
	[show_debugmenu setState:[[controller objectForKey:@"DebugMode"] intValue]];
}

-(BOOL)updateDictionary {
	[controller setObject:[NSNumber numberWithInt:[ac_ff intValue]] forKey:@"ac_ff"];
	[controller setObject:[NSNumber numberWithFloat:[bf_interval floatValue]] forKey:@"bf_interval"];
	[controller setObject:[NSNumber numberWithInt:[pr_interval intValue]] forKey:@"pr_interval"];
	[controller setObject:[NSNumber numberWithInt:[show_debugmenu state]] forKey:@"DebugMode"];
    return YES;
}

-(IBAction)setValueForSender:(id)sender {
   if(sender == ac_ff) {
	[controller setObject:[NSNumber numberWithInt:[ac_ff intValue]] forKey:@"ac_ff"];
    } else if(sender == bf_interval) {
		[controller setObject:[NSNumber numberWithFloat:[bf_interval floatValue]] forKey:@"bf_interval"];
    } else if(sender == pr_interval) {
       [controller setObject:[NSNumber numberWithInt:[pr_interval intValue]] forKey:@"pr_interval"];
	} else if(sender == show_debugmenu) {
		[controller setObject:[NSNumber numberWithInt:[show_debugmenu state]] forKey:@"DebugMode"];
	} else {
        NSLog(@"Error: Invalid sender(%@) in setValueForSender:",sender);
    }
}

-(IBAction)setDefaults:(id)sender {
	[ac_ff setIntValue:2];
	[bf_interval setFloatValue:0.1];
	[pr_interval setIntValue:100];
	[show_debugmenu setState:NSOffState];
}

@end
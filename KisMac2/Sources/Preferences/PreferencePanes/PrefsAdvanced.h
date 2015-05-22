//
//  PrefsAdvanced.h
//  KisMAC
//
//  Created by themacuser on Mon Apr 3 2006.
//

#import <AppKit/AppKit.h>

#import "PrefsClient.h"

@interface PrefsAdvanced : PrefsClient
{
	IBOutlet id ac_ff; // aircrack fudge factor
	IBOutlet id bf_interval; // beacon flood interval
	IBOutlet id pr_interval; //deauthenticate interval
	IBOutlet id kismetserverip; // Kismet server IP
	IBOutlet id kismetserverport; // Kismet server port
	IBOutlet id show_debugmenu;
}

-(IBAction)setDefaults:(id)sender;
@end
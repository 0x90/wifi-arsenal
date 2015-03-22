//
//  PrefsTraffic.h
//  KisMAC
//
//  Created by mick on Tue Sep 16 2003.
//  Copyright (c) 2003 __MyCompanyName__. All rights reserved.
//

#import <AppKit/AppKit.h>

#import "PrefsClient.h"

@interface PrefsTraffic : PrefsClient {
    IBOutlet NSButton* _showSSID;
    IBOutlet NSButton* _showBSSID;
    IBOutlet NSTextField *_avgSignalTime;
}

@end

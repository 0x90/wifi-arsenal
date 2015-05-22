//
//  PrefsSleep.h
//  KisMAC
//
//  Created by Michael Thole on Mon Jan 20 2003.
//  Copyright (c) 2003 Michael Thole. All rights reserved.
//

#import <AppKit/AppKit.h>

#import <sys/sysctl.h>

#import "PrefsClient.h"

@interface PrefsSleep : PrefsClient
{
    IBOutlet id aNoSleep;
}

@end

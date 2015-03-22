//
//  PrefsSounds.h
//  KisMAC
//
//  Created by Michael Thole on Mon Jan 20 2003.
//  Copyright (c) 2003 Michael Thole. All rights reserved.
//

#import <AppKit/AppKit.h>

#import "PrefsClient.h"

@interface PrefsSounds : PrefsClient
{
    IBOutlet id aWEPSounds;
    IBOutlet id aNOWEPSounds;
    IBOutlet id aVoices;
    IBOutlet id aGeigerSounds;
    IBOutlet id aGeigerSensity;    
	IBOutlet id useSounds;
}

- (IBAction)playVoice:(id)sender;
- (IBAction)playSound:(id)sender;

- (BOOL)updateDictionary;

@end

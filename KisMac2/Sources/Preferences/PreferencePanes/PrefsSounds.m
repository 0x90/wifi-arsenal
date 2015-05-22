//
//  PrefsSounds.m
//  KisMAC
//
//  Created by Michael Thole on Mon Jan 20 2003.
//  Copyright (c) 2003 Michael Thole. All rights reserved.
//

#import "PrefsSounds.h"
#import "PrefsController.h"
#import "WaveHelper.h"

@implementation PrefsSounds


- (void)updateUI
{
    short numOfVoices;
    long voiceIndex;
    VoiceDescription theVoiceDesc;
    NSString *voiceName;
    VoiceSpec theVoiceSpec;

    NSEnumerator* sounds;
    NSError * error;
    id object;

    CountVoices(&numOfVoices);
    for (voiceIndex = 1; voiceIndex <= numOfVoices; ++voiceIndex)
    {
        GetIndVoice(voiceIndex, &theVoiceSpec);
        GetVoiceDescription(&theVoiceSpec, &theVoiceDesc, sizeof(theVoiceDesc));
        voiceName = @((char*)&(theVoiceDesc.name[1]));
        [aVoices addItemWithTitle:voiceName];
    }

    [aGeigerSensity setIntValue:[[controller objectForKey:@"GeigerSensity"] intValue]];
    if ([aGeigerSensity intValue] < 1)
    {
        [aGeigerSensity setIntValue:1];
    }

    [aGeigerSounds removeAllItems];
    [aWEPSounds removeAllItems];
    [aNOWEPSounds removeAllItems];

    sounds = [[[NSFileManager defaultManager]
               contentsOfDirectoryAtPath:@"/System/Library/Sounds" error: &error] objectEnumerator];

    [aGeigerSounds addItemWithTitle:@"None"];
    [aWEPSounds addItemWithTitle:@"None"];
    [aNOWEPSounds addItemWithTitle:@"None"];

    [[aGeigerSounds menu] addItem:[NSMenuItem separatorItem]];
    [[aWEPSounds menu] addItem:[NSMenuItem separatorItem]];
    [[aNOWEPSounds menu] addItem:[NSMenuItem separatorItem]];

    while ((object = [sounds nextObject]) != nil)
    {
        [aGeigerSounds addItemWithTitle:[object stringByDeletingPathExtension]];
        [aWEPSounds addItemWithTitle:[object stringByDeletingPathExtension]];
        [aNOWEPSounds addItemWithTitle:[object stringByDeletingPathExtension]];
    }

    if([controller objectForKey:@"GeigerSound"] == nil || [controller objectForKey:@"WEPSound"] == nil ||
       [controller objectForKey:@"noWEPSound"] == nil)
    {
        [controller setObject:@"None" forKey:@"WEPSound"];
        [controller setObject:@"None" forKey:@"noWEPSound"];
        [controller setObject:@"None" forKey:@"GeigerSound"];
		[controller setObject:[NSNumber numberWithBool:TRUE] forKey:@"playCrackSounds"];
    }
    
    [aGeigerSounds selectItemWithTitle:[controller objectForKey:@"GeigerSound"]];
    [aWEPSounds selectItemWithTitle:[controller objectForKey:@"WEPSound"]];
    [aNOWEPSounds selectItemWithTitle:[controller objectForKey:@"noWEPSound"]];
	[useSounds setState:[[controller objectForKey:@"playCrackSounds"] intValue]];

    [aVoices selectItemAtIndex:[[controller objectForKey:@"Voice"] intValue]];
}

- (BOOL)updateDictionary
{
    [aGeigerSensity validateEditing];
    [controller setObject:@([aGeigerSensity intValue]) forKey:@"GeigerSensity"];

    return YES;
}

- (IBAction)setValueForSender:(id)sender
{
    if(sender == aVoices)
    {
        [self playVoice:sender];
        [controller setObject:[NSNumber numberWithInt:[sender indexOfSelectedItem]] forKey:@"Voice"];
    }
    else if(sender == aWEPSounds)
    {
        [self playSound:sender];
        [controller setObject:[sender titleOfSelectedItem] forKey:@"WEPSound"];
    }
    else if(sender == aNOWEPSounds)
    {
        [self playSound:sender];
        [controller setObject:[sender titleOfSelectedItem] forKey:@"noWEPSound"];
    }
    else if(sender == aGeigerSounds)
    {
        [self playSound:sender];
        [controller setObject:[sender titleOfSelectedItem] forKey:@"GeigerSound"];
    }
    else if (sender == aGeigerSensity)
    {
        [controller setObject:@([sender intValue]) forKey:@"GeigerSensity"];
    }
    else if (sender == useSounds)
    {
        [controller setObject:[NSNumber numberWithBool:[sender state]] forKey:@"playCrackSounds"];
    }
    else
    {
        DBNSLog(@"Error: Invalid sender(%@) in setValueForSender:",sender);
    }
}

#pragma mark -

- (IBAction)playSound:(id)sender
{
    [[NSSound soundNamed:[sender titleOfSelectedItem]] play];
}

- (IBAction) playVoice:(id)sender
{
    NSString *cSentence = @"Found network. SSID is TEST.";
    if ([sender indexOfSelectedItem] > 0)
    {
        [WaveHelper speakSentence:(__bridge CFStringRef)(cSentence) withVoice:[sender indexOfSelectedItem]];
    }
}

@end

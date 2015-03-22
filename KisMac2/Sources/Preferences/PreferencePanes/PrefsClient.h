//
//  PrefsClient.h
//  KisMAC
//
//  Created by Michael Thole on Mon Jan 20 2003.
//  Copyright (c) 2003 Michael Thole. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>

@class PrefsController;

@interface PrefsClient : NSObject {
    IBOutlet NSView* controlBox;

    PrefsController* controller;
}

- (void)setController:(id)newController;

-(void)updateUI;
-(BOOL)updateDictionary;
-(IBAction)setValueForSender:(id)sender;

- (NSView*)controlBox;

@end

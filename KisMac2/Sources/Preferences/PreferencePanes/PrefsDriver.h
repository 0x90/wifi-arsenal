//
//  PrefsDriver.h
//  KisMAC
//
//  Created by Michael Thole on Mon Jan 20 2003.
//  Copyright (c) 2003 Michael Thole. All rights reserved.
//

#import <AppKit/AppKit.h>

#import "PrefsClient.h"

@interface PrefsDriver : PrefsClient
{
    IBOutlet NSTextField    *_frequence;
    IBOutlet NSTextField    *_firstChannel;
    IBOutlet NSMatrix       *_channelSel;
    IBOutlet NSButton       *_selAll;
    IBOutlet NSButton       *_selNone;
	
    IBOutlet NSButton       *_injectionDevice;
    
    IBOutlet NSPopUpButton  *_driver;
    IBOutlet NSButton       *_removeDriver;
    IBOutlet NSTableView    *_driverTable;

    IBOutlet NSMatrix       *_dumpFilter;
    IBOutlet NSTextField    *_dumpDestination;
	
	IBOutlet NSTextField	*_kismet_host;
	IBOutlet NSTextField	*_kismet_port;
    	
	IBOutlet NSBox			*_chanhop;
	IBOutlet NSBox			*_kdrone_settings;
	IBOutlet NSBox			*_injection;
	IBOutlet NSBox			*_dumpFilterBox;
	IBOutlet NSBox			*_savedumpsat;
	IBOutlet NSBox			*_globalsettings;
}

- (IBAction)selAddDriver:(id)sender;
- (IBAction)selRemoveDriver:(id)sender;

- (IBAction)selAll:(id)sender;
- (IBAction)selNone:(id)sender;

@end

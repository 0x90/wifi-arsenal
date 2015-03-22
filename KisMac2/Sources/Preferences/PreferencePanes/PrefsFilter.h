//
//  PrefsFilter.h
//  KisMAC
//
//  Created by mick on Tue Sep 16 2003.
//  Copyright (c) 2003 __MyCompanyName__. All rights reserved.
//

#import <AppKit/AppKit.h>

#import "PrefsClient.h"

@interface PrefsFilter : PrefsClient {
    IBOutlet NSButton* _addItem;
    IBOutlet NSButton* _removeItem;
    IBOutlet NSTextField* _newItem;
    IBOutlet NSTableView* _bssidTable;
}

- (IBAction)addItem:(id)sender;
- (IBAction)removeItem:(id)sender;

@end

/*
        
        File:			PrefsController.h
        Program:		KisMAC
	Author:			Michael Thole
	Description:		KisMAC is a wireless stumbler for MacOS X.
                
        This file is part of KisMAC.

    KisMAC is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License, version 2,
    as published by the Free Software Foundation;

    KisMAC is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with KisMAC; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#import <Cocoa/Cocoa.h>

@class PrefsClient;
@class PrefsWindow;

#define defaults	[NSUserDefaults standardUserDefaults]

@interface PrefsController : NSObject <NSToolbarDelegate>
{
    IBOutlet PrefsWindow* prefsWindow;
    IBOutlet NSBox* prefsBox;

    NSMutableDictionary* changesDict;
    PrefsClient* currentClient;
    NSToolbarItem* defaultToolbarItem;
    NSToolbarItem* currentToolbarItem;

    NSToolbar* prefsToolbar;
    NSMutableDictionary* toolbarItems;
    NSMutableDictionary* nibNamesDict;
    NSMutableDictionary* classNamesDict;
}

- (id)objectForKey:(NSString*)key;
- (void)setObject:(id)object forKey:(NSString*)key;

- (IBAction)refreshUI:(id)sender;

- (IBAction)clickOk:(id)sender;
- (IBAction)clickCancel:(id)sender;
- (void)changeView:(NSToolbarItem*)sender;

- (NSArray *)toolbarDefaultItemIdentifiers:(NSToolbar*)toolbar;
- (NSArray *)toolbarAllowedItemIdentifiers:(NSToolbar*)toolbar;

- (NSWindow*)window;

@end


@interface NSToolbar (KnownPrivateMethods)
- (NSView*)_toolbarView;
@end
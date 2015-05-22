/*
        
        File:			PrefsController.m
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
#import "PrefsController.h"
#import "KisMACNotifications.h"
#import "PrefsWindow.h"
#import "PrefsClient.h"

void addToolbarItem(NSMutableDictionary *theDict,NSString *identifier,NSString *label,NSString *paletteLabel,NSString *toolTip,id target,SEL settingSelector, id itemContent,SEL action, NSMenu * menu)
{
    NSMenuItem *mItem;
    // here we create the NSToolbarItem and setup its attributes in line with the parameters
    NSToolbarItem *item = [[NSToolbarItem alloc] initWithItemIdentifier:identifier];
    [item setLabel:label];
    [item setPaletteLabel:paletteLabel];
    [item setToolTip:toolTip];
    [item setTarget:target];
    // the settingSelector parameter can either be @selector(setView:) or @selector(setImage:).  Pass in the right
    // one depending upon whether your NSToolbarItem will have a custom view or an image, respectively
    // (in the itemContent parameter).  Then this next line will do the right thing automatically.
	//[item performSelector:settingSelector withObject:itemContent];
	NSMethodSignature *methodSignature = [item methodSignatureForSelector:settingSelector];
	NSInvocation *invocation = [NSInvocation invocationWithMethodSignature:methodSignature];
	[invocation setSelector:settingSelector];
	[invocation setArgument:&itemContent atIndex:2];
	[invocation invokeWithTarget:item];
    [item setAction:action];
    // If this NSToolbarItem is supposed to have a menu "form representation" associated with it (for text-only mode),
    // we set it up here.  Actually, you have to hand an NSMenuItem (not a complete NSMenu) to the toolbar item,
    // so we create a dummy NSMenuItem that has our real menu as a submenu.
    if (menu!=nil)
    {
        // we actually need an NSMenuItem here, so we construct one
        mItem=[[NSMenuItem alloc] init];
        [mItem setSubmenu: menu];
        [mItem setTitle: [menu title]];
        [item setMenuFormRepresentation:mItem];
    }
    // Now that we've setup all the settings for this new toolbar item, we add it to the dictionary.
    // The dictionary retains the toolbar item for us, which is why we could autorelease it when we created
    // it (above).
    theDict[identifier] = item;
}

@implementation PrefsController

- (id)init {
	self = [super init];
	
    prefsToolbar=[[NSToolbar alloc] initWithIdentifier:@"prefsToolbar"];
    [prefsToolbar setDelegate:self];
    [prefsToolbar setAllowsUserCustomization:NO];
    
    toolbarItems = [[NSMutableDictionary alloc] init];
    nibNamesDict = [[NSMutableDictionary alloc] init];
    classNamesDict = [[NSMutableDictionary alloc] init];
    
    nibNamesDict[@"Scanning"] = @"PrefsScanning";
    classNamesDict[@"Scanning"] = @"PrefsScanning";
    addToolbarItem(toolbarItems,
                   @"Scanning",
                   @"Scanning",
                   @"Scanning",
                   @"Scanning Options",
                   self,
                   @selector(setImage:),
                   [NSImage imageNamed:@"preferences-scan"],
                   @selector(changeView:),
                   nil);
    defaultToolbarItem = toolbarItems[@"Scanning"];

    nibNamesDict[@"Traffic"] = @"PrefsTraffic";
    classNamesDict[@"Traffic"] = @"PrefsTraffic";
    addToolbarItem(toolbarItems,
                   @"Traffic",
                   @"Traffic",
                   @"Traffic",
                   @"Traffic View Options",
                   self,
                   @selector(setImage:),
                   [NSImage imageNamed:@"preferences-graph"],
                   @selector(changeView:),
                   nil);

    nibNamesDict[@"Filter"] = @"PrefsFilter";
    classNamesDict[@"Filter"] = @"PrefsFilter";
    addToolbarItem(toolbarItems,
                   @"Filter",
                   @"Filter",
                   @"Filter",
                   @"Filter Options for Data Capture",
                   self,
                   @selector(setImage:),
                   [NSImage imageNamed:@"preferences-filter"],
                   @selector(changeView:),
                   nil);


    nibNamesDict[@"Sounds"] = @"PrefsSounds";
    classNamesDict[@"Sounds"] = @"PrefsSounds";
    addToolbarItem(toolbarItems,
                   @"Sounds",
                   @"Sounds",
                   @"Sounds",
                   @"Sounds and Speech Options",
                   self,
                   @selector(setImage:),
                   [NSImage imageNamed:@"preferences-sound"],
                   @selector(changeView:),
                   nil);

    nibNamesDict[@"Driver"] = @"PrefsDriver";
    classNamesDict[@"Driver"] = @"PrefsDriver";
    addToolbarItem(toolbarItems,
                   @"Driver",
                   @"Driver",
                   @"Driver",
                   @"Wireless Card Driver",
                   self,
                   @selector(setImage:),
                   [NSImage imageNamed:@"preferences-driver"],
                   @selector(changeView:),
                   nil);

    nibNamesDict[@"GPS"] = @"PrefsGPS";
    classNamesDict[@"GPS"] = @"PrefsGPS";
    addToolbarItem(toolbarItems,
                   @"GPS",
                   @"GPS",
                   @"GPS",
                   @"GPS Options",
                   self,
                   @selector(setImage:),
                   [NSImage imageNamed:@"preferences-gps"],
                   @selector(changeView:),
                   nil);
    nibNamesDict[@"Map"] = @"PrefsMap";
    classNamesDict[@"Map"] = @"PrefsMap";
    addToolbarItem(toolbarItems,
                   @"Map",
                   @"Map",
                   @"Map",
                   @"Mapping Options",
                   self,
                   @selector(setImage:),
                   [NSImage imageNamed:@"preferences-map"],
                   @selector(changeView:),
                   nil);
	
	/*nibNamesDict[@"Advanced"] = @"PrefsAdvanced";
    classNamesDict[@"Advanced"] = @"PrefsAdvanced";
    addToolbarItem(toolbarItems,
                   @"Advanced",
                   @"Advanced",
                   @"Advanced",
                   @"Advanced Options",
                   self,
                   @selector(setImage:),
                   [NSImage imageNamed:@"EnergySaver"],
                   @selector(changeView:),
                   nil);*/

    changesDict = [[NSMutableDictionary alloc] init];
    
    return self;
}

- (void)awakeFromNib {
    [prefsWindow setTitle:@"KisMAC Preferences"];
    [prefsWindow setToolbar:prefsToolbar];
    [prefsWindow center];
    [self changeView:defaultToolbarItem];
}

#pragma mark -

- (void)changeView:(NSToolbarItem*)sender 
{
    int i, count;
    NSString* nibName = nil;
    NSString* className = nil;
    NSArray* itemsArray = [prefsToolbar items];
    NSView* contentView, *oldView, *controlBox;
    NSRect controlBoxFrame;
    NSRect windowFrame;
    int newWindowHeight;
    NSRect newWindowFrame;

    // TODO make this more error proof

    if(currentToolbarItem == sender) {
        [currentClient updateUI];
        return;
    }
    
    count = [itemsArray count];

    if (currentClient&&(![currentClient updateDictionary])) return;
    
    for(i = 0 ; i < count ; ++i) {
        if([[itemsArray[i] itemIdentifier] isEqualToString:[sender itemIdentifier]]) {
            nibName = nibNamesDict[[itemsArray[i] itemIdentifier]];
            className = classNamesDict[[itemsArray[i] itemIdentifier]];
            currentToolbarItem = sender;
            break;
        }
    }

    contentView = [prefsBox contentView];
    oldView = [[contentView subviews] lastObject];
    [oldView removeFromSuperview];

    currentClient = [[[[NSBundle mainBundle] classNamed:className] alloc] init];
    [currentClient setController:defaults];
    
    [[NSBundle mainBundle] loadNibNamed:nibName owner:currentClient topLevelObjects:nil];

    controlBox = [currentClient controlBox];
    controlBoxFrame = controlBox != nil ? [controlBox frame] : NSZeroRect;

    windowFrame = [NSWindow contentRectForFrameRect:[prefsWindow frame] styleMask:[prefsWindow styleMask]];
    newWindowHeight = NSHeight(controlBoxFrame) + 10;
    newWindowHeight += NSHeight([[prefsToolbar _toolbarView] frame]);
    //newWindowHeight += 43;
    newWindowFrame = [NSWindow frameRectForContentRect:NSMakeRect(NSMinX(windowFrame), NSMaxY(windowFrame) - newWindowHeight, NSWidth(windowFrame), newWindowHeight) styleMask:[prefsWindow styleMask]];
    [prefsWindow setFrame:newWindowFrame display:YES animate:[prefsWindow isVisible]];    
    [controlBox setFrameOrigin:NSMakePoint(floor((NSWidth([contentView frame]) - NSWidth(controlBoxFrame)) / 2.0),
                                           floor(NSHeight([contentView frame]) - NSHeight(controlBoxFrame)))];
    
    [currentClient updateUI];
    [contentView addSubview:controlBox];
    
    [[NSNotificationCenter defaultCenter] postNotificationName:KisMACUserDefaultsChanged object:self];
}

#pragma mark -


- (NSArray *)toolbarDefaultItemIdentifiers:(NSToolbar*)toolbar {
    return @[@"Scanning", @"Filter", @"Sounds", @"Driver", @"GPS", @"Map", @"Traffic", @"Advanced"];
}

- (NSArray *)toolbarAllowedItemIdentifiers:(NSToolbar*)toolbar {
    return [self toolbarDefaultItemIdentifiers:toolbar];
}

- (NSToolbarItem *)toolbar:(NSToolbar *)toolbar itemForItemIdentifier:(NSString *)itemIdentifier willBeInsertedIntoToolbar:(BOOL)flag
{
    // We create and autorelease a new NSToolbarItem, and then go through the process of setting up its
    // attributes from the master toolbar item matching that identifier in our dictionary of items.
    NSToolbarItem *newItem = [[NSToolbarItem alloc] initWithItemIdentifier:itemIdentifier];
    NSToolbarItem *item = nil;

    item=toolbarItems[itemIdentifier];

    [newItem setLabel:[item label]];
    [newItem setPaletteLabel:[item paletteLabel]];
    if ([item view]!=nil)
    {
        [newItem setView:[item view]];
    }
    else
    {
        [newItem setImage:[item image]];
    }
    [newItem setToolTip:[item toolTip]];
    [newItem setTarget:[item target]];
    [newItem setAction:[item action]];
    [newItem setMenuFormRepresentation:[item menuFormRepresentation]];
    // If we have a custom view, we *have* to set the min/max size - otherwise, it'll default to 0,0 and the custom
    // view won't show up at all!  This doesn't affect toolbar items with images, however.
    if ([newItem view]!=nil)
    {
        [newItem setMinSize:[[item view] bounds].size];
        [newItem setMaxSize:[[item view] bounds].size];
    }
    return newItem;
}

#pragma mark -

- (id)objectForKey:(NSString*)key {
    id object = changesDict[key];
    if(object) return object;
    
    object = [defaults objectForKey:key];
    if(!object) DBNSLog(@"Error: -[PrefsController objectForKey:%@] returning NULL!", key);
    return object;
}

- (void)setObject:(id)object forKey:(NSString*)key {
    changesDict[key] = object;
}

- (NSWindow*)window {
    return prefsWindow;
}

#pragma mark -

- (IBAction)refreshUI:(id)sender {
    [currentClient updateUI];
}

- (IBAction)clickOk:(id)sender
{
    if (![currentClient updateDictionary]) return;
    
    [prefsWindow close];
    [changesDict removeAllObjects];
    [currentClient updateUI];
}

- (IBAction)clickCancel:(id)sender {
    [prefsWindow close];
    [changesDict removeAllObjects];
    [currentClient updateUI];
}

- (BOOL)windowShouldClose:(id)sender {
    return [currentClient updateDictionary];
}

- (void)windowWillClose:(NSNotification *)aNotification {
    [currentClient updateDictionary];
    [defaults synchronize];
    [[NSNotificationCenter defaultCenter] postNotificationName:KisMACUserDefaultsChanged object:self];
}

#pragma mark -


@end
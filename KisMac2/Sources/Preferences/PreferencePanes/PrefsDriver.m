//
//  PrefsDriver.m
//  KisMAC
//
//  Created by Michael Thole on Mon Jan 20 2003.
//  Copyright (c) 2003 Michael Thole. All rights reserved.
//

#import "PrefsDriver.h"
#import "PrefsController.h"
#import "WaveHelper.h"
#import "WaveDriver.h"
#import "WaveDriverAirportExtreme.h"

@implementation PrefsDriver


//updates the driverlist, ignoring multiple drivers, which are allowed to be selected only once
- (void)updateDrivers
{
    NSArray *drivers;
    int i = 0;
    unsigned int j;
    NSString *s;
    Class c;
    
    [_driver removeAllItems];
    drivers = [controller objectForKey:@"ActiveDrivers"];
    
    while (WaveDrivers[i][0])
	{
        s = @(WaveDrivers[i]);
        for (j = 0 ; j < [drivers count] ; ++j)
		{
            c = NSClassFromString(s);
            
            //check if device exists
            if ([drivers[j][@"driverID"] isEqualToString:s])
				break;

            //check if device is in use by some other driver, which is already loaded
            if ([drivers[j][@"deviceName"] isEqualToString:[c deviceName]])
				break;
        }
        c = NSClassFromString(s);
        
        if (j == [drivers count] || [c allowsMultipleInstances])
		{
            [_driver addItemWithTitle:[NSClassFromString(s) description]];
            [[_driver lastItem] setTag:i];
        }
        ++i;
    }
}

- (Class) getCurrentDriver
{
    NSDictionary *d;
    int i = [_driverTable selectedRow];
    
    if (i < 0)
		return Nil;
    
    d = [controller objectForKey:@"ActiveDrivers"][i];
    return NSClassFromString(d[@"driverID"]);
}

- (NSDictionary*) getCurrentSettings
{
	int i = [_driverTable selectedRow];
    
    if ( i < 0 ) return nil;
    
    return [controller objectForKey:@"ActiveDrivers"][i];
}

- (void) updateSettings
{
    bool enableAll = NO;
    bool enableChannel = NO;
    bool enableInjection = NO;
    bool enableDumping = NO;
	bool enableIPAndPort = NO;
    Class driverClass;
    NSDictionary *d = nil;
    unsigned int x, y;
    int val, startCorrect = 0;
    
    [_frequence     setFloatValue:  [[controller objectForKey:@"frequence"   ] floatValue]];

    if ([_driverTable numberOfSelectedRows])
	{
        d = [self getCurrentSettings];
        enableAll = YES;

        driverClass = [self getCurrentDriver];
        if ([driverClass allowsChannelHopping])
			enableChannel = YES;
        
		if ([driverClass allowsInjection])
			enableInjection = YES;
        
		if ([driverClass type] == passiveDriver)
			enableDumping = YES;
		
		if ([driverClass wantsIPAndPort])
			enableIPAndPort = YES;
		
		if (enableIPAndPort)
		{
			[_chanhop setHidden:true];
			[_kdrone_settings setHidden:false];
			[_kismet_host setStringValue:d[@"kismetserverhost"]];
			[_kismet_port setIntValue:[d[@"kismetserverport"] intValue]];
		}
		else
		{
			[_chanhop setHidden:false];
			[_kdrone_settings setHidden:true];
		}
    }
    
    [_removeDriver		setEnabled:enableAll];
    [_selAll			setEnabled:enableChannel];
    [_selNone			setEnabled:enableChannel];
    [_channelSel		setEnabled:enableChannel];
    [_firstChannel		setEnabled:enableChannel];
    [_dumpDestination	setEnabled:enableDumping];
    [_dumpFilter		setEnabled:enableDumping];
    [_injectionDevice	setEnabled:enableInjection];
	
    if (!enableInjection) {
		[_injectionDevice setTitle:@"Injection Not Supported"];
    }else
        [_injectionDevice setTitle:@"use as primary device"];
    
    if (enableChannel)
	{
        [_firstChannel  setIntValue:    [d[@"firstChannel"] intValue]];

        for ( x = 0 ; x < 2 ; ++x )
            for ( y = 0 ; y < 7 ; ++y)
			{
                val = [d[[NSString stringWithFormat:@"useChannel%.2i",(x*7+y+1)]] boolValue] ? NSOnState : NSOffState;
                [[_channelSel cellAtRow:y column:x] setState:val];
                
				if (x*7+y+1 == [_firstChannel intValue])
					startCorrect = val;
            }
        
        if (startCorrect == 0) {
            for (x = 0 ; x < 2 ; ++x)
			{
                for (y = 0; y < 7; ++y)
				{
                    val = [d[[NSString stringWithFormat:@"useChannel%.2i",(x*7+y+1)]] boolValue] ? NSOnState : NSOffState;
                    if (val)
					{
                        [_firstChannel setIntValue:x*7+y+1];
                        break;
                    }
                }
                if (y != 7)
					break;
            }
        }
    } else {
        for (x = 0 ; x < 2 ; ++x)
            for (y = 0 ; y < 7 ; ++y)
                [[_channelSel cellAtRow:y column:x] setState:NSOffState];

        
        [_firstChannel  setIntValue:   1];
    }
    
    if (enableInjection) {
        [_injectionDevice setState: [d[@"injectionDevice"] intValue]];
    } else {
        [_injectionDevice setState: NSOffState];
    }
    
    if (enableDumping)
	{
       [_dumpDestination	setStringValue:d[@"dumpDestination"]];
       [_dumpFilter			selectCellAtRow:[d[@"dumpFilter"] intValue] column:0];
       [_dumpDestination	setEnabled:[d[@"dumpFilter"] intValue] ? YES : NO];
    }
	else
	{
       [_dumpDestination	setStringValue:@"~/DumpLog %y-%m-%d %H:%M"];
       [_dumpFilter			selectCellAtRow:0 column:0];
       [_dumpDestination	setEnabled:NO];
    }
}

- (BOOL)updateInternalSettings:(BOOL)warn
{
    NSMutableDictionary *d;
    NSMutableArray *a;
    WaveDriver *wd;
    int i = [_driverTable selectedRow];
    int val = 0, startCorrect = 0;
    unsigned int x, y;
	
    [controller setObject:@([_frequence     floatValue])    forKey:@"frequence"];
    if (i < 0)
		return YES;
    
	d = [[self getCurrentSettings] mutableCopy];
    if (!d)
		return YES;
    
    if ([[self getCurrentDriver] allowsChannelHopping])
	{
        for (x = 0 ; x < 2 ; ++x)
            for (y = 0; y < 7; ++y)
			{
                val+=[[_channelSel cellAtRow:y column:x] state];
                if (x*7+y+1 == [_firstChannel intValue]) startCorrect = [[_channelSel cellAtRow:y column:x] state];
            }    
        
        if (warn && (val == 0 || startCorrect == 0))
		{
            NSRunAlertPanel(NSLocalizedString(@"Invalid Option", "Invalid channel selection failure title"),
                            NSLocalizedString(@"Invalid channel selection failure title", "LONG Error description"),
                            //@"You have to select at least one channel, otherwise scanning makes no sense. Also please make sure that you have selected "
                            //"a valid start channel.",
                            OK,nil,nil);
            return NO;
        }
    }

    for (x = 0 ; x < 2 ; ++x)
        for (y = 0 ; y < 7 ; ++y)
		{
            val = [[_channelSel cellAtRow:y column:x] state];
            d[[NSString stringWithFormat:@"useChannel%.2i",(x*7+y+1)]] = [NSNumber numberWithBool: val ? YES : NO];
        }
    
    d[@"firstChannel"]		= @([_firstChannel  intValue]);
    
    d[@"injectionDevice"]	= [NSNumber numberWithBool:  [_injectionDevice state] ? YES : NO];
    
    d[@"dumpDestination"]	= [_dumpDestination stringValue];
    d[@"dumpFilter"]		= [NSNumber numberWithInt:[_dumpFilter selectedRow]];
    
	d[@"kismetserverhost"]	= [_kismet_host stringValue];
	d[@"kismetserverport"]	= @([_kismet_port intValue]);
	
    a = [[controller objectForKey:@"ActiveDrivers"] mutableCopy];
    a[i] = d;
    [controller setObject:a forKey:@"ActiveDrivers"];
    
    wd = [WaveHelper driverWithName:d[@"deviceName"]];
    [wd setConfiguration:d];
    
    return YES;
}

#pragma mark -

- (int)numberOfRowsInTableView:(NSTableView *)aTableView
{
    return [[controller objectForKey:@"ActiveDrivers"] count];
}

- (id) tableView:(NSTableView *) aTableView objectValueForTableColumn:(NSTableColumn *) aTableColumn row:(int) rowIndex
{
    return [NSClassFromString([controller objectForKey:@"ActiveDrivers"][rowIndex][@"driverID"]) description]; 
}

- (void)tableViewSelectionDidChange:(NSNotification *)notification
{
    [self updateSettings];
}

- (BOOL)tableView:(NSTableView *)tableView shouldSelectRow:(int)row
{
    return [self updateInternalSettings:YES];
}

#pragma mark -

- (void)updateUI
{
    [self updateDrivers];
    [self updateSettings];
}

- (BOOL)updateDictionary
{
    return [self updateInternalSettings:YES];
}

- (IBAction)setValueForSender:(id)sender
{
    [self updateInternalSettings:NO];
    [self updateSettings];
}

#pragma mark -

- (IBAction)selAddDriver:(id)sender
{
    NSMutableArray *drivers;
    NSString *driverClassName;
	NSNumber *kserverport;
    
    driverClassName = @(WaveDrivers[[[_driver selectedItem] tag]]);
    
	if ([driverClassName isEqualToString:@"WaveDriverKismet"]) {
		kserverport = @2501;
	} else if ([driverClassName isEqualToString:@"WaveDriverKismetDrone"]) {
		kserverport = @3501;
	} else {
		kserverport = @0;
	}
	
    drivers = [[controller objectForKey:@"ActiveDrivers"] mutableCopy];
    [drivers addObject:@{
		@"driverID":			driverClassName,
        @"firstChannel":		@1,
        @"useChannel01":		@YES,
        @"useChannel02":		@YES,
        @"useChannel03":		@YES,
        @"useChannel04":		@YES,
        @"useChannel05":		@YES,
        @"useChannel06":		@YES,
        @"useChannel07":		@YES,
        @"useChannel08":		@YES,
        @"useChannel09":		@YES,
        @"useChannel10":		@YES,
        @"useChannel11":		@YES,
        @"useChannel12":		@NO,
        @"useChannel13":		@NO,
        @"useChannel14":		@NO,
        @"injectionDevice":		@0,
        @"dumpFilter":			@0,
        @"dumpDestination":		@"~/DumpLog %y-%m-%d %H:%M",
        @"deviceName":			[NSClassFromString(driverClassName) deviceName], //todo make this unique for ever instance
		@"kismetserverhost":	@"127.0.0.1",
		@"kismetserverport":	kserverport}
	 ];
    [controller setObject:drivers forKey:@"ActiveDrivers"];
    
    [_driverTable reloadData];
    [_driverTable selectRowIndexes:[NSIndexSet indexSetWithIndex:[drivers count]-1]
              byExtendingSelection:NO];
	[self updateUI];
}

- (IBAction)selRemoveDriver:(id)sender
{
    int i;
    NSMutableArray *drivers;
    
    i = [_driverTable selectedRow];
    if (i < 0)
		return;
    
    drivers = [[controller objectForKey:@"ActiveDrivers"] mutableCopy];
    [drivers removeObjectAtIndex:i];
    [controller setObject:drivers forKey:@"ActiveDrivers"];    
    
    [_driverTable reloadData];
    [self updateUI];
}

- (IBAction)selAll:(id)sender
{
    [_channelSel selectAll:self];
    [self setValueForSender:_channelSel];
}

- (IBAction)selNone:(id)sender
{
    [_channelSel deselectAllCells];
    [self setValueForSender:_channelSel];
}


@end

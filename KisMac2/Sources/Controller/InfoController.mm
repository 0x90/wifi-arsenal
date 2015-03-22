/*
        
        File:			InfoController.mm
        Program:		KisMAC
	Author:			Michael Roßberg
				mick@binaervarianz.de
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
#import "InfoController.h"
#import "WaveClient.h"
#import "WaveHelper.h"
#import "WaveNet.h"

enum _rowIndexes {
    indexSSID,
    indexBSSID,
    indexVendor,
    indexFirstSeen,
    indexLastSeen,
    indexEmptyLine1,
    indexChannel,
    indexOriginalChannel,
	indexSupportedDataRates,
    indexSignal,
    indexMaxSignal,
    indexAvgSignal,
    indexType,
    indexEncryption,
//    indexIPAddress,
    indexEmptyLine3,
    indexPackets,
    indexDataPackets,
    indexMgmtPackets,
    indexCtrlPackets,
    indexWeakPackets,
	indexInjPackets,
    indexBytes,
    indexKey,
	indexASCIIKey, // Added for potential real password by DerNalia
    indexLastIV, 
    indexEmptyLine2,
    indexLatitude,
    indexLongitude,
    indexElevation
};

@implementation InfoController

- (void)awakeFromNib
{
    _clientCount = 0;
    [aShortTable setHeaderView:nil];
	[aClientTable setDoubleAction:@selector(trackClient:)];
}

- (void)setDetails:(bool)visible {
    aDetailsPane=visible;
}

- (void)reloadData
{
    unsigned int i;
    
    if (aDetailsPane) [aShortTable displayRect:[aShortTable rectOfColumn:1]];
    else [aTable displayRect:[aTable rectOfColumn:1]];
    
    if (_lastSorted) [_n sortByColumn:_lastSorted order:_ascending];

    if (_clientCount == [aClients count]) {
        for (i = 0; i < [aClients count]; ++i) {
            if ([aClients[aClientKeys[i]] changed]) 
                [aClientTable displayRect:[aClientTable rectOfRow:i]];
        }
    } else {
        [aClientTable noteNumberOfRowsChanged];
        _clientCount = [aClients count];
    }
}

- (IBAction)showNet:(id)sender
{
    [_commentField validateEditing];
    [_n setComment:[_commentField stringValue]];
    
    //release old data
	aClients = nil;
	aClientKeys = nil;
	_n = nil;
    
    //fetch all new interesting stuff
    _n=sender;
    aClients=[_n getClients];
    aClientKeys=[_n getClientKeys];
    
    //refresh
    [aTable reloadData];
    [aClientTable reloadData];
    [aShortTable reloadData];
    if ([_n comment]) [_commentField setStringValue:[_n comment]];
    else  [_commentField setStringValue:@""];
}

- (IBAction)commentChanged:(id)sender
{
    [_n setComment:[sender stringValue]];
}

#pragma mark -

- (id)tableView:(NSTableView *)aTableView objectValueForTableColumn:(NSTableColumn *)aTableColumn row:(int)rowIndex
{ 
    int col;
    NSString *key;
    WaveClient *lWCl;
    
    if ([aTableView isEqualTo:aTable])
	{
        if ([[aTableColumn identifier] isEqualToString:@"key"]) col=1;
        else col=0;
    
        //TODO show only interesting things
        switch(rowIndex) {
            case indexSSID:
                 return (col) ? NSLocalizedString(@"SSID", "table description") : [_n SSID];
            case indexBSSID:
                 return (col) ? NSLocalizedString(@"BSSID", "table description") : [_n BSSID];
            case indexVendor:
                 return (col) ? NSLocalizedString(@"Vendor", "table description") : [_n getVendor];
            case indexFirstSeen:
                 return (col) ? NSLocalizedString(@"First Seen", "table description") : [_n firstDate];
            case indexLastSeen:
                 return (col) ? NSLocalizedString(@"Last Seen", "table description") : [_n date];
            case indexEmptyLine1:
                 return @"";
            case indexChannel:
                 return (col) ? NSLocalizedString(@"Channel", "table description") : [NSString stringWithFormat:@"%i", [_n channel]];
            case indexOriginalChannel:
                 return (col) ? NSLocalizedString(@"Main Channel", "table description") : [NSString stringWithFormat:@"%i", [_n originalChannel]];
            case indexSupportedDataRates:
			     return (col) ? NSLocalizedString(@"Supported Rates", "table description") : [_n rates];
			case indexSignal:
                 return (col) ? NSLocalizedString(@"Signal", "table description") : [NSString stringWithFormat:@"%i", [_n curSignal]];
            case indexMaxSignal:
                 return (col) ? NSLocalizedString(@"MaxSignal", "table description") : [NSString stringWithFormat:@"%i", [_n maxSignal]];
            case indexAvgSignal:
                 return (col) ? NSLocalizedString(@"AvgSignal", "table description") : [NSString stringWithFormat:@"%i", [_n avgSignal]];
            case indexType:
                if (col!=0) return NSLocalizedString(@"Type", "table description");
                else {
                    switch([_n type]) {
                        case networkTypeUnknown: return NSLocalizedString(@"unknown", "table description");
                        case 1: return NSLocalizedString(@"ad-hoc", "table description");
                        case 2: return NSLocalizedString(@"managed", "table description");
                        case 3: return NSLocalizedString(@"tunnel", "table description"); 
                        case 4: return NSLocalizedString(@"probe", "table description");                  
                        case 5: return NSLocalizedString(@"lucent tunnel", "table description");                  
                    }
                }
            case indexEncryption:
                if (col!=0) return NSLocalizedString(@"Encryption", "table description");
                else {
                    switch([_n wep]) {
                        case encryptionTypeUnknown: return NSLocalizedString(@"unknown", "table description");
                        case encryptionTypeNone:    return NSLocalizedString(@"disabled", "table description");
                        case encryptionTypeWEP:     return NSLocalizedString(@"WEP", "table description");
                        case encryptionTypeWEP40:   return NSLocalizedString(@"WEP-40", "table description");
                        case encryptionTypeWPA:     return NSLocalizedString(@"WPA", "table description");
                        case encryptionTypeWPA2:     return NSLocalizedString(@"WPA2", "table description");
                        case encryptionTypeLEAP:    return NSLocalizedString(@"LEAP", "table description");
                    }
                }
                 return @"";
/*  FOR AP IP Detect -- Later
            case indexIPAddress:
                if ([_n getIP]) {
                    DBNSLog(@"Has IP");
                    return (col) ? NSLocalizedString(@"IP Address", "table description") : [NSString stringWithFormat:@"%@", [_n getIP]];
                }
*/  
            case indexEmptyLine3:
                 return @"";
            case indexPackets:
                 return (col) ? NSLocalizedString(@"Packets", "table description") : [NSString stringWithFormat:@"%i", [_n packets]];
            case indexDataPackets:
                 return (col) ? NSLocalizedString(@"Data Packets", "table description") : [NSString stringWithFormat:@"%i", [_n dataPackets]];
            case indexMgmtPackets:
                return (col) ? NSLocalizedString(@"Management Packets", "table description") : [NSString stringWithFormat:@"%i", [_n mgmtPackets]];
            case indexCtrlPackets:
                return (col) ? NSLocalizedString(@"Control Packets", "table description") : [NSString stringWithFormat:@"%i", [_n ctrlPackets]];
            case indexWeakPackets:
                 return (col) ? NSLocalizedString(@"Unique IVs", "table description") : [NSString stringWithFormat:@"%i", [_n uniqueIVs]];
            case indexInjPackets:
                 return (col) ? NSLocalizedString(@"Inj. Packets", "table description") : [NSString stringWithFormat:@"%i", (int)[[_n arpPacketsLog] count]];
            case indexBytes:
                 return (col) ? NSLocalizedString(@"Bytes", "table description") : [_n data];
            case indexKey:
                 return (col) ? NSLocalizedString(@"Key", "table description") : [_n key];
			case indexASCIIKey:
				return (col) ? NSLocalizedString(@"ASCII Key", "table descriptoin") : [_n asciiKey];
            case indexLastIV:
                 return (col) ? NSLocalizedString(@"LastIV", "table description") : [_n lastIV];
            case indexEmptyLine2:
                 return @"";
            case indexLatitude:
                 return (col) ? NSLocalizedString(@"Latitude", "table description") : [_n latitude];
            case indexLongitude:
                 return (col) ? NSLocalizedString(@"Longitude", "table description") : [_n longitude];
            case indexElevation:
		return (col) ? NSLocalizedString(@"Elevation", "GPS status string.") : [_n elevation];
        }
        return @"unknown row";
    }
	else if([aTableView isEqualTo:aClientTable])
	{
        key = aClientKeys[rowIndex];
        lWCl = aClients[key];
        if ([[aTableColumn identifier] isEqualToString:@"client"]) return key;
        else if ([[aTableColumn identifier] isEqualToString:@"vendor"]) return [lWCl vendor];
        else if ([[aTableColumn identifier] isEqualToString:@"lastseen"]) return [lWCl date];
        else if ([[aTableColumn identifier] isEqualToString:@"signal"]) return [NSString stringWithFormat:@"%i", [lWCl curSignal]];
        else if ([[aTableColumn identifier] isEqualToString:@"sent"]) return [lWCl sent];
        else if ([[aTableColumn identifier] isEqualToString:@"received"]) return [lWCl received];
        else if ([[aTableColumn identifier] isEqualToString:@"ipa"]) return [lWCl getIPAddress];
        else return [NSString stringWithFormat: @"unknown column %@", [aTableColumn identifier]];
    }
	else if([aTableView isEqualTo:aShortTable])
	{
        if ([[aTableColumn identifier] isEqualToString:@"key"]) col=1;
        else col=0;
    
        switch(rowIndex) {
            case 0:
                 return (col) ? NSLocalizedString(@"Vendor", "table description") : [_n getVendor];
            case 1:
                 return (col) ? NSLocalizedString(@"First Seen", "table description") : [_n firstDate];
            case 2:
                 return @"";
            case 3:
                 return (col) ? NSLocalizedString(@"Unique IVs", "table description") : [NSString stringWithFormat:@"%i", [_n uniqueIVs]];
            case 4:
                 return (col) ? NSLocalizedString(@"Data Packets", "table description") : [NSString stringWithFormat:@"%i", [_n dataPackets]];
            case 5:
                 return (col) ? NSLocalizedString(@"Bytes", "table description") : [_n data];
            case 6:
                 return (col) ? NSLocalizedString(@"Key", "table description") : [_n key];
            case 7:
                 return (col) ? NSLocalizedString(@"LastIV", "table description") : [_n lastIV];
            case 8:
                 return @"";
            case 9:
                 return (col) ? NSLocalizedString(@"Latitude", "table description") : [_n latitude];
            case 10:
                 return (col) ? NSLocalizedString(@"Longitude", "table description") : [_n longitude];
            case 11:
                 return @"";
            case 12:
                 return (col) ? NSLocalizedString(@"Comment", "table description") : [_n comment];
	    
        }
        return @"unknown row";
    }
    
    return @"unknown table"; 
}

- (int)numberOfRowsInTableView:(NSTableView *)aTableView
{
    if([aTableView isEqualTo:aTable])
        return 29;
    else if([aTableView isEqualTo:aClientTable])
        return [aClientKeys count];
    else if([aTableView isEqualTo:aShortTable])
        return 15;
   return 0;
}

- (void)tableView:(NSTableView*)tableView didClickTableColumn:(NSTableColumn *)tableColumn
{
    NSString *ident = [tableColumn identifier];
    
    if(![tableView isEqualTo:aClientTable]) return;

    if ((_lastSorted) && ([_lastSorted isEqualToString:ident])) {
        if (_ascending) _ascending=NO;
        else {
			_lastSorted = nil;
            
            [tableView setIndicatorImage:nil inTableColumn:tableColumn];
            [tableView setHighlightedTableColumn:nil];
            [tableView reloadData];
            return;
        }
    } else {
        _ascending=YES;
        if (_lastSorted) [tableView setIndicatorImage:nil inTableColumn:[tableView tableColumnWithIdentifier:_lastSorted]];
		_lastSorted = ident;
    }
    
    [_n sortByColumn:ident order:_ascending];

    [tableView setIndicatorImage:[NSImage imageNamed:(_ascending) ? @"NSAscendingSortIndicator" : @"NSDescendingSortIndicator"] inTableColumn:tableColumn];
    
    [tableView setHighlightedTableColumn:tableColumn];
    [tableView reloadData];
}

- (BOOL)tableView:(NSTableView *)aTableView shouldEditTableColumn:(NSTableColumn *)aTableColumn row:(int)rowIndex
{
    if ([aTableView isEqualTo:aShortTable]) {
        if (rowIndex==12)  return YES;	//only the comment field is to be edited
    }
	
    return NO;
}


- (void)tableView:(NSTableView *)aTableView setObjectValue:(id)anObject forTableColumn:(NSTableColumn *)aTableColumn row:(int)rowIndex
{
    if([aTableView isEqualTo:aTable] || [aTableView isEqualTo:aShortTable]) {
        [_n setComment:anObject];	//save the comment
    }
}

#pragma mark -

- (void) dealloc
{
	aClients = nil;
	aClientKeys = nil;
	_n = nil;
}

- (NSString *) theRow 
{
    SInt32 row = [aClientTable selectedRow];
    
	if (row == -1)
    {
        return nil;
    }
	
	return aClientKeys[[aClientTable selectedRow]];
}

@end

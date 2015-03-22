/*
 
 File:			ScanControllerScriptable.m
 Program:		KisMAC
 Author:			Michael Rossberg
 mick@binaervarianz.de
 Description:	KisMAC is a wireless stumbler for MacOS X.
 
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

#import "ScanControllerScriptable.h"
#import "ScanControllerPrivate.h"
#import "WaveScanner.h"
#import "WaveNetWEPCrack.h"
#import "MapView.h"
#import "MapDownload.h"
#import "KisMACNotifications.h"
#import "WaveStorageController.h"
#import "Trace.h"
#import "WaveHelper.h"
#import "GrowlController.h"
#import "ImportController.h"
#import "WaveContainer.h"

@implementation ScanController(ScriptableAdditions)

- (BOOL)isSaved
{
    if ([[[NSUserDefaults standardUserDefaults] objectForKey:@"dontAskToSave"] boolValue])
    {
        return YES; //dont bother the user if set in preferences
    }
    
    if ([_window isDocumentEdited])
    {
        return [_networkTable numberOfRows]==0; //dont ask to save empty documents
    }
    
    return YES;
}

- (NSString*)filename
{
    return _fileName;
}

- (WaveNet*)selectedNetwork
{
    return _curNet;
}

#pragma mark -

- (BOOL)showNetworks
{
    [self changedViewTo:tabNetworks contentView:_networkView];
    
    return YES;
}

- (BOOL)showTrafficView
{
    [self changedViewTo:tabTraffic contentView:_trafficView];
    
    return YES;
}

- (BOOL)showMap
{
    [self changedViewTo:tabMap contentView:_mapView];
    [_window makeFirstResponder:_mappingView];
    
    return YES;
}

- (BOOL)showDetails
{
    if (!_curNet)
    {
        NSBeep();
        
        return NO;
    }
    
    [self changedViewTo:tabDetails contentView:_detailsView];
    
    return YES;
}

- (BOOL)toggleScan
{
	if(_scanning)
    {
		_scanning = NO;
        
		return [self stopScan];
	}
    else
    {
		_scanning = YES;
        
		return [self startScan];
	}
}

- (BOOL)startScan
{
    bool result = NO;
    
    if ([WaveHelper loadDrivers])
    {
        if ([[WaveHelper getWaveDrivers] count] == 0)
        {
            NSBeginAlertSheet(@"No driver selected.", NULL, NULL, NULL, _window,
                              self, NULL, NULL, NULL, @"Please select a WiFi Driver in the Preferences Window!");
            return NO;
        }
        
        _scanning=YES;
        [_window setDocumentEdited:YES];
		[_scanButton setImage:[NSImage imageNamed:@"toolbar-stop-scan"]];
		
        [_scanButton setLabel:@"Stop"];
        result=[scanner startScanning];
		[GrowlController notifyGrowlStartScan];
	}
    
    [self updateChannelMenu];
    
	return result;
}

- (BOOL)stopScan
{
    bool result;
    
	[self stopActiveAttacks];
    result=[scanner stopScanning];
    [_scanButton setImage:[NSImage imageNamed:@"toolbar-start-scan"]];
    [_scanButton setLabel:@"Start"];
    _scanning=NO;
    
    [self updateChannelMenu];
    [_networkTable reloadData];
    
	[queue cancelAllOperations];
	
    return result;
}

- (BOOL)new
{
    [self showBusyWithText:NSLocalizedString(@"Resetting document...", "Status for busy dialog")];
    
    [self stopActiveAttacks];
    [self stopScan];
    
    [self clearAreaMap];
    [self hideDetails];
    [self showNetworks];
    [_networkTable deselectAll:self];
    
	[[WaveHelper trace] setTrace:nil];
    [_container clearAllEntries];
    
    [_window setDocumentEdited:NO];
    _curNet = nil;
	_fileName = nil;
    
    [self refreshScanHierarch];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        
        [self updateNetworkTable:self complete:YES];
    });
    
    [self busyDone];
    return YES;
}

- (BOOL)open:(NSString*)filename
{
    BOOL ret;
    
    NSParameterAssert(filename);
    
    filename = [filename standardPath];
    
    if ([[[filename pathExtension] lowercaseString] isEqualToString:@"kismac"])
    {
        [self showBusyWithText:[NSString stringWithFormat:NSLocalizedString(@"Opening %@...", "Status for busy dialog"), [filename stringByAbbreviatingWithTildeInPath]]];
        
        [self new];
		_fileName = filename;
        
        NS_DURING
        ret = [WaveStorageController loadFromFile:filename withContainer:_container andImportController:_importController];
        NS_HANDLER
        ret = NO;
        NS_ENDHANDLER
        
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
            
            [self updateNetworkTable:self complete:YES];
        });
        
        [self refreshScanHierarch];
        [_window setDocumentEdited:NO];
        
        [self busyDone];
        [self showNetworks];
        
        return ret;
    }
    else if ([[[filename pathExtension] lowercaseString] isEqualToString:@"kismap"])
    {
        [self showBusyWithText:[NSString stringWithFormat:NSLocalizedString(@"Opening %@...", "Status for busy dialog"), [filename stringByAbbreviatingWithTildeInPath]]];
        
        [self clearAreaMap];
        
        ret = [_mappingView loadFromFile:filename];
        
        [self busyDone];
        [self showMap];
        
        return ret;
    }
    
    DBNSLog(@"Warning unknown file format!");
    NSBeep();
    
    return NO;
}

- (BOOL)importKisMAC:(NSString*)filename
{
    BOOL ret;
    
    NSParameterAssert(filename);
    
    filename = [filename standardPath];
    
    if ([[[filename pathExtension] lowercaseString] isEqualToString:@"kismac"])
    {
        [self showBusyWithText:[NSString stringWithFormat:NSLocalizedString(@"Importing %@...", "Status for busy dialog"), [filename stringByAbbreviatingWithTildeInPath]]];
		
		_refreshGUI = NO;
		ret = [WaveStorageController importFromFile:filename withContainer:_container andImportController:_importController];
		_refreshGUI = YES;
        
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
            
            [self updateNetworkTable:self complete:YES];
        });
        
		[self refreshScanHierarch];
		[_window setDocumentEdited:YES];
        
		[self busyDone];
        [self showNetworks];
		
		[[NSNotificationCenter defaultCenter] postNotificationName:KisMACViewItemChanged object:self];
        
 		return ret;
	}
    
    DBNSLog(@"Warning unknown file format!");
    NSBeep();
    
    return NO;
}

- (BOOL)importImageForMap:(NSString*)filename
{
	BOOL ret;
    NSImage *img;
	
    NSParameterAssert(filename);
    
    filename = [filename standardPath];
    
	[self showBusyWithText:[NSString stringWithFormat:NSLocalizedString(@"Importing %@...", "Status for busy dialog"), [filename stringByAbbreviatingWithTildeInPath]]];
	
	[self clearAreaMap];
    
	img = [[NSImage alloc] initWithContentsOfFile:filename];
	if (!img)
    {
		DBNSLog(@"Warning unknown file format!");
		NSBeep();
		[self busyDone];
        
		return NO;
	}
	
    ret = [_mappingView setMap: img];
    [self showMap];
	[self busyDone];
    
	return ret;
}

- (BOOL)importPCAP:(NSString*)filename
{
    NSParameterAssert(filename);
    filename = [filename standardPath];
    
    [self showBusyWithText:[NSString stringWithFormat:NSLocalizedString(@"Importing %@...", "Status for busy dialog"), [filename stringByAbbreviatingWithTildeInPath]]];
    
    [self stopScan];
    [_networkTable deselectAll:self];
    
    NS_DURING
    
    [scanner readPCAPDump:filename];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        
        [self updateNetworkTable:self complete:YES];
    });
    
    [_window setDocumentEdited:YES];
    [self busyDone];
    
    NS_VALUERETURN(YES, BOOL);
    NS_HANDLER
    
    NSBeep();
    DBNSLog(@"Import of %@ failed!", filename);
    
    NS_ENDHANDLER
    
    [self busyDone];
    
    return NO;
}

- (BOOL)exportKML:(NSString*)filename
{
    NSParameterAssert(filename);
    filename = [filename standardPath];
    [self showBusy:@selector(performExportKML:) withArg:filename];
    if (_asyncFailure)
    {
        [self showExportFailureDialog];
    }
    
    return !_asyncFailure;
}

- (BOOL)downloadMapFrom:(NSString*)server forPoint:(waypoint)w resolution:(NSSize)size zoomLevel:(int)zoom
{
    NSImage *map;
    MapDownload *md;
    BOOL failure = YES;
    [self showBusyWithText:NSLocalizedString(@"Importing from Server...", "Status for busy dialog")];
    [self clearAreaMap];
    
    md = [MapDownload mapDownload];
    NS_DURING
    if ([md downloadMapFrom:server forPoint:w resolution:size zoomLevel:zoom]) {
        map = [md map];
        if (map)
        {
            [_mappingView setMap:map];
            [_mappingView setWaypoint:selWaypoint1 toPoint:[md waypoint1Pixel] atCoordinate:[md waypoint1]];
            [_mappingView setWaypoint:selWaypoint2 toPoint:[md waypoint2Pixel] atCoordinate:[md waypoint2]];
            
            failure = NO;
        }
    }
    NS_HANDLER
    NS_ENDHANDLER
    
    [self busyDone];
    
    if (failure)
    {
        NSBeginCriticalAlertSheet(
                                  NSLocalizedString(@"Import failed", "Import failure dialog title"),
                                  OK, NULL, NULL, _window, self, NULL, NULL, NULL,
                                  NSLocalizedString(@"Import failure description", "LONG description. Maybe no internet?")
                                  //"KisMAC was unable to complete the import. Are you sure that you have a valid internet connection?"
                                  );
    }
    else {
        [self showMap];
    }
    return !failure;
}

- (BOOL)save:(NSString*)filename
{
    BOOL ret = NO;
    BOOL wasScanning = NO;
    if (_scanning)
    {
        wasScanning = YES;
    }
    
    NSParameterAssert(filename);
    if (!_saveFilteredOnly)
    {
        [_container setFilterString:@""];
    }
    
    filename = [filename standardPath];
    DBNSLog(@"FileName is %@", filename);
    if ([[[filename pathExtension] lowercaseString] isEqualToString:@"kismac"])
    {
        [self showBusyWithText:[NSString stringWithFormat:NSLocalizedString(@"Saving to %@...", "Status for busy dialog"), [filename stringByAbbreviatingWithTildeInPath]]];
        
        NS_DURING
        
        [self stopActiveAttacks];
        [self stopScan];
        ret = [WaveStorageController saveToFile:filename withContainer:_container andImportController:_importController];
        _fileName = filename;
        if (!ret)
        {
            [self showSavingFailureDialog];
        }
        else
        {
            [_window setDocumentEdited: _scanning];
        }
        
        [self busyDone];
        [[WaveHelper scanController] changeSearchValue:self];
        
        if (wasScanning)
        {
            [self startScan];
        }
        
        NS_VALUERETURN(ret, BOOL);
        NS_HANDLER
        
        DBNSLog(@"Saving failed, because of an internal error!");
        
        NS_ENDHANDLER
		[self busyDone];
    }
    else if ([[[filename pathExtension] lowercaseString] isEqualToString:@"kismap"])
    {
        [self showBusyWithText:[NSString stringWithFormat:NSLocalizedString(@"Saving to %@...", "Status for busy dialog"), [filename stringByAbbreviatingWithTildeInPath]]];
        
        NS_DURING
        
        [_mappingView saveToFile:filename];
        [self busyDone];
        
        NS_VALUERETURN(YES, BOOL);
        NS_HANDLER
        
        DBNSLog(@"Map saving failed, because of an internal error!");
        
        [self showSavingFailureDialog];
        
        NS_ENDHANDLER
        
        [self busyDone];
    }
    
    DBNSLog(@"Warning unknown file format or internal error!");
    NSBeep();
    
    return NO;
}

- (BOOL)saveAs:(NSString*)filename
{
    [[WaveHelper scanController] checkFilter:self];
    return [self save: filename];
}

#pragma mark -

- (BOOL)selectNetworkWithBSSID:(NSString*)BSSID
{
    int i;
    
    NSParameterAssert(BSSID);
    
    for (i = [_container count]; i>=0; --i)
        if ([[[_container netAtIndex:i] BSSID] isEqualToString:BSSID])
        {
            _selectedRow = i;
            [_networkTable selectRowIndexes:[NSIndexSet indexSetWithIndex: i]
                       byExtendingSelection: NO];
            return YES;
        }
    
    return NO;
}

- (BOOL)selectNetworkAtIndex:(NSNumber*)index
{
    NSParameterAssert(index);
    
    int i = [index intValue];
    
    if (i < [_container count])
    {
        _selectedRow = i;
        [_networkTable selectRowIndexes:[NSIndexSet indexSetWithIndex: i]
                   byExtendingSelection: NO];
        return YES;
    }
    
    return NO;
}

- (int) networkCount
{
    return [_container count];
}

#pragma mark -

- (BOOL) isBusy
{
    return _importOpen > 0;
}

#pragma mark -

#define WEPCHECKS {\
if (_importOpen) return NO; \
if (_curNet==nil) return NO; \
if ([_curNet passwordAvailable]) return YES; \
if ([_curNet wep] != encryptionTypeWEP && [_curNet wep] != encryptionTypeWEP40) return NO; \
if ([[_curNet cryptedPacketsLog] count] < 8) return NO; \
}

- (BOOL)bruteforceNewsham
{
    WEPCHECKS;
    
	_crackType = 6;
    [self startCrackDialogWithTitle:NSLocalizedString(@"Performing Newsham attack...", "busy dialog")];
    [_importController setMax:127];
    
    [NSThread detachNewThreadSelector:@selector(performBruteforceNewsham:) toTarget:_curNet withObject:nil];
    
    return YES;
}

- (BOOL)bruteforce40bitLow
{
    WEPCHECKS;
    
	_crackType = 2;
    [self startCrackDialogWithTitle:NSLocalizedString(@"Bruteforce attack against WEP-40 lowercase...", "busy dialog")];
    [_importController setMax:26];
    
    [NSThread detachNewThreadSelector:@selector(performBruteforce40bitLow:) toTarget:_curNet withObject:nil];
    
    return YES;
}

- (BOOL)bruteforce40bitAlpha
{
    WEPCHECKS;
    
	_crackType = 2;
    [self startCrackDialogWithTitle:NSLocalizedString(@"Bruteforce attack against WEP-40 alphanumerical...", "busy dialog")];
    [_importController setMax:62];
    
    [NSThread detachNewThreadSelector:@selector(performBruteforce40bitAlpha:) toTarget:_curNet withObject:nil];
    
    return YES;
}

- (BOOL)bruteforce40bitAll
{
    WEPCHECKS;
    
	_crackType = 2;
    [self startCrackDialogWithTitle:NSLocalizedString(@"Bruteforce attack against WEP-40...", "busy dialog")];
    [_importController setMax:LAST_BIT];
    
    [NSThread detachNewThreadSelector:@selector(performBruteforce40bitAll:) toTarget:_curNet withObject:nil];
    
    return YES;
}

- (BOOL)wordlist40bitApple:(NSString*)wordlist
{
    WEPCHECKS;
    
    _crackType = 2;
	[self startCrackDialogWithTitle:NSLocalizedString(@"Wordlist attack against WEP-Apple40...", "busy dialog")];
    
    [NSThread detachNewThreadSelector:@selector(performWordlist40bitApple:) toTarget:_curNet withObject:[wordlist standardPath]];
    
    return YES;
}

- (BOOL)wordlist104bitApple:(NSString*)wordlist
{
    WEPCHECKS;
    
    _crackType = 2;
	[self startCrackDialogWithTitle:NSLocalizedString(@"Wordlist attack against WEP-Apple104...", "busy dialog")];
    
    [NSThread detachNewThreadSelector:@selector(performWordlist104bitApple:) toTarget:_curNet withObject:[wordlist standardPath]];
    
    return YES;
}

- (BOOL)wordlist104bitMD5:(NSString*)wordlist
{
    WEPCHECKS;
    
	_crackType = 2;
    [self startCrackDialogWithTitle:NSLocalizedString(@"Wordlist attack against WEP-MD5...", "busy dialog")];
    
    [NSThread detachNewThreadSelector:@selector(performWordlist104bitMD5:) toTarget:_curNet withObject:[wordlist standardPath]];
    
    return YES;
}

- (BOOL)wordlistWPA:(NSString*)wordlist
{
    if (_importOpen) return NO;
    if (_curNet==nil) return NO;
    if ([_curNet passwordAvailable]) return YES;
    if (([_curNet wep] != encryptionTypeWPA) && ([_curNet wep] != encryptionTypeWPA2)) return NO;
	if ([_curNet SSID] == nil) return NO;
	if ([[_curNet SSID] length] > 32) return NO;
	if ([_curNet capturedEAPOLKeys] == 0) return NO;
    
    _crackType = 3;
    [self startCrackDialogWithTitle:NSLocalizedString(@"Wordlist attack against WPA-PSK...", "busy dialog")];
    
    [NSThread detachNewThreadSelector:@selector(performWordlistWPA:) toTarget:_curNet withObject:[wordlist standardPath]];
    
    return YES;
}

- (BOOL)wordlistLEAP:(NSString*)wordlist
{
    if (_importOpen) return NO;
    if (_curNet==nil) return NO;
    if ([_curNet passwordAvailable]) return YES;
    if ([_curNet wep] != encryptionTypeLEAP) return NO;
	if ([_curNet capturedLEAPKeys] == 0) return NO;
    
    _crackType = 4;
    [self startCrackDialogWithTitle:NSLocalizedString(@"Wordlist attack against LEAP...", "busy dialog")];
    
    [NSThread detachNewThreadSelector:@selector(performWordlistLEAP:) toTarget:_curNet withObject:[wordlist standardPath]];
    
    return YES;
}

- (BOOL)weakSchedulingAttackForKeyLen:(int)keyLen andKeyID:(int)keyID
{
    if (_importOpen) return NO;
    if (_curNet==nil) return NO;
    if ([_curNet passwordAvailable]) return YES;
    if ([_curNet wep] != encryptionTypeWEP && [_curNet wep] != encryptionTypeWEP40) return NO;
    if ([_curNet uniqueIVs] < 8) return NO;
    if (keyLen != 13 && keyLen != 5 && keyLen != 0xFFFFFF) return NO;
    if (keyID < 0 || keyID > 3) return NO;
    
    int arg = (keyLen << 8) | keyID;
    
	_crackType = 1;
    [self startCrackDialogWithTitle:NSLocalizedString(@"Weak scheduling attack...", "busy dialog") stopScan:NO];
    
    [NSThread detachNewThreadSelector:@selector(performCrackWEPWeakforKeyIDAndLen:) toTarget:_curNet withObject:@(arg)];
    
    return YES;
}

@end

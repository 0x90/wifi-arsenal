/*
 
 File:			WaveDriverUSBIntersil.m
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
#import "WaveDriverUSBIntersil.h"
#import "../Driver/USBJack/IntersilJack.h"
#import "WaveHelper.h"

@implementation WaveDriverUSBIntersil

bool explicitlyLoadedUSBIntersil = NO;

#pragma mark -

+ (NSString*) description {
    return NSLocalizedString(@"USB Prism2 device, passive mode", "long driver description");
}

+ (NSString*) deviceName {
    return NSLocalizedString(@"USB Prism2 device", "short driver description");
}

#pragma mark -

+ (bool) loadBackend {
    
    if ([WaveHelper isServiceAvailable: (char*)"com_intersil_prism2USB"]) {
        NSRunCriticalAlertPanel(
                                NSLocalizedString(@"WARNING! Please unplug your USB device now.", "Warning dialog title"),
                                NSLocalizedString(@"Due a bug in Intersils Prism USB driver you must unplug your device now temporarily, otherwise you will not be able to use it any more. KisMAC will prompt you again to put it back in after loading is completed.", "USB driver bug warning."),
                                OK, nil, nil);
        
		if (![WaveHelper runScript:@"usbprism2_prep.sh"]) return NO;
        
        NSRunInformationalAlertPanel(
                                     NSLocalizedString(@"Connect your device again!", "dialog title"),
                                     NSLocalizedString(@"KisMAC completed the unload process. Please plug your device back in before you continue.", "USB driver bug warning."),
                                     OK, nil, nil);
		explicitlyLoadedUSBIntersil = YES;
    } else  if ([WaveHelper isServiceAvailable: (char*)"AeroPad"]) {
		if (![WaveHelper runScript:@"usbprism2_prep.sh"]) return NO;
		explicitlyLoadedUSBIntersil = YES;
	}
	
    return YES;
}

+ (bool) unloadBackend {
	if (!explicitlyLoadedUSBIntersil) return YES;
	
    DBNSLog(@"Restarting the USB drivers");
    return [WaveHelper runScript:@"usbprism2_unprep.sh"];
}

#pragma mark -

- (id) init {
    self = [super init];
    if (!self)
        return nil;
    
    _permittedRates = @[[NSNumber numberWithUnsignedInt:KMRate1],
        [NSNumber numberWithUnsignedInt:KMRate2],
        [NSNumber numberWithUnsignedInt:KMRate5_5],
        [NSNumber numberWithUnsignedInt:KMRate11]];
    return self;
}

- (bool) wakeDriver{
    [self sleepDriver];
    
    _driver = new IntersilJack;
    _driver->startMatching();
    DBNSLog(@"Matching finished\n");
    if (!(_driver->deviceMatched()))
        return NO;
    
    if(_driver->_init() != kIOReturnSuccess)
        return NO;
    
	_errors = 0;
    
    return YES;
}

#pragma mark -

@end

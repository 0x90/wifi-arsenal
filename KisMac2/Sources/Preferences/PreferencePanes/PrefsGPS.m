/*
        
        File:			PrefsGPS.m
        Program:		KisMAC
	Author:			Michael Rossberg
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

#import "PrefsGPS.h"
#import "PrefsController.h"
#include <unistd.h>
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/serial/IOSerialKeys.h>
#include <IOKit/IOBSD.h>
#import "WaveHelper.h"

@implementation PrefsGPS

-(NSString*) getRegistryString:(io_object_t) sObj name:(char *)propName {
    static char resultStr[LAST_BIT];
    CFTypeRef nameCFstring;
    CFTypeRef propNameString;

    resultStr[0] = 0;
    propNameString = CFStringCreateWithCString (
                                                kCFAllocatorDefault, propName, kCFStringEncodingASCII);
    nameCFstring = IORegistryEntryCreateCFProperty (
        sObj, propNameString,
        kCFAllocatorDefault, 0);
    CFRelease(propNameString);
    if (nameCFstring)
    {
        CFStringGetCString (
            nameCFstring, resultStr, sizeof (resultStr),
            kCFStringEncodingASCII);
        CFRelease (nameCFstring);
    }
    return @(resultStr);
}

- (void)updateRestrictions {
    switch ([aGPSSel indexOfSelectedItem]) {
        case 0:
            [_gpsdHost setEnabled:NO];
            [_gpsdPort setEnabled:NO];
            [_noFix setEnabled:NO];
            [_traceOp setEnabled:NO];
            [_tripmateMode setEnabled:NO];
            break;
        case 1:
            [_gpsdHost setEnabled:YES];
            [_gpsdPort setEnabled:YES];
            [_noFix setEnabled:YES];
            [_traceOp setEnabled:YES];
            [_tripmateMode setEnabled:YES];
            break;
        default:
            [_gpsdHost setEnabled:NO];
            [_gpsdPort setEnabled:NO];
            [_noFix setEnabled:YES];
            [_traceOp setEnabled:YES];
            [_tripmateMode setEnabled:YES];
            break;
    }
}
- (void)updateUI {
    unsigned int i;
    kern_return_t kernResult;
    mach_port_t masterPort;
    CFMutableDictionaryRef classesToMatch;
    io_iterator_t serialIterator;
    io_object_t sdev;
    NSMutableArray *a = [NSMutableArray array];
    bool found;
    
    [aGPSSel removeAllItems];
    [_tripmateMode setState: [[controller objectForKey:@"GPSTripmate"] boolValue] ? NSOnState : NSOffState];
    
    kernResult = IOMasterPort(0, &masterPort);
    if (KERN_SUCCESS == kernResult)
    {
        classesToMatch = IOServiceMatching (kIOSerialBSDServiceValue);
		if (classesToMatch != 0)
		{
			CFDictionarySetValue (
								  classesToMatch,
								  CFSTR (kIOSerialBSDTypeKey),
								  CFSTR (kIOSerialBSDRS232Type));
			kernResult = IOServiceGetMatchingServices (
													   masterPort, classesToMatch, &serialIterator);
			if (KERN_SUCCESS == kernResult)
			{
				while ((sdev = IOIteratorNext (serialIterator)))
				{
					NSString *tty = [self getRegistryString: sdev name:kIODialinDeviceKey];
					if (tty) {
						[a addObject: tty];
					}
				}
				IOObjectRelease (serialIterator);
			}
		}
    }

    [_noFix selectItemAtIndex:[[controller objectForKey:@"GPSNoFix"] intValue]];
    [_traceOp selectItemAtIndex:[[controller objectForKey:@"GPSTrace"] intValue]];
    [_gpsdPort setIntValue:[[controller objectForKey:@"GPSDaemonPort"] intValue]];
    [_gpsdHost setStringValue:[controller objectForKey:@"GPSDaemonHost"]];

    found = NO;
    [aGPSSel addItemWithTitle: NSLocalizedString(@"<do not use GPS integration>", "menu item for GPS prefs")];
    [aGPSSel addItemWithTitle: NSLocalizedString(@"<use GPSd to get coordinates>", "menu item for GPS prefs")];
    [aGPSSel addItemWithTitle: NSLocalizedString(@"<use CoreLocation to get coordinates>", "menu item for GPS prefs")];
    
    if ([a count] > 0) [[aGPSSel menu] addItem:[NSMenuItem separatorItem]];
    
    if ([[controller objectForKey:@"GPSDevice"] isEqualToString:@""]) {
        [aGPSSel selectItemAtIndex:0];
        found = YES;
    }
    
    if ([[controller objectForKey:@"GPSDevice"] isEqualToString:@"GPSd"]) {
        [aGPSSel selectItemAtIndex:1];
        found = YES;
    }
    
    if ([[controller objectForKey:@"GPSDevice"] isEqualToString:@"CoreLocation"]) {
        [aGPSSel selectItemAtIndex:2];
        found = YES;
    }
    
    for (i=0;i<[a count];++i) {
        [aGPSSel addItemWithTitle:a[i]];
        if ([[controller objectForKey:@"GPSDevice"] isEqualToString:a[i]]) {
            [aGPSSel selectItemAtIndex:(i+3)];
            found = YES;
        }
    }
    
    if (!found) {
        [aGPSSel addItemWithTitle:[controller objectForKey:@"GPSDevice"]];
        [aGPSSel selectItemAtIndex:[a count]+1];
    }
    
    [aGPSSel setEnabled:YES];
    [self updateRestrictions];
}

-(BOOL)updateDictionary {
    
    if ((![aGPSSel isEnabled]) || ([aGPSSel indexOfSelectedItem]==0)) {
        [controller setObject:@"" forKey:@"GPSDevice"];
    } else if ([[aGPSSel titleOfSelectedItem] isEqualToString: NSLocalizedString(@"<use GPSd to get coordinates>", "menu item for GPS prefs")]) {
        [controller setObject:@"GPSd" forKey:@"GPSDevice"];
    } else if ([[aGPSSel titleOfSelectedItem] isEqualToString: NSLocalizedString(@"<use CoreLocation to get coordinates>", "menu item for GPS prefs")]) {
        [controller setObject:@"CoreLocation" forKey:@"GPSDevice"];
    } else {
        [controller setObject:[aGPSSel titleOfSelectedItem] forKey:@"GPSDevice"];
    }
    
    [_gpsdPort validateEditing];
    [_gpsdHost validateEditing];
    
    [controller setObject:[NSNumber numberWithInt:[_noFix indexOfSelectedItem]] forKey:@"GPSNoFix"];
    [controller setObject:[NSNumber numberWithInt:[_traceOp indexOfSelectedItem]] forKey:@"GPSTrace"];
    [controller setObject:[NSNumber numberWithBool:[_tripmateMode state]==NSOnState] forKey:@"GPSTripmate"];
    [controller setObject:@([_gpsdPort intValue]) forKey:@"GPSDaemonPort"];
    [controller setObject:[[_gpsdHost stringValue] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] forKey:@"GPSDaemonHost"];
    
    [self updateRestrictions];

    return YES;
}

-(IBAction)setValueForSender:(id)sender {
    if(sender == aGPSSel) {
        [self updateDictionary];
    } else if (sender == _noFix) {
        [controller setObject:[NSNumber numberWithInt:[_noFix indexOfSelectedItem]] forKey:@"GPSNoFix"];
    } else if (sender == _traceOp) {
        [controller setObject:[NSNumber numberWithInt:[_traceOp indexOfSelectedItem]] forKey:@"GPSTrace"];
    } else if (sender == _tripmateMode) {
        [controller setObject:[NSNumber numberWithBool:[_tripmateMode state]==NSOnState] forKey:@"GPSTripmate"];
    } else if (sender == _gpsdPort) {
        [controller setObject:@([_gpsdPort intValue]) forKey:@"GPSDaemonPort"];
    } else if (sender == _gpsdHost) {
        [controller setObject:[[_gpsdHost stringValue] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] forKey:@"GPSDaemonHost"];
    } else {
        DBNSLog(@"Error: Invalid sender(%@) in setValueForSender:",sender);
    }
	NSUserDefaults *sets = [NSUserDefaults standardUserDefaults];
	[WaveHelper initGPSControllerWithDevice: [sets objectForKey:@"GPSDevice"]];
}

@end

/*
        
        File:			DownloadMapController.m
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

#import "DownloadMapController.h"
#import "ScriptingEngine.h"
#import "WaveHelper.h"

@implementation DownloadMapController 

- (void)awakeFromNib {
    NSUserDefaults *def = [NSUserDefaults standardUserDefaults];
    
    [_scale  selectItemWithTitle:[def stringForKey:@"DownloadMapScale"]];
    [_server selectItemWithTitle:[def stringForKey:@"DownloadMapServer"]];
    [_width  setIntValue:[def integerForKey:@"DownloadMapWidth"]];
    [_height setIntValue:[def integerForKey:@"DownloadMapHeight"]];
    [_nsButton selectItemWithTitle:[def stringForKey:@"DownloadMapNS"]];
    [_ewButton selectItemWithTitle:[def stringForKey:@"DownloadMapEW"]];
    [_latitude  setFloatValue:[def floatForKey:@"DownloadMapLatitude"]];
    [_longitude setFloatValue:[def floatForKey:@"DownloadMapLongitude"]];
    
    [self selectOtherServer:_server];

    [[self window] setDelegate:self];
    
}

- (IBAction)selectOtherServer:(id)sender {
    BOOL map24 = [[sender titleOfSelectedItem] isEqualToString:NSLocalizedString(@"Map24", "menu item, needs to be like in DownloadMap.nib")];
    BOOL sdau = [[sender titleOfSelectedItem] isEqualToString:NSLocalizedString(@"Street-Directory.com.au", "menu item, needs to be like in DownloadMap.nib")];
    [_scale  setEnabled:!map24];
    [_height setEnabled:!(map24 || sdau)];
    [_width  setEnabled:!(map24 || sdau)];
    if (map24) {
        [_height setIntValue:1000];
        [_width  setIntValue:1000];
    }
       if (sdau) {
        [_height setIntValue:1200];
        [_width  setIntValue:1200];
       }
}

- (IBAction)okAction:(id)sender {
    waypoint w;
    NSString *server;
    double tmp;
    NSMutableDictionary *d;
    NSAppleEventDescriptor *serv, *lat, *lon, *zoom, *width, *height;
    BOOL map24 = NO;

    w._lat  = [_latitude  floatValue] * ([[_nsButton titleOfSelectedItem] isEqualToString:@"N"] ? 1.0 : -1.0);
    w._long = [_longitude floatValue] * ([[_ewButton titleOfSelectedItem] isEqualToString:@"E"] ? 1.0 : -1.0);
    
    if ([[_server titleOfSelectedItem] isEqualToString: NSLocalizedString(@"TerraServer (Satellite)", "menu item, needs to be like in DownloadMap.nib")]) {
        server = @"TerraServer (Satellite)";
    } else if ([[_server titleOfSelectedItem] isEqualToString: NSLocalizedString(@"TerraServer (Map)", "menu item, needs to be like in DownloadMap.nib")]) {
        server = @"TerraServer (Map)";
    } else if ([[_server titleOfSelectedItem] isEqualToString: NSLocalizedString(@"Expedia (United States)", "menu item, needs to be like in DownloadMap.nib")]) {
        server = @"Expedia (United States)";
    } else if ([[_server titleOfSelectedItem] isEqualToString:NSLocalizedString(@"Expedia (Europe)", "menu item, needs to be like in DownloadMap.nib")]) {
        server = @"Expedia (Europe)";
    } else if ([[_server titleOfSelectedItem] isEqualToString:NSLocalizedString(@"Map24", "menu item, needs to be like in DownloadMap.nib")]) {
        server = @"Map24";
        map24 = YES;
    } else if ([[_server titleOfSelectedItem] isEqualToString:NSLocalizedString(@"Street-Directory.com.au", "menu item, needs to be like in DownloadMap.nib")]) {
        server = @"Street-Directory.com.au";
    } else if ([[_server titleOfSelectedItem] isEqualToString:NSLocalizedString(@"Census Bureau Maps (United States)", "menu item, needs to be like in DownloadMap.nib")]) {
        server = @"Census Bureau Maps (United States)";
    } else {
        NSRunCriticalAlertPanel(
            NSLocalizedString(@"No server selected.", "Download Map error title"),
            NSLocalizedString(@"No server selected. description", "LONG error description"),
            //@"KisMAC needs the name of a server from where it can load the map. Depending on your region and the look of the map you should find one in the pop-up menu. If you know how-to obtain a map from another server, please drop me a mail.",
            OK, nil, nil
            );
        return;
    }
    
    serv = [NSAppleEventDescriptor descriptorWithString:server];
    zoom = [NSAppleEventDescriptor descriptorWithInt32:[[_scale titleOfSelectedItem] intValue]];
    lat = [NSAppleEventDescriptor descriptorWithDescriptorType:typeIEEE64BitFloatingPoint bytes:&w._lat length:sizeof(double)];
    lon = [NSAppleEventDescriptor descriptorWithDescriptorType:typeIEEE64BitFloatingPoint bytes:&w._long length:sizeof(double)];
    tmp = [_height intValue];
    height = [NSAppleEventDescriptor descriptorWithDescriptorType:typeIEEE64BitFloatingPoint bytes:&tmp length:sizeof(double)];
    tmp = [_width intValue];
    width  = [NSAppleEventDescriptor descriptorWithDescriptorType:typeIEEE64BitFloatingPoint bytes:&tmp length:sizeof(double)];
    
    d = [NSMutableDictionary dictionaryWithObjectsAndKeys:lat, [NSString stringWithFormat:@"%d", 'KMLa'], lon, [NSString stringWithFormat:@"%d", 'KMLo'], serv, [NSString stringWithFormat:@"%d", keyDirectObject], nil];
    
    if ([[_scale titleOfSelectedItem] intValue] != 3 && !map24) d[[NSString stringWithFormat:@"%d", 'KScl']] = zoom;
    if ([_width  intValue] != 1000 && !map24) d[[NSString stringWithFormat:@"%d", 'KWid']] = width;
    if ([_height intValue] != 1000 && !map24) d[[NSString stringWithFormat:@"%d", 'KHig']] = height;
    
    [[self window] close];

    [ScriptingEngine selfSendEvent:'KDMp' withArgs:d];

    NSUserDefaults *def = [NSUserDefaults standardUserDefaults];
    [def setObject:[_scale titleOfSelectedItem] forKey:@"DownloadMapScale"];
    [def setObject:[_server titleOfSelectedItem] forKey:@"DownloadMapServer"];
    [def setInteger:[_width intValue] forKey:@"DownloadMapWidth"];
    [def setInteger:[_height intValue] forKey:@"DownloadMapHeight"];
    [def setFloat:[_latitude floatValue] forKey:@"DownloadMapLatitude"];
    [def setFloat:[_longitude floatValue] forKey:@"DownloadMapLongitude"];
    [def setObject:[_nsButton titleOfSelectedItem] forKey:@"DownloadMapNS"];
    [def setObject:[_ewButton titleOfSelectedItem] forKey:@"DownloadMapEW"];

}

- (IBAction)cancelAction:(id)sender {
    [[self window] performClose:sender];
}

- (void)setCoordinates:(waypoint)wp {
    if (wp._lat==0 && wp._long==0) return;
    
    [_latitude  setFloatValue: ((wp._lat >= 0) ? wp._lat : -wp._lat) ];
    [_longitude setFloatValue: ((wp._long>= 0) ? wp._long: -wp._long)];
 
    if (wp._lat>=0)  [_nsButton selectItemWithTitle:@"N"];
    else  [_nsButton selectItemWithTitle:@"S"];
    
    if (wp._long>=0) [_ewButton selectItemWithTitle:@"E"];
    else  [_ewButton selectItemWithTitle:@"W"];
}

#pragma mark Fade Out Code

- (BOOL)windowShouldClose:(id)sender 
{
    // Set up our timer to periodically call the fade: method.
    [NSTimer scheduledTimerWithTimeInterval:0.05 target:self selector:@selector(fade:) userInfo:nil repeats:YES];
    
    return NO;
}

- (void)fade:(NSTimer *)timer {
    if ([[self window] alphaValue] > 0.0) {
        // If window is still partially opaque, reduce its opacity.
        [[self window] setAlphaValue:[[self window] alphaValue] - 0.2];
    } else {
        // Otherwise, if window is completely transparent, destroy the timer and close the window.
        [timer invalidate];
        
        [[self window] close];
        
        // Make the window fully opaque again for next time.
        [[self window] setAlphaValue:1.0];
    }
}
@end

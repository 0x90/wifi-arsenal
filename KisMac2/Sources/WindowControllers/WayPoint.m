/*
        
        File:			WayPoint.m
        Program:		KisMAC
	Author:			Michael Rossberg
				mick@binaervarianz.de
	Description:		KisMAC is a wireless stumbler for MacOS X.
                
        This file is part of KisMAC.

    KisMAC is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    KisMAC is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with KisMAC; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#import "WayPoint.h"
#import "ScriptingEngine.h"

@implementation WayPoint

- (void)awakeFromNib {
    [[self window] setDelegate:self];
}

- (void)setWaypoint:(waypoint)w {
    [aLat  setFloatValue: ((w._lat >= 0) ? w._lat : -w._lat) ];
    [aLong setFloatValue: ((w._long>= 0) ? w._long: -w._long)];
    
    if (w._lat>=0)  [aNS setStringValue:@"N"];
    else  [aNS setStringValue:@"S"];
    
    if (w._long>=0) [aEW setStringValue:@"E"];
    else  [aEW setStringValue:@"W"];
}

- (void)setMode:(enum selmode)mode {
    NSParameterAssert(mode == selCurPos || mode == selWaypoint1 || mode == selWaypoint2);
    _mode = mode;
}

- (void)setPoint:(NSPoint)p {
    _p = p;
}

- (IBAction)NSStepClicked:(id)sender {
    if ([[aNS stringValue] isEqualToString:@"N"]) [aNS setStringValue:@"S"];
    else [aNS setStringValue:@"N"];
}

- (IBAction)EWStepClicked:(id)sender {
    if ([[aEW stringValue] isEqualToString:@"E"]) [aEW setStringValue:@"W"];
    else [aEW setStringValue:@"E"];
}

- (IBAction)OKClicked:(id)sender {
    NSDictionary *args;
    NSAppleEventDescriptor *lat, *lon, *x, *y;
    double z;
    
    z = [aLat  doubleValue] * ([[aNS stringValue] isEqualToString:@"N"] ? 1.0 : -1.0);
    lat = [NSAppleEventDescriptor descriptorWithDescriptorType:typeIEEE64BitFloatingPoint bytes:&z length:sizeof(double)];
    z = [aLong doubleValue] * ([[aEW stringValue] isEqualToString:@"E"] ? 1.0 : -1.0);
    lon = [NSAppleEventDescriptor descriptorWithDescriptorType:typeIEEE64BitFloatingPoint bytes:&z length:sizeof(double)];
    z = _p.x;
    x = [NSAppleEventDescriptor descriptorWithDescriptorType:typeIEEE64BitFloatingPoint bytes:&z length:sizeof(double)];
    z = _p.y;
    y = [NSAppleEventDescriptor descriptorWithDescriptorType:typeIEEE64BitFloatingPoint bytes:&z length:sizeof(double)];

    switch(_mode) {
    case selCurPos:
        args = @{[NSString stringWithFormat:@"%d", 'KMLa']: lat,[NSString stringWithFormat:@"%d", 'KMLo']: lon};
        [ScriptingEngine selfSendEvent:'KMSP' withArgs:args];
        break;
    case selWaypoint1:
    case selWaypoint2:
        args = @{[NSString stringWithFormat:@"%d", 'KMLa']: lat,[NSString stringWithFormat:@"%d", 'KMLo']: lon, [NSString stringWithFormat:@"%d", 'KM_x']: x, [NSString stringWithFormat:@"%d", 'KM_y']: y, [NSString stringWithFormat:@"%d", keyDirectObject]: [NSAppleEventDescriptor descriptorWithInt32: (_mode == selWaypoint1) ? 1 : 2]};
        [ScriptingEngine selfSendEvent:'KMSW' withArgs:args];
        break;        
    default:
        break;
    }

    [[self window] performClose:sender];
}

- (IBAction)CancelClicked:(id)sender {
    [[self window] performClose:sender];
}

#pragma mark Fade Out Code

- (BOOL)windowShouldClose:(id)sender {
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

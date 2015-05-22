/*
 
 File:			GPSInfoController.m
 Program:		KisMAC
 Author:	    themacuser  themacuser -at- gmail.com
 Description:	KisMAC is a wireless stumbler for MacOS X.
 
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

#import "GPSInfoController.h"
#import "WaveHelper.h"
#import "GPSSatInfo.h"

@implementation GPSInfoController

- (void)awakeFromNib {
    [[self window] setDelegate:self];
}

- (void)closeWindow:(NSWindow *)sheet returnCode:(int)returnCode contextInfo:(void *)contextInfo {
	//[[self window] performClose:self];
}

- (void)updateDataNS:(double)ns EW:(double)ew ELV:(double)elv numSats:(int)sats HDOP:(double)hdop VEL:(float)vel {
	_vel = vel;
	_alt = elv;
	
	if (_velFactor == 0) {
		_velFactor = 1.852;
	}
	
	if (_altFactor == 0) {
		_altFactor = 1;
	}
	
	if (!sats || ew > 180 || ns > 90 || vel < 0) {
		[_fix_indicator setFloatValue:0.1];
		[_fix_type setStringValue:@"NO"];
		[_hdop_indicator setIntValue:8];
		[_hdop_field setStringValue:@""];
		[_lat_field setStringValue:@""];
		[_lon_field setStringValue:@""];
		[_vel_field setStringValue:@""];
		[_speedBar setDoubleValue:0];
		[_altBar setDoubleValue:0];
		_haveFix = 0;
	} else if (!elv) {
		[_fix_indicator setFloatValue:0.5];
		[_fix_type setStringValue:@"2D"];
		[_hdop_indicator setFloatValue:hdop];
		[_hdop_field setStringValue:[NSString stringWithFormat:@"%.1f",hdop]];
		[_lat_field setStringValue:[NSString stringWithFormat:@"%.5f",ns]];
		[_lon_field setStringValue:[NSString stringWithFormat:@"%.5f",ew]];
		[_vel_field setStringValue:[NSString stringWithFormat:@"%.5f",(_vel * _velFactor)]];
		[_alt_field setStringValue:@""];
		[_speedBar setDoubleValue:(_vel * _velFactor)];
		
		if ((_vel * _velFactor) > _maxvel) {
			_maxvel = _vel;
			[_speedBar setMaxValue:(_vel * _velFactor)];
		}
		
		[_altBar setDoubleValue:0];
		_haveFix = 1;
	} else if (elv && sats) {
		[_fix_indicator setFloatValue:1];
		[_fix_type setStringValue:@"3D"];
		[_hdop_indicator setFloatValue:hdop];
		[_hdop_field setStringValue:[NSString stringWithFormat:@"%.1f",hdop]];
		[_lat_field setStringValue:[NSString stringWithFormat:@"%.5f",ns]];
		[_lon_field setStringValue:[NSString stringWithFormat:@"%.5f",ew]];
		[_vel_field setStringValue:[NSString stringWithFormat:@"%.5f",(_vel * _velFactor)]];
		[_alt_field setStringValue:[NSString stringWithFormat:@"%.1f",(_alt * _altFactor)]];
		[_speedBar setDoubleValue:(_vel * _velFactor)];
		[_altBar setDoubleValue:(_alt * _altFactor)];
		
		if ((_vel * _velFactor) > _maxvel) {
			_maxvel = _vel * _velFactor;
			[_speedBar setMaxValue:(_vel * _velFactor)];
		}
		
		if ((_alt * _altFactor) > _maxalt) {
			_maxalt = _alt;
			[_altBar setMaxValue:(_alt * _altFactor)];
		}
		_haveFix = 2;
	}
	
	[[self window] display];
}

- (void)updateSatPRNForSat:(int)sat prn:(int)prn {
	[_satinfo setPRNForSat:sat PRN:prn];
	[_satinfo redraw];
}

- (void)updateSatSignalStrength:(int)sat signal:(int)signal {
	[_satinfo setSignalForSat:sat signal:signal];
	[_satinfo redraw];
}

- (void)updateSatUsed:(int)sat used:(int)used {
	[_satinfo setUsedForSat:sat used:used];
	[_satinfo redraw];
}


- (IBAction)updateSpeed:(id)sender {
		if ([[_speedType titleOfSelectedItem] isEqualToString:@"KT"]) {
			_velFactor = 1;
		} else if ([[_speedType titleOfSelectedItem] isEqualToString:@"KPH"]) {
			_velFactor = 1.852;
		} else if ([[_speedType titleOfSelectedItem] isEqualToString:@"MPH"]) {
			_velFactor = 1.15077945;
		}
		
	if (_haveFix) {
		[_vel_field setStringValue:[NSString stringWithFormat:@"%.5f",(_vel * _velFactor)]];
	}
}

- (IBAction)updateAlt:(id)sender {
		if ([[_altType titleOfSelectedItem] isEqualToString:@"m"]) {
			_altFactor = 1;
		} else if ([[_altType titleOfSelectedItem] isEqualToString:@"ft"]) {
			_altFactor = 3.333;
		}
		
	if (_haveFix == 2) {
		[_alt_field setStringValue:[NSString stringWithFormat:@"%.1f",(_alt * _altFactor)]];
	}
}

- (BOOL)windowShouldClose:(id)sender 
{
    // Set up our timer to periodically call the fade: method.
    [NSTimer scheduledTimerWithTimeInterval:0.05 target:self selector:@selector(fade:) userInfo:nil repeats:YES];
    [_showMenu setState:NSOffState];
    return NO;
}

- (void)setShowMenu:(NSMenuItem *)menu
{
	_showMenu = menu;
}

- (void)fade:(NSTimer *)timer {
    if ([[self window] alphaValue] > 0.0) {
        // If window is still partially opaque, reduce its opacity.
        [[self window] setAlphaValue:[[self window] alphaValue] - 0.2];
    } else {
        // Otherwise, if window is completely transparent, destroy the timer and close the window.
        [timer invalidate];
        
		[[self window] close];
		[WaveHelper setGPSInfoController:NULL];
    }
}

- (IBAction)resetPeak:(id)sender {
	_maxalt = 0;
	_maxvel = 0;
}

@end
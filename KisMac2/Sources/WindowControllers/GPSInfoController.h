/*
 
 File:			GPSInfoController.h
 Program:		KisMAC
 Author:	    themacuser  themacuser -at- gmail.com
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

#import <Cocoa/Cocoa.h>

@class GPSSatInfo;

@interface GPSInfoController : NSWindowController <NSWindowDelegate>
{
	NSMenuItem* _showMenu;
	IBOutlet NSLevelIndicator* _hdop_indicator;
	IBOutlet NSLevelIndicator* _fix_indicator;
	IBOutlet NSTextField* _fix_type;
	IBOutlet NSTextField* _lat_field;
	IBOutlet NSTextField* _lon_field;
	IBOutlet NSTextField* _vel_field;
	IBOutlet NSTextField* _alt_field;
	IBOutlet NSPopUpButton* _speedType;
	IBOutlet NSPopUpButton* _altType;
	IBOutlet NSProgressIndicator* _speedBar;
	IBOutlet NSProgressIndicator* _altBar;
	IBOutlet NSTextField* _hdop_field;
	IBOutlet GPSSatInfo* _satinfo;
	
	float _vel;
	float _velFactor;
	float _maxvel;
	
	float _alt;
	float _altFactor;
	float _maxalt;
	
	int _haveFix;
}
- (void)setShowMenu:(NSMenuItem *)menu;
- (void)updateDataNS:(double)ns EW:(double)ew ELV:(double)elv numSats:(int)sats HDOP:(double)hdop VEL:(float)vel;
- (IBAction)updateSpeed:(id)sender;
- (IBAction)updateAlt:(id)sender;
- (IBAction)resetPeak:(id)sender;
- (void)updateSatPRNForSat:(int)sat prn:(int)prn;
- (void)updateSatSignalStrength:(int)sat signal:(int)signal;
- (void)updateSatUsed:(int)sat used:(int)used;
@end

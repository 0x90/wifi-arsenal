/*
 
 File:			GPSSatInfo.h
 Program:		KisMAC
 Author:	    Geordie  themacuser -at- gmail.com
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


@interface GPSSatInfo : NSView {
	int sat1_strength;
	int sat1_used;
	int sat1_prn;

	int sat2_strength;
	int sat2_used;
	int sat2_prn;

	int sat3_strength;
	int sat3_used;
	int sat3_prn;

	int sat4_strength;
	int sat4_used;
	int sat4_prn;

	int sat5_strength;
	int sat5_used;
	int sat5_prn;

	int sat6_strength;
	int sat6_used;
	int sat6_prn;

	int sat7_strength;
	int sat7_used;
	int sat7_prn;

	int sat8_strength;
	int sat8_used;
	int sat8_prn;

	int sat9_strength;
	int sat9_used;
	int sat9_prn;

	int sat10_strength;
	int sat10_used;
	int sat10_prn;

	int sat11_strength;
	int sat11_used;
	int sat11_prn;

	int sat12_strength;
	int sat12_used;
	int sat12_prn;
	
	NSDictionary *attr;
}

- (id)initWithFrame:(NSRect)frame;
- (void)drawRect:(NSRect)rect;
- (int)getPRNForSat:(int)sat;
- (void)setPRNForSat:(int)sat PRN:(int)prn;
- (int)getUsedForSat:(int)sat;
- (void)setUsedForSat:(int)sat used:(int)used;
- (int)getSignalForSat:(int)sat;
- (int)setSignalForSat:(int)sat signal:(int)signal;
- (void)redraw;


@end

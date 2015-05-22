/*
        
        File:			WaveNetTest.m
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
#import "WaveNet.h"
#import "WaveNetWPACrack.h"
#import "WPA.h"
#import "80211b.h"

@implementation WaveNet(UnitTestExtension)

- (void) testWPAFunctions {
    UInt8 output[40];
    int i, j;
    NSMutableString *ms;
    
    wpaPasswordHash("password",  (const UInt8*)"IEEE", 4, output);
    ms = [NSMutableString string];
    for (i=0; i < WPA_PMK_LENGTH; i++) {
        j = output[i];
        [ms appendFormat:@"%.2x", j];
    }
	XCTAssert(ms, @"f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e");
	 
    wpaPasswordHash("ThisIsAPassword",  (const UInt8*)"ThisIsASSID", 11, output);
    ms = [NSMutableString string];
    for (i=0; i < WPA_PMK_LENGTH; i++) {
        j = output[i];
        [ms appendFormat:@"%.2x", j];
    }
    UKStringsEqual(ms, @"0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af");
	    
    UKTrue(wpaTestPasswordHash());
}

@end

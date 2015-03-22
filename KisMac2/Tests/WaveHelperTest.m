/*
        
        File:			WaveHelperTest.m
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

#import "WaveHelper.h"
#import <XCTest/XCTest.h>

@implementation WaveHelper(UnitTestExtension)

- (void) testVendorNames
{
	UKStringContains([WaveHelper vendorForMAC:@"00:30:65:1B:F0:01"], @"Apple");
	UKStringsEqual(@"Broadcast", [WaveHelper vendorForMAC:@"FF:FF:FF:FF:FF:FF"]);
	UKStringContains([WaveHelper vendorForMAC:@"02:60:8C:00:00:00"], @"3Com");
}
- (void) testURLEncode {
	UKStringsEqual(@"abcd+123", [WaveHelper urlEncodeString:@"abcd 123"]);
	UKStringsEqual(@"http%3a%2f%2fkismac.binaervarianz.de%2f", [WaveHelper urlEncodeString:@"http://kismac.binaervarianz.de/"]);
}
- (void) testMD5Crypt {
	UInt8 key[16];
	WirelessCryptMD5("testkey", key);
	UKStringsEqual(@"5C:C8:16:BD:32:71:FB:0D:05:E8:3A:B9:DE", [WaveHelper hexEncode:key length:13]);
	WirelessCryptMD5("\x12\x12\x12\x12\x12\x12\x12\x12", key);
	UKStringsEqual(@"F5:E0:12:E6:3C:18:78:56:97:77:27:2D:42", [WaveHelper hexEncode:key length:13]);
}
- (void) testHexEncode {
	UKStringsEqual(@"AA",    [WaveHelper hexEncode:"\xaa" length:1]);
	UKStringsEqual(@"11:22", [WaveHelper hexEncode:"\x11\x22" length:2]);
}

@end

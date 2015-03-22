/*
 
 File:			WaveDriverUSBRalinkRT73.m
 Program:		KisMAC
 Author:        pr0gg3d
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

#import "WaveDriverUSBRalinkRT73.h"
#import "../Driver/USBJack/RT73Jack.h"

@implementation WaveDriverUSBRalinkRT73

- (id) init {
    self = [super init];
    if (!self)
        return nil;
    
    _permittedRates = @[[NSNumber numberWithUnsignedInt:KMRate1],
                       [NSNumber numberWithUnsignedInt:KMRate2],
                       [NSNumber numberWithUnsignedInt:KMRate5_5],
                       [NSNumber numberWithUnsignedInt:KMRate11],
                       [NSNumber numberWithUnsignedInt:KMRate6],
                       [NSNumber numberWithUnsignedInt:KMRate9],
                       [NSNumber numberWithUnsignedInt:KMRate12],
                       [NSNumber numberWithUnsignedInt:KMRate18],
                       [NSNumber numberWithUnsignedInt:KMRate24],
                       [NSNumber numberWithUnsignedInt:KMRate36],
                       [NSNumber numberWithUnsignedInt:KMRate48],
                       [NSNumber numberWithUnsignedInt:KMRate54]];
	_currentRate = KMRate11;
    return self;
}

- (bool) wakeDriver{
    [self sleepDriver];
    
    _driver = new RT73Jack;
    _driver->startMatching();
    DBNSLog(@"Matching finished\n");
    if (!(_driver->deviceMatched()))
        return NO;
    
    if(_driver->_init() != kIOReturnSuccess)
        return NO;
    
	_errors = 0;
    
    return YES;
}

+ (NSString*) description {
    return NSLocalizedString(@"USB RT73 device", "long driver description");
}

+ (NSString*) deviceName {
    return NSLocalizedString(@"USB RT73 device", "short driver description");
}

#pragma mark -

@end

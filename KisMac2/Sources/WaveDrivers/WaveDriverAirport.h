/*
        
        File:			WaveDriverAirport.h
        Program:		KisMAC
		Author:			Geofrey Kruse
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

#import <Foundation/Foundation.h>
#import <CoreWLAN/CoreWLAN.h>
#import "WaveDriver.h"


@interface WaveDriverAirport : WaveDriver
{
    CWInterface * airportInterface;
    NSArray * networks;
}

+ (int) airportInstanceCount;
+(WaveDriverAirport*)sharedInstance;

- (bool)joinBSSID:(UInt8*) bssid withPassword:(NSString*)passwd;
@end

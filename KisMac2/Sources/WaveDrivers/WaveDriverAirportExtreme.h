/*
        
        File:			WaveDriverAirportExtreme.h
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

#import <Cocoa/Cocoa.h>
#import "WaveDriver.h"

enum APExtType 
{
	APExtTypeUnknown,
	APExtTypeBcm,
	APExtTypeAth5414
};

#define DLT_PRISM_HEADER         119
#define DLT_IEEE802_11           105
#define DLT_IEEE802_11_RADIO_AVS 163
#define DLT_IEEE802_11_RADIO     127
#define DLT_TYPE_ERR             -1

@class CWInterface;

@interface WaveDriverAirportExtreme : WaveDriver
{
	enum APExtType _apeType;
    int DLTType;
    
    CWInterface * airportInterface;
}

@end

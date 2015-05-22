/*
        
        File:			WaveWeakContainer.h
        Program:		KisMAC
		Author:			Michael Roßberg
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


@interface WaveWeakContainer : NSObject {
    UInt8 **_data[LAST_BIT];
    UInt32 _count;
}

- (id)initWithData:(NSData*)data;

- (void)setBytes:(const UInt8*)bytes forIV:(const UInt8*)iv;
- (int)count;

- (void)addData:(NSData*)data;
- (NSData*)data;
@end

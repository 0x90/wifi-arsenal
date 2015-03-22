/*
        
        File:			MapControlPanel.h
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

#import <AppKit/AppKit.h>
#import "BISubView.h"

@class MapControlItem;

@interface MapControlPanel : BISubView {
	BOOL _restrictedMode;
    MapControlItem  *_items[6];
}

- (void)setRestrictedMode:(BOOL)restricedMode;
- (void)mouseMovedToPoint:(NSPoint)p;
- (void)mouseDownAtPoint:(NSPoint)p;
- (void)slide:(BOOL)visible;

@end

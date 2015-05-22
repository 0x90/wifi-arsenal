/*
        
        File:			MapControlPanel.m
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

#import "MapControlPanel.h"
#import "WaveHelper.h"
#import "MapView.h"
#import "MapControlItem.h"

#define CONTROLSIZE 30.0
#define CURVERAD 5.0
#define BORDER 1.0
#define OFFSET (CURVERAD + BORDER)
#define TRIANGLESIZE 15.0

@implementation MapControlPanel

- (id)init {
    int i, x, y;
    self = [super init];
    if (!self) return nil;
    
	for (x=0; x<3; ++x) {
        for (y=0; y<2; ++y) {
			i = (x + (y * 3));
			_items[i] = [[MapControlItem alloc] initForID:i];
			[self addSubView:_items[i]];
		}
	}
	[self setRestrictedMode:NO];
	
    return self;
}

- (void)setRestrictedMode:(BOOL)restricedMode {
    int x, y;
	NSPoint p;
	p = [self location];
	
	if (restricedMode) {
		_restrictedMode = restricedMode;
		p.x += CONTROLSIZE;
		[_items[0] setVisible:NO];
		[_items[1] setVisible:NO];
		[_items[2] setVisible:NO];
		[_items[3] setLocation:NSMakePoint(0, 0)];
		[_items[4] setVisible:NO];
		[_items[5] setLocation:NSMakePoint(CONTROLSIZE, 0)];
		[[WaveHelper mapView] setNeedsDisplayInRect:_frame];		
		[self setSize:NSMakeSize(2 * CONTROLSIZE, 1 * CONTROLSIZE)];
		[self setLocation:p];
		[self slide:YES];
	} else {
		_restrictedMode = restricedMode;
		p.x -= CONTROLSIZE;
		[[WaveHelper mapView] setNeedsDisplayInRect:_frame];
		[self setSize:NSMakeSize(3 * CONTROLSIZE, 2 * CONTROLSIZE)];
		[self setLocation:p];
		for (x=0; x<3; ++x) {
			for (y=0; y<2; ++y) {
				[_items[(x + (y * 3))] setLocation:NSMakePoint(x*CONTROLSIZE, y*CONTROLSIZE)];
				[_items[(x + (y * 3))] setVisible:YES];
			}
		}
		[self slide:YES];
	}
}

- (int)itemAtPoint:(NSPoint)p {
    int x, y, i;
    p.x -= _frame.origin.x;
    p.y -= _frame.origin.y;
        
    x = p.x / CONTROLSIZE;
    y = p.y / CONTROLSIZE;
    if (x > 2 || y > 1) {
        DBNSLog(@"MapControlPanel: Mouse out of bounds %f %f", p.x, p.y);
        return 3;
    }
    
    i = x + (y * 3);
	if (_restrictedMode) {
		if (i == 0) i = 3;
		else if (i == 1) i = 5;
		NSAssert(i==3 || i == 5, @"Index is out of bounds");
	} else {
		NSAssert(i>=0 && i < 6, @"Index is out of bounds");
	}
	return i;
}

- (void)mouseMovedToPoint:(NSPoint)p {
	int i = [self itemAtPoint:p];
	[_items[i] mouseEntered:_frame.origin];
}

- (void)mouseDownAtPoint:(NSPoint)p {
	int i = [self itemAtPoint:p];
	[_items[i] mouseClicked:_frame.origin];
    
    switch(i) {
    case 0:
        [[WaveHelper mapView] goLeft:self];
        break;
    case 1:
        [[WaveHelper mapView] goDown:self];
        break;
    case 2:
        [[WaveHelper mapView] goRight:self];
        break;
    case 3:
        [[WaveHelper mapView] zoomIn:self];
        break;
    case 4:
        [[WaveHelper mapView] goUp:self];
        break;
    case 5:
        [[WaveHelper mapView] zoomOut:self];
        break;
    }
}

- (void)slide:(BOOL)visible {
	int i;

	if (_restrictedMode) {
		[_items[3] slide:visible forParentLocation:_frame.origin];
		[_items[5] slide:visible forParentLocation:_frame.origin];
	} else {
		for (i = 0; i < 6; ++i) {
			[_items[i] slide:visible forParentLocation:_frame.origin];
		}
	}
}

@end

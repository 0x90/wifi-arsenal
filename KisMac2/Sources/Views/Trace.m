/*
        
        File:			Trace.m
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

#import "Trace.h"
#import "WaveHelper.h"
#import "MapView.h"

struct pointCoords {
	double x, y;
} __attribute__((packed));

@implementation Trace

- (id)init {
    self = [super init];
    if (!self) return nil;
    
    _trace = [NSMutableArray array];
    _state = stateNoPointPresent;
    return self;
}

- (BOOL)addPoint:(waypoint)w {
    NSMutableArray* a;
    waypoint old;
    
    switch(_state) {
    case stateNoPointPresent:
        _lastPoint = [BIValuePair valuePairFromWaypoint:w];
        _state = stateFirstPointPresent;
        break;
    case stateFirstPointPresent:
        old = [_lastPoint wayPoint];
        if (w._long == old._long && w._lat == old._lat) return NO;
        a = [NSMutableArray arrayWithObjects:_lastPoint, [BIValuePair valuePairFromWaypoint:w], nil];
        [_trace addObject:a];
        _state = stateMultiPointsPresent;
        break;
    case stateMultiPointsPresent:
        old = [[[_trace lastObject] lastObject] wayPoint];
        if (w._long == old._long && w._lat == old._lat) return NO;
        [[_trace lastObject] addObject:[BIValuePair valuePairFromWaypoint:w]];
        break;
    }
    return YES;
}

- (void)cut {
    _state = stateNoPointPresent;
}

- (BOOL)addTrace:(NSMutableArray*)trace {
	int i, j;
	id obj;
	BIValuePair *vp;
	const struct pointCoords *pL;
	NSMutableArray *a;
	
	for (i = 0; i < [trace count]; ++i) {
		obj = trace[i];
		if ([obj isKindOfClass:[NSMutableArray class]]) {
			[_trace insertObject:obj atIndex:0];
		} else if ([obj isKindOfClass:[NSData class]]) {
			NSParameterAssert([(NSData*)obj length] % sizeof(struct pointCoords) == 0);
			
			a = [NSMutableArray arrayWithCapacity:[(NSData*)obj length] / sizeof(struct pointCoords)];
			pL = (const struct pointCoords *)[obj bytes];
		
			for (j = 0; j < ([(NSData*)obj length] / sizeof(struct pointCoords)); ++j) {
				vp = [BIValuePair new];
				[vp setPairX:pL->x Y:pL->y];
				[a addObject:vp];
				++pL;
			}
			if (a) {
				[_trace insertObject:a atIndex:0];
			}
		}
	}
    return YES;
}

- (BOOL)setTrace:(NSMutableArray*)trace {
    
	_trace = [NSMutableArray array];
    [self addTrace: trace];
    [self cut];

    return YES;
}

- (NSMutableArray*)trace {
	BIValuePair *vp;
	struct pointCoords *pL;
	NSArray *subtrace;
	NSMutableArray *a;
	int i, j;
	NSMutableData *coord;
	unsigned int c = [_trace count];
	
	if (c == 0) return nil;
	
	a = [NSMutableArray arrayWithCapacity:c];
	for (i = 0; i < c; ++i) {
		subtrace = _trace[i];
		
		coord = [NSMutableData dataWithLength:[subtrace count] * sizeof(struct pointCoords)];
		pL = (struct pointCoords *)[coord mutableBytes];
		
		for (j = 0; j < [subtrace count]; ++j) {
			vp = subtrace[j];
			pL->x = [vp getX];
			pL->y = [vp getY];
			++pL;
		}
		
		[a addObject:coord];
	}

    return a;
}

#pragma mark -

- (void)drawSubAtPoint:(NSPoint)p inRect:(NSRect)rect {
    MapView *m;
    NSBezierPath *b;
    NSPoint p2;
    int i, j;
    NSArray *tour;
    NSColor *color = [WaveHelper intToColor:[[NSUserDefaults standardUserDefaults] objectForKey:@"TraceColor"]];
    NSAffineTransform *t;
    
    if ([_trace count] == 0) return;
    [color set];
    
    m = [WaveHelper mapView];
    t = [NSAffineTransform transform];
    [t translateXBy:p.x yBy:p.y];
    
    for (i = 0; i < [_trace count]; ++i) {
        tour = _trace[i];
        b = [NSBezierPath bezierPath];
        p2 = [m pixelForCoordinate:[tour[0] wayPoint]];
        [b moveToPoint:p2];
        for (j = 1; j < [tour count]; ++j) {
            p2 = [m pixelForCoordinate:[tour[j] wayPoint]];
            [b lineToPoint:p2];        
        }
        [b transformUsingAffineTransform:t];
        [b setLineWidth:2];
        [b stroke];
    }
}

#pragma mark -

@end

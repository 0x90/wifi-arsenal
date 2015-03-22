/*
        
        File:			MapControlItem.m
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

#import "MapControlItem.h"
#import "WaveHelper.h"
#import "MapView.h"

#define CONTROLSIZE 30.0
#define CURVERAD 5.0
#define BORDER 1.0
#define OFFSET (CURVERAD + BORDER)
#define TRIANGLESIZE 15.0

col fillColor() 
{
    col c;
    c.red = 35.0/255.0;
    c.green = 45.33333/255.0;
    c.blue = 58.666/255.0;
    c.alpha = .5;
    return c;
}

col borderColor() 
{
    col c;
    c.red = 105.0/255.0;
    c.green = 136.0/255.0;
    c.blue = 175.0/255.0;
    c.alpha = 1.0;
    return c;
}

col highBorderColor()
{
    col c;
    c.red = 1;
    c.green = 1;
    c.blue = 1;
    c.alpha = 1;
    return c;
}

col highFillColor()
{
    col c;
    c.red = .333333;
    c.green = .333333;
    c.blue = .333333;
    c.alpha = .5;
    return c;
}

col clickBorderColor() {
    return fillColor();
}

col clickFillColor() {
    return borderColor();
}

NSColor* col2NSColor(col c) {
    return [NSColor colorWithDeviceRed:c.red green:c.green blue:c.blue alpha:c.alpha];
}

col delta(col c1, col c2, int speed) {
    col c;
    c.red   = (c1.red   - c2.red)   / speed;
    c.green = (c1.green - c2.green) / speed;
    c.blue  = (c1.blue  - c2.blue)  / speed;
    c.alpha = (c1.alpha - c2.alpha) / speed;
    return c;
}

@implementation MapControlItem

- (void)_drawFrameForIndex:(int)index {
    NSBezierPath *b = [NSBezierPath bezierPath];
    NSAffineTransform *trans;
	
	trans = [NSAffineTransform transform];
	[trans scaleBy:_slideScale];
	[trans rotateByDegrees:90.0 - (90.0 * _slideScale)];
	[trans translateXBy:-CONTROLSIZE/2 yBy:-CONTROLSIZE/2];
	NSAffineTransform *t = [NSAffineTransform transform];
	[t translateXBy:CONTROLSIZE/2 yBy:CONTROLSIZE/2];
	[trans appendTransform:t];
	
    [b moveToPoint:NSMakePoint(OFFSET, BORDER)];
    
    [b appendBezierPathWithArcWithCenter:NSMakePoint(CONTROLSIZE - OFFSET, OFFSET) radius:CURVERAD
			       startAngle:270
				 endAngle:0];
    [b appendBezierPathWithArcWithCenter:NSMakePoint(CONTROLSIZE - OFFSET, CONTROLSIZE - OFFSET) radius:CURVERAD
			       startAngle:0
				 endAngle:90];
    [b appendBezierPathWithArcWithCenter:NSMakePoint(OFFSET, CONTROLSIZE - OFFSET) radius:CURVERAD
			       startAngle:90
				 endAngle:180];
    [b appendBezierPathWithArcWithCenter:NSMakePoint(OFFSET, OFFSET) radius:CURVERAD
			       startAngle:180
				 endAngle:270];
    [b closePath];
    b = [trans transformBezierPath:b];
	
    [col2NSColor(_current.fill) set];
    [b fill];
    
    [col2NSColor(_current.border) set];
    [b stroke];
    
    b = [NSBezierPath bezierPath];
    switch (index) {
    case 0:
        [b moveToPoint:NSMakePoint(CONTROLSIZE/2 + TRIANGLESIZE/2 - BORDER, CONTROLSIZE/2 - TRIANGLESIZE/2)];
        [b relativeLineToPoint:NSMakePoint(0, TRIANGLESIZE)];
        [b relativeLineToPoint:NSMakePoint(-TRIANGLESIZE, -TRIANGLESIZE/2)];
        break;
    case 1:
        [b moveToPoint:NSMakePoint(CONTROLSIZE/2 - TRIANGLESIZE/2, CONTROLSIZE/2 + TRIANGLESIZE/2)];
        [b relativeLineToPoint:NSMakePoint(TRIANGLESIZE, 0)];
        [b relativeLineToPoint:NSMakePoint(-TRIANGLESIZE/2, -TRIANGLESIZE)];
        break;
    case 2:
        [b moveToPoint:NSMakePoint(CONTROLSIZE/2 - TRIANGLESIZE/2 - BORDER, CONTROLSIZE/2 - TRIANGLESIZE/2)];
        [b relativeLineToPoint:NSMakePoint(0, TRIANGLESIZE)];
        [b relativeLineToPoint:NSMakePoint(TRIANGLESIZE, -TRIANGLESIZE/2)];
        break;
    case 3:
        [b moveToPoint:NSMakePoint(CONTROLSIZE/2, CONTROLSIZE/2)];
        [b appendBezierPathWithRect:NSMakeRect(CONTROLSIZE/2 - TRIANGLESIZE/8, CONTROLSIZE/2 - TRIANGLESIZE/2, TRIANGLESIZE/4, TRIANGLESIZE)];
    case 5:
        [b moveToPoint:NSMakePoint(CONTROLSIZE/2, CONTROLSIZE/2)];
        [b appendBezierPathWithRect:NSMakeRect(CONTROLSIZE/2 - TRIANGLESIZE/2, CONTROLSIZE/2 - TRIANGLESIZE/8, TRIANGLESIZE, TRIANGLESIZE/4)];
        break;
    case 4:
        [b moveToPoint:NSMakePoint(CONTROLSIZE/2 - TRIANGLESIZE/2, CONTROLSIZE/2 - TRIANGLESIZE/2)];
        [b relativeLineToPoint:NSMakePoint(TRIANGLESIZE, 0)];
        [b relativeLineToPoint:NSMakePoint(-TRIANGLESIZE/2, TRIANGLESIZE)];
        break;
    }
	
    [b closePath];
	b = [trans transformBezierPath:b];
	
    [b fill];
}

- (void)_generateCache {
    NSImage *img = [[NSImage alloc] initWithSize:NSMakeSize(CONTROLSIZE, CONTROLSIZE)];
    [img lockFocus];
	[self _drawFrameForIndex:_index];
    [img unlockFocus];
    [self setImage:img];
}

- (id)initForID:(int)i {
    self = [self init];
    if (!self) return nil;
    
	_index = i;
    _zoomLock = [[NSLock alloc] init];
    _slideLock = [[NSLock alloc] init];
	_current.fill    = fillColor();
	_current.border  = borderColor();
	_slideScale = 1;
    [self _generateCache];
    
    return self;
}

- (void)mouseEntered:(NSPoint)parentLocation {
	_parentLocation = parentLocation;
    _target.fill    = highFillColor();
    _target.border  = highBorderColor();
    _delta.fill   = delta(_target.fill  , _current.fill, 5);
    _delta.border = delta(_target.border, _current.border, 5);
    
    [NSThread detachNewThreadSelector:@selector(zoomThread:) toTarget:self withObject:nil];

    if (_timeout) {
        [_timeout invalidate];
    }
    _timeout = [NSTimer scheduledTimerWithTimeInterval:1.0 target:self selector:@selector(timeout:) userInfo:nil repeats:NO];
}

- (void)mouseClicked:(NSPoint)parentLocation {
	_parentLocation = parentLocation;
    _target.fill    = clickFillColor();
    _target.border  = clickBorderColor();
    _delta.fill   = delta(_target.fill  , _current.fill, 1);
    _delta.border = delta(_target.border, _current.border, 1);

    [NSThread detachNewThreadSelector:@selector(zoomThread:) toTarget:self withObject:nil];

    if (_timeout) {
        [_timeout invalidate];
    }
    _timeout = [NSTimer scheduledTimerWithTimeInterval:0.1 target:self selector:@selector(timeout:) userInfo:nil repeats:NO];
}

- (void)slide:(BOOL)visible forParentLocation:(NSPoint)parentLocation {
	_slideScale = visible ? 0 : 1;
	_parentLocation = parentLocation;

    [NSThread detachNewThreadSelector:@selector(slideThread:) toTarget:self withObject:@(visible)];
}

- (void)timeout:(NSTimer*)timer {
    _target.fill    = fillColor();
    _target.border  = borderColor();
    _delta.fill   = delta(_target.fill  , _current.fill, 20);
    _delta.border = delta(_target.border, _current.border, 20);
    
    [NSThread detachNewThreadSelector:@selector(zoomThread:) toTarget:self withObject:nil];
    _timeout = NULL;
}

#define ADJUSTCOMP(COMP) if (_delta.COMP != 0 && (_delta.COMP > 0 ? _target.COMP > _current.COMP : _target.COMP < _current.COMP)) { _current.COMP += _delta.COMP; didSomething = YES;  }
#define ADJUSTX(X) ADJUSTCOMP(X.red) ADJUSTCOMP(X.green) ADJUSTCOMP(X.blue) ADJUSTCOMP(X.alpha)

- (void)zoomThread:(id)object {
    @autoreleasepool {
        BOOL didSomething;
        NSRect f = _frame;
	f.origin.x += _parentLocation.x;
	f.origin.y += _parentLocation.y;
	
        if([_zoomLock tryLock]) {
            while(YES) {
                didSomething = NO;
			ADJUSTX(fill);
			ADJUSTX(border);
                if (!didSomething) break;
                [self _generateCache];
                [[WaveHelper mapView] setNeedsDisplayInRect:f];
                [NSThread sleepUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
            }
            [_zoomLock unlock];
        }

    }
}

- (void)slideThread:(id)object {
    @autoreleasepool {
		BOOL slideIn = [object boolValue];
    NSRect f = _frame;
		f.origin.x += _parentLocation.x;
		f.origin.y += _parentLocation.y;
		
    if([_slideLock tryLock]) {
			if (slideIn) [self setVisible:YES];
        while(slideIn ? _slideScale < 1.1 : _slideScale > 0.1) {
				if (slideIn) _slideScale += 0.1;
				else _slideScale -= 0.1;
            [self _generateCache];
            [[WaveHelper mapView] setNeedsDisplayInRect:f];
            [NSThread sleepUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
        }
			if (slideIn) {
				_slideScale = 1;
				[self _generateCache];
            [[WaveHelper mapView] setNeedsDisplayInRect:f];
			} else [self setVisible:NO];
        [_slideLock unlock];
    }

    }
}


#pragma mark -

- (void)dealloc {
	if (_timeout) {
		[_timeout invalidate];
	}
}

@end

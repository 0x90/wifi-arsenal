/*
        
        File:			BISubView.m
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

#import "BISubView.h"

@implementation BISubView

- (id)init {
    self = [super init];
    if (self) {
        _subViews = [NSMutableArray array];
        _lock = [[NSRecursiveLock alloc] init];
        _visible = YES;
        _frame = NSZeroRect;
    }
    return self;
}

- (id)initWithFrame:(NSRect)frame {
	self=[self init];
    if (!self) return nil;
    _frame = frame;
    return self;
}

- (id)initWithSize:(NSSize)size {
    self=[self init];
    if (!self) return nil;
    _frame.size = size;
    return self;
}

#pragma mark -

- (BOOL)addSubView:(BISubView*)subView {
    NSParameterAssert(subView);
    
    [_lock lock];
    if ([_subViews containsObject:subView]) {
        [_lock unlock];
        return NO;
    }
    
    [_subViews addObject:subView];
    [_lock unlock];
    return YES;
}

- (BOOL)removeSubView:(BISubView*)subView {
    NSParameterAssert(subView);

    [_lock lock];
    if (![_subViews containsObject:subView]) {
        [_lock unlock];
        return NO;
    }

    [_subViews removeObject:subView];
    [_lock unlock];
    return YES;
}

- (NSArray*)subViews {
    return _subViews;
}

#pragma mark -

- (void)setLocation:(NSPoint)loc {
    _frame.origin = loc;
}

- (BOOL)setSize:(NSSize)size {
    _frame.size = size;
    return YES;
}

- (NSSize)size {
    return _frame.size;
}

- (NSPoint)location {
    return _frame.origin;
}

- (NSRect)frame {
    return _frame;
}

- (void)setVisible:(BOOL)visible {
    _visible = visible;
}

- (BOOL)visible {
    return _visible;
}

- (void)drawSubAtPoint:(NSPoint)p inRect:(NSRect)rect {
    //done in subclasses
}

- (BOOL)drawAtPoint:(NSPoint)p inRect:(NSRect)rect {
    int i;
    if (!_visible) return NO;
    
    p.x += _frame.origin.x;
    p.y += _frame.origin.y;

    if (!NSIntersectsRect(NSMakeRect(p.x,p.y,_frame.size.width,_frame.size.height), rect))
		return NO;
    
    [_lock lock];
    for (i = 0; i < [_subViews count]; ++i)
        [(BISubView*)_subViews[i] drawAtPoint:p inRect:rect];
    [_lock unlock];
    
    [self drawSubAtPoint:p inRect:rect];
    
    return YES;
}

#pragma mark -


@end

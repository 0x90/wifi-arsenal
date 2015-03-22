/*
        
        File:			BIView.m
        Program:		KisMAC
	Author:			Michael Roßberg
				mick@binaervarianz.de
	Description:		KisMAC is a wireless stumbler for MacOS X.
                
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

#import "BIView.h"
#import "BISubView.h"

@implementation BIView

- (id)initWithFrame:(NSRect)frame {
    self = [super initWithFrame:frame];
    if (self) {
        _lock = [[NSRecursiveLock alloc] init];
        _subViews = [NSMutableArray array];
    }
    return self;
}

- (BOOL)isOpaque { return YES; }
- (BOOL)acceptsFirstResponder { return YES; }
- (BOOL)becomeFirstResponder  { return YES; }
- (void)drawRectSub:(NSRect)rect { }

- (void)drawRect:(NSRect)rect {
    int i;

#if USECOREGRAPHICS    
    CGRect r;
    CGContextRef myContext = [[NSGraphicsContext currentContext] graphicsPort];

    memcpy(&r, &rect, sizeof(CGRect));
    CGContextFillRect(myContext, r);
#else
    NSRectFill(rect);
#endif

    [self drawRectSub:rect];
    
    [_lock lock];
    for (i = 0; i < [_subViews count]; ++i) {
        [(BISubView*)_subViews[i] drawAtPoint:NSZeroPoint inRect:rect];
    }
    [_lock unlock];
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


@end

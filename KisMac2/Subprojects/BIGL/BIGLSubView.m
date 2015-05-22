/*        
        File:			BIGLSubView.m
        Program:		binaervarianz OpenGL Framework
	Author:			Michael Roßberg
				mick@binaervarianz.de
	Description:		This framework provides abstract Cocoa methods to quickly draw 2D sprites
                
        This file is part of BIGL.

    BIGL is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    BIGL is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with BIGL; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#import "BIGLSubView.h"

@implementation BIGLSubView

- (id)init {
    self = [super init];
    if (self) {
        _subViews = [NSMutableArray array];
        _visible = YES;
        _loc = NSZeroPoint;
    }
    return self;
}

#pragma mark -

- (BOOL)addSubView:(BIGLSubView*)subView {
    NSParameterAssert(subView);
    
    if ([_subViews containsObject:subView]) return NO;
    [_subViews addObject:subView];
    return YES;
}
- (BOOL)removeSubView:(BIGLSubView*)subView {
    NSParameterAssert(subView);

    if (![_subViews containsObject:subView]) return NO;
    [_subViews removeObject:subView];
    return YES;
}
- (NSArray*)subViews {
    return _subViews;
}

#pragma mark -

- (void)setLocation:(NSPoint)loc {
    _loc = loc;
}

- (void)setVisible:(BOOL)visible {
    _visible = visible;
}

- (BOOL)visible {
    return _visible;
}

- (void)drawSubAtPoint:(NSPoint)p {
    //done in subclasses
}

- (BOOL)drawAtPoint:(NSPoint)p {
    int i;
    if (!_visible) return NO;
    
    p.x += _loc.x;
    p.y += _loc.y;

    for (i = 0; i < [_subViews count]; ++i)
        [(BIGLSubView*)_subViews[i] drawAtPoint:p];

    glPushMatrix();
    
    [self drawSubAtPoint:p];
    
    glPopMatrix();

    return YES;
}

- (void)drawCocoaSubAtPoint:(NSPoint)p {

}

- (BOOL)drawCocoaAtPoint:(NSPoint)p {
    int i;
    if (!_visible) return NO;
    
    p.x += _loc.x;
    p.y += _loc.y;

    for (i = 0; i < [_subViews count]; ++i)
        [(BIGLSubView*)_subViews[i] drawCocoaAtPoint:p];

    [self drawCocoaSubAtPoint:p];
    
    return YES;
}

#pragma mark -


@end

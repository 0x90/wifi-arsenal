/*
        File:			BIGLPolyView.m
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

#import "BIGLPolyView.h"

@implementation BIGLPolyView

- (id)initWithPolygon:(NSArray*)p {
    return [self initWithPolygon:p andColor:[NSColor whiteColor]];
}

- (id)initWithPolygon:(NSArray*)p andColor:(NSColor*)c {
    self = [super init];
    if (!self) return nil;
    
    [self setPolygon:p];
    [self setColor:c];
    
    return self;
}

#pragma mark -

- (bool)setPolygon:(NSArray*)polygon {
    NSParameterAssert(polygon);
    NSParameterAssert([polygon count] % 2 == 0);
    
    _polygon = polygon;
    return YES;
}

- (void)setColor:(NSColor*)color {
    NSParameterAssert(color);
    
    color = [color colorUsingColorSpaceName:NSDeviceRGBColorSpace];
    _color[0] = [color redComponent];
    _color[1] = [color greenComponent];
    _color[2] = [color blueComponent];
    _color[3] = [color alphaComponent];
}

#pragma mark -

- (void)drawSubAtPoint:(NSPoint)p {
    int i;
    
    if ([_polygon count] < 6) return;
    
    glBlendFunc(GL_SRC_ALPHA_SATURATE, GL_ONE); // ditto
    glBegin(GL_POLYGON);
    glEnable(GL_POLYGON_SMOOTH);
    glHint(GL_POLYGON_SMOOTH_HINT, GL_NICEST);
    glColor4fv(_color);
    for(i = 0; i < [_polygon count]; i+=2) {
        glVertex2f([_polygon[i] floatValue] + p.x, [_polygon[i+1] floatValue] +  p.y);
    }

    glEnd();
}

- (void)drawCocoaSubAtPoint:(NSPoint)p {
    int i;
    NSBezierPath *bp = [NSBezierPath bezierPath];
    
    if ([_polygon count] < 6) return;
    [[NSColor colorWithDeviceRed:_color[0] green:_color[1] blue:_color[2] alpha:_color[3]] set];

    [bp moveToPoint:NSMakePoint([_polygon[0] floatValue] + p.x, [_polygon[1] floatValue] + p.y)];
    for(i = 2; i < [_polygon count]; i+=2) {
        [bp lineToPoint:NSMakePoint([_polygon[i] floatValue] + p.x, [_polygon[i+1] floatValue] + p.y)];
    }
    [bp closePath];
    [bp fill];
}

#pragma mark -

@end

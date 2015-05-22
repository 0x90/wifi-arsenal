/*
        File:			BIGLLineView.m
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

#import "BIGLLineView.h"

@implementation BIGLLineView

- (id)initWithLines:(NSArray*)l {
    return [self initWithLines:l andColor:[NSColor whiteColor]];
}

- (id)initWithLines:(NSArray*)l andColor:(NSColor*)c {
    self = [super init];
    if (!self) return nil;
    
    _width = 0.5;
    [self setLines:l];
    [self setColor:c];
    
    return self;
}

#pragma mark -

- (bool)setLines:(NSArray*)lines {
    NSParameterAssert(lines);
    NSParameterAssert([lines count] % 4 == 0);
    
    _lines = lines;
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

- (void)setLineWidth:(float)width {
    _width = width;
}

#pragma mark -

- (void)drawSubAtPoint:(NSPoint)p {
    int i;
    
    if ([_lines count] < 4) return;

    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); // ditto
    glLineWidth(_width);
    glColor4fv(_color);
    for(i = 0; i < [_lines count]; i+=4) {
        glBegin(GL_LINES);
        glVertex2f([_lines[i]   floatValue] + p.x, [_lines[i+1] floatValue] +  p.y);
        glVertex2f([_lines[i+2] floatValue] + p.x, [_lines[i+3] floatValue] +  p.y);
        glEnd();
    }
}

- (void)drawCocoaSubAtPoint:(NSPoint)p {
    int i;
    NSBezierPath *bp = [NSBezierPath bezierPath];
    
    if ([_lines count] < 4) return;
    [[NSColor colorWithDeviceRed:_color[0] green:_color[1] blue:_color[2] alpha:_color[3]] set];

    [bp setLineWidth:_width];
    for(i = 0; i < [_lines count]; i+=4) {
        [bp moveToPoint:NSMakePoint([_lines[i] floatValue] + p.x, [_lines[i+1] floatValue] + p.y)];
        [bp lineToPoint:NSMakePoint([_lines[i+2] floatValue] + p.x, [_lines[i+3] floatValue] + p.y)];
    }
    [bp stroke];
}

#pragma mark -

@end

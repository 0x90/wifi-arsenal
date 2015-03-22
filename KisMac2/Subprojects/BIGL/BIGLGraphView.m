/*
        File:			BIGLGraphView.m
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

#import "BIGLGraphView.h"

@implementation BIGLGraphView

- (id)initWithGraph:(NSArray*)p {
    return [self initWithGraph:p andColor:[NSColor whiteColor]];
}

- (id)initWithGraph:(NSArray*)p andColor:(NSColor*)c {
    self = [super init];
    if (!self) return nil;
    
    [self setGraph:p];
    [self setColor:c];
    
    return self;
}

#pragma mark -

- (bool)setGraph:(NSArray*)graph {
    NSParameterAssert(graph);
    NSParameterAssert([graph count] % 2 == 0);
    
    _graph = graph;
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
    GLfloat y1, y2;
    
    if ([_graph count] < 2) return;
    
    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); // ditto
    glColor4fv(_color);
    for(i = 2; i < [_graph count]; i+=2) {
        y1 = [_graph[i+1] floatValue];
        y2 = [_graph[i-1] floatValue];
        
        if (y1 == 0 && y2 == 0) continue;
        
        glBegin(GL_QUADS);
        glVertex2f([_graph[i] floatValue] + p.x, p.y);
        glVertex2f([_graph[i] floatValue] + p.x, y1 +  p.y);
        glVertex2f([_graph[i-2] floatValue] + p.x, y2 +  p.y);
        glVertex2f([_graph[i-2] floatValue] + p.x, p.y);
        glEnd();
        
        //smooth edges
        glLineWidth(2);
        glBegin(GL_LINES);
        glVertex2f([_graph[i-2] floatValue] + p.x, y2 +  p.y);
        glVertex2f([_graph[i] floatValue] + p.x, y1 +  p.y);
        glEnd();
    }

}

- (void)drawCocoaSubAtPoint:(NSPoint)p {
    int i;
    NSBezierPath *bp = [NSBezierPath bezierPath];
    
    if ([_graph count] < 2) return;
    [[NSColor colorWithDeviceRed:_color[0] green:_color[1] blue:_color[2] alpha:_color[3]] set];

    [bp moveToPoint:NSMakePoint([_graph[0] floatValue] + p.x, p.y)];
    for(i = 0; i < [_graph count]; i+=2) {
        [bp lineToPoint:NSMakePoint([_graph[i] floatValue] + p.x, [_graph[i+1] floatValue] + p.y)];
    }
    [bp lineToPoint:NSMakePoint([_graph[i-2] floatValue] + p.x, p.y)];
    
    [bp closePath];
    [bp fill];
    [bp setLineWidth:2];
    [bp stroke];
}

#pragma mark -

@end

/*
        File:			BIGLLineView.h
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

#import <Foundation/Foundation.h>
#import "BIGLSubView.h"

@interface BIGLLineView : BIGLSubView {
    NSArray         *_lines;
    GLfloat         _color[4];
    GLfloat         _width;
}

- (id)initWithLines:(NSArray*)l;
- (id)initWithLines:(NSArray*)l andColor:(NSColor*)c;

- (bool)setLines:(NSArray*)lines;
- (void)setColor:(NSColor*)color;
- (void)setLineWidth:(float)width;

@end

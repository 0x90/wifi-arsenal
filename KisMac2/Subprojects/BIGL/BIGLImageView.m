/*
        File:			BIGLImageView.h
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

#import "BIGLImageView.h"

@implementation BIGLImageView

- (void)deleteTexture {
    if (_texName && _cgl_ctx) {
        (*_cgl_ctx->disp.delete_textures)(_cgl_ctx->rend, 1, &_texName);
        _texName = 0; // ensure it is zeroed for failure cases
        _cgl_ctx = 0;
    }
}

- (void)genTexture { // generates the texture without drawing texture to current context
    NSBitmapImageRep    *bitmap;
    NSSize              frameSize;

    [self deleteTexture];
 
    [_img lockFocus];
    frameSize = [_img size];
    bitmap = [[NSBitmapImageRep alloc] initWithFocusedViewRect:NSMakeRect(0, 0, frameSize.width, frameSize.height)];
    [_img unlockFocus];
    
    _texSize = [bitmap size];
    
    // if we successfully retrieve a current context (required)
    if ((_cgl_ctx = CGLGetCurrentContext())) 
    { 
        glGenTextures(1, &_texName);
        glBindTexture(GL_TEXTURE_RECTANGLE_EXT, _texName);
        glTexImage2D(GL_TEXTURE_RECTANGLE_EXT, 0, GL_RGBA, _texSize.width, _texSize.height, 0, ([bitmap bitsPerPixel] == 24 ? GL_RGB : GL_RGBA), GL_UNSIGNED_BYTE, [bitmap bitmapData]);
    } else
        NSLog (@"ImageTexture -genTexture: Failure to get current OpenGL context\n");
    
}

#pragma mark -

- (id)initWithImage:(NSImage*)img {
    self = [super init];
    if (!self) return nil;
    
    NSParameterAssert(img);
    
    _cgl_ctx = NULL;
    _texName = 0;
    _texSize = NSMakeSize(0, 0);
    _img = img;
    
    return self;
}

- (void)setImage:(NSImage*)img {
    NSParameterAssert(img);
    
    [self deleteTexture];
    _img = img;
}

- (NSImage*)image {
    return _img;
}

#pragma mark -

- (void)drawSubAtPoint:(NSPoint)p {
    NSRect bounds;
    
    if (!_img) return;
    
    if (!_texName) 
        [self genTexture];
    
    bounds.origin = p;
    bounds.size   = _texSize;
  
    if (_texName) {
        glEnable (GL_TEXTURE_RECTANGLE_EXT);
        glColor4f(1,1,1,1);
        glBindTexture(GL_TEXTURE_RECTANGLE_EXT, _texName);
        //glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA); // ditto
        glBegin(GL_QUADS);
            glTexCoord2f(0, _texSize.height); // draw upper left in world coordinates
            glVertex2f(bounds.origin.x, bounds.origin.y);
            glTexCoord2f(0, 0); // draw lower left in world coordinates
            glVertex2f(bounds.origin.x, bounds.origin.y + bounds.size.height);
            glTexCoord2f(_texSize.width, 0); // draw upper right in world coordinates
            glVertex2f(bounds.origin.x + bounds.size.width, bounds.origin.y + bounds.size.height);
            glTexCoord2f(_texSize.width, _texSize.height); // draw lower right in world coordinates
            glVertex2f(bounds.origin.x + bounds.size.width, bounds.origin.y);
        glEnd();
        glDisable(GL_TEXTURE_RECTANGLE_EXT);
    }
}

- (void)drawCocoaSubAtPoint:(NSPoint)p
{
    [_img drawAtPoint:p fromRect:CGRectZero operation:NSCompositeSourceOver fraction:1.0];
}

#pragma mark -

- (void)dealloc {
    [self deleteTexture];
}

@end

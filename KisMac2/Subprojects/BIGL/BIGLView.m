/*
        
        File:			BIGLView.m
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


#import "BIGLView.h"
#import <OpenGL/gl.h>
#import <OpenGL/glext.h>
#import <OpenGL/glu.h>
#import "BIGLCocoaView.h"
#import "BIGLSubView.h"

NSString *const BIGLMainViewResized = @"BIGLMainViewResized";

@implementation BIGLView

- (void)prepareOpenGL {
    _offset = NSZeroPoint;
    glShadeModel(GL_SMOOTH);		// Enable smooth shading
    glEnable(GL_DEPTH_TEST);
    
    glEnable(GL_COLOR_MATERIAL);
    glColorMaterial(GL_FRONT, GL_AMBIENT_AND_DIFFUSE);

    glEnable(GL_TEXTURE_2D);
    glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
    
    glClearColor(0.0, 0.0, 0.0, 0.0);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
    
    glDisable(GL_DEPTH_TEST); // ensure text is not remove by deoth buffer test.
    //glDisable (GL_LIGHTING);
    glEnable(GL_BLEND); // for text fading
    glBlendFunc(GL_SRC_ALPHA, GL_ONE); // ditto
    //glBlendFunc(GL_SRC_ALPHA_SATURATE, GL_ONE);
    //glEnable(GL_CULL_FACE);

    [self reshape];

    _initialized = YES;
}

+ (NSOpenGLPixelFormat*)defaultPixelFormat
{
    NSOpenGLPixelFormatAttribute attributes [] =
    {
        //NSOpenGLPFAWindow,
        NSOpenGLPFADoubleBuffer,
        NSOpenGLPFASampleBuffers, 1, 
        NSOpenGLPFASamples, 2,
        NSOpenGLPFANoRecovery,
        (NSOpenGLPixelFormatAttribute)nil
    };
    return [[NSOpenGLPixelFormat alloc] 
                        initWithAttributes:attributes];
}

- (id)initWithCoder:(NSCoder *)aDecoder {
    self = [super initWithCoder:aDecoder];
    if (self) {
        _subViews = [NSMutableArray array];
        _lock = [[NSLock alloc] init];
        [self setBackgroundColor:[NSColor blackColor]];
    }
    return self;    
}

- (id)initWithFrame:(NSRect)frameRect pixelFormat:(NSOpenGLPixelFormat*)format {
    NSOpenGLPixelFormat *pixelFormat = [BIGLView defaultPixelFormat];

    self = [super initWithFrame: frameRect pixelFormat: pixelFormat];
    if (self) {
        _subViews = [NSMutableArray array];
        _lock = [[NSLock alloc] init];
        [self setBackgroundColor:[NSColor blackColor]];
    }
    return self;
}

- (void)setBackgroundColor:(NSColor*)color {
    NSParameterAssert(color);
    
    color = [color colorUsingColorSpaceName:NSDeviceRGBColorSpace];
    _color[0] = [color redComponent];
    _color[1] = [color greenComponent];
    _color[2] = [color blueComponent];
    _color[3] = [color alphaComponent];
}

#pragma mark -

- (void) reshape {
    [super reshape];
    NSRect rectView = [self bounds];
    float nRange = 1;
    
    if (![_lock tryLock]) return;
    glViewport (_offset.x, _offset.y, rectView.size.width, rectView.size.height);
    glMatrixMode(GL_PROJECTION);
    glLoadIdentity();
    
    glOrtho(_offset.x, rectView.size.width+_offset.x, _offset.y, rectView.size.height+_offset.y, -nRange, nRange);
        
    glMatrixMode(GL_MODELVIEW);
    glFinish();
    [_lock unlock];
    
    [[NSNotificationCenter defaultCenter] postNotificationName:BIGLMainViewResized object:self userInfo:nil];
}

- (void)setFrame:(NSRect)frameRect {
    [super setFrame:frameRect];
    [[NSNotificationCenter defaultCenter] postNotificationName:BIGLMainViewResized object:self userInfo:nil];
}

- (void)setFrameSize:(NSSize)newSize {
    [super setFrameSize:newSize];
    [[NSNotificationCenter defaultCenter] postNotificationName:BIGLMainViewResized object:self userInfo:nil];
}

- (void)drawRect:(NSRect)rect {
    int i;
    
    if (!_initialized) return;
    if (![_lock tryLock]) return;
    
    //glClearColor(_color[0], _color[1], _color[2], _color[3]);
    glClear(GL_COLOR_BUFFER_BIT|GL_DEPTH_BUFFER_BIT);
    glLoadIdentity();
 
    glPushMatrix();
   
    for (i = 0; i < [_subViews count]; ++i)
        [(BIGLSubView*)_subViews[i] drawAtPoint:NSZeroPoint];

    glPopMatrix();
 
    glFinish();
    [_lock unlock];
}

- (NSData *)dataWithPDFInsideRect:(NSRect)rect {
    NSRect r = rect;
    BIGLCocoaView  *view = [[BIGLCocoaView alloc] initWithFrame:r];
   
    [view setBackgroundColor:[NSColor colorWithDeviceRed:_color[0] green:_color[1] blue:_color[2] alpha:_color[3]]];
    [view setSubViews:_subViews];
    
    return [view dataWithPDFInsideRect:rect];
}

- (NSData *)dataWithTIFFInsideRect:(NSRect)rect {
    NSMutableData *d;
    int width, height;
    NSBitmapImageRep *b;
    int bytesPerPixel = 4;
    int bytesPerImage, x, y;
    char *imageBuffer;
    unsigned char *src, *dest;
        
    width = rect.size.width;
    height = rect.size.height;
    bytesPerImage = width * height * bytesPerPixel;
    
    d = [NSMutableData dataWithLength:bytesPerImage];
    imageBuffer = [d mutableBytes];
    [_lock lock];
    [[self openGLContext] makeCurrentContext];
    
    glReadPixels(0, 0, width, height, GL_RGBA, GL_UNSIGNED_BYTE, imageBuffer);
    [_lock unlock];
    
    b = [[NSBitmapImageRep alloc] initWithBitmapDataPlanes: nil
                        pixelsWide: width
                        pixelsHigh: height
                        bitsPerSample: 8
                        samplesPerPixel: 3
                        hasAlpha: NO
                        isPlanar: NO
                        colorSpaceName: NSCalibratedRGBColorSpace
                        bytesPerRow: 0
                        bitsPerPixel: 0];
                        
    src = (unsigned char*)imageBuffer;

    dest = [b bitmapData];

    for (y = 0; y < height; ++y) {
        for (x = 0; x < width; ++x) {
            dest[(y * width + x) * 3    ] = src[((height-y-1) * width + x) * 4    ];
            dest[(y * width + x) * 3 + 1] = src[((height-y-1) * width + x) * 4 + 1];
            dest[(y * width + x) * 3 + 2] = src[((height-y-1) * width + x) * 4 + 2];
        }
    }

    NSData *d2 = [b TIFFRepresentation];
    return d2;
}

#pragma mark -

- (BOOL)addSubView:(BIGLSubView*)subView {
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
- (BOOL)removeSubView:(BIGLSubView*)subView {
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

#pragma mark -

- (BOOL)isOpaque { return YES; }
- (BOOL)acceptsFirstResponder { return YES; }
- (BOOL)becomeFirstResponder  { return YES; }

#pragma mark -

@end

/*
        
        File:			BIImageView.m
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

#import "BIImageView.h"
#import "BIView.h"

@implementation BIImageView

- (void)_createCache
{
#if USECOREGRAPHICS
    NSBitmapImageRep *bitmap;
    CGDataProviderRef provider;
    CGColorSpaceRef   col;
    
    [_img lockFocus];
    bitmap = [[NSBitmapImageRep alloc] initWithFocusedViewRect:NSMakeRect(0, 0, _frame.size.width, _frame.size.height)];
    [_img unlockFocus];
    
    col = CGColorSpaceCreateDeviceRGB();
    provider = CGDataProviderCreateWithData(NULL, [bitmap bitmapData], [bitmap bytesPerRow] * _frame.size.height, NULL); 
    _cgImg = CGImageCreate(_frame.size.width,  _frame.size.height, 8, [bitmap bitsPerPixel], [bitmap bytesPerRow], col, ([bitmap bitsPerPixel] == 24 ? kCGImageAlphaNone : kCGImageAlphaLast), provider, NULL, true, kCGRenderingIntentDefault);
    CGDataProviderRelease(provider);
    CGColorSpaceRelease(col);
#endif
}

- (void)_deleteCache
{
#if USECOREGRAPHICS
    if (_cgImg) CGImageRelease(_cgImg);
    _cgImg = NULL;
#endif
}

- (id)initWithImage:(NSImage*)img
{
    NSParameterAssert(img);

    self = [super initWithSize:[img size]];
    if (!self) return nil;

    _cgImg = NULL;
    _img = img;
    
    return self;
}

- (void)setImage:(NSImage*)img
{
    NSParameterAssert(img);
    _img = img;
    _frame.size = [img size];
    [self _deleteCache];
}

- (NSImage*)image
{
   return _img;
}

#pragma mark -

- (void)drawSubAtPoint:(NSPoint)p inRect:(NSRect)rect
{
#if USECOREGRAPHICS
    CGRect r;
    CGContextRef myContext = [[NSGraphicsContext currentContext] graphicsPort];
    if (!_cgImg) [self _createCache];
    
    r.origin.x = p.x;
    r.origin.y = p.y;
    r.size.width = _frame.size.width;
    r.size.height = _frame.size.height;
    CGContextDrawImage (myContext, r, _cgImg); 
#else
    [_img drawAtPoint:p fromRect:rect operation:NSCompositeSourceOver fraction:1.0];
#endif
}

#pragma mark -

- (void)dealloc
{
    [self _deleteCache];
}

@end

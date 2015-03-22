/*
        
        File:			BITextView.m
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
#import "BITextView.h"
#import "BIView.h"

@implementation BITextView

- (void)_calcSize {
    _frame.size = [_string size]; // current string size
    _frame.size.width  += _marginSize.width * 2; // add padding
    _frame.size.height += _marginSize.height * 2;
}

- (void)_createCache {
#if USECOREGRAPHICS
    CGDataProviderRef provider;
    NSBitmapImageRep *bitmap;
    CGColorSpaceRef   col;
#endif
    
    [self _calcSize];
    
    _img = [[NSImage alloc] initWithSize:_frame.size];
    
    [_img lockFocus];
    NS_DURING
        if ([_color alphaComponent]) {
            [_color set]; 
            NSRectFill(NSMakeRect(0, 0, _frame.size.width, _frame.size.height));
        }
        if ([_borderColor alphaComponent]) {
            [_borderColor set]; 
            NSFrameRect(NSMakeRect(0, 0, _frame.size.width, _frame.size.height));
        }

        [_string drawAtPoint:NSMakePoint(_marginSize.width, _marginSize.height)]; // draw at offset position
        
#if USECOREGRAPHICS
        bitmap = [[NSBitmapImageRep alloc] initWithFocusedViewRect:NSMakeRect(0, 0, _frame.size.width, _frame.size.height)];
#endif
    NS_HANDLER
    NS_ENDHANDLER
    [_img unlockFocus];
    
#if USECOREGRAPHICS
    col = CGColorSpaceCreateDeviceRGB();
    provider = CGDataProviderCreateWithData(NULL, [bitmap bitmapData], [bitmap bytesPerRow] * _frame.size.height, NULL); 
    _cgImg = CGImageCreate(_frame.size.width,  _frame.size.height, 8, [bitmap bitsPerPixel], [bitmap bytesPerRow], col, ([bitmap bitsPerPixel] == 24 ? kCGImageAlphaNone : kCGImageAlphaLast), provider, NULL, true, kCGRenderingIntentDefault);
    CGDataProviderRelease(provider);
    CGColorSpaceRelease(col);
#endif
}

- (void)_deleteCache {
#if USECOREGRAPHICS
    if (_cgImg) CGImageRelease(_cgImg);
    _cgImg = NULL;
#endif
    _img = nil;
}

#pragma mark -

- (id)init {
    self = [super init];
    if (!self) return nil;

    _cgImg = NULL;
    _color = [NSColor clearColor];
    _borderColor = [NSColor clearColor];
    _marginSize = NSMakeSize(8,4);
    _string = [[NSAttributedString alloc] init];
    [self _calcSize];

    return self;
}

- (id)initWithAttributedString:(NSAttributedString*)attributedString {
    return [self initWithAttributedString:attributedString andBackgroundColor:[NSColor clearColor]];
}

- (id)initWithAttributedString:(NSAttributedString*)attributedString andBackgroundColor:(NSColor*)color {
    NSParameterAssert(attributedString);
    NSParameterAssert(color);

    self = [super init];
    if (!self) return nil;
        
    [self setString:attributedString];
    [self setBackgroundColor:color];
    
    return self;
}

- (void)setString:(NSAttributedString *)attributedString { // set string after initial creation 
    NSParameterAssert(attributedString);
    
    _string = attributedString;
    [self _deleteCache];
    [self _calcSize];
}

- (void)setString:(NSString *)string withAttributes:(NSDictionary*)attrs { // set string after initial creation 
    NSParameterAssert(string);
    NSParameterAssert(attrs);
    
    _string = [[NSAttributedString alloc] initWithString:string attributes:attrs];
    [self _deleteCache];
    [self _calcSize];
}

- (void)setBackgroundColor:(NSColor *)color {
    NSParameterAssert(color);
    
    _color = color;
    [self _deleteCache];
}

- (void)setBorderColor:(NSColor *)color {
    NSParameterAssert(color);
    
    _borderColor = color;
    [self _deleteCache];
}

#pragma mark -

- (void)drawSubAtPoint:(NSPoint)p inRect:(NSRect)rect {
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
    if (!_img) [self _createCache];
    [_img drawAtPoint:p fromRect:rect operation:NSCompositeSourceOver fraction:1.0];
#endif
}

#pragma mark -

- (void)dealloc {
    [self _deleteCache];
}

@end

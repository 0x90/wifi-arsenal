//
//  BIGLCocoaView.m
//  BIGL
//
//  Created by mick on Thu Jul 08 2004.
//  Copyright (c) 2004 __MyCompanyName__. All rights reserved.
//

#import "BIGLCocoaView.h"
#import "BIGLSubView.h"

@implementation BIGLCocoaView

- (id)initWithFrame:(NSRect)frame {
    self = [super initWithFrame:frame];
    if (self) {
        _color = [NSColor blackColor];
    }
    return self;
}

- (void)setSubViews:(NSArray*)subs {
    NSParameterAssert(subs);
    
    _subs = subs;
}
- (void)setBackgroundColor:(NSColor*)color {
    NSParameterAssert(color);
    
    _color = color;
}

- (void)drawRect:(NSRect)rect {
    int i;
    [_color set];
    NSRectFill(rect);

    for (i = [_subs count]; i > 0; i--) {
        [(BIGLSubView*)_subs[i-1] drawCocoaAtPoint:NSZeroPoint];
    }
}

#pragma mark -

@end

//
//  BIView.m
//  BIGeneric
//
//  Created by mick on Fri Jul 02 2004.
//  Copyright (c) 2004 __MyCompanyName__. All rights reserved.
//

#import "BIToolbarView.h"

@interface BIToolbarView ()

@property(nonatomic, strong) NSColor *startingColor;
@property(nonatomic, strong) NSColor *middleColor;
@property(nonatomic, strong) NSColor *endingColor;


@end

@implementation BIToolbarView

- (id)initWithFrame:(NSRect)frame
{
    self = [super initWithFrame:frame];
    if (self)
    {
        // Initialization code here.
        [self setStartingColor:[NSColor colorWithCalibratedWhite:0.372 alpha:1.000]];
        [self setMiddleColor:[NSColor colorWithCalibratedWhite:0.250 alpha:1.000]];
        [self setEndingColor:[NSColor colorWithCalibratedWhite:0.404 alpha:1.000]];
    }
    return self;
}

- (void)drawRect:(NSRect)rect
{
    if (_endingColor == nil || [_startingColor isEqual:_endingColor])
    {
        // Fill view with a standard background color
        [_startingColor set];
        NSRectFill(rect);
    }
    else
    {
        // Fill view with a top-down gradient
        // from startingColor to endingColor
        NSGradient* aGradient = [[NSGradient alloc] initWithColors:@[_startingColor, _middleColor, _endingColor]];
        [aGradient drawInRect:[self bounds] angle:90];
    }
}

@end

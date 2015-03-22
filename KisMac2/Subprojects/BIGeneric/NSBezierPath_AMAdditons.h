//
//  NSBezierPath_AMAdditons.h
//  PlateControl
//
//  Created by Andreas on Sun Jan 18 2004.
//  Copyright (c) 2004 Andreas Mayer. All rights reserved.
//

#import <AppKit/AppKit.h>


@interface NSBezierPath (AMAdditons)

+ (NSBezierPath *)bezierPathWithPlateInRect:(NSRect)rect;

- (void)appendBezierPathWithPlateInRect:(NSRect)rect;


@end

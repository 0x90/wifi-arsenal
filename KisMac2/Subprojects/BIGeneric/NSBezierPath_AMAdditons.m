//
//  NSBezierPath_AMAdditons.m
//  PlateControl
//
//  Created by Andreas on Sun Jan 18 2004.
//  Copyright (c) 2004 Andreas Mayer. All rights reserved.
//

#import "NSBezierPath_AMAdditons.h"


@implementation NSBezierPath (AMAdditons)

+ (NSBezierPath *)bezierPathWithPlateInRect:(NSRect)rect
{
	NSBezierPath *result = [[NSBezierPath alloc] init];
	[result appendBezierPathWithPlateInRect:rect];
	return result;
}

- (void)appendBezierPathWithPlateInRect:(NSRect)rect
{
	if (rect.size.height > 0) {
		float xoff = rect.origin.x;
		float yoff = rect.origin.y;
		float radius = rect.size.height/2.0;
		NSPoint point4 = NSMakePoint(xoff+radius, yoff+rect.size.height);
		NSPoint center1 = NSMakePoint(xoff+radius, yoff+radius);
		NSPoint center2 = NSMakePoint(xoff+rect.size.width-radius, yoff+radius);
		[self moveToPoint:point4];
		[self appendBezierPathWithArcWithCenter:center1 radius:radius startAngle:90.0 endAngle:270.0];
		[self appendBezierPathWithArcWithCenter:center2 radius:radius startAngle:270.0 endAngle:90.0];
		[self closePath];
	}
}


@end

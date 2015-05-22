/*
        
        File:			BIValuePair.m
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
#import "BIValuePair.h"

@implementation BIValuePair

- (id)initWithCoder:(NSCoder *)coder {
    self = [self init];
    if ( [coder allowsKeyedCoding] ) {
        _x=[coder decodeDoubleForKey:@"x"];
        _y=[coder decodeDoubleForKey:@"y"];
    } else {
        NSLog(@"Cannot decode this way");
    }
    return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    if ([coder allowsKeyedCoding]) {
        [coder encodeDouble:_x forKey:@"x"];
        [coder encodeDouble:_y forKey:@"y"];
    } else {
        NSLog(@"Cannot encode this way");
    }
    return;
}

- (id)initWithDataDictionary:(NSDictionary*)dict {
    self = [self init];
	
	_x = [dict[@"x"] doubleValue];
	_y = [dict[@"y"] doubleValue];
    
	return self;
}

- (NSDictionary*)dataDictionary {
	return @{@"x": @(_x),
		@"y": @(_y)};
}

+ (id)valuePairFromWaypoint:(waypoint)w {
    BIValuePair *vp = [[BIValuePair alloc] init];
    [vp setPairFromWaypoint:w];
    return vp;
}

- (double)getX {
    return _x;
}

- (double)getY {
    return _y;
}

- (void)setPairX:(double)x Y:(double) y {
    _x = x;
    _y = y;
}

- (void)setPairFromWaypoint:(waypoint)wp {
    _x = wp._long;
    _y = wp._lat;
}

- (waypoint)wayPoint {
    waypoint w;
    w._long = _x;
    w._lat  = _y;
    return w;
}

- (id)copyWithZone:(NSZone *)zone {
    BIValuePair *copy = [[BIValuePair allocWithZone:zone] init];
    [copy setPairX:_x Y:_y];
    
    return copy;
}

- (BOOL)isEqual:(id)anObject {
    if ([self isMemberOfClass:[self class]] && ([anObject getX]==_x) && ([anObject getY]==_y)) return YES;
    return NO;
}


@end

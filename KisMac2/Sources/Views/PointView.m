/*
        
        File:			PointView.m
        Program:		KisMAC
		Author:			Michael Rossberg
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

#import "PointView.h"
#import "WaveHelper.h"
#import "MapView.h"

@implementation PointView

- (void)_genCacheForSize:(int)size {
    NSRect q;
    NSColor *c = [WaveHelper intToColor:[[NSUserDefaults standardUserDefaults] objectForKey:@"CurrentPositionColor"]];
    NSBezierPath *x;
    float z;
    int w;
    
    if (size < 8) w = size / 2;
    else w = 4;
    
    q.size.height = q.size.width = size;
    q.origin.x = (_frame.size.width  - size) / 2;
    q.origin.y = (_frame.size.height - size) / 2;
    
    for (z=w; z>=-w; z--) {
        [[c blendedColorWithFraction:(((float)abs(z))/w) ofColor:[NSColor clearColor]] set];
        x=[NSBezierPath bezierPathWithOvalInRect:q];
        [x setLineWidth:1.5];
        [x stroke];
        q.origin.x++;
        q.origin.y++;
        q.size.height -= 2;
        q.size.width  -= 2;
    }
}

- (void)setupViewForFrame {
    float r1=1, r2=10, x1, y1;
    NSAffineTransform *t;

    _way1=[NSBezierPath bezierPath];
    
    x1=cos(30.0/180.0*M_PI)*r1;
    y1=sin(30.0/180.0*M_PI)*r1;
    
    [_way1 moveToPoint:NSMakePoint(x1,y1)];
    [_way1 lineToPoint:NSMakePoint(x1+cos(60.0/180.0*M_PI)*r2,y1+sin(60.0/180.0*M_PI)*r2)];
    [_way1 lineToPoint:NSMakePoint(x1+cos(0.0/180.0*M_PI)*r2 ,y1+sin(0.0/180.0*M_PI)*r2) ];
    [_way1 closePath];
    
    x1=cos(150.0/180.0*M_PI)*r1;
    y1=sin(150.0/180.0*M_PI)*r1;
    
    [_way1 moveToPoint:NSMakePoint(x1,y1)];
    [_way1 lineToPoint:NSMakePoint(x1+cos(120.0/180.0*M_PI)*r2,y1+sin(120.0/180.0*M_PI)*r2)];
    [_way1 lineToPoint:NSMakePoint(x1+cos(180.0/180.0*M_PI)*r2,y1+sin(180.0/180.0*M_PI)*r2) ];
    [_way1 closePath];
    
    x1=cos(270.0/180.0*M_PI)*r1;
    y1=sin(270.0/180.0*M_PI)*r1;
    
    [_way1 moveToPoint:NSMakePoint(x1,y1)];
    [_way1 lineToPoint:NSMakePoint(x1+cos(240.0/180.0*M_PI)*r2,y1+sin(240.0/180.0*M_PI)*r2)];
    [_way1 lineToPoint:NSMakePoint(x1+cos(300.0/180.0*M_PI)*r2,y1+sin(300.0/180.0*M_PI)*r2) ];
    [_way1 closePath];
    
    t = [NSAffineTransform transform];
    [t translateXBy:0.5*_frame.size.width yBy:0.5*_frame.size.height];
    [_way1 transformUsingAffineTransform: t];

}

- (void)_genWayCache {
    [[WaveHelper intToColor:[[NSUserDefaults standardUserDefaults] objectForKey:@"WayPointColor"]] set];

    NSAffineTransform *t4 = [NSAffineTransform transform];
    [t4 translateXBy:-_frame.size.width*0.5 yBy:-_frame.size.height*0.5];
    //[_way1 transformUsingAffineTransform: t4];
    
    t4 = [NSAffineTransform transform];
    [t4 rotateByDegrees: 5];
    [t4 translateXBy:-_frame.size.width*0.5 yBy:-_frame.size.height*0.5];
    [_way1 transformUsingAffineTransform: t4];
    
    t4 = [NSAffineTransform transform];
    [t4 translateXBy:_frame.size.width*0.5 yBy:_frame.size.height*0.5];
    [_way1 transformUsingAffineTransform: t4];
    
    [_way1 fill];
}

- (id)init {
    int i;
    self = [super init];
    if (!self) return nil;
    
    [self setSize:NSMakeSize(35, 35)];
    for (i = 2; i <= 35; ++i) {
        _currImg[i] = [[NSImage alloc] initWithSize:NSMakeSize(35, 35)];
        [_currImg[i] lockFocus];
        [self _genCacheForSize:i];
        [_currImg[i] unlockFocus];
    }
    [self setupViewForFrame];
    for (i = 0; i < 24; ++i) {
        _wayImg[i] = [[NSImage alloc] initWithSize:NSMakeSize(35, 35)];
        [_wayImg[i] lockFocus];
        [self _genWayCache];
        [_wayImg[i] unlockFocus];
    }
    _animLock = [[NSLock alloc] init];
    
    [self setImage:_currImg[35]];
    return self;
}

#pragma mark -

- (void)setWayPointMode:(BOOL)wayPointMode {
    _wayPointMode = wayPointMode;
}

#pragma mark -

- (void)setVisible:(BOOL)visible {
    [super setVisible:visible];
//    if (visible) [NSThread detachNewThreadSelector:@selector(animationThread:) toTarget:self withObject:nil];
}

- (void)setLocation:(NSPoint)loc {
    loc.x -= _frame.size.width / 2;
    loc.y -= _frame.size.height / 2;
    [super setLocation:loc];
}

#pragma mark -
- (void)animationThread:(id)object {
    BOOL e = NO;
    int scale = 35;
    int wp = 0;
    @autoreleasepool {
    
        if([_animLock tryLock]) {
            while(_visible) {
                if (_wayPointMode) {
                    ++wp;
                    wp = wp % 24;
                    [self setImage:_wayImg[wp]];
                } else {
                    if (e) {
                        ++scale;
                        if (scale>=25) e=NO;
                    } else {
                        --scale;
                        if (scale<=10) e=YES;
                    }
                    
                    [self setImage:_currImg[scale]];
                }
                [[WaveHelper mapView] setNeedsDisplayInMoveRect:_frame];
                NSDate * test = [NSDate dateWithTimeIntervalSinceNow:0.1];
                [NSThread sleepUntilDate: test];
            }
            [_animLock unlock];
        }

    }
}

@end

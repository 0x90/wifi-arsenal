/*

        File:			NetView.m
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

#import "NetView.h"
#import "MapView.h"
#import "WaveNet.h"
#import "WaveHelper.h"

#define USE_FAST_IMAGE_VIEWS

static NSImage* _networkUnkEnc;
static NSImage* _networkNoEnc;
static NSImage* _networkWEP;
static NSImage* _networkWPA;
static NSImage* _networkLEAP;
static NSImage* _networkStrange;

@implementation NetView

- (id)initWithNetwork:(WaveNet*)network
{
    self = [super init];
    if (self) {
        
		if (!_networkUnkEnc) _networkUnkEnc = [NSImage imageNamed:@"NetworkUnkEnc.tif"];
		if (!_networkNoEnc)  _networkNoEnc  = [NSImage imageNamed:@"NetworkNoEnc.tif"];
		if (!_networkWEP)    _networkWEP    = [NSImage imageNamed:@"NetworkWEP.tif"];
		if (!_networkWPA)    _networkWPA    = [NSImage imageNamed:@"NetworkWPA.tif"];
		if (!_networkLEAP)   _networkLEAP   = [NSImage imageNamed:@"NetworkLEAP.tif"];
		if (!_networkStrange)_networkStrange= [NSImage imageNamed:@"NetworkStrange.tif"];
		
		_name = @"<no ssid>";
        
		_netImg = _networkUnkEnc;
        _netColor = [NSColor yellowColor];
        _wep = 0;
        _wp._lat = 100;
        _wp._long = 0;
		_wp._elevation = 0;
        _network = network;
		_filtered = NO;
        [[WaveHelper mapView] addNetView:self];
		_attachedToSuperView = YES;
    }
    return self;
}

- (void) setName:(NSString*)name {
	_name = name;
    [self setImage:[self generateImage]];
    [[WaveHelper mapView] setNeedsDisplay:YES];
}

- (void)setFiltered:(BOOL)filtered {
	_filtered = filtered;
	if (!filtered) [self align];
	else [self setVisible:NO];
}

- (void) setWep:(encryptionType)wep {
    _wep = wep;

	_netImg = nil;
	_netColor = nil;
    
    switch (_wep) {
    case encryptionTypeUnknown:
        _netImg = _networkUnkEnc;
        _netColor = [NSColor yellowColor];
        break;
    case encryptionTypeNone:
        _netImg = _networkNoEnc;
        _netColor = [NSColor greenColor];
        break;
    case encryptionTypeWEP:
    case encryptionTypeWEP40:
        _netImg = _networkWEP;
        _netColor = [NSColor redColor];
        break;
    case encryptionTypeWPA:
        _netImg = _networkWPA;
        _netColor = [NSColor blueColor];
        break;
    case encryptionTypeWPA2:
        _netImg = _networkWPA;
        _netColor = [NSColor blueColor];
        break;
        case encryptionTypeLEAP:
        _netImg = _networkLEAP;
        _netColor = [NSColor cyanColor];
        break;
    default:
        _netImg = _networkStrange;
        _netColor = [NSColor magentaColor];
    }
    
    [self setImage:[self generateImage]];
    [[WaveHelper mapView] setNeedsDisplay:YES];
}

-(void) setCoord:(waypoint)wp {
    _wp = wp;
    [self align];
}

- (waypoint)coord {
    return _wp;
}

#pragma mark -

- (void)mouseDown:(NSEvent *)theEvent {
    if ([theEvent clickCount] == 2) [_network joinNetwork];
    else [[WaveHelper mapView] mouseDown:theEvent];
}

- (void)align {
    NSPoint p;
    p = [[WaveHelper mapView] pixelForCoordinate:_wp];

    if (p.x == INVALIDPOINT.x && p.y == INVALIDPOINT.y) {
        if (_visible) [self setVisible:NO];
        return;
    }
        
    if (!_visible && !_filtered) [self setVisible:YES];
    
    [self setLocation:p];
}

- (void)setLocation:(NSPoint)loc {
    [super setLocation:NSMakePoint(loc.x - 7.5, loc.y - ([_img size].height / 2))];
}

- (NSImage*)generateImage {
    float r = 15;
    NSBezierPath *legendPath = [NSBezierPath bezierPath];
    NSFont* textFont = [NSFont fontWithName:@"Monaco" size:12];
    NSMutableDictionary* attrs = [NSMutableDictionary dictionary];
    NSString *name;
    NSSize size = NSZeroSize;
    NSImage *img;
        
    if (!_visible) return [[NSImage alloc] initWithSize:NSMakeSize(0,0)];
    
    name =[_name stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]]; 
    if ([name length] > 0) {
        attrs[NSFontAttributeName] = textFont;
        
        size = [_name sizeWithAttributes:attrs];
        size.height+=5;
        size.width+=10;
    }
    
    float height = fmax(r, size.height);
    img = [[NSImage alloc] initWithSize:NSMakeSize(size.width + r + 10, height)];
    [img lockFocus];
    
    CGRect rect = CGRectZero;
    if ([name length])
    {
        rect = NSMakeRect(r+5, (height - size.height)/2, size.width, size.height);
        [legendPath appendBezierPathWithRect:rect];
        [[[NSColor blackColor] colorWithAlphaComponent:0.75] set];
        [legendPath fill];
        [[[NSColor whiteColor] colorWithAlphaComponent:0.3] set];
        [NSBezierPath setDefaultLineWidth:2];
        [legendPath stroke];
        
        attrs[NSForegroundColorAttributeName] = _netColor;
        [_name drawAtPoint:NSMakePoint(r+10, (height + 5 - size.height)/2) withAttributes:attrs];
    }
   
    [_img drawAtPoint:NSMakePoint(0, (height - r)/2) fromRect:rect operation:NSCompositeSourceOver fraction:1.0];
    
    [img unlockFocus];
    
    return img;
}

- (BOOL)removeFromSuperView {
	if (!_attachedToSuperView) return NO;
    [[WaveHelper mapView] removeNetView:self];
	return YES;
}

- (void)dealloc {
    [self removeFromSuperView];
	
    [[WaveHelper mapView] setNeedsDisplay:YES];
	_name = nil;
	_netImg = nil;
	_netColor = nil;
    
}
@end

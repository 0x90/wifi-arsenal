/*
        
        File:			MapView.m
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

#import "MapView.h"
#import "WaveHelper.h"
#import "KisMACNotifications.h"
#import "MapViewPrivate.h"
#import <BIGeneric/BIGeneric.h>
#import "NetView.h"
#import "BIImageView.h"
#import "BISubView.h"
#import "BITextView.h"
#import "MapControlPanel.h"
#import "PointView.h"
#import "WayPoint.h"
#import "Trace.h"
#import "GPSController.h"

#define ZOOMFACT 1.5

@implementation MapView

- (void)awakeFromNib {
    _mapImage = nil;
    _wp[0]._lat  = 0; _wp[0]._long = 0;
    _wp[1]._lat  = 0; _wp[1]._long = 0;
    _wp[2]._lat  = 0; _wp[2]._long = 0;
    _zoomFact = 1.0;
    
    _moveContainer = [[BISubView alloc] initWithSize:NSMakeSize(300000,300000)];
    [self addSubView:_moveContainer];

    _netContainer = [[BISubView alloc] initWithSize:NSMakeSize(300000,300000)];
    [_netContainer setVisible:NO];
	[_moveContainer addSubView:_netContainer];

    _selmode = selShowCurPos;
    _pView = [[PointView alloc] init];
    [_pView setVisible:NO];
    [_moveContainer addSubView:_pView];
    
    _trace = [[Trace alloc] initWithSize:NSMakeSize(300000,300000)];
    [_trace setVisible:NO];
    [_moveContainer addSubView:_trace];
    [WaveHelper setTrace:_trace];
    
    _gpsStatusView = [[BITextView alloc] init];
    [self _setGPSStatus:NSLocalizedString(@"No GPS device available.", "gps status")];
    [self addSubView:_gpsStatusView];
    [_gpsStatusView setLocation:NSMakePoint(-1,-1)];

    _statusView = [[BITextView alloc] init];
    [self _updateStatus];
    [self addSubView:_statusView];
    
    _controlPanel = [[MapControlPanel alloc] init];
    [_controlPanel setVisible:NO];
    [self _alignControlPanel];
    [self addSubView:_controlPanel];
    
    [self setNeedsDisplay:YES];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(_updateGPSStatus:) name:KisMACGPSStatusChanged object:nil];
	
	[self loadFromFile:[[[NSBundle mainBundle] resourcePath] stringByAppendingString:@"/world.kismap"]];
	_zoomFact = 1.0 / (ZOOMFACT * ZOOMFACT * ZOOMFACT * ZOOMFACT);
	[self _alignNetworks];
    [self setNeedsDisplay:YES];
}

#pragma mark -

- (BOOL)saveToFile:(NSString*)fileName {
    NSFileManager *fMgr;
    NSString *mapName;
    NSData *data;
    NSMutableDictionary *wp[3];
    NSString *error = nil;
    NSError * err;
    int i;
    
    if (!_orgImage) return NO;
    
    mapName = [fileName stringByExpandingTildeInPath];
    fMgr = [NSFileManager defaultManager];
    [fMgr createDirectoryAtPath: mapName withIntermediateDirectories: YES
                     attributes: nil error: &err];

    NSImageView *view = [[NSImageView alloc] init];
    [view setImage: _orgImage];
    [view setFrameSize: [_orgImage size]];

#if 0
    data = [view dataWithPDFInsideRect:[view frame]];
    [data writeToFile:[mapName stringByAppendingPathComponent:@"map.pdf"] atomically:NO];
#else
    data = [_orgImage TIFFRepresentation];
	data = [[NSBitmapImageRep imageRepWithData:data] representationUsingType:NSPNGFileType properties:nil];
    [data writeToFile:[mapName stringByAppendingPathComponent:@"map.png"] atomically:NO];
#endif

    
    for (i=1;i<=2;++i) {
        wp[i] = [NSMutableDictionary dictionaryWithCapacity:4];
        
        wp[i][@"latitude"] = [NSNumber numberWithFloat:((_wp[i]._lat ) >= 0 ? (_wp[i]._lat ) : -(_wp[i]._lat )) ];
        wp[i][@"latdir"] = ((_wp[i]._lat ) >= 0 ? @"N" : @"S");
        wp[i][@"longitude"] = [NSNumber numberWithFloat:((_wp[i]._long) >= 0 ? (_wp[i]._long) : -(_wp[i]._long)) ];
        wp[i][@"longdir"] = ((_wp[i]._long) >= 0 ? @"E" : @"W");
        wp[i][@"xpoint"] = @((int)floor(_point[i].x));
        wp[i][@"ypoint"] = @((int)floor(_point[i].y));
    }
    
    data = [NSPropertyListSerialization dataFromPropertyList:@[wp[1],wp[2]] format:NSPropertyListXMLFormat_v1_0 errorDescription:&error];
    
    if (error==nil) [data writeToFile:[mapName stringByAppendingPathComponent:@"waypoints.plist"] atomically:NO];
    else DBNSLog(@"Could not write XML File with Coordinates:%@", error);
    
    return (error==nil);
}

- (BOOL)loadFromFile:(NSString*)fileName {
    NSString *mapName = [fileName stringByExpandingTildeInPath];
    NSString *error = nil;
    NSArray *wps;
    NSDictionary *wp;
    int i;
    NSData* data;
	NSDictionary* settings;
    NSImage* img = nil;
    waypoint wpoint;
    
	NS_DURING
        data = [NSData dataWithContentsOfFile:[mapName stringByAppendingPathComponent:@"waypoints.plist"]];
        wps = [NSPropertyListSerialization propertyListFromData:data mutabilityOption:NSPropertyListImmutable format:NULL errorDescription:&error];
    NS_HANDLER
        DBNSLog(@"Could not open XML File with Coordinates: internal exception raised!");
        return NO;
    NS_ENDHANDLER
    
    if (error!=nil) {
        DBNSLog(@"Could not open XML File with Coordinates: %@", error);
        return NO; 
    }
    
	NS_DURING
		settings = wps[2];
		if (settings[@"fileName"]) {
			img = [[NSImage alloc] initWithContentsOfFile:[mapName stringByAppendingPathComponent:wps[2][@"fileName"]]];
        } 
	NS_HANDLER
    NS_ENDHANDLER
	
	NS_DURING
	if (!img) {
		img = [[NSImage alloc] initWithContentsOfFile:[mapName stringByAppendingPathComponent:@"map.pdf"]];
	}
	NS_HANDLER
    NS_ENDHANDLER
	
	NS_DURING
		if (!img) {
			//fall back
			img = [[NSImage alloc] initWithContentsOfFile:[mapName stringByAppendingPathComponent:@"map.png"]];
		}
		if (!img) {
			DBNSLog(@"Invalid KisMAP file");
			NS_VALUERETURN(NO, BOOL);
		}
        [self setMap:img];
    NS_HANDLER
        DBNSLog(@"Could not open Image file from KisMAP bundle!");
        return NO;
    NS_ENDHANDLER
	
    for (i=1;i<=2;++i) {
        wp = wps[i-1];
        
        wpoint._lat = [wp[@"latitude"] floatValue];
        wpoint._long= [wp[@"longitude"] floatValue];
        if ([wp[@"latdir"] isEqualToString:@"S"]) wpoint._lat *=-1;
        if ([wp[@"longdir"] isEqualToString:@"W"]) wpoint._long*=-1;
        
        [self setWaypoint:i toPoint:NSMakePoint([wp[@"xpoint"] intValue], [wp[@"ypoint"] intValue]) atCoordinate:wpoint];
    }
    
    return YES;
}

- (NSData*)pdfData {
    NSRect frame;
    NSData *data;
    BIView *view;
    NSImage *map;
    BIImageView *imgView;
    if (!_mapImage) return nil;
    
    frame.size = NSMakeSize([_mapImage size].width * _zoomFact, [_mapImage size].height * _zoomFact);
    frame.origin = [_moveContainer location];

    map = [[NSImage alloc] initWithSize:frame.size];
    [map lockFocus];
    [_mapImage drawInRect:NSMakeRect(0, 0, [_mapImage size].width * _zoomFact, [_mapImage size].height * _zoomFact) fromRect:NSMakeRect(0, 0, [_mapImage size].width, [_mapImage size].height) operation:NSCompositeCopy fraction:1.0];
    [map unlockFocus];
    
    imgView = [[BIImageView alloc] initWithImage:map];
    [imgView setLocation:frame.origin];
    
	//this is a quick hack!
	frame.size.height += frame.origin.y;
	frame.size.width += frame.origin.x;
    view = [[BIView alloc] initWithFrame:frame];
    [view addSubView:imgView];
    [view addSubView:_moveContainer];
	 
	frame.size = NSMakeSize([_mapImage size].width * _zoomFact, [_mapImage size].height * _zoomFact);
	data = [view dataWithPDFInsideRect:frame];
    
    
    return data;
}

#pragma mark -

- (BOOL)setMap:(NSImage*)map {
	_orgImage = map;
	_mapImage = map;

    _wp[0]._lat  = 0; _wp[0]._long = 0;
    _wp[1]._lat  = 0; _wp[1]._long = 0;
    _wp[2]._lat  = 0; _wp[2]._long = 0;
    _center.x = [_mapImage size].width  / 2;
    _center.y = [_mapImage size].height / 2;
    _zoomFact = 1.0;
    
	[_controlPanel setVisible:YES];
    [[WaveHelper mainWindow] invalidateCursorRectsForView:self];
    
    [self _updateStatus];
    [self _alignNetworks];
    [self setNeedsDisplay:YES];
    
    return YES;
}

- (BOOL)hasValidMap {
    if (!_mapImage) return NO;
    if ([_mapImage size].width <= 1 || [_mapImage size].height <= 1) return NO;
	return YES;
}

- (BOOL)setWaypoint:(int)which toPoint:(NSPoint)point atCoordinate:(waypoint)coord {
    if (which != selWaypoint1 && which != selWaypoint2) return NO;
    if (coord._lat > 90 || coord._lat < -90 || coord._long > 180 || coord._long < -180) return NO;
    
    _point[which] = point;
    _wp[which] = coord;
 
    [self _updateStatus];
    [self _alignNetworks];
    [self _centerCurPos];
	[self setNeedsDisplay:_visible];
    
    if (_selmode == which) [self _alignWayPoint];
	
    [[NSNotificationCenter defaultCenter] postNotificationName:KisMACAdvNetViewInvalid object:self];
    
    return YES;
}

- (BOOL)setCurrentPostionToLatitude:(double)lat andLongitude:(double)lon {
    if (lat > 90 || lat < -90 || lon > 180 || lon < -180) return NO;
    
    [[WaveHelper gpsController] setCurrentPointNS:lat EW:lon ELV:0];
    [self _alignCurrentPos];
	[self _centerCurPos];
    [self setNeedsDisplay:_visible];
    return YES;
}

- (void)setVisible:(BOOL)visible {
    _visible = visible;
    if (!_visible) [_pView setVisible:NO];
    else [self _alignCurrentPos];
}

- (NSPoint)pixelForCoordinateNoZoom:(waypoint)wp {
    NSPoint p;
    if ([_statusView visible]) return INVALIDPOINT;
    if (wp._long == 0 && wp._lat == 0) return INVALIDPOINT;
    
    NS_DURING
        p.x = ((_point[1].x - (_wp[1]._long- wp._long) / (_wp[1]._long-_wp[2]._long) * (_point[1].x-_point[2].x)));
        p.y = ((_point[1].y - (_wp[1]._lat - wp._lat)  / (_wp[1]._lat - _wp[2]._lat) * (_point[1].y-_point[2].y)));
    NS_HANDLER
        return INVALIDPOINT;
    NS_ENDHANDLER

    return p;
}

- (NSPoint)pixelForCoordinate:(waypoint)wp {
    NSPoint p;
    if ([_statusView visible]) return INVALIDPOINT;
    if (wp._long == 0 && wp._lat == 0) return INVALIDPOINT;
    
    NS_DURING
        p.x = ((_point[1].x - (_wp[1]._long- wp._long) / (_wp[1]._long-_wp[2]._long) * (_point[1].x-_point[2].x)) * _zoomFact);
        p.y = ((_point[1].y - (_wp[1]._lat - wp._lat)  / (_wp[1]._lat - _wp[2]._lat) * (_point[1].y-_point[2].y)) * _zoomFact);
    NS_HANDLER
        return INVALIDPOINT;
    NS_ENDHANDLER

    return p;
}

- (void)setNeedsDisplayInMoveRect:(NSRect)invalidRect {
    invalidRect.origin.x += [_moveContainer frame].origin.x;
    invalidRect.origin.y += [_moveContainer frame].origin.y;
    
    [self setNeedsDisplayInRect:invalidRect];
}

- (void)addNetView:(NetView*)view {
    [_netContainer addSubView:view];
}

- (void)removeNetView:(NetView*)view {
    [_netContainer removeSubView:view];
}

#pragma mark -

- (void)drawRectSub:(NSRect)rect { 
    [_mapImage drawInRect:rect fromRect:NSMakeRect(_center.x + ((rect.origin.x - (_frame.size.width / 2)) / _zoomFact), _center.y + ((rect.origin.y - (_frame.size.height / 2)) / _zoomFact), rect.size.width / _zoomFact, rect.size.height / _zoomFact) operation:NSCompositeCopy fraction:1.0];
}

#pragma mark -

- (void)resetCursorRects {
    [self addCursorRect:[self visibleRect] cursor:[NSCursor crosshairCursor]];
    if ([_controlPanel visible]) [self addCursorRect:NSIntersectionRect([self visibleRect], [_controlPanel frame]) cursor:[NSCursor arrowCursor]];
}

- (void)setFrameSize:(NSSize)newSize {
    [super setFrameSize:newSize];
    [self _align];
    [self _alignStatus];
    [self _alignControlPanel];
}

- (void)setFrame:(NSRect)frameRect {
    [super setFrame:frameRect];
    [self _align];
    [self _alignStatus];
    [self _alignControlPanel];
}

- (void)keyDown:(NSEvent *)theEvent {
    switch ([theEvent keyCode]) {
    case 115: //home
	case 123: //left
        [self goLeft:self];
        break;
	case 119: //end
    case 124: //right
        [self goRight:self];
        break;
	case 121: //pg dw
    case 125: //down
        [self goDown:self];
        break;
	case 116: //pg up
    case 126: //up
        [self goUp:self];
        break;
    case 44: //minus key
        [self zoomOut:self];
        break;
    case 30: //plus key
        [self zoomIn:self];
        break;
    }
}

- (void)mouseMoved:(NSEvent *)theEvent {
    NSPoint p;
    p = [self convertPoint:[theEvent locationInWindow] fromView:nil];
    if (NSPointInRect(p, [_controlPanel frame])) [_controlPanel mouseMovedToPoint:p];
}

- (void)mouseDown:(NSEvent *)theEvent {
    BOOL keepOn = YES;
    NSPoint p;
    WayPoint *wayPoint;
    waypoint w;
    
    p = [self convertPoint:[theEvent locationInWindow] fromView:nil];
    if (NSPointInRect(p, [_controlPanel frame])) {
        [_controlPanel mouseDownAtPoint:p];
        return;
    }
    
    if (_selmode >= selShowCurPos) return;
    
    _old = _point[_selmode];
    
    while (keepOn) {
        theEvent = [[self window] nextEventMatchingMask: NSLeftMouseUpMask | NSLeftMouseDraggedMask];
        p = [self convertPoint:[theEvent locationInWindow] fromView:nil];
        p.x -= [_moveContainer location].x;
        p.y -= [_moveContainer location].y;
        p.x /= _zoomFact;
        p.y /= _zoomFact;
        
        switch ([theEvent type]) {
        case NSLeftMouseUp:
            keepOn = NO;
            
            wayPoint = [[WayPoint alloc] initWithWindowNibName:@"WayPointDialog"];
            [[wayPoint window] setFrameUsingName:@"aKisMAC_WayPoint"];
            [[wayPoint window] setFrameAutosaveName:@"aKisMAC_WayPoint"];
            
            if (_selmode == selCurPos) {
                // calculate current point for setting the current position
                NS_DURING
                    w._long = _wp[1]._long - (_point[1].x - p.x) / (_point[1].x - _point[2].x) * (_wp[1]._long - _wp[2]._long);
                    w._lat  = _wp[1]._lat  - (_point[1].y - p.y) / (_point[1].y - _point[2].y) * (_wp[1]._lat  - _wp[2]._lat);
                NS_HANDLER
                    w._long = 0.0;
                    w._lat  = 0.0;
                NS_ENDHANDLER
                _point[selCurPos] = INVALIDPOINT;
            } else {// set the waypoints with current coordinates
                w=[[WaveHelper gpsController] currentPoint];
            }
                   
            [wayPoint setWaypoint:w];
            [wayPoint setMode:_selmode];
            [wayPoint setPoint:p];
            [wayPoint showWindow:self];
            p = _old;
        case NSLeftMouseDragged:
            _point[_selmode] = p;
            [self _alignWayPoint];
            [self setNeedsDisplay:YES];
            break;
        default:
            break;
        }
    }
}

#pragma mark -

- (IBAction)autoCenter:(id)sender {
	if ([sender state] == NSOffState) {
		_autoCenter = YES;
		[_controlPanel setRestrictedMode:YES];
		[sender setState:NSOnState];
		[[WaveHelper mainWindow] invalidateCursorRectsForView:self]; 
        [self _centerCurPos];
	} else {
		_autoCenter = NO;
		[_controlPanel setRestrictedMode:NO];
		[sender setState:NSOffState];
		[[WaveHelper mainWindow] invalidateCursorRectsForView:self];	
	}
}

- (IBAction)zoomIn:(id)sender {
    if (_zoomFact > 100) {
        NSBeep();
        return;
    }
    _zoomFact *= ZOOMFACT;
    [self _alignNetworks];
    [self setNeedsDisplay:YES];
}

- (IBAction)zoomOut:(id)sender {
    if (_zoomFact < 0.1) {
        NSBeep();
        return;
    }    
    _zoomFact /= ZOOMFACT;
    [self _alignNetworks];
    [self setNeedsDisplay:YES];
}

- (IBAction)goLeft:(id)sender {
	if (_autoCenter) {
		NSBeep();
		return;
    }
	_center.x -= 40.0 / _zoomFact;
    [self _align];
    [self setNeedsDisplay:YES];
}
- (IBAction)goRight:(id)sender{
    if (_autoCenter) {
		NSBeep();
		return;
    }
	_center.x += 40.0 / _zoomFact;
    [self _align];
    [self setNeedsDisplay:YES];
}
- (IBAction)goUp:(id)sender {
    if (_autoCenter) {
		NSBeep();
		return;
    }
	_center.y += 40.0 / _zoomFact;
    [self _align];
    [self setNeedsDisplay:YES];
}
- (IBAction)goDown:(id)sender {
    if (_autoCenter) {
		NSBeep();
		return;
    }
	_center.y -= 40.0 / _zoomFact;
    [self _align];
    [self setNeedsDisplay:YES];
}

- (void)disableAll {
    [_setWayPoint1 setState:NSOffState];
    [_setWayPoint2 setState:NSOffState];
    [_setCurrentPoint setState:NSOffState];
    [_showCurrentPoint setState:NSOffState];
    [_pView setVisible:NO];
    _selmode = selInvalid;
}

- (IBAction)setWaypoint1:(id)sender {
    if ([sender state] == NSOnState) {
        [self disableAll];
        return;
    }

    [self disableAll];
    [_setWayPoint1 setState:NSOnState];
    _selmode = selWaypoint1;
    [_pView setWayPointMode:YES];
    [self _alignWayPoint];
    [self setNeedsDisplay:YES];
}
- (IBAction)setWaypoint2:(id)sender {
    if ([sender state] == NSOnState) {
        [self disableAll];
        return;
    }

    [self disableAll];
    [_setWayPoint2 setState:NSOnState];
    _selmode = selWaypoint2;
    [_pView setWayPointMode:YES];
    [self _alignWayPoint];
    [self setNeedsDisplay:YES];
}
- (IBAction)setCurrentPosition:(id)sender {
    if ([sender state] == NSOnState) {
        [self disableAll];
        return;
    }

    [self disableAll];
    [_setCurrentPoint setState:NSOnState];
    _selmode = selCurPos;
    [_pView setWayPointMode:NO];
    [self _alignCurrentPos];
    [self setNeedsDisplay:YES];
}

- (IBAction)setShowCurrentPosition:(id)sender {
    if ([sender state] == NSOnState) {
        [self disableAll];
        return;
    }

    [self disableAll];
    [_showCurrentPoint setState:NSOnState];
    _selmode = selShowCurPos;
    [_pView setWayPointMode:NO];
    [self _alignCurrentPos];
    [self setNeedsDisplay:YES];
}


- (void)setShowNetworks:(BOOL)show {
    if (show && [_statusView visible]) {
		NSBeep(); //we got some error status
		return;
	}
	
	[_netContainer setVisible:show];
    [_showNetworks setState:(show ? NSOnState : NSOffState)];
    [self setNeedsDisplay:YES];
}

- (void)setShowTrace:(BOOL)show {
    [_trace setVisible:show];
    [_showTrace setState:(show ? NSOnState : NSOffState)];
    [self setNeedsDisplay:YES];
}

#pragma mark -

- (void)dealloc {
    [self unsubscribeNotifications];
}

@end

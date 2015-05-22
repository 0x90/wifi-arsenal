/*
        
        File:			MapView.h
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

#import <Cocoa/Cocoa.h>
#import "BIView.h"

#define INVALIDPOINT NSMakePoint(-100, -100)

enum selmode {
    selCurPos = 0,
    selWaypoint1 = 1,
    selWaypoint2 = 2,
    selShowCurPos = 3,
    selInvalid = 4,
};

@class NetView;
@class BIImageView;
@class BITextView;
@class BISubView;
@class MapControlPanel;
@class PointView;
@class Trace;

@interface MapView : BIView {
    NSString            *_status;
    NSString            *_gpsStatus;
    BITextView          *_statusView;
    BISubView           *_netContainer;
    BISubView           *_moveContainer;
    BITextView          *_gpsStatusView;
    MapControlPanel     *_controlPanel;
    PointView           *_pView;
    BOOL                _visible;
	BOOL				_autoCenter;
    NSImage             *_mapImage;
    NSImage             *_orgImage;
    Trace               *_trace;
    
    waypoint            _wp[3];
    NSPoint             _old;
    NSPoint             _point[3];
    NSPoint             _center;
    float               _zoomFact;
    
    enum selmode        _selmode;
    
    IBOutlet NSMenuItem *_setWayPoint1;
    IBOutlet NSMenuItem *_setWayPoint2;
    IBOutlet NSMenuItem *_setCurrentPoint;
    IBOutlet NSMenuItem *_showCurrentPoint;
    IBOutlet NSMenuItem *_showNetworks;
    IBOutlet NSMenuItem *_showTrace;    
}

- (BOOL)saveToFile:(NSString*)fileName;
- (BOOL)loadFromFile:(NSString*)fileName;
- (NSData*)pdfData;

- (BOOL)setMap:(NSImage*)map;
- (BOOL)hasValidMap;
- (BOOL)setWaypoint:(int)which toPoint:(NSPoint)point atCoordinate:(waypoint)coord;
- (void)setVisible:(BOOL)visible;
- (BOOL)setCurrentPostionToLatitude:(double)lat andLongitude:(double)lon;

- (NSPoint)pixelForCoordinateNoZoom:(waypoint)wp;
- (NSPoint)pixelForCoordinate:(waypoint)wp;
- (void)setNeedsDisplayInMoveRect:(NSRect)invalidRect;

- (void)addNetView:(NetView*)view;
- (void)removeNetView:(NetView*)view;

- (void)setShowNetworks:(BOOL)show;
- (void)setShowTrace:(BOOL)show;

- (IBAction)autoCenter:(id)sender;

- (IBAction)zoomIn:(id)sender;
- (IBAction)zoomOut:(id)sender;
- (IBAction)goLeft:(id)sender;
- (IBAction)goRight:(id)sender;
- (IBAction)goUp:(id)sender;
- (IBAction)goDown:(id)sender;

- (IBAction)setWaypoint1:(id)sender;
- (IBAction)setWaypoint2:(id)sender;
- (IBAction)setCurrentPosition:(id)sender;
- (IBAction)setShowCurrentPosition:(id)sender;

@end

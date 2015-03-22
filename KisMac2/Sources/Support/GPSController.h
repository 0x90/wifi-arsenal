/*
        
        File:			GPSController.h
        Program:		KisMAC
		Author:			Michael Rossberg, Robin Darroch
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

#import <Foundation/Foundation.h>
#include <CoreLocation/CoreLocation.h>

struct _position {
    char dir;
    float coordinates;
};

@interface GPSController : NSObject <CLLocationManagerDelegate>
{
    bool    _gpsThreadUp;
    bool    _gpsShallRun;
	bool	_gpsdReconnect;
    bool    _reliable;
    bool    _tripmateMode;
    int     _traceInterval;
    int     _onNoFix;
    bool    _debugEnabled;
    int     _linesRead;
    int     _serialFD;
    int     _veldir;
    float   _velkt;
	float   _maxvel;
	float   _peakvel;
    int     _numsat;
    float   _hdop;
	float   _sectordist;
	float   _sectortime;
	float   _totaldist;
    
    struct _position    _ns, _ew, _elev;
    NSDate*             _lastAdd;
    NSString*           _position;
    NSString*           _gpsDevice;
    NSDate*             _lastUpdate;
    NSDate*				_sectorStart;
    NSLock*             _gpsLock;
    NSString*           _status;
    
    CLLocationManager * clManager;
}

- (bool)startForDevice:(NSString*) device;
- (bool)reliable;
- (void)resetTrace;
- (bool)gpsRunning;
- (void)setTraceInterval:(int)interval;
- (void)setTripmateMode:(bool)mode;
- (void)setOnNoFix:(int)onNoFix;
- (NSDate*)lastUpdate;
- (NSString*)NSCoord;
- (NSString*)EWCoord;
- (NSString*)ElevCoord;
- (NSString*)status;
- (void)setCurrentPointNS:(double)ns EW:(double)ew ELV:(double)elv;

- (waypoint) currentPoint;
- (void)stop;

- (void)writeDebugOutput:(BOOL)enable;
@end

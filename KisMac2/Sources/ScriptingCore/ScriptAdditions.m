/*
        
        File:			ScriptAdditions.m
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

#import "ScriptAdditions.h"
#import "ScanController.h"
#import "ScanControllerScriptable.h"
#import "WaveHelper.h"
#import "MapView.h"

@implementation NSApplication (APLApplicationExtensions)

- (id)showNetworks:(NSScriptCommand *)command {
    return @([(ScanController*)[NSApp delegate] showNetworks]);
}
- (id)showTraffic:(NSScriptCommand *)command {
    return @([(ScanController*)[NSApp delegate] showTrafficView]);
}
- (id)showMap:(NSScriptCommand *)command {
    return @([(ScanController*)[NSApp delegate] showMap]);
}
- (id)showDetails:(NSScriptCommand *)command {
    return @([(ScanController*)[NSApp delegate] showDetails]);
}

#pragma mark -

- (id)startScan:(NSScriptCommand *)command {
    return @([(ScanController*)[NSApp delegate] startScan]);
}
- (id)stopScan:(NSScriptCommand *)command {
    return @([(ScanController*)[NSApp delegate] stopScan]);
}
- (id)toggleScan:(NSScriptCommand *)command {
    return @([(ScanController*)[NSApp delegate] toggleScan]);
}

#pragma mark -

- (id)new:(NSScriptCommand *)command 
{
    return @([(ScanController*)[NSApp delegate] new]);
}

- (id)save:(NSScriptCommand *)command {
    return @([(ScanController*)[NSApp delegate] save:[command directParameter]]);
}

- (id)saveAs:(NSScriptCommand *)command {
    return @([(ScanController*)[NSApp delegate] saveAs:[command directParameter]]);
}

- (id)importKisMAC:(NSScriptCommand *)command {
    return @([(ScanController*)[NSApp delegate] importKisMAC:[command directParameter]]);
}
- (id)importImageForMap:(NSScriptCommand *)command {
    return @([(ScanController*)[NSApp delegate] importImageForMap:[command directParameter]]);
}
- (id)importPCAP:(NSScriptCommand *)command {
    return @([(ScanController*)[NSApp delegate] importPCAP:[command directParameter]]);
}
- (id)exportKML:(NSScriptCommand *)command {
    return @([(ScanController*)[NSApp delegate] exportKML:[command directParameter]]);
}


- (id)downloadMap:(NSScriptCommand*)command {
    NSDictionary *args = [command arguments];
    NSSize size = NSZeroSize;
    waypoint w;
    int zoom = 0;
    NSString *server;
    
    server = [command directParameter];
    size.width = [args[@"Width"] doubleValue];
    size.height = [args[@"Height"] doubleValue];
    w._lat  = [args[@"Latitude"] doubleValue];
    w._long = [args[@"Longitude"] doubleValue];
	w._elevation = 0;
    zoom = [args[@"Zoom"] intValue];
    
    BOOL ret = [(ScanController*)[NSApp delegate] downloadMapFrom:server forPoint:w resolution:size zoomLevel:zoom];
    return @(ret);
}

#pragma mark -

- (id)selectNetworkWithBSSID:(NSScriptCommand *)command {
   return @([(ScanController*)[NSApp delegate] selectNetworkWithBSSID:[command directParameter]]);
}

- (id)selectNetworkAtIndex:(NSScriptCommand *)command {
   return @([(ScanController*)[NSApp delegate] selectNetworkAtIndex:[command directParameter]]);
}

- (id)networkCount:(NSScriptCommand *)command {
   return @([(ScanController*)[NSApp delegate] networkCount]);
}

#pragma mark -

- (id)busy:(NSScriptCommand *)command {
   return @([(ScanController*)[NSApp delegate] isBusy]);
}

#pragma mark -

- (id)bruteforceNewsham:(NSScriptCommand *)command {
   return @([(ScanController*)[NSApp delegate] bruteforceNewsham]);
}

- (id)bruteforce40bitLow:(NSScriptCommand *)command {
   return @([(ScanController*)[NSApp delegate] bruteforce40bitLow]);
}

- (id)bruteforce40bitAlpha:(NSScriptCommand *)command {
   return @([(ScanController*)[NSApp delegate] bruteforce40bitAlpha]);
}

- (id)bruteforce40bitAll:(NSScriptCommand *)command {
   return @([(ScanController*)[NSApp delegate] bruteforce40bitAll]);
}

- (id)wordlist40bitApple:(NSScriptCommand *)command {
   return @([(ScanController*)[NSApp delegate] wordlist40bitApple:[command directParameter]]);
}

- (id)wordlist104bitApple:(NSScriptCommand *)command {
   return @([(ScanController*)[NSApp delegate] wordlist104bitApple:[command directParameter]]);
}

- (id)wordlist104bitMD5:(NSScriptCommand *)command {
   return @([(ScanController*)[NSApp delegate] wordlist104bitMD5:[command directParameter]]);
}

- (id)wordlistWPA:(NSScriptCommand *)command {
   return @([(ScanController*)[NSApp delegate] wordlistWPA:[command directParameter]]);
}

- (id)wordlistLEAP:(NSScriptCommand *)command {
   return @([(ScanController*)[NSApp delegate] wordlistLEAP:[command directParameter]]);
}

- (id)weakSchedulingAttack:(NSScriptCommand *)command {
    NSDictionary *args = [command arguments];
    int keyID, keyLen;
    
    keyID = [args[@"KeyID"] intValue];
    keyLen = [args[@"KeyLen"] intValue];
    if (keyLen == 0) keyLen = 13;
    
    return @([(ScanController*)[NSApp delegate] weakSchedulingAttackForKeyLen:keyLen andKeyID:keyID]);
}

#pragma mark -

- (id)showNetworksInMap:(NSScriptCommand*)command {
    [[WaveHelper mapView] setShowNetworks:[[command directParameter] boolValue]];
    return @YES;    
}

- (id)showTraceInMap:(NSScriptCommand*)command {
    [[WaveHelper mapView] setShowTrace:[[command directParameter] boolValue]];
    return @YES;    
}

- (id)setCurrentPosition:(NSScriptCommand*)command {
    NSDictionary *args = [command arguments];
    BOOL ret = [[WaveHelper mapView] setCurrentPostionToLatitude:[args[@"Latitude"] doubleValue] andLongitude:[args[@"Longitude"] doubleValue]];
    return @(ret);
}

- (id)setWaypoint:(NSScriptCommand*)command {
    NSDictionary *args = [command arguments];
    NSPoint p;
    waypoint coord;
    int which;
    
    which = [[command directParameter] intValue];
    p.x = [args[@"X"] doubleValue];
    p.y = [args[@"Y"] doubleValue];
    coord._lat  = [args[@"Latitude"] doubleValue];
    coord._long = [args[@"Longitude"] doubleValue];
    coord._elevation = 0;
    BOOL ret = [[WaveHelper mapView] setWaypoint:which toPoint:p atCoordinate:coord];
    return @(ret);
}

@end

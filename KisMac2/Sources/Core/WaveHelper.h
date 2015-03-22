/*
        
        File:			WaveHelper.h
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

#import <Cocoa/Cocoa.h>
#import "KisMAC80211.h"

#ifdef __cplusplus
extern "C" {
#endif
void WirelessCryptMD5(char const *str, unsigned char *key);
#ifdef __cplusplus
}
#endif

#ifndef OK
#define OK NSLocalizedString(@"OK", @"OK Button")
#endif

#ifndef CANCEL
#define CANCEL NSLocalizedString(@"Cancel", "Cancel Button")
#endif

#ifndef ERROR_TITLE
#define ERROR_TITLE NSLocalizedString(@"Error", "Some user error dialog title")
#endif

@class ScanController;
@class MapView;
@class ImportController;
@class GPSController;
@class GPSInfoController;
@class WaveDriver;
@class Trace;

@interface WaveHelper : NSObject /*<UKTest>*/ {

}

+ (bool)runScript:(NSString*)script;
+ (bool)runScript:(NSString*)script withArguments:(NSArray*)args;

+ (NSString*) bytesToString:(float) bytes;
+ (NSString*) urlEncodeString:(NSString*)string;
+ (NSString*) vendorForMAC:(NSString*)MAC;
+ (NSString*) hexEncode:(UInt8*)data length:(int)len;
+ (NSString *) macToString:(UInt8*)m;

+ (void)speakSentence:(CFStringRef)cSentence withVoice:(int)voice;
+ (bool)isServiceAvailable:(char*)service;

+ (int)chan2freq:(int)channel;
+ (int)freq2chan:(int)frequency;

+ (bool)unloadAllDrivers;
+ (bool)loadDrivers;
+ (NSArray*) getWaveDrivers;
+ (WaveDriver*) injectionDriver;
+ (WaveDriver*) driverWithName:(NSString*) s;

+ (NSWindow*) mainWindow;
+ (void) setMainWindow:(NSWindow*)mw;

+ (ScanController*) scanController;
+ (void) setScanController:(ScanController*)scanController;

+ (GPSController*) gpsController;
+ (void) initGPSControllerWithDevice:(NSString*)device;

+ (void) setGPSInfoController:(GPSInfoController*)GPSController;
+ (GPSInfoController*) GPSInfoController;

+ (MapView*) mapView;
+ (void) setMapView:(MapView*)mv;
+ (Trace*) trace;
+ (void) setTrace:(Trace*)trace;

+ (NSColor*)intToColor:(NSNumber*)c;
+ (NSNumber*)colorToInt:(NSColor*)c;

+ (ImportController*) importController;
+ (void) setImportController:(ImportController*)im;
+ (NSMutableArray*) getProbeArrayForID:(char*)ident;

+ (void)addDictionary:(NSDictionary*)s toDictionary:(NSMutableDictionary*)d;

+ (int)showCouldNotInstaniciateDialog:(NSString*)driverName;

/* packet utilities */
+ (NSString*)frameControlToString:(UInt16)fc;
+ (void)dumpKFrame:(KFrame *)f;

@end

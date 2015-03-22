/*
        
        File:			WaveHelper.m
        Program:		KisMAC
		Author:			Michael Rossberg, Michael Thole
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

#import "WaveHelper.h"
#import <BIGeneric/BIGeneric.h>
#import "../WaveDrivers/WaveDriverAirport.h"
#import "../WaveDrivers/WaveDriver.h"

#include "polarssl/md5.h"
#include <unistd.h>
#import <CoreFoundation/CoreFoundation.h>
#import <IOKit/IOKitLib.h>
#import <Security/Security.h>
#import <CoreServices/CoreServices.h>

#import "WaveContainer.h"
#import "GPSController.h"
#import "GPSInfoController.h"
#import "ImportController.h"

#import "../Core/80211b.h"

/*
 * generate 104-bit key based on the supplied string
 */
void WirelessCryptMD5(char const *str, unsigned char *key) {
    int i, j;
    u_char md5_buf[64];
    md5_context ctx;

    j = 0;
    for(i = 0; i < 64; ++i) {
        if(str[j] == 0) j = 0;
        md5_buf[i] = str[j++];
    }

    md5_starts(&ctx);
    md5_update(&ctx, md5_buf, 64);
    md5_finish(&ctx, md5_buf);
    
    memcpy(key, md5_buf, 13);
}

@implementation WaveHelper

static NSDictionary *_vendors = nil;	//Dictionary
static BISpeechController *_speechController = nil;

// Global dictionary to keeps drivers
static NSMutableDictionary* _waveDrivers = nil;

static NSWindow* aMainWindow;
static GPSController* aGPSController;
static MapView *_mapView;
static NSMutableDictionary *_probes = nil;
static Trace *_trace;
static ImportController *_im;
static ScanController *_scanController;
static GPSInfoController *_gc;

// Converts a byte count to a human readable string
+ (NSString *) bytesToString:(float) bytes {
    if (bytes > 700000000)
        return [NSString stringWithFormat:@"%1.2fGiB",bytes/1024/1024/1024];
    else if (bytes > 700000)
        return [NSString stringWithFormat:@"%1.2fMiB",bytes/1024/1024];
    else if (bytes > 700)
        return [NSString stringWithFormat:@"%1.2fKiB",bytes/1024];
    else
        return [NSString stringWithFormat:@"%.fB",bytes];
}


//converts a string to an url encoded string
+ (NSString*) urlEncodeString:(NSString*)string 
{
    return [string stringByAddingPercentEscapesUsingEncoding: NSUTF8StringEncoding];
}

#pragma mark -
#pragma mark MAC Utilities
#pragma mark -

// Encode a binary string into form XX:XX:XX.....
+ (NSString*) hexEncode:(UInt8*)data length:(int)len {
    NSParameterAssert(len > 0);
	NSParameterAssert(data);
	int i, j;
	
	NSMutableString *ms = [NSMutableString stringWithFormat:@"%.2X", data[0]];
    
	for (i = 1; i < len; ++i) {
        j = data[i];
        [ms appendFormat:@":%.2X", j];
    }
	return ms;
}

+ (NSString*) macToString:(UInt8*)m {
    if (!m)
        return nil;
    return [NSString stringWithFormat:@"%.2X:%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", m[0], m[1], m[2], m[3], m[4], m[5], m[6]];
}

// Returns the vendor for a specific MAC-Address
+ (NSString *)vendorForMAC:(NSString*)MAC {
    NSString *aVendor;
    
    // The dictionary is cached for speed, but it needs to be loaded the first time
    if (_vendors == nil) {
		NSString *path = [[[NSBundle mainBundle] resourcePath] stringByAppendingPathComponent:@"vendor.db"];
        _vendors = [NSDictionary dictionaryWithContentsOfFile:path];
		if (!_vendors) {
			DBNSLog(@"No vendors Database found!");
			return @"error";
		}
    }
	
    // Do we have a valid MAC?
    if ((MAC == nil) || ([MAC length] < 11))
        return @"";
    
    // See if we can find a most matching dictionary entry
    aVendor = _vendors[MAC];
    if (aVendor == nil) {
        aVendor = _vendors[[MAC substringToIndex:11]];
        if (aVendor == nil) {
            aVendor = _vendors[[MAC substringToIndex:8]];
            if (aVendor == nil) {
                aVendor = _vendors[[MAC substringToIndex:5]];
                if (aVendor == nil) {
                    return @"unknown";                    
                } 
            }
        }
    }
    return aVendor;
}

#pragma mark -

//tries to speak something. if it does not work => put it to the queue
+ (void)speakSentence:(CFStringRef)cSentence withVoice:(int)voice
{
    if (!_speechController)
    {
        _speechController = [[BISpeechController alloc] init];
    }
    [_speechController speakSentence:cSentence withVoice:voice];
}

#pragma mark -
#pragma mark Channel utility functions
#pragma mark -

+ (int)chan2freq:(int)channel {
    if (channel == 14)
        return 2484;
    if (channel >= 1 && channel <= 13)
        return 2407 + channel * 5;
	if (channel < 200)
        return 5000 + channel * 5;
    return 0;
}
+ (int)freq2chan:(int)frequency {
    if (frequency == 2484)
        return 14;
    if (frequency < 2484 && frequency > 2411 && ((frequency - 2407) % 5 == 0))
        return (frequency - 2407) / 5;
	if (frequency >= 5000 && frequency < 5900 && (frequency % 5) == 0)
        return (frequency - 5000) / 5;
    return 0;
}

#pragma mark -
#pragma mark Driver handling
#pragma mark -

+ (bool)isServiceAvailable:(char*)service {
    mach_port_t masterPort;
    io_iterator_t iterator;
    io_object_t sdev;
 
    if (IOMasterPort(MACH_PORT_NULL, &masterPort) != KERN_SUCCESS) {
        return NO; // REV/FIX: throw.
    }
        
    if (IORegistryCreateIterator(masterPort, kIOServicePlane, kIORegistryIterateRecursively, &iterator) == KERN_SUCCESS) {
        while ((sdev = IOIteratorNext(iterator)))
            if (IOObjectConformsTo(sdev, service)) {
                IOObjectRelease (iterator);
                return YES;
            }
        IOObjectRelease(iterator);
    }
    
    return NO;
}

//tells us whether a driver is in the RAM
+ (bool)isDriverLoaded:(int)driverID {
    switch(driverID) {
    case 1:
        if (![self isServiceAvailable:"WLanDriver"]) return NO;
        else return YES;
    case 2:
        if (![self isServiceAvailable:"MACJackDriver"]) return NO;
        else return YES;
    case 3:
        if (![self isServiceAvailable:"AiroJackDriver"]) return NO;
        else return YES;
    case 4:
        if ([self isServiceAvailable:"AirPortDriver"] || [self isServiceAvailable:"AirPortPCI"] ||
            [self isServiceAvailable:"AirPortPCI_MM"] || [self isServiceAvailable:"AirPort_Brcm43xx"]  ||
            [WaveHelper isServiceAvailable:"AirPort_Athr5424"] || [self isServiceAvailable:"AirPort_Athr5424ab"]) return YES;
        else return NO;
    default:
        return NO;
    }
}

+ (bool)unloadAllDrivers {
    id key;
    WaveDriver *w;
    NSEnumerator *e;
    
    if (!_waveDrivers) return YES;
    
    e = [_waveDrivers keyEnumerator];
    
    while ((key = [e nextObject]))
    {
        w = _waveDrivers[key];
        [_waveDrivers removeObjectForKey:key];
        [w unloadBackend];
        w = nil;
    }
    
    return YES;
}

//placeholder for later
+ (bool)loadDrivers
{
    NSUserDefaults *d;
    WaveDriver *w = nil;
    NSArray *a;
    NSDictionary *driverProps;
    NSString *name;
    NSString *interfaceName;
    Class driver;
    unsigned int i, j;
    
    //if our dictionary does not exist then create it.
    if (!_waveDrivers) {
        _waveDrivers = [NSMutableDictionary dictionary];
    }
    
    d = [NSUserDefaults standardUserDefaults];
    a = [d objectForKey:@"ActiveDrivers"];
    
    //see if all of the drivers mentioned in our prefs are loaded
    for (i = 0; i < [a count]; ++i) {
        driverProps = a[i];
        name = driverProps[@"deviceName"];
        
        //the driver does not exist. go for it
        if (!_waveDrivers[name]) {
        
            //ugly hack but it works, this makes sure that the airport card is used only once
            interfaceName = driverProps[@"driverID"];
            
            // Get the class for driver
            driver = NSClassFromString(interfaceName);
            
            // Call driver Class method "loadBackend"
            if (![driver loadBackend]) 
            {
                //return NO;
            }
            
            //create an interface
            for (j = 0; j < 10; ++j)
            {
                w = [[driver alloc] init];
                if (w)
                {
                    break;
                }
                [NSThread sleepUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.4]];
            }
            
            if (w)
            {
                [w setConfiguration: driverProps];
                _waveDrivers[name] = w;
            }
            else
            {
                NSRunCriticalAlertPanel(NSLocalizedString(@"Could not instantiate Driver.", "Driver init failed"),
                NSLocalizedString (@"Instantiation Failure Description", @"LONG description of what might have gone wrong"),
                name,
                OK, nil, nil);
            
                DBNSLog(@"Error could not instantiate driver %@", interfaceName);
                return NO;
            }
        }
    }
    
    //now make sure any drivers that have been removed from the list are gone
    NSEnumerator *e = [_waveDrivers objectEnumerator];
   
    while((w = [e nextObject]))
    {
        if(![a containsObject: [w configuration]])
        {
            [_waveDrivers removeObjectForKey: [w deviceName]];
            
        }           
    }//end 

    return YES;
}

+ (NSArray*) getWaveDrivers {
    if (!_waveDrivers) {
        _waveDrivers = [NSMutableDictionary dictionary];
    }
    
    return [_waveDrivers allValues];
}

+ (WaveDriver*) injectionDriver {
    NSEnumerator *e;
    NSString *k;
    NSDictionary *d;
    
    e = [_waveDrivers keyEnumerator];
    while ((k = [e nextObject])) {
        d = [(WaveDriver*)_waveDrivers[k] configuration];
        if ([d[@"injectionDevice"] intValue]) return _waveDrivers[k];
    }
    
    return nil;
}

+ (WaveDriver*) driverWithName:(NSString*) s {
    return _waveDrivers[s];
}

#pragma mark -

+ (NSWindow*) mainWindow {
    return aMainWindow;
}
+ (void) setMainWindow:(NSWindow*)mw {
    aMainWindow = mw;
}

+ (ScanController*) scanController {
    return _scanController;
}
+ (void) setScanController:(ScanController*)scanController {
    _scanController=scanController;
}

+ (GPSInfoController*) GPSInfoController {
	return _gc;
}
+ (void) setGPSInfoController:(GPSInfoController*)GPSController {
    _gc=GPSController;
}

+ (GPSController*) gpsController {
    return aGPSController;
}

+ (void) initGPSControllerWithDevice:(NSString*)device {
    if (!aGPSController) 
        aGPSController = [[GPSController alloc] init];
    [aGPSController startForDevice:device];
}

+ (MapView*) mapView {
    return _mapView;
}
+ (void) setMapView:(MapView*)mv {
    _mapView = mv;
}

+ (Trace*) trace {
    return _trace;
}
+ (void) setTrace:(Trace*)trace {
    _trace = trace;
}

+ (NSColor*)intToColor:(NSNumber*)c {
    float r, g, b, a;    
    int i = [c intValue];

    a =  (i >> 24) & 0xFF;
    r =  (i >> 16) & 0xFF;
    g =  (i >> 8 ) & 0xFF;
    b =  (i      ) & 0xFF;
    
    return [NSColor colorWithCalibratedRed:r/255 green:g/255 blue:b/255 alpha:a/255];
}
+ (NSNumber*)colorToInt:(NSColor*)c {
    unsigned int i;
    float a, r,g, b;
    
    a = [c alphaComponent] * 255;
    r = [c redComponent]   * 255;
    g = [c greenComponent] * 255;
    b = [c blueComponent]  * 255;
    
    i = ((unsigned int)floor(a) << 24) | ((unsigned int)floor(r)<< 16) | ((unsigned int)floor(g) << 8) | (unsigned int)(b);
    return [NSNumber numberWithInt:i];
}

+ (ImportController*) importController {
    return _im;
}
+ (void) setImportController:(ImportController*)im {
    _im = im;
}

+ (NSMutableArray*) getProbeArrayForID:(char*)ident {
    NSMutableArray *ar;
    NSString *idstr;
    if (!_probes) _probes = [NSMutableDictionary dictionary];
    idstr = [NSString stringWithFormat:@"%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", ident[0], ident[1], ident[2], ident[3], ident[4], ident[5]];
    ar = _probes[idstr];
    if (!ar) {
        ar = [NSMutableArray array];
        [ar addObject:[NSDate date]];
        [ar addObject:@0];
        _probes[idstr] = ar;
    }
    return ar;
}

+ (bool)runScript:(NSString*)script {
    return [self runScript:script withArguments:nil];
}

+ (bool)runScript:(NSString*)script withArguments:(NSArray*)args
{
    bool ret = NO;

    NSString* s = [NSString stringWithFormat:@"%@/%@", [[NSBundle mainBundle] resourcePath], script];
    
    ret = [[BLAuthentication sharedInstance] executeCommand:s withArgs:args];
    
    if (!ret)
        DBNSLog(@"WARNING!!! User canceled password dialog for: %@", s);
    
    return ret;
}

+ (void)addDictionary:(NSDictionary*)s toDictionary:(NSMutableDictionary*)d {
    NSEnumerator* e = [s keyEnumerator];
    id key;
    
    while ((key = [e nextObject]) != nil) {
        d[key] = s[key];
    }
}

+ (int)showCouldNotInstaniciateDialog:(NSString*)driverName {
    NSString *warning = NSLocalizedString(@"Could not instanciate Driver description", "LONG description");
    /*@"KisMAC has been able to load the driver (%@). Reasons for this failure could be:\n\n"
        "\t1. You selecteted the wrong driver.\n"
        "\t2. You did not insert your PCMCIA card (only if you selected such a driver).\n"
        "\t3. Your kernel extensions screwed up. In this case simply reboot.\n"
        "\t4. You are using a 3rd party card and you are having another driver for the card installed, which could not be unloaded by KisMAC."
        "If you have the sourceforge wireless driver, please install the patch, provided with KisMAC.\n"*/
        
    return NSRunCriticalAlertPanel(
        NSLocalizedString(@"Could not instaniciate Driver.", "Error title"), 
        warning, driverName,
        NSLocalizedString(@"Retry", "Retry button"),
        NSLocalizedString(@"Abort", "Abort button"),
        nil);
}

#pragma mark -
#pragma mark -

+ (NSString*)frameControlToString:(UInt16)fc {
    NSString *typeStr;
    NSString *subtypeStr;
    UInt16 type =    (fc & IEEE80211_TYPE_MASK);
    UInt16 subtype = (fc & IEEE80211_SUBTYPE_MASK);
	typeStr = @"UNKNOWN";
	subtypeStr = @"UNKNOWN";
    switch (type) {
        case IEEE80211_TYPE_MGT:
            typeStr = @"Management";
            switch (subtype) {
                case IEEE80211_SUBTYPE_ASSOC_REQ:
                    subtypeStr = @"Association Request";
                    break;
                case IEEE80211_SUBTYPE_ASSOC_RESP:
                    subtypeStr = @"Association Response";
                    break;
                case IEEE80211_SUBTYPE_REASSOC_REQ:
                    subtypeStr = @"Reassociation Request";
                    break;
                case IEEE80211_SUBTYPE_REASSOC_RESP:
                    subtypeStr = @"Reassociation Response";
                    break;
                case IEEE80211_SUBTYPE_PROBE_REQ:
                    subtypeStr = @"Probe Request";
                    break;
                case IEEE80211_SUBTYPE_PROBE_RESP:
                    subtypeStr = @"Probe Response";
                    break;
                case IEEE80211_SUBTYPE_BEACON:
                    subtypeStr = @"Beacon";
                    break;
                case IEEE80211_SUBTYPE_ATIM:
                    subtypeStr = @"Atim";
                    break;
                case IEEE80211_SUBTYPE_DISASSOC:
                    subtypeStr = @"Dissassociation";
                    break;
                case IEEE80211_SUBTYPE_AUTH:
                    subtypeStr = @"Authentication";
                    break;
                case IEEE80211_SUBTYPE_DEAUTH:
                    subtypeStr = @"Deauthentication";
                    break;
                case IEEE80211_SUBTYPE_ACTION:
                    subtypeStr = @"Action";
                    break;                    
            }
            break;
        case IEEE80211_TYPE_CTL:
            typeStr = @"Control";
            switch (subtype) {
                case IEEE80211_SUBTYPE_PS_POLL:
                    subtypeStr = @"PS Poll";
                    break;
                case IEEE80211_SUBTYPE_RTS:
                    subtypeStr = @"RTS";
                    break;
                case IEEE80211_SUBTYPE_CTS:
                    subtypeStr = @"CTS";
                    break;
                case IEEE80211_SUBTYPE_ACK:
                    subtypeStr = @"ACK";
                    break;
                case IEEE80211_SUBTYPE_CF_END:
                    subtypeStr = @"CF END";
                    break;
                case IEEE80211_SUBTYPE_CF_END_ACK:
                    subtypeStr = @"CF END ACK";
                    break;                    
            }
            break;
        case IEEE80211_TYPE_DATA:
            typeStr = @"Data";
            switch (subtype) {
                case IEEE80211_SUBTYPE_DATA:
                    subtypeStr = @"Data";
                    break;
                case IEEE80211_SUBTYPE_DATA_CFACK:
                    subtypeStr = @"Data CF ACK";
                    break;
                case IEEE80211_SUBTYPE_DATA_CFPOLL:
                    subtypeStr = @"Data CF Poll";
                    break;
                case IEEE80211_SUBTYPE_DATA_CFACKPOLL:
                    subtypeStr = @"Data CF ACK Poll";
                    break;
                case IEEE80211_SUBTYPE_NULLFUNC:
                    subtypeStr = @"Null Function";
                    break;
                case IEEE80211_SUBTYPE_CFACK:
                    subtypeStr = @"CF ACK";
                    break;
                case IEEE80211_SUBTYPE_CFPOLL:
                    subtypeStr = @"CF POLL";
                    break;
                case IEEE80211_SUBTYPE_CFACKPOLL:
                    subtypeStr = @"CF ACK POLL";
                    break;
                case IEEE80211_SUBTYPE_QOS_DATA:
                    subtypeStr = @"QOS Data";
                    break;                    
            }
            break;
    }
    return [NSString stringWithFormat:@"%@ %@", typeStr, subtypeStr];
}
+ (void)dumpKFrame:(KFrame *)f {
    UInt32 size = f->ctrl.len;
    UInt8 *data = f->data;
    DBNSLog(@"--FRAME LENGTH %d--", (int)size);
    int idx = 0;
    int i,j;
	for (i=0;i<size;i=i+8) {
        fprintf(stderr, "0x%.4x ", i);
        for (j=0;j<8;++j) {
            if (idx < size)
                fprintf(stderr, "%.2x ", data[idx]);
            else
                fprintf(stderr, "   ");
            idx += 1;
        }
        fprintf(stderr, "\n");
    }
}
@end

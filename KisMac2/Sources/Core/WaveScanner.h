/*
        
        File:			WaveScanner.h
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

#import <AppKit/AppKit.h>
#import <pcap.h>

#import "KisMAC80211.h"

@class WaveNet;
@class WaveSpectrumDriver;
@class WaveContainer;
@class WaveClient;
@class ImportController;
@class ScanController;

@interface WaveScanner : NSObject <NSSoundDelegate> 
{    
    NSTimer* _scanTimer;                //timer for refreshing the tables
    NSTimer* _hopTimer;                 //channel hopper

    NSString* _geigerSound;             //sound file for the geiger counter

    int _packets;                       //packet count
    int _geigerInt;
    int _bytes;                         //bytes since last refresh (for graph)
    bool _soundBusy;                    //are we clicking?
    
    NSArray *_drivers;                  // Array of drivers
    
    int _graphLength;
    NSTimeInterval _scanInterval;	//refresh interval
    
    int  aPacketType;
    bool aScanRange;
    bool _scanning;
    bool _shouldResumeScan;
    bool _deauthing;
    double aFreq;
    int  _driver;
    
    unsigned char aFrameBuf[MAX_FRAME_BYTES];	//for reading in pcaps (still messy)
    KFrame* aWF;
    pcap_t*  _pcapP;

    ImportController *_im;

    IBOutlet ScanController* aController;
    IBOutlet WaveContainer* _container;
   
    NSMutableDictionary *_wavePlugins;
    
    WaveSpectrumDriver *_waveSpectrum;
}

- (void)readPCAPDump:(NSString*)dumpFile;
-(KFrame*) nextFrame:(bool*)corrupted;

//for communications with ScanController which does all the graphic stuff
- (int) graphLength;

//scanning properties
- (void) setFrequency:(double)newFreq;
- (bool) startScanning;
- (bool) stopScanning;
- (bool) sleepDrivers: (bool)isSleepy;
- (void) setGeigerInterval:(int)newGeigerInt sound:(NSString*) newSound;
- (NSTimeInterval) scanInterval;

//active attacks
- (NSString*) tryToInject:(WaveNet*)net;
- (void) setDeauthingAll:(BOOL)deauthing;
- (bool) authFloodNetwork:(WaveNet*)net;
- (bool) deauthenticateNetwork:(WaveNet*)net atInterval:(int)interval;
- (bool) beaconFlood;
- (bool) stopSendingFrames;
- (bool) injectionTest: (WaveNet *)net withClient: (WaveClient *)client;

- (void) sound:(NSSound *)sound didFinishPlaying:(bool)abool;
@end

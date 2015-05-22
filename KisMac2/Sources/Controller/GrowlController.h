/*
        
        File:			GrowlController.h
        Program:		KisMAC
		Description:	KisMAC is a wireless stumbler for MacOS X.
		Author:			themacuser at gmail dot com
                
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
#import <Growl/Growl.h>

@interface GrowlController : NSObject<GrowlApplicationBridgeDelegate> {
}
- (void)registerGrowl;
+ (void)notifyGrowlOpenNetwork:(NSString *)notname SSID:(NSString *)SSID BSSID:(NSString *)BSSID signal:(int)signal channel:(int)channel;
+ (void)notifyGrowlUnknownNetwork:(NSString *)notname SSID:(NSString *)SSID BSSID:(NSString *)BSSID signal:(int)signal channel:(int)channel;
+ (void)notifyGrowlLEAPNetwork:(NSString *)notname SSID:(NSString *)SSID BSSID:(NSString *)BSSID signal:(int)signal channel:(int)channel;
+ (void)notifyGrowlWEPNetwork:(NSString *)notname SSID:(NSString *)SSID BSSID:(NSString *)BSSID signal:(int)signal channel:(int)channel;
+ (void)notifyGrowlWPANetwork:(NSString *)notname SSID:(NSString *)SSID BSSID:(NSString *)BSSID signal:(int)signal channel:(int)channel;
+ (void)notifyGrowlProbeRequest:(NSString *)notname BSSID:(NSString *)BSSID signal:(int)signal;
+ (void)notifyGrowlStartScan;
+ (void)notifyGrowlStopScan;
+ (void)notifyGrowlWPAChallenge:(NSString *)notname mac:(NSString *)mac bssid:(NSString *)bssid;
+ (void)notifyGrowlWPAResponse:(NSString *)notname mac:(NSString *)mac bssid:(NSString *)bssid;
+ (void)notifyGrowlSSIDRevealed:(NSString *)notname BSSID:(NSString *)BSSID SSID:(NSString *)SSID;
@end

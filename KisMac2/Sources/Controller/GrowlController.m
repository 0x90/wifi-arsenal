/*
        
        File:			GrowlController.m
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

#import "GrowlController.h"

@implementation GrowlController

- (id)init
{
	return [super init];
}


- (void)registerGrowl
{
	NSBundle *myBundle = [NSBundle bundleForClass:[GrowlController class]];
	NSString *growlPath = [[myBundle privateFrameworksPath]
	stringByAppendingPathComponent:@"Growl.framework"];
	NSBundle *growlBundle = [NSBundle bundleWithPath:growlPath];
	if (growlBundle && [growlBundle load]) {
		[GrowlApplicationBridge setGrowlDelegate:self];
	} else {
		DBNSLog(@"Could not load Growl.framework");
	}
}

#pragma mark Growl Notifications

+ (void)notifyGrowlOpenNetwork:(NSString *)notname SSID:(NSString *)SSID BSSID:(NSString *)BSSID signal:(int)signal channel:(int)channel
{

}

+ (void)notifyGrowlWEPNetwork:(NSString *)notname SSID:(NSString *)SSID BSSID:(NSString *)BSSID signal:(int)signal channel:(int)channel
{

}

+ (void)notifyGrowlWPANetwork:(NSString *)notname SSID:(NSString *)SSID BSSID:(NSString *)BSSID signal:(int)signal channel:(int)channel
{

}

+ (void)notifyGrowlUnknownNetwork:(NSString *)notname SSID:(NSString *)SSID BSSID:(NSString *)BSSID signal:(int)signal channel:(int)channel
{

}
+ (void)notifyGrowlLEAPNetwork:(NSString *)notname SSID:(NSString *)SSID BSSID:(NSString *)BSSID signal:(int)signal channel:(int)channel
{

}

+ (void)notifyGrowlProbeRequest:(NSString *)notname BSSID:(NSString *)BSSID signal:(int)signal
{

}

+ (void)notifyGrowlStartScan
{
    NSData * iconData = nil;
    NSImage * image = [NSImage imageNamed:@"NSApplicationIcon"];
                       
    if(image != nil)
    {
        iconData = [image TIFFRepresentation];
    }
    
	[GrowlApplicationBridge
	notifyWithTitle:@"KisMAC"
		description:@"Starting Scan..."
   notificationName:@"Scan Started/Stopped"
		   iconData:iconData
		   priority:0
		   isSticky:NO
	   clickContext:nil];
}

+ (void)notifyGrowlStopScan
{
	[GrowlApplicationBridge
	notifyWithTitle:@"KisMAC"
		description:@"Stopping Scan..."
   notificationName:@"Scan Started/Stopped"
		   iconData:[NSData dataWithData:[[NSImage imageNamed:@"NSApplicationIcon"] TIFFRepresentation]]
		   priority:0
		   isSticky:NO
	   clickContext:nil];
}

+ (void)notifyGrowlWPAChallenge:(NSString *)notname mac:(NSString *)mac bssid:(NSString *)bssid
{

}

+ (void)notifyGrowlWPAResponse:(NSString *)notname mac:(NSString *)mac bssid:(NSString *)bssid
{

}

+ (void)notifyGrowlSSIDRevealed:(NSString *)notname BSSID:(NSString *)BSSID SSID:(NSString *)SSID
{

}

#pragma mark Growl Methods

- (NSString *)applicationNameForGrowl {
	return @"KisMAC";
}

- (NSDictionary *)registrationDictionaryForGrowl {
	NSArray *allNotifications = @[@"Scan Started/Stopped",@"Open Network Found",@"Closed Network Found",@"Probe Request Received",@"WPA Challenge/Response",@"Hidden SSID Revealed"];
	NSArray *defaultNotifications = @[@"Scan Started/Stopped",@"Open Network Found",@"Closed Network Found",@"WPA Challenge/Response",@"Hidden SSID Revealed"];
	NSDictionary *registrationDict = @{GROWL_NOTIFICATIONS_ALL: allNotifications, GROWL_NOTIFICATIONS_DEFAULT: defaultNotifications};
	return registrationDict;
}
	
@end

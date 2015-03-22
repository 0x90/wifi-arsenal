/*
        
        File:			WaveDriverKismet.m
        Program:		KisMAC
		Author:			Geordie Millar
						themacuser@gmail.com
		Description:	Scan with a Kismet server in KisMac.

		Details:		Tested with Kismet 2006.04.R1 on OpenWRT White Russian RC6 on a Diamond Digital R100
						(broadcom mini-PCI card, wrt54g capturesource)
						and Kismet 2006.04.R1 on Voyage Linux on a PC Engines WRAP.2E
						(CM9 mini-PCI card, madwifing)
                
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

#import "WaveDriverKismet.h"
#import "WaveHelper.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#include <unistd.h>
#include "80211b.h"

static int KismetInstances = 0;

@implementation WaveDriverKismet

- (id)init {
    self = [super init];
    if (!self)  return nil;
    
    ++KismetInstances;

    return self;
}

+(int) kismetInstanceCount {
    return KismetInstances;
}

#pragma mark -

+ (enum WaveDriverType) type {
    return activeDriver;
}

+ (bool) wantsIPAndPort {
    return YES;
}

+ (NSString*) description {
    return NSLocalizedString(@"Kismet Server, Passive Mode", "long driver description");
}

+ (NSString*) deviceName {
    return NSLocalizedString(@"Kismet Server", "short driver description");
}

#pragma mark -

+ (bool) loadBackend {
    return YES;
}

+ (bool) unloadBackend {
    return YES;
}

#pragma mark -

- (bool) startedScanning {
	NSUserDefaults *defs;
    defs = [NSUserDefaults standardUserDefaults];
	
	char* initstr = "!0 ENABLE NETWORK bssid,type,wep,signal,maxrate,channel,ssid\n";
	
	sockd  = socket(AF_INET, SOCK_STREAM, 0);
	if (sockd == -1) { 
		DBNSLog(@"Socket creation failed!"); 
			NSRunCriticalAlertPanel(
            NSLocalizedString(@"Could not connect to the Kismet server", "Error dialog title"),
            NSLocalizedString(@"Socket creation failed! This really shouldn't happen!", "LONG desc"),
            OK, nil, nil);
		return nil;
	}
	
	int foundhostname=0;
	int foundport=0;
	
	NSArray *a;
	a = [defs objectForKey:@"ActiveDrivers"];
	NSEnumerator *e = [a objectEnumerator];
	NSDictionary *drvr;
	@try {
		while ( (drvr = [e nextObject]) ) {
			if ([drvr[@"driverID"] isEqualToString:@"WaveDriverKismet"]) {
				hostname = [drvr[@"kismetserverhost"] UTF8String];
				foundhostname = 1;
				port = [drvr[@"kismetserverport"] intValue];
				foundport = 1;
			}
		}
	}
	@catch (NSException * ex) {
		DBNSLog(@"Exception getting the hostname and port from plist...");
	}

	if (foundhostname + foundport < 2) {
		DBNSLog(@"Error getting the hostname and port from plist...");
	}	
	
	ip = inet_addr(hostname);
		
	serv_name.sin_addr.s_addr = ip;
	serv_name.sin_family = AF_INET;
	serv_name.sin_port = htons(port); // option as well
	
	status = connect(sockd, (struct sockaddr*)&serv_name, sizeof(serv_name));
		
	if (status == -1)
    {
		DBNSLog(@"Could not connect to %s port %d", hostname, port);
        
        NSRunCriticalAlertPanel(NSLocalizedString(@"Could not connect to the Kismet server", "Error dialog title"),
                                @"KisMac could not connect to the Kismet server at %s port %@. Check the IP address and port.",
                                OK, nil, nil, hostname, @(port));

		return nil;
	}
		
	write(sockd, initstr, strlen(initstr));
	
	return YES;
}

- (bool) stopCapture {
	close(sockd);
	return YES;
}

#pragma mark -

- (NSArray*) networksInRange {
	int len,i,j,flags,t,signalint;
	int usenetarray = 0;
	char netbuf[2048];
	unsigned int bssidbyte;
	char bssidstring[6];
	NSString *netrcvd, *name;
	NSArray *netarray,*rcvd,*rcvd2,*rcvd3,*bssidar;
	NSDictionary *nets;
	NSData *bssid;
	NSNumber *signal,*noise,*channel,*capability,*isWPA;
		
	if((len = read(sockd, &netbuf[0], 2048)) < 0) { // read it in
		DBNSLog(@"Kismet Server read failed"); // we can't read in!
		return NO;
	}
	
	netarray = @[];
    //NULL terminate
    netbuf[len] = 0;
	netrcvd = @(netbuf);
	rcvd2 = [netrcvd componentsSeparatedByString:@"\n"]; // split packet into lines
	int arrayCount = [rcvd2 count];
	for (i = 0; i < arrayCount; ++i) { // iterate through each line - 1 line = 1 network
		@try {
				netrcvd = rcvd2[i]; // put the current object into netrcvd
				rcvd = [netrcvd componentsSeparatedByString:@"\x01"]; // strip the SSID out
				rcvd3 = [rcvd[0] componentsSeparatedByString:@" "]; // strip the rest down
				if ([rcvd3[0] isEqualToString:@"*NETWORK:"]) { // if this is a line specifying a new network
					bssidar = [rcvd3[1] componentsSeparatedByString:@":"]; // get the BSSID
					
					for (j=0; j<6; ++i) {
						sscanf([bssidar[j] UTF8String], "%x", &bssidbyte); // convert it from ascii 12:34:56 into raw binary
						bssidstring[j] = bssidbyte;
					}
					
					bssid = [NSData dataWithBytes:bssidstring length:6];					// bssid, simple enough
					signalint = [rcvd3[4] intValue];							// signal level, as an int
					if (signalint > 1000 || signalint < 0) { signalint = 0; }				// sometimes it comes through as an invalid number
					signal = @(signalint);							// signal level as NSNumber, you can't put int into array
					noise = @0;										// this is only subtracted from signal, not needed
					channel = @([rcvd3[6] intValue]);	// channel...
					
					flags = 0;
					
					if ([rcvd3[3] intValue] == 2) {
						flags = flags | IEEE80211_CAPINFO_PRIVACY_LE; // if it's 2, it's WEP
					}
					
					if ([rcvd3[3] intValue] > 2) { // it's either not WEP, or it's some other encryption scheme
						isWPA = @1; // it's WPA
					} else {
						isWPA = @0; // it's open, or we don't know what it is
					}
					
					t = [rcvd3[2] intValue]; // network type
					
					if (t == 0) {
					flags = flags | IEEE80211_CAPINFO_ESS_LE;		// it's managed
					} else if (t == 1) {
					flags = flags | IEEE80211_CAPINFO_IBSS_LE;		// it's adhoc
					} else if (t == 2) {
					flags = flags | IEEE80211_CAPINFO_PROBE_REQ_LE; // it's a probe request
					}
					capability = @(flags);
					name = rcvd[1];
					nets = @{@"BSSID": bssid,@"signal": signal,@"noise": noise,@"channel": channel,@"isWPA": isWPA,@"name": name,@"capability": capability};
					netarray = [netarray arrayByAddingObject:nets];
					usenetarray = 1; // we do want to send the result
				}
		}
		@catch (NSException *exception) {
			DBNSLog(@"Invalid message, ignored"); // if an invalid message came in, ignore it instead of crashing
		}
	}
	if (usenetarray == 1) { return netarray; } else { return nil; } // return the result
}

#pragma mark -

- (void) hopToNextChannel {
	return;
}

#pragma mark -

-(void) dealloc {
    KismetInstances--;
    close(sockd);
}

@end

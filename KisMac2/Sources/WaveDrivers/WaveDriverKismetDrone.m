/*
        
        File:			WaveDriverKismetDrone.m
        Program:		KisMAC
		Author:			Geordie Millar
						themacuser@gmail.com
						Contains a lot of code from Kismet - 
						http://kismetwireless.net/
						
		Description:	Scan with a Kismet drone (as opposed to kismet server) in KisMac.
		
		Details:		Tested with kismet_drone 2006.04.R1 on OpenWRT White Russian RC6 on a Diamond Digital R100
						(broadcom mini-PCI card, wrt54g capturesource)
						and kismet_drone 2006.04.R1 on Voyage Linux on a PC Engines WRAP.2E
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

#import "WaveDriverKismetDrone.h"
#import "ImportController.h"
#import "WaveHelper.h"
#import <BIGeneric/BIGeneric.h>

@implementation WaveDriverKismetDrone

+ (enum WaveDriverType) type
{
    return passiveDriver;
}

+ (bool) allowsInjection
{
    return NO;
}

+ (bool) wantsIPAndPort
{
    return YES;
}

+ (bool) allowsChannelHopping
{
    return NO;
}

+ (NSString*) description
{
    return NSLocalizedString(@"Kismet Drone (raw packets), passive mode", "long driver description");
}

+ (NSString*) deviceName
{
    return NSLocalizedString(@"Kismet Drone", "short driver description");
}

#pragma mark -


+ (BOOL)deviceAvailable
{
	return YES;
}


+ (int) initBackend
{
	return YES;
}

+ (bool) loadBackend
{
	return YES;
}

+ (bool) unloadBackend
{
	return YES;
}

#pragma mark -

- (id)init
{
	return self;
}

#pragma mark -

- (unsigned short) getChannelUnCached
{
	return _currentChannel;
}

- (bool) setChannel:(unsigned short)newChannel
{
	_currentChannel = newChannel;
	return YES;
}

- (bool) startCapture:(unsigned short)newChannel
{
    return YES;
}

- (bool) stopCapture
{
	close(drone_fd);
    return YES;
}

#pragma mark -

- (bool) startedScanning
{
	NSUserDefaults *defs = [NSUserDefaults standardUserDefaults];
	const char* hostname = 0;
	unsigned int port = 0;

	int foundhostname = 0;
	int foundport = 0;
	
	NSArray *activeDrivers = [defs objectForKey:@"ActiveDrivers"];
	NSEnumerator *e = [activeDrivers objectEnumerator];
	NSDictionary *drvr;
	
	@try { // todo: not multiple instance safe yet. not a problem currently.
		while ( (drvr = [e nextObject]) ) {
			if ([drvr[@"driverID"] isEqualToString:@"WaveDriverKismetDrone"]) {
				hostname = [drvr[@"kismetserverhost"] UTF8String];
				foundhostname = 1;
				port = [drvr[@"kismetserverport"] intValue];
				foundport = 1;
			}
		}
	}
	@catch (NSException * ex) {
		DBNSLog(@"Exception getting the hostname and port from plist...");
		DBNSLog(@"Error getting host and port!"); 
			NSRunCriticalAlertPanel(NSLocalizedString(@"No host/port set to connect to!", "Error dialog title"),
									NSLocalizedString(@"Check that one is set in the preferences", "LONG desc"),
									OK, nil, nil);
		return nil;
	}

	if (foundhostname + foundport < 2) {
		DBNSLog(@"Error getting the hostname and port from plist...");
		DBNSLog(@"Error getting host and port!"); 
		NSRunCriticalAlertPanel(NSLocalizedString(@"No host/port set to connect to!", "Error dialog title"),
								NSLocalizedString(@"Check that one is set in the preferences", "LONG desc"),
								OK, nil, nil);
		return nil;
	}

	UInt32 ip = inet_addr(hostname);
		
	drone_sock.sin_addr.s_addr = ip;

	memset(&drone_sock, 0, sizeof(drone_sock));
	drone_sock.sin_addr.s_addr = ip;
	drone_sock.sin_family = AF_INET;
	drone_sock.sin_port = htons(port); // option as well
	
	if ((drone_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
        DBNSLog(@"socket() failed %d (%s)\n", errno, strerror(errno));
		NSRunCriticalAlertPanel(NSLocalizedString(@"The connection to the Kismet drone failed", "Error dialog title"),
								@"%s",
								OK, nil, nil, strerror(errno));
		return nil;
    }

	local_sock.sin_family = AF_INET;
    local_sock.sin_addr.s_addr = htonl(INADDR_ANY);
    local_sock.sin_port = htons(0);

    if (bind(drone_fd, (struct sockaddr *) &local_sock, sizeof(local_sock)) < 0)
	{
		DBNSLog(@"bind() failed %d (%s)\n", errno, strerror(errno));
		NSRunCriticalAlertPanel(
		NSLocalizedString(@"The connection to the Kismet drone failed", "Error dialog title"),
								@"%s",
								OK, nil, nil, strerror(errno));
        return NULL;
    }

    // Connect
    if (connect(drone_fd, (struct sockaddr *) &drone_sock, sizeof(drone_sock)) < 0)
	{
		DBNSLog(@"connect() failed %d (%s)\n", errno, strerror(errno));
		NSRunCriticalAlertPanel(NSLocalizedString(@"The connection to the Kismet drone failed", "Error dialog title"),
								@"%s",
								OK, nil, nil, strerror(errno));
		return nil;
    }

    valid = 1;

    resyncs = 0;
    resyncing = 0;
	
    stream_recv_bytes = 0;

	return YES;
}

#pragma mark -

- (KFrame*) nextFrame
{
	KFrame *thisFrame = 0;
	static UInt8 frame[2500];
	thisFrame = (KFrame*)frame;
	
	uint8_t *inbound = 0;
	int ret = 0;
	fd_set rset;
	struct timeval tm;
	unsigned int offset = 0;
	
	int noValidFrame = 1;
	
	while (noValidFrame)
	{
	   if (stream_recv_bytes < sizeof(struct stream_frame_header))
	   {
		   inbound = (uint8_t *) &fhdr;
		   if ((ret = read(drone_fd, &inbound[stream_recv_bytes], (ssize_t) sizeof(struct stream_frame_header) - stream_recv_bytes)) < 0)
		   {
				DBNSLog(@"drone read() error getting frame header %d:%s", errno, strerror(errno));
                NSRunCriticalAlertPanel(NSLocalizedString(@"The connection to the Kismet drone failed", "Error dialog title"),
										@"Drone read() error getting frame header",
										OK, nil, nil);
			}
			stream_recv_bytes += ret;

			if (stream_recv_bytes < sizeof(struct stream_frame_header))
			{
				noValidFrame = 1;
				continue;
			}
			
			// Validate it
			if (ntohl(fhdr.frame_sentinel) != STREAM_SENTINEL) {
				int8_t cmd = STREAM_COMMAND_FLUSH;

				stream_recv_bytes = 0;
				++resyncs;

				if (resyncs > 20) {
				DBNSLog(@"too many resync attempts, something is wrong.");
				NSRunCriticalAlertPanel( NSLocalizedString(@"The connection to the Kismet drone failed", "Error dialog title"),
															@"Resync attempted too many times.",
															OK, nil, nil);
					return NULL;
				}

				if (resyncing == 1)
				{
					noValidFrame = 1;
					continue;
				}

				resyncing = 1;
				
				if (write(drone_fd, &cmd, 1) < 1)
                {
					DBNSLog(@"write() error attempting to flush "
							 "packet stream: %d %s",
							 errno, strerror(errno));
							 
							NSRunCriticalAlertPanel(NSLocalizedString(@"The connection to the Kismet drone failed", "Error dialog title"),
													@"Write error flushing packet stream",
													OK, nil, nil);
				
					return NULL;
				}
			}
		}
		
		////////
		offset = sizeof(struct stream_frame_header);
		if (fhdr.frame_type == STREAM_FTYPE_VERSION && stream_recv_bytes >= offset && stream_recv_bytes < offset + sizeof(struct stream_version_packet))
		{
			inbound = (uint8_t *) &vpkt;
			if ((ret = read(drone_fd, &inbound[stream_recv_bytes - offset], (ssize_t) sizeof(struct stream_version_packet) - (stream_recv_bytes - offset))) < 0)
			{
				DBNSLog(@"drone read() error getting version packet %d:%s", errno, strerror(errno));
				
				NSRunCriticalAlertPanel(NSLocalizedString(@"The connection to the Kismet drone failed", "Error dialog title"),
										@"Read error getting version",
										OK, nil, nil);
				return NULL;
			}
			stream_recv_bytes += ret;

			// Leave if we aren't done
			if ((stream_recv_bytes - offset) < sizeof(struct stream_version_packet))
			{
				noValidFrame = 1;
				continue;
			}

			// Validate
			if (ntohs(vpkt.drone_version) != STREAM_DRONE_VERSION)
			{
				DBNSLog(@"version mismatch:  Drone sending version %d, "
						 "expected %d.", ntohs(vpkt.drone_version), STREAM_DRONE_VERSION);
				NSRunCriticalAlertPanel( NSLocalizedString(@"The connection to the Kismet drone failed", "Error dialog title"),
										@"version mismatch:  Drone sending version %d, expected %d.",
										OK, nil, nil, ntohs(vpkt.drone_version), STREAM_DRONE_VERSION);
				return NULL;
			}

			stream_recv_bytes = 0;

			DBNSLog(@"debug - version packet valid\n\n");
		}

		if (fhdr.frame_type == STREAM_FTYPE_PACKET && stream_recv_bytes >= offset && stream_recv_bytes < offset + sizeof(struct stream_packet_header))
		{
			// Bail if we have a frame header too small for a packet of any sort
			if (ntohl(fhdr.frame_len) <= sizeof(struct stream_packet_header))
			{
				DBNSLog(@"frame too small to hold a packet.");
				NSRunCriticalAlertPanel( NSLocalizedString(@"The connection to the Kismet drone failed", "Error dialog title"),
										@"Frame too small to hold a packet",
										OK, nil, nil, ntohs(vpkt.drone_version), STREAM_DRONE_VERSION);
				return NULL;
			}

			inbound = (uint8_t *) &phdr;
			if ((ret = read(drone_fd, &inbound[stream_recv_bytes - offset], (ssize_t) sizeof(struct stream_packet_header) - (stream_recv_bytes - offset))) < 0) {
				DBNSLog(@"drone read() error getting packet header %d:%s", errno, strerror(errno));
				
				NSRunCriticalAlertPanel(NSLocalizedString(@"The connection to the Kismet drone failed", "Error dialog title"),
										@"drone read() error getting packet header %d:%s",
										OK, nil, nil, errno, strerror(errno));
				return NULL;
			}
			stream_recv_bytes += ret;

			// Leave if we aren't done
			if ((stream_recv_bytes - offset) < sizeof(struct stream_packet_header))
			{
				noValidFrame = 1;
				continue;
			}

			if (ntohs(phdr.drone_version) != STREAM_DRONE_VERSION)
			{
				DBNSLog(@"version mismatch:  Drone sending version %d, expected %d.", ntohs(phdr.drone_version), STREAM_DRONE_VERSION);
				NSRunCriticalAlertPanel(@"The connection to the Kismet drone failed",
										@"version mismatch:  Drone sending version %d, expected %d.",
										OK, nil, nil, ntohs(phdr.drone_version), STREAM_DRONE_VERSION);
				return NULL;
			}

			if (ntohl(phdr.caplen) <= 0 || ntohl(phdr.len) <= 0)
			{
				DBNSLog(@"drone sent us a 0-length packet.");
				NSRunCriticalAlertPanel(NSLocalizedString(@"The connection to the Kismet drone failed", "Error dialog title"),
										@"Drone sent us a zero-length packet",
										OK, nil, nil);
				return NULL;
			}

			if (ntohl(phdr.caplen) > MAX_PACKET_LEN || ntohl(phdr.len) > MAX_PACKET_LEN)
			{
				DBNSLog(@"drone sent us an oversized packet.");
				NSRunCriticalAlertPanel(NSLocalizedString(@"The connection to the Kismet drone failed", "Error dialog title"),
										@"Drone sent us an oversized packet",
										OK, nil, nil);
				return NULL;
			}
			
			// See if we keep looking for more packet pieces
			FD_ZERO(&rset);
			FD_SET(drone_fd, &rset);
			tm.tv_sec = 0;
			tm.tv_usec = 0;

			if (select(drone_fd + 1, &rset, NULL, NULL, &tm) <= 0)
			{
				noValidFrame = 1;
				continue;
			}

		}

		offset = sizeof(struct stream_frame_header) + sizeof(struct stream_packet_header);
		if (fhdr.frame_type == STREAM_FTYPE_PACKET && stream_recv_bytes >= offset)
		{
			unsigned int plen = (uint32_t) ntohl(phdr.len);

			inbound = (uint8_t *) databuf;
			if ((ret = read(drone_fd, &inbound[stream_recv_bytes - offset], (ssize_t) plen - (stream_recv_bytes - offset))) < 0)
			{
				DBNSLog(@"drone read() error getting packet header %d:%s", errno, strerror(errno));
				
				NSRunCriticalAlertPanel(NSLocalizedString(@"The connection to the Kismet drone failed", "Error dialog title"),
										@"drone read() error getting packet header %d:%s",
										OK, nil, nil, errno, strerror(errno));
				return NULL;
			}
			
			stream_recv_bytes += ret;

			if ((stream_recv_bytes - offset) < plen)
			{
				noValidFrame = 1;
				continue;
			}
			
			thisFrame->ctrl.len = (UInt16) ntohl(phdr.caplen);
			thisFrame->ctrl.signal = (UInt8) ntohs(phdr.signal);
			thisFrame->ctrl.channel = (UInt16) phdr.channel;
			thisFrame->ctrl.rate = (UInt8) ntohl(phdr.datarate);
		
			if (thisFrame->ctrl.len > MAX_FRAME_BYTES)
			{ // no buffer overflows please
				thisFrame->ctrl.len = MAX_FRAME_BYTES;
				DBNSLog(@"Captured frame >2500 octets");
			}

			memcpy(thisFrame->data, databuf, thisFrame->ctrl.len);

			noValidFrame = 0;
			stream_recv_bytes = 0;
		
		}
		else
		{
			DBNSLog(@"debug - somehow not a stream packet or too much data...  type %d recv %d\n", fhdr.frame_type, stream_recv_bytes);
		}

		if (fhdr.frame_type != STREAM_FTYPE_PACKET && fhdr.frame_type != STREAM_FTYPE_VERSION)
		{
			// Bail if we don't know the packet type
			DBNSLog(@"unknown frame type %d", fhdr.frame_type);

			// debug
			unsigned int x = 0;
			while (x < sizeof(struct stream_frame_header)) {
				printf("%02X ", ((uint8_t *) &fhdr)[x]);
				++x;
			}
			printf("\n");
			
			return NULL;
		}
	}
	
	return thisFrame; // finally!
}

@end

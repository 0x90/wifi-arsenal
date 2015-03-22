/*
        
        File:			WaveDriverKismet.h
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

#import <Foundation/Foundation.h>
#import "WaveDriver.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


@interface WaveDriverKismet : WaveDriver {
	int fd;
	int sockd;
    struct sockaddr_in serv_name;
    int status;
    struct hostent *hp;
    UInt32 ip;
	int port;
	const char *hostname;
}

+ (int) kismetInstanceCount;
@end

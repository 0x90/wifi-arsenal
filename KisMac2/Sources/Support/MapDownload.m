/*
        
        File:			MapDownload.m
        Program:		KisMAC
	Author:			Michael Rossberg
                                mick@binaervarianz.de
	Description:		KisMAC is a wireless stumbler for MacOS X.
                
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

#import "MapDownload.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <math.h>

#define a_WGS84 6378137
#define b_WGS84 6356752.3142

@implementation MapDownload

+ (MapDownload*)mapDownload {
    return [[MapDownload alloc] init];
}

#pragma mark -

- (NSString*)urlFromExpedia:(NSString*)server language:(NSString*)lang forPoint:(waypoint)w resolution:(NSSize)size zoomLevel:(int)zoom {
    NSString *req = nil, *error = nil;
    int scale;
    float expediaFactorW, expediaFactorH;
    int sockd;
    struct sockaddr_in serv_name;
    char buf[2024];
    int status;
    struct hostent *hp;
    u_long ip;
    int bytesread;
    NSString *s;
    int errcount = 0;
    CFHTTPMessageRef myMessage;
    
    scale = 6 - zoom;
    /*
    req = [NSString stringWithFormat:@"http://%@/pub/agent.dll?qscr=mrdt&CenP=%f,%f&Lang=%@&Alti=%d&MapS=0&Size=%d,%d&Offs=0.000000,0", 
        server, w._lat, w._long, lang, scale, (int)size.width, (int)size.height];
    
    NSDictionary *dic;
    NSHTTPCookieStorage *cookiestore;
    NSHTTPCookie *cookie;
    
    NS_DURING
        cookiestore = [NSHTTPCookieStorage sharedHTTPCookieStorage];
        if (cookiestore) {
            if ([cookiestore cookieAcceptPolicy]==NSHTTPCookieAcceptPolicyNever) {
                DBNSLog(@"Error: Cookies disabled!");
                NSBeginAlertSheet(@"Cookies disabled.",nil,nil,nil,[self window],nil,nil,nil,nil,
                @"The Expedia server requires cookies to be enabled! Since KisMAC uses the same sub-system as Safari, you will need to open it and enable cookies. \
You can also select another server, which does not require cookies. You can also select the \"accept cookies from the site you navigate to\" option \
in Safari.");
                NS_VOIDRETURN;
            }
            dic = [NSDictionary dictionaryWithObjectsAndKeys:@"http://www.expedia.com/", NSHTTPCookieOriginURL, @"jscript", NSHTTPCookieName, @"1", NSHTTPCookieValue, nil];
            cookie = [NSHTTPCookie cookieWithProperties:dic];
            if (cookie) [cookiestore setCookie:cookie];
            else DBNSLog(@"Critical Error: Could not create cookie!");
        } else {
            DBNSLog(@"Error: Cookie Storage unavailable. Operating System needs to be 10.2.6 with Safari 1.0 intalled!");
            NSBeginAlertSheet(@"Invalid Operating System.",nil,nil,nil,[self window],nil,nil,nil,nil,
            @"The Expedia server requires a complete browser system in order to send maps. KisMAC can provide this, however you will need at least a MacOS X 10.2.6 installation, with Safari 1.0 or higher installed!");
            NS_VOIDRETURN;
        }
    NS_HANDLER
        DBNSLog(@"Error: Cookie Storage unavailable. Operating System needs to be 10.2.6 with Safari 1.0 intalled!");
        NSBeginAlertSheet(@"Invalid Operating System.",nil,nil,nil,[self window],nil,nil,nil,nil,
        @"The Expedia server requires a complete browser system in order to send maps. KisMAC can provide this, however you will need at least a MacOS X 10.2.6 installation, with Safari 1.0 or higher installed!");
        return;
    NS_ENDHANDLER*/
                
    sockd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockd == -1) {
        error = @"Socket creation failed!";
		DBNSLog(@"%@",error);
        close(sockd);
		return nil;
    }
    
    hp = gethostbyname([server UTF8String]);
    if (hp == NULL) {
        error = NSLocalizedString(@"Could not resolve expedia server", "Download Map Error");
		DBNSLog(@"%@",error);
        close(sockd);
		return nil;
    }
    ip = *(int *)hp->h_addr_list[0];

    /* server address */ 
    serv_name.sin_family = AF_INET;
    serv_name.sin_addr.s_addr = ip;
    serv_name.sin_port = htons(80);
    
    DBNSLog(@"Connecting to expedia (%s, %lu)",inet_ntoa(serv_name.sin_addr), ip);
    
    /* connect to the server */
    status = connect(sockd, (struct sockaddr*)&serv_name, sizeof(serv_name));
    if (status == -1) {
        error = NSLocalizedString(@"Could not connect to www.expedia.com", "Download Map Error");
		DBNSLog(@"%@",error);
        close(sockd);
		return nil;
    }
        
    s = [NSString stringWithFormat:@"GET /pub/agent.dll?qscr=mrdt&CenP=%f,%f&Lang=%@&Alti=%d&MapS=0&Size=%d,%d&Offs=0.000000,0 HTTP/1.0\nHost: %@\nCookie: jscript=1\nConnection: close\n\n", 
        w._lat, w._long, lang, scale, (int)size.width, (int)size.height, server];

    DBNSLog(@"Sending request to expedia");
    write(sockd, [s UTF8String], [s length]);
    s = [NSString string];
    
    DBNSLog(@"Reading response from expedia");
    
    bytesread = read(sockd, buf, 2024);
	
	bool wasError = false;
    while ((bytesread != -1) && ([s length] < 1100)) {
        if (bytesread==0) {
            ++errcount;
            if (errcount == 60) {
                error = NSLocalizedString(@"Got no response from expedia. Mapsize too big?", "Download Map Error");
                wasError = true;
				break;
            }
            [NSThread sleepUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.5]];
        } else 
        {
            errcount = 0;
            //NULL Terminate
            buf[bytesread] = 0;
            s = [s stringByAppendingString:@(buf)];
        }
        bytesread = read(sockd, buf, 2024);
    }
	
    close(sockd);
	
	if (wasError)
	{
		DBNSLog(@"%@",error);
		return nil;
	}
    
    myMessage = CFHTTPMessageCreateEmpty(kCFAllocatorDefault, FALSE);
    if (!CFHTTPMessageAppendBytes(myMessage, (UInt8*)[s UTF8String], [s length]))
    {
        CFRelease(myMessage);
        error = @"CFTTPResponse Parsing error";
        DBNSLog(@"%@",error);
		return nil;
    }
    
    if (!CFHTTPMessageIsHeaderComplete(myMessage)) 
    {
        CFRelease(myMessage);
        error = @"Incomplete Headers!";
		DBNSLog(@"%@",error);
		return nil;
    }
    
    req = (NSString*)CFBridgingRelease(CFHTTPMessageCopyHeaderFieldValue(myMessage, CFSTR("Location")));
    DBNSLog(@"New location is at %@", req);
        
    switch(scale) {
        case 5:
            expediaFactorH = 15900;
            expediaFactorW = 16030.76934;
            break;
        case 4:
            expediaFactorH = 19900;
            expediaFactorW = 19953.19163;
            break;
        case 3:
            expediaFactorH = 26500;
            expediaFactorW = 26433.71541;
            break;
        case 2:
            expediaFactorH = 39800;
            expediaFactorW = 39703.79291;
            break;
        case 1:
            expediaFactorH = 79600;
            expediaFactorW = 79812.76652;
            break;
        default:
            expediaFactorH = 1;
            expediaFactorW = 1;
            DBNSLog(@"Warning Invalid Zoom Size!");
            NSBeep();
    }
    
    if (expediaFactorW) {
        expediaFactorH *= 2; //for the half map only
        expediaFactorW *= 2; //for the half map only
        
        _p1.x = size.width;
        _p1.y = size.height;
        _p2 = NSZeroPoint;
        _w1._lat  = w._lat  + size.height / expediaFactorH;
        _w1._long = w._long + size.width / (expediaFactorW * cos(_w1._lat * 0.017453292)); //the width depends on latitude
        _w2._lat  = w._lat  - size.height / expediaFactorH;
        _w2._long = w._long - size.width / (expediaFactorW  * cos(_w2._lat * 0.017453292)); //the width depends on latitude
    }
    
    CFRelease(myMessage);
    return req;
}

- (BOOL)downloadMapFrom:(NSString*)server forPoint:(waypoint)w resolution:(NSSize)size zoomLevel:(int)zoom {
    NSString *req;
    int scale,zone;
    float scalef;
       double utme,utmn,K1,K2,K3,K4,K5,p,S,k0,sin1sec,nu,eprimesqd,e,rlat = 0.0,mperdeglat,mperdeglon,numpx,lon0;

    
    if ((int)size.width == 0) { size.width = 1000; }
    if ((int)size.height == 0) { size.height = 1000; }
    if (zoom == 0) { zoom = 3; }
    if ((![server isEqualToString:@"Street-Directory.com.au"]) && (zoom > 5)) zoom = 5;
	
    if (!server) return NO;
    if ((int)size.height < 0 || (int)size.width < 0 || (int)size.height > 10000 || (int)size.width > 10000) return NO;
    if (w._lat > 90 || w._lat < -90 || w._long < -180 || w._long > 180) return NO;
    if (zoom > 7 || zoom < 1) return NO;
    
    _p1.x = size.width / 2.0;
    _p1.y = size.height / 2.0;
    _w1 = w;
    _p2.x = 0;
    _p2.y = 0;
    _w2._lat  = 0;
    _w2._long = 0;

    if ([server isEqualToString:@"TerraServer (Satellite)"]) {
        scale = 16 - zoom;
        req = [NSString stringWithFormat:@"http://terraserver-usa.com/GetImageArea.ashx?t=1&s=%d&lon=%f&lat=%f&w=%d&h=%d", scale, w._long, w._lat, (int)size.width, (int)size.height];
    } else if ([server isEqualToString:@"TerraServer (Map)"]) {
        scale = 16 - zoom;
        req = [NSString stringWithFormat:@"http://terraserver-usa.com/GetImageArea.ashx?t=2&s=%d&lon=%f&lat=%f&w=%d&h=%d", scale, w._long, w._lat, (int)size.width, (int)size.height];
    } else if ([server isEqualToString:@"Expedia (United States)"]) {
        req = [self urlFromExpedia:@"www.expedia.com" language:@"0409USA" forPoint:w resolution:size zoomLevel:zoom];
    } else if ([server isEqualToString:@"Expedia (Europe)"]) {
        req = [self urlFromExpedia:@"www.expedia.de" language:@"EUR0407" forPoint:w resolution:size zoomLevel:zoom];
    } else if ([server isEqualToString:@"Map24"]) {
        size = NSMakeSize(1000,1000);
        req = [NSString stringWithFormat:@"http://maptp.map24.com/map24/cgi?locid0=tmplocid0&wx0=%f&wy0=%f&iw=%d&ih=%d&mid=MAP24", w._long * 60.0, w._lat * 60.0, (int)size.width, (int)size.height];    
  
        _p1.x = size.width;
        _p1.y = size.height;
        _p2 = NSZeroPoint;
        
        //0.017453292 is for degree to rad conversion
        _w1._lat  = w._lat  + size.height / (1040.0 * 2 * 60.0 * cos(w._lat  * 0.017453292));
        _w1._long = w._long + size.width  / (712.0  * 2 * 60.0 * cos(_w1._lat * 0.017453292)); //the width depends on latitude
        _w2._lat  = w._lat  - size.height / (1040.0 * 2 * 60.0 * cos(w._lat  * 0.017453292));
        _w2._long = w._long - size.width  / (712.0  * 2 * 60.0 * cos(_w2._lat * 0.017453292)); //the width depends on latitude
    } else if ([server isEqualToString:@"Census Bureau Maps (United States)"]) {
        scalef = zoom;
        
        req = [NSString stringWithFormat:@"http://tiger.census.gov/cgi-bin/mapper/map.gif?&lat=%f&lon=%f&ht=%f&wid=%f&conf=mapnew.con&iht=%d&iwd=%d",
            w._lat, w._long, 0.065/scalef, 0.180/scalef, (int)size.height, (int)size.width];
    } else if ([server isEqualToString:@"Street-Directory.com.au"]) {
        size = NSMakeSize(1200,1200);
        
        _p1.x = size.width;
        _p1.y = size.height;
        _p2 = NSZeroPoint;

	   numpx = 55;

	   if ((w._lat > -39.52350013) || (w._long < 143.7716731)|| (w._long > 150)) {
	   // use non-Tassie scale factors, lat and long
			   switch (zoom) {
					   case 1:
							   scalef = 106;
							   break;
					   case 2:
							   scalef = 19;
							   numpx = 52.3;
							   break;
					   case 3:
							   scalef = 8;
							   numpx = 55.1;
							   break;
					   case 4:
							   scalef = 2;
							   numpx = 56.7;
							   break;
					   case 5:
							   scalef = 0.3;
							   numpx = 53.1;
							   break;
					   case 6:
							   scalef = 0.15;
							   numpx = 53.1;
							   break;
					   case 7:
							   scalef = 0.075;
							   numpx = 53.3;
							   break;
					   default:
							   scalef= 1;
							   DBNSLog(@"Warning Invalid Zoom Size!");
							   NSBeep();
			   }
			   req = [NSString stringWithFormat:@"http://www.street-directory.com.au/sd_new/genmap.cgi?x=%f&y=%f&sizex=%d&sizey=%d&level=%d&star=&circle=", w._long, w._lat, (int)size.width, (int)size.height, zoom];    
	   } else {
	   // use Tasmania scale factors, eastings and northings (UTM zone 55)
			   switch (zoom) {
					   case 1:
							   scalef = 106;
							   break;
					   case 2:
							   scalef = 15;
							   break;
					   case 3:
							   scalef = 7.5;
							   break;
					   case 4:
							   scalef = 2.4;
							   break;
					   case 5:
							   scalef = 0.489;
							   break;
					   case 6:
							   scalef = 0.244;
							   break;
					   case 7:
							   scalef = 0.136;
							   break;
					   default:
							   scalef= 1;
							   DBNSLog(@"Warning Invalid Zoom Size!");
							   NSBeep();
			   }

			   // code here to convert lat & long to UTM
			   /* formulae taken from http://www.uwgb.edu/dutchs/UsefulData/UTMFormulas.HTM */

			   // figure out zone:
			   if (w._long < 0) zone = floor((w._long + 180)/6)+1;
			   else zone = floor(w._long/6)+31;
			   lon0 = zone * 6 - 183;

			   DBNSLog(@"UTM zone %d, central meridian %d", zone, (int)lon0);

			   e = sqrt(1 - pow(b_WGS84,2)/pow(a_WGS84,2));
			   eprimesqd = pow(e,2)/(1-pow(e,2));

			   S = a_WGS84 * ((1 - pow(e,2)/4 - 3*pow(e,4)/64 - 5*pow(e,6)/LAST_BIT)*rlat - (3*pow(e,2)/8 + 3*pow(e,4)/32 + 45*pow(e,6)/1024)*sin(2*rlat) + (15*pow(e,4)/LAST_BIT + 45*pow(e,6)/1024)*sin(4*rlat) - (35*pow(e,6)/3072)*sin(6*rlat));
			   k0 = 0.9996;
			   K1 = S * k0;
			   p = (w._long - lon0)*3600/10000;

			   sin1sec = M_PI/(180*60*60);
			   nu = a_WGS84/sqrt(1 - pow(e,2) * pow(sin(rlat),2));
			   K2 = k0 * pow(sin1sec,2) * nu * sin(rlat) * cos(rlat)*100000000/2;
			   K3 = k0 * pow(sin1sec,4) * nu * sin(rlat) * pow(cos(rlat),3)/24 * (5 - pow(tan(rlat),2) + 9*eprimesqd*pow(cos(rlat),2) + 4*pow(eprimesqd,2)*pow(cos(rlat),4))*10000000000000000;

			   utmn = K1 + K2*pow(p,2) + K3*pow(p,4);
			   if (w._lat < 0) utmn += 10000000;

			   K4 = k0 * sin1sec * nu * cos(rlat) * 10000;
			   K5 = k0 * pow(sin1sec,3) * nu * pow(cos(rlat),3)/6 * (1 - pow(tan(rlat),2) + eprimesqd * pow(cos(rlat),2)) * 1000000000000;

			   utme = K4*p + K5*pow(p,3) + 500000;

			   // I hope those formulae are right... if not, someone in Tasmania can fix them
			   req = [NSString stringWithFormat:@"http://www.street-directory.com.au/sd_new/tas_genmap.cgi?x=%f&y=%f&sizex=%d&sizey=%d&level=%d&star=&circle=", utme, utmn, (int)size.width, (int)size.height, zoom];    
	   }
	   // scalef now equals number of km in approx 68?? (using numpx) px, and we should have a 1200x1200 map image request ready to go
	   // distance to edge of map = scalef*600/numpx km north AND east
		// at the moment, mperdeglon is not used, but it still makes sense to calculate it since - in theory - it *should* be used
		mperdeglon = M_PI / 180 * (a_WGS84 - (21384*fabs(w._lat)/90)) * cos(rlat);
		mperdeglat = 111132;
	   // degrees to north/south edge from centre = 1000 * scalef * size.height / 2 / numpx / mperdeglat
	   // trying my own conversion... may or may not work well
	   // looks like we may have a square grid in degrees?  doesn't make sense...
        _w1._lat  = w._lat  + 1000 * scalef * size.height / 2 / numpx / mperdeglat;
        _w1._long = w._long + 1000 * scalef * size.width / 2 / numpx / mperdeglat; // should use mperdeglon... but mperdeglat appears to work instead
        _w2._lat  = w._lat  - 1000 * scalef * size.height / 2 / numpx / mperdeglat;
        _w2._long = w._long - 1000 * scalef * size.width / 2 / numpx / mperdeglat; // should use mperdeglon... but mperdeglat appears to work instead
		
		DBNSLog(@"mperdeglon %f, mperdeglat %f, numpx %f",mperdeglon,mperdeglat,numpx);
		DBNSLog(@"Waypoint 1: %f %f",_w1._lat,_w1._long);
		DBNSLog(@"Waypoint 2: %f %f",_w2._lat,_w2._long);
		DBNSLog(@"Center: %f %f",w._lat,w._long);
    } else {
        DBNSLog(@"Invalid server!");
        return NO;
    }

    DBNSLog(@"Loading map from the following location: %@", req);
    
    _img = [[NSImage alloc] initWithContentsOfURL:[NSURL URLWithString:req]];

    DBNSLog(@"Map loaded");
    return _img != nil;
}

#pragma mark -

- (NSPoint)waypoint1Pixel {
    return _p1;
}

- (waypoint)waypoint1 {
    return _w1;
}

- (NSPoint)waypoint2Pixel {
    return _p2;
}

- (waypoint)waypoint2 {
    return _w2;
}

- (NSImage*)map {
    return _img;
}

#pragma mark -


@end

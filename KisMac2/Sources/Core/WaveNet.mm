/*
        
        File:			WaveNet.mm
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

#import <AppKit/NSSound.h>
#import <BIGeneric/BIGeneric.h>
#import "WaveNet.h"
#import "WaveClient.h"
#import "WaveHelper.h"
#import "80211b.h"
#import "WaveNetWPACrack.h"
#import "WaveNetLEAPCrack.h"
#import "WaveScanner.h"
#import "KisMACNotifications.h"
#import "GPSController.h"
#import "NetView.h"
#import "WaveWeakContainer.h"
#import "WaveDriverAirport.h"

#import "GrowlController.h"
#import <CoreWLAN/CoreWLAN.h>

#define WEP_GEM_ORANGE_LEVEL  80000
#define WEP_GEM_GREEN_LEVEL   130000

#define AMOD(x, y) ((x) % (y) < 0 ? ((x) % (y)) + (y) : (x) % (y))

#define min(a, b)	(a) < (b) ? a : b

struct graphStruct zeroGraphData;

struct signalCoords {
	double x, y;
	int strength;
} __attribute__((packed));
		
NSInteger lengthSort(id string1, id string2, void *context)
{
    int v1 = [(NSString*)string1 length];
    int v2 = [(NSString*)string2 length];
    if (v1 < v2)
        return NSOrderedAscending;
    else if (v1 > v2)
        return NSOrderedDescending;
    else
        return NSOrderedSame;
}

@implementation WaveNet

-(id)initWithID:(int)netID {
    waypoint cp;
    GPSController *gpsc;

    self = [super init];
    
    if (!self) return nil;
    
    _dataLock = [[NSRecursiveLock alloc] init];
    [_dataLock lock];
    
	// we should only create a _netView for this network if we have the information to see it
	// check with GPSController if we have a location or not!
	gpsc = [WaveHelper gpsController];
	cp = [gpsc currentPoint];  
    
	if (cp._lat != 100)
    {
        _netView = [[NetView alloc] initWithNetwork:self];
    }
    else
    {
        _netView = nil;
    }
	
    _ID = nil;
	graphData = &zeroGraphData;
	
    // Packet buffers
    _packetsLog=[NSMutableArray arrayWithCapacity:20];
    _ARPLog=[NSMutableArray arrayWithCapacity:20];
    _ACKLog=[NSMutableArray arrayWithCapacity:20];
    
    aClients=[NSMutableDictionary dictionary];
    aClientKeys=[NSMutableArray array];
    aComment=@"";
    aLat = @"";
    aLong = @"";
    aElev = @"";
    _coordinates = [NSMutableDictionary dictionary];
    _netID=netID;

    _gotData = NO;
    recentTraffic = 0;
    curTraffic = 0;
    curPackets = 0;
    _curSignal = 0;
    _channel = 0;
    _primaryChannel = 0;
    curTrafficData = 0;
    curPacketData = 0;
    _rateCount = 0;
	
    _SSID = nil;
    _firstPacket = YES;
    _liveCaptured = NO;
    aFirstDate = [NSDate date];
    
    _challengeResponseStatus = chreNone;

    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(updateSettings:) name:KisMACUserDefaultsChanged object:nil];
    [self updateSettings:nil];
    [_dataLock unlock];
    return self;
}

- (id)initWithCoder:(NSCoder *)coder {
    waypoint wp;
    int bssid[6];
    NSData *data;
        
    if (![coder allowsKeyedCoding]) {
        DBNSLog(@"Cannot decode this way");
        return nil;
    }

    if ([coder decodeObjectForKey:@"aFirstDate"] == nil) {
        DBNSLog(@"Invalid net, dropping!");
        return nil;
    }
    
    self = [self init];
    if (!self) return nil;

    _dataLock = [[NSRecursiveLock alloc] init];
    [_dataLock lock];

	graphData = &zeroGraphData;
    _channel = [coder decodeIntForKey:@"aChannel"];
    _primaryChannel = [coder decodeIntForKey:@"originalChannel"];
    _netID=[coder decodeIntForKey:@"aNetID"];
    _packets=[coder decodeIntForKey:@"aPackets"];
    _maxSignal=[coder decodeIntForKey:@"aMaxSignal"];
    _curSignal=[coder decodeIntForKey:@"aCurSignal"];
    _type=(networkType)[coder decodeIntForKey:@"aType"];
    _isWep = (encryptionType)[coder decodeIntForKey:@"aIsWep"];
    _dataPackets=[coder decodeIntForKey:@"aDataPackets"];
    _mgmtPackets=[coder decodeIntForKey:@"aMgmtPackets"];
    _ctrlPackets=[coder decodeIntForKey:@"aCtrlPackets"];
    _liveCaptured=[coder decodeBoolForKey:@"_liveCaptured"];;
    
    for(int x=0; x<14; ++x)
        _packetsPerChannel[x]=[coder decodeIntForKey:[NSString stringWithFormat:@"_packetsPerChannel%i",x]];
    
    _bytes = [coder decodeDoubleForKey:@"aBytes"];
    wp._lat = [coder decodeDoubleForKey:@"a_Lat"];
    wp._long = [coder decodeDoubleForKey:@"a_Long"];
    wp._elevation = [coder decodeDoubleForKey:@"a_Elev"];
    
    aLat = [coder decodeObjectForKey:@"aLat"];
    aLong = [coder decodeObjectForKey:@"aLong"];
    aElev = [coder decodeObjectForKey:@"aElev"];
    
    _ID=[coder decodeObjectForKey:@"aID"];
    if (_ID!=nil && sscanf([_ID UTF8String], "%2X%2X%2X%2X%2X%2X", &bssid[0], &bssid[1], &bssid[2], &bssid[3], &bssid[4], &bssid[5])!=6) {
        DBNSLog(@"Error could not decode ID %@!", _ID);
    }
    
    for (int x=0; x<6; ++x)
        _rawID[x] = bssid[x];
    
    _SSID=[coder decodeObjectForKey:@"aSSID"];
    _BSSID=[coder decodeObjectForKey:@"aBSSID"];
    if (![_BSSID isEqualToString:@"<no bssid>"]) {
        if (_BSSID!=nil && sscanf([_BSSID UTF8String], "%2X:%2X:%2X:%2X:%2X:%2X", &bssid[0], &bssid[1], &bssid[2], &bssid[3], &bssid[4], &bssid[5])!=6) 
            DBNSLog(@"Error could not decode BSSID %@!", _BSSID);
        for (int x=0; x<6; ++x)
            _rawBSSID[x] = bssid[x];
    } else {
         for (int x=0; x<6; ++x)
            _rawBSSID[x] = bssid[0];
    }
    _date=[coder decodeObjectForKey:@"aDate"];
    aFirstDate=[coder decodeObjectForKey:@"aFirstDate"];
    
    data = [coder decodeObjectForKey:@"ivData0"];
    if (data) _ivData[0] = [[WaveWeakContainer alloc] initWithData:data];
    data = [coder decodeObjectForKey:@"ivData1"];
    if (data) _ivData[1] = [[WaveWeakContainer alloc] initWithData:data];
    data = [coder decodeObjectForKey:@"ivData2"];
    if (data) _ivData[2] = [[WaveWeakContainer alloc] initWithData:data];
    data = [coder decodeObjectForKey:@"ivData3"];
    if (data) _ivData[3] = [[WaveWeakContainer alloc] initWithData:data];
    
    //_packetsLog=[[coder decodeObjectForKey:@"aPacketsLog"] retain];
    //_ARPLog=[[coder decodeObjectForKey:@"aARPLog"] retain]; cannot be used because it is now data
    //_ACKLog=[[coder decodeObjectForKey:@"aACKLog"] retain];
    _password=[coder decodeObjectForKey:@"aPassword"];
    aComment=[coder decodeObjectForKey:@"aComment"];
    _coordinates=[coder decodeObjectForKey:@"_coordinates"];
    
    aClients=[coder decodeObjectForKey:@"aClients"];
    aClientKeys=[coder decodeObjectForKey:@"aClientKeys"];
    
    if (!_packetsLog) _packetsLog=[NSMutableArray arrayWithCapacity:20];
    if (!_ARPLog) _ARPLog=[NSMutableArray arrayWithCapacity:20];
    if (!_ACKLog) _ACKLog=[NSMutableArray arrayWithCapacity:20];
    if (!aClients) aClients=[NSMutableDictionary dictionary];
    if (!aClientKeys) aClientKeys=[NSMutableArray array];
    if (!aComment) aComment=@"";
    if (!aLat) aLat = @"";
    if (!aLong) aLong = @"";
    if (!aElev) aElev = @"";
    if (!_coordinates) _coordinates = [NSMutableDictionary dictionary];
    
    if (_primaryChannel == 0) _primaryChannel = _channel;
    _gotData = NO;
    
    if (wp._long != 100)
    {
		_netView = [[NetView alloc] initWithNetwork:self];
		[_netView setWep:_isWep];
		[_netView setName:_SSID];
		[_netView setCoord:wp];
	}
    else
    {
        _netView = nil;
    }
	
    _firstPacket = NO;
    
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(updateSettings:) name:KisMACUserDefaultsChanged object:nil];
    [self updateSettings:nil];
    [_dataLock unlock];
    return self;
}

- (id)initWithNetstumbler:(const char*)buf andDate:(NSString*)date {
    waypoint wp;
    char ns_dir, ew_dir;
    float ns_coord, ew_coord;
    char ssid[255], temp_bss[8];
    unsigned int hour, min, sec, bssid[6], channelbits = 0, flags = 0;
    int interval = 0;
    
    self = [super init];
    
    if (!self) return nil;
    
    if(sscanf(buf, "%c %f %c %f (%*c%254[^)]) %7s "
    "( %2x:%2x:%2x:%2x:%2x:%2x ) %d:%d:%d (GMT) [ %d %*d %*d ] "
    "# ( %*[^)]) %x %x %d",
    &ns_dir, &ns_coord, &ew_dir, &ew_coord, ssid, temp_bss,
    &bssid[0], &bssid[1], &bssid[2], &bssid[3], &bssid[4], &bssid[5],
    &hour, &min, &sec,
    &_maxSignal,
    &flags, &channelbits, &interval) < 9) {
        DBNSLog(@"line in backup file is corrupt or not compatible");
        return nil;
    }

    if(ssid[strlen(ssid) - 1] == ' ') ssid[strlen(ssid) - 1] = '\0';

    _dataLock = [[NSRecursiveLock alloc] init];
    [_dataLock lock];
    
	graphData = &zeroGraphData;
	
    if (strcmp(temp_bss, "IBSS") == 0)          _type = networkTypeAdHoc;
    else if (strcmp(temp_bss, "ad-hoc") == 0)   _type = networkTypeAdHoc;
    else if (strcmp(temp_bss, "BSS") == 0)      _type = networkTypeManaged;
    else if (strcmp(temp_bss, "TUNNEL") == 0)   _type = networkTypeTunnel;
    else if (strcmp(temp_bss, "PROBE") == 0)    _type = networkTypeProbe;
    else if (strcmp(temp_bss, "LTUNNEL") == 0)  _type = networkTypeLucentTunnel;
    else _type = networkTypeUnknown;

    _isWep = (flags & 0x0010) ? encryptionTypeWEP : encryptionTypeNone;

    _date = [NSDate dateWithString:[NSString stringWithFormat:@"%@ %.2d:%.2d:%.2d +0000", date, hour, min, sec]];
    aFirstDate = _date;
    
    aLat  = [NSString stringWithFormat:@"%f%c", ns_coord, ns_dir];
    aLong = [NSString stringWithFormat:@"%f%c", ew_coord, ew_dir];
    _SSID = @(ssid);

    _ID = [NSString stringWithFormat:@"%2X%2X%2X%2X%2X%2X", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]];
    _BSSID = [NSString stringWithFormat:@"%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]];
    for (int x=0; x<6; ++x)
        _rawID[x] = bssid[x];
    
    wp._lat  = ns_coord * (ns_dir == 'N' ? 1.0 : -1.0);
    wp._long = ew_coord * (ew_dir == 'E' ? 1.0 : -1.0);
    wp._elevation = 0;

	if (!(wp._long == 100 || (wp._lat == 0 && wp._long == 0))) 
    {
		_netView = [[NetView alloc] initWithNetwork:self];
		[_netView setWep:_isWep];
		[_netView setName:_SSID];
		[_netView setCoord:wp];
	}
    else
    {
        _netView = nil;
    }
	
    _packetsLog = [NSMutableArray arrayWithCapacity:20];
    _ARPLog  = [NSMutableArray arrayWithCapacity:20];
    _ACKLog  = [NSMutableArray arrayWithCapacity:20];
    aClients = [NSMutableDictionary dictionary];
    aClientKeys = [NSMutableArray array];
    aComment = @"";
    aElev = @"";
    _coordinates = [NSMutableDictionary dictionary];
    _netID = 0;
	
    _gotData = NO;
    _liveCaptured = NO;
    recentTraffic = 0;
    curTraffic = 0;
    curPackets = 0;
    _curSignal = 0;
    curTrafficData = 0;
    curPacketData = 0;
        
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(updateSettings:) name:KisMACUserDefaultsChanged object:nil];
    [self updateSettings:nil];
    [_dataLock unlock];
    return self;
}

- (id)initWithDataDictionary:(NSDictionary*)dict {
    waypoint wp;
    char ns_dir, ew_dir;
    int bssid[6];
    NSData *data;
    NSMutableDictionary *clients;
	
	NSParameterAssert(dict);
	
	if (dict[@"ID"] == nil) {
        DBNSLog(@"Invalid net, dropping!");
        return nil;
    }
    
    self = [self init];
    if (!self) return nil;

    _dataLock = [[NSRecursiveLock alloc] init];
    [_dataLock lock];
	
	graphData = &zeroGraphData;
	
    _channel = [dict[@"channel"] intValue];
    _primaryChannel = [dict[@"originalChannel"] intValue];
    _netID = [dict[@"netID"] intValue];
    _packets = [dict[@"packets"] intValue];
    _maxSignal = [dict[@"maxSignal"] intValue];
    _curSignal = [dict[@"curSignal"] intValue];
    _type = (networkType)[dict[@"type"] intValue];
    _isWep = (encryptionType)[dict[@"encryption"] intValue];
    _dataPackets = [dict[@"dataPackets"] intValue];
    _mgmtPackets = [dict[@"mgmtPackets"] intValue];
    _ctrlPackets = [dict[@"ctrlPackets"] intValue];
    _liveCaptured = [dict[@"liveCaptured"] boolValue];
    
	for(int x=0; x<14; ++x)
        _packetsPerChannel[x] = [dict[@"packetsPerChannel"][[NSString stringWithFormat:@"%.2i",x]] intValue];
    
    _bytes = [dict[@"bytes"] doubleValue];
    wp._lat = [dict[@"lat"] doubleValue];
    wp._long = [dict[@"long"] doubleValue];
    wp._elevation = [dict[@"elev"] doubleValue];
    
    (wp._lat < 0) ? ns_dir = 'S' :  ns_dir = 'N';
    (wp._lat < 0) ? ew_dir = 'W' :  ew_dir = 'E';
    
    _ID=dict[@"ID"];
    if (_ID!=nil && sscanf([_ID UTF8String], "%2X%2X%2X%2X%2X%2X", &bssid[0], &bssid[1], &bssid[2], &bssid[3], &bssid[4], &bssid[5])!=6) {
        DBNSLog(@"Error could not decode ID %@!", _ID);
    }
    
    for (int x=0; x<6; ++x)
        _rawID[x] = bssid[x];
    
    _SSID  = dict[@"SSID"];
    _SSIDs = dict[@"SSIDs"];
    _BSSID=dict[@"BSSID"];
    if (![_BSSID isEqualToString:@"<no bssid>"]) {
        if (_BSSID!=nil && sscanf([_BSSID UTF8String], "%2X:%2X:%2X:%2X:%2X:%2X", &bssid[0], &bssid[1], &bssid[2], &bssid[3], &bssid[4], &bssid[5])!=6) 
            DBNSLog(@"Error could not decode BSSID %@!", _BSSID);
        for (int x=0; x<6; ++x)
            _rawBSSID[x] = bssid[x];
    } else {
         for (int x=0; x<6; ++x)
            _rawBSSID[x] = bssid[0];
    }
    _date=dict[@"date"];
    aFirstDate = dict[@"firstDate"];
    
	data = dict[@"rates"];
	_rateCount = min([data length], MAX_RATE_COUNT);
	[data getBytes:_rates length:_rateCount];
	
    data = dict[@"ivData0"];
    if (data) _ivData[0] = [[WaveWeakContainer alloc] initWithData:data];
    data = dict[@"ivData1"];
    if (data) _ivData[1] = [[WaveWeakContainer alloc] initWithData:data];
    data = dict[@"ivData2"];
    if (data) _ivData[2] = [[WaveWeakContainer alloc] initWithData:data];
    data = dict[@"ivData3"];
    if (data) _ivData[3] = [[WaveWeakContainer alloc] initWithData:data];
    
    _packetsLog = [dict[@"packetsLog"] mutableCopy];
    if (!_packetsLog) _packetsLog = [NSMutableArray arrayWithCapacity:20];
    _ARPLog = [dict[@"ARPLog"] mutableCopy];
    if (!_ARPLog) _ARPLog = [NSMutableArray arrayWithCapacity:100];
    _ACKLog = [dict[@"ACKLog"] mutableCopy];
    if (!_ACKLog) _ACKLog = [NSMutableArray arrayWithCapacity:20];
    aClientKeys = [dict[@"clientKeys"] mutableCopy];
    clients = dict[@"clients"];
	if (!clients) aClients = [NSMutableDictionary dictionary];
    else {
		NSString *c;
		aClients = [NSMutableDictionary dictionaryWithCapacity:[clients count]];
		NSEnumerator *e = [clients keyEnumerator];
		
		while ((c = [e nextObject])) {
			aClients[c] = [[WaveClient alloc] initWithDataDictionary:clients[c]];
		}
		aClientKeys = [[aClients allKeys] mutableCopy];
	}
    
	_password = dict[@"password"];
    
	aComment = dict[@"comment"];
    if (!aComment) aComment = @"";
    aLat = dict[@"latString"];
    if (!aLat) aLat = [NSString stringWithFormat:@"%f%c", wp._lat, ns_dir];
    aLong = dict[@"longString"];
    if (!aLong) aLong = [NSString stringWithFormat:@"%f%c", wp._long, ew_dir];
    aElev = dict[@"elevString"];
    if (!aElev) aElev = [NSString stringWithFormat:@"%.1f", (wp._elevation * 3.2808399)];
    
	_coordinates = dict[@"coordinates"];
    if (!_coordinates) _coordinates = [NSMutableDictionary dictionary];
    else {
		NSData *d;
		BIValuePair *vp;
		
		d = (NSData*)_coordinates;
		_coordinates = [NSMutableDictionary dictionary];
		const struct signalCoords *pL;
		
		if ([d length] % sizeof(struct signalCoords) == 0) {
			pL = (const struct signalCoords *)[d bytes];
		
			for (unsigned int i = 0; i < ([d length] / sizeof(struct signalCoords)); ++i) {
				vp = [BIValuePair new];
				[vp setPairX:pL->x Y:pL->y];
				_coordinates[vp] = @(pL->strength);
				++pL;
			}
		}
	}

    if (_primaryChannel == 0) _primaryChannel = _channel;
    _gotData = NO;
    
	if(wp._long != 100)
    {
		_netView = [[NetView alloc] initWithNetwork:self];
		[_netView setWep:_isWep];
		[_netView setName:_SSID];
		[_netView setCoord:wp];
	}
    else
    {
        _netView = nil;
    }
	
    _firstPacket = NO;
    
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(updateSettings:) name:KisMACUserDefaultsChanged object:nil];
    [self updateSettings:nil];
    [_dataLock unlock];
    return self;
}

- (NSDictionary*)dataDictionary {
    waypoint wp;
	NSMutableDictionary *dict;
	NSMutableData *coord = nil;
	NSMutableDictionary *clients = nil;
	NSMutableDictionary *packetsPerChannel = nil;
	
	[_dataLock lock];
	
	if ([_coordinates count])
    {
		BIValuePair *vp;
		struct signalCoords *pL;
		
		coord = [NSMutableData dataWithLength:[_coordinates count] * sizeof(struct signalCoords)];
		pL = (struct signalCoords *)[coord mutableBytes];
		NSEnumerator *e = [_coordinates keyEnumerator];
		
		while ((vp = [e nextObject])) {
			pL->strength = [_coordinates[vp] intValue];
			pL->x = [vp getX];
			pL->y = [vp getY];
			++pL;
		}
	}
	
	if ([aClients count]) {
		NSString *c;
		clients = [NSMutableDictionary dictionaryWithCapacity:[aClients count]];
		NSEnumerator *e = [aClients keyEnumerator];
		
		while ((c = [e nextObject]) != nil) {
			clients[c] = [aClients[c] dataDictionary];
		}
	}

	if (_packets) {
		packetsPerChannel = [NSMutableDictionary dictionary];
		for (int i = 0; i <14; ++i) {
			if (_packetsPerChannel[i]) {
				packetsPerChannel[[NSString stringWithFormat:@"%.2u", i]] = @(_packetsPerChannel[i]);
			}
		}
	}

	dict = [NSMutableDictionary dictionary];
	
	dict[@"maxSignal"] = @(_maxSignal);
	if (_curSignal > 0)  dict[@"curSignal"] = @(_curSignal);
	dict[@"type"] = [NSNumber numberWithInt:_type];
	dict[@"encryption"] = [NSNumber numberWithInt:_isWep];
	if (_packets > 0)  dict[@"packets"] = @(_packets);
	if (_dataPackets > 0)  dict[@"dataPackets"] = @(_dataPackets);
	if (_mgmtPackets > 0)  dict[@"mgmtPackets"] = @(_mgmtPackets);
	if (_ctrlPackets > 0)  dict[@"ctrlPackets"] = @(_ctrlPackets);
	dict[@"channel"] = @(_channel);
	dict[@"originalChannel"] = @(_primaryChannel);
	dict[@"netID"] = @(_netID);
	
	dict[@"liveCaptured"] = @(_liveCaptured);
	if (_bytes > 0) dict[@"bytes"] = @(_bytes);
	
	if (_rateCount) dict[@"rates"] = [NSData dataWithBytes:_rates length:_rateCount];
	
    if(nil != _netView)
    {
        wp = [_netView coord];
        if (wp._lat != 0) dict[@"lat"] = [NSNumber numberWithFloat:wp._lat];
        if (wp._long != 0) dict[@"long"] = [NSNumber numberWithFloat:wp._long];
        if (wp._elevation != 0) dict[@"elev"] = [NSNumber numberWithFloat:wp._elevation];
    }
	
	if (aLat  && [aLat  length]>0) dict[@"latString"] = aLat;
	if (aLong && [aLong length]>0) dict[@"longString"] = aLong;
	if (aElev && [aElev length]>0) dict[@"elevString"] = aElev;
	
	if (_ID) dict[@"ID"] = _ID;
	if (aFirstDate) dict[@"firstDate"] = aFirstDate;
	if (_SSID)  dict[@"SSID"] = _SSID;
	if (_SSIDs) dict[@"SSIDs"] = _SSIDs;
	if (_BSSID) dict[@"BSSID"] = _BSSID;
	if (_date)  dict[@"date"] = _date;
	if (_ivData[0])  dict[@"ivData0"] = [_ivData[0] data];
	if (_ivData[1])  dict[@"ivData1"] = [_ivData[1] data];
	if (_ivData[2])  dict[@"ivData2"] = [_ivData[2] data];
	if (_ivData[3])  dict[@"ivData3"] = [_ivData[3] data];
	if (_packetsLog && [_packetsLog count] > 0) dict[@"packetsLog"] = _packetsLog;
	if (_ARPLog && [_ARPLog count] > 0) dict[@"ARPLog"] = _ARPLog;
	if (_ACKLog && [_ACKLog count] > 0) dict[@"ACKLog"] = _ACKLog;
	if (_password)   dict[@"password"] = _password;
	if (aComment && [aComment length] > 0) dict[@"comment"] = aComment;
	
	if (clients) dict[@"clients"] = clients;
	if (coord) dict[@"coordinates"] = coord;
	if (packetsPerChannel) dict[@"packetsPerChannel"] = packetsPerChannel;
	
	[_dataLock unlock];

	return dict;
}

- (void)updateSettings:(NSNotification*)note {
    NSUserDefaults *sets = [NSUserDefaults standardUserDefaults];
    
    _avgTime = [[sets objectForKey:@"WaveNetAvgTime"]  intValue];
}

#pragma mark -

- (void)updateSSID:(NSString*)newSSID withSound:(bool)sound {
    int lVoice;
    NSString *lSentence;
    NSString *oc;
    const char *pc;
    unsigned int i;
    bool isHidden = YES;
    bool updatedSSID;
    
    if (newSSID==nil || [newSSID isEqualToString:_SSID]) return;

	pc = [newSSID UTF8String];
	for (i = 0; i < [newSSID length]; ++i) {
		if (pc[i]) {
			isHidden = NO;
			break;
		}
	}
	if ([newSSID length]==1 && pc[i]==32) isHidden = YES;
	
	if (!_SSID) updatedSSID = NO;
	else updatedSSID = YES;
	
	if (isHidden) {
		if (_SSID!=nil) return; //we might have the real ssid already
		_SSID = @"";
	} else {
		_SSID = newSSID;
		if (updatedSSID) {
			[GrowlController notifyGrowlSSIDRevealed:@"" BSSID:_BSSID SSID:newSSID];
		}
	}

    if(nil != _netView)
    {
        [_netView setName:_SSID];
    }
    
	if (!_firstPacket) [[NSNotificationCenter defaultCenter] postNotificationName:KisMACViewItemChanged object:self];

	if (updatedSSID) return;
	
	if (sound) {
		lVoice=[[NSUserDefaults standardUserDefaults] integerForKey:@"Voice"];
		if (lVoice) {
			switch(_isWep) {
				case encryptionTypeNone: 
						oc = NSLocalizedString(@"open", "for speech");
						break;
				case encryptionTypeWEP:
				case encryptionTypeWEP40:
				case encryptionTypeWPA:
				case encryptionTypeWPA2:
						oc = NSLocalizedString(@"closed", "for speech");
						break;
				default: oc=@"";
			}
			lSentence=[NSString stringWithFormat: NSLocalizedString(@"found %@ network. SSID is %@", "this is for speech output"),
				oc, isHidden ? NSLocalizedString(@"hidden", "for speech"): [_SSID uppercaseString]];
			NS_DURING
				[WaveHelper speakSentence:(__bridge CFStringRef)(lSentence) withVoice:lVoice];
			NS_HANDLER
			NS_ENDHANDLER
		}
	}
}

- (void)generalEncounterStuff:(bool)onlineCapture {
    waypoint cp;
    GPSController *gpsc;
    BIValuePair *pV;
    NSNumber *v;
    NSString *s;
    
    //lock the data while we are modifying it as the GUI thread reads this
    //data frequently
    @synchronized(self)
    {
        if (onlineCapture) {
            gpsc = [WaveHelper gpsController];
            cp = [gpsc currentPoint];    
            //after the first packet we should play some sound 
            if (_date == nil)
            {
                if (cp._lat != 100) 
                {
                    // we have a new network with a GPS position - initialise _netView
                    _netView = [[NetView alloc] initWithNetwork:self];
                    [_netView setWep:_isWep];
                    if (_SSID==nil) [_netView setName:_BSSID]; // use BSSID for map label
                    else [_netView setName:_SSID];
                    [_netView setCoord:cp];
                }
                            
                if (_isWep >= encryptionTypeWEP) [[NSSound soundNamed:[[NSUserDefaults standardUserDefaults] objectForKey:@"WEPSound"]] play];
                else [[NSSound soundNamed:[[NSUserDefaults standardUserDefaults] objectForKey:@"noWEPSound"]] play];
                
                if (_isWep == encryptionTypeUnknown) [GrowlController notifyGrowlProbeRequest:@"" BSSID:_BSSID signal:_curSignal];
                if (_isWep == encryptionTypeNone) [GrowlController notifyGrowlOpenNetwork:@"" SSID:_SSID BSSID:_BSSID signal:_curSignal channel:_channel];
                if (_isWep == encryptionTypeWEP) [GrowlController notifyGrowlWEPNetwork:@"" SSID:_SSID BSSID:_BSSID signal:_curSignal channel:_channel];
                if (_isWep == encryptionTypeWEP40) [GrowlController notifyGrowlWEPNetwork:@"" SSID:_SSID BSSID:_BSSID signal:_curSignal channel:_channel];
                if (_isWep == encryptionTypeWPA) [GrowlController notifyGrowlWPANetwork:@"" SSID:_SSID BSSID:_BSSID signal:_curSignal channel:_channel];
                if (_isWep == encryptionTypeWPA2) [GrowlController notifyGrowlWPANetwork:@"" SSID:_SSID BSSID:_BSSID signal:_curSignal channel:_channel];
                if (_isWep == encryptionTypeLEAP) [GrowlController notifyGrowlLEAPNetwork:@"" SSID:_SSID BSSID:_BSSID signal:_curSignal channel:_channel];
            } else if (_SSID != nil && ([_date timeIntervalSinceNow] < -120.0)) {
                int lVoice=[[NSUserDefaults standardUserDefaults] integerForKey:@"Voice"];
                if (lVoice) {
                    NSString * lSentence = [NSString stringWithFormat: NSLocalizedString(@"Reencountered network. SSID is %@", "this is for speech output"),
                        [_SSID length] == 0 ? NSLocalizedString(@"hidden", "for speech"): [_SSID uppercaseString]];
                    NS_DURING
                        [WaveHelper speakSentence:(__bridge CFStringRef)(lSentence) withVoice:lVoice];
                    NS_HANDLER
                    NS_ENDHANDLER
                }
            }
            
			_date = [NSDate date];

            if (cp._lat!=100) {
                pV = [BIValuePair new];
                [pV setPairFromWaypoint:cp];
                v = _coordinates[pV];
                if ((v==nil) || ([v intValue]<_curSignal))
                    _coordinates[pV] = @(_curSignal);
                if(_curSignal>=_maxSignal || ([aLat floatValue] == 0)) 
                {
                    if(nil == _netView) 
                    {
                        // we didn't have a GPS position when this was first found, so initialise _netView now
                        DBNSLog(@"First GPS fix for net %@ - initialising",_BSSID);
                        _netView = [[NetView alloc] initWithNetwork:self];
                        [_netView setWep:_isWep];
                        if (_SSID==nil) [_netView setName:_BSSID]; // use BSSID for map label
                        else [_netView setName:_SSID];
                    }
                    gpsc = [WaveHelper gpsController];
                    s = [gpsc NSCoord];
                    if (s) aLat = s;
                    s = [gpsc EWCoord];
                    if (s) aLong = s;
                    s = [gpsc ElevCoord];
                    if (s) aElev = s;
                    [_netView setCoord:cp];
                }
            }
        }
        
        if(_curSignal>=_maxSignal) _maxSignal=_curSignal;
        
        if (!_liveCaptured) _liveCaptured = onlineCapture;
        _gotData = onlineCapture;
    }
}

- (void) mergeWithNet:(WaveNet*)net {
    int temp;
    networkType tempType;
    encryptionType encType;
    int* p;
    
    temp = [net maxSignal];
    if (_maxSignal < temp) {
        _maxSignal = temp;
		aLat = [net latitude];
		aLong = [net longitude];
		aElev = [net elevation];
    }
    
    if ([_date compare:[net lastSeenDate]] == NSOrderedDescending) {
        _curSignal = [net curSignal];
        
        if ([net channel]) _channel = [net channel];
        _primaryChannel = [net originalChannel];
        
        tempType = [net type];
        if (tempType != networkTypeUnknown) _type = tempType;
        
        encType = [net wep];
        if (encType != encryptionTypeUnknown) _isWep = encType;
        
        temp = [net channel];
        if (temp) _channel = temp;
        
        if ([net rawSSID]) [self updateSSID:[net rawSSID] withSound:NO];
        if ([net SSIDs]) _SSIDs = [net SSIDs];
		
		_date = [net lastSeenDate];
        if (![[net comment] isEqualToString:@""]) aComment = [net comment];
    }
    
    if ([aFirstDate compare:[net firstSeenDate]] == NSOrderedAscending) aFirstDate = [net firstSeenDate];
	
    _packets +=     [net packets];
    _dataPackets += [net dataPackets];
    _mgmtPackets += [net mgmtPackets];
    _ctrlPackets += [net ctrlPackets];
    
    if (!_liveCaptured) _liveCaptured = [net liveCaptured];
    
    p = [net packetsPerChannel];
    for(int x=0;x<14;++x) {
        _packetsPerChannel[x] += p[x];
        if (_packetsPerChannel[x] == p[x]) //the net we merge with has some channel, we did not know about
            [[NSNotificationCenter defaultCenter] postNotificationName:KisMACViewItemChanged object:self];
    }
    
    _bytes += [net dataCount];
    
    [_dataLock lock];
    
    [WaveHelper addDictionary:[net coordinates] toDictionary:_coordinates];
    
    //add all those unique ivs to the log file
    WaveWeakContainer * __strong *ivData = [net ivData];
    if (_ivData[0]) [_ivData[0] addData:[ivData[0] data]];
    else _ivData[0] = [[WaveWeakContainer alloc] initWithData:[ivData[0] data]];
    if (_ivData[1]) [_ivData[1] addData:[ivData[1] data]];
    else _ivData[1] = [[WaveWeakContainer alloc] initWithData:[ivData[1] data]];
    if (_ivData[2]) [_ivData[2] addData:[ivData[2] data]];
    else _ivData[2] = [[WaveWeakContainer alloc] initWithData:[ivData[2] data]];
    if (_ivData[3]) [_ivData[3] addData:[ivData[3] data]];
    else _ivData[3] = [[WaveWeakContainer alloc] initWithData:[ivData[3] data]];
    
    [_packetsLog addObjectsFromArray:[net cryptedPacketsLog]];
    //sort them so that the smallest packet is in front of the array => faster cracking
    [_packetsLog sortUsingFunction:lengthSort context:nil];
    [_dataLock unlock];
}

- (void)parsePacket:(WavePacket*) w withSound:(bool)sound {
    NSString *clientid;
    WaveClient *lWCl;
    encryptionType wep;
    unsigned int bodyLength;
    UInt8 *body;
    
    // Invalidate cache
    _cacheValid = NO;

    // Update global packets count
    ++_packets;
    
    // Update global bytes count
    _bytes+=[w length];
	
    // If we doesn't have an ID already, try to update
    if (!_ID) {
        _ID = [w IDString];
        [w ID:_rawID];
    }
    
    // Set current signal (Perhaps we need to differentiate AP from clients in the future?)
    _curSignal = [w signal];
    
    // Set current channel
    _channel=[w channel];
    
    if ((_packetsPerChannel[_channel]==0) && (!_firstPacket))
        [[NSNotificationCenter defaultCenter] postNotificationName:KisMACViewItemChanged object:self];
    _packetsPerChannel[_channel]++;

    //statistical data for the traffic view
    if (sound) {
		if (!_graphInit) {
			graphData = new (struct graphStruct);
			_graphInit = YES;
			memset(graphData, 0, sizeof(struct graphStruct));
		}
        graphData->trafficData[graphLength] += [w length];
        graphData->packetData[graphLength] += 1;
        curSignalData += _curSignal;
        ++curPacketData;
        curTrafficData += [w length];
    }

    if (_BSSID == nil) {
        _BSSID = [NSString stringWithString:[w BSSIDString]];
        [w BSSID:_rawBSSID];
    }
    
    wep = [w wep];
    if (wep != encryptionTypeUnknown) 
    {
        if( (_isWep < wep) ||
            (([w type] == IEEE80211_TYPE_MGT) &&
             (wep != encryptionTypeUnknown) &&
             (_isWep != wep) &&
             (_isWep != encryptionTypeLEAP)) )
        {
            _isWep = wep;	//check if wep is enabled
            if(_netView != nil)
            {
                [_netView setWep:_isWep];
            }
        }
    }
    if ([w netType]) _type = [w netType];	//gets the type of network
    
    [_dataLock lock];
    body = [w payload];
    bodyLength = [w payloadLength];
    
    //do some special parsing depending on the packet type
    switch ([w type]) {
        case IEEE80211_TYPE_DATA: //Data frame                     
            ++_dataPackets;
            if (_isWep > encryptionTypeNone && bodyLength > 3)
                memcpy(_IV, body, 3);	//sets the last IV thingy
            
            if (_isWep==encryptionTypeWEP || _isWep==encryptionTypeWEP40) {
                
                if( (bodyLength > 10) && (bodyLength < MAX_FRAME_BYTES) )
                { //needs to have a fcs, an iv and two bytes of data at least
                    
                    //this packet might be interesting for password checking, use the packet if we do not have enough, or f it is smaller than our smallest
                    if ([_packetsLog count]<20 || [(NSString*)_packetsLog[0] length] > bodyLength) {
                        [_packetsLog addObject:[NSData dataWithBytes:body length:bodyLength]];
                        //sort them so that the smallest packet is in front of the array => faster cracking
                        [_packetsLog sortUsingFunction:lengthSort context:nil];
                    }

                    //log those packets for reinjection attack
                    if (bodyLength == ARP_SIZE || bodyLength == ARP_SIZE_PADDING) {
//						DBNSLog(@"ARP PACKET");
                        if ([[w stringReceiverID] isEqualToString:@"FF:FF:FF:FF:FF:FF"]) {
                            [_ARPLog addObject:[NSData dataWithBytes:[w frame] length:[w length]]];
							if ([_ARPLog count] > 100) {
                                [_ARPLog removeObjectAtIndex:0];
                            }
						}
                    }
//                    if (([_ACKLog count]<20)&&((bodyLength>=TCPACK_MIN_SIZE)||(bodyLength<=TCPACK_MAX_SIZE))) {
//						DBNSLog(@"ACK PACKET");
//                        [_ACKLog addObject:[NSData dataWithBytes:[w frame] length:[w length]]];
//                    }
                    
                    if (body[3] <= 3) { //record the IV for a later weak key attack
                        if (_ivData[body[3]] == nil) {
							_ivData[body[3]] = [[WaveWeakContainer alloc] init];
							NSAssert(_ivData[body[3]], @"unable to allocate weak container");
						}
                        @synchronized (_ivData[body[3]]) {
                            [_ivData[body[3]] setBytes:&body[4] forIV:&body[0]];
                        }
                    }
                }
            }
            break;
        case IEEE80211_TYPE_MGT:        //this is a management packet
            ++_mgmtPackets;
			if ([w SSIDs])
			{
				_SSIDs = [w SSIDs];
			}
			[self updateSSID:[w SSID] withSound:sound]; //might contain SSID infos
            
			if ([w primaryChannel])
				_primaryChannel = [w primaryChannel];
			switch ([w subType]) {
				case IEEE80211_SUBTYPE_BEACON:
					_rateCount = [w getRates:_rates];
					break;
				case IEEE80211_SUBTYPE_AUTH:
					DBNSLog(@"Authentication Frame");
					_authState = 0;
					switch (_authState) {
						case 0:
							switch (((Ieee80211_Auth_Frame *)[w frame])->wi_algo) {
								case 0x00:
									DBNSLog(@"Auth Type Open for net %@", [w BSSIDString]);
                                    break;
								case 0x01:
									DBNSLog(@"Auth Type Shared-Key %@", [w BSSIDString]);
                                    break;
								default:
									break;
							}
							break;
						case 1:
							break;
						case 2:
							break;
						case 3:
							break;
					}
					break;
			}
            break;
        case IEEE80211_TYPE_CTL:
            ++_ctrlPackets;
            break;
    }

    // Update client info (Incoming and Outgoing)
    // If it doesn't exists, we will create it
    
    clientid = [w stringReceiverID];
    if (clientid != nil) {
        lWCl = aClients[clientid];
        if (lWCl == nil) {
            lWCl = [[WaveClient alloc] init];
            aClients[clientid] = lWCl;
            [aClientKeys addObject:clientid];  
        }
        [lWCl parseFrameAsIncoming:w];
    }
    clientid = [w stringSenderID];
    if (clientid != nil) {
        lWCl=aClients[clientid];
        if (lWCl == nil) {
            lWCl = [[WaveClient alloc] init];
            aClients[clientid] = lWCl;
            [aClientKeys addObject:clientid];
        }
        [lWCl parseFrameAsOutgoing:w];
    }
    
    // Set WPA challenge/response status
    if (_challengeResponseStatus != chreComplete && [lWCl eapolDataAvailable] ) {
        _challengeResponseStatus = chreComplete;
    }
    
    [self generalEncounterStuff:sound];
    
    if (_firstPacket) {
        [[NSNotificationCenter defaultCenter] postNotificationName:KisMACViewItemChanged object:self];
        _firstPacket = NO;
    }
    
    [_dataLock unlock];
}

- (void)parseAppleAPIData:(CWNetwork*)info
{
    encryptionType wep;
    const char *mac;
	
	NSParameterAssert(info);
	
	_cacheValid = NO;
	
    if (!_ID) {
		unsigned char macData[6] = {0};
		
		// [CWInterface bssid] returns a string formatted "00:00:00:00:00:00".
		NSString* macString = [info bssid];
		if (macString && ([macString length] == 17)) {
			for (NSUInteger i = 0; i < 6; ++i) {
				NSString* part = [macString substringWithRange:NSMakeRange(i * 3, 2)];
				NSScanner* scanner = [NSScanner scannerWithString:part];
				unsigned int data = 0;
				if (![scanner scanHexInt:&data]) {
					data = 0;
				}
				macData[i] = (unsigned char) data;
			}
		}
        mac = (const char*)macData;
		//NSAssert([[info objectForKey:@"BSSID"] length] == 6, @"BSSID length is not 6");
        memcpy(_rawID, mac, 6);
		memcpy(_rawBSSID, mac, 6);

        _ID = [NSString stringWithFormat:@"%.2X%.2X%.2X%.2X%.2X%.2X", _rawID[0], _rawID[1], _rawID[2],
                _rawID[3], _rawID[4], _rawID[5]];
        _BSSID = [NSString stringWithFormat:@"%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", _rawBSSID[0], _rawBSSID[1], _rawBSSID[2],
                _rawBSSID[3], _rawBSSID[4], _rawBSSID[5]];
    }
    
	int rssi = (int) ((NSInteger) [info rssiValue]);
	int noise = [info noiseMeasurement];
	
	_curSignal = rssi - noise;
    if (_curSignal<0) _curSignal = 0;
    
    _primaryChannel = _channel = [[info wlanChannel] channelNumber];
    if (_packetsPerChannel[_channel]==0) {
        if (!_firstPacket) [[NSNotificationCenter defaultCenter] postNotificationName:KisMACViewItemChanged object:self];
        _packetsPerChannel[_channel] = 1;
    }
    
    //statistical data for the traffic view
    //not much though
    curSignalData += _curSignal;
    ++curPacketData;
    
	/*kCWSecurityNone                 = 0,
	 kCWSecurityWEP                  = 1,
	 kCWSecurityWPAPersonal          = 2,
	 kCWSecurityWPAPersonalMixed     = 3,
	 kCWSecurityWPA2Personal         = 4,
	 kCWSecurityPersonal             = 5,
	 kCWSecurityDynamicWEP           = 6,
	 kCWSecurityWPAEnterprise        = 7,
	 kCWSecurityWPAEnterpriseMixed   = 8,
	 kCWSecurityWPA2Enterprise       = 9,
	 kCWSecurityEnterprise           = 10,
	 kCWSecurityUnknown              = NSIntegerMax,*/
	CWSecurity sm = kCWSecurityNone;
	
	for (; sm <= kCWSecurityEnterprise; ++sm) {
		if ([info supportsSecurity:sm])
			break;
	}
	
    switch (sm)
    {
        case kCWSecurityNone:
            wep = encryptionTypeNone;
        break;
            
        case kCWSecurityWEP:
		case kCWSecurityDynamicWEP:
            wep = encryptionTypeWEP;
        break;
            
        case kCWSecurityWPAPersonal:
        case kCWSecurityWPAPersonalMixed:
		case kCWSecurityWPAEnterprise:
		case kCWSecurityWPAEnterpriseMixed:
            wep = encryptionTypeWPA;
        break;
            
        case kCWSecurityWPA2Personal:
        case kCWSecurityWPA2Enterprise:
            wep = encryptionTypeWPA2;
        break;
        default:
            wep = encryptionTypeUnknown;
        break;
    }

	if (_isWep != wep) 
    {
        _isWep = wep;	//check if wep is enabled
        if(_netView != nil)
        {
            [_netView setWep:_isWep];
        }
    }
	
    if ([info ibss])
    {
        _type = networkTypeAdHoc;
    } 
    else
    {
        _type = networkTypeManaged;
    }

    [_dataLock lock];
    [self updateSSID: info.ssid withSound:YES];

    [self generalEncounterStuff:YES];
    
    if (_firstPacket) {
        [[NSNotificationCenter defaultCenter] postNotificationName:KisMACViewItemChanged object:self];
        _firstPacket = NO;
    }
    
    [_dataLock unlock];
}

#pragma mark -

- (bool)noteFinishedSweep:(int)num {
    // shuffle the values around in the aYield array
    bool ret;
    BIValuePair *pV;
    waypoint cp;
    
    graphLength = num;

    if (curPacketData) {
        curSignalData/=curPacketData;
        ret = NO;
    } else if ([[NSDate date] timeIntervalSinceDate:_date]>1 && _gotData) {
        cp = [[WaveHelper gpsController] currentPoint];
       
        if (cp._lat!=100) {
            [_dataLock lock];
            pV = [[BIValuePair alloc] init];
            [pV setPairFromWaypoint:cp];
            _coordinates[pV] = @0;
            [_dataLock unlock];
        }

        curSignalData=0;
        _curSignal=0;
        ret = YES;	//the net needs an update
        _gotData = NO;
    } else {
        return NO;
    }
    
    
	if (!_graphInit) {
		graphData = new (struct graphStruct);
		_graphInit = YES;
		memset(graphData, 0, sizeof(struct graphStruct));
	}
	
	// set the values we collected
    graphData->trafficData[graphLength] = curTrafficData;
    graphData->packetData[graphLength] = curPacketData;
    graphData->signalData[graphLength] = curSignalData;

    curTraffic = curTrafficData;
    curTrafficData = 0;
    curPackets = curPacketData;
    curPacketData = 0;
    curSignalData = 0;
    
    int x = num - 120;

    recentTraffic = 0;
    recentPackets = 0;
    recentSignal = 0;
    
	if(x < 0) x = 0;
    while(x < num) {
        recentTraffic += graphData->trafficData[x];
        recentPackets += graphData->packetData[x];
        recentSignal  += graphData->signalData[x];
			++x;
    }
    
    if(graphLength >= MAX_YIELD_SIZE) {
        memcpy(graphData->trafficData, graphData->trafficData + 1, (MAX_YIELD_SIZE) * sizeof(int));
        graphData->trafficData[MAX_YIELD_SIZE] = 0;

        memcpy(graphData->packetData, graphData->packetData + 1, (MAX_YIELD_SIZE) * sizeof(int));
        graphData->packetData[MAX_YIELD_SIZE] = 0;

        memcpy(graphData->signalData, graphData->signalData + 1, (MAX_YIELD_SIZE) * sizeof(int));
        graphData->signalData[MAX_YIELD_SIZE] = 0;
    }
 
	_cacheValid = NO;
    return ret;
}

- (void)setVisible:(BOOL)visible 
{
	[_netView setFiltered: !visible];
}

#pragma mark -

- (struct graphStruct)graphData {
    return *graphData;
}
- (NSDictionary*)getClients {
    return aClients;
}
- (NSArray*)getClientKeys {
    return aClientKeys;
}
- (encryptionType)wep { 
    return _isWep;
}
- (NSString *)ID {
    return _ID;
}
- (NSString *)BSSID {
    if (_BSSID==nil) return NSLocalizedString(@"<no bssid>", "for tunnels");
    return _BSSID;
}
- (NSString *)SSID {
	NSString *ssid;
    if (_SSID==nil) {
        switch (_type) {
        case networkTypeTunnel:
            ssid = NSLocalizedString(@"<tunnel>", "the ssid for tunnels");
			break;
		case networkTypeLucentTunnel:
            ssid = NSLocalizedString(@"<lucent tunnel>", "ssid for lucent tunnels");
			break;
		case networkTypeProbe:
            ssid = NSLocalizedString(@"<any ssid>", "the any ssid for probe nets");
			break;
        default:
            ssid = @"<no ssid>";
        }
    } else if ([_SSID isEqualToString:@""]) {
        ssid = (_type == networkTypeProbe ? 
            NSLocalizedString(@"<any ssid>", "the any ssid for probe nets") : 
            NSLocalizedString(@"<hidden ssid>", "hidden ssid")
        );
	} else {
		ssid = _SSID;
	}
	if ([_SSIDs count]) {
		return [NSString stringWithFormat:@"%@ (%@)", ssid, [_SSIDs componentsJoinedByString:@", "]];
	} else {
		return ssid;
	}
}

- (bool)isCorrectSSID {
	NSString *ssid = [self SSID];
	if (ssid && [ssid length]
		&& ![ssid isEqualToString:NSLocalizedString(@"<tunnel>", "the ssid for tunnels")]
		&& ![ssid isEqualToString:NSLocalizedString(@"<lucent tunnel>", "ssid for lucent tunnels")]
		&& ![ssid isEqualToString:NSLocalizedString(@"<any ssid>", "the any ssid for probe nets")]
		&& ![ssid isEqualToString:@"<no ssid>"]
		&& ![ssid isEqualToString:@""]
		)
	{
		return true;
	}
	
	return false;
}

- (NSString *)rawSSID {
    return [_SSID isEqualToString:@""] ? nil : _SSID;
}
- (NSArray *)SSIDs {
	return _SSIDs;
}

- (NSString *)date
{
    NSString * dateString;
    
    @synchronized(self)
    {
        if(nil == _date)
        {
            dateString = @"";
        }
        else
        {
            dateString = [NSString stringWithFormat:@"%@", _date];
        }
    }

    return dateString;
}

- (NSDate*)lastSeenDate {
    return _date;
}
- (NSString *)firstDate {
    return [NSString stringWithFormat:@"%@", aFirstDate]; //[aFirstDate descriptionWithCalendarFormat:@"%H:%M %d-%m-%y" timeZone:nil locale:nil];
}
- (NSDate *)firstSeenDate {
    return aFirstDate;
}
- (NSString *)getIP {
    if (_IPAddress) {
        return _IPAddress;
    }
    return nil;
}
- (NSString *)data {
    return [WaveHelper bytesToString: _bytes];
}
- (float)dataCount {
    return _bytes;
}
- (NSString *)getVendor {
    if (_vendor) return _vendor;
    _vendor=[WaveHelper vendorForMAC:_BSSID];
    return _vendor;
}
- (NSString*)rates {
	int i;
	NSMutableArray *a = [NSMutableArray array];
	for (i = 0; i < _rateCount; ++i) {
		[a addObject:@(((float)(_rates[i] & 0x7F)) / 2)];
	}
	return [a componentsJoinedByString:@", "];
}
- (NSString*)comment {
    return aComment;
}
- (void)setComment:(NSString*)comment {
    aComment=comment;
}
- (int)avgSignal {
    int sum = 0;
    int i, x, c;
    int max = (graphLength < _avgTime*4) ? graphLength : _avgTime*4;
    
    c=0;
    for (i=0; i<max; ++i) {
        x = graphData->signalData[graphLength - i];
        if (x) {
            sum += x;
            ++c;
        }
    }
    if (c==0) return 0;
    return sum / c;
}
- (int)curSignal {
    return _curSignal;
}
- (int)curPackets {
    return curPackets;
}
- (int)curTraffic {
    return curTraffic;
}
- (int)recentTraffic {
    return recentTraffic;
}
- (int)recentPackets {
    return recentPackets;
}
- (int)recentSignal {
    return recentSignal;
}
- (int)maxSignal {
    return _maxSignal;
}
- (int)channel {
    return _channel;
}
- (int)originalChannel {
    return _primaryChannel;
}
- (networkType)type {
    return _type;
}
- (void)setNetID:(int)netID {
    _netID = netID;
}
- (int)netID {
    return _netID;
}
- (int)packets {
    return _packets;
}
- (int)uniqueIVs {
    return [_ivData[0] count] + [_ivData[1] count] + [_ivData[2] count] + [_ivData[3] count];
}
- (int)dataPackets {
    return _dataPackets;
}
- (int)mgmtPackets {
    return _mgmtPackets;
}
- (int)ctrlPackets {
    return _ctrlPackets;
}
- (int*)packetsPerChannel {
    return _packetsPerChannel;
}
- (bool)liveCaptured {
    return _liveCaptured;
}
- (NSArray*)cryptedPacketsLog {
    return _packetsLog;
}
- (NSMutableArray*)arpPacketsLog {
    return _ARPLog;
}
- (NSMutableArray*)ackPacketsLog {
    return _ACKLog;
}
- (NSString*)key {
    if ((_password==nil)&&(_isWep > encryptionTypeNone)) return NSLocalizedString(@"<unresolved>", "Unresolved password");
    return _password;
}

//Showing real password if available
//needs more cleanup todo fixme!!
- (NSString*)asciiKey
{ 
    NSString * asciiKey = nil;
    const char *password;
    int len; 
    int mem = 0;
    char ascii[14]; //the max length is 14
    int p;
    char hex[5];
    int i;
    
    //if it is wep but we don't have the passwd
    if ((nil == _password) && (_isWep > encryptionTypeNone))
    {
		asciiKey = NSLocalizedString(@"<unresolved>", "Unresolved password");
	}
    else if(_isWep > encryptionTypeNone)
    {		
		password = [_password UTF8String];
		len = strlen(password); 

		if (len == 14 || len == 38 )
        {
			if (len == 14) mem = 5; // for WEP 40 bit
			if (len == 38) mem = 13; // for WEP 104 bit			
			
			for (p = 0; p <= len; p += 3)
            {				 
				hex[0] = '0';
				hex[1] = 'x';
				hex[2] = password[p];
				hex[3] = password[p+1];
				hex[4] = '\0';
				ascii[p/3] = strtol(hex, NULL, 16);
			}
			ascii[mem] = '\0';
			
			for(i = 0; i < mem; ++i)
            {
				if(!isascii(ascii[i]))
                {
					//asciiKey = [NSString stringWithFormat:@"%s", "Key cannot be converted"];
                    break;
				}
			}//for
            
			asciiKey = [NSString stringWithFormat:@"%s", ascii];
		} // len 13 or 38
        else
        {
            //its not an ascii key
            asciiKey = [NSString stringWithFormat:@"%s", "ASCII key unavailable"];
        }
         
	}//else (is Wep and have passwd)
    
    //if it is still nil after all of that, blank it out
    if(nil == asciiKey)
    {
        asciiKey = @"";
    }
    
    return asciiKey;
}	

- (NSString*)lastIV {
    return [NSString stringWithFormat:@"%.2X:%.2X:%.2X", _IV[0], _IV[1], _IV[2]];
}
- (UInt8*)rawBSSID {
    return _rawBSSID;
}
- (UInt8*)rawID {
    return _rawID;
}
- (NSDictionary*)coordinates {
    return _coordinates;
}
- (WaveWeakContainer *__strong*)ivData {
    return _ivData;
}
- (BOOL)passwordAvailable {
    return _password != nil;
}

- (int)challengeResponseStatus {
    return _challengeResponseStatus;
}

#pragma mark -

- (NSDictionary*)cache
{
	NSString *enc, *type;
	NSDictionary *cache;
	NSImage *image = nil;
	if (_cacheValid) return _cache;
	
	switch (_isWep)
    {
		case encryptionTypeLEAP:
			enc = NSLocalizedString(@"LEAP", "table description");
			break;
		case encryptionTypeWPA2:     
			enc = NSLocalizedString(@"WPA2", "table description");
            if(_challengeResponseStatus == chreResponse)
            {
                image = [NSImage imageNamed:@"orangegem.pdf"];
            }
            else if(_challengeResponseStatus == chreChallenge)
            {
                image = [NSImage imageNamed:@"orangegem.pdf"];
            }
            else if(_challengeResponseStatus == chreComplete)
            {
                image = [NSImage imageNamed:@"greengem.pdf"];
            }
			break;
		case encryptionTypeWPA:     
			enc = NSLocalizedString(@"WPA", "table description");
            if(_challengeResponseStatus == chreResponse)
            {
                image = [NSImage imageNamed:@"orangegem.pdf"];
            }
            else if(_challengeResponseStatus == chreChallenge)
            {
                image = [NSImage imageNamed:@"orangegem.pdf"];
            }
            else if(_challengeResponseStatus == chreComplete)
            {
                image = [NSImage imageNamed:@"greengem.pdf"];
            }
			break;
		case encryptionTypeWEP40:
			enc = NSLocalizedString(@"WEP-40", "table description");
            if( [self uniqueIVs] > WEP_GEM_ORANGE_LEVEL && 
                [self uniqueIVs] < WEP_GEM_GREEN_LEVEL)
            {
                image = [NSImage imageNamed:@"orangegem.pdf"];
            }
            else if([self uniqueIVs] > WEP_GEM_GREEN_LEVEL)
            {
                image = [NSImage imageNamed:@"greengem.pdf"];
            }
			break;
		case encryptionTypeWEP:
			enc = NSLocalizedString(@"WEP", "table description");
            if( [self uniqueIVs] > WEP_GEM_ORANGE_LEVEL && 
                [self uniqueIVs] < WEP_GEM_GREEN_LEVEL)
            {
                image = [NSImage imageNamed:@"orangegem.pdf"];
            }
            else if([self uniqueIVs] > WEP_GEM_GREEN_LEVEL)
            {
                image = [NSImage imageNamed:@"greengem.pdf"];
            }
			break;
		case encryptionTypeNone:
            image = [NSImage imageNamed:@"greengem.pdf"];
			enc = NSLocalizedString(@"NO", "table description");
			break;
		case encryptionTypeUnknown:
			enc = @"";
			break;
		default:
			enc = @"";
			NSAssert(NO, @"Encryption type invalid");
	}
   
	switch (_type) 
    {
		case networkTypeUnknown:
			type = @"";
			break;
		case networkTypeAdHoc:
			type = NSLocalizedString(@"ad-hoc", "table description");
			break;
		case networkTypeManaged:
			type = NSLocalizedString(@"managed", "table description");
			break;
		case networkTypeTunnel:
			type = NSLocalizedString(@"tunnel", "table description");
			break;
		case networkTypeProbe:
			type = NSLocalizedString(@"probe", "table description");
			break;
		case networkTypeLucentTunnel:
			type = NSLocalizedString(@"lucent tunnel", "table description");
			break;
		default:
			type = @"";
			NSAssert(NO, @"Network type invalid");
	}
    
    //if we didn't set the Gem yet, set it red here
    if (image == nil)
    {
        image = [NSImage imageNamed:@"redgem.pdf"];
    }
	
	cache = @{@"id": [NSString stringWithFormat:@"%i", _netID],
		@"ssid": [self SSID],
		@"bssid": [self BSSID], 
		@"signal": [NSString stringWithFormat:@"%i", _curSignal],
		@"avgsignal": [NSString stringWithFormat:@"%i", [self avgSignal]],
		@"maxsignal": [NSString stringWithFormat:@"%i", _maxSignal],
		@"channel": [NSString stringWithFormat:@"%i", _channel],
        @"primaryChannel": [NSString stringWithFormat:@"%i", _primaryChannel],
		@"packets": [NSString stringWithFormat:@"%i", _packets],
		@"data": [self data],
		@"wep": enc,
		@"type": type,
		@"lastseen": [NSString stringWithFormat:@"%@", _date],
        @"challengeResponse": image};
	
	_cache = cache;
	_cacheValid = YES;
	return _cache; 
}

#pragma mark -

- (bool)joinNetwork 
{
    return [[WaveDriverAirport sharedInstance] joinBSSID: _rawBSSID 
                                            withPassword: _password];
}

#pragma mark -

- (NSString *)latitude {
    if (!aLat) return @"0.000000N";
    return aLat;
}
- (NSString *)longitude {
    if (!aLong) return @"0.000000E";
    return aLong;
}
- (NSString *)elevation {
    if (!aElev) return @"0";
    return aElev;
}

- (NSString*)crackError {
    return _crackErrorString;
}

#pragma mark -

// for display color in TrafficView
- (NSColor*)graphColor {
    return _graphColor;
}
- (void)setGraphColor:(NSColor*)newColor {
    _graphColor = newColor;
}

// for easy sorting by TrafficView
- (NSComparisonResult)compareSignalTo:(id)aNet {
    if (_curSignal == [aNet curSignal])
        return NSOrderedSame;
    if (_curSignal > [aNet curSignal])
        return NSOrderedAscending;
    return NSOrderedDescending;
}
- (NSComparisonResult)comparePacketsTo:(id)aNet {
    if (curPackets == [aNet curPackets])
        return NSOrderedSame;
    if (curPackets > [aNet curPackets])
        return NSOrderedAscending;
    return NSOrderedDescending;
}
- (NSComparisonResult)compareTrafficTo:(id)aNet {
    if (curTraffic == [aNet curTraffic])
        return NSOrderedSame;
    if (curTraffic > [aNet curTraffic])
        return NSOrderedAscending;
    return NSOrderedDescending;
}
- (NSComparisonResult)compareRecentTrafficTo:(id)aNet {
    if (recentTraffic == [aNet recentTraffic])
        return NSOrderedSame;
    if (recentTraffic > [aNet recentTraffic])
        return NSOrderedAscending;
    return NSOrderedDescending;
}
- (NSComparisonResult)compareRecentPacketsTo:(id)aNet {
    if (recentPackets == [aNet recentPackets])
        return NSOrderedSame;
    if (recentPackets > [aNet recentPackets])
        return NSOrderedAscending;
    return NSOrderedDescending;
}
- (NSComparisonResult)compareRecentSignalTo:(id)aNet {
    if (recentSignal == [aNet recentSignal])
        return NSOrderedSame;
    if (recentSignal > [aNet recentSignal])
        return NSOrderedAscending;
    return NSOrderedDescending;
}

#pragma mark -

int compValues(int v1, int v2) {
    if (v1 < v2) return NSOrderedAscending;
    else if (v1 > v2) return NSOrderedDescending;
    else return NSOrderedSame;
}

int compFloatValues(float v1, float v2) {
    if (v1 < v2) return NSOrderedAscending;
    else if (v1 > v2) return NSOrderedDescending;
    else return NSOrderedSame;
}

int idSort(WaveClient* w1, WaveClient* w2, int ascend) {
    int v1 = [[w1 ID] intValue];
    int v2 = [[w2 ID] intValue];
    return ascend * compValues(v1,v2);
}

int clientSort(WaveClient* w1, WaveClient* w2, int ascend) {
    return ascend * [[w1 ID] compare:[w2 ID]];
}

int vendorSort(WaveClient* w1, WaveClient* w2, int ascend) {
    return ascend * [[w1 vendor] compare:[w2 vendor]];
}

int signalSort(WaveClient* w1, WaveClient* w2, int ascend) {
    return ascend * compValues( [w1 curSignal], [w2 curSignal]);
}

int receivedSort(WaveClient* w1, WaveClient* w2, int ascend) {
    return ascend * compFloatValues([w1 receivedBytes], [w2 receivedBytes]);
}

int sentSort(WaveClient* w1, WaveClient* w2, int ascend) {
    return ascend * compFloatValues([w1 sentBytes], [w2 sentBytes]);
}
int dateSort(WaveClient* w1, WaveClient* w2, int ascend) {
    return ascend * [[w1 rawDate] compare:[w2 rawDate]];
}
int ipSort(WaveClient* w1, WaveClient* w2, int ascend) {
    //we break the ips into sections and sort 
    int i, ndx = 0;
    NSArray *ip1 = [[w1 getIPAddress] componentsSeparatedByString:@"."];
    NSArray *ip2 = [[w2 getIPAddress] componentsSeparatedByString:@"."];
    if ([ip1 count] < 4) {
        return ascend * NSOrderedDescending;
    }
    else if ([ip2 count] < 4) {
        return ascend * NSOrderedAscending;
    }
    while(ndx < 4){
        i = compValues([ip1[ndx] intValue], [ip2[ndx]intValue]);
        if (i == NSOrderedSame) {
            ++ndx;
        }
        else break;
    }
    return ascend * i;
}

typedef int (*SORTFUNC)(id, id, int);

- (void) sortByColumn:(NSString*)ident order:(bool)ascend {
    bool sorted = YES;
    SORTFUNC sf;
    int ret;
    unsigned int w, x, y, _sortedCount, a;
    
    if      ([ident isEqualToString:@"id"])			sf = (SORTFUNC)idSort;
    else if ([ident isEqualToString:@"client"])		sf = (SORTFUNC)clientSort;
    else if ([ident isEqualToString:@"vendor"])		sf = (SORTFUNC)vendorSort;
    else if ([ident isEqualToString:@"signal"])		sf = (SORTFUNC)signalSort;
    else if ([ident isEqualToString:@"received"])	sf = (SORTFUNC)receivedSort;
    else if ([ident isEqualToString:@"sent"])		sf = (SORTFUNC)sentSort;
    else if ([ident isEqualToString:@"lastseen"])	sf = (SORTFUNC)dateSort;
    else if ([ident isEqualToString:@"ipa"])		sf = (SORTFUNC)ipSort;
    else {
        DBNSLog(@"Unknown sorting column. This is a bug and should never happen.");
        return;
    }

    a = (ascend ? 1 : -1);
    
    [_dataLock lock];
    
    _sortedCount = [aClientKeys count];
    
    for (y = 1; y <= _sortedCount; ++y) {
        for (x = y - 1; x < (_sortedCount - y); ++x) {
            w = x + 1;
            ret = (*sf)(aClients[aClientKeys[x]], aClients[aClientKeys[w]], a);
            if (ret == NSOrderedDescending) {
                sorted = NO;
                
                //switch places
                [aClientKeys exchangeObjectAtIndex:x withObjectAtIndex:w];
                [aClients[aClientKeys[x]] wasChanged];
                [aClients[aClientKeys[w]] wasChanged];
            }
        }
        
        if (sorted) break;
        sorted = YES;
        
        for (x = (_sortedCount - y); x >= y; x--) {
            w = x - 1;
            ret = (*sf)(aClients[aClientKeys[w]], aClients[aClientKeys[x]], a);
            if (ret == NSOrderedDescending) {
                sorted = NO;
                
                //switch places
                [aClientKeys exchangeObjectAtIndex:x withObjectAtIndex:w];
                [aClients[aClientKeys[x]] wasChanged];
                [aClients[aClientKeys[w]] wasChanged];
            }
        }
        
        if (sorted) break;
        sorted = YES;
    }
        
    [_dataLock unlock];
}

#pragma mark -
#pragma mark WPA/LEAP cracking
#pragma mark -

- (int)capturedEAPOLKeys {
	int keys = 0;
	unsigned int i;
	
    for (i = 0; i < [aClientKeys count]; ++i) {
        if ([aClients[aClientKeys[i]] eapolDataAvailable]) ++keys;
    }
	return keys;
}

- (int)capturedLEAPKeys {
    int keys = 0;
    unsigned int i;
	
	for (i = 0; i < [aClientKeys count]; ++i) {
        if ([aClients[aClientKeys[i]] leapDataAvailable]) ++keys;
    }
	return keys;
}

#pragma mark -

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];

    [_dataLock lock];
	
	[_netView removeFromSuperView];
    [_dataLock unlock];
    
	if (_graphInit) delete graphData;
	
}

@end

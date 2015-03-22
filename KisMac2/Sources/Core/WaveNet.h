/*
        
        File:			WaveNet.h
        Program:		KisMAC
		Author:			Michael Ro§berg
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

#import "WavePacket.h"

enum {
    trafficData,
    packetData,
    signalData
};

enum {
    chreNone,
    chreChallenge,
    chreResponse,
    chreComplete
};

struct graphStruct {
    int trafficData[MAX_YIELD_SIZE + 1];
    int packetData[MAX_YIELD_SIZE + 1];
    int signalData[MAX_YIELD_SIZE + 1];
};

@class NetView;
@class WaveWeakContainer;
@class CWNetwork;
@class ImportController;

@interface WaveNet : NSObject /*<UKTest>*/ {
    int					_netID;					//network ID
    int					_maxSignal;				//biggest signal ever
    int					_curSignal;				//current signal
    int					_channel;				//last channel
    int					_primaryChannel;        //channel which is broadcasted by AP
    networkType			_type;                  //0=unknown, 1=ad-hoc, 2=managed, 3=tunnel 4=probe 5=lucent tunnel
    
    // Statistical Data
    int					_packets;				//# of packets
    int					_packetsPerChannel[16];	//how many packets on each channel
    int					_dataPackets;			//# of Data packets
    int                 _mgmtPackets;           //# of Management packets
    int                 _ctrlPackets;           //# of Control packets
    
    double				_bytes;                 //bytes, float because of size
    int					graphLength;
    struct graphStruct *graphData;
    
    encryptionType		_isWep;                 //0=unknown, 1=disabled, 2=enabled 3=40-bit 4-WPA .....
    UInt8				_IV[3];				    //last iv
    UInt8				_rawID[6];			    //our id
    UInt8				_rawBSSID[6];			//our bssid
	UInt8				_rateCount;
	UInt8				_rates[MAX_RATE_COUNT];
    bool				_gotData;
    bool				_firstPacket;
    bool				_liveCaptured;
	bool				_graphInit;
	NSDictionary		*_cache;
    bool				_cacheValid;

    NSRecursiveLock *_dataLock;
    
    NetView*  _netView;
    NSString* aLat;
    NSString* aLong;
    NSString* aElev;
    NSString *_crackErrorString;

    NSString *_SSID;
	NSArray  *_SSIDs;
    NSString* _BSSID;
    NSString* _IPAddress;
    NSString* _vendor;
    NSString* _password;
    NSString* aComment;
    NSString* _ID;
    NSDate* _date;		//current date
    NSDate* aFirstDate;
    NSMutableArray* _packetsLog;    //array with a couple of packets to calculate checksum
    NSMutableArray* _ARPLog;        //array with a couple of packets to do reinjection attack
    NSMutableArray* _ACKLog;        //array with a couple of packets to do reinjection attack
    NSMutableDictionary* aClients;
    NSMutableArray* aClientKeys;
    NSMutableDictionary* _coordinates;
    WaveWeakContainer *_ivData[4];       //one for each key id
    
    int _challengeResponseStatus;
    
    NSColor* _graphColor;	// display color in TrafficView
    int recentTraffic;
    int recentPackets;
    int recentSignal;
    int curPackets;		// for setting graphData
    int curTraffic;		// for setting graphData
    int curTrafficData;		// for setting graphData
    int curPacketData;		// for setting graphData
    int curSignalData;		// for setting graphData
    int _avgTime;               // how many seconds are take for average?
    ImportController *_im;

/*	PRGA Snarf */
	int _authState;
		
}

- (id)initWithID:(int)netID;
- (id)initWithNetstumbler:(const char*)buf andDate:(NSString*)date;
- (id)initWithDataDictionary:(NSDictionary*)dict;
- (void)mergeWithNet:(WaveNet*)net;

- (void)updateSettings:(NSNotification*)note;

- (bool)noteFinishedSweep:(int)num;
- (NSColor*)graphColor;
- (void)setGraphColor:(NSColor*)newColor;
- (NSComparisonResult)compareSignalTo:(id)net;
- (NSComparisonResult)comparePacketsTo:(id)net;
- (NSComparisonResult)compareTrafficTo:(id)net;
- (NSComparisonResult)compareRecentTrafficTo:(id)aNet;

- (NSDictionary*)dataDictionary;

- (struct graphStruct)graphData;
- (NSDictionary*)getClients;
- (NSArray*)getClientKeys;
- (void)setVisible:(BOOL)visible;

- (encryptionType)wep;
- (NSString *)ID;
- (NSString *)BSSID;
- (NSString *)SSID;
- (bool)isCorrectSSID;
- (NSArray *)SSIDs;
- (NSString *)rawSSID;
- (NSString *)date;
- (NSDate*)lastSeenDate;
- (NSString *)firstDate;
- (NSDate *)firstSeenDate;
- (NSString *)getIP;
- (NSString*)data;
- (NSString*)getVendor;
- (NSString*)rates;
- (NSArray*)cryptedPacketsLog;      //a couple of encrypted packets
- (NSMutableArray*)arpPacketsLog;	//a couple of reinject packets
- (NSMutableArray*)ackPacketsLog;	//a couple of reinject packets
- (NSString*)key;
- (NSString*)lastIV;
- (NSString*)comment;
- (void)setComment:(NSString*)comment;
- (NSDictionary*)coordinates;
- (WaveWeakContainer *__strong*)ivData;
- (BOOL)passwordAvailable;
- (int)challengeResponseStatus;

- (NSDictionary*)cache;

- (NSString *)latitude;
- (NSString *)longitude;
- (NSString *)elevation;

- (float)dataCount;
- (int)curTraffic;
- (int)curPackets;
- (int)curSignal;
- (int)maxSignal;
- (int)avgSignal;
- (int)channel;
- (int)originalChannel;
- (networkType)type;

// Packet Statistics
- (int)packets;
- (int)uniqueIVs;
- (int)dataPackets;
- (int)mgmtPackets;
- (int)ctrlPackets;

- (int*)packetsPerChannel;
- (void)setNetID:(int)netID;
- (int)netID;
- (UInt8*)rawBSSID;
- (UInt8*)rawID;
- (bool)liveCaptured;

- (bool)joinNetwork;

- (void)parsePacket:(WavePacket*) w withSound:(bool)sound;
- (void)parseAppleAPIData:(CWNetwork*)info;

- (void)sortByColumn:(NSString*)ident order:(bool)ascend;

- (int)capturedEAPOLKeys;
- (int)capturedLEAPKeys;

- (NSString*)crackError;
- (NSString*)asciiKey;
@end

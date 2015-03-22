/*
        
        File:			WavePacket.h
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

#import <Foundation/Foundation.h>
#import "KisMAC80211.h"
#import <sys/time.h>

//#define DEBUG			//This has currently no meaning
//#define LOGPACKETS		//do not enable unless you know what you are doing

// 1201 = 5 minutes (plus one) for 0.25s interval
#define MAX_YIELD_SIZE (int)1200

#define MAX_RATE_COUNT 64

//this is given to us by the driver
struct sAirportFrame { // 14 Byte
    UInt16 status;
    UInt16 reserved0;
    UInt16 reserved1;
    UInt8  signal;
    UInt8  silence;
    UInt16 rate;
    UInt16 reserved2;
    UInt16 txControl;
};

//the beginning of each beacon frame. currently not in use
struct sBeaconFrame { //at least 12 bytes
    UInt8  timestamp[8];
    UInt16 beaconInterval;
    UInt16 capabilities;
};

typedef enum _networkType {
    networkTypeUnknown      = 0,
    networkTypeAdHoc        = 1,
    networkTypeManaged      = 2,
    networkTypeTunnel       = 3,
    networkTypeProbe        = 4,
    networkTypeLucentTunnel = 5
} networkType;

typedef enum _wpaNoncePresent {
    wpaNonceNone,
    wpaNonceANonce,
    wpaNonceSNonce
} wpaNoncePresent;

typedef enum _encryptionType {
    encryptionTypeUnknown   = 0,
    encryptionTypeNone      = 1,
    encryptionTypeWEP       = 2,
    encryptionTypeWEP40     = 3,
    encryptionTypeWPA       = 4,
    encryptionTypeLEAP      = 5,
    encryptionTypeWPA2      = 6,    
} encryptionType;

typedef enum _leapAuthCode {
    leapAuthCodeChallenge   = 1,
    leapAuthCodeResponse    = 2,
    leapAuthCodeSuccess     = 3,
    leapAuthCodeFailure     = 4    
} leapAuthCode;

//this represents a packet
@interface WavePacket : NSObject /*<UKTest>*/ {
    int _signal;            // current signal strength
    int _channel;           // well the channel
    int  _primaryChannel;   // Primary channel
    int _type;			//type 0=management 1=control 2=data
    int _subtype;		//deprending on type, WARNING might be little endian
    
    networkType    _netType;    //0=unknown, 1=ad-hoc, 2=managed, 3=tunnel
    encryptionType _isWep;      //0=unknown, 1=disabled, 2=enabled
    leapAuthCode   _leapCode;
    
    bool _isToDS;		//to access point?
    bool _isFrDS;		//from access point?
    bool _isEAP;

    NSString		*_SSID;
    NSMutableArray	*_SSIDs;
	
	UInt8			_rateCount;
	UInt8			_rates[MAX_RATE_COUNT];
	
	NSString *_username;
    NSData   *_challenge;
    NSData   *_response;
    
    struct timeval _creationTime; //time for cap
    
    UInt8* _frame;                  // 80211 frame
    UInt8 *_payload;                // Payload

    int _length;                    // Length of 80211 frame
    int _headerLength;              // Length of 80211 header
    int _payloadLength;				// Length of payload

    int _revelsKeyByte;         //-2 = no idea

    UInt8 _addr1[ETH_ALEN];
    UInt8 _addr2[ETH_ALEN];
    UInt8 _addr3[ETH_ALEN];
    UInt8 _addr4[ETH_ALEN];
    
    //WPA stuff
    int _wpaKeyCipher;
    wpaNoncePresent _nonce;
}

//input function
- (bool)parseFrame:(KFrame*) f;

- (int)length;          // Length of 80211 frame
- (int)payloadLength;   // Length of payload
- (int)signal;
- (int)channel;
- (int)type;
- (int)subType;
- (int)primaryChannel;
- (bool)fromDS;
- (bool)toDS;
- (encryptionType)wep;
- (networkType)netType;
- (UInt8*)payload;      // payload
- (UInt8*)frame;
- (int)isResolved;	//for wep cracking 
- (NSString*)SSID;
- (NSArray*)SSIDs;
- (UInt8)getRates:(UInt8*)rates;
- (bool)isCorrectSSID;

- (UInt8*)rawSenderID;
- (NSString*)stringSenderID;
- (UInt8*)rawReceiverID;
- (NSString*)stringReceiverID;
- (UInt8*)rawBSSID;
- (NSString*)BSSIDString;
- (bool)BSSID:(UInt8*)bssid;
- (bool)ID:(UInt8*)ident;
- (NSString*)IDString;	//gives a unique for each net, bssid is not useful
- (bool)isEAPPacket;
- (struct timeval *)creationTime;

// IP handling by Dylan Neild
- (NSString *)sourceIPAsString;
- (NSString *)destinationIPAsString;
- (unsigned char *)sourceIPAsData;
- (unsigned char *)destinationIPAsData;

// MAC Addresses
- (UInt8*)addr1;
- (UInt8*)addr2;
- (UInt8*)addr3;
- (UInt8*)addr4;

//WPA handling
- (bool)isWPAKeyPacket;
- (wpaNoncePresent)wpaCopyNonce:(UInt8*)destNonce;
- (int)wpaKeyCipher;
- (NSData*)eapolMIC;
- (NSData*)eapolData;

//LEAP handling
- (bool)isLEAPKeyPacket;
- (leapAuthCode)leapCode;
- (NSString*)username;
- (NSData*)challenge;
- (NSData*)response;
@end

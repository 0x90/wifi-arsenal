/*
        
        File:			WaveClient.h
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


#import <Foundation/Foundation.h>

@class WavePacket;

@interface WaveClient : NSObject {
    NSString *_ID, *_vendor;
    NSString * _IPAddress;
    NSDate *_date;
    int _curSignal;
    float _receivedBytes;
    float _sentBytes;
    bool _changed;
    
    //WPA
    NSData *_aNonce, *_sNonce, *_MIC, *_packet;
    int _wpaKeyCipher;
    
    //LEAP
    NSData *_leapChallenge, *_leapResponse;
    NSString *_leapUsername;
}

- (id)initWithDataDictionary:(NSDictionary*)dict;
- (NSDictionary*)dataDictionary;

- (void)parseFrameAsIncoming:(WavePacket*)w;
- (void)parseFrameAsOutgoing:(WavePacket*)w;

- (NSString *)received;
- (NSString *)sent;
- (NSString *)vendor;
- (NSString *)date;
- (NSString *)getIPAddress;

- (float)receivedBytes;
- (float)sentBytes;
- (int)curSignal;
- (NSDate *)rawDate;


//WPA stuff
- (NSData *)sNonce;
- (NSData *)aNonce;
- (NSData *)eapolMIC;
- (NSData *)eapolPacket;
- (NSData *)rawID;
- (BOOL) eapolDataAvailable;
- (int) wpaKeyCipher;

//LEAP stuff
- (NSData *)leapChallenge;
- (NSData *)leapResponse;
- (NSString *)leapUsername;
- (BOOL) leapDataAvailable;

- (NSString *)ID;

- (BOOL)changed;
- (void)wasChanged;

@end

/*
        
        File:			WaveClient.m
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

#import "WaveClient.h"
#import "WaveHelper.h"
#import "WavePacket.h"
#import "WPA.h"
#import "GrowlController.h"
#import "80211b.h"

@implementation WaveClient

#pragma mark -
#pragma mark Coder stuff
#pragma mark -

- (id)initWithCoder:(NSCoder *)coder {
    self = [self init];
    if ( [coder allowsKeyedCoding] ) {
        _curSignal=[coder decodeIntForKey:@"aCurSignal"];

        _receivedBytes=[coder decodeDoubleForKey:@"aReceivedBytes"];
        _sentBytes=[coder decodeDoubleForKey:@"aSentBytes"];
        
        _ID     = [coder decodeObjectForKey:@"aID"];
        _date   = [coder decodeObjectForKey:@"aDate"];
        _IPAddress = [coder decodeObjectForKey:@"aIPA"];
        
        //WPA stuff
        _sNonce = [coder decodeObjectForKey:@"sNonce"];
        _aNonce = [coder decodeObjectForKey:@"aNonce"];
        _packet = [coder decodeObjectForKey:@"packet"];
        _MIC    = [coder decodeObjectForKey:@"MIC"];
        _wpaKeyCipher = [coder decodeIntForKey:@"wpaKeyCipher"];
        
        //LEAP stuff
        _leapUsername   = [coder decodeObjectForKey:@"leapUsername"];
        _leapChallenge  = [coder decodeObjectForKey:@"leapChallenge"];
        _leapResponse   = [coder decodeObjectForKey:@"leapResponse"];
        
        _changed = YES;
     } else {
        DBNSLog(@"Cannot decode this way");
    }
    return self;
}

- (id)initWithDataDictionary:(NSDictionary*)dict {
    self = [self init];
	if (!self) return nil;
	
	_curSignal = [dict[@"curSignal"] intValue];

	_receivedBytes = [dict[@"receivedBytes"] doubleValue];
	_sentBytes = [dict[@"sentBytes"] doubleValue];
	
	_ID     = dict[@"ID"];
	_date   = dict[@"date"];
    _IPAddress = dict[@"IPAddress"];
	
	//WPA stuff
	_sNonce = dict[@"wpaSNonce"];
	_aNonce = dict[@"wpaANonce"];
	_packet = dict[@"wpaPacket"];
	_MIC    = dict[@"wpaMIC"];
    _wpaKeyCipher = [dict[@"wpaKeyCipher"] intValue];

	//LEAP stuff
	_leapUsername   = dict[@"leapUsername"];
	_leapChallenge  = dict[@"leapChallenge"];
	_leapResponse   = dict[@"leapResponse"];
	
	_changed = YES;

    return self;
}

- (NSDictionary*)dataDictionary {
	NSMutableDictionary *dict = [NSMutableDictionary dictionary];
	
	dict[@"curSignal"] = @(_curSignal);
	dict[@"receivedBytes"] = [NSNumber numberWithDouble:_receivedBytes];
	dict[@"sentBytes"] = [NSNumber numberWithDouble:_sentBytes];
	
	dict[@"ID"] = _ID;
	if (_date) dict[@"date"] = _date;
    if (_IPAddress) dict[@"IPAddress"] = _IPAddress;
	
	if (_sNonce) dict[@"wpaSNonce"] = _sNonce;
	if (_aNonce) dict[@"wpaANonce"] = _aNonce;
	if (_packet) dict[@"wpaPacket"] = _packet;
	if (_MIC)    dict[@"wpaMIC"] = _MIC;
    if (_wpaKeyCipher) dict[@"wpaKeyCipher"] = @(_wpaKeyCipher);
        
	if (_leapUsername)  dict[@"leapUsername"] = _leapUsername;
	if (_leapChallenge) dict[@"leapChallenge"] = _leapChallenge;
	if (_leapResponse)  dict[@"leapResponse"] = _leapResponse;

	return dict;
}

#pragma mark -

- (void)wpaHandler:(WavePacket*) w {
    UInt8 nonce[WPA_NONCE_LENGTH];
    NSData *mic, *packet;
    if (![w isEAPPacket])
        return;
    
    if ([w isWPAKeyPacket]) {
        switch ([w wpaCopyNonce:nonce]) {
            case wpaNonceANonce:
                DBNSLog(@"Detected WPA challenge for %@!", _ID);
				[GrowlController notifyGrowlWPAChallenge:@"" mac:_ID bssid:[w BSSIDString]];
                DBNSLog(@"Nonce %.2X %.2X", nonce[0], nonce[WPA_NONCE_LENGTH-1]);
				_aNonce = [NSData dataWithBytes:nonce length:WPA_NONCE_LENGTH];
                _wpaKeyCipher = [w wpaKeyCipher];
                break;
            case wpaNonceSNonce:
                DBNSLog(@"Detected WPA response for %@!", _ID);
				[GrowlController notifyGrowlWPAResponse:@"" mac:_ID bssid:[w BSSIDString]];
                DBNSLog(@"Nonce %.2X %.2X", nonce[0], nonce[WPA_NONCE_LENGTH-1]);
				_sNonce = [NSData dataWithBytes:nonce length:WPA_NONCE_LENGTH];
                break;
            case wpaNonceNone:
                DBNSLog(@"Nonce None");
                break;
        }
        packet = [w eapolData];
        mic = [w eapolMIC];
        if (packet) _packet = packet;
        if (mic)    _MIC = mic;
    } else if ([w isLEAPKeyPacket]) {
        switch ([w leapCode]) {
        case leapAuthCodeChallenge:
			if (!_leapUsername) _leapUsername = [w username];
			if (!_leapChallenge) _leapChallenge = [w challenge];
            break;
        case leapAuthCodeResponse:
			if (!_leapResponse) _leapResponse = [w response];
            break;
        case leapAuthCodeFailure:
            DBNSLog(@"Detected LEAP authentication failure for client %@! Username: %@. Deleting all collected auth data!", _ID, _leapUsername);
			_leapUsername = nil;
			_leapChallenge = nil;
			_leapResponse = nil;
            break;
        default:
            break;
        }
    }
}

-(void) parseFrameAsIncoming:(WavePacket*)w {
    if (!_ID) {
        _ID=[w stringReceiverID];
		if ([_ID isEqualToString:@"00:0F:F7:C8:7A:60"] || [_ID isEqualToString:@"00:11:20:EE:CE:48"] || 
			[_ID isEqualToString:@"00:12:D9:B3:16:C0"] || [_ID isEqualToString:@"00:12:D9:B3:18:90"] ||
			[_ID isEqualToString:@"00:12:D9:B3:1D:40"])
        {
            NSString *speachText = [NSString stringWithFormat:@"Found desired Access Point: %@", _ID];
			DBNSLog(@"Found desired Access Point: %@", _ID);
			[WaveHelper speakSentence:(__bridge CFStringRef)(speachText) withVoice:[[NSUserDefaults standardUserDefaults] integerForKey:@"Voice"]];
			NSBeep(); NSBeep(); NSBeep();
		}
	}

    _receivedBytes+=[w length];
    _changed = YES;
    
    if ([w destinationIPAsString] != nil && ![[w destinationIPAsString] isEqualToString:@"0.0.0.0"] ) {
        _IPAddress = [w destinationIPAsString];
     //   DBNSLog(@"Incoming Packet Client dest IP Found: %@", [w destinationIPAsString]);
    }
    
    if (![w toDS])
        [self wpaHandler:w]; //dont store it in the AP client
}

-(void) parseFrameAsOutgoing:(WavePacket*)w {
    if (!_ID) {
        _ID=[w stringSenderID];
		if ([_ID isEqualToString:@"00:0F:F7:C8:7A:60"] || [_ID isEqualToString:@"00:11:20:EE:CE:48"] || 
			[_ID isEqualToString:@"00:12:D9:B3:16:C0"] || [_ID isEqualToString:@"00:12:D9:B3:18:90"] ||
			[_ID isEqualToString:@"00:12:D9:B3:1D:40"])
        {
            NSString *speachText = [NSString stringWithFormat:@"Found desired Access Point: %@", _ID];
			DBNSLog(@"Found desired Access Point: %@", _ID);
			[WaveHelper speakSentence:(__bridge CFStringRef)(speachText) withVoice:[[NSUserDefaults standardUserDefaults] integerForKey:@"Voice"]];
			NSBeep(); NSBeep(); NSBeep();
		}
    }
	_date = [NSDate date];
    
    _curSignal=[w signal];
    _sentBytes+=[w length];    
    _changed = YES;
    if ([w sourceIPAsString] != nil  && ![[w sourceIPAsString] isEqualToString:@"0.0.0.0"] ) {
        _IPAddress = [w sourceIPAsString];
        //DBNSLog(@"Outgoing Packet Client source IP Found: %@", [w sourceIPAsString]);
    }
    
    if (![w fromDS])
        [self wpaHandler:w]; //dont store it in the AP client
}

#pragma mark -

- (NSString *)ID {
    if (!_ID) return NSLocalizedString(@"<unknown>", "unknown client ID");
    return _ID;
}

- (NSString *)received {
    return [WaveHelper bytesToString: _receivedBytes];
}

- (NSString *)sent {
    return [WaveHelper bytesToString: _sentBytes];
}

- (NSString *)vendor {
    if (_vendor) return _vendor;
    _vendor=[WaveHelper vendorForMAC:_ID];
    return _vendor;
}

- (NSString *)date {
    if (_date==nil) return @"";
    else return [NSString stringWithFormat:@"%@", _date]; //return [_date descriptionWithCalendarFormat:@"%H:%M %d-%m-%y" timeZone:nil locale:nil];
}

- (NSString *)getIPAddress{
    if (_IPAddress == nil) return @"unknown";
    return _IPAddress;
}

#pragma mark -

- (float)receivedBytes {
    return _receivedBytes;
}

- (float)sentBytes {
    return _sentBytes;
}

- (int)curSignal {
    if ([_date compare:[NSDate dateWithTimeIntervalSinceNow:0.5]]==NSOrderedDescending) _curSignal=0;
    return _curSignal;
}

- (NSDate *)rawDate {
    return _date;
}

#pragma mark -
#pragma mark WPA stuff
#pragma mark -

- (NSData *)sNonce {
    return _sNonce;
}

- (NSData *)aNonce {
    return _aNonce;
}

- (NSData *)eapolMIC {
    return _MIC;
}

- (NSData *)eapolPacket {
    return _packet;
}

- (int)wpaKeyCipher {
    return _wpaKeyCipher;
}

- (NSData *)rawID {
    UInt8   ID8[6];
    int     ID32[6];
    int i;
    
    if (!_ID) return nil;
    
    if (sscanf([_ID UTF8String], "%2X:%2X:%2X:%2X:%2X:%2X", &ID32[0], &ID32[1], &ID32[2], &ID32[3], &ID32[4], &ID32[5]) != 6) return nil;
    for (i = 0; i < 6; ++i)
        ID8[i] = ID32[i];
    
    return [NSData dataWithBytes:ID8 length:6];
}

- (BOOL) eapolDataAvailable {
    if (_sNonce && _aNonce && _MIC && _packet) return YES;
    return NO;
}

#pragma mark -
#pragma mark LEAP stuff
#pragma mark -

- (NSData *)leapChallenge {
    return _leapChallenge;
}
- (NSData *)leapResponse {
    return _leapResponse;
}
- (NSString *)leapUsername {
    return _leapUsername;
}
- (BOOL) leapDataAvailable {
    if (_leapChallenge && _leapResponse && _leapUsername) return YES;
    return NO;
}

#pragma mark -

- (BOOL)changed {
    BOOL c = _changed;
    _changed = NO;
    return c;
}

- (void)wasChanged {
    _changed = YES;
}

#pragma mark -

@end

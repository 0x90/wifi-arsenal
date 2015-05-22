/*
        
        File:			WavePacket.mm
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

#import "WavePacket.h"
#import "WaveHelper.h"
#import "80211b.h"
#import "KisMAC80211.h"
#import <pcap.h>

#define AMOD(x, y) ((x) % (y) < 0 ? ((x) % (y)) + (y) : (x) % (y))

bool is8021xPacket(const UInt8* fileData) {
    if (fileData[0] == 0xAA &&
        fileData[1] == 0xAA &&
        fileData[2] == 0x03 &&
        fileData[3] == 0x00 &&
        fileData[4] == 0x00 &&
        (fileData[5] == 0x00 || fileData[5] == 0xf8) &&
        fileData[6] == 0x88 &&
        fileData[7] == 0x8e)
        
        return YES;
    else
        return NO;
}

@implementation WavePacket

//scans through variable length fields for ssid
-(void) parseTaggedData:(unsigned char*) packet length:(int) length {
    int len;
	UInt32 *vendorID;
    char ssid[LAST_BIT];
	
    _primaryChannel = 0;
    
	_SSID = nil;
	_SSIDs = nil;

	_rateCount = 0;
	
    while(length>2) {
        switch (*packet) {
        case IEEE80211_ELEMID_SSID:
            len=(*(packet+1));
            if ((length >= len+2) && (_SSID == nil) && (len <= 32)) {
				@try  {
					memcpy(ssid, packet+2, len);
					ssid[len]=0;
					_SSID = @(ssid);
				}
				@catch (NSException *exception) { //fallback if not UTF-8 encoded
					_SSID = [NSString stringWithCharacters:(unichar*)(packet+2) length:len];
				}
			}
            break;
		case IEEE80211_ELEMID_RATES:
		case IEEE80211_ELEMID_EXTENDED_RATES:
			len=(*(packet+1));
            if ((length >= len+2) && (len <= (MAX_RATE_COUNT - _rateCount))) {
				memcpy(&_rates[_rateCount], packet+2, len);
				_rateCount += len;
			}
			break;
        case IEEE80211_ELEMID_DSPARMS:
            len=(*(packet+1));
            if (len == 1 && length >= 3)
                _primaryChannel = (UInt8)(*(packet+2));
            break;
        case IEEE80211_ELEMID_RSN:
            // WPA2 Detecting
            len=(*(packet+1));
            if (len < 6)
                break;
            if (memcmp(packet+4, RSN_OUI, 3) == 0)
				_isWep = encryptionTypeWPA2;
            break;
        case IEEE80211_ELEMID_VENDOR:
            len=(*(packet+1));
            if (len <= 4 || length < len + 2)
                break;
			vendorID = (UInt32*)(packet+2);
			if ((*vendorID) == VENDOR_WPA_HEADER) {
				_isWep = encryptionTypeWPA;
			} else if ((*vendorID) == VENDOR_CISCO_HEADER) {
				if ((len -= 6) < 0) break;
				//if (*(packet + 6) != 0x2) break; //SSIDL Parsing
				
				UInt8 count = (*(packet+7));
				UInt8 *ssidl = (packet+8);
				UInt8 slen;
				_SSIDs = [NSMutableArray array];
				
				while (count) {
					if ((len -= 6) < 0) break;
					//if (*((UInt32*)ssidl) != 0x00000000) break; //dont know really what this is for. probably version or so
					//if (*(ssidl + 4)      != 0x10) break; //strange flag might have something todo with QOS?
					slen = (*(ssidl + 5));
					ssidl += 6;
					
					if ((len -= slen) < 0) break;
					
					@try  {
						memcpy((void*)ssid, ssidl, slen);
						ssid[slen]=0;
						[_SSIDs addObject:@(ssid)];
					}
					@catch (NSException *exception) {
						[_SSIDs addObject:[NSString stringWithCharacters:(unichar*)(ssidl) length:slen]];
					}

					ssidl += slen;
					count--;
				}
			}
            break;
        }
        
        ++packet;
        length-=(*packet)+2;
        packet+=(*packet)+1;
    }
}

//this initializes the structure with a raw frame
- (bool)parseFrame:(KFrame*) f {
    int i;
    NSMutableArray *ar;
	
    struct ieee80211_hdr *hdr1;
    struct ieee80211_hdr_3addr *hdr3;
    struct ieee80211_hdr_4addr *hdr4;
    struct ieee80211_hdr_3addrqos *hdr3qos;
    struct ieee80211_hdr_4addrqos *hdr4qos;
    struct ieee80211_probe_beacon *beacon;
    struct ieee80211_probe_request *probe_req;
    struct ieee80211_assoc_request *assoc_req;
    struct ieee80211_reassoc_request *reassoc_req;
    
    // If kframe is NULL, we reject it
    if (f == NULL)
        return NO;
    
    hdr1 = (struct ieee80211_hdr *)(f->data);
    hdr3 = (struct ieee80211_hdr_3addr *)(f->data);
    hdr4 = (struct ieee80211_hdr_4addr *)(f->data);
    hdr3qos = (struct ieee80211_hdr_3addrqos *)(f->data);
    hdr4qos = (struct ieee80211_hdr_4addrqos *)(f->data);
    
    beacon = (struct ieee80211_probe_beacon *)(f->data);
    probe_req = (struct ieee80211_probe_request *)(f->data);
    assoc_req = (struct ieee80211_assoc_request *)(f->data);
    reassoc_req = (struct ieee80211_reassoc_request *)(f->data);

    // Check IEEE80211 Version
	if ((hdr1->frame_ctl & IEEE80211_VERSION_MASK) != IEEE80211_VERSION_0) {
		DBNSLog(@"Packet with illegal 802.11 version captured.\n");
		return NO;
	}
	

    _netType = networkTypeUnknown;
    _isWep = encryptionTypeUnknown;
    _isEAP = NO;
    _revelsKeyByte = -2;

    // Set frame pointer and length
    _length = f->ctrl.len;
    _frame = (UInt8*)(f->data);
    
    // Initialize payload pointer and length
    _payload = NULL;
    _payloadLength = 0;
    
    // Set type, subtype, toDS and fromDS
    _type =    (hdr1->frame_ctl & IEEE80211_TYPE_MASK);
    _subtype = (hdr1->frame_ctl & IEEE80211_SUBTYPE_MASK);
    _isToDS = ((hdr1->frame_ctl & IEEE80211_DIR_TODS) ? YES : NO);
    _isFrDS = ((hdr1->frame_ctl & IEEE80211_DIR_FROMDS) ? YES : NO);
    
//    DBNSLog(@"%@", [WaveHelper frameControlToString:hdr1->frame_ctl]);
    // Determine frame signal strength
    _signal = f->ctrl.signal - f->ctrl.silence;
    if (_signal < 0)
        _signal=0;
    
    // Determine frame channel (received channel)
    _channel=(f->ctrl.channel>14 || f->ctrl.channel<1 ? 1 : f->ctrl.channel);
    
    // TODO: Determine frame rx rate
//    DBNSLog(@"rx_rate %d", f->ctrl.rate);
    
    // Depending on the frame type we have to figure
    // the length of the header and payload
    if (_type == IEEE80211_TYPE_DATA) {
        if (_subtype == IEEE80211_SUBTYPE_QOS_DATA) {
            if (_isToDS && _isFrDS) {
                _payload = hdr4qos->payload;
                _payloadLength = _length - sizeof(struct ieee80211_hdr_4addrqos);                
            } else {
                _payload = hdr3qos->payload;
                _payloadLength = _length - sizeof(struct ieee80211_hdr_3addrqos);
            }
        } else {
            if (_isToDS && _isFrDS) {
                _payload = hdr4->payload;
                _payloadLength = _length - sizeof(struct ieee80211_hdr_4addr);
            }
            _payload = hdr3->payload;
            _payloadLength = _length - sizeof(struct ieee80211_hdr_3addr);
        }
    } else if (_type == IEEE80211_TYPE_MGT) {
        
    } else if (_type == IEEE80211_TYPE_CTL) {
        
    }
    
    // Determine various aspect of frame
    switch(_type) {
        case IEEE80211_TYPE_DATA:               //Data Frames
            //DBNSLog(@"rx_rate %d", f->ctrl.rate);
            if (_isToDS && _isFrDS) {
                _netType = networkTypeTunnel;   //what can i say? it is a tunnel
            } else {
                // if either the from or the to ap bit set we are managed
                if (_isToDS|_isFrDS)
					_netType = networkTypeManaged;
                else if (memcmp(_addr3, "\x00\x00\x00\x00\x00\x00", 6)==0) 
					_netType = networkTypeLucentTunnel;
                else 
					_netType = networkTypeAdHoc;
            }
            if (_payload && is8021xPacket(_payload)) {
                _isEAP = YES;
                if ([self isWPAKeyPacket]) {
					_isWep = encryptionTypeWPA;                    
                } else if ([self isLEAPKeyPacket]) {
					_isWep = encryptionTypeLEAP;
                } else if (hdr1->frame_ctl & IEEE80211_WEP) {
					if (_payload[3] & WPA_EXT_IV_PRESENT) {
						_isWep = encryptionTypeWPA;                        
                    } else {
						_isWep = encryptionTypeWEP;     //is just WEP                        
                    }
				} else {
					_isWep = encryptionTypeNone;                    
                }
            } else {
                if (hdr1->frame_ctl & IEEE80211_WEP) {     //is just WEP
					if ((_length > 16) && (_payload[3] & WPA_EXT_IV_PRESENT)) {
						_isWep = encryptionTypeWPA;                        
                    } else {
						_isWep = encryptionTypeWEP;                        
                    }
				} else {
					_isWep = encryptionTypeNone;                    
                }
            }
            break;            
        case IEEE80211_TYPE_CTL: //Control Frames
            switch(_subtype) {
                case IEEE80211_SUBTYPE_PS_POLL:
                case IEEE80211_SUBTYPE_RTS:
                case IEEE80211_SUBTYPE_CTS:
                case IEEE80211_SUBTYPE_ACK:
                case IEEE80211_SUBTYPE_CF_END:
                case IEEE80211_SUBTYPE_CF_END_ACK:
				case IEEE80211_SUBTYPE_BLOCK_ACK:
				case IEEE80211_SUBTYPE_BLOCK_ACK_REQ:
                    break;
                default:
                    DBNSLog(@"%d %d", _type, _subtype);
                    return NO;
            }
            break;
        case IEEE80211_TYPE_MGT: //Management Frame
            switch (_subtype) {
                case IEEE80211_SUBTYPE_PROBE_REQ:
                    // ProbeFloodDetection
                    if (IS_BCAST_MACADDR(probe_req->header.addr3)) {
                        ar = [WaveHelper getProbeArrayForID:(char*)probe_req->header.addr2];
                        i = [ar[1] intValue];
                        if (i==-1) {
                            _netType = networkTypeProbe;
                            break;
                        }
                        if ([[NSDate date] timeIntervalSinceDate:ar[0]]>5) {
                            ar[0] = [NSDate date];
                            ar[1] = @1;
                        } else if (i>=15) { 
                            DBNSLog(@"WARNING!!! Received a Probe flood from %@. This usually means that this computer uses a cheap stumbler such as iStumbler, Macstumbler or Netstumbler!", [NSString stringWithFormat:@"%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", hdr3->addr2[0], hdr3->addr2[1], hdr3->addr2[2], hdr3->addr2[3], hdr3->addr2[4], hdr3->addr2[5]]);
                            ar[1] = @-1;
                            _netType = networkTypeProbe;
                        } else {
                            ar[1] = @(i+1);
                        }
                    }
                    break;
                case IEEE80211_SUBTYPE_PROBE_RESP:
                case IEEE80211_SUBTYPE_BEACON:
                    _isWep=((beacon->capability & IEEE80211_CAPINFO_PRIVACY) ? encryptionTypeWEP : encryptionTypeNone);
                    if (beacon->capability & IEEE80211_CAPINFO_ESS)
						_netType = networkTypeManaged;
                    else if (beacon->capability & IEEE80211_CAPINFO_IBSS)
						_netType = networkTypeAdHoc;
                    // TODO: Toggle cast
                    [self parseTaggedData:(unsigned char *)beacon->info_element length:_length-12]; //12 byte fixed info
                    break;
                case IEEE80211_SUBTYPE_ASSOC_REQ:
                    // TODO: Toggle cast
                    [self parseTaggedData:(unsigned char *)assoc_req->info_element length:_length-4]; //4 byte fixed info
                    break;
                case IEEE80211_SUBTYPE_REASSOC_REQ:
                    // TODO: Toggle cast
                    [self parseTaggedData:(unsigned char *)reassoc_req->info_element length:_length-10]; //10 byte fixed info
                    break;
                case IEEE80211_SUBTYPE_DEAUTH:
                    DBNSLog(@"ATTENTION! Received deauthentication frame. You might want to check for other WiFi people.");
					break;
            }
            break;
        default:
            DBNSLog(@"%d %d", _type, _subtype);
            return NO;
    }
	if ((memcmp(_addr2, "\x00\x90\xd0\xf8\x99\x00", 6) == 0) && (_type == IEEE80211_TYPE_DATA)) {
		DBNSLog(@"%@ %@ %@ %@ %@", [NSString stringWithFormat:@"%.2X%.2X%.2X%.2X%.2X%.2X%.2X", _addr1[0], _addr1[1], _addr1[2], _addr1[3], _addr1[4], _addr1[5], _addr1[6]],
			  [NSString stringWithFormat:@"%.2X%.2X%.2X%.2X%.2X%.2X%.2X", _addr2[0], _addr2[1], _addr2[2], _addr2[3], _addr2[4], _addr2[5], _addr2[6]], 
			  [NSString stringWithFormat:@"%.2X%.2X%.2X%.2X%.2X%.2X%.2X", _addr3[0], _addr3[1], _addr3[2], _addr3[3], _addr3[4], _addr3[5], _addr3[6]], 
			  [NSString stringWithFormat:@"%.2X%.2X%.2X%.2X%.2X%.2X%.2X", _addr4[0], _addr4[1], _addr4[2], _addr4[3], _addr4[4], _addr4[5], _addr4[6]], 
			  [WaveHelper frameControlToString:hdr1->frame_ctl]);
        [WaveHelper dumpKFrame:f];
    }
    //copy all those interesting MAC addresses
    memcpy(_addr1, hdr4->addr1, ETH_ALEN);
    memcpy(_addr2, hdr4->addr2, ETH_ALEN);
    memcpy(_addr3, hdr4->addr3, ETH_ALEN);
    memcpy(_addr4, hdr4->addr4, ETH_ALEN);

    //Set creation time (important for pcap)
    gettimeofday(&_creationTime,NULL);
    
    // Good packet.
    return YES;
}

#pragma mark -

// This function returns a unique net id for each packet. if it cannot be determined null. bssid is not useable because of tunnels
- (NSString*)IDString {
    UInt8 *m = nil;
    
    switch (_type) {
        case IEEE80211_TYPE_MGT:
            //probe requests are BS
            if (_subtype != IEEE80211_SUBTYPE_PROBE_REQ)
                m = _addr3;
            else if (_netType == networkTypeProbe)
                m = _addr2;
            break; 
        case IEEE80211_TYPE_CTL:
            if (_subtype == IEEE80211_SUBTYPE_PS_POLL)
                m = _addr1;
            break;
        case IEEE80211_TYPE_DATA:
            if((!_isToDS)&&(!_isFrDS)) {
                if (_netType == networkTypeLucentTunnel)
                    m = _addr2;
                else
                    m = _addr3;
            }
            else if((_isToDS)&&(!_isFrDS))
                m = _addr1;
            else if((!_isToDS)&&(_isFrDS))
                m = _addr2;
            else if (IS_GREATER_MACADDR(_addr1, _addr2)) {
                    m = _addr1;
                    break;
                } else if (IS_LESS_MACADDR(_addr1, _addr2)) {
                    m = _addr2;
                    break;
                }
            break;
        default:
            break;
    }
    if (m == nil)
        return nil;
    return [NSString stringWithFormat:@"%.2X%.2X%.2X%.2X%.2X%.2X%.2X", m[0], m[1], m[2], m[3], m[4], m[5], m[6]];
}

#pragma mark -
#pragma mark Client/Sender Id
#pragma mark -

- (UInt8*)rawSenderID {
    switch (_type) {
        case IEEE80211_TYPE_MGT:
            return _addr2;
        case IEEE80211_TYPE_CTL:
            if (_subtype == IEEE80211_SUBTYPE_PS_POLL)
                return _addr2;
            break;
        case IEEE80211_TYPE_DATA:
            if (!_isToDS && !_isFrDS)
                return _addr2;
            else if( _isToDS && !_isFrDS)
                return _addr2;
            else if(!_isToDS && _isFrDS)
                return _addr3;
            else
                return _addr4;
        default:
            break;
    }
    return nil;
}
- (NSString*)stringSenderID {
	UInt8* mac;
	mac = [self rawSenderID];
	
    if (!mac)
        return nil;
    return [WaveHelper macToString:mac];
}
- (bool) isSenderEqualTo: (UInt8 *)senderID {
	UInt8* mac;
	mac = [self rawSenderID];
	
    if ((senderID == NULL) || (mac == NULL)) {
        if (senderID == mac)
            return YES;
        return NO;
    }
    if (!memcmp(senderID, mac, ETH_ALEN))
        return YES;
    return NO;
}

#pragma mark -
#pragma mark Client/Receiver Id
#pragma mark -

- (UInt8*)rawReceiverID {
    switch (_type) {
        case IEEE80211_TYPE_MGT:
            return _addr1;
        case IEEE80211_TYPE_CTL:
            return _addr1;
            break;
        case IEEE80211_TYPE_DATA:
            if (!_isToDS && !_isFrDS)
                return _addr1;
            else if( _isToDS && !_isFrDS)
                return _addr3;
            else if(!_isToDS && _isFrDS)
                return _addr1;
            else
                return _addr3;
        default:
            break;
    }
    return nil;
}
- (NSString*)stringReceiverID {
	UInt8* mac;
	mac = [self rawReceiverID];
	
    if (!mac)
        return nil;
    return [WaveHelper macToString:mac];
}
- (bool) isReceiverEqualTo: (UInt8 *)receiverID {
	UInt8* mac;
	mac = [self rawReceiverID];
	
    if ((receiverID == NULL) || (mac == NULL)) {
        if (receiverID == mac)
            return YES;
        return NO;
    }
    if (!memcmp(receiverID, mac, ETH_ALEN))
        return YES;
    return NO;
}

#pragma mark -
#pragma mark BSSID
#pragma mark -

- (UInt8*)rawBSSID {
    switch (_type) {
        case IEEE80211_TYPE_MGT:
            //probe requests are BS
            if (_subtype != IEEE80211_SUBTYPE_PROBE_REQ) {
                return _addr3;                
            }
            else if (_netType == networkTypeProbe)
                return _addr2;
            break; 
        case IEEE80211_TYPE_CTL:
            if (_subtype==IEEE80211_SUBTYPE_PS_POLL)
                return _addr1;
            break;
        case IEEE80211_TYPE_DATA:
            if((!_isToDS)&&(!_isFrDS)) {
                if (_netType == networkTypeLucentTunnel)
                    return _addr2;
                else
                    return _addr3;
            }
            else if((_isToDS)&&(!_isFrDS))
                return _addr1;
            else if((!_isToDS)&&(_isFrDS))
                return _addr2;
            break;
        default:
            break;
    }
    return nil;
}
- (NSString*)BSSIDString {
	UInt8* mac;
	mac = [self rawBSSID];
	
    if (!mac)
        return @"<no bssid>";
    return [WaveHelper macToString:mac];
}
- (bool) isBSSIDEqualTo: (UInt8 *)BSSID {
	UInt8* mac;
	mac = [self rawBSSID];
	
    if ((BSSID == NULL) || (mac == NULL)) {
        if (BSSID == mac)
            return YES;
        return NO;
    }
    if (!memcmp(BSSID, mac, ETH_ALEN))
        return YES;
    return NO;
}
- (bool)BSSID:(UInt8*)bssid {
	UInt8* mac;
	mac = [self rawBSSID];
	
    if (!mac) return NO;
    memcpy(bssid, mac, ETH_ALEN);
	
    return YES;
}
- (bool)ID:(UInt8*)netid {
    UInt8 *m = nil;

    switch (_type) {
        case IEEE80211_TYPE_MGT:
            //probe requests are BS
            if (_subtype!=IEEE80211_SUBTYPE_PROBE_REQ) 
                m = _addr3;
            else if (_netType == networkTypeProbe)
                m = _addr2;
            break; 
        case IEEE80211_TYPE_CTL:
            if (_subtype==IEEE80211_SUBTYPE_PS_POLL)
                m = _addr1;
            break;
        case IEEE80211_TYPE_DATA:
            if((!_isToDS)&&(!_isFrDS)) {
                if (_netType == networkTypeLucentTunnel)
                    m = _addr2;
                else
                    m = _addr3;
            }
            else if((_isToDS)&&(!_isFrDS))
                m = _addr1;
            else if((!_isToDS)&&(_isFrDS))
                m = _addr2;
            else if (IS_GREATER_MACADDR(_addr1, _addr2)) {
                    m = _addr1;
                    break;
                } else if (IS_LESS_MACADDR(_addr1, _addr2)) {
                    m = _addr2;
                    break;
                }
            break;
        default:
            break;
    }
    if (m == nil)
        return NO;
    
    memcpy(netid, m, ETH_ALEN);
    return YES;
}

#pragma mark -
#pragma mark Initialization
#pragma mark -

-(id)init {
    if ((self = [super init]) != nil) {
        bzero(_addr1, ETH_ALEN);
        bzero(_addr2, ETH_ALEN);
        bzero(_addr3, ETH_ALEN);
        bzero(_addr4, ETH_ALEN);
        _frame = NULL;
        _payload = NULL;
    }
    return self;
}


#pragma mark -

- (int)signal {
    return _signal;
}
- (int)length {
    return _length;
}
- (int)payloadLength {
    return _payloadLength;
}
- (int)channel {
    return _channel;
}
- (int)primaryChannel {
    return _primaryChannel;
}
- (int)type {
    return _type;
}
- (int)subType {
    return _subtype;
}
- (bool)fromDS {
    return _isFrDS;
}
- (bool)toDS {
    return _isToDS;
}
- (encryptionType)wep {
    return _isWep;
}
- (networkType)netType {
    return _netType;
}
- (NSString*)SSID {
    return _SSID;
}
- (NSArray*)SSIDs {
    return _SSIDs;
}
- (bool)isCorrectSSID {
	NSString *ssid = [self SSID];
	if (ssid && [ssid length]
		&& ![ssid isEqualToString:NSLocalizedString(@"<tunnel>", "the ssid for tunnels")]
		&& ![ssid isEqualToString:NSLocalizedString(@"<lucent tunnel>", "ssid for lucent tunnels")]
		&& ![ssid isEqualToString:NSLocalizedString(@"<any ssid>", "the any ssid for probe nets")]
		&& ![ssid isEqualToString:@"<no ssid>"]
		)
	{
		return true;
	}
	
	return false;
}
- (UInt8)getRates:(UInt8*)rates {
	memcpy(rates, _rates, _rateCount);
	return _rateCount;
}
- (UInt8*) payload {
    return _payload;
}
- (UInt8*) frame {
    return _frame;
}
- (bool)isEAPPacket {
    return _isEAP;
}
- (struct timeval *)creationTime {
    return &_creationTime;
}

#pragma mark -

//which keybyte will be reveled by this packet
//-1 if none
- (int)isResolved {
    if (_revelsKeyByte != -2) return _revelsKeyByte;
    
    if ((_isWep!=encryptionTypeWEP && _isWep!=encryptionTypeWEP40) || (_type!=IEEE80211_TYPE_DATA) || (_payloadLength<9)) {
        _revelsKeyByte = -1;
        return _revelsKeyByte;
    }
        
    int a = (_payload[0] + _payload[1]) % LAST_BIT;
    int b = AMOD((_payload[0] + _payload[1]) - _payload[2], LAST_BIT);

    for(UInt8 B = 0; B < 13; ++B) {
      if((((0 <= a && a < B) ||
         (a == B && b == (B + 1) * 2)) &&
         (B % 2 ? a != (B + 1) / 2 : 1)) ||
         (a == B + 1 && (B == 0 ? b == (B + 1) * 2 : 1)) ||
         (_payload[0] == B + 3 && _payload[1] == LAST_BIT - 1) ||
         (B != 0 && !(B % 2) ? (_payload[0] == 1 && _payload[1] == (B / 2) + 1) ||
         (_payload[0] == (B / 2) + 2 && _payload[1] == (LAST_BIT - 1) - _payload[0]) : 0)) {
            //DBNSLog(@"We got a weak packet reveling byte: %u",B);
            _revelsKeyByte = B;
            return _revelsKeyByte;
        }
    }

    //DBNSLog(@"end of weak packet");
   
    _revelsKeyByte = -1;
    return _revelsKeyByte;
}
- (int)isResolved2 {
    unsigned char sum, k;
    
    if ((_isWep!=encryptionTypeWEP && _isWep!=encryptionTypeWEP40) || (_type!=IEEE80211_TYPE_DATA) || (_payloadLength<9)) return -1;

    if ((_payload[0]>3) && (_payload[2]>=254) && (_payload[1]+_payload[0]-_payload[2]==2)) 
            return 0;

    if (_payload[1] == 255 && _payload[0] > 2 && _payload[0] < 16) return _payload[0] - 3; //this is for the base line attack

    sum = _payload[0] + _payload[1];
    if (sum == 1) {
        if (_payload[2] <= 0x0A) return _payload[2] + 2;
        if (_payload[2] == 0xFF) return 0;
        return -1;
    } if (sum < 13) {
        k = 0xFE - _payload[2];
        if (sum == k) return k;
    }
    //k = 0xFE - _payload[2];
    //if (sum == k && (_payload[2] >= 0xF2 && _payload[2] <= 0xFE)) return k;

    return -1;
}

#pragma mark -
#pragma mark IP detection
#pragma mark -

// Patch Added by Dylan Neild 
// Detects and returns source IP and/or destination IP. 

// These Methods are internal methods... not for external use.

int detectLLCAndSNAP(UInt8 *fileData, int fileLength) {
    if (fileLength < 8)	
        return FALSE;
    else {
        if (fileData[0] == 0xAA &&
            fileData[1] == 0xAA &&
            fileData[2] == 0x03 &&
            fileData[3] == 0x00 &&
            fileData[4] == 0x00 &&
            fileData[5] == 0x00 &&
            fileData[6] == 0x08 &&
            fileData[7] == 0x00)
            
            return TRUE;
        else
            return FALSE;
    }
}
int detectIPVersion(UInt8 *fileData, int fileLength) {
    if (fileLength < 9)
        return -1;
    else 
        return (fileData[8] >> 4);
}
int detectIPHeaderLength(UInt8 *fileData, int fileLength) {
    
    unsigned char shiftLeft;
    
    if (fileLength < 9)
            return -1;
    else {
        shiftLeft = fileData[8] << 4;
        
        return (shiftLeft >> 4);
    }
}
int verifyIPv4Checksum(UInt8 *fileData, int fileLength) {
	
    long computedChecksum;
    //unsigned char *dataPointer;
    int i, headerLength, headerLoop;
    
    headerLength = detectIPHeaderLength(fileData, fileLength);
    headerLoop = (headerLength * 4); 
    
    if (headerLength < 5) 
        return FALSE;
    else {	
        //dataPointer = &fileData[8];
        computedChecksum = 0;
        
        for (i = 0; i < headerLoop; i=i+2) 
            computedChecksum = computedChecksum + ((fileData[8+i]<<8) + fileData[8+i+1]);
        
        computedChecksum = (computedChecksum & 0xffff) + (computedChecksum >> 16);
                        
        if (computedChecksum == 0xffff) 
            return TRUE;
        else
            return FALSE;
    }	
}
int isValidPacket(UInt8 *fileData, int fileLength) {
    if (detectLLCAndSNAP(fileData, fileLength) == TRUE) {
        // frame probably contains data. 
        
        if (detectIPVersion(fileData, fileLength) == 4) {
            // frame apparently contains an IPv4 header

            if (verifyIPv4Checksum(fileData, fileLength) == TRUE)
                return 4;
            else 
                return -1;
        }
        else if (detectIPVersion(fileData, fileLength) == 6) {
            // frame apparently contains an detects IPv6 header.
            // we don't actually do anything for this, as we don't 
            // currently support IPv6.
            // TODO add check for IPv6
            return 6;
        }
        else
            return -1;
    }
    else {
        // frame doesn't contain usable data.
        return -1;
    }
}

// Methods for external use.

#pragma mark -
#pragma mark MAC Addresses
#pragma mark -

- (UInt8 *)addr1 {
    return _addr1;
}
- (UInt8 *)addr2 {
    return _addr2;
}
- (UInt8 *)addr3 {
    return _addr3;
}
- (UInt8 *)addr4 {
    return _addr4;
}

- (NSString *)sourceIPAsString {
    
    if (isValidPacket(_payload, _payloadLength) == 4) 
        return [NSString stringWithFormat:@"%u.%u.%u.%u", *(_payload+20), *(_payload+21), *(_payload+22), *(_payload+23)];
    else
        return nil;
}
- (NSString *)destinationIPAsString {
    
    if (isValidPacket(_payload, _payloadLength) == 4)  
        return [NSString stringWithFormat:@"%u.%u.%u.%u", *(_payload+24), *(_payload+25), *(_payload+26), *(_payload+27)];
    else
        return nil;
}
- (unsigned char *)sourceIPAsData {
    unsigned char *targetAddress = (unsigned char *)malloc(sizeof(unsigned char) * 4);
    
    if (targetAddress == NULL) 
        return nil;
    else {
        if (isValidPacket(_payload, _payloadLength) == 4) {
            memcpy(targetAddress, _payload+20, 4);
            return targetAddress;
        }
        else
		{
			free(targetAddress);
			return nil;
		}
    }
}
- (unsigned char *)destinationIPAsData {
    unsigned char *targetAddress = (unsigned char *)malloc(sizeof(unsigned char) * 4);
    
    if (targetAddress == NULL) 
        return nil;
    else {
        if (isValidPacket(_payload, _payloadLength) == 4) {
            memcpy(targetAddress, _payload, 4);
            return targetAddress;
        }
        else
		{
			free(targetAddress);
			return nil;
		}
    }
}

#pragma mark -
#pragma mark WPA stuff
#pragma mark -

- (bool)isWPAKeyPacket {
    if (!_isEAP)
        return NO;
        
    UInt8 *zeroNonce[WPA_NONCE_LENGTH];
    frame8021x *f;
    UInt16 flags;
    
    if (_payloadLength < 99)
        return NO;
    
    f = (frame8021x*)(_payload+8);
    
//    if (f->version != 1)      //version 1
//        return NO;
    
    if (f->type != 3)         //should be a key
        return NO;

    if (*(_payload+12) != 254 && *(_payload+12) != 2)   //should be a WPA key or a RSN (WPA2) Key
        return NO;
        
    flags = *((UInt16*)(_payload+13));
    
    if ((flags & WPA_FLAG_KEYTYPE) == WPA_FLAG_KEYTYPE_GROUPWISE)
         return NO; //this is not interesting
    
    _wpaKeyCipher = flags & WPA_FLAG_KEYCIPHER_MASK;
    DBNSLog(@"WPA Cipher %x", _wpaKeyCipher);
    switch (flags & (WPA_FLAG_MIC | WPA_FLAG_ACK | WPA_FLAG_INSTALL)) {
        case WPA_FLAG_ACK:  //only ack set
            DBNSLog(@"frame1");
            _nonce = wpaNonceANonce;
            break;
        case WPA_FLAG_MIC:  //only mic set
            DBNSLog(@"frame2");
            memset(zeroNonce, 0, WPA_NONCE_LENGTH);
            if (memcmp(zeroNonce, _payload+25, WPA_NONCE_LENGTH))
                _nonce = wpaNonceSNonce;
            else
                _nonce = wpaNonceNone;
            break;
        case WPA_FLAG_MIC | WPA_FLAG_ACK | WPA_FLAG_INSTALL:  //all set
            DBNSLog(@"frame3");
            _nonce = wpaNonceANonce;
            break;
        default:
            _nonce = wpaNonceNone;
    }
    
    return YES;
}
- (int)wpaKeyCipher {
    return _wpaKeyCipher;
}
- (wpaNoncePresent)wpaCopyNonce:(UInt8*)destNonce {

    if (destNonce) {
        memcpy(destNonce, _payload+25, WPA_NONCE_LENGTH);
    }
    
    return _nonce;
}
- (NSData*)eapolMIC {
    UInt16 flags = *((UInt16*)(_payload+13));
    
    if ((flags & (WPA_FLAG_MIC | WPA_FLAG_ACK | WPA_FLAG_INSTALL)) != (WPA_FLAG_MIC | WPA_FLAG_ACK | WPA_FLAG_INSTALL))
        return nil; //no MIC present
    
    return [NSData dataWithBytes:(_payload+89) length:WPA_EAP_MIC_LENGTH];
}
- (NSData*)eapolData {
    UInt16 flags = *((UInt16*)(_payload+13));

    NSMutableData *md;
    
    if ((flags & (WPA_FLAG_MIC | WPA_FLAG_ACK | WPA_FLAG_INSTALL)) != (WPA_FLAG_MIC | WPA_FLAG_ACK | WPA_FLAG_INSTALL))
        return nil; //no MIC present

    md = [NSMutableData dataWithBytes:(_payload+8) length:_payloadLength - 8];    //copy the whole key packet
    memset(&((UInt8*)[md mutableBytes])[81], 0, WPA_EAP_MIC_LENGTH);
    
    return md;
}

#pragma mark -
#pragma mark LEAP stuff
#pragma mark -

- (bool)isLEAPKeyPacket {
    if (!_isEAP)
        return NO;
    frame8021x  *f;
    frameLEAP   *l;
    int         userLength;
    
    f = (frame8021x*)(_payload+8);
    l = (frameLEAP*) &f->data;
    
    if (f->version != 1 || 
        f->type != 0    || 
        l->type != 17   || //looking for LEAP
        l->version != 1) return NO;
    
    _leapCode = (leapAuthCode)l->code;
    switch (_leapCode) {
        case leapAuthCodeChallenge: //handle challenge
            userLength = l->length-16;
            if (_payloadLength-24 < userLength) return NO;
			_challenge = [NSData dataWithBytes:l->challenge length:8];
			_username = [NSString stringWithCharacters:(unichar*)&l->name length:userLength];
            break;
        case leapAuthCodeResponse:  //handle response
            if (_payloadLength-16 < 24) return NO;
			_response = [NSData dataWithBytes:l->challenge length:24];
            break; 
        default:
            break;
    }
    
    return YES;
}
- (leapAuthCode)leapCode {
    return _leapCode;
}
- (NSString*)username {
    return _username;
}
- (NSData*)challenge {
    return _challenge;
}
- (NSData*)response {
    return _response;
}

@end

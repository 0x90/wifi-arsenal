/*
        
        File:			WaveDriverAirportExtreme.m
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

#import "WaveDriverAirportExtreme.h"
#import "ImportController.h"
#import "WaveHelper.h"
#import <BIGeneric/BIGeneric.h>
#import "../Core/80211b.h"
#import <pcap.h>
#import <CoreWLAN/CoreWLAN.h>

//stolen from kismet
// Hack around some headers that don't seem to define all of these
#ifndef IEEE80211_CHAN_TURBO
#define IEEE80211_CHAN_TURBO    0x0010  /* Turbo channel */
#endif
#ifndef IEEE80211_CHAN_CCK
#define IEEE80211_CHAN_CCK      0x0020  /* CCK channel */ 
#endif
#ifndef IEEE80211_CHAN_OFDM
#define IEEE80211_CHAN_OFDM     0x0040  /* OFDM channel */
#endif
#ifndef IEEE80211_CHAN_2GHZ
#define IEEE80211_CHAN_2GHZ     0x0080  /* 2 GHz spectrum channel. */
#endif
#ifndef IEEE80211_CHAN_5GHZ
#define IEEE80211_CHAN_5GHZ     0x0100  /* 5 GHz spectrum channel */
#endif
#ifndef IEEE80211_CHAN_PASSIVE
#define IEEE80211_CHAN_PASSIVE  0x0200  /* Only passive scan allowed */
#endif
#ifndef IEEE80211_CHAN_DYN
#define IEEE80211_CHAN_DYN      0x0400  /* Dynamic CCK-OFDM channel */
#endif
#ifndef IEEE80211_CHAN_GFSK
#define IEEE80211_CHAN_GFSK     0x0800  /* GFSK channel (FHSS PHY) */
#endif

@implementation WaveDriverAirportExtreme

//we only ever want one of these
static pcap_t *_device;

+ (enum WaveDriverType) type {
    return passiveDriver;
}

+ (bool) allowsInjection {
    return NO;
}

+ (bool) allowsChannelHopping {
    return YES;
}

+ (NSString*) description {
    return NSLocalizedString(@"Apple Airport Extreme card, passive mode", "long driver description");
}

+ (NSString*) deviceName {
    return NSLocalizedString(@"Airport Extreme Card", "short driver description");
}

#pragma mark -

+ (BOOL)deviceAvailable 
{   
	CWInterface * airport = [CWInterface interfaceWithName:
                             [[CWInterface interfaceNames] allObjects][0]];
    return [airport serviceActive];
}

// return 0 for success, 1 for error, 2 for self handled error
+ (int) initBackend
{
	int ret = -1;
    
	if ([WaveDriverAirportExtreme deviceAvailable]) ret = 0;
    
    return ret;
}

+ (bool) loadBackend {
    ImportController *importController;
    int result;
    int x;
        
    do {
        importController = [[ImportController alloc] initWithWindowNibName:@"Import"];
        [importController setTitle:[NSString stringWithFormat:NSLocalizedString(@"Loading %@...", "for Backend loading"), [self description]]];
    
        [NSApp beginSheet:[importController window]
		   modalForWindow:[WaveHelper mainWindow]
			modalDelegate:nil
		   didEndSelector:nil
			  contextInfo:nil];
        
        result = [self initBackend];
    
        [NSApp endSheet: [importController window]];        
        [[importController window] close];
        [importController stopAnimation];
        importController=nil;
            
        if (result == 1) {	//see if we actually have the driver accessed
            x = [WaveHelper showCouldNotInstaniciateDialog:[self description]];
        }
    } while (result==1 && x==1);

    return (result==0);
}

+ (bool) unloadBackend
{
	
	return YES;
}

#pragma mark -
pcap_dumper_t * dumper;
- (id)init 
{
	NSUserDefaults *defs = [NSUserDefaults standardUserDefaults];
    char err[PCAP_ERRBUF_SIZE];
    NSInteger retErr = 0;
    BOOL shouldPlayback = NO;

    NSInteger dataLinks[] = {DLT_PRISM_HEADER, DLT_IEEE802_11_RADIO_AVS, DLT_IEEE802_11_RADIO, 0};
    
	_apeType = APExtTypeBcm;
    
     //get the api based interface for changing channels
    NSString *interfaceName = [[CWInterface interfaceNames] allObjects][0];
    airportInterface =  [CWInterface interfaceWithName:interfaceName];
    [airportInterface disassociate];
    
    DBNSLog(@"Airport Interface: %@", airportInterface);
    
    shouldPlayback = [[defs objectForKey: @"playback-rawdump"] boolValue];
    const char * deviceName = [interfaceName UTF8String];
    
    if (shouldPlayback)
    {
        _device = pcap_open_offline([[defs objectForKey: @"rawDumpInFile"] UTF8String], err);
    }
	else if(!_device)
    {
        _device = pcap_open_live(deviceName, 3000, 1, 2, err);
    }
    
	if (!_device && !shouldPlayback)
    {
        NSArray * args = @[@"0777", @"/dev/bpf0", @"/dev/bpf1", @"/dev/bpf2", @"/dev/bpf3"];
		if (![[BLAuthentication sharedInstance] executeCommand:@"/bin/chmod" withArgs: args]) return nil;
		[NSThread sleep:0.5];
	
        DBNSLog(@"All Airport Interfaces: %@", [[CWInterface interfaceNames] allObjects]);
        
		_device = pcap_open_live(deviceName, 3000, 1, 2, err);
        
		[[BLAuthentication sharedInstance] executeCommand:@"/bin/chmod" withArgs:args];

		if (!_device)
        {
            return nil;
        }
    }
    
    if (shouldPlayback)
    {
        DLTType = [[defs objectForKey: @"playback-rawdump-dlt"] intValue];
        DBNSLog(@"err returned from pcap open: %s", err);
        retErr = 0;
    }
    else
    {
        NSInteger i = 0;
        retErr = -1;
        while ((retErr != 0) && (dataLinks[i] != 0)) 
        {
            retErr = pcap_set_datalink(_device, dataLinks[i]);
            DLTType = dataLinks[i];
            ++i;
        };
    } 
    
    if( [[defs objectForKey: @"rawdump"] boolValue] )
    {
        if(_device) dumper = pcap_dump_open(_device, [[defs objectForKey: @"rawDumpOutFile"] UTF8String]);
        else DBNSLog(@"couldn't open dumper");
    }
    
    if (retErr != 0)
    {
        DBNSLog(@"Error opening airpot device using pcap_set_datalink()");
        return nil;
    }
    
	self = [super init];
    if(!self)
    {
        return nil;
    }

    return self;
}

#pragma mark -

- (unsigned short) getChannelUnCached 
{
	return [[airportInterface wlanChannel] channelNumber];
}

- (bool) setChannel:(unsigned short)newChannel 
{
    bool success = FALSE;
    NSError * error = nil;

	NSSet *channels = [airportInterface supportedWLANChannels];
	CWChannel *wlanChannel = nil;
	
	for (CWChannel *_wlanChannel in channels) {
		if ([_wlanChannel channelNumber] == newChannel) {
			wlanChannel = _wlanChannel;
		}
	}
	
	if (wlanChannel != nil)
		success = [airportInterface setWLANChannel:wlanChannel error: &error];
    
    //this is kindof a hack...  The airport interface may not go completely
    //into monitor mode the first time.  It can be interrupted by a "sw beacon miss"
    //The result of this is that the channel cannot be changed.  The only way to fix
    //this is to come out of monitor mode, and then go back in.  The state machine 
    //in the Apple driver must reach "Scan" mode for channel changing to work.
    //If it only makes it to "Run" mode, you will see this problem.
    //enable debug output of the driver using the airport utility
    //to see what is happening here.
    if(!success && wlanChannel)
    {
        [airportInterface disassociate];
        pcap_set_datalink(_device, 1);
        pcap_set_datalink(_device, DLTType);
        sleep(2);
        success = [airportInterface setWLANChannel:wlanChannel error: &error];
    }
        
    _currentChannel = newChannel;
    
    if(!success)
    {
        CFShow((__bridge CFTypeRef)(error));
    }
    return success;
}

- (bool) startCapture:(unsigned short)newChannel
{
    bool success = FALSE;
    
    //we lave to let go to scan...
    [airportInterface disassociate];
    
    //set dlt
    success = pcap_set_datalink(_device, DLTType);
    
    //sleep here in case it works the first time
    sleep(2);
    [self setChannel:newChannel];

    return success;
}

-(bool) stopCapture
{
    bool success;
    //restore dlt
    success = pcap_set_datalink(_device, 1);
    
    return success;
}

#pragma mark -

// wlan-ng (and hopefully others) AVS header, version one.  Fields in
// network byte order.
typedef struct __avs_80211_1_header 
{
        uint32_t version;
        uint32_t length;
        uint64_t mactime;
        uint64_t hosttime;
        uint32_t phytype;
        uint32_t channel;
        uint32_t datarate;
        uint32_t antenna;
        uint32_t priority;
        uint32_t ssi_type;
        int32_t ssi_signal;
        int32_t ssi_noise;
        uint32_t preamble;
        uint32_t encoding;
} __attribute__((__packed__)) avs_80211_1_header;

//radiotap field types
#define IEEE80211_RADIOTAP_TSFT_BIT      0
#define IEEE80211_RADIOTAP_TSFT_BYTES    8
   
#define IEEE80211_RADIOTAP_FLAGS_BIT     1
#define IEEE80211_RADIOTAP_FLAGS_BYTES   1

#define IEEE80211_RADIOTAP_RATE_BIT      2
#define IEEE80211_RADIOTAP_RATE_BYTES    1

#define IEEE80211_RADIOTAP_CHANNEL_BIT   3
#define IEEE80211_RADIOTAP_CHANNEL_BYTES 4

#define IEEE80211_RADIOTAP_DBM_TX_POWER_BIT   10
#define IEEE80211_RADIOTAP_DBM_TX_POWER_BYTES 1

#define IEEE80211_RADIOTAP_ANT_BIT       11
#define IEEE80211_RADIOTAP_ANT_BYTES     1

#define IEEE80211_RADIOTAP_DBANTSIG_BIT       12
#define IEEE80211_RADIOTAP_DBANTSIG_BYTES     1

//stolen from kismet
//todo fixme!!
/*
 * Convert MHz frequency to IEEE channel number.
 */
static u_int ieee80211_mhz2ieee(u_int freq, u_int flags) {
    if (flags & IEEE80211_CHAN_2GHZ) {		/* 2GHz band */
        if (freq == 2484)
            return 14;
        if (freq < 2484)
            return (freq - 2407) / 5;
        else
            return 15 + ((freq - 2512) / 20);
    } else if (flags & IEEE80211_CHAN_5GHZ) {	/* 5Ghz band */
        return (freq - 5000) / 5;
    } else {					/* either, guess */
        if (freq == 2484)
            return 14;
        if (freq < 2484)
            return (freq - 2407) / 5;
        if (freq < 5000)
            return 15 + ((freq - 2512) / 20);
        return (freq - 5000) / 5;
    }
}

- (KFrame*) nextFrame 
{
	struct pcap_pkthdr			header;
	const u_char				*data;
	static UInt8				frame[sizeof(KFrame)];
    KFrame						*f;
    avs_80211_1_header			*af;
    ieee80211_radiotap_header   *rtf;
    UInt16 rtHeaderLength = 0;
    UInt16 dataLen = 0;
    UInt32 rtFieldsPresent;
    UInt32 rtBit;
    UInt8 * rtDataPointer = nil;
    static UInt32 count = 0;
    
	f = (KFrame *)frame;
    //DBNSLog(@"DLT %d", DLTType);
    
	while(YES)
    {
		if (!_device) {
			continue;
		}
		
		data = pcap_next(_device, &header);
        
        if(data && dumper)
        {
            pcap_dump((unsigned char*)dumper, &header, (u_char*)data);
            pcap_dump_flush(dumper); 
        }

      /*  err = pcap_inject(_device, data,  header.caplen);
        if(err) 
        {
            DBNSLog(@"Couldn't inject frame :(");
            pcap_perror(_device, "PCAP ERROR:");
        }*/
        
		//DBNSLog(@"pcap_next: data:0x%x, len:%u\n", data, header.caplen);
		if (!data) continue;
        
        ++count;
        //DBNSLog(@"COUnt: %u", count);

        switch(DLTType)
        {
            case DLT_IEEE802_11_RADIO:
                //here we get the length of the rt header
                //this includes the length of the ieee80211_radiotap_header itself 
                rtHeaderLength = ((ieee80211_radiotap_header*)data)->it_len;
                dataLen = header.caplen - rtHeaderLength;
                if (dataLen <= 0)
                    continue;
                
                rtf = (ieee80211_radiotap_header*)data;
                //get the field's present into a u32
                rtFieldsPresent = rtf->it_present;
                
                //on my c2d it is 0x180F
                //DBNSLog(@"Raido Tap Fields present %.8x", rtFieldsPresent);
                
                //todo make this better
                //parse radiotap data
                //start at the least significant bit, process it, then shift it off
                //once all bits are processed, rtFieldsPresent should be 0
                //exiting the loop
                //DBNSLog(@"==============================================================================");
                rtBit = 0;
                //rt data is right after header
                rtDataPointer = (UInt8*)(data + sizeof(ieee80211_radiotap_header));
                //don't subtract these from dataLen, they are accounted for in the header len
                while(rtFieldsPresent)
                {
                    if(rtFieldsPresent & 0x01) //this bit is set
                    {
                        //DBNSLog(@"RT Field found %u", rtBit);
                        //increment the data pointer if by the bytes for this field
                        switch(rtBit)
                        {
                            case IEEE80211_RADIOTAP_TSFT_BIT:
                                rtDataPointer += IEEE80211_RADIOTAP_TSFT_BYTES;
                                break;
                            case IEEE80211_RADIOTAP_FLAGS_BIT:
                                rtDataPointer += IEEE80211_RADIOTAP_FLAGS_BYTES;
                                break;
                            case IEEE80211_RADIOTAP_RATE_BIT:
                                //DBNSLog(@"Rate: %u", *(UInt8*)rtDataPointer * 512); 
                                rtDataPointer += IEEE80211_RADIOTAP_RATE_BYTES;
                                break;
                            case IEEE80211_RADIOTAP_CHANNEL_BIT:
                                //DBNSLog(@"Found radiotap channel field");
                                //DBNSLog(@"Frequency: %u", *(UInt16*)rtDataPointer);
                                f->ctrl.channel = ieee80211_mhz2ieee(*(UInt16*)rtDataPointer, *(UInt16*)(rtDataPointer + 2));
                                rtDataPointer += IEEE80211_RADIOTAP_CHANNEL_BYTES;
                                break;
                            case IEEE80211_RADIOTAP_DBM_TX_POWER_BIT:
                                dataLen -= IEEE80211_RADIOTAP_DBM_TX_POWER_BYTES;  
                                rtDataPointer += IEEE80211_RADIOTAP_DBM_TX_POWER_BYTES;
                                break;
                            case IEEE80211_RADIOTAP_ANT_BIT:
                                //DBNSLog(@"Packet received on antenna %u", *(UInt8*)rtDataPointer);
                                rtDataPointer += IEEE80211_RADIOTAP_ANT_BYTES;
                                break;   
                            case IEEE80211_RADIOTAP_DBANTSIG_BIT:
                                //DBNSLog(@"Signal Db: %u", *(UInt8*)rtDataPointer);
                                f->ctrl.signal =  *(UInt8*)rtDataPointer;
                                rtDataPointer += IEEE80211_RADIOTAP_DBANTSIG_BYTES;
                                break;   
                            default:
                                DBNSLog(@"Unknown Field %i", rtBit);
                                //this is a serious error and will break everything
                                break;
                        }//end switch
                    }//end fields present 
                    //abort if we have reached the end of the data
                    //continue would just go around agian in this while loop
                    //pointless
                    if(dataLen <=0) break;
                    ++rtBit;
                    rtFieldsPresent >>= 1;
                } //end while
                //DBNSLog(@"==============================================================================");
                
                //this is the start of the data after the device header and after the 80211 header
                dataLen -= 4; //Skip FCS?
                //DBNSLog(@"Data length: %u, caplen: %u", dataLen, header.caplen);
                if (dataLen <= 0 || dataLen > header.caplen) continue;
                f->ctrl.len = dataLen;
                if(dataLen <= MAX_FRAME_BYTES)
                {
                    memcpy(f->data, rtDataPointer, dataLen);
                }
                else
                {
                    //this is probaby a garbage frame.  We should consider 
                    //skipping it but for now we just copy as much as we can 
                    //instead of crashing. todo fixme!!
                    memcpy(f->data, rtDataPointer, MAX_FRAME_BYTES);
                }

                break;
            case DLT_IEEE802_11_RADIO_AVS:
                dataLen = header.caplen - sizeof(avs_80211_1_header);
                dataLen -= 4;       // Skip fcs?
                if (dataLen <= 0)
                    continue;
               
                if(dataLen <= MAX_FRAME_BYTES)
                {
                    memcpy(f->data, data + sizeof(avs_80211_1_header), dataLen);
                }
                else
                {
                    //this is probaby a garbage frame.  We should consider 
                    //skipping it but for now we just copy as much as we can 
                    //instead of crashing. todo fixme!!
                    memcpy(f->data, data + sizeof(avs_80211_1_header), MAX_FRAME_BYTES);
                }
                
                af = (avs_80211_1_header*)data;
                f->ctrl.signal = OSSwapBigToHostInt32(af->ssi_signal) + 155;
                
                f->ctrl.silence = 0;
                
                f->ctrl.channel = OSSwapBigToHostInt32(af->channel);
                f->ctrl.len = dataLen;
                //DBNSLog(@"Got packet!!! hLen %u signal: %d  noise: %d channel %u length: %u\n", headerLength, af->ssi_signal, af->ssi_noise, f->channel, f->dataLen );
                break;
            case DLT_IEEE802_11:
                f->ctrl.len = header.caplen - 4;
                if (f->ctrl.len <= 0)
                    continue;
                f->ctrl.channel = _currentChannel;
                memcpy(f->data, data, header.caplen);
                break;
            default:
                DBNSLog(@"AE: Unknown packet format");
                DBNSLog(@"DLT %d", DLTType);
                break;
        } //switch
        ++_packets;
        return f;
    }
}

#pragma mark -

-(void) dealloc 
{
    DBNSLog(@"about to close pcap device");
	if(_device) pcap_close(_device);
}

@end

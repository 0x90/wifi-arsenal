//
//  WavePcapDump.m
//  KisMAC
//
//  Created by pr0gg3d on 6/2/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import "WavePcapDump.h"
#import "WaveHelper.h"
#import "WaveDriver.h"
#import "WavePacket.h"
#import "../Core/80211b.h"

@implementation WavePcapDump

- (id) initWithDriver:(WaveDriver *)wd andDumpFilter:(int)dumpFilter {
    self = [super initWithDriver:wd];
    
    if (!self)
        return nil;

    _dumpFilter = dumpFilter;
    NSString* path;
    char err[PCAP_ERRBUF_SIZE];
    int i;
    _f = NULL;
    _p = NULL;

    NSDictionary *d = [_driver configuration];
    NSString *dumpDestination;
    dumpDestination = d[@"dumpDestination"];

    //in the example dump are informations like 802.11 network
    path = [[[NSBundle mainBundle] resourcePath] stringByAppendingString:@"/example.dump"];
    _p = pcap_open_offline([path UTF8String],err);
    if (_p) {
        i = 1;
        
        //opens output
        path = [[NSDate date] descriptionWithCalendarFormat:[dumpDestination stringByExpandingTildeInPath]
												   timeZone:nil
													 locale:nil];
        while ([[NSFileManager defaultManager] fileExistsAtPath: path]) 
        {
            path = [[NSString stringWithFormat:@"%@.%u", dumpDestination, i] stringByExpandingTildeInPath];
            path = [[NSDate date] descriptionWithCalendarFormat:path
													   timeZone:nil
														 locale:nil];
            ++i;
        }
        
        _f = pcap_dump_open(_p, [path UTF8String]);
    } //p
    
    //error
    if(_p == NULL || _f == NULL) {
        NSBeginAlertSheet(ERROR_TITLE, 
                          OK, NULL, NULL, [WaveHelper mainWindow], self, NULL, NULL, NULL, 
                          NSLocalizedString(@"Could not create dump", "LONG error description with possible causes."),
                          //@"Could not create dump file %@. Are you sure that the permissions are set correctly?" 
                          path);
        if (_p) {
            pcap_close(_p);
            _p = NULL;
        }
        return nil;
    }
    return self;
}

- (WavePluginPacketResponse) gotPacket:(WavePacket *)packet fromDriver:(WaveDriver *)driver {
    struct pcap_pkthdr h;
    
    // Dump if needed
    if ( (_dumpFilter==1) || 
        ((_dumpFilter==2) && ([packet type] == IEEE80211_TYPE_DATA)) || 
        ((_dumpFilter==3) && ([packet isResolved]!=-1)) ) {
        memcpy(&h.ts, [packet creationTime], sizeof(struct timeval));
        h.len = h.caplen = [packet length];
        pcap_dump((u_char*)_f, &h, (u_char*)[packet frame]);
    }
    
    return WavePluginPacketResponseContinue;
}

-(void) dealloc {
    if (_f)
        pcap_dump_close(_f);
    if (_p)
        pcap_close(_p);
}

@end

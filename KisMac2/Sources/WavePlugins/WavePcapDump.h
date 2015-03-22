//
//  WavePcapDump.h
//  KisMAC
//
//  Created by pr0gg3d on 6/2/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "WavePlugin.h"
#import <pcap.h>

@interface WavePcapDump : WavePlugin {
    int _dumpFilter;
    pcap_dumper_t* _f;
    pcap_t* _p;
}

- (id) initWithDriver:(WaveDriver *)wd andDumpFilter:(int)dumpfilter;
@end

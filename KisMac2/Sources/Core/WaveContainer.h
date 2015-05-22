/*
        
        File:			WaveContainer.h
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

#import <Foundation/Foundation.h>
#import <CoreWLAN/CoreWLAN.h>
#import "WavePacket.h"

@class WaveNet;

#define MAXNETS 1000000
#define MAXCACHE 20
#define MAXFILTER 100
#define MAXCHANGED 100

#ifdef FASTLOOKUP
    #define LOOKUPSIZE 0x1000000
#else
    #define LOOKUPSIZE 0x10000
#endif

typedef struct WaveNetEntry {
    unsigned char ID[6];
    bool changed;
    __unsafe_unretained WaveNet* net;

} WaveNetEntry;

@interface WaveContainer : NSObject <NSFastEnumeration> {
    int _order;
    bool _dropAll;
    bool _ascend;
    NSLock *_sortLock;
    
    int _viewType;
    int _viewChannel;
    int _viewCrypto;
    
    NSString *_viewSSID;
    NSString *_filterString;
	NSString *_filterType;
	
    WaveNetEntry *_idList;
    unsigned int _sortedList[MAXNETS + 1];
    unsigned int _lookup[LOOKUPSIZE];
    
    //unsigned int _cache[MAXCACHE + 1];
    unsigned char _filter[MAXFILTER + 1][6];
    
    unsigned int _netCount;
    unsigned int _sortedCount;
    unsigned int _cacheSize;
    unsigned int _filterCount;
    
    NSArray *_netFields;
    NSMutableArray *_displayedNetFields;
	
	NSOperationQueue *queue;
}

//for initialisation etc...
- (void)updateSettings:(NSNotification*)note;

//for loading and saving
- (bool) loadLegacyData:(NSDictionary*)data;
- (bool) loadData:(NSArray*)data;
- (bool) importLegacyData:(NSDictionary*)data;
- (bool) importData:(NSArray*)data;
- (NSArray*) dataToSave;

//for view filtering
- (void) refreshView;
- (void) setViewType:(int)type value:(id)val;
- (void) setFilterType:(NSString*)filter; 
- (void) setFilterString:(NSString*)filter;
- (NSString*) getImageForChallengeResponse:(int)challengeResponseStatus;
- (NSString*) getStringForEncryptionType:(encryptionType)encryption; 
- (NSString*) getStringForNetType:(networkType)type;

//for sorting
- (void) sortByColumn:(NSString*)ident order:(bool)ascend;
- (void) sortWithShakerByColumn:(NSString*)ident order:(bool)ascend;

//for adding data
- (BOOL) IDFiltered:(const unsigned char*)ID;
- (bool) addPacket:(WavePacket*)p liveCapture:(bool)live;
- (bool) addAppleAPIData:(CWNetwork*)net;
- (bool) addNetwork:(WaveNet*)net;

- (unsigned int) count;
- (WaveNet*) netAtIndex:(unsigned int) index;
- (WaveNet*) netForKey:(unsigned char*) ID;
- (NSMutableArray*) allNets;

- (void) scanUpdate:(int)graphLength;
- (void) ackChanges;
- (unsigned int) nextChangedRow:(unsigned int)lastRow;

- (void) clearAllEntries;
- (void) clearEntry:(WaveNet*)net;
- (void) clearAllBrokenEntries;

@end

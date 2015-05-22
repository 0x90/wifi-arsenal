/*        
        File:			WavePluginMidi.m
        Program:		KisMAC
        Author:			Geoffrey Kruse
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

#import "WavePluginMidi.h"
#import "WaveHelper.h"
#import "WavePacket.h"

@implementation WavePluginMidi

#ifdef __i386__
    static int _numMidi;
    static NoteAllocator   na, na2;
    static NoteChannel     nc, nc2;
    static NoteRequest     nr, nr2;
#endif
static NSString *trackString,*trackStringClient;

- (WavePluginPacketResponse) gotPacket:(WavePacket *)packet fromDriver:(WaveDriver *)driver 
{
    // themacuser - sounds here
    if (([[packet BSSIDString] isEqualToString:trackString] || 
         [trackString isEqualToString:@"any"]) &&
        ([[packet stringSenderID] isEqualToString:trackStringClient] ||
         [trackStringClient isEqualToString:@"any"]))
    {
        #ifdef __i386__
            if (_numMidi == 200)
            {
                [self openChannel2:7];
            }

            if (_numMidi == 255)
            {
                _numMidi = 0;
                [self closeChannel];
                na = na2;
                nc = nc2;
                nr = nr2;
            }

            if (!nc || !na)
            {
                ComponentResult  thisError;
                na = 0;
                nc = 0;
                // Open up the note allocator.
                na = OpenDefaultComponent(kNoteAllocatorComponentType, 0);
                if (!na)
                    DBNSLog(@"Error initializing QuickTime Component");
                
                BigEndianShort s = (BigEndianShort){EndianS16_NtoB(8)};
                BigEndianFixed f = (BigEndianFixed){EndianS16_NtoB(0x00010000)};
                
                // Fill out a NoteRequest using NAStuffToneDescription to help, and
                // allocate a NoteChannel.
                nr.info.flags = 0;
                nr.info.polyphony = s;   // simultaneous tones
                nr.info.typicalPolyphony = f; // usually just one note
                thisError = NAStuffToneDescription(na, 7, &nr.tone); // 1 is piano
                thisError = NANewNoteChannel(na, &nr, &nc);			
            }

            [self playChord:[packet signal]];
            ++_numMidi;
            //	[self closeChannel];
        #endif
    }//tracking
    
    return WavePluginPacketResponseContinue;
}

#ifdef __i386__
- (void)openChannel2:(int)note 
{
	ComponentResult  thisError;
    na2 = 0;
    nc2 = 0;
    // Open up the note allocator.
    na2 = OpenDefaultComponent(kNoteAllocatorComponentType, 0);
    if (!na2)
		DBNSLog(@"Error initializing QuickTime Component");
	
	BigEndianShort s = (BigEndianShort){EndianS16_NtoB(8)};
	BigEndianFixed f = (BigEndianFixed){EndianS16_NtoB(0x00010000)};
	
    // Fill out a NoteRequest using NAStuffToneDescription to help, and
    // allocate a NoteChannel.
    nr2.info.flags = 0;
    nr2.info.polyphony = s;   // simultaneous tones
    nr2.info.typicalPolyphony = f; // usually just one note
    thisError = NAStuffToneDescription(na2, note, &nr2.tone); // 1 is piano
    thisError = NANewNoteChannel(na2, &nr2, &nc2); 	
}

- (void) playChord:(int)note
{
	int the_note = note; //  middle C == 60
	NAPlayNote(na, nc, the_note, 127);     // note at velocity 80
	[NSThread sleepUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
	the_note = 60 + 0 - 13;
	NAPlayNote(na, nc, the_note, 0);     // note at velocity 80
	
}

- (void)closeChannel 
{
	if (nc)
		NADisposeNoteChannel(na, nc);
	if (na)
		CloseComponent(na);
	
}
#else
- (void)openChannel2:(int)note {}
- (void)playChord:(int)note {}
- (void)closeChannel {}
#endif

+ (void)setTrackString:(NSString*)cs
{
	trackString = cs;
}

+ (void)setTrackStringClient:(NSString*)cs
{
	trackStringClient = cs;
}

+ (NSString*)trackString
{
	return trackString;
}

@end

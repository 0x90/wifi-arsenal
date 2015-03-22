/*
        
		File:			AirCrackWrapper.h
		Program:		KisMAC
		Author:			Michael Rossberg
						mick@binaervarianz.de
		
		Description:	KisMAC is a wireless stumbler for MacOS X.
                
        This file is part of KisMAC.

    Most parts of this file are based on aircrack by Christophe Devine.

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

#define SWAP(x,y) { unsigned char tmp = x; x = y; y = tmp; }

#define INT_INFINITY 65535
#define N_ATTACKS 17

enum KoreK_attacks
{
    A_u15,                      /* semi-stable  15%             */
    A_s13,                      /* stable       13%             */
    A_u13_1,                    /* unstable     13%             */
    A_u13_2,                    /* unstable ?   13%             */
    A_u13_3,                    /* unstable ?   13%             */
    A_s5_1,                     /* standard      5% (~FMS)      */
    A_s5_2,                     /* other stable  5%             */
    A_s5_3,                     /* other stable  5%             */
    A_u5_1,                     /* unstable      5% no good ?   */
    A_u5_2,                     /* unstable      5%             */
    A_u5_3,                     /* unstable      5% no good     */
    A_u5_4,                     /* unstable      5%             */
    A_s3,                       /* stable        3%             */
    A_4_s13,                    /* stable       13% on q = 4    */
    A_4_u5_1,                   /* unstable      5% on q = 4    */
    A_4_u5_2,                   /* unstable      5% on q = 4    */
    A_neg                       /* helps reject false positives */
};

@class ImportController;

@interface AirCrackWrapper : NSObject {
    NSData *key;
    
    /* command-line parameters */
    int debug_lvl;              /* # of keybytes fixed  */
    int stability;              /* unstable attacks on  */
    unsigned char debug[13];    /* user-defined wepkey  */
    int keyid;                  /* WEP KeyID            */
    int weplen;                 /* WEP key length       */
    int ffact;                  /* fudge threshold      */
    int nfork;                  /* number of forks      */

    /* runtime global data */
    unsigned char buffer[65536];    /* buffer for reading packets   */
    unsigned char wepkey[13];       /* the current chosen WEP key   */
    unsigned char *ivbuf;           /* buffer for the unique IVs    */
    unsigned long nb_ivs;           /* number of elements in ivbuf  */
    unsigned long tried;            /* total # of keys tried so far */
    int mc_pipe[LAST_BIT][2];            /* master->child control pipe   */
    int cm_pipe[LAST_BIT][2];            /* child->master results pipe   */
    int fudge[13];                  /* bruteforce level (1 to 256)  */
    int depth[13];                  /* how deep we are in the fudge */
    int _votes[13][N_ATTACKS][LAST_BIT];

    ImportController *_im;
    
    struct byte_stat
    {
        int index;
        int votes;
    }   wpoll[13][LAST_BIT];             /* FMS + Korek attacks: stats.  */
}

- (void)setKeyID:(int)keyID;
- (void)setKeyLen:(int)keyLen;
- (NSData*)key;
- (void)setIVs:(NSData*)ivs;
- (BOOL)attack;

@end

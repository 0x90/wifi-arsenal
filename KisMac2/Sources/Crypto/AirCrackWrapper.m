/*
        
        File:			AirCrackWrapper.m
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

#import "AirCrackWrapper.h"
#import "WaveHelper.h"
#import "ImportController.h"
#include <sys/types.h>
#include <sys/sysctl.h>

#import <unistd.h>
int coeff_attacks[4][N_ATTACKS] =
{
    { 15, 13, 12, 12, 12, 5, 5, 5, 3, 4, 3, 4, 3, 13, 4, 4, 0 },
    { 15, 13, 12, 12, 12, 5, 5, 5, 0, 0, 0, 0, 3, 13, 4, 4, 0 },
    { 15, 13,  0,  0,  0, 5, 5, 5, 0, 0, 0, 0, 0, 13, 0, 0, 0 },
    {  0, 13,  0,  0,  0, 5, 0, 0, 0, 0, 0, 0, 0,  0, 0, 0, 0 }
};


@implementation AirCrackWrapper

/* safe I/O routines */
int safe_read( int fd, void *buf, size_t len )
{
    int n;
    size_t sum = 0;
    char  *off = (char *) buf;

    while( sum < len )
    {
        if( ! ( n = read( fd, (void *) off, len - sum ) ) )
            return( 0 );

        if( n < 0 && errno == EINTR ) continue;
        if( n < 0 ) return( n );

        sum += n;
        off += n;
    }

    return( sum );
}

int safe_write( int fd, void *buf, size_t len )
{
    int n;
    size_t sum = 0;
    char  *off = (char *) buf;

    while( sum < len )
    {
        if( ( n = write( fd, (void *) off, len - sum ) ) < 0 )
        {
            if( errno == EINTR ) continue;
            return( n );
        }

        sum += n;
        off += n;
    }

    return( sum );
}

- (id)init
{
    self = [super init];
    if (!self) return nil;
	NSUserDefaults *defs;
	defs = [NSUserDefaults standardUserDefaults];
        
    /* initialize all the data */
    debug_lvl = 0;										/* # of keybytes fixed  */
    stability = 0;										/* unstable attacks on  */
    keyid  =  0;										/* WEP KeyID            */
    weplen = 13;										/* WEP key length       */
    ffact  = [[defs objectForKey:@"ac_ff"] intValue];	/* fudge threshold      */
    nfork  =  1;										/* number of forks      */

    //find number of processors and setup the same number of cracking threads
    int value;
    size_t valSize = sizeof(value);
    if (sysctlbyname ("hw.activecpu", &value, &valSize, NULL, 0) == 0){
        nfork  =  value;        
        //DBNSLog([NSString stringWithFormat:@"Creating %i cracking threads...", nfork]);
    }
      
    nb_ivs = 0;
    if (! ( ivbuf = (unsigned char *) malloc( 5 * LAST_BIT * LAST_BIT * LAST_BIT ) ) ) {
        return nil;
    }
    
    return self;
}

- (void)setKeyID:(int)keyID
{
    keyid = keyID;
}

- (void)setKeyLen:(int)keyLen
{
    weplen = keyLen;
}

- (NSData*)key
{
    return key;
}

- (void)setIVs:(NSData*)ivs
{
    NSParameterAssert(ivs);
    NSParameterAssert([ivs length] % 5 == 0);
    
    memcpy(ivbuf, [ivs bytes], [ivs length]);
    nb_ivs = [ivs length] / 5;
}


/* each child performs the attacks over nb_ivs / nfork */

- (void)calc_votes:(NSNumber*)c
{
    unsigned long xv, min, max;
    unsigned char R[LAST_BIT], jj[LAST_BIT];
    unsigned char S[LAST_BIT], Si[LAST_BIT];
    unsigned char K[16];

    unsigned char io1, o1, io2, o2;
    unsigned char Sq, dq, Kq, jq, q;
    unsigned char S1, S2, J2, t2;
    unsigned char buf[14];    /* buffer for reading packets   */
   
    int child = [c intValue];
    int i, j, B, votes[N_ATTACKS][256];

    min = 5 * ( ( (     child ) * nb_ivs ) / nfork );
    max = 5 * ( ( ( 1 + child ) * nb_ivs ) / nfork );

    for( i = 0; i < LAST_BIT; ++i )
	{
		R[i] = i;
	}

	while (true)
	{
		if( safe_read( mc_pipe[child][0], buf, 14 ) != 14 )
		{
			//perror( "in calc_votes: read()" );
			return;
		}
		
		B = (int) buf[0];
		q = 3 + B;
		
		memcpy( K + 3, buf + 1, 13 );
		memset( votes, 0, sizeof( votes ) );
		
		/*
		 *                        JABBERWOCKY
		 */
		
		for( xv = min; xv < max; xv += 5 )
		{
			memcpy( K, &ivbuf[xv], 3 );
			memcpy( S,  R, LAST_BIT );
			memcpy( Si, R, LAST_BIT );
			
			/*
			 *      `Twas brillig, and the slithy toves
			 *        Did gyre and gimble in the wabe:
			 *         All mimsy were the borogoves,
			 *          And the mome raths outgrabe.
			 */
			
			if( weplen == 13 )
			{
				for( i = j = 0; i < q; ++i )
				{
					jj[i] = j = ( j + S[i] + K[i & 15] ) & 0xFF;
					SWAP( S[i], S[j] );
				}
			}
			
			if( weplen == 5 )
			{
				for( i = j = 0; i < q; i++ )
				{
					jj[i] = j = ( j + S[i] + K[i & 7] ) & 0xFF;
					SWAP( S[i], S[j] );
				}
			}
			
			/*
			 *      Beware the Jabberwock, my son!
			 *        The jaws that bite, the claws that catch!
			 *      Beware the Jubjub bird, and shun
			 *        The frumious Bandersnatch!
			 */
			
			i = q; do { i--; SWAP(Si[i],Si[jj[i]]); } while( i != 0 );
			
			o1 = ivbuf[xv + 3] ^ 0xAA; io1 = Si[o1]; S1 = S[1];
			o2 = ivbuf[xv + 4] ^ 0xAA; io2 = Si[o2]; S2 = S[2];
			Sq = S[q]; dq = Sq + jj[q - 1];
			
			if( S2 == 0 )
			{
				if( ( S1 == 2 ) && ( o1 == 2 ) )
				{
					Kq = 1 - dq; votes[A_neg][Kq]++;
					Kq = 2 - dq; votes[A_neg][Kq]++;
				}
				else if( o2 == 0 )
				{
					Kq = 2 - dq; votes[A_neg][Kq]++;
				}
			}
			else
			{
				if( ( o2 == 0 ) && ( Sq == 0 ) )
				{
					Kq = 2 - dq; votes[A_u15][Kq]++;
				}
			}
			
			/*
			 *      He took his vorpal sword in hand:
			 *        Long time the manxome foe he sought --
			 *      So rested he by the Tumtum tree,
			 *        And stood awhile in thought.
			 */
			
			if( ( S1 == 1 ) && ( o1 == S2 ) )
			{
				Kq = 1 - dq; votes[A_neg][Kq]++;
				Kq = 2 - dq; votes[A_neg][Kq]++;
			}
			
			if( ( S1 == 0 ) && ( S[0] == 1 ) && ( o1 == 1 ) )
			{
				Kq = 0 - dq; votes[A_neg][Kq]++;
				Kq = 1 - dq; votes[A_neg][Kq]++;
			}
			
			if( S1 == q )
			{
				if( o1 == q )
				{
					Kq = Si[0] - dq; votes[A_s13][Kq]++;
				}
				else if( ( ( 1 - q - o1 ) & 0xff ) == 0 )
				{
					Kq = io1 - dq; votes[A_u13_1][Kq]++;
				}
				else if( io1 < q )
				{
					jq = Si[( io1 - q ) & 0xff];
					
					if( jq != 1 )
					{
						Kq = jq - dq; votes[A_u5_1][Kq]++;
					}
				}
			}
			
			/*
			 *      And, as in uffish thought he stood,
			 *        The Jabberwock, with eyes of flame,
			 *      Came whiffling through the tulgey wood,
			 *        And burbled as it came!
			 */
			
			if( ( io1 == 2 ) && ( S[q] == 1 ) )
			{
				Kq = 1 - dq; votes[A_u5_2][Kq]++;
			}
			
			if( S[q] == q )
			{
				if( ( S1 == 0 ) && ( o1 == q ) )
				{
					Kq = 1 - dq; votes[A_u13_2][Kq]++;
				}
				else if( ( ( ( 1 - q - S1 ) & 0xff ) == 0 ) && ( o1 == S1 ) )
				{
					Kq = 1 - dq; votes[A_u13_3][Kq]++;
				}
				else if( ( S1 >= ( ( -q ) & 0xff ) )
						&& ( ( ( q + S1 - io1 ) & 0xff ) == 0 ) )
				{
					Kq = 1 - dq; votes[A_u5_3][Kq]++;
				}
			}
			
			/*
			 *      One, two! One, two! And through and through
			 *        The vorpal blade went snicker-snack!
			 *      He left it dead, and with its head
			 *        He went galumphing back.
			 */
			
			if( ( S1 < q ) && ( ( ( S1 + S[S1] - q ) & 0xFF ) == 0 )  &&
			   ( io1 != 1 ) && ( io1 != S[S1] ) )
			{
				Kq = io1 - dq; votes[A_s5_1][Kq]++;
			}
			
			if( ( S1 > q ) && ( ( ( S2 + S1 - q ) & 0xff ) == 0 ) )
			{
				if( o2 == S1 )
				{
					jq = Si[(S1 - S2) & 0xFF];
					
					if( ( jq != 1 ) && ( jq != 2 ) )
					{
						Kq = jq - dq; votes[A_s5_2][Kq]++;
					}
				}
				else if( o2 == ( ( 2 - S2 ) & 0xFF ) )
				{
					jq = io2;
					
					if( ( jq != 1 ) && ( jq != 2 ) )
					{
						Kq = jq - dq; votes[A_s5_3][Kq]++;
					}
				}
			}
			
			/*
			 *      And, has thou slain the Jabberwock?
			 *        Come to my arms, my beamish boy!
			 *      O frabjous day! Callooh! Callay!'
			 *        He chortled in his joy.
			 */
			
			if( ( S[1] != 2 ) && ( S[2] != 0 ) )
			{
				J2 = S[1] + S[2];
				
				if( J2 < q )
				{
					t2 = S[J2] + S[2];
					
					if( ( t2 == q ) && ( io2 != 1 ) && ( io2 != 2 )
					   && ( io2 != J2 ) )
					{
						Kq = io2 - dq; votes[A_s3][Kq]++;
					}
				}
			}
			
			/*
			 *      `Twas brillig, and the slithy toves
			 *        Did gyre and gimble in the wabe:
			 *         All mimsy were the borogoves,
			 *          And the mome raths outgrabe.
			 */
			
			if( S1 == 2 )
			{
				if( q == 4 )
				{
					if( o2 == 0 )
					{
						Kq = Si[0] - dq; votes[A_4_s13][Kq]++;
					}
					else
					{
						if( ( jj[1] == 2 ) && ( io2 == 0 ) )
						{
							Kq = Si[254] - dq; votes[A_4_u5_1][Kq]++;
						}
						if( ( jj[1] == 2 ) && ( io2 == 2 ) )
						{
							Kq = Si[255] - dq; votes[A_4_u5_2][Kq]++;
						}
					}
				}
				else if( ( q > 4 ) && ( ( S[4] + 2 ) == q ) &&
						( io2 != 1 ) && ( io2 != 4 ) )
				{
					Kq = io2 - dq; votes[A_u5_4][Kq]++;
				}
			}
		}
		
		if( safe_write( cm_pipe[child][1], votes, sizeof( votes ) ) !=
		   sizeof( votes ) )
		{
			perror( "in calc_votes: write()" );
			return;
		}
	}
}

/* routine that tests if a potential key is valid */
- (BOOL) check_wepkey
{
    unsigned char K[16];
    unsigned char S[LAST_BIT];
    unsigned char R[LAST_BIT];
    unsigned char x1, x2;
    unsigned long xv = 0;
    int i, j, n, match = 0;

    memcpy( K + 3, wepkey, weplen );

    for( i = 0; i < LAST_BIT; ++i )
	{
        R[i] = i;
	}

    for( n = 0; n < 16; ++n )
    {
        xv = 5 * ( rand() % nb_ivs );

        memcpy( K, &ivbuf[xv], 3 );
        memcpy( S, R, LAST_BIT );

        for( i = j = 0; i < LAST_BIT; ++i )
        {
            j = ( j + S[i] + K[i & (2 + weplen)]) & 0xFF;
            SWAP( S[i], S[j] );
        }

        i = 1; j = ( 0 + S[i] ) & 0xFF; SWAP(S[i], S[j]);
        x1 = ivbuf[xv + 3] ^ S[(S[i] + S[j]) & 0xFF];

        i = 2; j = ( j + S[i] ) & 0xFF; SWAP(S[i], S[j]);
        x2 = ivbuf[xv + 4] ^ S[(S[i] + S[j]) & 0xFF];

        if( ( x1 == 0xAA && x2 == 0xAA ) ||
            ( x1 == 0xE0 && x2 == 0xE0 ) )
            ++match;
    }

    if( match >= 8 )
        return YES;

    return NO;
}

/* routine used to sort the votes */

int cmp_votes( const void *bs1, const void *bs2 )
{
    if( ((struct byte_stat *) bs1)->votes <
        ((struct byte_stat *) bs2)->votes )
        return(  1 );

    if( ((struct byte_stat *) bs1)->votes >
        ((struct byte_stat *) bs2)->votes )
        return( -1 );

    return( 0 );
}

/* this routine computes the average votes and recurses */

- (BOOL)do_wep_crack:(int) B
{
    int child, i, n, *vi;

    for( i = 0; i < LAST_BIT; ++i )
    {
        wpoll[B][i].index = i;
        wpoll[B][i].votes = 0;
    }

    memset( &_votes[B], 0, sizeof( _votes ) / 13 );

    /* send B and wepkey to each child */

    buffer[0] = (unsigned char) B;
    memcpy( buffer + 1, wepkey, 13 );

    for( child = 0; child < nfork; ++child )
    {
        if( safe_write( mc_pipe[child][1], buffer, 14 ) != 14 )
        {
            perror( "in do_wep_crack: write()" );
            return NO;
        }
    }

    /* collect the poll results from each child */

    for( child = 0; child < nfork; ++child )
    {
        if( safe_read( cm_pipe[child][0], buffer, sizeof( _votes ) /13 ) !=
                                                  sizeof( _votes ) /13 )
        {
            perror( "in do_wep_crack: read()" );
            return NO;
        }

        vi = (int *) buffer;

        for( n = 0; n < N_ATTACKS; ++n )
            for( i = 0; i < LAST_BIT; ++i, ++vi )
                _votes[B][n][i] += *vi;
    }

    /* compute the average vote and reject the unlikely keybytes */

    for( i = 0; i < LAST_BIT; ++i )
    {
        for( n = 0; n < N_ATTACKS; ++n )
        {
            wpoll[B][i].votes += coeff_attacks[stability][n] *
                                 _votes[B][n][i];
        }

        wpoll[B][i].votes -= 20 * _votes[B][A_neg][i];
    }

    /* set votes to the max if keybyte is user-defined */

    if( B < debug_lvl )
        wpoll[B][debug[B]].votes = INT_INFINITY;

    /* sort the votes, highest ones first */

    qsort( wpoll[B], LAST_BIT, sizeof( struct byte_stat ), cmp_votes );

    /* see how far we should go based on the number of votes */

    for( fudge[B] = 1; fudge[B] < LAST_BIT; fudge[B]++ )
        if( wpoll[B][fudge[B]].votes < wpoll[B][0].votes / ffact )
            break;

    /* try the most likely n votes, where n is our current fudge */ 

    for( depth[B] = 0; depth[B] < fudge[B]; depth[B]++ )
    {
        if( B == weplen - 1 )
            ++tried;

        if (tried % 1000 == 0 && tried != 0) {
            if ([[WaveHelper importController] canceled]) return NO;
            [[WaveHelper importController] setStatusField:[NSString stringWithFormat:NSLocalizedString(@"Checked %d,000 keys", "State for weak scheduling attack"), tried / 1000]];
        }
        wepkey[B] = wpoll[B][depth[B]].index;

        if( B == 4 && weplen == 13 )
        {
            weplen = 5;

            if([self check_wepkey])
			{
				key = [NSData dataWithBytes:wepkey length:weplen];
                return YES;
			}

            weplen = 13;
        }

        if (B < weplen - 1) {
            /* this keybyte has been set, attack the next one */
            if([self do_wep_crack:(B + 1)] == YES) return YES;
        } else {
            /* last keybyte reached, so check if wepkey is valid */

            if ([self check_wepkey] == YES) {
                key = [NSData dataWithBytes:wepkey length:weplen];
                return YES;
            }
        }
    }

    return NO;
}

- (BOOL)attack
{
    int i;
    
    _im = [WaveHelper importController];
    
    NSParameterAssert(nb_ivs > 8);
    srand( time( NULL ) );

    for( i = 0; i < nfork; ++i) {
        pipe( mc_pipe[i] );
        pipe( cm_pipe[i] );

        [NSThread detachNewThreadSelector:@selector(calc_votes:) toTarget:self withObject:@(i)];
    }

    BOOL ret = [self do_wep_crack:0];
    
    for( i = 0; i < nfork; ++i)
	{
        close( mc_pipe[i][1] );
        close( mc_pipe[i][0] );
        close( cm_pipe[i][1] );
        close( cm_pipe[i][0] );
    }
    
    return ret;
}

- (void)dealloc
{
    free(ivbuf);
    ivbuf = NULL;
}

@end

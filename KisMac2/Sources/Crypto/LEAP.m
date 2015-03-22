/*
        
        File:			LEAP.c
        Program:		KisMAC
		Author:			Michael Rossberg
						mick@binaervarianz.de
		Description:	KisMAC is a wireless stumbler for MacOS X.
                
        This file is part of KisMAC.
        
        parts of this file are stolen from asleap

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

//Big Thanks for Tim Hockin, Cobalt Networks Inc. and others

#include "LEAP.h"
#include "../3rd Party/DESSupport.h"
#include "polarssl/md4.h"

//calulate the last two bytes
int gethashlast2(const unsigned char *challenge, const unsigned char *response, unsigned char* endofhash)
{
    unsigned char zpwhash[7] = { 0, 0, 0, 0, 0, 0, 0 };
    unsigned char cipher[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

    for (int i = 0; i <= 0xffff; ++i)
	{
        zpwhash[0] = i >> 8;
        zpwhash[1] = i & 0xff;

        DesEncrypt(challenge, zpwhash, cipher);
        if (memcmp(cipher, response + 16, 8) == 0)
		{
            /* Success in calculating the last 2 of the hash */
            /* debug - printf("%2x%2x\n", zpwhash[0], zpwhash[1]); */
            endofhash[0] = zpwhash[0];
            endofhash[1] = zpwhash[1];
           
			return 0;
        }
    }

    return 1;
}

/* quick wrapper for easy md4 */

void NtPasswordHash(char *secret, int secret_len, unsigned char *hash)
{
    unsigned char unicodePassword[64];

    /* Initialize the Unicode version of the secret (== password). */
    /* This implicitly supports 8-bit ISO8859/1 characters. */
    memset(unicodePassword, 0, sizeof(unicodePassword));

    for (int i = 0; i < secret_len; ++i)
        unicodePassword[i * 2] = (unsigned char) secret[i];

    /* Unicode is 2 bytes per char */
    md4(unicodePassword, secret_len * 2, hash);
}

int testChallenge(const unsigned char* challenge, const unsigned char* response, unsigned char *zpwhash) 
{
    unsigned char cipher[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

    DesEncrypt(challenge, zpwhash, cipher);
    if (memcmp(cipher, response, 8) != 0)
	{
        return 1;
	}
	
    DesEncrypt(challenge, zpwhash + 7, cipher);
    if (memcmp(cipher, response + 8, 8) != 0)
	{
        return 1;
	}
	
    /* else - we have a match */
    return 0;
}


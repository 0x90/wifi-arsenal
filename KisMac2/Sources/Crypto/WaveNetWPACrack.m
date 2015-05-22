/*
        
        File:			WaveNetWPACrack.m
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

#import "WaveNetWPACrack.h"
#import "WaveHelper.h"
#import "WaveClient.h"
#import "WPA.h"
#import "ImportController.h"
#import "80211b.h"
#import "polarssl/sha1.h"

struct clientData {
    UInt8 ptkInput[WPA_NONCE_LENGTH+WPA_NONCE_LENGTH+12];
    const UInt8 *mic;
    const UInt8 *data;
    UInt32 dataLen;
    __unsafe_unretained NSString *clientID;
    int wpaKeyCipher;
};

#pragma mark-
#pragma mark Macros for SHA1
#pragma mark-

/* SHA1InitAndUpdateFistSmall64 - Initialize new context And fillup 64*/
void SHA1InitWithStatic64(sha1_context* context, unsigned char* staticT) {
	
	sha1_starts(context);
	sha1_process(context, staticT);
}

/* Add padding and return the message digest. */
void SHA1FinalFastWith20ByteData(unsigned char digest[20], sha1_context* context,unsigned char data[64])
{
        //memcpy(buffer, data, 20);
	memset(&data[21], 0, 41);
	data[20] = 128;
	data[62] = 2;
	data[63] = 160;

	sha1_process(context, data);

	for (UInt32 i = 0; i < 20; ++i)
	{
		digest[i] = (unsigned char)((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
	}
}

void prepared_hmac_sha1(const sha1_context *k_ipad, const sha1_context *k_opad, unsigned char digest[64])
{
    sha1_context ipad, opad;

    memcpy(&ipad, k_ipad, sizeof(ipad));
    memcpy(&opad, k_opad, sizeof(opad));
    
    /* perform inner SHA1*/
    SHA1FinalFastWith20ByteData(digest, &ipad, digest); /* finish up 1st pass */ 
    
    /* perform outer SHA1 */ 
    SHA1FinalFastWith20ByteData(digest, &opad, digest); /* finish up 2nd pass */
}

#pragma mark -
#pragma mark optimized WPA password -> PMK mapping
#pragma mark -

void fastF(unsigned char *password, int pwdLen, const unsigned char *ssid, int ssidlength, const sha1_context *ipadContext, const sha1_context *opadContext, int count, unsigned char output[40])
{
    unsigned char digest[64], digest1[64];
    
    /* U1 = PRF(P, S || int(i)) */ 
    memcpy(digest1, ssid, ssidlength);
    digest1[ssidlength]   = 0;   
    digest1[ssidlength+1] = 0; 
    digest1[ssidlength+2] = 0;
    digest1[ssidlength+3] = (unsigned char)(count & 0xff); 
    
    fast_hmac_sha1(digest1, ssidlength+4, password, pwdLen, digest);
    
    /* output = U1 */ 
    memcpy(output, digest, SHA_DIGEST_LENGTH);

	int j;
    for (int i = 1; i < 4096; ++i) {
        /* Un = PRF(P, Un-1) */ 
        prepared_hmac_sha1(ipadContext, opadContext, digest); 
    
        j = 0;
        /* output = output xor Un */
        ((int*)output)[j] ^= ((int*)digest)[j]; ++j;
        ((int*)output)[j] ^= ((int*)digest)[j]; ++j;
        ((int*)output)[j] ^= ((int*)digest)[j]; ++j;
        ((int*)output)[j] ^= ((int*)digest)[j]; ++j;
        ((int*)output)[j] ^= ((int*)digest)[j];
    }
} 


void fastWP_passwordHash(char *password, const unsigned char *ssid, int ssidlength, unsigned char output[40])
{
    unsigned char k_ipad[65]; /* inner padding - key XORd with ipad */ 
    unsigned char k_opad[65]; /* outer padding - key XORd with opad */
    sha1_context ipadContext, opadContext;
    int pwdLen = strlen(password);
    
    /* XOR key with ipad and opad values */ 
    for (int i = 0; i < pwdLen; ++i) {
        k_ipad[i] = password[i] ^ 0x36; 
        k_opad[i] = password[i] ^ 0x5c;
    } 

    memset(&k_ipad[pwdLen], 0x36, sizeof k_ipad - pwdLen); 
    memset(&k_opad[pwdLen], 0x5c, sizeof k_opad - pwdLen); 

    SHA1InitWithStatic64(&ipadContext, k_ipad);
    SHA1InitWithStatic64(&opadContext, k_opad);
 
    fastF((UInt8*)password, pwdLen, ssid, ssidlength, &ipadContext, &opadContext, 1, output);
    fastF((UInt8*)password, pwdLen, ssid, ssidlength, &ipadContext, &opadContext, 2, &output[SHA_DIGEST_LENGTH]); 
} 

#pragma mark -

@implementation WaveNet(WPACrackExtension)

- (BOOL)crackWPAWithWordlist:(NSString*)wordlist andImportController:(ImportController*)im
{
    char wrd[100];
    const char *ssid = 0;
    FILE* fptr = NULL;
    unsigned int i, j, words, ssidLength, keys, curKey;
    UInt8 pmk[40], ptk[64], digest[16];
    struct clientData *c;
    WaveClient *wc;
    const UInt8 *anonce, *snonce;
    UInt8 prefix[] = "Pairwise key expansion";

    fptr = fopen([wordlist UTF8String], "r");
    if (!fptr)
	{
		return NO;
	}
    
    keys = 0;
    for (i = 0; i < [aClientKeys count]; ++i)
	{
        if ([aClients[aClientKeys[i]] eapolDataAvailable])
            ++keys;
    }

    NSAssert(keys!=0, @"There must be more keys");
    
    curKey = 0;
    c = malloc(keys * sizeof(struct clientData));
    
    for (i = 0; i < [aClientKeys count]; ++i)
	{
        wc = aClients[aClientKeys[i]];
        if ([wc eapolDataAvailable])
		{
            if ([[wc ID] isEqualToString: _BSSID])
			{
                keys--;
            }
			else
			{
                if (memcmp(_rawBSSID, [[wc rawID] bytes], 6) > 0)
				{
                    memcpy(&c[curKey].ptkInput[0], [[wc rawID] bytes] , 6);
                    memcpy(&c[curKey].ptkInput[6], _rawBSSID, 6);
                }
				else
				{
                    memcpy(&c[curKey].ptkInput[0], _rawBSSID, 6);
                    memcpy(&c[curKey].ptkInput[6], [[wc rawID] bytes] , 6);
                }
                
                anonce = [[wc aNonce] bytes]; 
                snonce = [[wc sNonce] bytes];
                
				if (memcmp(anonce, snonce, WPA_NONCE_LENGTH) > 0)
				{
                    memcpy(&c[curKey].ptkInput[12],                     snonce, WPA_NONCE_LENGTH);
                    memcpy(&c[curKey].ptkInput[12 + WPA_NONCE_LENGTH],  anonce, WPA_NONCE_LENGTH);
                }
				else
				{
                    memcpy(&c[curKey].ptkInput[12],                     anonce, WPA_NONCE_LENGTH);
                    memcpy(&c[curKey].ptkInput[12 + WPA_NONCE_LENGTH],  snonce, WPA_NONCE_LENGTH);
                }

                c[curKey].data          = [[wc eapolPacket] bytes];
                c[curKey].dataLen       = [[wc eapolPacket] length];
                c[curKey].mic           = [[wc eapolMIC]    bytes];
                c[curKey].clientID      = [wc ID];
                c[curKey].wpaKeyCipher  = [wc wpaKeyCipher];
                ++curKey;
            }
        }
    }

    words = 0;
    wrd[90] = 0;

    ssid = [_SSID UTF8String];
    ssidLength = [_SSID lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
  
    float theTime, prevTime = clock() / (float)CLK_TCK;
	
    while(![im canceled] && !feof(fptr))
    {
        //get the line from the file
        fgets(wrd, 90, fptr);
        
        //get the length.  no need to account for linefeed because it will
        //be done below.  Remember indexed from 0
        i = strlen(wrd) - 1;
        
        //passwords must be shorter than 63 signs
        if (i < 8 || i > 63) continue;
    
        //remove the linefeed by setting the last char to null
        //if we still have line feed chars, keep going
        while('\r' == wrd[i] || '\n' == wrd[i])
        {
            wrd[i--] = 0;
        }
        
        //switch i back to length instead of an index into the array
        //this is kinda dumb
        i = strlen(wrd);
        
        ++words;

        if (words % 500 == 0)
        {
            theTime =clock() / (float)CLK_TCK;
            [im setStatusField:[NSString stringWithFormat:@"%d words tested    %.2f/second", words, 500.0 / (theTime - prevTime)]];
            prevTime = theTime;
        }
        
        for(j = 0; j < i; ++j)
		{
            if ((wrd[j] < 32) || (wrd[j] > 126))
			{
				break;
			}
		}
		
        if ( j!=i ) continue;
        
        fastWP_passwordHash(wrd, (const UInt8*)ssid, ssidLength, pmk);
    
        for (curKey = 0; curKey < keys; ++curKey)
		{
            PRF(pmk, 32, prefix, strlen((char *)prefix), c[curKey].ptkInput, WPA_NONCE_LENGTH*2 + 12, ptk, 16);
            
            if (c[curKey].wpaKeyCipher == 1)
			{
                fast_hmac_md5(c[curKey].data, c[curKey].dataLen, ptk, 16, digest);
			}
            else
			{
                fast_hmac_sha1((unsigned char*)c[curKey].data, c[curKey].dataLen, ptk, 16, digest);
            }
			
            if (memcmp(digest, c[curKey].mic, 16) == 0)
			{
                _password = [NSString stringWithFormat:@"%s for Client %@", wrd, c[curKey].clientID];
                fclose(fptr);
                
				DBNSLog(@"Cracking was successful. Password is <%s> for Client %@", wrd, c[curKey].clientID);
                free(c);
                
				return YES;
            }
        }
    }
    
    free(c);
    fclose(fptr);
    
    _crackErrorString = NSLocalizedString(@"The key was none of the tested passwords.", @"Error description for WPA crack.");
	
    return NO;
}

- (void)performWordlistWPA:(NSString*)wordlist
{
    @autoreleasepool {
        BOOL successful = NO;
	
		NSParameterAssert((_isWep == encryptionTypeWPA) || (_isWep == encryptionTypeWPA2));
        NSParameterAssert(_SSID);
		NSParameterAssert([_SSID length] <= 32);
		NSParameterAssert([self capturedEAPOLKeys] > 0);
		NSParameterAssert(_password == nil);
		NSParameterAssert(wordlist);

        if ([self crackWPAWithWordlist:[wordlist stringByExpandingTildeInPath] andImportController:[WaveHelper importController]])
		{
			successful = YES;
		}
        
        [[WaveHelper importController] terminateWithCode: (successful) ? 1 : -1];
	}
}

@end

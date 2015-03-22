/*
        
        File:			WaveNetLEAPCrack.m
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

#import "WaveNetLEAPCrack.h"
#import "LEAP.h"
#import "WaveClient.h"
#import "WaveHelper.h"
#import "ImportController.h"

struct leapClientData
{
    const UInt8 *response;
    const UInt8 *challenge;
    UInt8    hashend[2];
    __unsafe_unretained NSString *username;
    __unsafe_unretained NSString *clientID;
};

@implementation WaveNet(LEAPCrackExtension)

- (void)performWordlistLEAP:(NSString*)wordlist
{
    @autoreleasepool {
        BOOL successful = NO;
	
		NSParameterAssert(_isWep == encryptionTypeLEAP);
		NSParameterAssert([self capturedLEAPKeys] > 0);
		NSParameterAssert(_password == nil);
		NSParameterAssert(wordlist);
	
	
		if ([self crackLEAPWithWordlist:[wordlist stringByExpandingTildeInPath] andImportController:[WaveHelper importController]])
		{
			successful = YES;
		}
	
        [[WaveHelper importController] terminateWithCode: (successful) ? 1 : -1];
	}
}

- (BOOL)crackLEAPWithWordlist:(NSString*)wordlist andImportController:(ImportController*)im
{
    char wrd[100];
    FILE* fptr = NULL;
    unsigned int i, words, curKey = 0;
	int keys = 0;
    struct leapClientData *c = NULL;
    WaveClient *wc = nil;
    UInt8 pwhash[MD4_DIGEST_LENGTH] = "";
    
    //open wordlist
    fptr = fopen([wordlist UTF8String], "r");
    if (!fptr)
	{
		return NO;
	}
    
    //initialize all the data structures
	uint aClientKeysCount = [aClientKeys count];
    for (i = 0; i < aClientKeysCount; ++i)
	{
        if ([aClients[aClientKeys[i]] leapDataAvailable])
		{
			++keys;
		}
    }
    
	if (keys > 0)
	{
		c = malloc(keys * sizeof(struct leapClientData));
	
		for (i = 0; i < aClientKeysCount; ++i)
		{
			wc = aClients[aClientKeys[i]];
			if ([wc leapDataAvailable])
			{
				if ([[wc ID] isEqualToString:_BSSID])
				{
					keys--;
				}
				else
				{
					c[curKey].username  = [wc leapUsername];
					c[curKey].challenge = [[wc leapChallenge] bytes];
					c[curKey].response  = [[wc leapResponse]  bytes];
					c[curKey].clientID  = [wc ID];
					
					//prepare our attack
					if (gethashlast2(c[curKey].challenge, c[curKey].response, c[curKey].hashend) == 0)
						++curKey;
					else 
						--keys;
				}
			}
		}
	}

    if (keys <= 0)
	{
		_crackErrorString = NSLocalizedString(@"The captured challenge response packets are not sufficient to perform this attack", @"Error description for LEAP crack.");
		if (c)
		{
			free(c);
		}
		
		return NO;
	}
    
    words = 0;
    wrd[90] = 0;

    while(![im canceled] && !feof(fptr))
	{
        fgets(wrd, 90, fptr);
        i = strlen(wrd) - 1;
        wrd[i--] = 0;
        if (wrd[i]=='\r') wrd[i] = 0;
        
        ++words;

        if (words % 100000 == 0)
		{
            [im setStatusField:[NSString stringWithFormat:@"%d words tested", words]];
        }

        if (i > 31)
		{
			continue; //dont support large passwords
		}
        
        NtPasswordHash(wrd, i+1, pwhash);

		if (c && pwhash)
		{
			for (curKey = 0; curKey < keys; ++curKey)
			{
				if (c[curKey].hashend[0] != pwhash[MD4_DIGEST_LENGTH-2] || c[curKey].hashend[1] != pwhash[MD4_DIGEST_LENGTH-1]) continue;
				if (testChallenge(c[curKey].challenge, c[curKey].response, pwhash)) continue;
				
				_password = [NSString stringWithFormat:@"%s for username %@", wrd, c[curKey].username];
				fclose(fptr);
				DBNSLog(@"Cracking was successful. Password is <%s> for username %@, client %@", wrd, c[curKey].username, c[curKey].clientID);
				free(c);
				return YES;
			}
		}
    }
    
	if (c) {
		free(c);
	}
    
    fclose(fptr);
    
    _crackErrorString = NSLocalizedString(@"The key was none of the tested passwords.", @"Error description for WPA crack.");
	
    return NO;
}

@end

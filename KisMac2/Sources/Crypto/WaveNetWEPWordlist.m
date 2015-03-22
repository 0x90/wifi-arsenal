/*
        
        File:			WaveNetWEPWordlist.h
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

#import "WaveNetWEPWordlist.h"
#import "WaveHelper.h"
#import "../3rd Party/FCS.h"
#import "../3rd Party/Apple80211.h"
#import "KisMACNotifications.h"
#import <BIGeneric/BINSExtensions.h>
#import "ImportController.h"

@implementation WaveNet(WEPWorlistCrackExtension)

- (void)performWordlist40bitApple:(NSString*)wordlist
{
	@autoreleasepool {
		FILE* fptr = NULL;
		char wrd[1000];
		unsigned int i, words, foundCRC, counter, length = 0;
		UInt8 key[16], currentGuess[16], skeletonStateArray[LAST_BIT], currentStateArray[LAST_BIT];
		UInt8 y, z, tmp, xov;
		const char *data = nil;
		BOOL isInit;
		ImportController *controller;
		
		CHECK;
		
		controller = [WaveHelper importController];
		isInit = NO;
		
		fptr = fopen([wordlist UTF8String], "r");
		if (!fptr)
		{
			RET;
		}
		
		//select the right increment function for each character set
		for (counter = 0; counter < LAST_BIT; ++counter)
		{
			skeletonStateArray[counter] = counter;
		}
		words = 0;
		wrd[990]=0;
		
		while(![controller canceled] && !feof(fptr))
		{
			fgets(wrd, 990, fptr);
			i = strlen(wrd) - 1;
			wrd[i] = 0;
			if (wrd[i - 1]=='\r')
			{
				wrd[--i] = 0;
			}
			
			++words;
			
			//Null terminate
			CFStringRef ref = CFStringCreateWithCString(kCFAllocatorDefault, wrd, kCFStringEncodingUTF8);
			if (ref)
			{
				//WirelessEncrypt(ref,(WirelessKey*)(key+3),0);
				CFRelease(ref);
			}
			
			for(i=0;i<[_packetsLog count];++i) {
				if (!isInit) {
					data = [_packetsLog[i] bytes];
					length=[(NSData*)_packetsLog[i] length];
					
					memcpy(key, data, 3);
					
					if (i==0) isInit = YES;
				}
				
				memcpy(currentStateArray, skeletonStateArray, LAST_BIT);
				y = z = 0;
				
				for (counter = 0; counter < LAST_BIT; ++counter)
				{
					z = (key[y] + currentStateArray[counter] + z);
					
					tmp = currentStateArray[counter];
					currentStateArray[counter] = currentStateArray[z];
					currentStateArray[z] = tmp;
					
					y = (y + 1) % 8;
				}
				
				foundCRC = BAD_ADDRESS;
				y = z = 0;
				
				for (counter = 4; counter < length; ++counter)
				{
					++y;
					z = currentStateArray[y] + z;
					
					tmp = currentStateArray[y];
					currentStateArray[y] = currentStateArray[z];
					currentStateArray[z] = tmp;
					
					xov = currentStateArray[y] + currentStateArray[z];
					
					foundCRC = UPDC32((data[counter] ^ currentStateArray[xov]), foundCRC);
				}
				
				if (foundCRC == ERROR_FREE_ADDRESS)
				{
					memcpy(&currentGuess, &key, 16);
					isInit=NO;
				}
				else
					break;
			}
			
			if (i >= 8) {
				_password=[NSMutableString stringWithFormat:@"%.2X", currentGuess[3]];
				for (i = 4 ; i < 8 ; ++i)
				{
					[(NSMutableString*)_password appendString:[NSString stringWithFormat:@":%.2X", currentGuess[i]]];
				}
				
				fclose(fptr);
				DBNSLog(@"Cracking was successful. Password is <%s>", wrd);
				
				SRET;
			}
			if (words % 10000 == 0)
			{
				[controller setStatusField:[NSString stringWithFormat:@"%d words tested", words]];
			}
		}
		
		fclose(fptr);
		RET;
	}
    
}

- (void)performWordlist104bitApple:(NSString*)wordlist
{
	@autoreleasepool {
		FILE* fptr = NULL;
		char wrd[1000];
		unsigned int i, words, foundCRC, counter, length = 0;
		UInt8 key[16], currentGuess[16], skeletonStateArray[LAST_BIT], currentStateArray[LAST_BIT];
		UInt8 y, z, tmp, xov;
		const char *data = nil;
		BOOL isInit;
		
		CHECK;
		
		ImportController *controller = [WaveHelper importController];
		isInit = NO;
		
		fptr = fopen([wordlist UTF8String], "r");
		if (!fptr)
		{
			RET;
		}
		
		//select the right increment function for each character set
		for (counter = 0; counter < LAST_BIT; ++counter)
		{
			skeletonStateArray[counter] = counter;
		}
		
		words = 0;
		wrd[990]=0;
		
		while(![controller canceled] && !feof(fptr))
		{
			fgets(wrd, 990, fptr);
			i = strlen(wrd) - 1;
			wrd[i] = 0;
			if (wrd[i - 1]=='\r')
			{
				wrd[--i] = 0;
			}
			
			++words;
			
			//NULL terminate
			wrd[i-1] = 0;
			CFStringRef ref = CFStringCreateWithCString(kCFAllocatorDefault, wrd, kCFStringEncodingUTF8);
			if (ref)
			{
				//WirelessEncrypt(ref,(WirelessKey*)(key+3),1);
				CFRelease(ref);
			}
			
			for(i = 0; i < [_packetsLog count]; ++i)
			{
				if (!isInit)
				{
					data = [_packetsLog[i] bytes];
					length=[(NSData*)_packetsLog[i] length];
					
					memcpy(key, data, 3);
					
					if (i==0)
					{
						isInit = YES;
					}
				}
				
				memcpy(currentStateArray, skeletonStateArray, LAST_BIT);
				y = z = 0;
				
				for (counter = 0; counter < LAST_BIT; ++counter)
				{
					z = (key[y] + currentStateArray[counter] + z);
					
					tmp = currentStateArray[counter];
					currentStateArray[counter] = currentStateArray[z];
					currentStateArray[z] = tmp;
					
					y = (y + 1) % 16;
				}
				
				foundCRC = BAD_ADDRESS;
				y = z = 0;
				
				for (counter = 4; counter < length; ++counter)
				{
					++y;
					z = currentStateArray[y] + z;
					
					tmp = currentStateArray[y];
					currentStateArray[y] = currentStateArray[z];
					currentStateArray[z] = tmp;
					
					xov = currentStateArray[y] + currentStateArray[z];
					
					foundCRC = UPDC32((data[counter] ^ currentStateArray[xov]), foundCRC);
				}
				
				if (foundCRC == ERROR_FREE_ADDRESS)
				{
					memcpy(&currentGuess, &key, 16);
					isInit = NO;
				}
				else
					break;
			}
			
			if (i >= 8) {
				_password=[NSMutableString stringWithFormat:@"%.2X", currentGuess[3]];
				for (i = 4 ; i < 16 ; ++i)
				{
					[(NSMutableString*)_password appendString:[NSString stringWithFormat:@":%.2X", currentGuess[i]]];
				}
				
				fclose(fptr);
				DBNSLog(@"Cracking was successful. Password is <%s>", wrd);
				
				SRET;
			}
			if (words % 10000 == 0)
			{
				[controller setStatusField:[NSString stringWithFormat:@"%d words tested", words]];
			}
		}
		
		fclose(fptr);
		RET;
	}
}

- (void)performWordlist104bitMD5:(NSString*)wordlist
{
	@autoreleasepool
	{
		FILE* fptr = NULL;
		char wrd[1000];
		unsigned int i, words, foundCRC, counter, length = 0;
		unsigned char key[16], currentGuess[16], skeletonStateArray[LAST_BIT], currentStateArray[LAST_BIT];
		unsigned char y, z, tmp, xov;
		const char *data = nil;
		BOOL isInit;
		
		CHECK;
		
		ImportController *controller = [WaveHelper importController];
		isInit = NO;
		
		fptr = fopen([wordlist UTF8String], "r");
		if (!fptr)
		{
			RET;
		}
		
		//select the right increment function for each character set
		for (counter = 0; counter < LAST_BIT; ++counter)
		{
			skeletonStateArray[counter] = counter;
		}
		
		words = 0;
		wrd[990]=0;
		
		while(![controller canceled] && !feof(fptr))
		{
			fgets(wrd, 990, fptr);
			i = strlen(wrd) - 1;
			wrd[i--] = 0;
			if (wrd[i]=='\r')
			{
				wrd[i] = 0;
			}
			
			++words;
			
			WirelessCryptMD5(wrd, key+3);
			
			for(i = 0 ; i < [_packetsLog count] ; ++i)
			{
				if (!isInit) {
					data = [_packetsLog[i] bytes];
					length=[(NSData*)_packetsLog[i] length];
					
					memcpy(key, data, 3);
					
					if (i==0)
					{
						isInit = YES;
					}
				}
				
				memcpy(currentStateArray, skeletonStateArray, LAST_BIT);
				y = z = 0;
				
				for (counter = 0; counter < LAST_BIT; ++counter)
				{
					z = (key[y] + currentStateArray[counter] + z);
					
					tmp = currentStateArray[counter];
					currentStateArray[counter] = currentStateArray[z];
					currentStateArray[z] = tmp;
					
					y = (y + 1) % 16;
				}
				
				foundCRC = BAD_ADDRESS;
				y = z = 0;
				
				for (counter = 4; counter < length; ++counter)
				{
					++y;
					z = currentStateArray[y] + z;
					
					tmp = currentStateArray[y];
					currentStateArray[y] = currentStateArray[z];
					currentStateArray[z] = tmp;
					
					xov = currentStateArray[y] + currentStateArray[z];
					
					foundCRC = UPDC32((data[counter] ^ currentStateArray[xov]), foundCRC);
				}
				
				if (foundCRC == ERROR_FREE_ADDRESS)
				{
					memcpy(&currentGuess, &key, 16);
					isInit = NO;
				}
				else
				{
					break;
				}
			}
			
			if (i >= 8)
			{
				_password=[NSMutableString stringWithFormat:@"%.2X", currentGuess[3]];
				for ( i = 4 ; i <  16 ; ++i)
				{
					[(NSMutableString*)_password appendString:[NSString stringWithFormat:@":%.2X", currentGuess[i]]];
				}
				
				fclose(fptr);
				DBNSLog(@"Cracking was successful. Password is <%s>", wrd);
				
				SRET;
			}
			
			if (words % 10000 == 0)
			{
				[controller setStatusField:[NSString stringWithFormat:@"%d words tested", words]];
			}
		}
		
		fclose(fptr);
		RET;
	}
}

@end

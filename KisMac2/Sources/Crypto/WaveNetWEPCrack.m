/*
        
        File:			WaveNetWEPCrack.m
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

#import "WaveNetWEPCrack.h"
#import "WaveHelper.h"
#import "../3rd Party/FCS.h"
#import "KisMACNotifications.h"
#import <BIGeneric/BINSExtensions.h>
#import "ImportController.h"

@implementation WaveNet(WEPBruteforceCrackExtension) 

- (void)performBruteforce40bitLow:(NSObject*)obj
{
	@autoreleasepool {
		unsigned int i, foundCRC, counter, length = 0;
		unsigned char key[16], currentGuess[16], skeletonStateArray[LAST_BIT], currentStateArray[LAST_BIT];
		unsigned char y, z, tmp, xov;
		const char *data = nil;
		BOOL isInit;
		ImportController *controller;
		
		CHECK;
        
		controller = [WaveHelper importController];
		
		isInit = NO;
		
		memset(key,32,16);
		
		for (counter = 0; counter < LAST_BIT; ++counter)
			skeletonStateArray[counter] = counter;
		
		while(YES)
		{
			for(i = 0; i < [_packetsLog count]; ++i) {
				
				if (!isInit)
				{
					data = [_packetsLog[i] bytes];
					length = [(NSData*)_packetsLog[i] length];
					
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
					isInit = NO;
				}
				else
					break;
			}
			
			if (i < 8)
			{
				for (int i = 3; i <= 7; ++i) {
					if (key[i] == 32)
					{
						key[i] = 48;
					}
					else if (key[i] == 57)
					{
						key[i] = 65;
					}
					else if (key[3] == 90)
					{
						key[i] = 97;
					}
					else
					{
						key[i]++;
					}
					
					if (key[i] > 122 && i < 7)
					{
						key[i] = 32;
					}
					else if (i == 7) {
						if (key[i] > 122) {
							RET;
						}
						else
						{
							[controller increment];
						}
					}
				}
			}
			else
			{
				_password = [NSMutableString stringWithFormat:@"%.2X", currentGuess[3]];
				for ( i = 4 ; i <  8 ; ++i )
					[(NSMutableString*)_password appendString:[NSString stringWithFormat:@":%.2X", currentGuess[i]]];
				
				SRET;
			}
		}
	}
}

- (void)performBruteforce40bitAlpha:(NSObject*)obj
{
	@autoreleasepool {
		unsigned int i, foundCRC, counter, length = 0;
		unsigned char key[16], currentGuess[16], skeletonStateArray[LAST_BIT], currentStateArray[LAST_BIT];
		unsigned char y, z, tmp, xov;
		const char *data = nil;
		BOOL isInit = false;
		
		CHECK;
		
		ImportController *controller = [WaveHelper importController];
		
		memset(key, 32, 16);
		
		for (counter = 0; counter < LAST_BIT; ++counter)
		{
			skeletonStateArray[counter] = counter;
		}
		
		while(YES)
		{
			for(i = 0 ; i < [_packetsLog count] ; ++i)
			{
				if (!isInit) {
					data = [_packetsLog[i] bytes];
					length = [(NSData*)_packetsLog[i] length];
					
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
					isInit = NO;
				}
				else
				{
					break;
				}
			}
			
			if (i < 8)
			{
				for (int i = 3; i <= 7; ++i) {
					if (key[i] == 32)
					{
						key[i] = 48;
					}
					else if (key[i] == 57)
					{
						key[i] = 65;
					}
					else if (key[3] == 90)
					{
						key[i] = 97;
					}
					else
					{
						key[i]++;
					}
					
					if (key[i] > 122 && i < 7)
					{
						key[i] = 32;
					}
					else if (i == 7) {
						if (key[i] > 122) {
							RET;
						}
						else
						{
							[controller increment];
						}
					}
				}
			}
			else {
				_password = [NSMutableString stringWithFormat:@"%.2X", currentGuess[3]];
				for (i = 4 ; i < 8 ; ++i)
				{
					[(NSMutableString*)_password appendString:[NSString stringWithFormat:@":%.2X", currentGuess[i]]];
				}
				
				SRET;
			}
		}
		
		RET;
	}
}

- (void)performBruteforce40bitAll:(NSObject*)obj
{
	@autoreleasepool {
		unsigned int i, foundCRC, counter, length = 0;
		unsigned char key[16], currentGuess[16], skeletonStateArray[LAST_BIT], currentStateArray[LAST_BIT];
		unsigned char y, z, tmp, xov;
		const char *data = nil;
		BOOL isInit;
		ImportController *controller;
		
		CHECK;
		
		controller = [WaveHelper importController];
		
		isInit = false;
		
		memset(key, 32, 16);
		
		for (counter = 0; counter < LAST_BIT; ++counter)
		{
			skeletonStateArray[counter] = counter;
		}
		while(YES) {
			for(i=0;i<[_packetsLog count];++i) {
				
				if (!isInit) {
					data = [_packetsLog[i] bytes];
					length = [(NSData*)_packetsLog[i] length];
					
					memcpy(key, data, 3);
					
					if (i==0) isInit = YES;
				}
				
				memcpy(currentStateArray, skeletonStateArray, LAST_BIT);
				y = z = 0;
				
				for (counter = 0; counter < LAST_BIT; ++counter) {
					z = (key[y] + currentStateArray[counter] + z);
					
					tmp = currentStateArray[counter];
					currentStateArray[counter] = currentStateArray[z];
					currentStateArray[z] = tmp;
					
					y = (y + 1) % 8;
				}
				
				foundCRC = BAD_ADDRESS;
				y = z = 0;
				
				for (counter = 4; counter < length; ++counter) {
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
			
			if (i < 8) {
				key[3]++;
				
				if (key[3]==0) {
					key[4]++;
					
					if (key[4]==0) {
						key[5]++;
						if ([controller canceled]) RET;
                        
						if (key[5]==0) {
							key[6]++;
							
							if (key[6]==0) {
								key[7]++;
								
								if (key[7]==0) {
									RET;
								} else {
									[controller increment];
								}
							}
						}
					}
				}
			}
			else {
				_password = [NSMutableString stringWithFormat:@"%.2X", currentGuess[3]];
				for (i=4;i<(8);++i)
					[(NSMutableString*)_password appendString:[NSString stringWithFormat:@":%.2X", currentGuess[i]]];
				
				SRET;
			}
		}
		
		RET;
	}
}

#define KEYLENGTH 5
#define KEYNUM 4

- (void)performBruteforceNewsham:(NSObject*)obj
{
	@autoreleasepool {
		unsigned char key[KEYNUM][KEYLENGTH + 3], skeletonStateArray[LAST_BIT], currentStateArray[LAST_BIT];
		unsigned int i, foundCRC, counter, length = 0;
		unsigned char y, z, tmp, xov, j, curGuess[16];
		unsigned int w, x, q, selKey;
		const char *data = nil;
		BOOL isInit;
		ImportController *controller;
		
		if (_password != nil) RET;
		if (_isWep != encryptionTypeWEP && _isWep != encryptionTypeWEP40) RET;
		if ([_packetsLog count] < 8) RET;
		
		controller = [WaveHelper importController];
		
		isInit = NO;
		
		memset(key,0,16);
		q = 0;
		j = 0;
		selKey = 0;
		
		//if we want to do it against 2,3,4 key we have to modifiy this
		for (i= 0; i < KEYNUM; ++i)
		{
			for(x = 0; x < KEYLENGTH; ++x)
			{
				q *= 0x343fd;
				q += 0x269ec3;
				key[i][x+3] = q >> 16;
			}
		}
		w = 0;
		
		for (counter = 0; counter < LAST_BIT; ++counter)
		{
			skeletonStateArray[counter] = counter;
		}
		
		while(true)
		{
			for( i = 0 ; i < [_packetsLog count] ; ++i )
			{
				if (!isInit)
				{
					data = [_packetsLog[i] bytes];
					length = [(NSData*)_packetsLog[i] length];
					
					selKey = data[3] & 0x03;
					memcpy(&key[selKey][0], data, 3);
					
					if (i == 0)
					{
						isInit = YES;
					}
				}
				
				memcpy(currentStateArray, skeletonStateArray, LAST_BIT);
				y = z = 0;
				
				for (counter = 0; counter < LAST_BIT; ++counter)
				{
					z = (key[selKey][y] + currentStateArray[counter] + z);
					
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
					memcpy(&curGuess, &key[selKey][0], 8);
					isInit=NO;
				}
				else
					break;
			}
			
			if (i < 8)
			{
				while (++w & 0x80808080);
				
				if (w > 0x1000000) RET;
				
				if (((char*)(&w))[1]!=j)
				{
					j = ((char*)(&w))[1];
					if ([controller canceled])
					{
						RET;
					}
					[controller increment];
				}
				q = w;
				
				for (x = 0; x < KEYNUM; ++x) {
					q = (q * 0x343fd) + 0x269ec3;
					key[x][3] = q>>16;
					
					q = (q * 0x343fd) + 0x269ec3;
					key[x][4] = q >> 16;
					
					q = (q * 0x343fd) + 0x269ec3;
					key[x][5] = q >> 16;
					
					q = (q * 0x343fd) + 0x269ec3;
					key[x][6] = q >> 16;
					
					q = (q * 0x343fd) + 0x269ec3;
					key[x][7] = q >> 16;
				}
				
			} else {
				_password = [NSMutableString stringWithFormat:@"%.2X", curGuess[3]];
				for (i=4;i<(8);++i)
				{
					[(NSMutableString*)_password appendString:[NSString stringWithFormat:@":%.2X", curGuess[i]]];
				}
				
				[(NSMutableString*)_password appendString:[NSString stringWithFormat:@" for Key %d", selKey]];
				
				SRET;
			}
		}
		
		RET;
	}
}

@end

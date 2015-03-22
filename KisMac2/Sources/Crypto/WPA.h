/*
        
        File:			WPA.h
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

#include <stdbool.h>

void fast_hmac_md5(const unsigned char *text, int text_len, unsigned char *key, int key_len, void * digest);
void hmac_md5 (const unsigned char *text, int text_len, unsigned char *key, int key_len, void * digest);
void fast_hmac_sha1( unsigned char *text, int text_len, unsigned char *key, int key_len, unsigned char *digest);
void hmac_sha1(unsigned char *text, int text_len, unsigned char *key, int key_len, unsigned char *digest);
int wpaPasswordHash(char *password, const unsigned char *ssid, int ssidlength, unsigned char *output);
void PRF(unsigned char *key, int key_len, unsigned char *prefix, int prefix_len, unsigned char *data, int data_len, unsigned char *output, int len);
void generatePTK512(UInt8* ptk, UInt8* pmk, const UInt8* anonce, const UInt8* snonce, const UInt8* bssid, const UInt8* clientMAC);


bool wpaTestPasswordHash();
/*
 * coWPAtty - Brute-force dictionary attack against WPA-PSK.
 *
 * Copyright (c) 2004, Joshua Wright <jwright@hasborg.com>
 *
 * $Id: sha1.h,v 1.1.1.1 2004/11/02 11:43:30 jwright Exp $
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See COPYING for more
 * details.
 *
 * coWPAtty is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/*
 * Significant code is graciously taken from the following:
 * wpa_supplicant by Jouni Malinen.  This tool would have been MUCH more
 * difficult for me if not for this code.  Thanks Jouni.
 */


#ifndef SHA1_H
#define SHA1_H

#ifdef OPENSSL

#include <openssl/sha.h>

#define SHA1_CTX SHA_CTX
#define SHA1Init SHA1_Init
#define SHA1Update SHA1_Update
#define SHA1Final SHA1_Final
#define SHA1Transform SHA1_Transform
#define SHA1_MAC_LEN SHA_DIGEST_LENGTH

#else /* OPENSSL */

#define SHA1_MAC_LEN 20

typedef struct {
	u32 state[5];
	u32 count[2];
    unsigned char buffer[64];
} SHA1_CTX;

void SHA1Init(SHA1_CTX *context);
void SHA1Update(SHA1_CTX *context, unsigned char *data, u32 len);
void SHA1Final(unsigned char digest[20], SHA1_CTX* context);
void SHA1Transform(u32 state[5], u32 state_out[5], unsigned char buffer[64]);

#endif /* OPENSSL */

#define USECACHED 1
#define NOCACHED 0

typedef struct {
    unsigned char k_ipad[65];
    unsigned char k_opad[65];
    unsigned char k_ipad_set;
    unsigned char k_opad_set;
} SHA1_CACHE;

void sha1_mac(unsigned char *key, unsigned int key_len,
	      unsigned char *data, unsigned int data_len,
	      unsigned char *mac);
void hmac_sha1_vector(unsigned char *key, unsigned int key_len,
		      size_t num_elem, unsigned char *addr[],
		      unsigned int *len, unsigned char *mac, int usecached);
void hmac_sha1(unsigned char *key, unsigned int key_len,
	       unsigned char *data, unsigned int data_len,
	       unsigned char *mac, int usecached);
void sha1_prf(unsigned char *key, unsigned int key_len,
	      char *label, unsigned char *data, unsigned int data_len,
	      unsigned char *buf, size_t buf_len);
void pbkdf2_sha1(char *passphrase, char *ssid, size_t ssid_len, int iterations,
		 unsigned char *buf, size_t buflen, int usecached);
void sha1_transform(u8 *state, u8 data[64]);

#endif /* SHA1_H */

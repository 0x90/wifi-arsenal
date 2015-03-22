/*
 * coWPAtty - Brute-force dictionary attack against WPA-PSK.
 *
 * Copyright (c) 2004, Joshua Wright <jwright@hasborg.com>
 *
 * $Id: md5.h,v 1.1.1.1 2004/11/02 11:43:30 jwright Exp $
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


#ifndef MD5_H
#define MD5_H

#ifdef OPENSSL

#include <openssl/md5.h>

#define MD5Init MD5_Init
#define MD5Update MD5_Update
#define MD5Final MD5_Final
#define MD5Transform MD5_Transform

#define MD5_MAC_LEN MD5_DIGEST_LENGTH

#else /* OPENSSL */

#define MD5_MAC_LEN 16

struct MD5Context {
	u32 buf[4];
	u32 bits[2];
	u8 in[64];
};

void MD5Init(struct MD5Context *context);
void MD5Update(struct MD5Context *context, unsigned char const *buf,
	       unsigned len);
void MD5Final(unsigned char digest[16], struct MD5Context *context);
void MD5Transform(u32 buf[4], u32 const in[16]);

typedef struct MD5Context MD5_CTX;

#endif /* OPENSSL */


void md5_mac(u8 *key, size_t key_len, u8 *data, size_t data_len, u8 *mac);
void hmac_md5_vector(u8 *key, size_t key_len, size_t num_elem,
		     u8 *addr[], size_t *len, u8 *mac);
void hmac_md5(u8 *key, size_t key_len, u8 *data, size_t data_len, u8 *mac);

#endif /* MD5_H */

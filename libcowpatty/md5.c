/*
 * MD5 hash implementation and interface functions
 * Copyright (c) 2003-2004, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>

#include <endian.h>
#if __BYTE_ORDER == __BIG_ENDIAN
#define WORDS_BIGENDIAN
#endif

#include "md5.h"

void md5_mac(uint8_t * key, size_t key_len, uint8_t * data, size_t data_len,
             uint8_t * mac) {
    MD5_CTX context;
    MD5Init(&context);
    MD5Update(&context, key, key_len);
    MD5Update(&context, data, data_len);
    MD5Update(&context, key, key_len);
    MD5Final(mac, &context);
}

/* HMAC code is based on RFC 2104 */
void hmac_md5_vector(uint8_t * key, size_t key_len, size_t num_elem,
                     uint8_t * addr[], size_t * len, uint8_t * mac) {
    MD5_CTX context;
    uint8_t k_ipad[65];      /* inner padding - key XORd with ipad */
    uint8_t k_opad[65];      /* outer padding - key XORd with opad */
    uint8_t tk[16];
    int i;

    /* if key is longer than 64 bytes reset it to key = MD5(key) */
    if (key_len > 64) {
        MD5Init(&context);
        MD5Update(&context, key, key_len);
        MD5Final(tk, &context);

        key = tk;
        key_len = 16;
    }

    /* the HMAC_MD5 transform looks like:
     *
     * MD5(K XOR opad, MD5(K XOR ipad, text))
     *
     * where K is an n byte key
     * ipad is the byte 0x36 repeated 64 times
     * opad is the byte 0x5c repeated 64 times
     * and text is the data being protected */

    /* start out by storing key in pads */
    memset(k_ipad, 0, sizeof(k_ipad));
    memset(k_opad, 0, sizeof(k_opad));
    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key, key_len);

    /* XOR key with ipad and opad values */
    for (i = 0; i < 64; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    /* perform inner MD5 */
    MD5Init(&context);  /* init context for 1st pass */
    MD5Update(&context, k_ipad, 64);    /* start with inner pad */
    /* then text of datagram; all fragments */
    for (i = 0; i < num_elem; i++) {
        MD5Update(&context, addr[i], len[i]);
    }
    MD5Final(mac, &context);    /* finish up 1st pass */

    /* perform outer MD5 */
    MD5Init(&context);  /* init context for 2nd pass */
    MD5Update(&context, k_opad, 64);    /* start with outer pad */
    MD5Update(&context, mac, 16);   /* then results of 1st hash */
    MD5Final(mac, &context);    /* finish up 2nd pass */
}

void hmac_md5(uint8_t * key, size_t key_len, uint8_t * data, size_t data_len,
              uint8_t * mac) {
    hmac_md5_vector(key, key_len, 1, &data, &data_len, mac);
}


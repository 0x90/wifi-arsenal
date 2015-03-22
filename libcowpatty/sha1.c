/*
 * coWPAtty - Brute-force dictionary attack against WPA-PSK.
 *
 * Copyright (c) 2004-2005, Joshua Wright <jwright@hasborg.com>
 *
 * $Id: sha1.c,v 4.1 2007/11/03 20:28:39 jwright Exp $
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
 *
 * i386 assembly SHA code taken from the umac.c message auth code by
 * Ted Krovetz (tdk@acm.org):
 * http://www.cs.ucdavis.edu/~rogaway/umac/umac.c
 * (dragorn)
 *
 * SHA1 caching and thread safe support contributed
 * by Adam Bregenzer <adam@bregenzer.net>
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "sha1.h"

/*
 * Initialize a pmk_st
 *
 */
void pmk_init(pmk_st *pmk, unsigned char *passphrase, size_t passphrase_len,
              unsigned char *ssid, size_t ssid_len) {
    size_t val_s_len = (ssid_len < MAX_SSID_LEN ?
                        ssid_len : MAX_SSID_LEN);
    size_t val_p_len = (passphrase_len < MAX_PASSPHRASE_LEN ?
                        passphrase_len : MAX_PASSPHRASE_LEN);
    uint8_t k_ipad[PADDING_LEN];    /* inner padding - key XORd with IPAD_XOR */
    uint8_t k_opad[PADDING_LEN];    /* outer padding - key XORd with OPAD_XOR */
    int i = 0; /* counter */

    /* Reset structure */
    memset(pmk, 0, sizeof(pmk));

    /* Set the ssid and passphrase */
    memcpy(pmk->ssid, ssid, val_s_len);
    memcpy(pmk->passphrase, passphrase, val_p_len);
    pmk->ssid_len = val_s_len;
    pmk->passphrase_len = val_p_len;

    /* start out by storing key in pads */
    memset(k_ipad, 0, sizeof(k_ipad));
    memset(k_opad, 0, sizeof(k_opad));
    memcpy(k_ipad, passphrase, val_p_len);
    memcpy(k_opad, passphrase, val_p_len);

    /* XOR key with ipad and opad values */
    for (i = 0; i < PADDING_LEN; i++) {
        k_ipad[i] ^= IPAD_XOR;
        k_opad[i] ^= OPAD_XOR;
    }

    /* Cache SHA contexts with padding values */
    SHA1Init(&(pmk->ipad_context));
    SHA1Init(&(pmk->opad_context));
    SHA1Update(&(pmk->ipad_context), k_ipad, PADDING_LEN);
    SHA1Update(&(pmk->opad_context), k_opad, PADDING_LEN);
}

/*
 * Compute HMAC SHA1
 *
 * HMAC code is based on RFC 2104
 * Modifications (hacks) by Joshua Wright.
 * Re-written to support caching part of the SHA1 calculation
 */
void pmk_hmac_sha1_vector(pmk_st *pmk, size_t num_elem, unsigned char *addr[],
                          unsigned int *len, unsigned char *mac)
{
    SHA1_CTX context;
    int i;

    /* perform inner SHA1 */
    memcpy(&context, &(pmk->ipad_context), sizeof(context));
    for (i = 0; i < num_elem; i++) {
        SHA1Update(&context, addr[i], len[i]);
    }
    SHA1Final(mac, &context);    /* finish up 1st pass */

    /* perform outer SHA1 */
    memcpy(&context, &(pmk->opad_context), sizeof(context));
    SHA1Update(&context, mac, SHA1_MAC_LEN);
    SHA1Final(mac, &context);    /* finish up 2nd pass */

    return;
}

/* Helper Functions */
void hmac_sha1_vector(unsigned char *key, unsigned int key_len,
                      size_t num_elem, unsigned char *addr[],
                      unsigned int *len, unsigned char *mac)
{
    pmk_st pmk;
    uint8_t ssid[] = "";

    pmk_init(&pmk, key, key_len, ssid, 0);
    pmk_hmac_sha1_vector(&pmk, num_elem, addr, len, mac);
}
void pmk_hmac_sha1(pmk_st *pmk, unsigned char *data,
                      unsigned int data_len, unsigned char *mac)
{
    pmk_hmac_sha1_vector(pmk, 1, &data, &data_len, mac);
}
void hmac_sha1(unsigned char *key, unsigned int key_len,
               unsigned char *data, unsigned int data_len, unsigned char *mac)
{
    pmk_st pmk;
    uint8_t ssid[] = "";

    pmk_init(&pmk, key, key_len, ssid, 0);
    pmk_hmac_sha1(&pmk, data, data_len, mac);
}

/*
 * Compute a digest value
 *
 */
static void pmk_pbkdf2_sha1_f(pmk_st *pmk, int count, unsigned char *digest)
{
    uint8_t tmp[SHA1_MAC_LEN], tmp2[SHA1_MAC_LEN];
    int i, j;
    uint8_t count_buf[4];
    uint8_t *addr[] = { (uint8_t *)pmk->ssid, count_buf };
    unsigned int len[] = { pmk->ssid_len, 4 };

    /* F(P, S, c, i) = U1 xor U2 xor ... Uc
     * U1 = PRF(P, S || i)
     * U2 = PRF(P, U1)
     * Uc = PRF(P, Uc-1)
     */

    count_buf[0] = (count >> 24) & 0xff;
    count_buf[1] = (count >> 16) & 0xff;
    count_buf[2] = (count >> 8) & 0xff;
    count_buf[3] = count & 0xff;

    pmk_hmac_sha1_vector(pmk, 2, addr, len, tmp);
    memcpy(digest, tmp, SHA1_MAC_LEN);

    for (i = 1; i < WPA2_SHA1_ITERATIONS; i++) {
        pmk_hmac_sha1(pmk, tmp, SHA1_MAC_LEN, tmp2);
        memcpy(tmp, tmp2, SHA1_MAC_LEN);
        for (j = 0; j < SHA1_MAC_LEN; j++)
            digest[j] ^= tmp2[j];
    }
}

/*
 * Initialize a pmk_st
 *
 */
void pmk_pbkdf2_sha1(pmk_st *pmk)
{
    int count = 0;
    uint8_t *pos = pmk->key;
    size_t left = PMK_KEY_LEN, plen;
    uint8_t digest[SHA1_MAC_LEN];

    while (left > 0) {
        count++;
        pmk_pbkdf2_sha1_f(pmk, count, digest);
        plen = (left > SHA1_MAC_LEN ? SHA1_MAC_LEN : left);
        memcpy(pos, digest, plen);
        pos += plen;
        left -= plen;
    }
}


void sha1_prf(unsigned char *key, unsigned int key_len,
          char *label, unsigned char *data, unsigned int data_len,
          unsigned char *buf, size_t buf_len)
{

    char zero = 0, counter = 0;
    size_t pos, plen;
    uint8_t hash[SHA1_MAC_LEN];
    size_t label_len = strlen(label);
    unsigned char *addr[] = { (unsigned char *)label,
        (unsigned char *)&zero,
        data,
        (unsigned char *)&counter };
    unsigned int len[] = { label_len, 1, data_len, 1 };

    pos = 0;
    while (pos < buf_len) {
        plen = buf_len - pos;
        if (plen >= SHA1_MAC_LEN) {
            hmac_sha1_vector(key, key_len, 4, addr, len, &buf[pos]);
            pos += SHA1_MAC_LEN;
        } else {
            hmac_sha1_vector(key, key_len, 4, addr, len, hash);
            memcpy(&buf[pos], hash, plen);
            break;
        }
        counter++;
    }
}


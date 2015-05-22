/*
 * coWPAtty - Brute-force dictionary attack against WPA-PSK.
 *
 * Copyright (c) 2004-2005, Joshua Wright <jwright@hasborg.com>
 *
 * $Id: sha1.h,v 4.0 2006/07/28 12:23:48 jwright Exp $
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
 * SHA1 caching and thread safe support contributed
 * by Adam Bregenzer <adam@bregenzer.net>
 */

#ifndef SHA1_H
#define SHA1_H

#include <stdint.h>
#include <openssl/sha.h>

#define SHA1_CTX        SHA_CTX
#define SHA1Init        SHA1_Init
#define SHA1Update      SHA1_Update
#define SHA1Final       SHA1_Final
#define SHA1_MAC_LEN    SHA_DIGEST_LENGTH

#define PADDING_LEN               64
#define IPAD_XOR                0x36
#define OPAD_XOR                0x5c
#define WPA2_SHA1_ITERATIONS    4096
#define PMK_KEY_LEN               32
#define MAX_SSID_LEN             255
#define MAX_PASSPHRASE_LEN        63


typedef struct PMK_ST {
    uint8_t ssid[MAX_SSID_LEN + 1]; /* The ssid being used.                   */
    size_t ssid_len;                /* The length of the ssid.                */
    uint8_t passphrase[MAX_PASSPHRASE_LEN + 1]; /* The passphrase to encrypt. */
    size_t passphrase_len;          /* The length of the passphrase.          */
    uint8_t key[PMK_KEY_LEN];       /* The resulting pmk value.               */
    SHA1_CTX ipad_context;          /* A fresh ipad SHA1 context.             */
    SHA1_CTX opad_context;          /* A fresh opad SHA1 context.             */
} pmk_st;


/*
 * Initialize a pmk_st
 *
 */
void pmk_init(pmk_st *pmk, unsigned char *passphrase, size_t passphrase_len,
              unsigned char *ssid, size_t ssid_len);
void pmk_pbkdf2_sha1(pmk_st *pmk);
void pmk_hmac_sha1_vector(pmk_st *pmk, size_t num_elem, unsigned char *addr[],
                          unsigned int *len, unsigned char *mac);
void hmac_sha1_vector(unsigned char *key, unsigned int key_len,
                      size_t num_elem, unsigned char *addr[],
                      unsigned int *len, unsigned char *mac);
void pmk_hmac_sha1(pmk_st *pmk, unsigned char *data,
                   unsigned int data_len, unsigned char *mac);
void hmac_sha1(unsigned char *key, unsigned int key_len,
               unsigned char *data, unsigned int data_len, unsigned char *mac);
void sha1_prf(unsigned char *key, unsigned int key_len,
          char *label, unsigned char *data, unsigned int data_len,
          unsigned char *buf, size_t buf_len);

#endif                /* SHA1_H */

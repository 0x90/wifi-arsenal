/*
 * libcoWPAtty - Brute-force dictionary attack against WPA-PSK.
 *
 * Copyright (c) 2004-2005, Joshua Wright <jwright@hasborg.com>
 * Copyright (c) 2008-2013, Adam Bregenzer <adam@bregenzer.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See COPYING for more
 * details.
 *
 * libcoWPAtty is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/*
 * Significant code is graciously taken from the following:
 * wpa_supplicant by Jouni Malinen.  This tool would have been MUCH more
 * difficult for me if not for this code.  Thanks Jouni.
 */

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "sha1.h"
#include "md5.h"
#include "libcowpatty.h"
#include "../cowpatty.h"
#include "../libattkthread/libattkthread.h"
#include "../libattkthread/read_file.h"
#include "../libattkthread/write_file.h"
#include "../libattkthread/brute_force.h"
#include "../config.h"

static void wpa_pmk_to_ptk(uint8_t *pmk, uint8_t *addr1, uint8_t *addr2,
                           uint8_t *nonce1, uint8_t *nonce2, uint8_t *ptk,
                           size_t ptk_len) {
    uint8_t data[2 * ETH_ALEN + 2 * 32];

    memset(&data, 0, sizeof(data));

    /* PTK = PRF-X(PMK, "Pairwise key expansion",
     *             Min(AA, SA) || Max(AA, SA) ||
     *             Min(ANonce, SNonce) || Max(ANonce, SNonce)) */

    if (memcmp(addr1, addr2, ETH_ALEN) < 0) {
        memcpy(data, addr1, ETH_ALEN);
        memcpy(data + ETH_ALEN, addr2, ETH_ALEN);
    } else {
        memcpy(data, addr2, ETH_ALEN);
        memcpy(data + ETH_ALEN, addr1, ETH_ALEN);
    }

    if (memcmp(nonce1, nonce2, 32) < 0) {
        memcpy(data + 2 * ETH_ALEN, nonce1, 32);
        memcpy(data + 2 * ETH_ALEN + 32, nonce2, 32);
    } else {
        memcpy(data + 2 * ETH_ALEN, nonce2, 32);
        memcpy(data + 2 * ETH_ALEN + 32, nonce1, 32);
    }

    sha1_prf(pmk, 32, "Pairwise key expansion", data, sizeof(data),
         ptk, ptk_len);
}


static void hmac_hash(int ver, uint8_t *key, int hashlen, uint8_t *buf,
                      int buflen, uint8_t *mic) {
    uint8_t hash[SHA1_MAC_LEN];

    if (ver == WPA_KEY_INFO_TYPE_HMAC_MD5_RC4) {
        hmac_md5(key, hashlen, buf, buflen, mic);
    } else if (ver == WPA_KEY_INFO_TYPE_HMAC_SHA1_AES) {
        hmac_sha1(key, hashlen, buf, buflen, hash);
        memcpy(mic, hash, MD5_MAC_LEN); /* only 16 bytes, not 20 */
    }
}


int cowp_check_word(char *word, size_t word_size, char *ret_record,
                    size_t return_size, void *data) {
    cowp_attack_data *cdata = (cowp_attack_data *)data;
    pmk_st pmk;
    uint8_t ptk[64];
    uint8_t keymic[16];
    struct wpa_ptk *ptkset;
    size_t word_len;

    word_len = strlen(word);
    memset(ptk, 0, 64);

    /* Test length of word. */
    /* IEEE 802.11i indicates the passphrase
     * must be at least 8 characters in length, and no more than 63
     * characters in length.
     */
    if (word_len < 8 || word_len > 63) {
        return E_ATTK_RECORD_INVALID;
    }

    pmk_init(&pmk, (uint8_t *)word, word_len, (uint8_t *)cdata->ssid,
             strlen(cdata->ssid));
    pmk_pbkdf2_sha1(&pmk);

    wpa_pmk_to_ptk(pmk.key, cdata->aa, cdata->spa, cdata->anonce, cdata->snonce,
                   ptk, sizeof(ptk));

    ptkset = (struct wpa_ptk *)ptk;

    hmac_hash(cdata->ver, ptkset->mic_key, 16, cdata->eapolframe,
              sizeof(cdata->eapolframe), keymic);

    if (memcmp(cdata->keymic, keymic, sizeof(keymic)) == 0) {
        return 0;
    }

    return E_ATTK_RECORD_NO_MATCH;
}


int cowp_make_hash(char *word, size_t word_size, char *ret_record,
                   size_t return_size, void *data) {
    char *ssid = (char *)data;
    pmk_st pmk;
    size_t word_len;
    cowp_hash_st hash;

    /* Sanity check */
    assert(word_size <= sizeof(hash.word));
    assert(return_size == sizeof(hash));

    memset(&hash, 0, sizeof(hash));
    word_len = strlen(word);

    /* Test length of word. */
    /* IEEE 802.11i indicates the passphrase
     * must be at least 8 characters in length, and no more than 63
     * characters in length.
     */
    if (word_len < 8 || word_len > 63 || word_len >= word_size) {
        return E_ATTK_RECORD_INVALID;
    }

    pmk_init(&pmk, (uint8_t *)word, word_len, (uint8_t *)ssid, strlen(ssid));
    pmk_pbkdf2_sha1(&pmk);

    memcpy(hash.word, word, strlen(word));
    memcpy(hash.pmk, pmk.key, PMK_KEY_LEN);
    memcpy(ret_record, &hash, sizeof(hash));

    return E_ATTK_RECORD_NO_MATCH;
}


int cowp_check_hash(char *record, size_t record_size, char *ret_record,
                    size_t return_size, void *data) {
    cowp_attack_data *cdata = (cowp_attack_data *)data;
    cowp_hash_st hash;
    size_t word_len;
    uint8_t ptk[64];
    uint8_t keymic[16];
    struct wpa_ptk *ptkset;

    memcpy(&hash, record, sizeof(hash));

    word_len = strlen(hash.word);

    memset(ptk, 0, 64);

    wpa_pmk_to_ptk(hash.pmk, cdata->aa, cdata->spa, cdata->anonce,
                   cdata->snonce, ptk, sizeof(ptk));

    ptkset = (struct wpa_ptk *)ptk;

    hmac_hash(cdata->ver, ptkset->mic_key, 16, cdata->eapolframe,
              sizeof(cdata->eapolframe), keymic);

    if (memcmp(cdata->keymic, keymic, sizeof(keymic)) == 0) {
        return 0;
    }

    return E_ATTK_RECORD_NO_MATCH;
}

void ahexdump(unsigned char *data, int len) {
    int i;
    for (i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
}
int cowp_data_init(cowp_attack_data *attack_data, char *ssid, uint8_t *aa,
                   uint8_t *spa, uint8_t *snonce, uint8_t *anonce,
                   uint8_t *eapolframe, uint8_t *keymic, int ver) {
    memset(attack_data, 0, sizeof(cowp_attack_data));
    size_t val_s_len = (strlen(ssid) < MAX_SSID_LEN ?
                        strlen(ssid) : MAX_SSID_LEN);

    #ifdef DEBUG
    printf("ssid: %s\n", ssid);
    #endif
    memcpy(attack_data->ssid, ssid, val_s_len);
    #ifdef DEBUG
    printf("aa: ");
    ahexdump(aa, CDATA_AA_LEN);
    printf("\n");
    #endif
    memcpy(attack_data->aa, aa, CDATA_AA_LEN);
    #ifdef DEBUG
    printf("spa: ");
    ahexdump(spa, CDATA_SPA_LEN);
    printf("\n");
    #endif
    memcpy(attack_data->spa, spa, CDATA_SPA_LEN);
    #ifdef DEBUG
    printf("snonce: ");
    ahexdump(snonce, CDATA_SNONCE_LEN);
    printf("\n");
    #endif
    memcpy(attack_data->snonce, snonce, CDATA_SNONCE_LEN);
    #ifdef DEBUG
    printf("anonce: ");
    ahexdump(anonce, CDATA_ANONCE_LEN);
    printf("\n");
    #endif
    memcpy(attack_data->anonce, anonce, CDATA_ANONCE_LEN);
    #ifdef DEBUG
    printf("eapolframe: ");
    ahexdump(eapolframe, CDATA_EAPOLFRAME_LEN);
    printf("\n");
    #endif
    memcpy(attack_data->eapolframe, eapolframe, CDATA_EAPOLFRAME_LEN);
    #ifdef DEBUG
    printf("keymic: ");
    ahexdump(keymic, CDATA_KEYMIC_LEN);
    printf("\n");
    #endif
    memcpy(attack_data->keymic, keymic, CDATA_KEYMIC_LEN);
    #ifdef DEBUG
    printf("ver: %i\n", ver);
    #endif
    attack_data->ver = ver;

    return 0;
}

int cowp_dict_init(attack_st *attk_st, char *file_path, int threads,
                   int (*callback)(attack_st *callback_args),
                   void *callback_data, cowp_attack_data *attack_data,
                   uint64_t skip_records, uint64_t count_records) {
    file_st *file;

    file = malloc(sizeof(file_st));

    read_file_init(file, DICT_QUEUE_WORDS, file_path, "", skip_records,
                   count_records);
    attack_st_init(attk_st, file, NULL, threads, cowp_check_word, callback,
                   callback_data, attack_data);

    /* TODO: Fix return value */
    return 0;
}
int cowp_dict_destroy(attack_st *attack_st) {
    read_file_destroy(attack_st->file_in);
    attack_st_destroy(attack_st);
    free(attack_st->file_in);

    /* TODO: Fix return value */
    return 0;
}
int cowp_bf_init(attack_st *attk_st, char *start, char *end, char *alphabet,
                 int threads, int (*callback)(attack_st *callback_args),
                 void *callback_data, cowp_attack_data *attack_data) {
    file_st *file;

    file = malloc(sizeof(file_st));

    brute_force_init(file, DICT_QUEUE_WORDS, start, end, alphabet);
    attack_st_init(attk_st, file, NULL, threads, cowp_check_word, callback,
                   callback_data, attack_data);

    /* TODO: Fix return value */
    return 0;
}
int cowp_bf_destroy(attack_st *attack_st) {
    brute_force_destroy(attack_st->file_in);
    attack_st_destroy(attack_st);
    free(attack_st->file_in);

    /* TODO: Fix return value */
    return 0;
}
int cowp_hash_init(attack_st *attk_st, char *file_path, int threads,
                   int (*callback)(attack_st *callback_args),
                   void *callback_data, cowp_attack_data *attack_data,
                   uint64_t skip_records, uint64_t count_records) {
    file_st *file;

    file = malloc(sizeof(file_st));

    read_file_init(file, HASH_QUEUE_WORDS, file_path, attack_data->ssid,
                   skip_records, count_records);
    attack_st_init(attk_st, file, NULL, threads, cowp_check_hash, callback,
                   callback_data, attack_data);

    /* TODO: Fix return value */
    return 0;
}
int cowp_hash_destroy(attack_st *attack_st) {
    read_file_destroy(attack_st->file_in);
    attack_st_destroy(attack_st);
    free(attack_st->file_in);

    /* TODO: Fix return value */
    return 0;
}
int cowp_make_hash_init(attack_st *attk_st, char *dict_file_path,
                        char *hash_file_path, int threads,
                        int (*callback)(attack_st *callback_args), void
                        *callback_data, char *ssid, uint32_t file_order,
                        uint64_t skip_records, uint64_t count_records) {
    file_st *file_in;
    file_st *file_out;

    #ifdef DEBUG
    printf("cowp_make_hash_init: GOT |%p|%s|%s|%i|%p|%p|%s|%i|%i|%i\n",
           attk_st, dict_file_path, hash_file_path, threads,
           callback, callback_data, ssid, file_order,
           skip_records, count_records);
    #endif
    file_in = malloc(sizeof(file_st));
    file_out = malloc(sizeof(file_st));

    read_file_init(file_in, DICT_QUEUE_WORDS, dict_file_path, "", skip_records,
                   count_records);
    write_file_init(file_out, hash_file_path, ssid, file_order,
                    sizeof(cowp_hash_st));
    attack_st_init(attk_st, file_in, file_out, threads, cowp_make_hash,
                   callback, callback_data, ssid);

    /* TODO: Fix return value */
    return 0;
}
int cowp_make_hash_destroy(attack_st *attack_st) {
    #ifdef DEBUG
    printf("cowp_make_hash_destroy START\n");
    #endif
    write_file_destroy(attack_st->file_out);
    read_file_destroy(attack_st->file_in);
    attack_st_destroy(attack_st);
    free(attack_st->file_in);
    free(attack_st->file_out);

    /* TODO: Fix return value */
    return 0;
}


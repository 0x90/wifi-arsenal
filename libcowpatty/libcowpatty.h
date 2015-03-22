/*
 * coWPAtty - Brute-force dictionary attack against WPA-PSK.
 *
 * Copyright (c) 2004-2005, Joshua Wright <jwright@hasborg.com>
 * Copyright (c) 2008-2013, Adam Bregenzer <adam@bregenzer.net>
 *
 * $Id$
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

#ifndef LIBCOWPATTY_H
#define LIBCOWPATTY_H

#include <stdint.h>

#include "../libattkthread/libattkthread.h"
#include "sha1.h"

#define CDATA_AA_LEN                  6
#define CDATA_SPA_LEN                 6
#define CDATA_SNONCE_LEN             32
#define CDATA_ANONCE_LEN             32
#define CDATA_EAPOLFRAME_LEN         99
#define CDATA_KEYMIC_LEN             16
#ifndef MAX_SSID_LEN
#define MAX_SSID_LEN                255
#endif
#define DICT_WORD_SIZE               64
#define DICT_QUEUE_WORDS            256
#define HASH_QUEUE_WORDS          10240

typedef struct COWP_ATTACK_DATA {
    char ssid[MAX_SSID_LEN + 1];
    uint8_t aa[CDATA_AA_LEN];
    uint8_t spa[CDATA_SPA_LEN];
    uint8_t snonce[CDATA_SNONCE_LEN];
    uint8_t anonce[CDATA_ANONCE_LEN];
    uint8_t eapolframe[CDATA_EAPOLFRAME_LEN];   /* Length the same for all packets? */
    uint8_t keymic[CDATA_KEYMIC_LEN];
    int ver;
} cowp_attack_data;

typedef struct COWP_HASH_ST {
    char word[DICT_WORD_SIZE];
    uint8_t pmk[PMK_KEY_LEN];
} cowp_hash_st;

int cowp_data_init(cowp_attack_data *attack_data, char *ssid, uint8_t *aa,
                   uint8_t *spa, uint8_t *snonce, uint8_t *anonce,
                   uint8_t *eapolframe, uint8_t *keymic, int ver);
int cowp_dict_init(attack_st *attk_st, char *file_path, int threads,
                   int (*callback)(attack_st *callback_args),
                   void *callback_data, cowp_attack_data *attack_data,
                   uint64_t skip_records, uint64_t count_records);
int cowp_dict_destroy(attack_st *attack_st);
int cowp_bf_init(attack_st *attk_st, char *start, char *end, char *alphabet,
                 int threads, int (*callback)(attack_st *callback_args),
                 void *callback_data, cowp_attack_data *attack_data);
int cowp_bf_destroy(attack_st *attack_st);
int cowp_hash_init(attack_st *attk_st, char *file_path, int threads,
                   int (*callback)(attack_st *callback_args),
                   void *callback_data, cowp_attack_data *attack_data,
                   uint64_t skip_records, uint64_t count_records);
int cowp_hash_destroy(attack_st *attack_st);
int cowp_make_hash_init(attack_st *attk_st, char *dict_file_path,
                        char *hash_file_path, int threads,
                        int (*callback)(attack_st *callback_args), void
                        *callback_data, char *ssid, uint32_t file_order,
                        uint64_t skip_records, uint64_t count_records);
int cowp_make_hash_destroy(attack_st *attack_st);

#endif      /* LIBCOWPATTY_H */


/*
 * coWPAtty - Brute-force dictionary attack against WPA-PSK.
 *
 * Copyright (c) 2004-2005, Joshua Wright <jwright@hasborg.com>
 *
 * $Id: md5.h,v 4.0 2006/07/28 12:23:48 jwright Exp $
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

#include <stdint.h>
#include <openssl/md5.h>

#define MD5Init         MD5_Init
#define MD5Update       MD5_Update
#define MD5Final        MD5_Final
#define MD5Transform    MD5_Transform
#define MD5_MAC_LEN     MD5_DIGEST_LENGTH

void md5_mac(uint8_t *key, size_t key_len, uint8_t *data, size_t data_len,
             uint8_t *mac);
void hmac_md5_vector(uint8_t *key, size_t key_len, size_t num_elem,
                     uint8_t *addr[], size_t *len, uint8_t *mac);
void hmac_md5(uint8_t *key, size_t key_len, uint8_t *data, size_t data_len,
              uint8_t *mac);

#endif              /* MD5_H */


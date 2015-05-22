/*
 * Copyright (C) 2006 toast
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 *
 */

#define IS_WEP(flags) ((flags) & 0x40)
#define WEPSMALLKEYSIZE 5
#define WEPLARGEKEYSIZE 13

struct wepkey {
  uint8_t key[WEPLARGEKEYSIZE];
  uint32_t keylen;
  struct wepkey *next;
};

typedef struct wepkey wepkey;

int32_t wep_decrypt(const uint8_t *src, uint8_t *dest, uint32_t len, 
    		     const uint8_t *wepkey, uint32_t keylen);
int32_t wep_encrypt(const uint8_t *src, uint8_t *dest, uint32_t len, 
    		     const uint8_t *wepkey, uint32_t keylen);

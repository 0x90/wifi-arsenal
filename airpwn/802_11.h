/*
 * Copyright (C) 2004 toast
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
 */
 
/*
 * Header describing the structure of an 802.11b + LLC frame
 */
#include <sys/types.h>

struct LLC_hdr {
  uint8_t dsap;
  uint8_t ssap;
  uint8_t control_field;
  uint8_t org_code[3];
  uint16_t type;
#define LLC_TYPE_IP 0x0008
};

struct ieee80211_hdr {
  uint8_t frame_control;
  uint8_t flags;
#define IEEE80211_TO_DS 0x01
#define IEEE80211_FROM_DS 0x02
#define IEEE80211_MORE_FRAG 0x04
#define IEEE80211_RETRY 0x08
#define IEEE80211_PWR_MGT 0x10
#define IEEE80211_MORE_DATA 0x20
#define IEEE80211_WEP_FLAG 0x40
#define IEEE80211_ORDER_FLAG 0x80
  uint16_t duration;
  uint8_t addr1[6]; //dest
  uint8_t addr2[6]; //src
  uint8_t addr3[6]; //bssid
  uint16_t frag_and_seq;

  /* Logical-Link Control */
  struct LLC_hdr llc;
};

typedef struct ieee80211_hdr ieee80211_hdr;
typedef struct LLC_hdr LLC_hdr;

#define IEEE80211_HDR_LEN_NO_LLC 24
#define LLC_HDR_LEN 8
#define IEEE80211_HDR_LEN 32
#define IEEE80211_FCS_LEN 4


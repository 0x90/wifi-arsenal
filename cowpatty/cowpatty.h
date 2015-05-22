/*
 * coWPAtty - Brute-force dictionary attack against WPA-PSK.
 *
 * Copyright (c) 2004, Joshua Wright <jwright@hasborg.com>
 *
 * $Id: cowpatty.h,v 1.1.1.1 2004/11/02 11:43:30 jwright Exp $
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


#include "common.h"

struct ieee802_1x_hdr {
	u8 version;
	u8 type;
	u16 length;
	/* followed by length octets of data */
} __attribute__ ((packed));

/* The 802.1x header indicates a version, type and length */
struct ieee8021x {
    u8    version;
    u8    type;
    u16   length;
} __attribute__ ((packed));


#define MAXPASSLEN 63
#define MEMORY_DICT 0
#define STDIN_DICT 1
#define EAPDOT1XOFFSET 4
#define BIT(n) (1 << (n))
#define WPA_KEY_INFO_TYPE_MASK (BIT(0) | BIT(1) | BIT(2))
#define WPA_KEY_INFO_TYPE_HMAC_MD5_RC4 BIT(0)
#define WPA_KEY_INFO_TYPE_HMAC_SHA1_AES BIT(1)
#define WPA_KEY_INFO_KEY_TYPE BIT(3) /* 1 = Pairwise, 0 = Group key */
/* bit4..5 is used in WPA, but is reserved in IEEE 802.11i/RSN */
#define WPA_KEY_INFO_KEY_INDEX_MASK (BIT(4) | BIT(5))
#define WPA_KEY_INFO_KEY_INDEX_SHIFT 4
#define WPA_KEY_INFO_INSTALL BIT(6) /* pairwise */
#define WPA_KEY_INFO_TXRX BIT(6) /* group */
#define WPA_KEY_INFO_ACK BIT(7)
#define WPA_KEY_INFO_MIC BIT(8)
#define WPA_KEY_INFO_SECURE BIT(9)
#define WPA_KEY_INFO_ERROR BIT(10)
#define WPA_KEY_INFO_REQUEST BIT(11)
#define WPA_KEY_INFO_ENCR_KEY_DATA BIT(12) /* IEEE 802.11i/RSN only */
#define WPA_NONCE_LEN 32
#define WPA_REPLAY_COUNTER_LEN 8

struct wpa_eapol_key {
    u8 type;
    u16 key_info;
    u16 key_length;
    u8 replay_counter[WPA_REPLAY_COUNTER_LEN];
    u8 key_nonce[WPA_NONCE_LEN];
    u8 key_iv[16];
    u8 key_rsc[8];
    u8 key_id[8]; /* Reserved in IEEE 802.11i/RSN */
    u8 key_mic[16];
    u16 key_data_length;
/*    u8 key_data[0]; */
} __attribute__ ((packed));


struct wpa_ptk {
    u8 mic_key[16]; /* EAPOL-Key MIC Key (MK) */
    u8 encr_key[16]; /* EAPOL-Key Encryption Key (EK) */
    u8 tk1[16]; /* Temporal Key 1 (TK1) */
    union {
        u8 tk2[16]; /* Temporal Key 2 (TK2) */
        struct {
            u8 tx_mic_key[8];
            u8 rx_mic_key[8];
        } auth;
    } u;
} __attribute__ ((packed));

struct user_opt {
    char ssid[256];
    char dictfile[256];
    char pcapfile[256];
    int verbose;
};

struct capture_data {
    char pcapfilename[256];
    int pcaptype;
    int dot1x_offset;
    int l2type_offset;
    int dstmac_offset;
    int srcmac_offset;
};

struct crack_data {
    u8  aa[6];
    u8  spa[6];
    u8  snonce[32];
    u8  anonce[32];
    u8  eapolframe[99]; /* Length the same for all packets? */
    u8  keymic[16];
    u8  aaset;
    u8  spaset;
    u8  snonceset;
    u8  anonceset;
    u8  keymicset;
    u8  eapolframeset;
    u8  replay_counter[8];
};


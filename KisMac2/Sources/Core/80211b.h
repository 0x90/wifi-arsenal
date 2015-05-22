/*
        
        File:			80211b.h
        Program:		KisMAC
		Author:			Michael Rossberg
						mick@binaervarianz.de
		Description:	KisMAC is a wireless stumbler for MacOS X.
                
        This file is part of KisMAC.

    KisMAC is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License, version 2,
    as published by the Free Software Foundation;

    KisMAC is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with KisMAC; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "libkern/OSByteOrder.h"


#define MAXLEN80211 2400

typedef struct _WLFrame {
    /* Control Fields (Little Endian) 14 byte*/ 
    UInt16 status;
    UInt16 channel;
    UInt16 reserved1;
    UInt8  signal;
    UInt8  silence;
    UInt8  rate;
    UInt8  rx_flow;
    UInt8  tx_rtry;
    UInt8  tx_rate;
    UInt16 txControl;

    /* 802.11 Header Info (Little Endian) 32 byte */
    UInt16 frameControl;
    UInt8  duration;
    UInt8  idnum;
    UInt8  address1[6];
    UInt8  address2[6];
    UInt8  address3[6];
    UInt16 sequenceControl;
    UInt8  address4[6];
    UInt16 dataLen;
 
    /* 802.3 Header Info (Big Endian) 14 byte*/
    UInt8  dstAddr[6];
    UInt8  srcAddr[6];
    UInt16 length;
} __attribute__((packed)) WLFrame;

typedef struct {
    /* Control Fields (Little Endian) 14 byte*/ 
    UInt16 status;
    UInt16 channel;
    UInt16 reserved1;
    UInt8  signal;
    UInt8  silence;
    UInt8  rate;
    UInt8  rx_flow;
    UInt8  tx_rtry;
    UInt8  tx_rate;
    UInt16 txControl;
} __attribute__((packed)) WLPrismHeader;

struct prism_value
{
  uint32 did;
  uint16 status;
  uint16 len;
  uint32 data;
};

struct prism_header
{
  uint32 msgcode;
  uint32 msglen;
  uint8  devname[16];
  struct prism_value hosttime;
  struct prism_value mactime;
  struct prism_value channel;
  struct prism_value rssi;
  struct prism_value sq;
  struct prism_value signal;
  struct prism_value noise;
  struct prism_value rate;
  struct prism_value istx;
  struct prism_value frmlen;
};

typedef struct __ieee80211_radiotap_header
{
    u_int8_t        it_version;     /* set to 0 */
    u_int8_t        it_pad;
    u_int16_t       it_len;         /* entire length */
    u_int32_t       it_present;     /* fields present */
} __attribute__((__packed__)) ieee80211_radiotap_header;

typedef struct _WLIEEEFrame {
    UInt16 frameControl;
    UInt8  duration;
    UInt8  idnum;
    UInt8  address1[6];
    UInt8  address2[6];
    UInt8  address3[6];
    UInt16 sequenceControl;
    UInt8  address4[6];
    UInt16 dataLen;
} __attribute__((packed)) WLIEEEFrame;

typedef struct _WLMgmtFrame {
    /* 802.11 Header Info (Little Endian) 24 bytes */
    UInt16 frameControl;
    UInt8  duration;
    UInt8  idnum;
    UInt8  address1[6];
    UInt8  address2[6];
    UInt8  address3[6];
    UInt16 sequenceControl;
} __attribute__((packed)) WLMgmtFrame;

typedef struct {
    WLMgmtFrame hdr;
    UInt16	wi_algo;
    UInt16	wi_seq;
    UInt16	wi_status;
} __attribute__ ((packed)) Ieee80211_Auth_Frame;


typedef struct _WLCryptedFrame {
    WLFrame frame;
    UInt8   IV[3];
    UInt8   keyID;
} __attribute__((packed)) WLCryptedFrame;

typedef struct _special_set {
    UInt16	resv;
    UInt16	wi_channel;
    UInt16	wi_port;
    UInt16	wi_beaconint;
    UInt16	wi_ssidlen;
    char	wi_ssid[LAST_BIT];
    char	wi_mac[6];
} special_set;    

typedef struct _frame8021x {
    UInt8       version;
    UInt8       type;
    UInt16      length;
    UInt8       data;
} __attribute__((packed)) frame8021x;

typedef struct _frameLEAP {
    UInt8       code;
    UInt8       ID;
    UInt16      length;
    UInt8       type;
    UInt8       version;
    UInt8       reserved;
    UInt8       count;
    UInt8       challenge[8];
    UInt8       name;
} __attribute__((packed)) frameLEAP;

#define HDR_SIZE        16
#define LLC_SIZE		8
#define WEP_SIZE		4
#define ARPDATA_SIZE	28
#define WEP_CRC_SIZE	4
#define ETHERPADDING	18

#define TCPACK_MIN_SIZE		(40 + HDR_SIZE)
#define TCPACK_MAX_SIZE		(52 + HDR_SIZE)
#define TCPRST_SIZE			(40 + HDR_SIZE)
#define ARP_SIZE			(WEP_SIZE + LLC_SIZE + ARPDATA_SIZE + WEP_CRC_SIZE)
#define ARP_SIZE_PADDING 	(ARP_SIZE + ETHERPADDING)

//this is all for a big endian system...

#define	IEEE80211_VERSION_MASK	OSSwapBigToHostConstInt16(0x0300)
#define	IEEE80211_VERSION_0		OSSwapBigToHostConstInt16(0x0000)

#define	IEEE80211_TYPE_MASK		OSSwapBigToHostConstInt16(0x0c00)
#define	IEEE80211_TYPE_MGT		OSSwapBigToHostConstInt16(0x0000)
#define	IEEE80211_TYPE_CTL		OSSwapBigToHostConstInt16(0x0400)
#define	IEEE80211_TYPE_DATA		OSSwapBigToHostConstInt16(0x0800)


/* Subtypes */

#define	IEEE80211_SUBTYPE_MASK			OSSwapBigToHostConstInt16(0xf000)

/* management subtypes */
#define	IEEE80211_SUBTYPE_ASSOC_REQ		OSSwapBigToHostConstInt16(0x0000)
#define	IEEE80211_SUBTYPE_ASSOC_RESP	OSSwapBigToHostConstInt16(0x1000)
#define	IEEE80211_SUBTYPE_REASSOC_REQ	OSSwapBigToHostConstInt16(0x2000)
#define	IEEE80211_SUBTYPE_REASSOC_RESP	OSSwapBigToHostConstInt16(0x3000)
#define	IEEE80211_SUBTYPE_PROBE_REQ		OSSwapBigToHostConstInt16(0x4000)
#define	IEEE80211_SUBTYPE_PROBE_RESP	OSSwapBigToHostConstInt16(0x5000)
#define	IEEE80211_SUBTYPE_BEACON		OSSwapBigToHostConstInt16(0x8000)
#define	IEEE80211_SUBTYPE_ATIM			OSSwapBigToHostConstInt16(0x9000)
#define	IEEE80211_SUBTYPE_DISASSOC		OSSwapBigToHostConstInt16(0xa000)
#define	IEEE80211_SUBTYPE_AUTH			OSSwapBigToHostConstInt16(0xb000)
#define	IEEE80211_SUBTYPE_DEAUTH		OSSwapBigToHostConstInt16(0xc000)
#define	IEEE80211_SUBTYPE_ACTION		OSSwapBigToHostConstInt16(0xd000)

/* control subtypes */
#define	IEEE80211_SUBTYPE_BLOCK_ACK_REQ	OSSwapBigToHostConstInt16(0x8000)
#define	IEEE80211_SUBTYPE_BLOCK_ACK		OSSwapBigToHostConstInt16(0x9000)
#define	IEEE80211_SUBTYPE_PS_POLL		OSSwapBigToHostConstInt16(0xa000)
#define	IEEE80211_SUBTYPE_RTS			OSSwapBigToHostConstInt16(0xb000)
#define	IEEE80211_SUBTYPE_CTS			OSSwapBigToHostConstInt16(0xc000)
#define	IEEE80211_SUBTYPE_ACK			OSSwapBigToHostConstInt16(0xd000)
#define	IEEE80211_SUBTYPE_CF_END		OSSwapBigToHostConstInt16(0xe000)
#define	IEEE80211_SUBTYPE_CF_END_ACK	OSSwapBigToHostConstInt16(0xf000)

/* data subtypes */
#define	IEEE80211_SUBTYPE_DATA          OSSwapBigToHostConstInt16(0x0000)
#define	IEEE80211_SUBTYPE_DATA_CFACK	OSSwapBigToHostConstInt16(0x1000)
#define	IEEE80211_SUBTYPE_DATA_CFPOLL	OSSwapBigToHostConstInt16(0x2000)
#define	IEEE80211_SUBTYPE_DATA_CFACKPOLL OSSwapBigToHostConstInt16(0x3000)
#define	IEEE80211_SUBTYPE_NULLFUNC		OSSwapBigToHostConstInt16(0x4000)
#define	IEEE80211_SUBTYPE_CFACK         OSSwapBigToHostConstInt16(0x5000)
#define	IEEE80211_SUBTYPE_CFPOLL		OSSwapBigToHostConstInt16(0x6000)
#define	IEEE80211_SUBTYPE_CFACKPOLL		OSSwapBigToHostConstInt16(0x7000)
#define	IEEE80211_SUBTYPE_QOS_DATA		OSSwapBigToHostConstInt16(0x8000)
#define	IEEE80211_SUBTYPE_QOS_DATA_CFACK		OSSwapBigToHostConstInt16(0x9000)
#define	IEEE80211_SUBTYPE_QOS_DATA_CFPOLL		OSSwapBigToHostConstInt16(0xa000)
#define	IEEE80211_SUBTYPE_QOS_DATA_CFACKPOLL	OSSwapBigToHostConstInt16(0xb000)
#define	IEEE80211_SUBTYPE_QOS_NULL				OSSwapBigToHostConstInt16(0xc000)
#define	IEEE80211_SUBTYPE_QOS_NODATA_CFPOLL		OSSwapBigToHostConstInt16(0xe000)
#define	IEEE80211_SUBTYPE_QOS_NODATA_CFACKPOLL	OSSwapBigToHostConstInt16(0xf000)

#define	IEEE80211_DIR_MASK				OSSwapBigToHostConstInt16(0x0003)
#define	IEEE80211_DIR_NODS				OSSwapBigToHostConstInt16(0x0000)	/* STA->STA */
#define	IEEE80211_DIR_TODS				OSSwapBigToHostConstInt16(0x0001)	/* STA->AP  */
#define	IEEE80211_DIR_FROMDS			OSSwapBigToHostConstInt16(0x0002)	/* AP ->STA */
#define	IEEE80211_DIR_DSTODS			OSSwapBigToHostConstInt16(0x0003)	/* AP ->AP  */

#define	IEEE80211_MORE_FRAG				OSSwapBigToHostConstInt16(0x0004)
#define	IEEE80211_RETRY					OSSwapBigToHostConstInt16(0x0008)
#define	IEEE80211_PWR_MGT				OSSwapBigToHostConstInt16(0x0010)
#define	IEEE80211_MORE_DATA				OSSwapBigToHostConstInt16(0x0020)
#define	IEEE80211_WEP					OSSwapBigToHostConstInt16(0x0040)
#define	IEEE80211_ORDER					OSSwapBigToHostConstInt16(0x0080)

#define	IEEE80211_CAPINFO_ESS			OSSwapBigToHostConstInt16(0x0100)
#define	IEEE80211_CAPINFO_IBSS			OSSwapBigToHostConstInt16(0x0200)
#define	IEEE80211_CAPINFO_CF_POLLABLE	OSSwapBigToHostConstInt16(0x0400)
#define	IEEE80211_CAPINFO_CF_POLLREQ	OSSwapBigToHostConstInt16(0x0800)
#define	IEEE80211_CAPINFO_PRIVACY		OSSwapBigToHostConstInt16(0x1000)

//does le stand for little endian?  we shouldn't swap if this is the case!!
#define	IEEE80211_CAPINFO_ESS_LE			0x0001  
#define	IEEE80211_CAPINFO_IBSS_LE			0x0002
#define	IEEE80211_CAPINFO_CF_POLLABLE_LE	0x0004
#define	IEEE80211_CAPINFO_CF_POLLREQ_LE		0x0008
#define	IEEE80211_CAPINFO_PRIVACY_LE        0x0010
#define IEEE80211_CAPINFO_PROBE_REQ_LE		0xF100 // this isn't a real flag

#define	IEEE80211_ELEMID_SSID			0
#define	IEEE80211_ELEMID_RATES			1
#define	IEEE80211_ELEMID_FHPARMS		2
#define	IEEE80211_ELEMID_DSPARMS		3
#define	IEEE80211_ELEMID_CFPARMS		4
#define	IEEE80211_ELEMID_TIM			5
#define	IEEE80211_ELEMID_IBSSPARMS		6
#define	IEEE80211_ELEMID_CHALLENGE		16
#define	IEEE80211_ELEMID_EXTENDED_RATES	50
#define	IEEE80211_ELEMID_VENDOR			0xDD
#define IEEE80211_ELEMID_RSN            48

#define RSN_OUI                         "\x00\x0f\xac"

#define VENDOR_WPA_HEADER				OSSwapBigToHostConstInt32(0x0050f201)
#define VENDOR_CISCO_HEADER				OSSwapBigToHostConstInt32(0x0050f205)

#define WPA_EXT_IV_PRESENT              0x20

#define WPA_FLAG_REQUEST                OSSwapBigToHostConstInt16(0x0800)
#define WPA_FLAG_ERROR                  OSSwapBigToHostConstInt16(0x0400)
#define WPA_FLAG_SECURE                 OSSwapBigToHostConstInt16(0x0200)
#define WPA_FLAG_MIC                    OSSwapBigToHostConstInt16(0x0100)
#define WPA_FLAG_ACK                    OSSwapBigToHostConstInt16(0x0080)
#define WPA_FLAG_INSTALL                OSSwapBigToHostConstInt16(0x0040)
#define WPA_FLAG_KEYID                  OSSwapBigToHostConstInt16(0x0030)
#define WPA_FLAG_KEYTYPE                OSSwapBigToHostConstInt16(0x0008)

#define WPA_FLAG_KEYTYPE_PAIRWISE       OSSwapBigToHostConstInt16(0x0008)
#define WPA_FLAG_KEYTYPE_GROUPWISE      OSSwapBigToHostConstInt16(0x0000)

#define WPA_FLAG_KEYCIPHER_MASK         OSSwapBigToHostConstInt16(0x0007)
#define WPA_FLAG_KEYCIPHER_HMAC_MD5     OSSwapBigToHostConstInt16(0x0001)
#define WPA_FLAG_KEYCIPHER_AES_CBC      OSSwapBigToHostConstInt16(0x0002)

#define WPA_NONCE_LENGTH                32
#define WPA_EAPOL_LENGTH                99
#define WPA_EAP_MIC_LENGTH              16

#define WPA_PMK_LENGTH                  32

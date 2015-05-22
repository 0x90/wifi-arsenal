/*
    bully - retrieve WPA/WPA2 passphrase from a WPS-enabled AP

    Copyright (C) 2012  Brian Purcell <purcell.briand@gmail.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#ifndef _80211_H
#define _80211_H
#pragma pack(push)
#pragma pack(1)

#define	FALSE	0
#define	TRUE	1

#define uint8	u_int8_t
#define uint16	u_int16_t
#define uint32	u_int32_t
#define uint64	u_int64_t
#define int8	int8_t
#define int16	int16_t
#define int32	int32_t

#define	ui(x)	((int32)(x))
#define	uc(x)	((uint8*)(x))

uint8	nulls[33]	= {0};
#define	NULL_MAC	nulls
#define	BCAST_MAC	"\xFF\xFF\xFF\xFF\xFF\xFF"
#define	BULL_MAC	"\xFA\xCE\xFA\xCE\xFA\xCE"

uint8	ackpkt[] = "\x00\x00\x08\x00\x00\x00\x00\x00"
			"\xD4\x00\x00\x00\xdd\xdd\xdd\xdd\xdd\xdd\xFF\xFF\xFF\xFF";

uint8	deauth[] = "\x00\x00\x08\x00\x00\x00\x00\x00"
			"\xC0\x00\x3a\x01\xdd\xdd\xdd\xdd\xdd\xdd\x00\x1c\xcc\xcc\xcc\xcc\xbb\xbb\xbb\xbb\xbb\xbb"
			"\xCF\xCC\x08\x00\xFF\xFF\xFF\xFF";

uint8	prober[] = "\x00\x00\x08\x00\x00\x00\x00\x00"
			"\x40\x00\x3a\x01\xFF\xFF\xFF\xFF\xFF\xFF\x00\x1c\xcc\xcc\xcc\xcc\xFF\xFF\xFF\xFF\xFF\xFF"
			"\xCF\xCC\xFF\xFF\xFF\xFF";

uint8	authrq[] = "\x00\x00\x08\x00\x00\x00\x00\x00"
			"\xB0\x00\x3a\x01\xdd\xdd\xdd\xdd\xdd\xdd\x00\x1c\xcc\xcc\xcc\xcc\xbb\xbb\xbb\xbb\xbb\xbb"
			"\xCF\xCC\x00\x00\x01\x00\x00\x00\xFF\xFF\xFF\xFF";

uint8	asshat[] = "\x00\x00\x08\x00\x00\x00\x00\x00"
			"\x00\x00\x3a\x01\xdd\xdd\xdd\xdd\xdd\xdd\x00\x1c\xcc\xcc\xcc\xcc\xbb\xbb\xbb\xbb\xbb\xbb"
			"\xCF\xCC\x00\x00\x01\x00\xFF\xFF\xFF\xFF";

uint8	eapols[] = "\x00\x00\x08\x00\x00\x00\x00\x00"
			"\x08\x01\x3a\x01\xdd\xdd\xdd\xdd\xdd\xdd\x00\x1c\xcc\xcc\xcc\xcc\xbb\xbb\xbb\xbb\xbb\xbb"
			"\xCF\xCC\xAA\xAA\x03\x00\x00\x00\x88\x8E"
			"\x02\x01\x00\x00\xFF\xFF\xFF\xFF";

uint8	eapolf[] = "\x00\x00\x08\x00\x00\x00\x00\x00"
			"\x08\x01\x3a\x01\xdd\xdd\xdd\xdd\xdd\xdd\x00\x1c\xcc\xcc\xcc\xcc\xbb\xbb\xbb\xbb\xbb\xbb"
			"\xCF\xCC\xAA\xAA\x03\x00\x00\x00\x88\x8E"
			"\x02\x00\x00\x04\x04\x1D\x00\x04\xFF\xFF\xFF\xFF";

uint8	eap_id[] = "\x00\x00\x08\x00\x00\x00\x00\x00"
			"\x08\x01\x3a\x01\xdd\xdd\xdd\xdd\xdd\xdd\x00\x1c\xcc\xcc\xcc\xcc\xbb\xbb\xbb\xbb\xbb\xbb"
			"\xCF\xCC\xAA\xAA\x03\x00\x00\x00\x88\x8E"
			"\x02\x00\x00\x23\x02\x1D\x00\x23\x01"
			"WFA-SimpleConfig-Registrar-1-0" "\xFF\xFF\xFF\xFF";

uint8	wfamsg[] = "\x00\x00\x08\x00\x00\x00\x00\x00"
			"\x08\x01\x3a\x01\xdd\xdd\xdd\xdd\xdd\xdd\x00\x1c\xcc\xcc\xcc\xcc\xbb\xbb\xbb\xbb\xbb\xbb"
			"\xCF\xCC\xAA\xAA\x03\x00\x00\x00\x88\x8E"
			"\x02\x00\xff\xff\x02\x1D\xff\xff\xfe"
			"\x00\x37\x2a\x00\x00\x00\x01\x04\x00\xFF\xFF\xFF\xFF";


struct radiotap_header {
	u_int8_t	it_version;
	u_int8_t	it_pad;
	u_int16_t	it_len;
	u_int32_t	it_present;
};
typedef struct radiotap_header rth_t;
#define	RTH_SIZE (sizeof(rth_t))


struct adr_frame {
	uint8		addr[6];
};
typedef struct adr_frame adr_t;
#define	ADR_SIZE (sizeof(adr_t))


struct qos_frame {
	uint8		control;
	uint8		flags;
};
typedef struct qos_frame qos_t;
#define	QOS_SIZE (sizeof(qos_t))


struct mac_frame {
#if __BYTE_ORDER == __BIG_ENDIAN
	unsigned	subtype : 4;
	unsigned	type : 	2;
	unsigned	version : 2;

	unsigned	ordered : 1;
	unsigned	protected : 1;
	unsigned	more_data : 1;
	unsigned	power : 1;
	unsigned	retry : 1;
	unsigned	more_frag : 1;
	unsigned	from_ds : 1;
	unsigned	to_ds : 1;
#else
	unsigned	version : 2;
	unsigned	type : 	2;
	unsigned	subtype : 4;

	unsigned	to_ds : 1;
	unsigned	from_ds : 1;
	unsigned	more_frag : 1;
	unsigned	retry : 1;
	unsigned	power : 1;
	unsigned	more_data : 1;
	unsigned	protected : 1;
	unsigned	ordered : 1;
#endif
	uint16		duration;
	adr_t		adr1;
	adr_t		adr2;
	adr_t		adr3;
	uint16		sequence;
	adr_t		addr4;
	qos_t		qos;
};
typedef struct mac_frame mac_t;
#define	MAC_SIZE_ACK	(10)
#define	MAC_SIZE_RTS	(16)
#define	MAC_SIZE_NORM	(24)
#define	MAC_SIZE_LONG	(30)

#define	MAC_TYPE_MGMT	0x0
#define	MAC_TYPE_CTRL	0x1
#define	MAC_TYPE_DATA	0x2
#define	MAC_TYPE_RSVD	0x3

// management subtypes
#define	MAC_ST_ASSOC_REQ	0x0
#define	MAC_ST_ASSOC_RESP	0x1
#define	MAC_ST_REASSOC_REQ	0x2
#define	MAC_ST_REASSOC_RESP	0x3
#define	MAC_ST_PROBE_REQ	0x4
#define	MAC_ST_PROBE_RESP	0x5
#define	MAC_ST_BEACON		0x8
#define	MAC_ST_DISASSOC		0xA
#define	MAC_ST_AUTH		0xB
#define	MAC_ST_DEAUTH		0xC
// data subtypes
#define	MAC_ST_DATA		0x0
#define	MAC_ST_NULL		0x4
#define	MAC_ST_QOSDATA		0x8
// control subtypes
#define	MAC_ST_RTS		0xB
#define	MAC_ST_ACK		0xD


struct fcs_frame {
	uint32		fcs;
};
typedef struct fcs_frame fcs_t;
#define	FCS_SIZE (sizeof(fcs_t))


struct bfp_frame {
	uint8		timestamp[8];
	uint16		interval;
	uint16		capability;
};
typedef struct bfp_frame bfp_t;
#define BFP_SIZE (sizeof(bfp_t))


struct cap_info {
#if __BYTE_ORDER == __BIG_ENDIAN
	unsigned	agility : 1;
	unsigned	pbcc : 1;
	unsigned	preamble : 1;
	unsigned	privacy : 1;
	unsigned	poll_req : 1;
	unsigned	pollable : 1;
	unsigned	ibss : 1;
	unsigned	ess : 1;

	unsigned	immed_ba : 1;
	unsigned	delay_ba : 1;
	unsigned	dss_ofdm : 1;
	unsigned	resvd : 1;
	unsigned	apsd : 1;
	unsigned	short_slot : 1;
	unsigned	qos : 1;
	unsigned	spectrum : 1;
#else
	unsigned	ess : 1;
	unsigned	ibss : 1;
	unsigned	pollable : 1;
	unsigned	poll_req : 1;
	unsigned	privacy : 1;
	unsigned	preamble : 1;
	unsigned	pbcc : 1;
	unsigned	agility : 1;

	unsigned	spectrum : 1;
	unsigned	qos : 1;
	unsigned	short_slot : 1;
	unsigned	apsd : 1;
	unsigned	resvd : 1;
	unsigned	dss_ofdm : 1;
	unsigned	delay_ba : 1;
	unsigned	immed_ba : 1;
#endif
};


struct ie_tag {
	uint8		id;
#define	TAG_SSID	0
#define	TAG_RATE	1
#define	TAG_CHAN	3
#define	TAG_XRAT	50
#define	TAG_VEND	221
	uint8		len;
	uint8		data[];
};
typedef struct ie_tag tag_t;
#define	TAG_SIZE (sizeof(tag_t))

#define	MS_WPS_ID	"\x00\x50\xf2\x04"
#define	MS_WPS_TAG	"\xdd\x09" MS_WPS_ID "\x10\x4a\x00\x01\x10"


struct ie_vtag {
	uint16		id;
#define	TAG_WPS_VERSION	"\x10\x4A"
#define	TAG_WPS_STATE	"\x10\x44"
#define	TAG_WPS_APLOCK	"\x10\x57"
	uint16		len;
	uint8		data[];
#define	TAG_WPS_CONFIG	2
#define	TAG_WPS_LOCKED	1
};
typedef struct ie_vtag vtag_t;
#define	VTAG_SIZE (sizeof(vtag_t))


struct auth_frame {
	uint16		algorithm;
	uint16		sequence;
	uint16		status;
#define	AUTH_SUCCESS	0
};
typedef struct auth_frame auth_t;
#define AUTH_SIZE (sizeof(auth_t))


struct assn_frame {
	uint16		capability;
	uint16		listen;
};
typedef struct assn_frame assn_t;
#define ASSN_SIZE (sizeof(assn_t))


struct resp_frame {
	uint16		capability;
	uint16		status;
#define	RESP_SUCCESS	0
	uint16		assn_id;
};
typedef struct resp_frame resp_t;
#define RESP_SIZE (sizeof(resp_t))


struct llc_frame {
	uint8		dsap;
	uint8		ssap;
	uint8		control;
	uint8		org[3];
	uint16		type;
#define	LLC_TYPE_AUTH	0x888e
};
typedef struct llc_frame llc_t;
#define	LLC_SIZE (sizeof(llc_t))


struct d1x_frame {
	uint8		version;
	uint8		type;
#define	D1X_TYPE_EAP	0
	uint16		len;
	uint8		data[];
};
typedef struct d1x_frame d1x_t;
#define	D1X_SIZE (sizeof(d1x_t))


struct eap_frame {
	uint8		code;
#define	EAP_CODE_REQ	1
#define	EAP_CODE_RESP	2
#define	EAP_CODE_FAIL	4
	uint8		id;
	uint16		len;
	uint8		type;
#define	EAP_TYPE_ID	1
#define	EAP_TYPE_EXPAND	254
	uint8		data[];
};
typedef struct eap_frame eap_t;
#define	EAP_SIZE (sizeof(eap_t))


struct wfa_frame {
	uint8		vid[3];
#define	WFA_VENDOR	"\x00\x37\x2a"
	uint32		type;
#define	WFA_SIMPLECONF	1
	uint8		op;
#define	WSC_OP_NACK	3
#define	WSC_OP_MSG	4
	uint8		flags;
	vtag_t		tags[];
#define	WPS_MSG_TYPE	"\x10\x22"
#define	MSG_M1		4
#define	MSG_M2		5
#define	MSG_M2D		6
#define	MSG_M3		7
#define	MSG_M4		8
#define	MSG_M5		9
#define	MSG_M6		10
#define	MSG_M7		11
#define	MSG_NACK	14
};
typedef struct wfa_frame wfa_t;
#define	WFA_SIZE (sizeof(wfa_t))


#pragma pack(pop)
#endif /* _80211_h */

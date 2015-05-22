#ifndef _WLAN_HEADER_H_
#define _WLAN_HEADER_H_

#include <sys/types.h>

struct wlan_frame {
	u_int16_t	fc;
	u_int16_t	duration;
	u_int8_t	addr1[6];
	u_int8_t	addr2[6];
	u_int8_t	addr3[6];
	u_int16_t	seq;
	union {
		u_int16_t	qos;
		u_int8_t	addr4[6];
		struct {
			u_int16_t	qos;
			u_int32_t	ht;
		} __attribute__ ((packed)) ht;
		struct {
			u_int8_t	addr4[6];
			u_int16_t	qos;
			u_int32_t	ht;
		} __attribute__ ((packed)) addr4_qos_ht;
	} u;
} __attribute__ ((packed));

#define WLAN_FRAME_FC_VERSION_MASK	0x0003
#define WLAN_FRAME_FC_TYPE_MASK		0x000C
#define WLAN_FRAME_FC_STYPE_MASK	0x00F0
#define WLAN_FRAME_FC_STYPE_QOS		0x0080
#define WLAN_FRAME_FC_TO_DS		0x0100
#define WLAN_FRAME_FC_FROM_DS		0x0200
#define WLAN_FRAME_FC_MORE_FRAG		0x0400
#define WLAN_FRAME_FC_RETRY		0x0800
#define WLAN_FRAME_FC_POWER_MGMT	0x1000
#define WLAN_FRAME_FC_MORE_DATA		0x2000
#define WLAN_FRAME_FC_PROTECTED		0x4000
#define WLAN_FRAME_FC_ORDER		0x8000

#define WLAN_FRAME_FC_MASK		(WLAN_FRAME_FC_TYPE_MASK | WLAN_FRAME_FC_STYPE_MASK)

/* internal use only */
#define _WLAN_FRAME_FC(_type, _stype)	(((_type) << 2) | ((_stype) << 4))
#define _FC_TYPE_MGMT			0x0
#define _FC_TYPE_CTRL			0x1
#define _FC_TYPE_DATA			0x2

/* main types */
#define WLAN_FRAME_TYPE_MGMT		_WLAN_FRAME_FC(_FC_TYPE_MGMT, 0x0)
#define WLAN_FRAME_TYPE_CTRL		_WLAN_FRAME_FC(_FC_TYPE_CTRL, 0x0)
#define WLAN_FRAME_TYPE_DATA		_WLAN_FRAME_FC(_FC_TYPE_DATA, 0x0)

#define WLAN_FRAME_IS_MGMT(_fc)		(((_fc) & WLAN_FRAME_FC_TYPE_MASK) == WLAN_FRAME_TYPE_MGMT)
#define WLAN_FRAME_IS_CTRL(_fc)		(((_fc) & WLAN_FRAME_FC_TYPE_MASK) == WLAN_FRAME_TYPE_CTRL)
#define WLAN_FRAME_IS_DATA(_fc)		(((_fc) & WLAN_FRAME_FC_TYPE_MASK) == WLAN_FRAME_TYPE_DATA)
#define WLAN_FRAME_IS_QOS(_fc)		(((_fc) & WLAN_FRAME_FC_STYPE_MASK) == WLAN_FRAME_FC_STYPE_QOS)

/*** management ***/
#define WLAN_FRAME_ASSOC_REQ		_WLAN_FRAME_FC(_FC_TYPE_MGMT, 0x0)
#define WLAN_FRAME_ASSOC_RESP		_WLAN_FRAME_FC(_FC_TYPE_MGMT, 0x1)
#define WLAN_FRAME_REASSOC_REQ		_WLAN_FRAME_FC(_FC_TYPE_MGMT, 0x2)
#define WLAN_FRAME_REASSOC_RESP		_WLAN_FRAME_FC(_FC_TYPE_MGMT, 0x3)
#define WLAN_FRAME_PROBE_REQ		_WLAN_FRAME_FC(_FC_TYPE_MGMT, 0x4)
#define WLAN_FRAME_PROBE_RESP		_WLAN_FRAME_FC(_FC_TYPE_MGMT, 0x5)
#define WLAN_FRAME_TIMING		_WLAN_FRAME_FC(_FC_TYPE_MGMT, 0x6)
/* (reserved)							      0x7 */
#define WLAN_FRAME_BEACON		_WLAN_FRAME_FC(_FC_TYPE_MGMT, 0x8)
#define WLAN_FRAME_ATIM			_WLAN_FRAME_FC(_FC_TYPE_MGMT, 0x9)
#define WLAN_FRAME_DISASSOC		_WLAN_FRAME_FC(_FC_TYPE_MGMT, 0xa)
#define WLAN_FRAME_AUTH			_WLAN_FRAME_FC(_FC_TYPE_MGMT, 0xb)
#define WLAN_FRAME_DEAUTH		_WLAN_FRAME_FC(_FC_TYPE_MGMT, 0xc)
#define WLAN_FRAME_ACTION		_WLAN_FRAME_FC(_FC_TYPE_MGMT, 0xd)
#define WLAN_FRAME_ACTION_NOACK		_WLAN_FRAME_FC(_FC_TYPE_MGMT, 0xe)
/* (reserved)							      0xf */

/*** control ***/
/* (reserved)							      0-6 */
#define WLAN_FRAME_CTRL_WRAP		_WLAN_FRAME_FC(_FC_TYPE_CTRL, 0x7)
#define WLAN_FRAME_BLKACK_REQ		_WLAN_FRAME_FC(_FC_TYPE_CTRL, 0x8)
#define WLAN_FRAME_BLKACK		_WLAN_FRAME_FC(_FC_TYPE_CTRL, 0x9)
#define WLAN_FRAME_PSPOLL		_WLAN_FRAME_FC(_FC_TYPE_CTRL, 0xa)
#define WLAN_FRAME_RTS			_WLAN_FRAME_FC(_FC_TYPE_CTRL, 0xb)
#define WLAN_FRAME_CTS			_WLAN_FRAME_FC(_FC_TYPE_CTRL, 0xc)
#define WLAN_FRAME_ACK			_WLAN_FRAME_FC(_FC_TYPE_CTRL, 0xd)
#define WLAN_FRAME_CF_END		_WLAN_FRAME_FC(_FC_TYPE_CTRL, 0xe)
#define WLAN_FRAME_CF_END_ACK		_WLAN_FRAME_FC(_FC_TYPE_CTRL, 0xf)

/*** data ***/
#define WLAN_FRAME_DATA			_WLAN_FRAME_FC(_FC_TYPE_DATA, 0x0)
#define WLAN_FRAME_DATA_CF_ACK		_WLAN_FRAME_FC(_FC_TYPE_DATA, 0x1)
#define WLAN_FRAME_DATA_CF_POLL		_WLAN_FRAME_FC(_FC_TYPE_DATA, 0x2)
#define WLAN_FRAME_DATA_CF_ACKPOLL	_WLAN_FRAME_FC(_FC_TYPE_DATA, 0x3)
#define WLAN_FRAME_NULL			_WLAN_FRAME_FC(_FC_TYPE_DATA, 0x4)
#define WLAN_FRAME_CF_ACK		_WLAN_FRAME_FC(_FC_TYPE_DATA, 0x5)
#define WLAN_FRAME_CF_POLL		_WLAN_FRAME_FC(_FC_TYPE_DATA, 0x6)
#define WLAN_FRAME_CF_ACKPOLL		_WLAN_FRAME_FC(_FC_TYPE_DATA, 0x7)
#define WLAN_FRAME_QDATA		_WLAN_FRAME_FC(_FC_TYPE_DATA, 0x8)
#define WLAN_FRAME_QDATA_CF_ACK		_WLAN_FRAME_FC(_FC_TYPE_DATA, 0x9)
#define WLAN_FRAME_QDATA_CF_POLL	_WLAN_FRAME_FC(_FC_TYPE_DATA, 0xa)
#define WLAN_FRAME_QDATA_CF_ACKPOLL	_WLAN_FRAME_FC(_FC_TYPE_DATA, 0xb)
#define WLAN_FRAME_QOS_NULL		_WLAN_FRAME_FC(_FC_TYPE_DATA, 0xc)
/* (reserved)							      0xd */
#define WLAN_FRAME_QOS_CF_POLL		_WLAN_FRAME_FC(_FC_TYPE_DATA, 0xe)
#define WLAN_FRAME_QOS_CF_ACKPOLL	_WLAN_FRAME_FC(_FC_TYPE_DATA, 0xf)

#define WLAN_FRAME_QOS_TID_MASK		0x7
#define WLAN_FRAME_QOS_AMSDU_PRESENT	0x80

/*** individual frame formats ***/

/* beacon + probe response */
struct wlan_frame_beacon {
	u_int64_t	tsf;
	u_int16_t	bintval;
	u_int16_t	capab;
	unsigned char	ie[0];
} __attribute__ ((packed));


/*** capabilities ***/
#define WLAN_CAPAB_ESS		0x0001
#define WLAN_CAPAB_IBSS		0x0002
#define WLAN_CAPAB_CF_POLL	0x0004
#define WLAN_CAPAB_CF_POLL_REQ	0x0008
#define WLAN_CAPAB_PRIVACY	0x0010
#define WLAN_CAPAB_SHORT_PRE	0x0020
#define WLAN_CAPAB_PBCC		0x0040
#define WLAN_CAPAB_CHAN_AGILIY	0x0080
#define WLAN_CAPAB_SPECT_MGMT	0x0100
#define WLAN_CAPAB_QOS		0x0200
#define WLAN_CAPAB_SHORT_SLOT	0x0400
#define WLAN_CAPAB_APSD		0x0800
#define WLAN_CAPAB_RADIO_MEAS	0x1000
#define WLAN_CAPAB_OFDM		0x2000
#define WLAN_CAPAB_DEL_BLKACK	0x4000
#define WLAN_CAPAB_IMM_BLKACK	0x8000

/*** information elements ***/
struct information_element {
	u_int8_t	id;
	u_int8_t	len;
	unsigned char	var[0];
};

/* only the information element IDs we are interested in */
#define WLAN_IE_ID_SSID		0
#define WLAN_IE_ID_DSSS_PARAM	3
#define WLAN_IE_ID_RSN		48
#define WLAN_IE_ID_VENDOR	221

#define WLAN_MAX_SSID_LEN	34

#endif

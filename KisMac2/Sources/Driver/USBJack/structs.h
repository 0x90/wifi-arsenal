/*
        
        File:			structs.h
        Program:		KisMAC
	Description:		KisMAC is a wireless stumbler for MacOS X.
                
        This file is part of KisMAC. Most of this has been shamelessly ripped off
        the Linux wlan-driver-ng. Sorry but I did not want to sign the NDA.

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

#define		_RID_GUESSING_MAXLEN	2048  /* I'm not really sure */
#define		_RIDDATA_MAXLEN		_RID_GUESSING_MAXLEN	
#define		_USB_RWMEM_MAXLEN	2048
#define         WLAN_DATA_MAXLEN                2400

/*--------------------------------------------------------------------
USB Packet structures and constants.
--------------------------------------------------------------------*/

/* Should be sent to the bulkout endpoint */
#define _USB_TXFRM	0
#define _USB_CMDREQ	1
#define _USB_WRIDREQ	2
#define _USB_RRIDREQ	3
#define _USB_WMEMREQ	4
#define _USB_RMEMREQ	5

/* Received from the bulkin endpoint */
#define _USB_ISFRM(a)	(!((a) & 0x8000))
#define _USB_ISTXFRM(a)	(((a) & 0x9000) == 0x1000)
#define _USB_ISRXFRM(a)	(!((a) & 0x9000))
#define _USB_INFOFRM	0x8000
#define _USB_CMDRESP	0x8001
#define _USB_WRIDRESP	0x8002
#define _USB_RRIDRESP	0x8003
#define _USB_WMEMRESP	0x8004
#define _USB_RMEMRESP	0x8005
#define _USB_BUFAVAIL	0x8006
#define _USB_ERROR	0x8007

#define	_TX_CFPOLL			(0x1000)
#define	_TX_PRST                        (0x0800)
#define	_TX_MACPORT			(0x0700)
#define	_TX_NOENCRYPT			(0x0080)
#define	_TX_RETRYSTRAT			(0x0060)
#define	_TX_STRUCTYPE			(0x0018)
#define	_TX_TXEX                        (0x0004)
#define	_TX_TXOK                        (0x0001)
#define	_TX_SET(v,m,s)			((((UInt16)(v))<<((UInt16)(s)))&((UInt16)(m)))
#define	_TX_RETRYSTRAT_SET(v)		_TX_SET(v, _TX_RETRYSTRAT, 5)
#define	_TX_CFPOLL_SET(v)		_TX_SET(v, _TX_CFPOLL,12)
#define	_TX_MACPORT_SET(v)		_TX_SET(v, _TX_MACPORT, 8)
#define	_TX_TXEX_SET(v)			_TX_SET(v, _TX_TXEX, 2)
#define	_TX_TXOK_SET(v)			_TX_SET(v, _TX_TXOK, 1)

/*--------------------------------------------------------------------
FRAME STRUCTURES: Communication Frames
----------------------------------------------------------------------
Communication Frames: Transmit Frames
--------------------------------------------------------------------*/


/*------------------------------------*/
/* Request (bulk OUT) packet contents */

typedef struct _usb_txfrm {
	WLFrame         desc;
	UInt8           data[WLAN_DATA_MAXLEN];
} __attribute__((packed)) _usb_txfrm_t;

typedef struct _usb_cmdreq {
	UInt16		type				;
	UInt16		cmd				;
	UInt16		parm0				;
	UInt16		parm1				;
	UInt16		parm2				;
	UInt8		pad[54]				;
} __attribute__((packed)) _usb_cmdreq_t;

typedef struct _usb_wridreq {
	UInt16		type				;
	UInt16		frmlen				;
	UInt16		rid				;
	UInt8		data[_RIDDATA_MAXLEN]	;
} __attribute__((packed)) _usb_wridreq_t;

typedef struct _usb_rridreq {
	UInt16		type				;
	UInt16		frmlen				;
	UInt16		rid				;
	UInt8		pad[58]				;
} __attribute__((packed)) _usb_rridreq_t;

typedef struct _usb_wmemreq {
	UInt16		type				;
	UInt16		frmlen				;
	UInt16		offset				;
	UInt16		page				;
	UInt8		data[_USB_RWMEM_MAXLEN]	;
} __attribute__((packed)) _usb_wmemreq_t;

typedef struct _usb_rmemreq {
	UInt16		type				;
	UInt16		frmlen				;
	UInt16		offset				;
	UInt16		page				;
	UInt8		pad[56]				;
} __attribute__((packed)) _usb_rmemreq_t;

/*--------------------------------------------------------------------
Communication Frames: Receive Frames
--------------------------------------------------------------------*/

/*------------------------------------*/
/* Response (bulk IN) packet contents */

typedef struct _usb_rxfrm {
	WLFrame         desc;
	UInt8           data[WLAN_DATA_MAXLEN];
} __attribute__((packed)) _usb_rxfrm_t;

typedef struct _usb_cmdresp {
	UInt16		type				;
	UInt16		status				;
	UInt16		resp0				;
	UInt16		resp1				;
	UInt16		resp2				;
} __attribute__((packed)) _usb_cmdresp_t;

typedef struct _usb_wridresp {
	UInt16		type				;
	UInt16		status				;
	UInt16		resp0				;
	UInt16		resp1				;
	UInt16		resp2				;
} __attribute__((packed)) _usb_wridresp_t;

typedef struct _usb_rridresp {
	UInt16		type				;
	UInt16		frmlen				;
	UInt16		rid				;
	UInt8		data[_RIDDATA_MAXLEN]	;
} __attribute__((packed)) _usb_rridresp_t;

typedef struct _usb_wmemresp {
	UInt16		type				;
	UInt16		status				;
	UInt16		resp0				;
	UInt16		resp1				;
	UInt16		resp2				;
} __attribute__((packed)) _usb_wmemresp_t;

typedef struct _usb_rmemresp {
	UInt16		type				;
	UInt16		frmlen				;
	UInt8		data[_USB_RWMEM_MAXLEN]	;
} __attribute__((packed)) _usb_rmemresp_t;

typedef struct _usb_bufavail {
	UInt16		type				;
	UInt16		frmlen				;
} __attribute__((packed)) _usb_bufavail_t;

typedef struct _usb_error {
	UInt16		type				;
	UInt16		errortype			;
} __attribute__((packed)) _usb_error_t;

/*----------------------------------------------------------*/
/* Unions for packaging all the known packet types together */

typedef union _usbout {
	UInt16			type			;
	_usb_txfrm_t	txfrm			;
	_usb_cmdreq_t	cmdreq			;
	_usb_wridreq_t	wridreq			;
	_usb_rridreq_t	rridreq			;
	_usb_wmemreq_t	wmemreq			;
	_usb_rmemreq_t	rmemreq			;
} __attribute__((packed)) _usbout_t;

typedef union _usbin {
	UInt16			type			;
	_usb_rxfrm_t	rxfrm			;
	_usb_txfrm_t	txfrm			;
	_usb_cmdresp_t	cmdresp			;
	_usb_wridresp_t	wridresp		;
	_usb_rridresp_t	rridresp		;
	_usb_wmemresp_t	wmemresp		;
	_usb_rmemresp_t	rmemresp		;
	_usb_bufavail_t	bufavail		;
	_usb_error_t	usberror		;
	UInt8			boguspad[3000]  ;
} __attribute__((aligned)) __attribute__((packed)) _usbin_t;
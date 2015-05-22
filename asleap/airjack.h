/******************************************************************************
**
** AirJack: 802.11b attack drivers for use with the AirJack set of tools...
**
**   Author:  Abaddon, abaddon@802.11ninja.net
**
**   Other Development Stuff:  Xx25,  xx25@leper.org
**
**   Copyright (c) 2002 Abaddon, All Rights Reserved (see license info below). 
**
********************
**
**    airjack.h:
**        Header file for this thing...
**
********************
**
** Legal/Credits:
**
**   While this code is unique, much of it is influenced by the Absolute 
**   Value Systems wlan-ng driver. 
**
**   This program is free software; you can redistribute it and/or
**   modify it under the terms of the GNU General Public License
**   as published by the Free Software Foundation; either version 2
**   of the License, or (at your option) any later version.
**
**   This program is distributed in the hope that it will be useful,
**   but WITHOUT ANY WARRANTY; without even the implied warranty of
**   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**   GNU General Public License for more details.
**
**   You should have received a copy of the GNU General Public License
**   along with this program; if not, write to the Free Software
**   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
**
********************
**
** $Id: airjack.h,v 1.1.1.1 2003/07/16 09:22:16 jwright Exp $
**
******************************************************************************/
#ifndef __AIRJACK_H__
#define __AIRJACK_H__

#define SUCCESS	0
#define ERROR	-1


/* our device private ioctl calls */
#define SIOCAJSMODE		SIOCDEVPRIVATE		/* so i here this probably wont work on 2.5.x, blah */
#define SIOCAJGMODE		SIOCAJSMODE + 1

struct aj_config {
    __u16	mode;			/* mac port operating mode */
    __u8	ownmac[6];		/* our mac address */
    __u8	monitor;		/* are we in monitor mode */
    __u8	channel;		/* channel to operate on... */
    __u8	essid[33];		/* first byte is length */
};

/*
 * our ioctl structure...
 */
struct aj_ioctl {
    union {
        char	ifrn_name[IFNAMSIZ];	/* device name */
    } ifr_ifrn;
    struct aj_config	*config;		/* uses ifr_data */
};

/*
 * link layer header...
 */
struct llc_hdr {
    __u8	dsap;
    __u8	ssap;
    __u8	cntl;
    __u8	org_code[3];
    __u16	type;
} __attribute__ ((packed));


/* below this is the parts for the driver */
#if defined(__AIRJACK_C__) || defined(__HFA384X_C__)

#ifndef htons
#define htons	cpu_to_be16
#endif

#define __inline__ 

/*
#define DEBUG
#define DEBUG_VERBOSE
*/


#ifdef DEBUG
#ifdef DEBUG_VERBOSE
/* im pretty sure this is a GCC externtion but its too nice a feature to not use */
#define DEBUG_PRINT(args...)	do{ if(!in_interrupt()) {printk(KERN_WARNING args);} } while(0)
#else 
#define DEBUG_PRINT(...)	
#endif	/* #ifdef DEBUG_VERBOSE */
#else 
#define DEBUG_PRINT(...)	
#endif	/* #ifdef DEBUG */


#ifndef DWORD_SIZE
#define DWORD_SIZE	sizeof(unsigned long)
#endif

/* XXXX - replace this with whatever real define they have in the kernel someplace */
#ifndef CACHE_LINE
#define CACHE_LINE	32	/* this is for all P6 family < P4 (P4 is 128, Uber) */
#endif

#define MIN(a,b)	((a < b) ? a : b)
#define MAX(a,b)	((a > b) ? a : b)


/*
 * the device name (minus the device number) that will
 * display in ifconfig and other such things...
 */
#define AIRJACK_DEV_NAME	"aj"


#define DEFAULT_CHANNEL	11		/* the channel we'll start on */

/* needed for ARM support */
#pragma pack(1)

/*
 * the device info structure...this should always be allocated
 * on at least DWORD boundries but alloc_netdev() will insure
 * alignment on a 32 byte boundry of the private area, so its
 * not a problem...
 *
 * NOTE:
 *   do be mindful of alignment if you make changes...
 * XXXX - i need to take my own advice and fix alignment on this...
 */
typedef struct aj_info_t {
    __u8					registered:1;	/* is the net device registered yet? */
    __u8					irq_set:1;		/* set if the irq is setup */
    __u8					channel:4;		/* the channel we're on */
    __u8					tbusy:2;		/* reserved for later use */
    __u8					monitor;		/* monitor mode */
    __u8					mac[6];			/* the mac address we are pretending to be */
    __u8					essid[33];		/* essid, first byte length */
    __u16					port_mode;		/* current power save mode */
    struct net_device_stats	stats;			/* network device statistics */
    __u8					padding1[DWORD_SIZE - (sizeof(struct net_device_stats) % DWORD_SIZE)];	/* padding to dword line boundry */
    dev_link_t				link;			/* device link structure used by card services */
    __u8					padding2[DWORD_SIZE - (sizeof(dev_link_t) % DWORD_SIZE)];	/* padding to dword line boundry */
    dev_node_t				node;			/* device node structure */
    struct net_device		*net_dev;		/* network device structure */
    struct proc_dir_entry	*proc_ent;		/* proc filesystem entry */
} aj_info_t;


#define OUT384x(dev, reg, u16value)	outw(u16value, dev->net_dev->base_addr+reg)
#define IN384x(dev, reg)			inw(dev->net_dev->base_addr+reg)


/*  HFA384x txFid control header */
struct tx_control {

    /* now where have i seen this before? ;) */
	__u16	tc_status;
	__u16	tc_reserved1;
	__u16	tc_reserved2;
	__u32	tc_sw_sup;
	__u16	tc_reserved3;
	__u16	tc_tx_ctl;

    /* 802.11 header (most of it any ways) */
	__u16	tc_fc;
	__u16	tc_duration_id;
	__u8	tc_mac1[6];
	__u8	tc_mac2[6];
	__u8	tc_mac3[6];
	__u16	tc_seq_ctl;
	__u8	tc_mac4[6];
	__u16	tc_data_len;			/* little endian */

    /* 802.3 header? */
	__u8	tc_dest_addr[6];
	__u8	tc_src_addr[6];
	__u16	tc_data_length;		/* big endian */
} __attribute__ ((packed));


#ifdef __AIRJACK_C__

extern struct file_operations	airjack_operations;

extern void hfa384x_disable_interrupts (aj_info_t *);
extern void hfa384x_enable_interrupts (aj_info_t *);
extern void hfa384x_aux_enable (aj_info_t *);
extern void hfa384x_aux_disable (aj_info_t *);
extern void hfa384x_aux_write (aj_info_t *, __u32, __u16 *, ssize_t);
extern void hfa384x_aux_read (aj_info_t *, __u32, __u16 *, ssize_t);
extern ssize_t airjack_read_core (struct file *, char *, size_t, loff_t *);

#endif


#define HFA384X_VCC						50
#define HFA384X_VPP1					50
#define HFA384X_VPP2					50
#define HFA384X_MTU						1700
#define BIT0							0x00000001
#define BIT1							0x00000002
#define BIT2							0x00000004
#define BIT3							0x00000008
#define BIT4							0x00000010
#define BIT5							0x00000020
#define BIT6							0x00000040
#define BIT7							0x00000080
#define BIT8							0x00000100
#define BIT9							0x00000200
#define BIT10							0x00000400
#define BIT11							0x00000800
#define BIT12							0x00001000
#define BIT13							0x00002000
#define BIT14							0x00004000
#define BIT15							0x00008000
#define BIT16							0x00010000
#define BIT17							0x00020000
#define BIT18							0x00040000
#define BIT19							0x00080000
#define BIT20							0x00100000
#define BIT21							0x00200000
#define BIT22							0x00400000
#define BIT23							0x00800000
#define BIT24							0x01000000
#define BIT25							0x02000000
#define BIT26							0x04000000
#define BIT27							0x08000000
#define BIT28							0x10000000
#define BIT29							0x20000000
#define BIT30							0x40000000
#define BIT31							0x80000000
#define HFA384X_DISABLE_RXCRYPT			((__u16)BIT7)
#define HFA384X_AUX_CTL_EXTDS			(0x00)
#define	HFA384X_AUX_PAGE_MASK			(0x003fff80)
#define	HFA384X_AUX_OFF_MASK			(0x0000007f)
#define	HFA384X_AUX_OFF_MAX				((__u16)0x007f)
#define	HFA384X_AUX_PAGE_MAX			((__u16)0xffff)
#define	HFA384X_AUX_MKOFF(n, c)			((((__u16)(n))&HFA384X_AUX_OFF_MASK) | (((__u16)(c))<<12))
#define	HFA384X_AUX_MKPAGE(n)			((__u16)(((n)&HFA384X_AUX_PAGE_MASK)>>7))
#define	HFA384X_CMD						(0x00)
#define	HFA384X_PARAM0					(0x02)
#define	HFA384X_PARAM1					(0x04)
#define	HFA384X_PARAM2					(0x06)
#define	HFA384X_STATUS					(0x08)
#define	HFA384X_RESP0					(0x0A)
#define	HFA384X_RESP1					(0x0C)
#define	HFA384X_RESP2					(0x0E)
#define	HFA384X_ALLOCFID				(0x22)
#define	HFA384X_RXFID					(0x20)
#define	HFA384X_SELECT0					(0x18)
#define	HFA384X_OFFSET0					(0x1C)
#define	HFA384X_DATA0					(0x36)
#define	HFA384X_SELECT1					(0x1A)
#define	HFA384X_OFFSET1					(0x1E)
#define	HFA384X_DATA1					(0x38)
#define	HFA384X_EVSTAT					(0x30)
#define	HFA384X_INTEN					(0x32)
#define	HFA384X_EVACK					(0x34)
#define	HFA384X_CONTROL					(0x14)
#define	HFA384X_AUXPAGE					(0x3A)
#define	HFA384X_AUXOFFSET				(0x3C)
#define	HFA384X_AUXDATA					(0x3E)
#define	HFA384X_CMD_BUSY				((__u16)BIT15)
#define	HFA384X_CMD_AINFO				((__u16)(BIT14 | BIT13 | BIT12 | BIT11 | BIT10 | BIT9 | BIT8))
#define	HFA384X_CMD_MACPORT				((__u16)(BIT10 | BIT9 | BIT8))
#define	HFA384X_CMD_RECL				((__u16)BIT8)
#define	HFA384X_CMD_WRITE				((__u16)BIT8)
#define	HFA384X_CMD_PROGMODE			((__u16)(BIT9 | BIT8))
#define	HFA384X_CMD_CMDCODE				((__u16)(BIT5 | BIT4 | BIT3 | BIT2 | BIT1 | BIT0))
#define	HFA384X_STATUS_RESULT			((__u16)(BIT14 | BIT13 | BIT12 | BIT11 | BIT10 | BIT9 | BIT8))
#define	HFA384X_STATUS_CMDCODE			((__u16)(BIT5 | BIT4 | BIT3 | BIT2 | BIT1 | BIT0))
#define	HFA384X_OFFSET_BUSY				((__u16)BIT15)
#define	HFA384X_OFFSET_ERR				((__u16)BIT14)
#define	HFA384X_OFFSET_DATAOFF			((__u16)(BIT11 | BIT10 | BIT9 | BIT8 | BIT7 | BIT6 | BIT5 | BIT4 | BIT3 | BIT2 | BIT1))
#define	HFA384X_EVSTAT_CMD				((__u16)BIT4)
#define	HFA384X_EVSTAT_ALLOC			((__u16)BIT3)
#define	HFA384X_EVSTAT_TXEXC			((__u16)BIT2)
#define	HFA384X_EVSTAT_TX				((__u16)BIT1)
#define	HFA384X_EVSTAT_RX				((__u16)BIT0)
#define	HFA384X_EVACK_CMD				((__u16)BIT4)
#define	HFA384X_EVACK_ALLOC				((__u16)BIT3)
#define	HFA384X_EVACK_TXEXC				((__u16)BIT2)
#define	HFA384X_EVACK_TX				((__u16)BIT1)
#define	HFA384X_EVACK_RX				((__u16)BIT0)
#define	HFA384X_CMDCODE_INIT			((__u16)0x00)
#define	HFA384X_CMDCODE_ENABLE			((__u16)0x01)
#define	HFA384X_CMDCODE_DISABLE			((__u16)0x02)
#define	HFA384X_CMDCODE_ALLOC			((__u16)0x0A)
#define	HFA384X_CMDCODE_TX				((__u16)0x0B)
#define	HFA384X_CMDCODE_ACCESS			((__u16)0x21)
#define HFA384X_CMDCODE_MONITOR			((__u16)(0x38))
#define	HFA384X_MONITOR_ENABLE			((__u16)(0x0b))
#define	HFA384X_MONITOR_DISABLE			((__u16)(0x0f))
#define	HFA384X_AUXPW0					((__u16)0xfe01)
#define	HFA384X_AUXPW1					((__u16)0xdc23)
#define	HFA384X_AUXPW2					((__u16)0xba45)
#define	HFA384X_CONTROL_AUX_ISDISABLED	((__u16)0x0000)
#define	HFA384X_CONTROL_AUX_ISENABLED	((__u16)0xc000)
#define	HFA384X_CONTROL_AUX_DOENABLE	((__u16)0x8000)
#define	HFA384X_CONTROL_AUX_DODISABLE	((__u16)0x4000)
#define	HFA384X_RID_CNFPORTTYPE			((__u16)0xFC00)
#define	HFA384X_RID_CNFOWNMACADDR		((__u16)0xFC01)
#define	HFA384X_RID_CNFDESIREDSSID		((__u16)0xFC02)
#define	HFA384X_RID_CNFOWNCHANNEL		((__u16)0xFC03)
#define	HFA384X_RID_CNFOWNSSID			((__u16)0xFC04)
#define	HFA384X_RID_CNFMAXDATALEN		((__u16)0xFC07)
#define	HFA384X_RID_CNFBEACONINT 		((__u16)0xFC33)
#define	HFA384X_RID_CREATEIBSS			((__u16)0xFC81)
#define	HFA384X_RID_CNFWEPFLAGS			((__u16)0xFC28)
#define	HFA384X_CMD_RECL_SET(value)		((__u16)((__u16)((__u16)(value) << 8)))
#define	HFA384X_CMD_QOS_SET(value)		((__u16)((((__u16)(value)) << 12) & 0x3000))
#define	HFA384X_EVACK_ISALLOC(value)	((__u16)(((__u16)(value)) & HFA384X_EVACK_ALLOC))
#define	HFA384X_CMD_WRITE_SET(value)	((__u16)((__u16)((__u16)(value) << 8)))
#define	HFA384X_TX_CFPOLL				((__u16)BIT12)
#define	HFA384X_TX_PRST					((__u16)BIT11)
#define	HFA384X_TX_MACPORT				((__u16)(BIT10 | BIT9 | BIT8))
#define	HFA384X_TX_NOENCRYPT			((__u16)BIT7)
#define	HFA384X_TX_RETRYSTRAT			((__u16)(BIT6 | BIT5))
#define	HFA384X_TX_STRUCTYPE			((__u16)(BIT4 | BIT3))
#define	HFA384X_TX_TXEX					((__u16)BIT2)
#define	HFA384X_TX_TXOK					((__u16)BIT1)
#define	HFA384X_TX_SET(v,m,s)			((((__u16)(v))<<((__u16)(s)))&((__u16)(m)))
#define	HFA384X_TX_CFPOLL_SET(v)		HFA384X_TX_SET(v, HFA384X_TX_CFPOLL,12)
#define	HFA384X_TX_MACPORT_SET(v)		HFA384X_TX_SET(v, HFA384X_TX_MACPORT, 8)
#define	HFA384X_TX_RETRYSTRAT_SET(v)	HFA384X_TX_SET(v, HFA384X_TX_RETRYSTRAT, 5)
#define	HFA384X_TX_STRUCTYPE_SET(v)		HFA384X_TX_SET(v, HFA384X_TX_STRUCTYPE, 3)
#define	HFA384X_TX_TXEX_SET(v)			HFA384X_TX_SET(v, HFA384X_TX_TXEX, 2)
#define	HFA384X_TX_TXOK_SET(v)			HFA384X_TX_SET(v, HFA384X_TX_TXOK, 1)
#define	HFA384X_RXSTATUS_FCSERR			((__u16)BIT0)
#define	HFA384X_BAP0					0
#define	HFA384X_BAP1					2
#define	HFA384X_VCC						50
#define	HFA384X_VPP1					50
#define	HFA384X_VPP2					50

#define HFA384X_WEPFLAGS_HOSTENCRYPT BIT4
#define HFA384X_WEPFLAGS_HOSTDECRYPT BIT7


/*
 * this structure holds all the values returned from a command...
 */
typedef struct cmd_resp_t {
    __u16	status;
    __u16	resp0;
    __u16	resp1;
    __u16	resp2;
} cmd_resp_t;

/* Interrupt Mask (just the interrupts we care about here) */
#define HFA384X_IRQ_MASK	((1<<0)|(1<<1)|(1<<2))


#pragma pack()

#ifdef __HFA384X_C__

#define CMD_MAX_RETRIES		100000	/* max number of retries to issue for a command */

#endif /* #ifdef __HFA384X_C__ */


#ifndef __AIRJACK_C__

/*** Globals ***/
/***************/


/*** Prototypes ***/
/******************/

#endif /* #ifndef __AIRJACK_C__ */

#ifndef __HFA384X_C__

/*** Globals ***/
/***************/


/*** Prototypes ***/

extern void hfa384x_clear_status (aj_info_t *);
extern void hfa384x_busy_wait (aj_info_t *);
extern int hfa384x_command (aj_info_t *, __u16, __u16, __u16, __u16, cmd_resp_t *);
extern void hfa384x_command_no_wait (aj_info_t *, __u16, __u16, __u16, __u16);
extern int hfa384x_setup_bap (aj_info_t *, __u16, __u16, int);
extern int hfa384x_read_bap (aj_info_t *, __u16 *, size_t, int);
extern int hfa384x_write_bap (aj_info_t *, __u16 *, size_t, int);
extern int hfa384x_read_rid (aj_info_t *, __u16, void *, size_t, int);
extern int hfa384x_write_rid (aj_info_t *, __u16, void *, size_t, int);

/******************/


#endif /* #ifndef __HFA384X_C__ */
#endif /*#if defined(__AIRJACK_C__) || defined(__HFA384X_C__) */

#endif /* #ifndef __AIRJACK_H__ */


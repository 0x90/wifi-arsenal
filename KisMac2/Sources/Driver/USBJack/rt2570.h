/*************************************************************************** 
 * RT2x00 SourceForge Project - http://rt2x00.sourceforge.net              * 
 *                                                                         * 
 *   This program is free software; you can redistribute it and/or modify  * 
 *   it under the terms of the GNU General Public License as published by  * 
 *   the Free Software Foundation; either version 2 of the License, or     * 
 *   (at your option) any later version.                                   * 
 *                                                                         * 
 *   This program is distributed in the hope that it will be useful,       * 
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        * 
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         * 
 *   GNU General Public License for more details.                          * 
 *                                                                         * 
 *   You should have received a copy of the GNU General Public License     * 
 *   along with this program; if not, write to the                         * 
 *   Free Software Foundation, Inc.,                                       * 
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             * 
 *                                                                         * 
 *   Licensed under the GNU GPL                                            * 
 *   Original code supplied under license from RaLink Inc, 2004.           * 
 ***************************************************************************/

/*************************************************************************** 
 *	Module Name:	rt2570.h
 *
 *	Abstract:
 *
 *	Revision History:
 *	Who		When		What
 *	--------	----------	-----------------------------
 *	Name		Date		Modification logs
 *	Jan Lee		2005-06-01	Release
 ***************************************************************************/
#ifndef	__RT2570_H__
#define	__RT2570_H__

#include "ralink.h"

#define RETRY_LIMIT	3
#define	LENGTH_802_11			24

#define ETH_LENGTH_OF_ADDRESS   6

#define mdelay(a) usleep(a*100)
#define NdisMSleep	mdelay

// value domain for pAdapter->PortCfg.RfType
#define RFIC_2522               0
#define RFIC_2523               1
#define RFIC_2524               2
#define RFIC_2525               3
#if 0//steven:modified by brand,blue
#define RFIC_2525E              4
#else
#define RFIC_2525E              5
#endif
#define RFIC_5222               16
// This chip is same as RT2526, it's for 11b only purpose
#define	RFIC_2426				6

typedef	struct	_RTMP_RF_REGS
{
	UCHAR   Channel;
	ULONG	R1;
	ULONG   R2;
	ULONG   R3;
	ULONG   R4;
}	RTMP_RF_REGS, *PRTMP_RF_REGS;

typedef	struct	_RTMP_RF_REGS_1
{
	UCHAR   Channel;
	ULONG	TempR2;
	ULONG	R1;
	ULONG   R2;
	ULONG   R3;
	ULONG   R4;
}	RTMP_RF_REGS_1, *PRTMP_RF_REGS_1;

RTMP_RF_REGS RF2522RegTable[] = {
    //      ch   R1          R2          R3(TX0~4=0) R4
{1,  0x94002050, 0x940c1fda, 0x94000101, 0},
{2,  0x94002050, 0x940c1fee, 0x94000101, 0},
{3,  0x94002050, 0x940c2002, 0x94000101, 0},
{4,  0x94002050, 0x940c2016, 0x94000101, 0},
{5,  0x94002050, 0x940c202a, 0x94000101, 0},
{6,  0x94002050, 0x940c203e, 0x94000101, 0},
{7,  0x94002050, 0x940c2052, 0x94000101, 0},
{8,  0x94002050, 0x940c2066, 0x94000101, 0},
{9,  0x94002050, 0x940c207a, 0x94000101, 0},
{10, 0x94002050, 0x940c208e, 0x94000101, 0},
{11, 0x94002050, 0x940c20a2, 0x94000101, 0},
{12, 0x94002050, 0x940c20b6, 0x94000101, 0},
{13, 0x94002050, 0x940c20ca, 0x94000101, 0},
{14, 0x94002050, 0x940c20fa, 0x94000101, 0}
};
#define	NUM_OF_2522_CHNL	(sizeof(RF2522RegTable) / sizeof(RTMP_RF_REGS))

RTMP_RF_REGS RF2523RegTable[] = {
    //      ch   R1          R2          R3(TX0~4=0) R4
    {1,  0x94022010, 0x94000c9e, 0x940e0111, 0x94000a1b},
    {2,  0x94022010, 0x94000ca2, 0x940e0111, 0x94000a1b},
    {3,  0x94022010, 0x94000ca6, 0x940e0111, 0x94000a1b},
    {4,  0x94022010, 0x94000caa, 0x940e0111, 0x94000a1b},
    {5,  0x94022010, 0x94000cae, 0x940e0111, 0x94000a1b},
    {6,  0x94022010, 0x94000cb2, 0x940e0111, 0x94000a1b},
    {7,  0x94022010, 0x94000cb6, 0x940e0111, 0x94000a1b},
    {8,  0x94022010, 0x94000cba, 0x940e0111, 0x94000a1b},
    {9,  0x94022010, 0x94000cbe, 0x940e0111, 0x94000a1b},
    {10, 0x94022010, 0x94000d02, 0x940e0111, 0x94000a1b},
    {11, 0x94022010, 0x94000d06, 0x940e0111, 0x94000a1b},
    {12, 0x94022010, 0x94000d0a, 0x940e0111, 0x94000a1b},
    {13, 0x94022010, 0x94000d0e, 0x940e0111, 0x94000a1b},
    {14, 0x94022010, 0x94000d1a, 0x940e0111, 0x94000a03}
};
#define	NUM_OF_2523_CHNL	(sizeof(RF2523RegTable) / sizeof(RTMP_RF_REGS))

RTMP_RF_REGS RF2524RegTable[] = {
    //      ch   R1          R2          R3(TX0~4=0) R4
    {1,  0x94032020, 0x94000c9e, 0x94000101, 0x94000a1b},
    {2,  0x94032020, 0x94000ca2, 0x94000101, 0x94000a1b},
    {3,  0x94032020, 0x94000ca6, 0x94000101, 0x94000a1b},
    {4,  0x94032020, 0x94000caa, 0x94000101, 0x94000a1b},
    {5,  0x94032020, 0x94000cae, 0x94000101, 0x94000a1b},
    {6,  0x94032020, 0x94000cb2, 0x94000101, 0x94000a1b},
    {7,  0x94032020, 0x94000cb6, 0x94000101, 0x94000a1b},
    {8,  0x94032020, 0x94000cba, 0x94000101, 0x94000a1b},
    {9,  0x94032020, 0x94000cbe, 0x94000101, 0x94000a1b},
    {10, 0x94032020, 0x94000d02, 0x94000101, 0x94000a1b},
    {11, 0x94032020, 0x94000d06, 0x94000101, 0x94000a1b},
    {12, 0x94032020, 0x94000d0a, 0x94000101, 0x94000a1b},
    {13, 0x94032020, 0x94000d0e, 0x94000101, 0x94000a1b},
    {14, 0x94032020, 0x94000d1a, 0x94000101, 0x94000a03}
};
#define	NUM_OF_2524_CHNL	(sizeof(RF2524RegTable) / sizeof(RTMP_RF_REGS))

RTMP_RF_REGS_1 RF2525RegTable[] = {
    //      ch   TempR2		 R1          R2          R3(TX0~4=0) R4
    {1,  0x94080cbe, 0x94022020, 0x94080c9e, 0x94060111, 0x94000a1b}, // {1,  0x94022010, 0x9408062e, 0x94060111, 0x94000a23}, 
    {2,  0x94080d02, 0x94022020, 0x94080ca2, 0x94060111, 0x94000a1b},
    {3,  0x94080d06, 0x94022020, 0x94080ca6, 0x94060111, 0x94000a1b},
    {4,  0x94080d0a, 0x94022020, 0x94080caa, 0x94060111, 0x94000a1b},
    {5,  0x94080d0e, 0x94022020, 0x94080cae, 0x94060111, 0x94000a1b},
    {6,  0x94080d12, 0x94022020, 0x94080cb2, 0x94060111, 0x94000a1b},
    {7,  0x94080d16, 0x94022020, 0x94080cb6, 0x94060111, 0x94000a1b},
    {8,  0x94080d1a, 0x94022020, 0x94080cba, 0x94060111, 0x94000a1b},
    {9,  0x94080d1e, 0x94022020, 0x94080cbe, 0x94060111, 0x94000a1b},
    {10, 0x94080d22, 0x94022020, 0x94080d02, 0x94060111, 0x94000a1b},
    {11, 0x94080d26, 0x94022020, 0x94080d06, 0x94060111, 0x94000a1b}, // {11, 0x94022010, 0x94080682, 0x94060111, 0x94000a23}, 
    {12, 0x94080d2a, 0x94022020, 0x94080d0a, 0x94060111, 0x94000a1b},
    {13, 0x94080d2e, 0x94022020, 0x94080d0e, 0x94060111, 0x94000a1b}, // {13, 0x94022010, 0x94080686, 0x94060111, 0x94000a23}, 
    {14, 0x94080d3a, 0x94022020, 0x94080d1a, 0x94060111, 0x94000a03}
};
#define	NUM_OF_2525_CHNL	(sizeof(RF2525RegTable) / sizeof(RTMP_RF_REGS_1))

RTMP_RF_REGS_1 RF2525eRegTable[] = {
    // using 10 Mhz reference clock
    //      ch   TempR2		 R1          R2          R3(TX0~4=0) R4
    {1,  0x940008aa, 0x94022010, 0x9400089a, 0x94060111, 0x94000e1b},
    {2,  0x940008ae, 0x94022010, 0x9400089e, 0x94060111, 0x94000e07},
    {3,  0x940008ae, 0x94022010, 0x9400089e, 0x94060111, 0x94000e1b},
    {4,  0x940008b2, 0x94022010, 0x940008a2, 0x94060111, 0x94000e07},
    {5,  0x940008b2, 0x94022010, 0x940008a2, 0x94060111, 0x94000e1b},
    {6,  0x940008b6, 0x94022010, 0x940008a6, 0x94060111, 0x94000e07},
    {7,  0x940008b6, 0x94022010, 0x940008a6, 0x94060111, 0x94000e1b},
    {8,  0x940008ba, 0x94022010, 0x940008aa, 0x94060111, 0x94000e07},
    {9,  0x940008ba, 0x94022010, 0x940008aa, 0x94060111, 0x94000e1b},
    {10, 0x940008be, 0x94022010, 0x940008ae, 0x94060111, 0x94000e07},
    {11, 0x940008b7, 0x94022010, 0x940008ae, 0x94060111, 0x94000e1b}, 
    {12, 0x94000902, 0x94022010, 0x940008b2, 0x94060111, 0x94000e07},
    {13, 0x94000902, 0x94022010, 0x940008b2, 0x94060111, 0x94000e1b},
    {14, 0x94000906, 0x94022010, 0x940008b6, 0x94060111, 0x94000e23}
};
#define	NUM_OF_2525E_CHNL	(sizeof(RF2525eRegTable) / sizeof(RTMP_RF_REGS_1))

RTMP_RF_REGS RF5222RegTable[] = {
    //      ch   R1          R2          R3(TX0~4=0) R4
    {1,  0x94022020, 0x94001136, 0x94000101, 0x94000a0b},
    {2,  0x94022020, 0x9400113a, 0x94000101, 0x94000a0b},
    {3,  0x94022020, 0x9400113e, 0x94000101, 0x94000a0b},
    {4,  0x94022020, 0x94001182, 0x94000101, 0x94000a0b},
    {5,  0x94022020, 0x94001186, 0x94000101, 0x94000a0b},
    {6,  0x94022020, 0x9400118a, 0x94000101, 0x94000a0b},
    {7,  0x94022020, 0x9400118e, 0x94000101, 0x94000a0b},
    {8,  0x94022020, 0x94001192, 0x94000101, 0x94000a0b},
    {9,  0x94022020, 0x94001196, 0x94000101, 0x94000a0b},
    {10, 0x94022020, 0x9400119a, 0x94000101, 0x94000a0b},
    {11, 0x94022020, 0x9400119e, 0x94000101, 0x94000a0b},
    {12, 0x94022020, 0x940011a2, 0x94000101, 0x94000a0b},
    {13, 0x94022020, 0x940011a6, 0x94000101, 0x94000a0b},
    {14, 0x94022020, 0x940011ae, 0x94000101, 0x94000a1b},
    
    // still lack of MMAC(Japan) ch 34,38,42,46
    
    {36, 0x94022010, 0x94018896, 0x94000101, 0x94000a1f},
    {40, 0x94022010, 0x9401889a, 0x94000101, 0x94000a1f},
    {44, 0x94022010, 0x9401889e, 0x94000101, 0x94000a1f},
    {48, 0x94022010, 0x940188a2, 0x94000101, 0x94000a1f},
    {52, 0x94022010, 0x940188a6, 0x94000101, 0x94000a1f},
    {66, 0x94022010, 0x940188aa, 0x94000101, 0x94000a1f},
    {60, 0x94022010, 0x940188ae, 0x94000101, 0x94000a1f},
    {64, 0x94022010, 0x940188b2, 0x94000101, 0x94000a1f},
    
    {100, 0x94022010, 0x94008802, 0x94000101, 0x94000a0f},
    {104, 0x94022010, 0x94008806, 0x94000101, 0x94000a0f},
    {108, 0x94022010, 0x9400880a, 0x94000101, 0x94000a0f},
    {112, 0x94022010, 0x9400880e, 0x94000101, 0x94000a0f},
    {116, 0x94022010, 0x94008812, 0x94000101, 0x94000a0f},
    {120, 0x94022010, 0x94008816, 0x94000101, 0x94000a0f},
    {124, 0x94022010, 0x9400881a, 0x94000101, 0x94000a0f},
    {128, 0x94022010, 0x9400881e, 0x94000101, 0x94000a0f},
    {132, 0x94022010, 0x94008822, 0x94000101, 0x94000a0f},
    {136, 0x94022010, 0x94008826, 0x94000101, 0x94000a0f},
    {140, 0x94022010, 0x9400882a, 0x94000101, 0x94000a0f},
    
    {149, 0x94022020, 0x940090a6, 0x94000101, 0x94000a07},
    {153, 0x94022020, 0x940090ae, 0x94000101, 0x94000a07},
    {157, 0x94022020, 0x940090b6, 0x94000101, 0x94000a07},
    {161, 0x94022020, 0x940090be, 0x94000101, 0x94000a07}
};
#define	NUM_OF_5222_CHNL	(sizeof(RF5222RegTable) / sizeof(RTMP_RF_REGS))

USHORT	 RT2570BBPRegTable[] = {
	0x0302,  // R03
	0x0419,  // R04
	0x0E1C,  // R14
	0x0F30,  // R15
	0x10ac,  // R16
	0x1148,  // R17
	0x1218,  // R18
	0x13ff,  // R19
	0x141E,  // R20
	0x1508,  // R21
	0x1608,  // R22
	0x1708,  // R23
             //modified by david    0x1870,	// R24
	0x1880,  // R24	modified by david
             //modified by gary	  0x1940,  // R25
	0x1950,  // R25	//modified by gary
	0x1A08,  // R26
	0x1B23,  // R27
	0x1E10,  // R30
	0x1F2B,  // R31
	0x20B9,  // R32
	0x2212,  // R34
	0x2350,  // R35
	0x27c4,  // R39
	0x2802,  // R40
	0x2960,  // R41
	0x3510,  // R53
	0x3618,  // R54
	0x3808,  // R56
	0x3910,  // R57
	0x3A08,  // R58
	0x3D60,  // R61
	0x3E10,  // R62
	0x4BFF,  // R75//by MAX
};

#define	NUM_BBP_REG_PARMS	(sizeof(RT2570BBPRegTable) / sizeof(USHORT))

//
// P802.11 Frame control field, 16 bit
//
typedef	struct	_FRAME_CONTROL	{
	USHORT		Ver:2;				// Protocol version
	USHORT		Type:2;				// MSDU type
	USHORT		Subtype:4;			// MSDU subtype
	USHORT		ToDs:1;				// To DS indication
	USHORT		FrDs:1;				// From DS indication
	USHORT		MoreFrag:1;			// More fragment bit
	USHORT		Retry:1;			// Retry status bit
	USHORT		PwrMgt:1;			// Power management bit
	USHORT		MoreData:1;			// More data bit
	USHORT		Wep:1;				// Wep data
	USHORT		Order:1;			// Strict order expected
}	FRAME_CONTROL, *PFRAME_CONTROL;

typedef	struct	_CONTROL_HEADER	{
	FRAME_CONTROL	Frame;				// Frame control structure
	USHORT			Duration;			// Duration value
	UInt8			Addr1[6];				// Address 1 field
	UInt8			Addr2[6];				// Address 2 field
}	CONTROL_HEADER, *PCONTROL_HEADER;

typedef	struct	_HEADER_802_11	{
	CONTROL_HEADER	Controlhead;
	UInt8			Addr3[6];				// Address 3 field
	USHORT			Frag:4;				// Fragment number
	USHORT			Sequence:12;		// Sequence number
}	HEADER_802_11, *PHEADER_802_11;
/*
typedef struct _BBP_TUNING_PARAMETERS_STRUC
{
	UCHAR			BBPTuningThreshold;
	UCHAR			R24LowerValue;
	UCHAR			R24HigherValue;
	UCHAR			R25LowerValue;
	UCHAR			R25HigherValue;
	UCHAR			R61LowerValue;
	UCHAR			R61HigherValue;
	UCHAR			BBPR17LowSensitivity;
	UCHAR			BBPR17MidSensitivity;
	UCHAR			RSSIToDbmOffset;
	bool			LargeCurrentRSSI;
}
BBP_TUNING_PARAMETERS_STRUC, *PBBP_TUNING_PARAMETERS_STRUC;
*/

//
// Control/Status Registers	(CSR)
//
#define	MAC_CSR0		0x00	// ASIC	version
#define	MAC_CSR1		0x02	// system control
#define	MAC_CSR2		0x04	// MAC addr0
#define	MAC_CSR3		0x06	// MAC addr1
#define	MAC_CSR4		0x08	// MAC addr2
#define	MAC_CSR5		0x0A	// BSSID0
#define	MAC_CSR6		0x0C	// BSSID1
#define	MAC_CSR7		0x0E	// BSSID2
#define	MAC_CSR8		0x10	// max frame length
#define	MAC_CSR9		0x12	// timer control
#define	MAC_CSR10		0x14	// slot time
#define	MAC_CSR11		0x16	// IFS
#define	MAC_CSR12		0x18	// EIFS
#define	MAC_CSR13		0x1A	// power mode0
#define	MAC_CSR14		0x1C	// power mode1
#define	MAC_CSR15		0x1E	// power saving transition0
#define	MAC_CSR16		0x20	// power saving transition1
#define	MAC_CSR17		0x22	// power state control
#define	MAC_CSR18		0x24	// auto wake-up control
#define	MAC_CSR19		0x26	// GPIO control
#define	MAC_CSR20		0x28	// LED control0
#define	MAC_CSR21		0x2A	// LED control1
#define	MAC_CSR22		0x2C	// LED control1

#define	TXRX_CSR0		0x40		// security control
#define	TXRX_CSR1		0x42		// TX configuration
#define	TXRX_CSR2		0x44		// RX control
#define	TXRX_CSR3		0x46		// CCK RX BBP ID
#define	TXRX_CSR4		0x48		// OFDM RX BBP ID
#define	TXRX_CSR5		0x4A		// CCK TX BBP ID0
#define	TXRX_CSR6		0x4C		// CCK TX BBP ID1
#define	TXRX_CSR7		0x4E		// OFDM TX BBP ID0
#define	TXRX_CSR8		0x50		// OFDM TX BBP ID1
#define	TXRX_CSR9		0x52		// TX ACK time-out
#define	TXRX_CSR10		0x54		// auto responder control
#define	TXRX_CSR11		0x56		// auto responder basic rate
#define	TXRX_CSR12		0x58		// ACK/CTS time0
#define	TXRX_CSR13		0x5A		// ACK/CTS time1
#define	TXRX_CSR14		0x5C		// ACK/CTS time2
#define	TXRX_CSR15		0x5E		// ACK/CTS time3
#define	TXRX_CSR16		0x60		// ACK/CTS time4
#define	TXRX_CSR17		0x62		// ACK/CTS time5
#define	TXRX_CSR18		0x64		// Beacon interval
#define	TXRX_CSR19		0x66		// Beacon/sync control
#define	TXRX_CSR20		0x68		// Beacon alignment
#define	TXRX_CSR21		0x6A		// blue

//WEP key registers
#define	SEC_CSR0		0x80	// shared key 0, word 0
#define	SEC_CSR1		0x82	// shared key 0, word 1
#define	SEC_CSR2		0x84	// shared key 0, word 2
#define	SEC_CSR3		0x86	// shared key 0, word 3
#define	SEC_CSR4		0x88	// shared key 0, word 4
#define	SEC_CSR5		0x8A	// shared key 0, word 5
#define	SEC_CSR6		0x8C	// shared key 0, word 6
#define	SEC_CSR7		0x8E	// shared key 0, word 7
#define	SEC_CSR8		0x90	// shared key 1, word 0
#define	SEC_CSR9		0x92	// shared key 1, word 1
#define	SEC_CSR10		0x94	// shared key 1, word 2
#define	SEC_CSR11		0x96	// shared key 1, word 3
#define	SEC_CSR12		0x98	// shared key 1, word 4
#define	SEC_CSR13		0x9A	// shared key 1, word 5
#define	SEC_CSR14		0x9C	// shared key 1, word 6
#define	SEC_CSR15		0x9E	// shared key 1, word 7
#define	SEC_CSR16		0xA0	// shared key 2, word 0
#define	SEC_CSR17		0xA2	// shared key 2, word 1
#define	SEC_CSR18		0xA4	// shared key 2, word 2
#define	SEC_CSR19		0xA6	// shared key 2, word 3
#define	SEC_CSR20		0xA8	// shared key 2, word 4
#define	SEC_CSR21		0xAA	// shared key 2, word 5
#define	SEC_CSR22		0xAC	// shared key 2, word 6
#define	SEC_CSR23		0xAE	// shared key 2, word 7
#define	SEC_CSR24		0xB0	// shared key 3, word 0
#define	SEC_CSR25		0xB2	// shared key 3, word 1
#define	SEC_CSR26		0xB4	// shared key 3, word 2
#define	SEC_CSR27		0xB6	// shared key 3, word 3
#define	SEC_CSR28		0xB8	// shared key 3, word 4
#define	SEC_CSR29		0xBA	// shared key 3, word 5
#define	SEC_CSR30		0xBC	// shared key 3, word 6
#define	SEC_CSR31		0xBE	// shared key 3, word 7

//PHY control registers
#define	PHY_CSR0		0xC0	// RF switching timing control
#define	PHY_CSR1		0xC2	// TX PA configuration
#define	PHY_CSR2		0xC4	// TX MAC configuration
#define	PHY_CSR3		0xC6	// RX MAC configuration
#define	PHY_CSR4		0xC8	// interface configuration
#define	PHY_CSR5		0xCA	// BBP pre-TX CCK
#define	PHY_CSR6		0xCC	// BBP pre-TX OFDM
#define	PHY_CSR7		0xCE	// BBP serial control
#define	PHY_CSR8		0xD0	// BBP serial status
#define	PHY_CSR9		0xD2	// RF serial control0
#define	PHY_CSR10		0xD4	// RF serial control1


// Statistic Register
#define	STA_CSR0		0xE0		// FCS error
#define	STA_CSR1		0xE2		// PLCP error
#define	STA_CSR2		0xE4		// LONG error
#define	STA_CSR3		0xE6		// CCA false alarm
#define	STA_CSR4		0xE8		// RX FIFO overflow
#define	STA_CSR5		0xEA		// Beacon sent counter
#define	STA_CSR6		0xEC
#define	STA_CSR7		0xEE
#define	STA_CSR8		0xF0
#define	STA_CSR9		0xF2
#define	STA_CSR10		0xF4

//
// BBP & RF	definition
//
#define	BUSY		1
#define	IDLE		0

#define	BBP_Version					0x00
#define	BBP_Tx_Configure			2  // R2
#define	BBP_Tx_Tssi					1  // R1,blue
#define	BBP_Rx_Configure			14 // R14

#define PHY_TR_SWITCH_TIME          5  // usec

#define BBP_R17_LOW_SENSIBILITY     0x48
#define BBP_R17_MID_SENSIBILITY     0x41
#define BBP_R17_DYNAMIC_UP_BOUND    0x40
#define RSSI_FOR_LOW_SENSIBILITY    -58
#define RSSI_FOR_MID_SENSIBILITY    -74
//#define RSSI_HIGH_WATERMARK         -53
//#define RSSI_LOW_WATERMARK          -58

//-------------------------------------------------------------------------
// EEPROM definition
//-------------------------------------------------------------------------
#define EEDO        0x10
#define EEDI        0x08
#define EECS        0x04
#define EESK        0x02
#define EERL        0x01

#define EEPROM_WRITE_OPCODE     0x05
#define EEPROM_READ_OPCODE      0x06
#define EEPROM_EWDS_OPCODE      0x10
#define EEPROM_EWEN_OPCODE      0x13



#define	NUM_EEPROM_BBP_PARMS		19
#define	NUM_EEPROM_TX_PARMS			7
#define	NUM_EEPROM_BBP_TUNING_PARMS	7
#define EEPROM_VERSION_OFFSET       0x2
#define	EEPROM_MAC_ADDRESS_BASE_OFFSET		0x4
#define	EEPROM_BBP_BASE_OFFSET		0x16
#define	EEPROM_TX_PWR_OFFSET		0x3C
#define	EEPROM_TSSI_REF_OFFSET		0x4A
#define	EEPROM_TSSI_DELTA_OFFSET	0x1A
#define	EEPROM_BBP_TUNING_OFFSET	0x60
#define	EEPROM_MAC_STATUS_OFFSET	0x7E


// =================================================================================
// TX / RX ring descriptor format
// =================================================================================

//
// TX descriptor format
//

#define TYPE_TXD                                        0
#define TYPE_RXD                                        1
#define TXD_SIZE                                sizeof(TXD_STRUC)
#define RXD_SIZE                                sizeof(RXD_STRUC)

#define SWAP32(x) \
((UInt32)( \
(((UInt32)(x) & (UInt32) 0x000000ffUL) << 24) | \
(((UInt32)(x) & (UInt32) 0x0000ff00UL) <<  8) | \
(((UInt32)(x) & (UInt32) 0x00ff0000UL) >>  8) | \
(((UInt32)(x) & (UInt32) 0xff000000UL) >> 24) ))

typedef	struct	_TXD_STRUC
{
#ifdef __BIG_ENDIAN__
	// Word    0
	ULONG				KeyID:2;// KeyID
	ULONG				Cipher:1;// cliper
	ULONG				Rsv1:1;// Rev1
	ULONG				DataByteCnt:12;// Data byte count
	ULONG				Rsv0:1;// Rev0
	ULONG				IFS:2;// IFS
	ULONG				newseq:1;// new_seq
	ULONG				Ofdm:1;// OFDM
	ULONG				Timestamp:1;// ins_TSF
	ULONG				ACK:1;// ACK
	ULONG				MoreFrag:1;// More     fragment following this       tx ring
	ULONG				RetryLimit:4;// Retry limit
	ULONG				PacketID:4;// PacketID - write by MAC about Frame translate status

	// Word    1
	ULONG				Rsv2:16;// Rev2
	ULONG				CWmax:4;// CWmax
	ULONG				CWmin:4;// CWmin
	ULONG				Aifs:2;// AIFS
	ULONG				IvOffset:6;// IV offset
	
	// Word    2
	ULONG				PlcpLengthHigh:8;// BBP R3 - PLCP length_high
	ULONG				PlcpLengthLow:8;// BBP R2 - PLCP length_Low
	ULONG				PlcpService:8;// BBP R1 - PLCP Service
	ULONG				PlcpSignal:8;// BBP R0 - PLCP Singal

	// Word    3
	ULONG				Iv;// IV
	
	// Word    4
	ULONG				Eiv;// EIV    
#else
	// Word    0
	ULONG				PacketID:4;// PacketID - write by MAC about Frame translate status
	ULONG				RetryLimit:4;// Retry limit
	ULONG				MoreFrag:1;// More     fragment following this       tx ring
	ULONG				ACK:1;// ACK
	ULONG				Timestamp:1;// ins_TSF
	ULONG				Ofdm:1;// OFDM
	ULONG				newseq:1;// new_seq
	ULONG				IFS:2;// IFS
	ULONG				Rsv0:1;// Rev0
	
	ULONG				DataByteCnt:12;// Data byte count
	ULONG				Rsv1:1;// Rev1
	ULONG				Cipher:1;// cliper
	ULONG				KeyID:2;// KeyID
	
	
	
	// Word    1
	ULONG				IvOffset:6;// IV offset
	ULONG				Aifs:2;// AIFS
	ULONG				CWmin:4;// CWmin
	ULONG				CWmax:4;// CWmax
	ULONG				Rsv2:16;// Rev2
	
	
	
	// Word    2
	ULONG				PlcpSignal:8;// BBP R0 - PLCP Singal
	ULONG				PlcpService:8;// BBP R1 - PLCP Service
	ULONG				PlcpLengthLow:8;// BBP R2 - PLCP length_Low
	ULONG				PlcpLengthHigh:8;// BBP R3 - PLCP length_high
	
	
	
	// Word    3
	ULONG				Iv;// IV
	
	
	
	// Word    4
	ULONG				Eiv;// EIV
#endif
}
TXD_STRUC, *PTXD_STRUC;

//
// Rx descriptor format
//
typedef	struct	_RXD_STRUC
{
#if __BIG_ENDIAN__
	// Word    0
	ULONG				Rsv2:4;// Rev2
	ULONG				DataByteCnt:12;// data byte count

	ULONG				Rsv1:6;// Rev1
	ULONG				CiErr:1;// ci error
	ULONG				Cipher:1;// cipher

	ULONG				PhyErr:1;// phy err
	ULONG				Ofdm:1;// OFDM
	ULONG				Crc:1;// crc error
	ULONG				MyBss:1;// my bss
	ULONG				Bcast:1;// bcast
	ULONG				Mcast:1;// mcast
	ULONG				U2M:1;// u2me
	ULONG				Rev0:1;// Rev0
	
	
	
	
	// Word    1
	UCHAR				Rev3[2];// Rev3
	UCHAR				BBR0;// BBP R1 - RSSI
	UCHAR				BBR1;// BBP R0 - SIGNAL / rate
	
	// Word    2
	ULONG				Iv;// IV
	
	// Word 3
	ULONG				Eiv;// EIV
#else
	// Word    0
	ULONG				Rev0:1;// Rev0
	ULONG				U2M:1;// u2me
	ULONG				Mcast:1;// mcast
	ULONG				Bcast:1;// bcast
	ULONG				MyBss:1;// my bss
	ULONG				Crc:1;// crc error
	ULONG				Ofdm:1;// OFDM
	ULONG				PhyErr:1;// phy err
	ULONG				Cipher:1;// cipher
	ULONG				CiErr:1;// ci error
	ULONG				Rsv1:6;// Rev1
	
	ULONG				DataByteCnt:12;// data byte count
	ULONG				Rsv2:4;// Rev2
	
	
	
	// Word    1
	UCHAR				BBR1;// BBP R0 - SIGNAL / rate
	UCHAR				BBR0;// BBP R1 - RSSI
	UCHAR				Rev3[2];// Rev3
	
	// Word    2
	ULONG				Iv;// IV
	
	// Word 3
	ULONG				Eiv;// EIV
#endif
}
RXD_STRUC, *PRXD_STRUC;


// =================================================================================
// CSR Registers
// =================================================================================

//
// CSR1: System control register
//
typedef	union	_CSR1_STRUC	{
	struct	{
		ULONG		SoftReset:1;		// Software reset bit, 1: reset, 0: normal
		ULONG		Rsvd0:1;
		ULONG		HostReady:1;		// Host is ready after initialization, 1: ready
		ULONG		Rsvd1:29;
	}	field;
	ULONG			word;
}	CSR1_STRUC, *PCSR1_STRUC;

// MAC_CSR2: STA MAC register 0
typedef	union	_MAC_CSR2_STRUC	{
	struct	{
		UCHAR		Byte0;		// MAC address byte 0
		UCHAR		Byte1;		// MAC address byte 1
	}				field;
	USHORT			value;
}	MAC_CSR2_STRUC, *PMAC_CSR2_STRUC;

// MAC_CSR3: STA MAC register 1
typedef	union	_MAC_CSR3_STRUC	{
	struct	{
		UCHAR		Byte2;		// MAC address byte 2
		UCHAR		Byte3;		// MAC address byte 3
	}				field;
	USHORT			value;
}	MAC_CSR3_STRUC, *PMAC_CSR3_STRUC;

// MAC_CSR4: STA MAC register 2
typedef	union	_MAC_CSR4_STRUC	{
	struct	{
		UCHAR		Byte4;		// MAC address byte 4
		UCHAR		Byte5;		// MAC address byte 5
	}				field;
	USHORT			value;
}	MAC_CSR4_STRUC, *PMAC_CSR4_STRUC;
#if 0//rt2460
//
// CSR3: STA MAC register 0
//
typedef	union	_CSR3_STRUC	{
	struct	{
		UCHAR		Byte0;		// MAC address byte 0
		UCHAR		Byte1;		// MAC address byte 1
		UCHAR		Byte2;		// MAC address byte 2
		UCHAR		Byte3;		// MAC address byte 3
	}	field;
	ULONG			word;
}	CSR3_STRUC, *PCSR3_STRUC;

//
// CSR4: STA MAC register 1
//
typedef	union	_CSR4_STRUC	{
	struct	{
		UCHAR		Byte4;		// MAC address byte 4
		UCHAR		Byte5;		// MAC address byte 5
		UCHAR		Rsvd0;
		UCHAR		Rsvd1;
	}	field;
	ULONG			word;
}	CSR4_STRUC, *PCSR4_STRUC;
#endif

//
// CSR5: BSSID register 0
//
typedef	union	_CSR5_STRUC	{
	struct	{
		UCHAR		Byte0;		// BSSID byte 0
		UCHAR		Byte1;		// BSSID byte 1
		UCHAR		Byte2;		// BSSID byte 2
		UCHAR		Byte3;		// BSSID byte 3
	}	field;
	ULONG			word;
}	CSR5_STRUC, *PCSR5_STRUC;

//
// CSR6: BSSID register 1
//
typedef	union	_CSR6_STRUC	{
	struct	{
		UCHAR		Byte4;		// BSSID byte 4
		UCHAR		Byte5;		// BSSID byte 5
		UCHAR		Rsvd0;
		UCHAR		Rsvd1;
	}	field;
	ULONG			word;
}	CSR6_STRUC, *PCSR6_STRUC;

//
// CSR7: Interrupt source register
// Write one to clear corresponding bit
//
typedef	union	_CSR7_STRUC	{
	struct	{
		ULONG		TbcnExpire:1;		// Beacon timer expired interrupt
		ULONG		TwakeExpire:1;		// Wakeup timer expired interrupt
		ULONG		TatimwExpire:1;		// Timer of atim window expired interrupt
		ULONG		TxRingTxDone:1;		// Tx ring transmit done interrupt
		ULONG		AtimRingTxDone:1;	// Atim ring transmit done interrupt
		ULONG		PrioRingTxDone:1;	// Priority ring transmit done interrupt
		ULONG		RxDone:1;			// Receive done interrupt
		ULONG		Rsvd:25;
	}	field;
	ULONG			word;
}	CSR7_STRUC, *PCSR7_STRUC, INTSRC_STRUC, *PINTSRC_STRUC;

//
// CSR8: Interrupt Mask register
// Write one to mask off interrupt
//
typedef	union	_CSR8_STRUC	{
	struct	{
		ULONG		TbcnExpire:1;		// Beacon timer expired interrupt mask
		ULONG		TwakeExpire:1;		// Wakeup timer expired interrupt mask
		ULONG		TatimwExpire:1;		// Timer of atim window expired interrupt mask
		ULONG		TxRingTxDone:1;		// Tx ring transmit done interrupt mask
		ULONG		AtimRingTxDone:1;	// Atim ring transmit done interrupt mask
		ULONG		PrioRingTxDone:1;	// Priority ring transmit done interrupt mask
		ULONG		RxDone:1;			// Receive done interrupt mask
		ULONG		Rsvd:25;
	}	field;
	ULONG			word;
}	CSR8_STRUC, *PCSR8_STRUC, INTMSK_STRUC, *PINTMSK_STRUC;

//
// CSR9: Maximum frame length register
//
typedef	union	_CSR9_STRUC	{
	struct	{
		ULONG		Rsvd0:7;
		ULONG		MaxFrameUnit:5;		// Maximum frame legth in 128B unit, default is 12 = 0xC.
		ULONG		Rsvd1:20;
	}	field;
	ULONG			word;
}	CSR9_STRUC, *PCSR9_STRUC;

//
// CSR11: Back-Off control register
//
typedef	union	_CSR11_STRUC	{
	struct {
		ULONG		CWMin:4;		// Bit for Cwmin. default Cwmin is 31 (2^5 - 1).
		ULONG		CWMax:4;		// Bit for Cwmax, default Cwmax is 1023 (2^10 - 1).
		ULONG		SlotTime:5;		// Slot time, default is 20us for 802.11B
		ULONG		Rsvd:3;
		ULONG		LongRetry:8;	// Long retry count
		ULONG		ShortRetry:8;	// Short retry count
	}	field;
	ULONG			word;
}	CSR11_STRUC, *PCSR11_STRUC; 

#if 0
//
// CSR12: Synchronization configuration register 0
// All uint in 1/16 TU
//
typedef	union	_CSR12_STRUC	{
	struct	{
		ULONG		BeaconInterval:16;	// CFP maximum duration, default is 100 TU
		ULONG		CfpMaxDuration:16;	// Beacon interval, default is 100 TU
	}	field;
	ULONG			word;
}	CSR12_STRUC, *PCSR12_STRUC;

//
// CSR13: Synchronization configuration register 1
// All uint in 1/16 TU
//
typedef	union	_CSR13_STRUC	{
	struct	{
		ULONG		AtimwDuration:16;	// ATIM window duration, default is 10 TU
		ULONG		CfpPeriod:8;		// CFP period, default is 0 TU
		ULONG		Rsvd:8;
	}	field;
	ULONG			word;
}	CSR13_STRUC, *PCSR13_STRUC;
#endif

//
// TXRX_CSR18: Synchronization control register
//
typedef	union	_TXRX_CSR18_STRUC	{
	struct	{
		USHORT		Offset:4;			// Enable TSF auto counting
		USHORT		Interval:12;			// Enable TSF sync, 00: disable, 01: infra mode, 10: ad-hoc mode
	}	field;
	USHORT			value;
}	TXRX_CSR18_STRUC, *PTXRX_CSR18_STRUC;

//
// TXRX_CSR19: Synchronization control register
//
typedef	union	_TXRX_CSR19_STRUC	{
	struct	{
		USHORT		TsfCount:1;			// Enable TSF auto counting
		USHORT		TsfSync:2;			// Enable TSF sync, 00: disable, 01: infra mode, 10: ad-hoc mode
		USHORT		Tbcn:1;				// Enable Tbcn with reload value
//		ULONG		Tcfp:1;				// Enable Tcfp & CFP / CP switching
//		ULONG		Tatimw:1;			// Enable Tatimw & ATIM window switching
		USHORT		BeaconGen:1;		// Enable beacon generator
		USHORT		Rsvd:11;
//		ULONG		CfpCntPreload:8;	// Cfp count preload value
//		ULONG		TbcnPreload:16;		// Tbcn preload value
	}	field;
	USHORT			value;
}	TXRX_CSR19_STRUC, *PTXRX_CSR19_STRUC;
#if 0
//
// CSR14: Synchronization control register
//
typedef	union	_CSR14_STRUC	{
	struct	{
		ULONG		TsfCount:1;			// Enable TSF auto counting
		ULONG		TsfSync:2;			// Enable TSF sync, 00: disable, 01: infra mode, 10: ad-hoc mode
		ULONG		Tbcn:1;				// Enable Tbcn with reload value
		ULONG		Tcfp:1;				// Enable Tcfp & CFP / CP switching
		ULONG		Tatimw:1;			// Enable Tatimw & ATIM window switching
		ULONG		BeaconGen:1;		// Enable beacon generator
		ULONG		Rsvd:1;
		ULONG		CfpCntPreload:8;	// Cfp count preload value
		ULONG		TbcnPreload:16;		// Tbcn preload value
	}	field;
	ULONG			word;
}	CSR14_STRUC, *PCSR14_STRUC;
#endif

//
// CSR15: Synchronization status register
//
typedef	union	_CSR15_STRUC	{
	struct	{
		ULONG		Cfp:1;			// CFP period
		ULONG		Atimw:1;		// Atim window period
		ULONG		BeaconSent:1;	// Beacon sent
		ULONG		Rsvd:29;
	}	field;
	ULONG			word;
}	CSR15_STRUC, *PCSR15_STRUC;

//
// CSR18: IFS Timer register 0
//
typedef	union	_CSR18_STRUC	{
	struct	{
		ULONG		SIFS:16;	// SIFS, default is 10 TU
		ULONG		PIFS:16;	// PIFS, default is 30 TU
	}	field;
	ULONG			word;
}	CSR18_STRUC, *PCSR18_STRUC;

//
// CSR19: IFS Timer register 1
//
typedef	union	_CSR19_STRUC	{
	struct	{
		ULONG		DIFS:16;	// DIFS, default is 50 TU
		ULONG		EIFS:16;	// EIFS, default is 364 TU
	}	field;
	ULONG			word;
}	CSR19_STRUC, *PCSR19_STRUC;

//
// MAC_CSR18: Wakeup timer register
//
typedef	union	_MAC_CSR18_STRUC	{
	struct	{
		USHORT		DelayAfterBcn:8;		// Delay after Tbcn expired in units of 1/16 TU
		USHORT		NumBcnBeforeWakeup:7;	// Number of beacon before wakeup
		USHORT		AutoWake:1;				// Enable auto wakeup / sleep mechanism
	}	field;
	USHORT			value;
}	MAC_CSR18_STRUC, *PMAC_CSR18_STRUC;
#if 0//RT2560
//
// CSR20: Wakeup timer register
//
typedef	union	_CSR20_STRUC	{
	struct	{
		ULONG		DelayAfterBcn:16;		// Delay after Tbcn expired in units of 1/16 TU
		ULONG		NumBcnBeforeWakeup:8;	// Number of beacon before wakeup
		ULONG		AutoWake:1;				// Enable auto wakeup / sleep mechanism
		ULONG		Rsvd:7;
	}	field;
	ULONG			word;
}	CSR20_STRUC, *PCSR20_STRUC;
#endif

//
// CSR21: EEPROM control register
//
typedef	union	_CSR21_STRUC	{
	struct	{
		ULONG		Reload:1;		// Reload EEPROM content, write one to reload, self-cleared.
		ULONG		EepromSK:1;
		ULONG		EepromCS:1;
		ULONG		EepromDI:1;
		ULONG		EepromDO:1;
		ULONG		Type:1;			// 1: 93C46, 0:93C66
		ULONG		Rsvd:26;
	}	field;
	ULONG			word;
}	CSR21_STRUC, *PCSR21_STRUC;

//
// CSR22: CFP control register
//
typedef	union	_CSR22_STRUC	{
	struct	{
		ULONG		CfpDurRemain:16;		// CFP duration remain, in units of TU
		ULONG		ReloadCfpDurRemain:1;	// Reload CFP duration remain, write one to reload, self-cleared
		ULONG		Rsvd:15;
	}	field;
	ULONG			word;
}	CSR22_STRUC, *PCSR22_STRUC;

// =================================================================================
// TX / RX Registers
// =================================================================================

//
// TXCSR0 <0x0060> : TX	Control	Register 
//
typedef	union	_TXCSR0_STRUC	{
	struct	{
		ULONG		KickTx:1;		// Kick Tx ring 
		ULONG		KickAtim:1;		// Kick ATIM ring
		ULONG		KickPrio:1;		// Kick priority ring
		ULONG		Abort:1;		// Abort all transmit related ring operation
		ULONG		Rsvd:28;
	}	field;	
	ULONG			word;
}	TXCSR0_STRUC, *PTXCSR0_STRUC;


//
// TXRX_CSR0: Security control register
//
typedef union _TXRX_CSR0_STRUC {
	struct {
		USHORT		Algorithm:3;
		USHORT		IVOffset:6;
		USHORT		KeyID:4;
		USHORT		Rsvd:3;
	} field;
	USHORT			value;
} TXRX_CSR0_STRUC, *PTXRX_CSR0_STRUC;
//
// TXCSR1 <0x0064> : TX	Configuration Register
//
typedef	union	_TXCSR1_STRUC	{
	struct	{
		ULONG		AckTimeOut:9;		// Ack timeout, default = SIFS + 2*SLOT_ACKtime @ 1Mbps
		ULONG		AckConsumeTime:9;	// ACK consume time, default = SIFS + ACKtime @ 1Mbps
		ULONG		TsFOffset:6;		// Insert Tsf offset
		ULONG		AutoResponder:1;	// enable auto responder which include ACK & CTS
		ULONG		Reserved:7;
	}	field;
	ULONG			word;
}	TXCSR1_STRUC, *PTXCSR1_STRUC;

//
// TXCSR2: Tx descriptor configuration register
//
typedef	union	_TXCSR2_STRUC	{
	struct	{
		ULONG		TxDSize:8;		// Tx descriptor size, default is 32
		ULONG		NumTxD:8;		// Number of TxD in ring
		ULONG		NumAtimD:8;		// Number of AtimD in ring
		ULONG		NumPrioD:8;		// Number of PriorityD in ring
	}	field;
	ULONG			word;
}	TXCSR2_STRUC, *PTXCSR2_STRUC;

//
// TXCSR7: Auto responder control register
//
typedef	union	_TXCSR7_STRUC	{
	struct	{
		ULONG		ARPowerManage:1;	// Auto responder power management bit
		ULONG		Rsvd:31;
	}	field;
	ULONG		word;
}	TXCSR7_STRUC, *PTXCSR7_STRUC;

//
// RXCSR0 <0x0080> : RX	Control	Register
//
typedef	union	_RXCSR0_STRUC	{
	struct	{
		ULONG		DisableRx:1;		// Disable Rx engine
		ULONG		DropCRC:1;			// Drop CRC error
		ULONG		DropPhysical:1;		// Drop physical error
		ULONG		DropControl:1;		// Drop control frame
		ULONG		DropNotToMe:1;		// Drop not to me unicast frame
		ULONG		DropToDs:1;			// Drop fram ToDs bit is true
		ULONG		DropVersionErr:1;	// Drop version error frame
		ULONG		PassCRC:1;			// Pass all receive packet to host with CRC attached
		ULONG		Reserved:24;
	}	field;
	ULONG			word;
}	RXCSR0_STRUC, *PRXCSR0_STRUC;

//
// RXCSR1: RX descriptor configuration register
//
typedef	union	_RXCSR1_STRUC	{
	struct	{
		ULONG		RxDSize:8;		// Rx descriptor size, default is 32B.
		ULONG		NumRxD:8;		// Number of RxD in ring.
		ULONG		Rsvd:16;
	}	field;
	ULONG			word;
}	RXCSR1_STRUC, *PRXCSR1_STRUC;

//
// RXCSR3: BBP ID register for Rx operation
//
typedef	union	_RXCSR3_STRUC	{
	struct	{
		ULONG		IdBbp0:7;			// BBP register 0 ID
		ULONG		ValidBbp0:1;		// BBP register 0 ID is valid or not
		ULONG		IdBbp1:7;			// BBP register 1 ID
		ULONG		ValidBbp1:1;		// BBP register 1 ID is valid or not
		ULONG		IdBbp2:7;			// BBP register 2 ID
		ULONG		ValidBbp2:1;		// BBP register 2 ID is valid or not
		ULONG		IdBbp3:7;			// BBP register 3 ID
		ULONG		ValidBbp3:1;		// BBP register 3 ID is valid or not
	}	field;
	ULONG			word;
}	RXCSR3_STRUC, *PRXCSR3_STRUC;

//
// RXCSR4: BBP ID register for Rx operation
//
typedef	union	_RXCSR4_STRUC	{
	struct	{
		ULONG		IdBbp4:7;			// BBP register 4 ID
		ULONG		ValidBbp4:1;		// BBP register 4 ID is valid or not
		ULONG		IdBbp5:7;			// BBP register 5 ID
		ULONG		ValidBbp5:1;		// BBP register 5 ID is valid or not
		ULONG		Rsvd:16;
	}	field;
	ULONG			word;
}	RXCSR4_STRUC, *PRXCSR4_STRUC;

//
// ARCSR0: Auto Responder PLCP value register 0
//
typedef	union	_ARCSR0_STRUC	{
	struct	{
		ULONG		ArBbpData0:8;		// Auto responder BBP register 0 data
		ULONG		ArBbpId0:8;			// Auto responder BBP register 0 Id
		ULONG		ArBbpData1:8;		// Auto responder BBP register 1 data
		ULONG		ArBbpId1:8;			// Auto responder BBP register 1 Id
	}	field;
	ULONG			word;
}	ARCSR0_STRUC, *PARCSR0_STRUC;

//
// ARCSR0: Auto Responder PLCP value register 1
//
typedef	union	_ARCSR1_STRUC	{
	struct	{
		ULONG		ArBbpData2:8;		// Auto responder BBP register 2 data
		ULONG		ArBbpId2:8;			// Auto responder BBP register 2 Id
		ULONG		ArBbpData3:8;		// Auto responder BBP register 3 data
		ULONG		ArBbpId3:8;			// Auto responder BBP register 3 Id
	}	field;
	ULONG			word;
}	ARCSR1_STRUC, *PARCSR1_STRUC;

// =================================================================================
// Miscellaneous Registers
// =================================================================================

//
// PCISR: PCI control register
//
typedef	union	_PCICSR_STRUC	{
	struct	{
		ULONG		BigEndian:1;		// 1: big endian, 0: little endian
		ULONG		RxThreshold:2;		// Rx threshold in DW to start PCI access
										// 01: 8DW, 10: 4DW, 11: 32DW, default 00: 16DW
		ULONG		TxThreshold:2;		// Tx threshold in DW to start PCI access
										// 01: 1DW, 10: 4DW, 11: store & forward, default 00: 0DW
		ULONG		BurstLength:2;		// PCI burst length
										// 01: 8DW, 10: 16DW, 11:32DW, default 00: 4DW
		ULONG		EnableClk:1;		// Enable CLK_RUN, PCI clock can't going down to non-operational
		ULONG		Rsvd:24;
	}	field;
	ULONG			word;
}	PCICSR_STRUC, *PPCICSR_STRUC;

//
// PWRCSR0: Power mode configuration register
//

//
// PSCSR0: Power saving delay time register 0
//

//
// PSCSR1: Power saving delay time register 1
//

//
// PSCSR2: Power saving delay time register 2
//

//
// PSCSR3: Power saving delay time register 3
//

//
// MAC_CSR17: Manual power control / status register
//
typedef	union	_MAC_CSR17_STRUC	{
	struct	{
		USHORT		SetState:1;	
		USHORT		BbpDesireState:2;
		USHORT		RfDesireState:2;
		USHORT		BbpCurrState:2;
		USHORT       RfCurrState:2;
		USHORT       PutToSleep:1;
		USHORT       Rsvd:6;
	}	field;
	USHORT			value;
}	MAC_CSR17_STRUC, *PMAC_CSR17_STRUC;
#if 0//RT2560
//
// PWRCSR1: Manual power control / status register
//
typedef	union	_PWRCSR1_STRUC	{
	struct	{
		ULONG		SetState:1;	
		ULONG		BbpDesireState:2;
		ULONG		RfDesireState:2;
		ULONG		BbpCurrState:2;
		ULONG       RfCurrState:2;
		ULONG       PutToSleep:1;
		ULONG       Rsvd:22;
	}	field;
	ULONG			word;
}	PWRCSR1_STRUC, *PPWRCSR1_STRUC;
#endif

//
// TIMECSR: Timer control register
//

//
// MACCSR0: MAC configuration register 0
//

//
// MACCSR1: MAC configuration register 1
//
typedef	union	_MACCSR1_STRUC	{
	struct	{
		ULONG		KickRx:1;			// Kick one-shot Rx in one-shot Rx mode
		ULONG		OneShotRxMode:1;	// Enable one-shot Rx mode for debugging
		ULONG		BbpRxResetMode:1;	// Ralink BBP RX reset mode
		ULONG		AutoTxBbp:1;		// Auto Tx logic access BBP control register
		ULONG		AutoRxBbp:1;		// Auto Rx logic access BBP control register
		ULONG		LoopBack:2;			// Loopback mode. 00: normal, 01: internal, 10: external, 11:rsvd.
		ULONG		IntersilIF:1;		// Intersil IF calibration pin
		ULONG		Rsvd:24;
	}	field;
	ULONG			word;
}	MACCSR1_STRUC, *PMACCSR1_STRUC;

//
// RALINKCSR: Ralink Rx auto-reset BBCR
//
typedef	union	_RALINKCSR_STRUC	{
	struct	{
		ULONG		ArBbpData0:8;		// Auto reset BBP register 0 data
		ULONG		ArBbpId0:7;			// Auto reset BBP register 0 Id
		ULONG		ArBbpValid0:1;		// Auto reset BBP register 0 is valid
		ULONG		ArBbpData1:8;		// Auto reset BBP register 1 data
		ULONG		ArBbpId1:7;			// Auto reset BBP register 1 Id
		ULONG		ArBbpValid1:1;		// Auto reset BBP register 1 is valid
	}	field;
	ULONG			word;
}	RALINKCSR_STRUC, *PRALINKCSR_STRUC;

//
// BCNCSR: Beacon interval control register
//
typedef	union	_BCNCSR_STRUC	{
	struct	{
		ULONG		Change:1;		// Write one to change beacon interval
		ULONG		DeltaTime:4;	// The delta time value
		ULONG		NumBcn:8;		// Delta time value or number of beacon according to mode
		ULONG		Mode:2;			// please refer to ASIC specs.
		ULONG		Plus:1;			// plus or minus delta time value
		ULONG		Rsvd:16;
	}	field;
	ULONG			word;
}	BCNCSR_STRUC, *PBCNCSR_STRUC;

typedef	union	_PHY_CSR7_STRUC	{
	struct	{
        #if __BIG_ENDIAN__
            USHORT		WriteControl:1;		// 1: Write, 0:	Read
            USHORT		RegID:7;			// BBP register ID
            USHORT		Data:8;				// BBP data
        #else
            USHORT		Data:8;				// BBP data
            USHORT		RegID:7;			// BBP register ID
            USHORT		WriteControl:1;		// 1: Write, 0:	Read
        #endif
	}				field;
	USHORT			value;
}	PHY_CSR7_STRUC, *PPHY_CSR7_STRUC;

typedef	union	_PHY_CSR8_STRUC	{
	struct	{
		USHORT		Busy:1;				// 1: ASIC is busy execute BBP programming.	
		USHORT		Rsvd:15;
	}				field;
	USHORT			value;
}	PHY_CSR8_STRUC, *PPHY_CSR8_STRUC;

typedef	union	_PHY_CSR10_STRUC	{
	struct	{
#if __BIG_ENDIAN__
        USHORT		Busy:1;				// 1: ASIC is busy execute RF programming.
        USHORT		PLL_LD:1;			// RF PLL_LD status
        USHORT		IFSelect:1;			// 1: select IF	to program,	0: select RF to	program
        USHORT		NumberOfBits:5;		// Number of bits used in RFRegValue (I:20,	RFMD:22)
        USHORT		RFRegValue:8;		// Register	value (include register	id)	serial out to RF/IF	chip.
#else
		USHORT		RFRegValue:8;		// Register	value (include register	id)	serial out to RF/IF	chip.
		USHORT		NumberOfBits:5;		// Number of bits used in RFRegValue (I:20,	RFMD:22)
		USHORT		IFSelect:1;			// 1: select IF	to program,	0: select RF to	program
		USHORT		PLL_LD:1;			// RF PLL_LD status
		USHORT		Busy:1;				// 1: ASIC is busy execute RF programming.
#endif
	}	field;
	USHORT			value;
}	PHY_CSR10_STRUC, *PPHY_CSR10_STRUC;
#if 0//rt2460
//
// BBPCSR: BBP serial control register
//
typedef	union	_BBPCSR_STRUC	{
	struct	{
		ULONG		Value:8;			// Register	value to program into BBP
		ULONG		RegNum:7;			// Selected	BBP	register
		ULONG		Busy:1;				// 1: ASIC is busy execute BBP programming.	
		ULONG		WriteControl:1;		// 1: Write	BBP, 0:	Read BBP
		ULONG		Rsvd:15;
	}	field;
	ULONG			word;
}	BBPCSR_STRUC, *PBBPCSR_STRUC;

//
// RFCSR: RF serial control register
//
typedef	union	_RFCSR_STRUC	{
	struct	{
		ULONG		RFRegValue:24;		// Register	value (include register	id)	serial out to RF/IF	chip.
		ULONG		NumberOfBits:5;		// Number of bits used in RFRegValue (I:20,	RFMD:22)
		ULONG		IFSelect:1;			// 1: select IF	to program,	0: select RF to	program
		ULONG		PLL_LD:1;			// RF PLL_LD status
		ULONG		Busy:1;				// 1: ASIC is busy execute RF programming.
	}	field;
	ULONG			word;
}	RFCSR_STRUC, *PRFCSR_STRUC;
#endif

//
// LEDCSR: LED control register
//
typedef	union	_LEDCSR_STRUC	{
	struct	{
		ULONG		OnPeriod:8;			// On period, default 70ms
		ULONG		OffPeriod:8;		// Off period, default 30ms
		ULONG		Link:1;				// 1: linkup, 0: linkoff
		ULONG		Activity:1;			// 1: active, 0: idle
		ULONG		Rsvd:14;
	}	field;
	ULONG			word;
}	LEDCSR_STRUC, *PLEDCSR_STRUC;

//
// GPIOCSR: GPIO control register
//
typedef	union	_GPIOCSR_STRUC	{
	struct	{
		ULONG		Bit0:1;
		ULONG		Bit1:1;
		ULONG		Bit2:1;
		ULONG		Bit3:1;
		ULONG		Bit4:1;
		ULONG		Bit5:1;
		ULONG		Bit6:1;
		ULONG		Bit7:1;
		ULONG		Rsvd:24;
	}	field;
	ULONG			word;
}	GPIOCSR_STRUC, *PGPIOCSR_STRUC;

//
// TXRX_CSR20: Tx BEACON offset time control register
//
typedef	union	_TXRX_CSR20_STRUC	{
	struct	{
		USHORT       Offset:13;      // in units of usec
		USHORT       BeaconExpectWindow:3;   // 2^CwMin
	}	field;
	USHORT			value;
}	TXRX_CSR20_STRUC, *PTXRX_CSR20_STRUC;
#if 0
//
// BCNCSR1: Tx BEACON offset time control register
//
typedef	union	_BCNCSR1_STRUC	{
	struct	{
		USHORT      Preload;    // in units of usec
		USHORT  	Rsvd;
	}	field;
	ULONG			word;
}	BCNCSR1_STRUC, *PBCNCSR1_STRUC;
#endif

//
// MACCSR2: TX_PE to RX_PE turn-around time control register
//
typedef	union	_MACCSR2_STRUC	{
	struct	{
		ULONG       Delay:8;    // in units of PCI clock cycle
		ULONG       Rsvd:24;
	}	field;
	ULONG			word;
}	MACCSR2_STRUC, *PMACCSR2_STRUC;

//
// EEPROM antenna select format
//
typedef	union	_EEPROM_ANTENNA_STRUC	{
	struct	{
#if __BIG_ENDIAN__
        USHORT      RfType:5;               // see E2PROM document
        USHORT		HardwareRadioControl:1;	// 1: Hardware controlled radio enabled, Read GPIO0 required.
        USHORT      DynamicTxAgcControl:1;	
        USHORT      LedMode:3;              // 0-default mode, 1:TX/RX activity mode, 2: Single LED (didn't care about link), 3: reserved
        USHORT		RxDefaultAntenna:2;		// default of antenna, 0: diversity, 1:antenna-A, 2:antenna-B reserved (default = 0)
        USHORT		TxDefaultAntenna:2;		// default of antenna, 0: diversity, 1:antenna-A, 2:antenna-B reserved (default = 0)
        USHORT		NumOfAntenna:2;			// Number of antenna
#else
		USHORT		NumOfAntenna:2;			// Number of antenna
		USHORT		TxDefaultAntenna:2;		// default of antenna, 0: diversity, 1:antenna-A, 2:antenna-B reserved (default = 0)
		USHORT		RxDefaultAntenna:2;		// default of antenna, 0: diversity, 1:antenna-A, 2:antenna-B reserved (default = 0)
		USHORT      LedMode:3;              // 0-default mode, 1:TX/RX activity mode, 2: Single LED (didn't care about link), 3: reserved
		USHORT      DynamicTxAgcControl:1;	
		USHORT		HardwareRadioControl:1;	// 1: Hardware controlled radio enabled, Read GPIO0 required.
		USHORT      RfType:5;               // see E2PROM document
#endif
	}	field;
	USHORT			word;
}	EEPROM_ANTENNA_STRUC, *PEEPROM_ANTENNA_STRUC;

typedef	union	_EEPROM_NIC_CINFIG2_STRUC	{
	struct	{
		USHORT		CardbusAcceleration:1;	// !!! NOTE: 0 - enable, 1 - disable
		USHORT		DynamicBbpTuning:1;		// !!! NOTE: 0 - enable, 1 - disable
		USHORT		CckTxPower:2;			// CCK TX power compensation
		USHORT      Rsv:12;                 // must be 0
	}	field;
	USHORT			word;
}	EEPROM_NIC_CONFIG2_STRUC, *PEEPROM_NIC_CONFIG2_STRUC;

typedef	union	_EEPROM_TX_PWR_STRUC	{
	struct	{
		UCHAR	Byte0;				// Low Byte
		UCHAR	Byte1;				// High Byte
	}	field;
	USHORT	word;
}	EEPROM_TX_PWR_STRUC, *PEEPROM_TX_PWR_STRUC;

#endif	// __RT2570_H__

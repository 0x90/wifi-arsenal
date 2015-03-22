/*
 ***************************************************************************
 * Ralink Tech Inc.
 * 4F, No. 2 Technology 5th Rd.
 * Science-based Industrial Park
 * Hsin-chu, Taiwan, R.O.C.
 *
 * (c) Copyright 2002-2006, Ralink Technology, Inc.
 *
 * This program is free software; you can redistribute it and/or modify  * 
 * it under the terms of the GNU General Public License as published by  * 
 * the Free Software Foundation; either version 2 of the License, or     * 
 * (at your option) any later version.                                   * 
 *                                                                       * 
 * This program is distributed in the hope that it will be useful,       * 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of        * 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         * 
 * GNU General Public License for more details.                          * 
 *                                                                       * 
 * You should have received a copy of the GNU General Public License     * 
 * along with this program; if not, write to the                         * 
 * Free Software Foundation, Inc.,                                       * 
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             * 
 *                                                                       * 
 ************************************************************************
 
	Module Name:
	rt73.h
 
	Abstract:
	RT2573 ASIC	related	definition & structures
 
	Revision History:
	Who			When		  What
	--------	----------	  ----------------------------------------------
	Nemo Tang	02-20-2005	  created
 
 */

#ifndef	__RT73_H__
#define	__RT73_H__

#include "ralink.h"

////////////////////////////////////////////////////////////////////////////////////////

///////////////////////////
// reg for RT73 ///////////
//////////////////////////

// 8051 firmware image - base address = 0x4000
#define FIRMWARE_IMAGE_BASE     0x800
#define MAX_FIRMWARE_IMAGE_SIZE 2048   // 2kbytes


//
// Security key table memory, base address = 0x1000
//
#define SHARED_KEY_TABLE_BASE       0x1000      // 32-byte * 16-entry = 512-byte
#define PAIRWISE_KEY_TABLE_BASE     0x1200      // 32-byte * 64-entry = 2048-byte
#define PAIRWISE_TA_TABLE_BASE      0x1a00      // 8-byte * 64-entry = 512-byte

// 32-byte per entry, total 16-entry for shared key table, 64-entry for pairwise key table
typedef struct _HW_KEY_ENTRY {          // 32-byte per entry
	UCHAR   Key[16];
	UCHAR   TxMic[8];
	UCHAR   RxMic[8];
} HW_KEY_ENTRY, *PHW_KEY_ENTRY; 
#define HW_KEY_ENTRY_SIZE           sizeof(HW_KEY_ENTRY)

// 64-entry for pairwise key table
typedef struct _HW_PAIRWISE_TA_ENTRY {  // 8-byte per entry
	UCHAR   Address[6];
	UCHAR   Rsv[2];
} HW_PAIRWISE_TA_ENTRY, PHW_PAIRWISE_TA_ENTRY;
#define HW_PAIRWISE_TA_ENTRY_SIZE   sizeof(HW_PAIRWISE_TA_ENTRY)

#define HW_DEBUG_SETTING_BASE   0x2bf0  // 0x2bf0~0x2bff total 16 bytes
#define HW_DEBUG_SETTING_END	0x2bff

// on-chip BEACON frame space - base address = 0x2400
#define HW_BEACON_BASE0         0x2400
#define HW_BEACON_BASE1         0x2500
#define HW_BEACON_BASE2         0x2600
#define HW_BEACON_BASE3         0x2700

//
// MAC Control Registers - base address 0x3000
//
#define MAC_CSR0            0x3000
#define MAC_CSR1            0x3004
#define MAC_CSR2            0x3008
#define MAC_CSR3            0x300c
#define MAC_CSR4            0x3010
#define MAC_CSR5            0x3014
#define MAC_CSR6            0x3018
#define MAC_CSR7            0x301c
#define MAC_CSR8            0x3020  // SIFS/EIFS
#define MAC_CSR9            0x3024
#define MAC_CSR10           0x3028  // power state configuration
#define MAC_CSR11           0x302c  // Power state transition time
#define MAC_CSR12           0x3030  // power state
#define MAC_CSR13           0x3034  // GPIO
#define MAC_CSR14           0x3038  // LED control
#define MAC_CSR15           0x303c  // NAV control

//
// TXRX control registers - base address 0x3000
//
#define TXRX_CSR0           0x3040
#define TXRX_CSR1           0x3044
#define TXRX_CSR2           0x3048
#define TXRX_CSR3           0x304c
#define TXRX_CSR4           0x3050
#define TXRX_CSR5           0x3054
#define TXRX_CSR6           0x3058  // ACK/CTS payload consumed time
#define TXRX_CSR7           0x305c  // ACK/CTS payload consumed time
#define TXRX_CSR8           0x3060  // ACK/CTS payload consumed time
#define TXRX_CSR9           0x3064  // BEACON SYNC
#define TXRX_CSR10          0x3068  // BEACON alignment
#define TXRX_CSR11          0x306c  // AES mask
#define TXRX_CSR12          0x3070  // TSF low 32
#define TXRX_CSR13          0x3074  // TSF high 32
#define TXRX_CSR14          0x3078  // TBTT timer
#define TXRX_CSR15          0x307c  // TKIP MIC priority byte "AND" mask

//
// PHY control registers - base address 0x3000
//
#define PHY_CSR0            0x3080  // RF/PS control
#define PHY_CSR1            0x3084
#define PHY_CSR2            0x3088  // pre-TX BBP control
#define PHY_CSR3            0x308c  // BBP access
#define PHY_CSR4            0x3090  // RF serial control
#define PHY_CSR5            0x3094  // RX to TX signal switch timing control
#define PHY_CSR6            0x3098  // TX to RX signal timing control
#define PHY_CSR7            0x309c  // TX DAC switching timing control

//
// Security control register - base address 0x3000
//
#define SEC_CSR0            0x30a0  // shared key table control
#define SEC_CSR1            0x30a4  // shared key table security mode
#define SEC_CSR2            0x30a8  // pairwise key table valid bitmap 0
#define SEC_CSR3            0x30ac  // pairwise key table valid bitmap 1
#define SEC_CSR4            0x30b0  // pairwise key table lookup control
#define SEC_CSR5            0x30b4  // shared key table security mode

//
// STA control registers - base address 0x3000
//
#define STA_CSR0            0x30c0  // CRC/PLCP error counter
#define STA_CSR1            0x30c4  // Long/False-CCA error counter
#define STA_CSR2            0x30c8  // RX FIFO overflow counter
#define STA_CSR3            0x30cc  // TX Beacon counter
#define STA_CSR4            0x30d0  // TX Retry (1) Counters
#define STA_CSR5            0x30d4  // TX Retry (2) Counters

//
// QOS control registers - base address 0x3000
//
#define QOS_CSR0            0x30e0  // TXOP holder MAC address 0
#define QOS_CSR1            0x30e4  // TXOP holder MAC address 1
#define QOS_CSR2            0x30e8  // TXOP holder timeout register
#define QOS_CSR3            0x30ec  // RX QOS-CFPOLL MAC address 0
#define QOS_CSR4            0x30f0  // RX QOS-CFPOLL MAC address 1
#define QOS_CSR5            0x30f4  // "QosControl" field of the RX QOS-CFPOLL



////////WMM Scheduler Register////////////

#define AIFSN_CSR               0x0400
#define CWMIN_CSR           	0x0404
#define CWMAX_CSR           	0x0408
#define AC_TXOP_CSR0        	0x040c
#define AC_TXOP_CSR1        	0x0410
////////////////////////////////////////////////////////////////////////////////////////

// ================================================================
// Tx /	Rx / Mgmt ring descriptor definition
// ================================================================

// value domain of pTxD->Owner and pRxD->Owner
#define	DESC_OWN_HOST		    0
#define	DESC_OWN_NIC		    1

// the following PID values are used to mark outgoing frame type in TXD so that
// proper TX statistics can be collected based on these categories
#define PID_DATA_REQUIRE_ACK    0x00    // b0~6 = MAC table index when acking as AP
#define PID_DATA_WITHOUT_ACK    0x40    // b0~6 = MAC table index when acting as AP
#define PID_NULL_AT_HIGH_RATE   0x80
#define PID_RTS_FRAME           0x81
#define PID_MGMT_FRAME          0x82
#define PID_CNTL_FRAME          0x83    // other non-RTS Control frame
#define PID_MCU_INTERNAL        0xff    // frame generated internally by 8051

#if 0
// the following PID values are used to mark outgoing frame type in TXD->PID so that
// proper TX statistics can be collected based on these categories
// b7-6 of PID field -
#define PTYPE_DATA_REQUIRE_ACK  0x00 // b7-6:00, b5-0: 0~59 is MAC table index (AID?), 60~63 is WDS index
#define PTYPE_NULL_AT_HIGH_RATE 0x40 // b7-6:01, b5-0: 0~59 is MAC table index (AID?), 60~63 is WDS index
#define PTYPE_RESERVED          0x80 // b7-6:10
#define PTYPE_SPECIAL           0xc0 // b7-6:11

// when b7-6=11 (PTYPE_SPECIAL), b5-0 coube be ...
#define PSUBTYPE_DATA_NO_ACK    0x00
#define PSUBTYPE_MGMT           0x01
#define PSUBTYPE_OTHER_CNTL     0x02
#define PSUBTYPE_RTS            0x03
#define PSUBTYPE_MCU_INTERNAL   0x04
#endif

// value domain of pTxD->HostQId (4-bit: 0~15)
#define QID_AC_BK               1   // meet ACI definition in 802.11e
#define QID_AC_BE               0   // meet ACI definition in 802.11e
#define QID_AC_VI               2
#define QID_AC_VO               3
#define QID_HCCA                4
#define NUM_OF_TX_RING          5
#define QID_MGMT                13
#define QID_RX                  14
#define QID_OTHER               15

//-----------------------------------------------------
// BBP & RF	definition
//-----------------------------------------------------
#define	BUSY		1
#define	IDLE		0

#define	BBP_R0					    0  // version
#define	BBP_R1				        1  // TSSI
#define	BBP_R2          			2  // TX configure
#define BBP_R3                      3
#define BBP_R4                      4
#define BBP_R5                      5
#define BBP_R6                      6
#define	BBP_R14			            14 // RX configure
#define BBP_R16                     16
#define BBP_R17                     17 // RX sensibility
#define BBP_R18                     18
#define BBP_R21                     21
#define BBP_R22                     22
#define BBP_R32                     32
#define BBP_R62                     62 // Rx SQ0 Threshold HIGH
#define BBP_R64                     64
#define BBP_R66                     66
#define BBP_R70                     70 // Japan filter
#define BBP_R77                     77
#define BBP_R82                     82
#define BBP_R83                     83
#define BBP_R84                     84
#define BBP_R94                     94 // Tx Gain Control

#define BBPR94_DEFAULT              0x06 // Add 1 value will gain 1db

#define RSSI_FOR_VERY_LOW_SENSIBILITY -35
#define RSSI_FOR_LOW_SENSIBILITY    -58
#define RSSI_FOR_MID_LOW_SENSIBILITY  -66
#define RSSI_FOR_MID_SENSIBILITY    -74

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
#define	NUM_EEPROM_TX_G_PARMS			7
#define	NUM_EEPROM_BBP_TUNING_PARMS	7
#define EEPROM_VERSION_OFFSET       0x2
#define	EEPROM_MAC_ADDRESS_BASE_OFFSET		0x4
#define	EEPROM_BBP_BASE_OFFSET		0x20
#define	EEPROM_G_TX_PWR_OFFSET		0x46
#define	EEPROM_FREQ_OFFSET			0x5e
#define EEPROM_LED_OFFSET			0x60
#define EEPROM_A_TX_PWR_OFFSET      0x62
#define EEPROM_J52_TX_PWR_OFFSET    0x7C  //Skip 0x7C, it start from 0x7D
#define	EEPROM_TSSI_REF_OFFSET		0x4A
#define	EEPROM_TSSI_DELTA_OFFSET	0x1A

#define	EEPROM_RSSI_BG_OFFSET			0x9a
#define	EEPROM_RSSI_A_OFFSET			0x9c
#define	EEPROM_BG_TSSI_CALIBRAION	0x54
#define	EEPROM_A_TSSI_CALIBRAION	0x90
#define EEPROM_TXPOWER_DELTA_OFFSET 0x9e

// =================================================================================
// TX / RX ring descriptor format
// =================================================================================

// the first 24-byte in TXD is called TXINFO and will be DMAed to MAC block through TXFIFO.
// MAC block use this TXINFO to control the transmission behavior of this frame.
#define TXINFO_SIZE                 24

//
// TX descriptor format, Tx	ring, Mgmt Ring
//
#ifdef __BIG_ENDIAN__
typedef struct  _TXD_STRUC {

        //Word 5
        ULONG       CipherAlg:3;
        ULONG       Burst2:1;            // definition as same as "Burst", for backward compatible set this one to the same as "Burst" set.
        ULONG       DataByteCnt:12;
        ULONG       KeyIndex:6;         // Key index (0~31) to the pairwise KEY table; or
                                                                        // 0~3 to shared KEY table 0 (BSS0). STA always use BSS0
                                                                        // 4~7 to shared KEY table 1 (BSS1)
                                                                        // 8~11 to shared KEY table 2 (BSS2)
                                                                        // 12~15 to shared KEY table 3 (BSS3)
        ULONG       KeyTable:1;                 // 1: use per-client pairwise KEY table, 0: shared KEY table
        ULONG       TkipMic:1;                  // 1: ASIC is responsible for appending TKIP MIC if TKIP is inused
        ULONG           RetryMd:1;              // 1: Long retry (4 times), 0: short retry (7 times)
        ULONG           IFS:1;                  // 1: require a BACKOFF before this frame, 0:SIFS before this frame
        ULONG           Ofdm:1;                 // 1: TX using OFDM rates
        ULONG           Timestamp:1;            // 1: MAC auto overwrite current TSF into frame body
        ULONG           ACK:1;                  // 1: ACK is required
        ULONG           MoreFrag:1;             // 1: More fragment following this frame
        ULONG           Drop:1;                 // 0: skip this frame, 1:valid frame inside
        ULONG           Burst:1;                // 1: Contiguously used current End Ponit, eg, Fragment packet should turn on.
                                                //      Tell EDCA that the next frame belongs to the same "burst" even though TXOP=0
        //Word 4
        ULONG       BufCount:3;         // number of buffers in this TXD
        ULONG       HwSeq:1;            // MAC auto replace the 12-bit frame sequence #
        ULONG       :6;
        ULONG       IvOffset:6;
        ULONG       Cwmax:4;
        ULONG       Cwmin:4;
        ULONG       Aifsn:4;
        ULONG       HostQId:4;          // EDCA/HCCA queue ID
        // Word 3
        ULONG           PlcpLengthHigh:8;
        ULONG           PlcpLengthLow:8;
        ULONG           PlcpService:8;
        ULONG           PlcpSignal:8;

        // Word 2
        ULONG       Iv;
        // Word 1
        ULONG       Eiv;
        //Word 0
        ULONG       Reserved:7;
        ULONG       bWaitingDmaDoneInt:1; // pure s/w flag. 1:TXD been filled with data and waiting for TxDoneISR for housekeeping
        ULONG       BbpTxPower:8;
        ULONG       PktId:8;            // driver assigned packet ID to categorize TXResult in TxDoneInterrupt
        ULONG       FrameOffset:8;      // frame start offset inside ASIC TXFIFO (after TXINFO field)
}       TXD_STRUC, *PTXD_STRUC;
#else
typedef	struct	_TXD_STRUC {
	// word 0
	ULONG		Burst:1;			// 1: Contiguously used current End Ponit, eg, Fragment packet should turn on.
									//    Tell EDCA that the next frame belongs to the same "burst" even though TXOP=0
	ULONG		Drop:1;			    // 0: skip this frame, 1:valid frame inside
	ULONG		MoreFrag:1;			// 1: More fragment following this frame
	ULONG		ACK:1;              // 1: ACK is required
	ULONG		Timestamp:1;        // 1: MAC auto overwrite current TSF into frame body
	ULONG       Ofdm:1;             // 1: TX using OFDM rates
	ULONG		IFS:1;              // 1: require a BACKOFF before this frame, 0:SIFS before this frame
	ULONG		RetryMd:1;          // 1: Long retry (4 times), 0: short retry (7 times)
    
	ULONG       TkipMic:1;          // 1: ASIC is responsible for appending TKIP MIC if TKIP is inused
	ULONG       KeyTable:1;         // 1: use per-client pairwise KEY table, 0: shared KEY table
	ULONG       KeyIndex:6;         // Key index (0~31) to the pairwise KEY table; or
									// 0~3 to shared KEY table 0 (BSS0). STA always use BSS0
									// 4~7 to shared KEY table 1 (BSS1)
									// 8~11 to shared KEY table 2 (BSS2)
									// 12~15 to shared KEY table 3 (BSS3)
	
	ULONG       DataByteCnt:12;
	ULONG       Burst2:1;            // definition as same as "Burst", for backward compatible set this one to the same as "Burst" set.
	ULONG       CipherAlg:3;
    
	// Word	1
	ULONG       HostQId:4;          // EDCA/HCCA queue ID
	ULONG       Aifsn:4;
	ULONG       Cwmin:4;
	ULONG       Cwmax:4;
	ULONG       IvOffset:6;
ULONG       :6;
	ULONG       HwSeq:1;            // MAC auto replace the 12-bit frame sequence #
	ULONG       BufCount:3;         // number of buffers in this TXD
	
	// Word	2
	ULONG      	PlcpSignal:8;
	ULONG      	PlcpService:8;
	ULONG      	PlcpLengthLow:8;
	ULONG      	PlcpLengthHigh:8;
    
	// Word	3
	ULONG       Iv;
    
	// Word	4
	ULONG       Eiv;
    
	// Word 5
	ULONG       FrameOffset:8;      // frame start offset inside ASIC TXFIFO (after TXINFO field)
	ULONG       PktId:8;            // driver assigned packet ID to categorize TXResult in TxDoneInterrupt
	ULONG       BbpTxPower:8;
	ULONG       bWaitingDmaDoneInt:1; // pure s/w flag. 1:TXD been filled with data and waiting for TxDoneISR for housekeeping
	ULONG       Reserved:7;
    
	// the above 24-byte is called TXINFO and will be DMAed to MAC block through TXFIFO.
	// MAC block use this TXINFO to control the transmission behavior of this frame.
    
	// The following fields are not used by MAC block. They are used by DMA block and HOST
	// driver only. Once a frame has been DMA to ASIC, all the following fields are useless
	// to ASIC.
}	TXD_STRUC, *PTXD_STRUC;
#endif

//
// Rx descriptor format, Rx	Ring
//
#ifdef __BIG_ENDIAN__
typedef	struct	_RXD_STRUC	{
    ULONG       Rsv:1;
    ULONG       CipherAlg:3;
    ULONG		DataByteCnt:12;
    ULONG       KeyIndex:6;         // decryption key actually used
    ULONG		CipherErr:2;        // 0: decryption okay, 1:ICV error, 2:MIC error, 3:KEY not valid
    ULONG		Ofdm:1;             // 1: this frame is received in OFDM rate
    ULONG		Crc:1;              // 1: CRC error
    ULONG		MyBss:1;            // 1: this frame belongs to the same BSSID
    ULONG		Bcast:1;            // 1: this is a broadcast frame
    ULONG		Mcast:1;            // 1: this is a multicast frame
    ULONG		U2M:1;              // 1: this RX frame is unicast to me
    ULONG       Drop:1;             // 1: drop without receiving to HOST
    ULONG		Owner:1;            // 1: owned by ASIC, 0: owned by HOST driver

    ULONG       Rsv1:1;
    ULONG       FrameOffset:7;
    ULONG       Rsv0:8;
    ULONG       PlcpRssi:8;         // RSSI reported by BBP
    ULONG       PlcpSignal:8;       // RX raw data rate reported by BBP

    ULONG       Iv;                 // received IV if originally encrypted; for replay attack checking

    ULONG       Eiv;                // received EIV if originally encrypted; for replay attack checking

    ULONG       Rsv2;

    ULONG		Rsv3;	// BufPhyAddr;
}	RXD_STRUC, *PRXD_STRUC;
#else
typedef	struct	_RXD_STRUC	{
    ULONG		Owner:1;            // 1: owned by ASIC, 0: owned by HOST driver
    ULONG       Drop:1;             // 1: drop without receiving to HOST
    ULONG		U2M:1;              // 1: this RX frame is unicast to me
    ULONG		Mcast:1;            // 1: this is a multicast frame
    ULONG		Bcast:1;            // 1: this is a broadcast frame
    ULONG		MyBss:1;            // 1: this frame belongs to the same BSSID
    ULONG		Crc:1;              // 1: CRC error
    ULONG		Ofdm:1;             // 1: this frame is received in OFDM rate
    ULONG		CipherErr:2;        // 0: decryption okay, 1:ICV error, 2:MIC error, 3:KEY not valid
    ULONG       KeyIndex:6;         // decryption key actually used
    ULONG		DataByteCnt:12;
    ULONG       CipherAlg:3;
    ULONG       Rsv:1;

    ULONG       PlcpSignal:8;       // RX raw data rate reported by BBP
    ULONG       PlcpRssi:8;         // RSSI reported by BBP
    ULONG       Rsv0:8;
    ULONG       FrameOffset:7;
    ULONG       Rsv1:1;

    ULONG       Iv;                 // received IV if originally encrypted; for replay attack checking

    ULONG       Eiv;                // received EIV if originally encrypted; for replay attack checking

    ULONG       Rsv2;

    ULONG		Rsv3;	// BufPhyAddr;
}	RXD_STRUC, *PRXD_STRUC;
#endif

// =================================================================================
// HOST-MCU communication data structure
// =================================================================================

//
// H2M_MAILBOX_CSR: Host-to-MCU Mailbox
//
#ifdef __BIG_ENDIAN__
typedef union  _H2M_MAILBOX_STRUC {
	struct {
		ULONG       Owner:8;
		ULONG       CmdToken:8;    // 0xff tells MCU not to report CmdDoneInt after excuting the command
		ULONG       HighByte:8;
		ULONG       LowByte:8;
	}   field;
	ULONG           word;
} H2M_MAILBOX_STRUC, *PH2M_MAILBOX_STRUC;
#else
typedef union  _H2M_MAILBOX_STRUC {
	struct {
		ULONG       LowByte:8;
		ULONG       HighByte:8;
		ULONG       CmdToken:8;
		ULONG       Owner:8;
	}   field;
	ULONG           word;
} H2M_MAILBOX_STRUC, *PH2M_MAILBOX_STRUC;
#endif

//
// M2H_CMD_DONE_CSR: MCU-to-Host command complete indication
//
#ifdef __BIG_ENDIAN__
typedef union _M2H_CMD_DONE_STRUC {
	struct  {
		ULONG       CmdToken3;
		ULONG       CmdToken2;
		ULONG       CmdToken1;
		ULONG       CmdToken0;
	} field;
	ULONG           word;
} M2H_CMD_DONE_STRUC, *PM2H_CMD_DONE_STRUC;
#else
typedef union _M2H_CMD_DONE_STRUC {
	struct  {
		ULONG       CmdToken0;
		ULONG       CmdToken1;
		ULONG       CmdToken2;
		ULONG       CmdToken3;
	} field;
	ULONG           word;
} M2H_CMD_DONE_STRUC, *PM2H_CMD_DONE_STRUC;
#endif

//
// MCU_INT_SOURCE_CSR, MCU_INT_MASK_CSR: MCU interrupt source/mask register
//
#ifdef __BIG_ENDIAN__
typedef union _MCU_INT_SOURCE_STRUC {
	struct {
ULONG       :22;
		ULONG       TBTTExpire:1;
		ULONG       Twakeup:1;
		ULONG       McuInt7:1;
		ULONG       McuInt6:1;
		ULONG       McuInt5:1;
		ULONG       McuInt4:1;
		ULONG       McuInt3:1;
		ULONG       McuInt2:1;
		ULONG       McuInt1:1;
		ULONG       McuInt0:1;
	} field;
	ULONG           word;
} MCU_INT_SOURCE_STRUC, *PMCU_INT_SOURCE_STRUC, MCU_INT_MASK_STRUC, *PMCU_INT_MASK_STRUC;
#else
typedef union _MCU_INT_SOURCE_STRUC {
	struct {
		ULONG       McuInt0:1;
		ULONG       McuInt1:1;
		ULONG       McuInt2:1;
		ULONG       McuInt3:1;
		ULONG       McuInt4:1;
		ULONG       McuInt5:1;
		ULONG       McuInt6:1;
		ULONG       McuInt7:1;
		ULONG       Twakeup:1;
		ULONG       TBTTExpire:1;
ULONG       :22;
	} field;
	ULONG           word;
} MCU_INT_SOURCE_STRUC, *PMCU_INT_SOURCE_STRUC, MCU_INT_MASK_STRUC, *PMCU_INT_MASK_STRUC;
#endif

/*
//
// MCU_LEDCS: MCU LED Control Setting.
//
#ifdef __BIG_ENDIAN__
typedef union  _MCU_LEDCS_STRUC {
	struct	{
		USHORT		PolarityRDY_A:1;
		USHORT		PolarityRDY_G:1;
		USHORT		PolarityACT:1;
		USHORT		PolarityGPIO_4:1;
		USHORT		PolarityGPIO_3:1;
		USHORT		PolarityGPIO_2:1;
		USHORT		PolarityGPIO_1:1;
		USHORT		PolarityGPIO_0:1;
		USHORT		LinkAStatus:1;
		USHORT		LinkGStatus:1;
		USHORT		RadioStatus:1;
		USHORT		LedMode:5;		
	} field;
	USHORT			word;
} MCU_LEDCS_STRUC, *PMCU_LEDCS_STRUC;
#else
typedef union  _MCU_LEDCS_STRUC {
	struct	{
		USHORT		LedMode:5;
		USHORT		RadioStatus:1;
		USHORT		LinkGStatus:1;
		USHORT		LinkAStatus:1;
		USHORT		PolarityGPIO_0:1;
		USHORT		PolarityGPIO_1:1;
		USHORT		PolarityGPIO_2:1;
		USHORT		PolarityGPIO_3:1;
		USHORT		PolarityGPIO_4:1;
		USHORT		PolarityACT:1;
		USHORT		PolarityRDY_G:1;
		USHORT		PolarityRDY_A:1;
	} field;
	USHORT			word;
} MCU_LEDCS_STRUC, *PMCU_LEDCS_STRUC;
#endif
*/
// =================================================================================
// Register format
// =================================================================================

//
// MAC_CSR1: System control register
//
#ifdef __BIG_ENDIAN__
typedef	union	_MAC_CSR1_STRUC	{
	struct	{
		ULONG		Rsvd1:29;
		ULONG		HostReady:1;		// Host is ready after initialization, 1: ready
		ULONG		BbpReset:1;			// Hardware reset BBP
		ULONG		SoftReset:1;		// Software reset bit, 1: reset, 0: normal
	}	field;
	ULONG			word;
}	MAC_CSR1_STRUC, *PMAC_CSR1_STRUC;
#else
typedef	union	_MAC_CSR1_STRUC	{
	struct	{
		ULONG		SoftReset:1;		// Software reset bit, 1: reset, 0: normal
		ULONG		BbpReset:1;			// Hardware reset BBP
		ULONG		HostReady:1;		// Host is ready after initialization, 1: ready
		ULONG		Rsvd1:29;
	}	field;
	ULONG			word;
}	MAC_CSR1_STRUC, *PMAC_CSR1_STRUC;
#endif

//
// MAC_CSR2: STA MAC register 0
//
#ifdef __BIG_ENDIAN__
typedef	union	_MAC_CSR2_STRUC	{
	struct	{
		UCHAR		Byte3;		// MAC address byte 3
		UCHAR		Byte2;		// MAC address byte 2
		UCHAR		Byte1;		// MAC address byte 1
		UCHAR		Byte0;		// MAC address byte 0
	}	field;
	ULONG			word;
}	MAC_CSR2_STRUC, *PMAC_CSR2_STRUC;
#else
typedef	union	_MAC_CSR2_STRUC	{
	struct	{
		UCHAR		Byte0;		// MAC address byte 0
		UCHAR		Byte1;		// MAC address byte 1
		UCHAR		Byte2;		// MAC address byte 2
		UCHAR		Byte3;		// MAC address byte 3
	}	field;
	ULONG			word;
}	MAC_CSR2_STRUC, *PMAC_CSR2_STRUC;
#endif

//
// MAC_CSR3: STA MAC register 1
//
#ifdef __BIG_ENDIAN__
typedef	union	_MAC_CSR3_STRUC	{
	struct	{
		UCHAR		Rsvd1;
		UCHAR		U2MeMask;
		UCHAR		Byte5;		// MAC address byte 5
		UCHAR		Byte4;		// MAC address byte 4
	}	field;
	ULONG			word;
}	MAC_CSR3_STRUC, *PMAC_CSR3_STRUC;
#else
typedef	union	_MAC_CSR3_STRUC	{
	struct	{
		UCHAR		Byte4;		// MAC address byte 4
		UCHAR		Byte5;		// MAC address byte 5
		UCHAR		U2MeMask;
		UCHAR		Rsvd1;
	}	field;
	ULONG			word;
}	MAC_CSR3_STRUC, *PMAC_CSR3_STRUC;
#endif

//
// MAC_CSR4: BSSID register 0
//
#ifdef __BIG_ENDIAN__
typedef	union	_MAC_CSR4_STRUC	{
	struct	{
		UCHAR		Byte3;		// BSSID byte 3
		UCHAR		Byte2;		// BSSID byte 2
		UCHAR		Byte1;		// BSSID byte 1
		UCHAR		Byte0;		// BSSID byte 0
	}	field;
	ULONG			word;
}	MAC_CSR4_STRUC, *PMAC_CSR4_STRUC;
#else
typedef	union	_MAC_CSR4_STRUC	{
	struct	{
		UCHAR		Byte0;		// BSSID byte 0
		UCHAR		Byte1;		// BSSID byte 1
		UCHAR		Byte2;		// BSSID byte 2
		UCHAR		Byte3;		// BSSID byte 3
	}	field;
	ULONG			word;
}	MAC_CSR4_STRUC, *PMAC_CSR4_STRUC;
#endif

//
// MAC_CSR5: BSSID register 1
//
#ifdef __BIG_ENDIAN__
typedef	union	_MAC_CSR5_STRUC	{
	struct	{
		USHORT		Rsvd:14;
		USHORT		BssIdMask:2; // 11: one BSSID, 00: 4 BSSID, 10 or 01: 2 BSSID
		UCHAR		Byte5;		 // BSSID byte 5
		UCHAR		Byte4;		 // BSSID byte 4
	}	field;
	ULONG			word;
}	MAC_CSR5_STRUC, *PMAC_CSR5_STRUC;
#else
typedef	union	_MAC_CSR5_STRUC	{
	struct	{
		UCHAR		Byte4;		 // BSSID byte 4
		UCHAR		Byte5;		 // BSSID byte 5
		USHORT      BssIdMask:2; // 11: one BSSID, 00: 4 BSSID, 10 or 01: 2 BSSID
		USHORT		Rsvd:14;
	}	field;
	ULONG			word;
}	MAC_CSR5_STRUC, *PMAC_CSR5_STRUC;
#endif

//
// MAC_CSR8: SIFS/EIFS register
#ifdef __BIG_ENDIAN__
typedef	union	_MAC_CSR8_STRUC	{
	struct	{
		USHORT		Eifs;               // in unit of 1-us
		UCHAR       SifsAfterRxOfdm;    // in unit of 1-us
		UCHAR		Sifs;               // in unit of 1-us
	}	field;
	ULONG			word;
}	MAC_CSR8_STRUC, *PMAC_CSR8_STRUC;
#else
typedef	union	_MAC_CSR8_STRUC	{
	struct	{
		UCHAR		Sifs;               // in unit of 1-us
		UCHAR       SifsAfterRxOfdm;    // in unit of 1-us
		USHORT		Eifs;               // in unit of 1-us
	}	field;
	ULONG			word;
}	MAC_CSR8_STRUC, *PMAC_CSR8_STRUC;
#endif

//
// MAC_CSR9: Back-Off control register
//
#ifdef __BIG_ENDIAN__
typedef	union	_MAC_CSR9_STRUC	{
	struct {
		ULONG		Rsvd:15;
		ULONG       CWSelect:1;     // 1: CWmin/Cwmax select from register, 0:select from TxD
		ULONG		CWMax:4;		// Bit for Cwmax, default Cwmax is 1023 (2^10 - 1).
		ULONG		CWMin:4;		// Bit for Cwmin. default Cwmin is 31 (2^5 - 1).
		ULONG		SlotTime:8;		// Slot time, default is 20us for 802.11B
	}	field;
	ULONG			word;
}	MAC_CSR9_STRUC, *PMAC_CSR9_STRUC; 
#else
typedef	union	_MAC_CSR9_STRUC	{
	struct {
		ULONG		SlotTime:8;		// Slot time, default is 20us for 802.11B
		ULONG		CWMin:4;		// Bit for Cwmin. default Cwmin is 31 (2^5 - 1).
		ULONG		CWMax:4;		// Bit for Cwmax, default Cwmax is 1023 (2^10 - 1).
		ULONG       CWSelect:1;     // 1: CWmin/Cwmax select from register, 0:select from TxD
		ULONG		Rsvd:15;
	}	field;
	ULONG			word;
}	MAC_CSR9_STRUC, *PMAC_CSR9_STRUC; 
#endif

//
// MAC_CSR11: Power saving transition time register
//
#ifdef BG_ENDIAN 
typedef union _MAC_CSR11_STRUC {
	struct {
ULONG       :12;
		ULONG       Sleep2AwakeLatency:4;              // in unit of 1-TU
		ULONG       bAutoWakeupEnable:1;
		ULONG		NumOfTBTTBeforeWakeup:7;           // Number of beacon before wakeup
		ULONG		DelayAfterLastTBTTBeforeWakeup:8;  // Delay after Tbcn expired in units of 1-TU
	} field;
	ULONG   word;
} MAC_CSR11_STRUC, *PMAC_CSR11_STRUC;
#else
typedef union _MAC_CSR11_STRUC {
	struct {
		ULONG		DelayAfterLastTBTTBeforeWakeup:8;  // Delay after Tbcn expired in units of 1-TU
		ULONG		NumOfTBTTBeforeWakeup:7;           // Number of beacon before wakeup
		ULONG       bAutoWakeupEnable:1;
		ULONG       Sleep2AwakeLatency:4;              // in unit of 1-TU
ULONG       :12;
	} field;
	ULONG   word;
} MAC_CSR11_STRUC, *PMAC_CSR11_STRUC;
#endif

//
// MAC_CSR12: Manual power control / status register (merge CSR20 & PWRCSR1)
//
#ifdef __BIG_ENDIAN__
typedef	union	_MAC_CSR12_STRUC	{
	struct	{
ULONG		:28;
		ULONG		BbpRfStatus:1;			// 0: not ready, 1:ready		
		ULONG       ForceWakeup:1;          // ForceWake has high privilege than PutToSleep when both set
		ULONG       PutToSleep:1;
		ULONG		CurrentPowerState:1;	// 0:sleep, 1:awake
	}	field;
	ULONG			word;
}	MAC_CSR12_STRUC, *PMAC_CSR12_STRUC;
#else
typedef	union	_MAC_CSR12_STRUC	{
	struct	{
		ULONG		CurrentPowerState:1;	// 0:sleep, 1:awake
		ULONG       PutToSleep:1;
		ULONG       ForceWakeup:1;          // ForceWake has high privilege than PutToSleep when both set
		ULONG		BbpRfStatus:1;			// 0: not ready, 1:ready
ULONG		:28;
	}	field;
	ULONG			word;
}	MAC_CSR12_STRUC, *PMAC_CSR12_STRUC;
#endif

//
// MAC_CSR14: LED control register
//
#ifdef __BIG_ENDIAN__
typedef	union	_MAC_CSR14_STRUC	{
	struct	{
ULONG		:12;
		ULONG       SwLed2:1;
		ULONG       HwLedPolarity:1;    // 0: active low, 1: active high
		ULONG		SwLed1:1;		    // s/w LED, 1: ON, 0: OFF
		ULONG		HwLed:1;			// h/w TX activity, 1: normal OFF, blinking upon TX, 0: normal ON, blinking upon TX
		ULONG		OffPeriod:8;		// Off period in unit of 1-ms, default 30ms
		ULONG		OnPeriod:8;			// On period in unit of 1-ms, default 70ms
	}	field;
	ULONG			word;
}	MAC_CSR14_STRUC, *PMAC_CSR14_STRUC;
#else
typedef	union	_MAC_CSR14_STRUC	{
	struct	{
		ULONG		OnPeriod:8;			// On period, default 70ms
		ULONG		OffPeriod:8;		// Off period, default 30ms
		ULONG		HwLed:1;			// h/w TX activity, 1: normal OFF, blinking upon TX, 0: normal ON, blinking upon TX
		ULONG		SwLed1:1;		    // s/w LED, 1: ON, 0: OFF
		ULONG       HwLedPolarity:1;    // 0: active low, 1: active high
		ULONG       SwLed2:1;
ULONG		:12;
	}	field;
	ULONG			word;
}	MAC_CSR14_STRUC, *PMAC_CSR14_STRUC;
#endif

//
// TXRX_CSR0: TX/RX configuration register
//
#ifdef __BIG_ENDIAN__
typedef	union	TXRX_CSR0_STRUC	{
	struct	{
ULONG		:5;		
		ULONG       TxWithoutWaitingSBox:1;
		ULONG       DropAckCts:1;       // 1: drop received ACK and CTS
		ULONG		DropBcast:1;		// Drop broadcast frames
		ULONG		DropMcast:1;		// Drop multicast frames
		ULONG		DropVerErr:1;	    // Drop version error frame
		ULONG		DropToDs:1;			// Drop fram ToDs bit is true
		ULONG		DropNotToMe:1;		// Drop not to me unicast frame
		ULONG		DropControl:1;		// Drop control frame
		ULONG		DropPhyErr:1;		// Drop physical error
		ULONG		DropCRCErr:1;		// Drop CRC error
		ULONG		DisableRx:1;		// Disable Rx engine
		ULONG       AutoTxSeq:1;        // 1: ASIC auto replace sequence# in outgoing frame
		ULONG       TsfOffset:6;        // default is 24
		ULONG       RxAckTimeout:9;
	}	field;
	ULONG			word;
}	TXRX_CSR0_STRUC, *PTXRX_CSR0_STRUC;
#else
typedef	union	_TXRX_CSR0_STRUC	{
	struct	{
		ULONG       RxAckTimeout:9;
		ULONG       TsfOffset:6;        // default is 24
		ULONG       AutoTxSeq:1;        // 1: ASIC auto replace sequence# in outgoing frame
		ULONG		DisableRx:1;		// Disable Rx engine
		ULONG		DropCRCErr:1;		// Drop CRC error
		ULONG		DropPhyErr:1;		// Drop physical error
		ULONG		DropControl:1;		// Drop control frame
		ULONG		DropNotToMe:1;		// Drop not to me unicast frame
		ULONG		DropToDs:1;			// Drop fram ToDs bit is true
		ULONG		DropVerErr:1;	    // Drop version error frame
		ULONG		DropMcast:1;		// Drop multicast frames
		ULONG		DropBcast:1;		// Drop broadcast frames
		ULONG       DropAckCts:1;       // 1: drop received ACK and CTS
		ULONG       TxWithoutWaitingSBox:1;
ULONG		:5;
	}	field;
	ULONG			word;
}	TXRX_CSR0_STRUC, *PTXRX_CSR0_STRUC;
#endif

//
// TXRX_CSR4: Auto-Responder/Tx-retry register
//
#ifdef __BIG_ENDIAN__
typedef	union	_TXRX_CSR4_STRUC	{
	struct	{
		ULONG       ShortRetryLimit:4;
		ULONG       LongRetryLimit:4;
		ULONG		Rsv1:1;
		ULONG		OfdmTxFallbacktoCCK:1;      // 0: Fallbackt o OFDM 6M oly, 1: Fallback to CCK 1M,2M
		ULONG       OfdmTxRateDownStep:2;       // 0:1-step, 1: 2-step, 2:3-step, 3:4-step
		ULONG       OfdmTxRateDownEnable:1;     // 1:enable
		ULONG       AutoResponderPreamble:1;    // 0:long, 1:short preamble
		ULONG       AutoResponderEnable:1;
		ULONG       AckCtsPsmBit:1;
		ULONG       Rsv2:5;
		ULONG       CntlFrameAckPolicy:3;
		ULONG       TxAckTimeout:8;
	}	field;
	ULONG			word;
}	TXRX_CSR4_STRUC, *PTXRX_CSR4_STRUC;
#else
typedef	union	_TXRX_CSR4_STRUC	{
	struct	{
		ULONG       TxAckTimeout:8;
		ULONG       CntlFrameAckPolicy:3;
		ULONG       Rsv2:5;
		ULONG       AckCtsPsmBit:1;
		ULONG       AutoResponderEnable:1;
		ULONG       AutoResponderPreamble:1;    // 0:long, 1:short preamble
		ULONG       OfdmTxRateDownEnable:1;     // 1:enable
		ULONG       OfdmTxRateDownStep:2;       // 0:1-step, 1: 2-step, 2:3-step, 3:4-step
		ULONG		OfdmTxFallbacktoCCK:1;      // 0: Fallbackt o OFDM 6M oly, 1: Fallback to CCK 1M,2M
		ULONG		Rsv1:1;		
		ULONG       LongRetryLimit:4;
		ULONG       ShortRetryLimit:4;
	}	field;
	ULONG			word;
}	TXRX_CSR4_STRUC, *PTXRX_CSR4_STRUC;
#endif

//
// TXRX_CSR9: Synchronization control register
//
#ifdef __BIG_ENDIAN__
typedef	union	_TXRX_CSR9_STRUC	{
	struct	{
		ULONG		TxTimestampCompensate:8;
ULONG       :3;
		ULONG		bBeaconGen:1;		// Enable beacon generator
		ULONG       bTBTTEnable:1;
		ULONG		TsfSyncMode:2;		// Enable TSF sync, 00: disable, 01: infra mode, 10: ad-hoc mode
		ULONG		bTsfTicking:1;		// Enable TSF auto counting
		ULONG       BeaconInterval:16;  // in unit of 1/16 TU
	}	field;
	ULONG			word;
}	TXRX_CSR9_STRUC, *PTXRX_CSR9_STRUC;
#else
typedef	union	_TXRX_CSR9_STRUC	{
	struct	{
		ULONG       BeaconInterval:16;  // in unit of 1/16 TU
		ULONG		bTsfTicking:1;		// Enable TSF auto counting
		ULONG		TsfSyncMode:2;		// Enable TSF sync, 00: disable, 01: infra mode, 10: ad-hoc mode
		ULONG       bTBTTEnable:1;
		ULONG		bBeaconGen:1;		// Enable beacon generator
ULONG       :3;
		ULONG		TxTimestampCompensate:8;
	}	field;
	ULONG			word;
}	TXRX_CSR9_STRUC, *PTXRX_CSR9_STRUC;
#endif

//
// PHY_CSR3: BBP serial control register
//
#ifdef __BIG_ENDIAN__
typedef	union	_PHY_CSR3_STRUC	{
	struct	{
ULONG		:15;		
		ULONG		Busy:1;				// 1: ASIC is busy execute BBP programming.	
		ULONG		fRead:1;		    // 0: Write	BBP, 1:	Read BBP
		ULONG		RegNum:7;			// Selected	BBP	register
		ULONG		Value:8;			// Register	value to program into BBP
	}	field;
	ULONG			word;
}	PHY_CSR3_STRUC, *PPHY_CSR3_STRUC;
#else
typedef	union	_PHY_CSR3_STRUC	{
	struct	{
		ULONG		Value:8;			// Register	value to program into BBP
		ULONG		RegNum:7;			// Selected	BBP	register
		ULONG		fRead:1;		    // 0: Write	BBP, 1:	Read BBP
		ULONG		Busy:1;				// 1: ASIC is busy execute BBP programming.	
ULONG		:15;
	}	field;
	ULONG			word;
}	PHY_CSR3_STRUC, *PPHY_CSR3_STRUC;
#endif

//
// PHY_CSR4: RF serial control register
//
#ifdef __BIG_ENDIAN__
typedef	union	_PHY_CSR4_STRUC	{
	struct	{
		ULONG		Busy:1;				// 1: ASIC is busy execute RF programming.		
		ULONG		PLL_LD:1;			// RF PLL_LD status
		ULONG		IFSelect:1;			// 1: select IF	to program,	0: select RF to	program
		ULONG		NumberOfBits:5;		// Number of bits used in RFRegValue (I:20,	RFMD:22)
		ULONG		RFRegValue:24;		// Register	value (include register	id)	serial out to RF/IF	chip.
	}	field;
	ULONG			word;
}	PHY_CSR4_STRUC, *PPHY_CSR4_STRUC;
#else
typedef	union	_PHY_CSR4_STRUC	{
	struct	{
		ULONG		RFRegValue:24;		// Register	value (include register	id)	serial out to RF/IF	chip.
		ULONG		NumberOfBits:5;		// Number of bits used in RFRegValue (I:20,	RFMD:22)
		ULONG		IFSelect:1;			// 1: select IF	to program,	0: select RF to	program
		ULONG		PLL_LD:1;			// RF PLL_LD status
		ULONG		Busy:1;				// 1: ASIC is busy execute RF programming.
	}	field;
	ULONG			word;
}	PHY_CSR4_STRUC, *PPHY_CSR4_STRUC;
#endif

//
// SEC_CSR1: shared key table security mode register
//
#ifdef __BIG_ENDIAN__
typedef	union	_SEC_CSR1_STRUC	{
	struct	{
ULONG       :1;
		ULONG       Bss1Key3CipherAlg:3;
ULONG       :1;
		ULONG       Bss1Key2CipherAlg:3;
ULONG       :1;
		ULONG       Bss1Key1CipherAlg:3;
ULONG       :1;
		ULONG       Bss1Key0CipherAlg:3;
ULONG       :1;
		ULONG       Bss0Key3CipherAlg:3;
ULONG       :1;
		ULONG       Bss0Key2CipherAlg:3;
ULONG       :1;
		ULONG       Bss0Key1CipherAlg:3;
ULONG       :1;
		ULONG       Bss0Key0CipherAlg:3;
	}	field;
	ULONG			word;
}	SEC_CSR1_STRUC, *PSEC_CSR1_STRUC;
#else
typedef	union	_SEC_CSR1_STRUC	{
	struct	{
		ULONG       Bss0Key0CipherAlg:3;
ULONG       :1;
		ULONG       Bss0Key1CipherAlg:3;
ULONG       :1;
		ULONG       Bss0Key2CipherAlg:3;
ULONG       :1;
		ULONG       Bss0Key3CipherAlg:3;
ULONG       :1;
		ULONG       Bss1Key0CipherAlg:3;
ULONG       :1;
		ULONG       Bss1Key1CipherAlg:3;
ULONG       :1;
		ULONG       Bss1Key2CipherAlg:3;
ULONG       :1;
		ULONG       Bss1Key3CipherAlg:3;
ULONG       :1;
	}	field;
	ULONG			word;
}	SEC_CSR1_STRUC, *PSEC_CSR1_STRUC;
#endif

//
// SEC_CSR5: shared key table security mode register
//
#ifdef __BIG_ENDIAN__
typedef	union	_SEC_CSR5_STRUC	{
	struct	{
ULONG       :1;
		ULONG       Bss3Key3CipherAlg:3;
ULONG       :1;
		ULONG       Bss3Key2CipherAlg:3;
ULONG       :1;
		ULONG       Bss3Key1CipherAlg:3;
ULONG       :1;
		ULONG       Bss3Key0CipherAlg:3;
ULONG       :1;
		ULONG       Bss2Key3CipherAlg:3;
ULONG       :1;
		ULONG       Bss2Key2CipherAlg:3;
ULONG       :1;
		ULONG       Bss2Key1CipherAlg:3;
ULONG       :1;
		ULONG       Bss2Key0CipherAlg:3;
	}	field;
	ULONG			word;
}	SEC_CSR5_STRUC, *PSEC_CSR5_STRUC;
#else
typedef	union	_SEC_CSR5_STRUC	{
	struct	{
		ULONG       Bss2Key0CipherAlg:3;
ULONG       :1;
		ULONG       Bss2Key1CipherAlg:3;
ULONG       :1;
		ULONG       Bss2Key2CipherAlg:3;
ULONG       :1;
		ULONG       Bss2Key3CipherAlg:3;
ULONG       :1;
		ULONG       Bss3Key0CipherAlg:3;
ULONG       :1;
		ULONG       Bss3Key1CipherAlg:3;
ULONG       :1;
		ULONG       Bss3Key2CipherAlg:3;
ULONG       :1;
		ULONG       Bss3Key3CipherAlg:3;
ULONG       :1;
	}	field;
	ULONG			word;
}	SEC_CSR5_STRUC, *PSEC_CSR5_STRUC;
#endif

//
// STA_CSR0: RX PLCP error count & RX CRC error count
//
#ifdef __BIG_ENDIAN__
typedef	union	_STA_CSR0_STRUC	{
	struct	{
		USHORT  PlcpErr;
		USHORT  CrcErr;
	}	field;
	ULONG			word;
}	STA_CSR0_STRUC, *PSTA_CSR0_STRUC;
#else
typedef	union	_STA_CSR0_STRUC	{
	struct	{
		USHORT  CrcErr;
		USHORT  PlcpErr;
	}	field;
	ULONG			word;
}	STA_CSR0_STRUC, *PSTA_CSR0_STRUC;
#endif

//
// STA_CSR1: RX False CCA count & RX LONG frame count
//
#ifdef __BIG_ENDIAN__
typedef	union	_STA_CSR1_STRUC	{
	struct	{
		USHORT  FalseCca;
		USHORT  PhyErr;
	}	field;
	ULONG			word;
}	STA_CSR1_STRUC, *PSTA_CSR1_STRUC;
#else
typedef	union	_STA_CSR1_STRUC	{
	struct	{
		USHORT  PhyErr;
		USHORT  FalseCca;
	}	field;
	ULONG			word;
}	STA_CSR1_STRUC, *PSTA_CSR1_STRUC;
#endif

//
// STA_CSR2: TX Beacon count and RX FIFO overflow count
//
#ifdef __BIG_ENDIAN__
typedef	union	_STA_CSR2_STRUC	{
	struct	{
		USHORT  RxOverflowCount;
		USHORT  RxFifoOverflowCount;
	}	field;
	ULONG			word;
}	STA_CSR2_STRUC, *PSTA_CSR2_STRUC;
#else
typedef	union	_STA_CSR2_STRUC	{
	struct	{
		USHORT  RxFifoOverflowCount;
		USHORT  RxOverflowCount;
	}	field;
	ULONG			word;
}	STA_CSR2_STRUC, *PSTA_CSR2_STRUC;
#endif

//
// STA_CSR3: TX Beacon count
//
#ifdef __BIG_ENDIAN__
typedef	union	_STA_CSR3_STRUC	{
	struct	{
		USHORT  Rsv;
		USHORT  TxBeaconCount;
	}	field;
	ULONG			word;
}	STA_CSR3_STRUC, *PSTA_CSR3_STRUC;
#else
typedef	union	_STA_CSR3_STRUC	{
	struct	{
		USHORT  TxBeaconCount;
		USHORT  Rsv;
	}	field;
	ULONG			word;
}	STA_CSR3_STRUC, *PSTA_CSR3_STRUC;
#endif

//
// STA_CSR4: TX Retry count
//
#ifdef __BIG_ENDIAN__
typedef	union	_STA_CSR4_STRUC	{
	struct	{
		USHORT  TxOneRetryCount;
		USHORT  TxNoRetryCount;
	}	field;
	ULONG			word;
}	STA_CSR4_STRUC, *PSTA_CSR4_STRUC;
#else
typedef	union	_STA_CSR4_STRUC	{
	struct	{
		USHORT  TxNoRetryCount;
		USHORT  TxOneRetryCount;
	}	field;
	ULONG			word;
}	STA_CSR4_STRUC, *PSTA_CSR4_STRUC;
#endif


//
// STA_CSR5: TX Retry count
//
#ifdef __BIG_ENDIAN__
typedef	union	_STA_CSR5_STRUC	{
	struct	{
		USHORT  TxRetryFailCount;
		USHORT  TxMultiRetryCount;
	}	field;
	ULONG			word;
}	STA_CSR5_STRUC, *PSTA_CSR5_STRUC;
#else
typedef	union	_STA_CSR5_STRUC	{
	struct	{
		USHORT  TxMultiRetryCount;
		USHORT  TxRetryFailCount;
	}	field;
	ULONG			word;
}	STA_CSR5_STRUC, *PSTA_CSR5_STRUC;
#endif

//
// HOST_CMD_CSR: For HOST to interrupt embedded processor
//
#ifdef __BIG_ENDIAN__
typedef	union	_HOST_CMD_CSR_STRUC	{
	struct	{
		ULONG   Rsv:24;
		ULONG   InterruptMcu:1;
		ULONG   HostCommand:7;
	}	field;
	ULONG			word;
}	HOST_CMD_CSR_STRUC, *PHOST_CMD_CSR_STRUC;
#else
typedef	union	_HOST_CMD_CSR_STRUC	{
	struct	{
		ULONG   HostCommand:7;
		ULONG   InterruptMcu:1;
		ULONG   Rsv:24;
	}	field;
	ULONG			word;
}	HOST_CMD_CSR_STRUC, *PHOST_CMD_CSR_STRUC;
#endif

//
// TX_RING_CSR0: TX Ring size for AC_BK, AC_BE, AC_VI, AC_VO
//
#ifdef __BIG_ENDIAN__
typedef	union	_TX_RING_CSR0_STRUC	{
	struct	{
		UCHAR   Ac3Total;
		UCHAR   Ac2Total;
		UCHAR   Ac1Total;
		UCHAR   Ac0Total;
	}	field;
	ULONG			word;
}	TX_RING_CSR0_STRUC, *PTX_RING_CSR0_STRUC;
#else
typedef	union	_TX_RING_CSR0_STRUC	{
	struct	{
		UCHAR   Ac0Total;
		UCHAR   Ac1Total;
		UCHAR   Ac2Total;
		UCHAR   Ac3Total;
	}	field;
	ULONG			word;
}	TX_RING_CSR0_STRUC, *PTX_RING_CSR0_STRUC;
#endif

//
// TX_RING_CSR1: TX Ring size for MGMT Ring, HCCA Ring
//
#ifdef __BIG_ENDIAN__
typedef	union	_TX_RING_CSR1_STRUC	{
	struct	{
		ULONG   Rsv:10;
		ULONG   TxdSize:6;      // in unit of 32-bit
		ULONG   HccaTotal:8;
		ULONG   MgmtTotal:8;
	}	field;
	ULONG			word;
}	TX_RING_CSR1_STRUC, *PTX_RING_CSR1_STRUC;
#else
typedef	union	_TX_RING_CSR1_STRUC	{
	struct	{
		ULONG   MgmtTotal:8;
		ULONG   HccaTotal:8;
		ULONG   TxdSize:6;      // in unit of 32-bit
		ULONG   Rsv:10;
	}	field;
	ULONG			word;
}	TX_RING_CSR1_STRUC, *PTX_RING_CSR1_STRUC;
#endif

//
// AIFSN_CSR: AIFSN for each EDCA AC
//
#ifdef __BIG_ENDIAN__
typedef	union	_AIFSN_CSR_STRUC	{
	struct	{
		ULONG   Rsv:16;
		ULONG   Aifsn3:4;       // for AC_VO
		ULONG   Aifsn2:4;       // for AC_VI
		ULONG   Aifsn1:4;       // for AC_BK
		ULONG   Aifsn0:4;       // for AC_BE
	}	field;
	ULONG			word;
}	AIFSN_CSR_STRUC, *PAIFSN_CSR_STRUC;
#else
typedef	union	_AIFSN_CSR_STRUC	{
	struct	{
		ULONG   Aifsn0:4;       // for AC_BE
		ULONG   Aifsn1:4;       // for AC_BK
		ULONG   Aifsn2:4;       // for AC_VI
		ULONG   Aifsn3:4;       // for AC_VO
		ULONG   Rsv:16;
	}	field;
	ULONG			word;
}	AIFSN_CSR_STRUC, *PAIFSN_CSR_STRUC;
#endif

//
// CWMIN_CSR: CWmin for each EDCA AC
//
#ifdef __BIG_ENDIAN__
typedef	union	_CWMIN_CSR_STRUC	{
	struct	{
		ULONG   Rsv:16;
		ULONG   Cwmin3:4;       // for AC_VO
		ULONG   Cwmin2:4;       // for AC_VI
		ULONG   Cwmin1:4;       // for AC_BK
		ULONG   Cwmin0:4;       // for AC_BE
	}	field;
	ULONG			word;
}	CWMIN_CSR_STRUC, *PCWMIN_CSR_STRUC;
#else
typedef	union	_CWMIN_CSR_STRUC	{
	struct	{
		ULONG   Cwmin0:4;       // for AC_BE
		ULONG   Cwmin1:4;       // for AC_BK
		ULONG   Cwmin2:4;       // for AC_VI
		ULONG   Cwmin3:4;       // for AC_VO
		ULONG   Rsv:16;
	}	field;
	ULONG			word;
}	CWMIN_CSR_STRUC, *PCWMIN_CSR_STRUC;
#endif

//
// CWMAX_CSR: CWmin for each EDCA AC
//
#ifdef __BIG_ENDIAN__
typedef	union	_CWMAX_CSR_STRUC	{
	struct	{
		ULONG   Rsv:16;
		ULONG   Cwmax3:4;       // for AC_VO
		ULONG   Cwmax2:4;       // for AC_VI
		ULONG   Cwmax1:4;       // for AC_BK
		ULONG   Cwmax0:4;       // for AC_BE
	}	field;
	ULONG			word;
}	CWMAX_CSR_STRUC, *PCWMAX_CSR_STRUC;
#else
typedef	union	_CWMAX_CSR_STRUC	{
	struct	{
		ULONG   Cwmax0:4;       // for AC_BE
		ULONG   Cwmax1:4;       // for AC_BK
		ULONG   Cwmax2:4;       // for AC_VI
		ULONG   Cwmax3:4;       // for AC_VO
		ULONG   Rsv:16;
	}	field;
	ULONG			word;
}	CWMAX_CSR_STRUC, *PCWMAX_CSR_STRUC;
#endif

//
// TX_CNTL_CSR: KICK/Abort TX
//
#ifdef __BIG_ENDIAN__
typedef	union	_TX_CNTL_CSR_STRUC	{
	struct	{
		ULONG   Rsv1:11;
		ULONG   AbortTxMgmt:1;
		ULONG   AbortTxAc3:1;       // for AC_VO
		ULONG   AbortTxAc2:1;       // for AC_VI
		ULONG   AbortTxAc1:1;       // for AC_BE
		ULONG   AbortTxAc0:1;       // for AC_BK
		ULONG   Rsv2:11;
		ULONG   KickTxMgmt:1;
		ULONG   KickTxAc3:1;       // for AC_VO
		ULONG   KickTxAc2:1;       // for AC_VI
		ULONG   KickTxAc1:1;       // for AC_BE
		ULONG   KickTxAc0:1;       // for AC_BK
	}	field;
	ULONG			word;
}	TX_CNTL_CSR_STRUC, *PTX_CNTL_CSR_STRUC;
#else
typedef	union	_TX_CNTL_CSR_STRUC	{
	struct	{
		ULONG   KickTxAc0:1;       // for AC_BK
		ULONG   KickTxAc1:1;       // for AC_BE
		ULONG   KickTxAc2:1;       // for AC_VI
		ULONG   KickTxAc3:1;       // for AC_VO
		ULONG   KickTxMgmt:1;
		ULONG   Rsv2:11;
		ULONG   AbortTxAc0:1;       // for AC_BK
		ULONG   AbortTxAc1:1;       // for AC_BE
		ULONG   AbortTxAc2:1;       // for AC_VI
		ULONG   AbortTxAc3:1;       // for AC_VO
		ULONG   AbortTxMgmt:1;
		ULONG   Rsv1:11;
	}	field;
	ULONG			word;
}	TX_CNTL_CSR_STRUC, *PTX_CNTL_CSR_STRUC;
#endif

//
// CWMAX_CSR: CWmin for each EDCA AC
//
#ifdef __BIG_ENDIAN__
typedef	union	_RX_RING_CSR_STRUC	{
	struct	{
		ULONG   Rsv:13;
		ULONG   RxdWritebackSize:3;
ULONG   :2;
		ULONG   RxdSize:6;      // in unit of 32-bit     
		ULONG   RxRingTotal:8;
	}	field;
	ULONG			word;
}	RX_RING_CSR_STRUC, *PRX_RING_CSR_STRUC;
#else
typedef	union	_RX_RING_CSR_STRUC	{
	struct	{
		ULONG   RxRingTotal:8;
		ULONG   RxdSize:6;      // in unit of 32-bit     
ULONG   :2;
		ULONG   RxdWritebackSize:3;
		ULONG   Rsv:13;
	}	field;
	ULONG			word;
}	RX_RING_CSR_STRUC, *PRX_RING_CSR_STRUC;
#endif

//
// INT_SOURCE_CSR: Interrupt source register. Write one to clear corresponding bit
//
#ifdef __BIG_ENDIAN__
typedef	union	_INT_SOURCE_CSR_STRUC	{
	struct	{
ULONG       :10;
		ULONG       HccaDmaDone:1;
		ULONG       MgmtDmaDone:1;
		ULONG       Ac3DmaDone:1;
		ULONG       Ac2DmaDone:1;
		ULONG       Ac1DmaDone:1;
		ULONG       Ac0DmaDone:1;
ULONG		:11;
		ULONG       TxAbortDone:1;
ULONG       :1;
		ULONG       BeaconTxDone:1;
		ULONG		RxDone:1;
		ULONG		TxDone:1;
	}	field;
	ULONG			word;
}	INT_SOURCE_CSR_STRUC, *PINT_SOURCE_CSR_STRUC;
#else
typedef	union	_INT_SOURCE_CSR_STRUC	{
	struct	{
		ULONG		TxDone:1;
		ULONG		RxDone:1;
		ULONG       BeaconTxDone:1;
ULONG       :1;
		ULONG       TxAbortDone:1;
ULONG		:11;
		ULONG       Ac0DmaDone:1;
		ULONG       Ac1DmaDone:1;
		ULONG       Ac2DmaDone:1;
		ULONG       Ac3DmaDone:1;
		ULONG       MgmtDmaDone:1;
		ULONG       HccaDmaDone:1;
ULONG       :10;
	}	field;
	ULONG			word;
} INT_SOURCE_CSR_STRUC, *PINT_SOURCE_CSR_STRUC;
#endif

//
// INT_MASK_CSR:   Interrupt MASK register.   1: the interrupt is mask OFF
//
#ifdef __BIG_ENDIAN__
typedef	union	_INT_MASK_CSR_STRUC	{
	struct	{
ULONG       :10;
		ULONG       HccaDmaDone:1;
		ULONG       MgmtDmaDone:1;
		ULONG       Ac3DmaDone:1;
		ULONG       Ac2DmaDone:1;
		ULONG       Ac1DmaDone:1;
		ULONG       Ac0DmaDone:1;
		ULONG       MitigationPeriod:8; // interrupt mitigation in unit of 32 PCI clock
		ULONG       bEnableMitigationPeriod:1;
ULONG		:2;
		ULONG       TxAbortDone:1;
ULONG       :1;
		ULONG       BeaconTxDone:1;
		ULONG		RxDone:1;
		ULONG		TxDone:1;
	}	field;
	ULONG			word;
}INT_MASK_CSR_STRUC, *PINT_MASK_CSR_STRUC;
#else
typedef	union	_INT_MASK_CSR_STRUC	{
	struct	{
		ULONG		TxDone:1;
		ULONG		RxDone:1;
		ULONG       BeaconTxDone:1;
ULONG       :1;
		ULONG       TxAbortDone:1;
ULONG		:2;
		ULONG       bEnableMitigationPeriod:1;
		ULONG       MitigationPeriod:8; // interrupt mitigation in unit of 32 PCI clock
		ULONG       Ac0DmaDone:1;
		ULONG       Ac1DmaDone:1;
		ULONG       Ac2DmaDone:1;
		ULONG       Ac3DmaDone:1;
		ULONG       MgmtDmaDone:1;
		ULONG       HccaDmaDone:1;
ULONG       :10;
	}	field;
	ULONG			word;
} INT_MASK_CSR_STRUC, *PINT_MASK_CSR_STRUC;
#endif
//
// E2PROM_CSR: EEPROM control register
//
#ifdef __BIG_ENDIAN__
typedef	union	_E2PROM_CSR_STRUC	{
	struct	{
		ULONG		Rsvd:25;
		ULONG       LoadStatus:1;   // 1:loading, 0:done
		ULONG		Type:1;			// 1: 93C46, 0:93C66
		ULONG		EepromDO:1;
		ULONG		EepromDI:1;
		ULONG		EepromCS:1;
		ULONG		EepromSK:1;
		ULONG		Reload:1;		// Reload EEPROM content, write one to reload, self-cleared.
	}	field;
	ULONG			word;
}	E2PROM_CSR_STRUC, *PE2PROM_CSR_STRUC;
#else
typedef	union	_E2PROM_CSR_STRUC	{
	struct	{
		ULONG		Reload:1;		// Reload EEPROM content, write one to reload, self-cleared.
		ULONG		EepromSK:1;
		ULONG		EepromCS:1;
		ULONG		EepromDI:1;
		ULONG		EepromDO:1;
		ULONG		Type:1;			// 1: 93C46, 0:93C66
		ULONG       LoadStatus:1;   // 1:loading, 0:done
		ULONG		Rsvd:25;
	}	field;
	ULONG			word;
}	E2PROM_CSR_STRUC, *PE2PROM_CSR_STRUC;
#endif

//
// AC_TXOP_CSR0: AC_BK/AC_BE TXOP register
//
#ifdef __BIG_ENDIAN__
typedef	union	_AC_TXOP_CSR0_STRUC	{
	struct	{
		USHORT  Ac1Txop;        // for AC_BE, in unit of 32us
		USHORT  Ac0Txop;        // for AC_BK, in unit of 32us
	}	field;
	ULONG			word;
}	AC_TXOP_CSR0_STRUC, *PAC_TXOP_CSR0_STRUC;
#else
typedef	union	_AC_TXOP_CSR0_STRUC	{
	struct	{
		USHORT  Ac0Txop;        // for AC_BK, in unit of 32us
		USHORT  Ac1Txop;        // for AC_BE, in unit of 32us
	}	field;
	ULONG			word;
}	AC_TXOP_CSR0_STRUC, *PAC_TXOP_CSR0_STRUC;
#endif

//
// AC_TXOP_CSR1: AC_VO/AC_VI TXOP register
//
#ifdef __BIG_ENDIAN__
typedef	union	_AC_TXOP_CSR1_STRUC	{
	struct	{
		USHORT  Ac3Txop;        // for AC_VO, in unit of 32us
		USHORT  Ac2Txop;        // for AC_VI, in unit of 32us
	}	field;
	ULONG			word;
}	AC_TXOP_CSR1_STRUC, *PAC_TXOP_CSR1_STRUC;
#else
typedef	union	_AC_TXOP_CSR1_STRUC	{
	struct	{
		USHORT  Ac2Txop;        // for AC_VI, in unit of 32us
		USHORT  Ac3Txop;        // for AC_VO, in unit of 32us
	}	field;
	ULONG			word;
}	AC_TXOP_CSR1_STRUC, *PAC_TXOP_CSR1_STRUC;
#endif


// -------------------------------------------------------------------
//  E2PROM data layout
// -------------------------------------------------------------------

//
// EEPROM antenna select format
//
#ifdef __BIG_ENDIAN__
typedef	union	_EEPROM_ANTENNA_STRUC	{
	struct	{
		USHORT      RfIcType:5;             // see E2PROM document		
		USHORT		HardwareRadioControl:1;	// 1: Hardware controlled radio enabled, Read GPIO0 required.
		USHORT      DynamicTxAgcControl:1;
		USHORT		Rsv:2;
		USHORT		FrameType:1;			// 0: DPDT , 1: SPDT , noted this bit is valid for g only.				
		USHORT		RxDefaultAntenna:2;		// default of antenna, 0: diversity, 1:antenna-A, 2:antenna-B reserved (default = 0)
		USHORT		TxDefaultAntenna:2;		// default of antenna, 0: diversity, 1:antenna-A, 2:antenna-B reserved (default = 0)
		USHORT		NumOfAntenna:2;			// Number of antenna
	}	field;
	USHORT			word;
}	EEPROM_ANTENNA_STRUC, *PEEPROM_ANTENNA_STRUC;
#else
typedef	union	_EEPROM_ANTENNA_STRUC	{
	struct	{
		USHORT		NumOfAntenna:2;			// Number of antenna
		USHORT		TxDefaultAntenna:2;		// default of antenna, 0: diversity, 1:antenna-A, 2:antenna-B reserved (default = 0)
		USHORT		RxDefaultAntenna:2;		// default of antenna, 0: diversity, 1:antenna-A, 2:antenna-B reserved (default = 0)
		USHORT		FrameType:1;			// 0: DPDT , 1: SPDT , noted this bit is valid for g only.				
		USHORT		Rsv:2;
		USHORT      DynamicTxAgcControl:1;
		USHORT		HardwareRadioControl:1;	// 1: Hardware controlled radio enabled, Read GPIO0 required.
		USHORT      RfIcType:5;             // see E2PROM document
	}	field;
	USHORT			word;
}	EEPROM_ANTENNA_STRUC, *PEEPROM_ANTENNA_STRUC;
#endif

#ifdef __BIG_ENDIAN__
typedef	union	_EEPROM_NIC_CINFIG2_STRUC	{
	struct	{
		USHORT      Rsv2:11;					// must be 0
		USHORT		ExternalLNA:1;			// external LNA enable
		USHORT		Rsv1:4;
	}	field;
	USHORT			word;
}	EEPROM_NIC_CONFIG2_STRUC, *PEEPROM_NIC_CONFIG2_STRUC;
#else
typedef	union	_EEPROM_NIC_CINFIG2_STRUC	{
	struct	{
		USHORT		Rsv1:4;
		USHORT		ExternalLNA:1;			// external LNA enable
		USHORT      Rsv2:11;                 // must be 0
	}	field;
	USHORT			word;
}	EEPROM_NIC_CONFIG2_STRUC, *PEEPROM_NIC_CONFIG2_STRUC;
#endif

#ifdef __BIG_ENDIAN__
typedef	union	_EEPROM_TX_PWR_STRUC	{
	struct	{
		UCHAR	Byte1;				// High Byte
		UCHAR	Byte0;				// Low Byte
	}	field;
	USHORT	word;
}	EEPROM_TX_PWR_STRUC, *PEEPROM_TX_PWR_STRUC;
#else
typedef	union	_EEPROM_TX_PWR_STRUC	{
	struct	{
		UCHAR	Byte0;				// Low Byte
		UCHAR	Byte1;				// High Byte
	}	field;
	USHORT	word;
}	EEPROM_TX_PWR_STRUC, *PEEPROM_TX_PWR_STRUC;
#endif

#ifdef __BIG_ENDIAN__
typedef	union	_EEPROM_VERSION_STRUC	{
	struct	{
		UCHAR	Version;			// High Byte
		UCHAR	FaeReleaseNumber;	// Low Byte
	}	field;
	USHORT	word;
}	EEPROM_VERSION_STRUC, *PEEPROM_VERSION_STRUC;
#else
typedef	union	_EEPROM_VERSION_STRUC	{
	struct	{
		UCHAR	FaeReleaseNumber;	// Low Byte
		UCHAR	Version;			// High Byte
	}	field;
	USHORT	word;
}	EEPROM_VERSION_STRUC, *PEEPROM_VERSION_STRUC;
#endif

#ifdef __BIG_ENDIAN__
typedef	union	_EEPROM_LED_STRUC	{
	struct	{
		USHORT	Rsvd:3;				// Reserved
		USHORT	LedMode:5;			// Led mode.
		USHORT	PolarityGPIO_4:1;	// Polarity GPIO#4 setting.
		USHORT	PolarityGPIO_3:1;	// Polarity GPIO#3 setting.
		USHORT	PolarityGPIO_2:1;	// Polarity GPIO#2 setting.
		USHORT	PolarityGPIO_1:1;	// Polarity GPIO#1 setting.
		USHORT	PolarityGPIO_0:1;	// Polarity GPIO#0 setting.
		USHORT	PolarityACT:1;		// Polarity ACT setting.
		USHORT	PolarityRDY_A:1;		// Polarity RDY_A setting.
		USHORT	PolarityRDY_G:1;		// Polarity RDY_G setting.
	}	field;
	USHORT	word;
}	EEPROM_LED_STRUC, *PEEPROM_LED_STRUC;
#else
typedef	union	_EEPROM_LED_STRUC	{
	struct	{
		USHORT	PolarityRDY_G:1;		// Polarity RDY_G setting.
		USHORT	PolarityRDY_A:1;		// Polarity RDY_A setting.
		USHORT	PolarityACT:1;		// Polarity ACT setting.
		USHORT	PolarityGPIO_0:1;	// Polarity GPIO#0 setting.
		USHORT	PolarityGPIO_1:1;	// Polarity GPIO#1 setting.
		USHORT	PolarityGPIO_2:1;	// Polarity GPIO#2 setting.
		USHORT	PolarityGPIO_3:1;	// Polarity GPIO#3 setting.
		USHORT	PolarityGPIO_4:1;	// Polarity GPIO#4 setting.
		USHORT	LedMode:5;			// Led mode.
		USHORT	Rsvd:3;				// Reserved		
	}	field;
	USHORT	word;
}	EEPROM_LED_STRUC, *PEEPROM_LED_STRUC;
#endif
/*
#ifdef __BIG_ENDIAN__
typedef	union	_EEPROM_TXPOWER_DELTA_STRUC	{
	struct	{
		UCHAR	TxPowerEnable:1;// Enable
		UCHAR	Type:1;			// 1: plus the delta value, 0: minus the delta value
		UCHAR	DeltaValue:6;	// Tx Power dalta value (MAX=4)
	}	field;
	UCHAR	value;
}	EEPROM_TXPOWER_DELTA_STRUC, *PEEPROM_TXPOWER_DELTA_STRUC;
#else
typedef	union	_EEPROM_TXPOWER_DELTA_STRUC	{
	struct	{
		UCHAR	DeltaValue:6;	// Tx Power dalta value (MAX=4)
		UCHAR	Type:1;			// 1: plus the delta value, 0: minus the delta value
		UCHAR	TxPowerEnable:1;// Enable
	}	field;
	UCHAR	value;
}	EEPROM_TXPOWER_DELTA_STRUC, *PEEPROM_TXPOWER_DELTA_STRUC;
#endif
*/
////////////////////////////////////////////////////////////////////////////////////////
/*
// structure to store channel TX power
typedef struct _CHANNEL_TX_POWER {
	unsigned char	Channel;
	char	Power;
}	CHANNEL_TX_POWER, *PCHANNEL_TX_POWER;
*/
/*
 //
 //	configuration and status
 //
 typedef struct _PORT_CONFIG {
     
     // MIB:ieee802dot11.dot11smt(1).dot11StationConfigTable(1)
     USHORT		Psm;				  // power management mode	 (PWR_ACTIVE|PWR_SAVE)
     USHORT		DisassocReason;
     UCHAR		DisassocSta[MAC_ADDR_LEN];
     USHORT		DeauthReason;
     UCHAR		DeauthSta[MAC_ADDR_LEN];
     USHORT		AuthFailReason;
     UCHAR		AuthFailSta[MAC_ADDR_LEN];
     
     NDIS_802_11_AUTHENTICATION_MODE 	AuthMode;		// This should match to whatever microsoft defined
     NDIS_802_11_WEP_STATUS				WepStatus;
     NDIS_802_11_WEP_STATUS				OrigWepStatus;	// Original wep status set from OID
     
     
     // Add to support different cipher suite for WPA2/WPA mode
     NDIS_802_11_ENCRYPTION_STATUS		GroupCipher;		// Multicast cipher suite
     NDIS_802_11_ENCRYPTION_STATUS		PairCipher;			// Unicast cipher suite
     BOOLEAN								bMixCipher;			// Indicate current Pair & Group use different cipher suites
     USHORT								RsnCapability;
     
     // MIB:ieee802dot11.dot11smt(1).dot11WEPDefaultKeysTable(3)
     CIPHER_KEY	PskKey; 				// WPA PSK mode PMK
     UCHAR		PTK[64];				// WPA PSK mode PTK
     BSSID_INFO	SavedPMK[PMKID_NO];
     ULONG		SavedPMKNum;			// Saved PMKID number
     
     // WPA 802.1x port control, WPA_802_1X_PORT_SECURED, WPA_802_1X_PORT_NOT_SECURED
     UCHAR		PortSecured;
     UCHAR		RSN_IE[44];
     UCHAR		RSN_IELen;
     
     //#if WPA_SUPPLICANT_SUPPORT	
     BOOLEAN     IEEE8021X;				// Enable or disable IEEE 802.1x 
     CIPHER_KEY	DesireSharedKey[4];		// Record user desired WEP keys	
     BOOLEAN		IEEE8021x_required_keys;				// Enable or disable dynamic wep key updating
     BOOLEAN     WPA_Supplicant;         // Enable or disable WPA_SUPPLICANT 
     BOOLEAN     Send_Beacon;
     //#endif
     
     // For WPA countermeasures
     ULONG		LastMicErrorTime;	// record last MIC error time
     ULONG		MicErrCnt;			// Should be 0, 1, 2, then reset to zero (after disassoiciation).
     BOOLEAN 	bBlockAssoc;		// Block associate attempt for 60 seconds after counter measure occurred.
                                    // For WPA-PSK supplicant state
     WPA_STATE	WpaState;			// Default is SS_NOTUSE and handled by microsoft 802.1x
     UCHAR		ReplayCounter[8];
     UCHAR		ANonce[32]; 		// ANonce for WPA-PSK from aurhenticator
     UCHAR		SNonce[32]; 		// SNonce for WPA-PSK
     
     // MIB:ieee802dot11.dot11smt(1).dot11PrivacyTable(5)
     UCHAR								DefaultKeyId;
     NDIS_802_11_PRIVACY_FILTER			PrivacyFilter;	// PrivacyFilter enum for 802.1X
     
     
     // MIB:ieee802dot11.dot11mac(2).dot11OperationTable(1)
     USHORT		RtsThreshold;			// in unit of BYTE
     USHORT		FragmentThreshold;		// in unit of BYTE
     BOOLEAN 	bFragmentZeroDisable;	// Microsoft use 0 as disable 
     
     // MIB:ieee802dot11.dot11phy(4).dot11PhyTxPowerTable(3)
     UCHAR		TxPower;				// in unit of mW
     ULONG		TxPowerPercentage;		// 0~100 %
     ULONG		TxPowerDefault; 		// keep for TxPowerPercentage
     
     // MIB:ieee802dot11.dot11phy(4).dot11PhyDSSSTable(5)
     UCHAR		Channel;		  // current (I)BSS channel used in the station
     UCHAR       AdhocChannel;     // current (I)BSS channel used in the station
     UCHAR		CountryRegion;	  // Enum of country region, 0:FCC, 1:IC, 2:ETSI, 3:SPAIN, 4:France, 5:MKK, 6:MKK1, 7:Israel
     UCHAR		CountryRegionForABand;	// Enum of country region for A band
     
     
     // Copy supported rate from desired AP's beacon. We are trying to match
     // AP's supported and extended rate settings.
     UCHAR		SupRate[MAX_LEN_OF_SUPPORTED_RATES];
     UCHAR		SupRateLen;
     UCHAR		ExtRate[MAX_LEN_OF_SUPPORTED_RATES];
     UCHAR		ExtRateLen;
     UCHAR		ExpectedACKRate[MAX_LEN_OF_SUPPORTED_RATES];
     
     ULONG		BasicRateBitmap;		// backup basic ratebitmap
     
     //
     // other parameters not defined in standard MIB
     //
     UCHAR		DesireRate[MAX_LEN_OF_SUPPORTED_RATES]; 	 // OID_802_11_DESIRED_RATES
     UCHAR		MaxDesiredRate;
     UCHAR       BasicMlmeRate;          // Default Rate for sending MLME frames
     UCHAR		MlmeRate;
     UCHAR		RtsRate;				// RATE_xxx
     UCHAR		TxRate; 				// RATE_1, RATE_2, RATE_5_5, RATE_11, ...
     UCHAR		MaxTxRate;				// RATE_1, RATE_2, RATE_5_5, RATE_11
     
     UCHAR		Bssid[MAC_ADDR_LEN];
     USHORT		BeaconPeriod; 
     CHAR		Ssid[MAX_LEN_OF_SSID];		// NOT NULL-terminated
     UCHAR		SsidLen;					// the actual ssid length in used
     UCHAR		LastSsidLen;				// the actual ssid length in used
     CHAR		LastSsid[MAX_LEN_OF_SSID];	// NOT NULL-terminated
     UCHAR		LastBssid[MAC_ADDR_LEN];
     
     UCHAR		BssType;				// BSS_INFRA or BSS_ADHOC
     USHORT		AtimWin;				// used when starting a new IBSS
     
     UCHAR		RssiTrigger;
     UCHAR		RssiTriggerMode;		// RSSI_TRIGGERED_UPON_BELOW_THRESHOLD or RSSI_TRIGGERED_UPON_EXCCEED_THRESHOLD
     USHORT		DefaultListenCount; 	// default listen count;
     ULONG		WindowsPowerMode;			// Power mode for AC power
     ULONG		WindowsBatteryPowerMode;	// Power mode for battery if exists
     BOOLEAN 	bWindowsACCAMEnable;		// Enable CAM power mode when AC on
     BOOLEAN 	bAutoReconnect; 		// Set to TRUE when setting OID_802_11_SSID with no matching BSSID
     
     UCHAR		LastRssi;				// last received BEACON's RSSI
     UCHAR		LastRssi2;				// last received BEACON's RSSI for smart antenna
     USHORT		AvgRssi;				// last 8 BEACON's average RSSI
     USHORT		AvgRssiX8;				// sum of last 8 BEACON's RSSI
     ULONG		NumOfAvgRssiSample;
     
     ULONG		LastBeaconRxTime;		// OS's timestamp of the last BEACON RX time
     ULONG		Last11bBeaconRxTime;	// OS's timestamp of the last 11B BEACON RX time
     ULONG		LastScanTime;			// Record last scan time for issue BSSID_SCAN_LIST
     ULONG		ScanCnt;			  // Scan counts since most recent SSID, BSSID, SCAN OID request
     BOOLEAN 	bSwRadio;				// Software controlled Radio On/Off, TRUE: On
     BOOLEAN 	bHwRadio;				// Hardware controlled Radio On/Off, TRUE: On
     BOOLEAN 	bRadio; 				// Radio state, And of Sw & Hw radio state
     BOOLEAN 	bHardwareRadio; 		// Hardware controlled Radio enabled
     BOOLEAN 	bShowHiddenSSID;	  // Show all known SSID in SSID list get operation
     
     
     // PHY specification
     UCHAR	  PhyMode;			// PHY_11A, PHY_11B, PHY_11BG_MIXED, PHY_ABG_MIXED
     USHORT	  Dsifs;			// in units of usec
     USHORT	  TxPreamble;		// Rt802_11PreambleLong, Rt802_11PreambleShort, Rt802_11PreambleAuto
     
     // New for WPA, windows want us to to keep association information and
     // Fixed IEs from last association response
     NDIS_802_11_ASSOCIATION_INFORMATION 	AssocInfo;
     UCHAR					ReqVarIELen;				// Length of next VIE include EID & Length
     UCHAR					ReqVarIEs[MAX_VIE_LEN];
     UCHAR					ResVarIELen;				// Length of next VIE include EID & Length
     UCHAR					ResVarIEs[MAX_VIE_LEN];
     
     ULONG					EnableTurboRate;	  // 1: enable 72/100 Mbps whenever applicable, 0: never use 72/100 Mbps
     ULONG					UseBGProtection;	  // 0:AUTO, 1-always ON,2-always OFF
     ULONG					UseShortSlotTime;	  // 0: disable, 1 - use short slot (9us)
     
     
     // EDCA Qos
     BOOLEAN 				bWmmCapable;		// 0:disable WMM, 1:enable WMM
     QOS_CAPABILITY_PARM		APQosCapability;	// QOS capability of the current associated AP
     EDCA_PARM				APEdcaParm; 		// EDCA parameters of the current associated AP
     QBSS_LOAD_PARM			APQbssLoad; 		// QBSS load of the current associated AP
     
     BOOLEAN					bEnableTxBurst; 		// 0: disable, 1: enable TX PACKET BURST
     BOOLEAN					bAggregationCapable;	// 1: enable TX aggregation when the peer supports it
     BOOLEAN 				bUseZeroToDisableFragment;			// Microsoft use 0 as disable
     BOOLEAN 				bIEEE80211H;			// 1: enable IEEE802.11h spec.
     
     // a bitmap of BOOLEAN flags. each bit represent an operation status of a particular 
     // BOOLEAN control, either ON or OFF. These flags should always be accessed via
     // OPSTATUS_TEST_FLAG(), OPSTATUS_SET_FLAG(), OP_STATUS_CLEAR_FLAG() macros.
     // see fOP_STATUS_xxx in RTMP_DEF.C for detail bit definition
     ULONG					OpStatusFlags;
     
     UCHAR					AckPolicy[4];		// ACK policy of the specified AC. see ACK_xxx
     
     ABGBAND_STATE			BandState;			// For setting BBP used on B/G or A mode
     
     ULONG					AdhocMode;			// 0:WIFI mode (11b rates only), 1: b/g mixed, 2: 11g only, 3: 11a only, 4: 11abg mixed
     
     RALINK_TIMER_STRUCT		QuickResponeForRateUpTimer;
     BOOLEAN					QuickResponeForRateUpTimerRunning;
     
     
     // Fast Roaming
     BOOLEAN                 bFastRoaming;       // 0:disable fast roaming, 1:enable fast roaming
     ULONG                   dBmToRoam;          // the condition to roam when receiving Rssi less than this value. It's negative value.
     
     RADAR_DETECT_STRUCT	    RadarDetect;
     
     BOOLEAN                 bGetAPConfig;    	
     
     BOOLEAN                 bWscCapable;	// 1:use simple config, 0:otherwise
     WSC_LV_INFO             WscIEProbeReq;
     WSC_LV_INFO             WscIEBeacon;
     
 } PORT_CONFIG, *PPORT_CONFIG;
 */

////////////////////////////////////////////////////////////////////////////////////////

//
// Register set pair for initialzation register set definition
//
/*
typedef struct	_RTMP_RF_REGS
{
	UCHAR	Channel;
	ULONG	R1;
	ULONG	R2;
	ULONG	R3;
	ULONG	R4;
}	RTMP_RF_REGS, *PRTMP_RF_REGS;
*/
RTMP_RF_REGS RF2528RegTable[] = {
    //		ch	 R1 		 R2 		 R3(TX0~4=0) R4
    {1,  0x94002c0c, 0x94000786, 0x94068255, 0x940fea0b},
    {2,  0x94002c0c, 0x94000786, 0x94068255, 0x940fea1f},
    {3,  0x94002c0c, 0x9400078a, 0x94068255, 0x940fea0b},
    {4,  0x94002c0c, 0x9400078a, 0x94068255, 0x940fea1f},
    {5,  0x94002c0c, 0x9400078e, 0x94068255, 0x940fea0b},
    {6,  0x94002c0c, 0x9400078e, 0x94068255, 0x940fea1f},
    {7,  0x94002c0c, 0x94000792, 0x94068255, 0x940fea0b},
    {8,  0x94002c0c, 0x94000792, 0x94068255, 0x940fea1f},
    {9,  0x94002c0c, 0x94000796, 0x94068255, 0x940fea0b},
    {10, 0x94002c0c, 0x94000796, 0x94068255, 0x940fea1f},
    {11, 0x94002c0c, 0x9400079a, 0x94068255, 0x940fea0b},
    {12, 0x94002c0c, 0x9400079a, 0x94068255, 0x940fea1f},
    {13, 0x94002c0c, 0x9400079e, 0x94068255, 0x940fea0b},
    {14, 0x94002c0c, 0x940007a2, 0x94068255, 0x940fea13}
};
UCHAR	NUM_OF_2528_CHNL = (sizeof(RF2528RegTable) / sizeof(RTMP_RF_REGS));


RTMP_RF_REGS RF5226RegTable[] = {
    //		ch	 R1 		 R2 		 R3(TX0~4=0) R4
    {1,  0x94002c0c, 0x94000786, 0x94068255, 0x940fea0b},
    {2,  0x94002c0c, 0x94000786, 0x94068255, 0x940fea1f},
    {3,  0x94002c0c, 0x9400078a, 0x94068255, 0x940fea0b},
    {4,  0x94002c0c, 0x9400078a, 0x94068255, 0x940fea1f},
    {5,  0x94002c0c, 0x9400078e, 0x94068255, 0x940fea0b},
    {6,  0x94002c0c, 0x9400078e, 0x94068255, 0x940fea1f},
    {7,  0x94002c0c, 0x94000792, 0x94068255, 0x940fea0b},
    {8,  0x94002c0c, 0x94000792, 0x94068255, 0x940fea1f},
    {9,  0x94002c0c, 0x94000796, 0x94068255, 0x940fea0b},
    {10, 0x94002c0c, 0x94000796, 0x94068255, 0x940fea1f},
    {11, 0x94002c0c, 0x9400079a, 0x94068255, 0x940fea0b},
    {12, 0x94002c0c, 0x9400079a, 0x94068255, 0x940fea1f},
    {13, 0x94002c0c, 0x9400079e, 0x94068255, 0x940fea0b},
    {14, 0x94002c0c, 0x940007a2, 0x94068255, 0x940fea13},
    
    {36, 0x94002c0c, 0x9400099a, 0x94098255, 0x940fea23},
    {40, 0x94002c0c, 0x940009a2, 0x94098255, 0x940fea03},
    {44, 0x94002c0c, 0x940009a6, 0x94098255, 0x940fea0b},
    {48, 0x94002c0c, 0x940009aa, 0x94098255, 0x940fea13},
    {52, 0x94002c0c, 0x940009ae, 0x94098255, 0x940fea1b},
    {56, 0x94002c0c, 0x940009b2, 0x94098255, 0x940fea23},
    {60, 0x94002c0c, 0x940009ba, 0x94098255, 0x940fea03},
    {64, 0x94002c0c, 0x940009be, 0x94098255, 0x940fea0b},
    
    {100, 0x94002c0c, 0x94000a2a, 0x940b8255, 0x940fea03},
    {104, 0x94002c0c, 0x94000a2e, 0x940b8255, 0x940fea0b},
    {108, 0x94002c0c, 0x94000a32, 0x940b8255, 0x940fea13},
    {112, 0x94002c0c, 0x94000a36, 0x940b8255, 0x940fea1b},
    {116, 0x94002c0c, 0x94000a3a, 0x940b8255, 0x940fea23},
    {120, 0x94002c0c, 0x94000a82, 0x940b8255, 0x940fea03},
    {124, 0x94002c0c, 0x94000a86, 0x940b8255, 0x940fea0b},
    {128, 0x94002c0c, 0x94000a8a, 0x940b8255, 0x940fea13},
    {132, 0x94002c0c, 0x94000a8e, 0x940b8255, 0x940fea1b},
    {136, 0x94002c0c, 0x94000a92, 0x940b8255, 0x940fea23},
    {140, 0x94002c0c, 0x94000a9a, 0x940b8255, 0x940fea03},
    
    {149, 0x94002c0c, 0x94000aa2, 0x940b8255, 0x940fea1f},
    {153, 0x94002c0c, 0x94000aa6, 0x940b8255, 0x940fea27},
    {157, 0x94002c0c, 0x94000aae, 0x940b8255, 0x940fea07},
    {161, 0x94002c0c, 0x94000ab2, 0x940b8255, 0x940fea0f},
    {165, 0x94002c0c, 0x94000ab6, 0x940b8255, 0x940fea17},
    
    //MMAC(Japan)J52 ch 34,38,42,46
    {34, 0x94002c0c, 0x9408099a, 0x940da255, 0x940d3a0b},
    {38, 0x94002c0c, 0x9408099e, 0x940da255, 0x940d3a13},
    {42, 0x94002c0c, 0x940809a2, 0x940da255, 0x940d3a1b},
    {46, 0x94002c0c, 0x940809a6, 0x940da255, 0x940d3a23},
    
};
UCHAR	NUM_OF_5226_CHNL = (sizeof(RF5226RegTable) / sizeof(RTMP_RF_REGS));

// Reset the RFIC setting to new series    
static RTMP_RF_REGS RF5225RegTable[] = {
    //		ch	 R1 		 R2 		 R3(TX0~4=0) R4
    {1,  0x95002ccc, 0x95004786, 0x95068455, 0x950ffa0b},
    {2,  0x95002ccc, 0x95004786, 0x95068455, 0x950ffa1f},
    {3,  0x95002ccc, 0x9500478a, 0x95068455, 0x950ffa0b},
    {4,  0x95002ccc, 0x9500478a, 0x95068455, 0x950ffa1f},
    {5,  0x95002ccc, 0x9500478e, 0x95068455, 0x950ffa0b},
    {6,  0x95002ccc, 0x9500478e, 0x95068455, 0x950ffa1f},
    {7,  0x95002ccc, 0x95004792, 0x95068455, 0x950ffa0b},
    {8,  0x95002ccc, 0x95004792, 0x95068455, 0x950ffa1f},
    {9,  0x95002ccc, 0x95004796, 0x95068455, 0x950ffa0b},
    {10, 0x95002ccc, 0x95004796, 0x95068455, 0x950ffa1f},
    {11, 0x95002ccc, 0x9500479a, 0x95068455, 0x950ffa0b},
    {12, 0x95002ccc, 0x9500479a, 0x95068455, 0x950ffa1f},
    {13, 0x95002ccc, 0x9500479e, 0x95068455, 0x950ffa0b},
    {14, 0x95002ccc, 0x950047a2, 0x95068455, 0x950ffa13},
    
    // 802.11 UNI / HyperLan 2
    {36, 0x95002ccc, 0x9500499a, 0x9509be55, 0x950ffa23},
    {40, 0x95002ccc, 0x950049a2, 0x9509be55, 0x950ffa03},
    {44, 0x95002ccc, 0x950049a6, 0x9509be55, 0x950ffa0b},
    {48, 0x95002ccc, 0x950049aa, 0x9509be55, 0x950ffa13},
    {52, 0x95002ccc, 0x950049ae, 0x9509ae55, 0x950ffa1b},
    {56, 0x95002ccc, 0x950049b2, 0x9509ae55, 0x950ffa23},
    {60, 0x95002ccc, 0x950049ba, 0x9509ae55, 0x950ffa03},
    {64, 0x95002ccc, 0x950049be, 0x9509ae55, 0x950ffa0b},
    
    // 802.11 HyperLan 2
    {100, 0x95002ccc, 0x95004a2a, 0x950bae55, 0x950ffa03},
    {104, 0x95002ccc, 0x95004a2e, 0x950bae55, 0x950ffa0b},
    {108, 0x95002ccc, 0x95004a32, 0x950bae55, 0x950ffa13},
    {112, 0x95002ccc, 0x95004a36, 0x950bae55, 0x950ffa1b},
    {116, 0x95002ccc, 0x95004a3a, 0x950bbe55, 0x950ffa23},
    {120, 0x95002ccc, 0x95004a82, 0x950bbe55, 0x950ffa03},
    {124, 0x95002ccc, 0x95004a86, 0x950bbe55, 0x950ffa0b},
    {128, 0x95002ccc, 0x95004a8a, 0x950bbe55, 0x950ffa13},
    {132, 0x95002ccc, 0x95004a8e, 0x950bbe55, 0x950ffa1b},
    {136, 0x95002ccc, 0x95004a92, 0x950bbe55, 0x950ffa23},
    
    // 802.11 UNII
    {140, 0x95002ccc, 0x95004a9a, 0x950bbe55, 0x950ffa03},
    {149, 0x95002ccc, 0x95004aa2, 0x950bbe55, 0x950ffa1f},
    {153, 0x95002ccc, 0x95004aa6, 0x950bbe55, 0x950ffa27},
    {157, 0x95002ccc, 0x95004aae, 0x950bbe55, 0x950ffa07},
    {161, 0x95002ccc, 0x95004ab2, 0x950bbe55, 0x950ffa0f},
    {165, 0x95002ccc, 0x95004ab6, 0x950bbe55, 0x950ffa17},
    
    //MMAC(Japan)J52 ch 34,38,42,46
    {34, 0x95002ccc, 0x9500499a, 0x9509be55, 0x950ffa0b},
    {38, 0x95002ccc, 0x9500499e, 0x9509be55, 0x950ffa13},
    {42, 0x95002ccc, 0x950049a2, 0x9509be55, 0x950ffa1b},
    {46, 0x95002ccc, 0x950049a6, 0x9509be55, 0x950ffa23},
    
};
UCHAR	NUM_OF_5225_CHNL = (sizeof(RF5225RegTable) / sizeof(RTMP_RF_REGS));

#define TYPE_TXD                                        0
#define TYPE_RXD                                        1
#define TXD_SIZE                                sizeof(TXD_STRUC)
#define RXD_SIZE                                sizeof(RXD_STRUC)

#define CW_MIN_IN_BITS              4         // actual CwMin = 2^CW_MIN_IN_BITS - 1
#define CW_MAX_IN_BITS              10        // actual CwMax = 2^CW_MAX_IN_BITS - 1

#define LENGTH_CRC                  4

#define SWAP32(x) \
    ((UInt32)( \
    (((UInt32)(x) & (UInt32) 0x000000ffUL) << 24) | \
    (((UInt32)(x) & (UInt32) 0x0000ff00UL) <<  8) | \
    (((UInt32)(x) & (UInt32) 0x00ff0000UL) >>  8) | \
    (((UInt32)(x) & (UInt32) 0xff000000UL) >> 24) ))

#define RATE_AUTO_SWITCH                255 // for UserCfg.FixedTxRate only

#define DEFAULT_BBP_TX_POWER            0

#define CIPHER_NONE                             0
#define CIPHER_WEP64                    1
#define CIPHER_WEP128                   2
#define CIPHER_TKIP                             3
#define CIPHER_AES                              4
#define CIPHER_CKIP64                   5
#define CIPHER_CKIP128                  6
#define CIPHER_TKIP_NO_MIC              7        // MIC has been appended by driver, not a valid value in hardware key table 

#define IFS_BACKOFF                             0
#define IFS_SIFS                                1

////////////////////////////////////////////////////////////////////////////////////////

#define RETRY_LIMIT	3
#define ETH_LENGTH_OF_ADDRESS	6	// = MAC_ADDR_LEN
#define MAC_ADDR_LEN                      6
#define MAX_NUM_OF_CHANNELS		43	//1-14, 36/40/44/48/52/56/60/64/100/104/108/112/116/120/124/ 
									//128/132/136/140/149/153/157/161/165/34/38/42/46 + 1 as NULL termination
#define MAX_NUM_OF_A_CHANNELS	24	//36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165
#define J52_CHANNEL_START_OFFSET	38	//1-14, 36/40/44/48/52/56/60/64/100/104/108/112/116/120/124/
										//128/132/136/140/149/153/157/161/165/
#define DEFAULT_RF_TX_POWER 		5


// value domain for pAd->RfIcType
#define RFIC_5226				1  //A/B/G
#define RFIC_2528				2  //B/G
#define RFIC_5225				3  //A/B/G
#define RFIC_2527				4  //B/G

////////////////////////////////////////////////////////////////////////////////////////

/*
 //
 //this stuff goes here for now because something is funkey with the include order
 //
#define	NUM_EEPROM_BBP_PARMS		19
#define	NUM_EEPROM_BBP_TUNING_PARMS	7
 */
/*
 typedef struct _RT73_BBP_TUNING_PARAMETERS_STRUC
 {
     unsigned char			BBPTuningThreshold;
     unsigned char			R24LowerValue;
     unsigned char			R24HigherValue;
     unsigned char			R25LowerValue;
     unsigned char			R25HigherValue;
     unsigned char			R61LowerValue;
     unsigned char			R61HigherValue;
     unsigned char			BBPR17LowSensitivity;
     unsigned char			BBPR17MidSensitivity;
     unsigned char			RSSIToDbmOffset;
     bool			LargeCurrentRSSI;
 }
 RT73_BBP_TUNING_PARAMETERS_STRUC, *PRT73_BBP_TUNING_PARAMETERS_STRUC;
 */

// RT73 LED Actions.
#define LED_LNK_ON	5
#define LED_LNK_OFF	6
#define LED_ACT_ON	7
#define LED_ACT_OFF	8
#define LED_NONE	9

// RT73 value domain of LedCntl.LedMode and E2PROM
#define LED_MODE_DEFAULT			0
#define LED_MODE_TWO_LED			1
#define LED_MODE_SIGNAL_STRENGTH	2

////////////////////////////////////////////////////////////////////////////////

unsigned char	BIT8[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};
unsigned long	BIT32[] = {0x00000001, 0x00000002, 0x00000004, 0x00000008,
    0x00000010, 0x00000020, 0x00000040, 0x00000080,
    0x00000100, 0x00000200, 0x00000400, 0x00000800,
    0x00001000, 0x00002000, 0x00004000, 0x00008000,
    0x00010000, 0x00020000, 0x00040000, 0x00080000,
    0x00100000, 0x00200000, 0x00400000, 0x00800000,
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000};

char*	CipherName[] = {(char*)"none",(char*)"wep64",(char*)"wep128",(char*)"TKIP",
                        (char*)"AES",(char*)"CKIP64",(char*)"CKIP128"};

const unsigned short ccitt_16Table[] = {
	0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,
	0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF,
	0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6,
	0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE,
	0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485,
	0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D,
	0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4,
	0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC,
	0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823,
	0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B,
	0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12,
	0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A,
	0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41,
	0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49,
	0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70,
	0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78,
	0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F,
	0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,
	0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E,
	0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256,
	0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D,
	0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
	0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C,
	0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634,
	0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB,
	0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3,
	0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A,
	0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92,
	0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9,
	0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1,
	0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8,
	0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0
};
#define ByteCRC16(v, crc) \
(unsigned short)((crc << 8) ^  ccitt_16Table[((crc >> 8) ^ (v)) & 255])

//
// Register set pair for initialzation register set definition
//
typedef struct	_RTMP_REG_PAIR
{
	ULONG	Register;
	ULONG	Value;
}	RTMP_REG_PAIR, *PRTMP_REG_PAIR;

typedef struct	_BBP_REG_PAIR
{
	UCHAR	Register;
	UCHAR	Value;
}	BBP_REG_PAIR, *PBBP_REG_PAIR;

//
// BBP register initialization set
//
BBP_REG_PAIR   RT73BBPRegTable[] = {
	{3, 	0x80},
	{15,	0x30},
	{17,	0x20},
	{21,	0xc8},
	{22,	0x38},
	{23,	0x06},
	{24,	0xfe},
	{25,	0x0a},
	{26,	0x0d},
	{32,	0x0b},
	{34,	0x12},
	{37,	0x07},
	{39,	0xf8}, // 2005-09-02 by Gary, Atheros 11b issue 
	{41,	0x60}, // 03-09 gary
	{53,	0x10}, // 03-09 gary
	{54,	0x18}, // 03-09 gary
	{60,	0x10},
	{61,	0x04},
	{62,	0x04},
	{75,	0xfe},
	{86,	0xfe},
	{88,	0xfe},
	{90,	0x0f},
	{99,	0x00},
	{102,	0x16},
	{107,	0x04},
};
#define	NUM_BBP_REG_PARMS	(sizeof(RT73BBPRegTable) / sizeof(BBP_REG_PAIR))

//
// ASIC register initialization sets
//
RTMP_REG_PAIR	MACRegTable[] =	{
	{TXRX_CSR0, 	0x025fb032}, // 0x3040, RX control, default Disable RX
	{TXRX_CSR1, 	0x9eaa9eaf}, // 0x3044, BBP 30:Ant-A RSSI, R51:Ant-B RSSI, R42:OFDM rate, R47:CCK SIGNAL
	{TXRX_CSR2, 	0x8a8b8c8d}, // 0x3048, CCK TXD BBP registers
	{TXRX_CSR3, 	0x00858687}, // 0x304c, OFDM TXD BBP registers
	{TXRX_CSR7, 	0x2E31353B}, // 0x305c, ACK/CTS payload consume time for 18/12/9/6 mbps    
	{TXRX_CSR8, 	0x2a2a2a2c}, // 0x3060, ACK/CTS payload consume time for 54/48/36/24 mbps
	{TXRX_CSR15,	0x0000000f}, // 0x307c, TKIP MIC priority byte "AND" mask
	{MAC_CSR6,		0x00000fff}, // 0x3018, MAX frame length
	{MAC_CSR8,		0x016c030a}, // 0x3020, SIFS/EIFS time, set SIFS delay time.	
	{MAC_CSR10, 	0x00000718}, // 0x3028, ASIC PIN control in various power states
	{MAC_CSR12, 	0x00000004}, // 0x3030, power state control, set to AWAKE state
	{MAC_CSR13, 	0x00007f00}, // 0x3034, GPIO pin#7 as bHwRadio (input:0), otherwise (output:1)
	{SEC_CSR0,		0x00000000}, // 0x30a0, invalidate all shared key entries
	{SEC_CSR1,		0x00000000}, // 0x30a4, reset all shared key algorithm to "none"
	{SEC_CSR5,		0x00000000}, // 0x30b4, reset all shared key algorithm to "none"
	{PHY_CSR1,		0x000023b0}, // 0x3084, BBP Register R/W mode set to "Parallel mode"	
	{PHY_CSR5,		0x00040a06}, //  0x060a100c
	{PHY_CSR6,		0x00080606},
	{PHY_CSR7,		0x00000408},
	{AIFSN_CSR, 	0x00002273},
	{CWMIN_CSR, 	0x00002344},
	{CWMAX_CSR, 	0x000034aa},
};
#define	NUM_MAC_REG_PARMS	(sizeof(MACRegTable) / sizeof(RTMP_REG_PAIR))

//
// RT73 firmware image
//
unsigned char FirmwareImage[] = 
{
	//2005/07/22 Suport LED mode #0,#1,#2
	//2005/07/28 add Version control V1.0
	//2005/09/14 Update firmware code to prevent buffer not page out while aggregate.
	//2005/10/04 Firmware support Windows Power Saving.
	//2005/11/03 V1.3 not release, V1.4 improve Aggregation throughput
	//			 V1.4 will cause USB1.0 RX Stuck.
	//			 V1.5 remove RX checking(Special case, fixed on USB1.X Stuck issue)
	//			 V1.6 High throughput & WMM support (base on V1.4) not release
	//2005/11/24 V1.7 prevent USB1.0 Stuck issue. (base on V1.5)
	0x02, 0x13, 0x25, 0x12, 0x10, 0xd9, 0x02, 0x12, 0x58, 0x02, 0x13, 0x58, 0x02, 0x13, 0x5a, 0xc0, 
	0xd0, 0x75, 0xd0, 0x18, 0x12, 0x13, 0x5c, 0xd0, 0xd0, 0x22, 0x02, 0x14, 0x5c, 0x02, 0x14, 0xe7, 
	0xed, 0x4c, 0x70, 0x44, 0x90, 0x01, 0xa8, 0x74, 0x80, 0xf0, 0xef, 0x30, 0xe5, 0x07, 0xe4, 0x90, 
	0x00, 0x0f, 0xf0, 0x80, 0x2c, 0xe5, 0x40, 0x24, 0xc0, 0x60, 0x13, 0x24, 0xc0, 0x60, 0x16, 0x24, 
	0xc0, 0x60, 0x19, 0x24, 0xc0, 0x70, 0x1a, 0xe4, 0x90, 0x00, 0x0b, 0xf0, 0x80, 0x13, 0xe4, 0x90, 
	0x00, 0x13, 0xf0, 0x80, 0x0c, 0xe4, 0x90, 0x00, 0x1b, 0xf0, 0x80, 0x05, 0xe4, 0x90, 0x00, 0x23, 
	0xf0, 0xe4, 0x90, 0x01, 0xa8, 0xf0, 0xd3, 0x22, 0x90, 0x02, 0x02, 0xed, 0xf0, 0x90, 0x02, 0x01, 
	0xef, 0xf0, 0xd3, 0x22, 0xef, 0x24, 0xc0, 0x60, 0x1f, 0x24, 0xc0, 0x60, 0x2e, 0x24, 0xc0, 0x60, 
	0x3d, 0x24, 0xc0, 0x70, 0x53, 0x90, 0x00, 0x0b, 0xe0, 0x30, 0xe1, 0x02, 0xc3, 0x22, 0x90, 0x00, 
	0x09, 0xe0, 0xfe, 0x90, 0x00, 0x08, 0x80, 0x37, 0x90, 0x00, 0x13, 0xe0, 0x30, 0xe1, 0x02, 0xc3, 
	0x22, 0x90, 0x00, 0x11, 0xe0, 0xfe, 0x90, 0x00, 0x10, 0x80, 0x24, 0x90, 0x00, 0x1b, 0xe0, 0x30, 
	0xe1, 0x02, 0xc3, 0x22, 0x90, 0x00, 0x19, 0xe0, 0xfe, 0x90, 0x00, 0x18, 0x80, 0x11, 0x90, 0x00, 
	0x23, 0xe0, 0x30, 0xe1, 0x02, 0xc3, 0x22, 0x90, 0x00, 0x21, 0xe0, 0xfe, 0x90, 0x00, 0x20, 0xe0, 
	0xfd, 0xee, 0xf5, 0x37, 0xed, 0xf5, 0x38, 0xd3, 0x22, 0x30, 0x09, 0x20, 0x20, 0x04, 0x0b, 0x90, 
	0x02, 0x08, 0xe0, 0x54, 0x0f, 0x70, 0x03, 0x02, 0x12, 0x57, 0xc2, 0x09, 0x90, 0x02, 0x00, 0xe0, 
	0x44, 0x04, 0xf0, 0x74, 0x04, 0x12, 0x0c, 0x3a, 0xc2, 0x04, 0xc2, 0x07, 0x90, 0x02, 0x01, 0xe0, 
	0x30, 0xe0, 0x03, 0x00, 0x80, 0xf6, 0x90, 0x03, 0x26, 0xe0, 0x20, 0xe2, 0x03, 0x02, 0x12, 0x57, 
	0x90, 0x02, 0x08, 0xe0, 0x70, 0x1b, 0x20, 0x07, 0x03, 0x02, 0x12, 0x57, 0x90, 0x03, 0x12, 0xe0, 
	0x64, 0x22, 0x60, 0x03, 0x02, 0x12, 0x57, 0xd2, 0x09, 0xc2, 0x07, 0x74, 0x02, 0x12, 0x0c, 0x3a, 
	0x22, 0x90, 0x02, 0x03, 0xe0, 0x30, 0xe4, 0x47, 0x20, 0x06, 0x44, 0xe5, 0x3c, 0x60, 0x34, 0xe5, 
	0x40, 0x24, 0xc0, 0x60, 0x14, 0x24, 0xc0, 0x60, 0x18, 0x24, 0xc0, 0x60, 0x1c, 0x24, 0xc0, 0x70, 
	0x22, 0x90, 0x00, 0x0b, 0xe0, 0x30, 0xe1, 0x1b, 0x22, 0x90, 0x00, 0x13, 0xe0, 0x30, 0xe1, 0x13, 
	0x22, 0x90, 0x00, 0x1b, 0xe0, 0x30, 0xe1, 0x0b, 0x22, 0x90, 0x00, 0x23, 0xe0, 0x30, 0xe1, 0x03, 
	0x02, 0x12, 0x57, 0x90, 0x02, 0x03, 0x74, 0x01, 0xf0, 0x00, 0xe0, 0x54, 0xc0, 0xf5, 0x40, 0xe5, 
	0x40, 0x24, 0xc0, 0x60, 0x20, 0x24, 0xc0, 0x60, 0x30, 0x24, 0xc0, 0x60, 0x40, 0x24, 0xc0, 0x70, 
	0x56, 0x90, 0x00, 0x0b, 0xe0, 0x30, 0xe1, 0x03, 0x02, 0x12, 0x57, 0x90, 0x00, 0x09, 0xe0, 0xfe, 
	0x90, 0x00, 0x08, 0x80, 0x3a, 0x90, 0x00, 0x13, 0xe0, 0x30, 0xe1, 0x03, 0x02, 0x12, 0x57, 0x90, 
	0x00, 0x11, 0xe0, 0xfe, 0x90, 0x00, 0x10, 0x80, 0x26, 0x90, 0x00, 0x1b, 0xe0, 0x30, 0xe1, 0x03, 
	0x02, 0x12, 0x57, 0x90, 0x00, 0x19, 0xe0, 0xfe, 0x90, 0x00, 0x18, 0x80, 0x12, 0x90, 0x00, 0x23, 
	0xe0, 0x30, 0xe1, 0x03, 0x02, 0x12, 0x57, 0x90, 0x00, 0x21, 0xe0, 0xfe, 0x90, 0x00, 0x20, 0xe0, 
	0xfd, 0xee, 0xf5, 0x37, 0xed, 0xf5, 0x38, 0x90, 0x03, 0x27, 0x74, 0x82, 0xf0, 0x90, 0x02, 0x01, 
	0xe5, 0x40, 0xf0, 0x90, 0x02, 0x06, 0xe0, 0xf5, 0x3c, 0xc3, 0xe5, 0x38, 0x95, 0x3a, 0xe5, 0x37, 
	0x95, 0x39, 0x50, 0x21, 0xe5, 0x40, 0x44, 0x05, 0xff, 0xe5, 0x37, 0xa2, 0xe7, 0x13, 0xfc, 0xe5, 
	0x38, 0x13, 0xfd, 0x12, 0x10, 0x20, 0xe5, 0x3c, 0x30, 0xe2, 0x04, 0xd2, 0x06, 0x80, 0x02, 0xc2, 
	0x06, 0x53, 0x3c, 0x01, 0x22, 0x30, 0x0b, 0x07, 0xe4, 0x90, 0x02, 0x02, 0xf0, 0x80, 0x06, 0x90, 
	0x02, 0x02, 0x74, 0x20, 0xf0, 0xe5, 0x40, 0x44, 0x01, 0x90, 0x02, 0x01, 0xf0, 0x90, 0x02, 0x01, 
	0xe0, 0x30, 0xe0, 0x03, 0x00, 0x80, 0xf6, 0x90, 0x03, 0x27, 0x74, 0x02, 0xf0, 0xaf, 0x40, 0x12, 
	0x10, 0x74, 0x40, 0xa5, 0x00, 0x80, 0xf6, 0x22, 0x90, 0x7f, 0xf8, 0xe0, 0xb4, 0x02, 0x03, 0x12, 
	0x16, 0x38, 0x90, 0x02, 0x01, 0xe0, 0x30, 0xe0, 0x03, 0x00, 0x80, 0xf6, 0x90, 0x03, 0x26, 0xe0, 
	0x20, 0xe1, 0x07, 0xe5, 0x3b, 0x70, 0x03, 0x02, 0x13, 0x24, 0xe5, 0x3b, 0x70, 0x15, 0x90, 0x03, 
	0x24, 0xe0, 0x75, 0xf0, 0x40, 0xa4, 0xf5, 0x36, 0x85, 0xf0, 0x35, 0x75, 0x24, 0x83, 0x75, 0x3b, 
	0x01, 0x80, 0x03, 0x75, 0x24, 0x03, 0xd3, 0xe5, 0x36, 0x95, 0x3a, 0xe5, 0x35, 0x95, 0x39, 0x40, 
	0x36, 0x90, 0x02, 0x01, 0xe0, 0x30, 0xe0, 0x03, 0x00, 0x80, 0xf6, 0x90, 0x03, 0x27, 0xe5, 0x24, 
	0xf0, 0x90, 0x00, 0x0f, 0xe0, 0x30, 0xe1, 0x04, 0x30, 0x0e, 0xf6, 0x22, 0x30, 0x0b, 0x07, 0xe4, 
	0x90, 0x02, 0x02, 0xf0, 0x80, 0x06, 0x90, 0x02, 0x02, 0x74, 0x20, 0xf0, 0x90, 0x02, 0x01, 0x74, 
	0x21, 0xf0, 0x75, 0x24, 0x03, 0x80, 0x3d, 0xe5, 0x35, 0xa2, 0xe7, 0x13, 0xfe, 0xe5, 0x36, 0x13, 
	0xfd, 0xac, 0x06, 0x90, 0x02, 0x01, 0xe0, 0x30, 0xe0, 0x03, 0x00, 0x80, 0xf6, 0x90, 0x03, 0x27, 
	0xe5, 0x24, 0xf0, 0x90, 0x00, 0x0f, 0xe0, 0x30, 0xe1, 0x04, 0x30, 0x0e, 0xf6, 0x22, 0x7f, 0x25, 
	0x12, 0x10, 0x20, 0xe5, 0x36, 0xb5, 0x3a, 0x08, 0xe5, 0x35, 0xb5, 0x39, 0x03, 0x00, 0x80, 0x04, 
	0xe4, 0xf5, 0x3b, 0x22, 0xc3, 0xe5, 0x36, 0x95, 0x3a, 0xf5, 0x36, 0xe5, 0x35, 0x95, 0x39, 0xf5, 
	0x35, 0x02, 0x12, 0x96, 0x22, 0x75, 0xa8, 0x0f, 0x90, 0x03, 0x06, 0x74, 0x01, 0xf0, 0x90, 0x03, 
	0x07, 0xf0, 0x90, 0x03, 0x08, 0x04, 0xf0, 0x90, 0x03, 0x09, 0x74, 0x6c, 0xf0, 0x90, 0x03, 0x0a, 
	0x74, 0xff, 0xf0, 0x90, 0x03, 0x02, 0x74, 0x1f, 0xf0, 0x90, 0x03, 0x00, 0x74, 0x04, 0xf0, 0x90, 
	0x03, 0x25, 0x74, 0x31, 0xf0, 0xd2, 0xaf, 0x22, 0x00, 0x22, 0x00, 0x22, 0x90, 0x03, 0x05, 0xe0, 
	0x30, 0xe0, 0x0b, 0xe0, 0x44, 0x01, 0xf0, 0x30, 0x09, 0x02, 0xd2, 0x04, 0xc2, 0x07, 0x22, 0x8d, 
	0x24, 0xa9, 0x07, 0x90, 0x7f, 0xfc, 0xe0, 0x75, 0x25, 0x00, 0xf5, 0x26, 0xa3, 0xe0, 0x75, 0x27, 
	0x00, 0xf5, 0x28, 0xa3, 0xe0, 0xff, 0xa3, 0xe0, 0xfd, 0xe9, 0x30, 0xe5, 0x14, 0x54, 0xc0, 0x60, 
	0x05, 0x43, 0x05, 0x03, 0x80, 0x03, 0x53, 0x05, 0xfc, 0xef, 0x54, 0x3f, 0x44, 0x40, 0xff, 0x80, 
	0x06, 0x53, 0x07, 0x3f, 0x53, 0x05, 0xf0, 0xe5, 0x24, 0x30, 0xe0, 0x05, 0x43, 0x05, 0x10, 0x80, 
	0x03, 0x53, 0x05, 0xef, 0x90, 0x7f, 0xfc, 0xe5, 0x26, 0xf0, 0xa3, 0xe5, 0x28, 0xf0, 0xa3, 0xef, 
	0xf0, 0xa3, 0xed, 0xf0, 0x22, 0x8f, 0x24, 0xa9, 0x05, 0x90, 0x7f, 0xfc, 0xe0, 0x75, 0x25, 0x00, 
	0xf5, 0x26, 0xa3, 0xe0, 0x75, 0x27, 0x00, 0xf5, 0x28, 0xa3, 0xe0, 0xff, 0xa3, 0xe0, 0xfd, 0xe5, 
	0x24, 0x30, 0xe5, 0x0b, 0x43, 0x05, 0x0f, 0xef, 0x54, 0x3f, 0x44, 0x40, 0xff, 0x80, 0x06, 0x53, 
	0x05, 0xf0, 0x53, 0x07, 0x3f, 0xe9, 0x30, 0xe0, 0x05, 0x43, 0x05, 0x10, 0x80, 0x03, 0x53, 0x05, 
	0xef, 0x90, 0x7f, 0xfc, 0xe5, 0x26, 0xf0, 0xa3, 0xe5, 0x28, 0xf0, 0xa3, 0xef, 0xf0, 0xa3, 0xed, 
	0xf0, 0x22, 0x90, 0x7f, 0xfc, 0xe0, 0xf9, 0xa3, 0xe0, 0xfe, 0xa3, 0xe0, 0xfc, 0xa3, 0xe0, 0xfb, 
	0xef, 0x30, 0xe5, 0x0b, 0x43, 0x03, 0x0f, 0xec, 0x54, 0x3f, 0x44, 0x40, 0xfc, 0x80, 0x06, 0x53, 
	0x03, 0xf0, 0x53, 0x04, 0x3f, 0xed, 0x30, 0xe0, 0x07, 0xef, 0x54, 0xc0, 0x60, 0x07, 0x80, 0x0a, 
	0xef, 0x54, 0xc0, 0x60, 0x05, 0x43, 0x03, 0x10, 0x80, 0x03, 0x53, 0x03, 0xef, 0x90, 0x7f, 0xfc, 
	0xe9, 0xf0, 0xa3, 0xee, 0xf0, 0xa3, 0xec, 0xf0, 0xa3, 0xeb, 0xf0, 0x22, 0xe5, 0x4b, 0xfd, 0x54, 
	0x1f, 0x90, 0x7f, 0xf8, 0xf0, 0xe5, 0x4a, 0xf5, 0x09, 0x90, 0x30, 0x38, 0xe0, 0x90, 0x7f, 0xfc, 
	0xf0, 0x90, 0x30, 0x39, 0xe0, 0x90, 0x7f, 0xfd, 0xf0, 0x90, 0x30, 0x3a, 0xe0, 0x90, 0x7f, 0xfe, 
	0xf0, 0x90, 0x30, 0x3b, 0xe0, 0x90, 0x7f, 0xff, 0xf0, 0xed, 0x30, 0xe5, 0x0c, 0x54, 0xc0, 0x60, 
	0x0d, 0x90, 0x7f, 0xf0, 0xe5, 0x47, 0xf0, 0x80, 0x05, 0xe4, 0x90, 0x7f, 0xf0, 0xf0, 0x90, 0x7f, 
	0xf8, 0xe0, 0x14, 0x60, 0x08, 0x24, 0xfe, 0x60, 0x0d, 0x24, 0x03, 0x80, 0x12, 0xaf, 0x05, 0xad, 
	0x09, 0x12, 0x13, 0xc5, 0x80, 0x10, 0xaf, 0x05, 0xad, 0x09, 0x12, 0x14, 0x12, 0x80, 0x07, 0xaf, 
	0x05, 0xad, 0x09, 0x12, 0x13, 0x6f, 0x90, 0x7f, 0xfc, 0xe0, 0x90, 0x30, 0x38, 0xf0, 0x90, 0x7f, 
	0xfd, 0xe0, 0x90, 0x30, 0x39, 0xf0, 0x90, 0x7f, 0xfe, 0xe0, 0x90, 0x30, 0x3a, 0xf0, 0x90, 0x7f, 
	0xff, 0xe0, 0x90, 0x30, 0x3b, 0xf0, 0x22, 0xe5, 0x4b, 0x64, 0x01, 0x60, 0x03, 0x02, 0x15, 0x71, 
	0xf5, 0x4b, 0xe5, 0x44, 0x45, 0x43, 0x70, 0x03, 0x02, 0x15, 0xa0, 0x12, 0x0c, 0x14, 0x12, 0x0b, 
	0x86, 0x50, 0xfb, 0x90, 0x00, 0x00, 0xe0, 0xf5, 0x25, 0x12, 0x15, 0xb4, 0xc2, 0x92, 0xe4, 0xf5, 
	0x24, 0xe5, 0x24, 0xc3, 0x95, 0x25, 0x50, 0x49, 0x7e, 0x00, 0x7f, 0x4c, 0x74, 0x40, 0x25, 0x24, 
	0xf5, 0x82, 0xe4, 0x34, 0x01, 0xad, 0x82, 0xfc, 0x75, 0x2b, 0x02, 0x7b, 0x10, 0x12, 0x07, 0x1e, 
	0xc2, 0x93, 0x12, 0x15, 0xa1, 0x7d, 0xa0, 0x12, 0x15, 0xd0, 0xe5, 0x24, 0x54, 0x0f, 0x24, 0x4c, 
	0xf8, 0xe6, 0xfd, 0xaf, 0x4b, 0xae, 0x4a, 0x12, 0x15, 0xd8, 0x05, 0x4b, 0xe5, 0x4b, 0x70, 0x02, 
	0x05, 0x4a, 0x12, 0x0a, 0x5f, 0x05, 0x24, 0xe5, 0x24, 0x54, 0x0f, 0x70, 0xd5, 0xd2, 0x93, 0x80, 
	0xb0, 0xc3, 0xe5, 0x44, 0x95, 0x25, 0xf5, 0x44, 0xe5, 0x43, 0x94, 0x00, 0xf5, 0x43, 0x02, 0x14, 
	0xf2, 0x12, 0x15, 0xb4, 0xc2, 0x93, 0xc2, 0x92, 0x12, 0x15, 0xa1, 0x7d, 0x80, 0x12, 0x15, 0xd0, 
	0x7d, 0xaa, 0x74, 0x55, 0xff, 0xfe, 0x12, 0x15, 0xd8, 0x7d, 0x55, 0x7f, 0xaa, 0x7e, 0x2a, 0x12, 
	0x15, 0xd8, 0x7d, 0x30, 0xaf, 0x4b, 0xae, 0x4a, 0x12, 0x15, 0xd8, 0x12, 0x0a, 0x5f, 0xd2, 0x93, 
	0x22, 0x7d, 0xaa, 0x74, 0x55, 0xff, 0xfe, 0x12, 0x15, 0xd8, 0x7d, 0x55, 0x7f, 0xaa, 0x7e, 0x2a, 
	0x12, 0x15, 0xd8, 0x22, 0xad, 0x47, 0x7f, 0x34, 0x7e, 0x30, 0x12, 0x15, 0xd8, 0x7d, 0xff, 0x7f, 
	0x35, 0x7e, 0x30, 0x12, 0x15, 0xd8, 0xe4, 0xfd, 0x7f, 0x37, 0x7e, 0x30, 0x12, 0x15, 0xd8, 0x22, 
	0x74, 0x55, 0xff, 0xfe, 0x12, 0x15, 0xd8, 0x22, 0x8f, 0x82, 0x8e, 0x83, 0xed, 0xf0, 0x22, 0xe4, 
	0xfc, 0x90, 0x7f, 0xf0, 0xe0, 0xaf, 0x09, 0x14, 0x60, 0x14, 0x14, 0x60, 0x15, 0x14, 0x60, 0x16, 
	0x14, 0x60, 0x17, 0x14, 0x60, 0x18, 0x24, 0x05, 0x70, 0x16, 0xe4, 0xfc, 0x80, 0x12, 0x7c, 0x01, 
	0x80, 0x0e, 0x7c, 0x03, 0x80, 0x0a, 0x7c, 0x07, 0x80, 0x06, 0x7c, 0x0f, 0x80, 0x02, 0x7c, 0x1f, 
	0xec, 0x6f, 0xf4, 0x54, 0x1f, 0xfc, 0x90, 0x30, 0x34, 0xe0, 0x54, 0xe0, 0x4c, 0xfd, 0xa3, 0xe0, 
	0xfc, 0x43, 0x04, 0x1f, 0x7f, 0x34, 0x7e, 0x30, 0x12, 0x15, 0xd8, 0xad, 0x04, 0x0f, 0x12, 0x15, 
	0xd8, 0xe4, 0xfd, 0x7f, 0x37, 0x02, 0x15, 0xd8, 0x02, 0x15, 0xdf, 0x00, 0x00, 0x00, 0x00, 0x00, 
};

#define	FIRMWAREIMAGE_LENGTH		(sizeof (FirmwareImage) / sizeof(unsigned char))
#define FIRMWARE_MAJOR_VERSION	1
#define FIRMWARE_MINOR_VERSION	7
#define FIRMWARE_IMAGE_BASE     0x800
#define MAX_FIRMWARE_IMAGE_SIZE 2048   // 2kbytes

#endif	// __RT73_H__

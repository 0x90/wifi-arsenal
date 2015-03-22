/*
        
        File:			prism2.h
        Program:		KisMAC
	Description:		KisMAC is a wireless stumbler for MacOS X.
                
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

#define wlResetTries 100
#define wlTimeout  65536

/* Firmware types */
#define	WI_NOTYPE	0
#define	WI_LUCENT	1
#define	WI_INTERSIL	2
#define	WI_SYMBOL	3

enum WLCommandCode {
    wlcInit        = 0x0000,
    wlcEnable      = 0x0001,
    wlcDisable     = 0x0002,
    wlcDiag        = 0x0003,
    wlcAllocMem    = 0x000a,
    wlcTransmit    = 0x000b,
    wlcNotify      = 0x0010,
    wlcInquire     = 0x0011,
    wlcAccessRead  = 0x0021,
    wlcAccessWrite = 0x0121,
    wlcProgram     = 0x0022,
    wlcMonitorOn   = 0x0B38,
    wlcMonitorOff  = 0x0F38
};

struct WLHardwareAddress {
    UInt8 bytes[6];
};

struct WLIdentity {
    UInt16 vendor;
    UInt16 variant;
    UInt16 major;
    UInt16 minor;
};



 /*
  * This program is derived from code bearing the following Copyright(s)
  */

 /*                                                        -*- linux-c -*-
  *   _  _ ____ __ _ ___ ____ ____ __ _ _ _ _ |
  * .  \/  |--| | \|  |  |--< [__] | \| | _X_ | s e c u r e  s y s t e m s
  *
  * .vt|ar5k - PCI/CardBus 802.11a WirelessLAN driver for Atheros AR5k chipsets
  *
  * Copyright (c) 2002, .vantronix | secure systems
  *                     and Reyk Floeter <reyk_(_at_)_va_(_dot_)__(_dot_)__(_dot_)_>
  *
  * This program is free software ; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License as published by
  * the Free Software Foundation ; either version 2 of the License, or
  * (at your option) any later version.
  *
  * This program is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY ; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  * GNU General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program ; if not, write to the Free Software
  * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
  */

 /*
  * Modified by Jan Krupa for EEPROM read/write/repair
  * Version 1.0
  */


/*
* Copyright (C) 2010, Gennady "ShultZ" Kozlov <qpxtool@mail.ru>
*/

#include "ath5kio.h"

#define ATH5K_EEPROM_SIZE  0x800
#define ATH5K_EEPROM_SIGNATURE    0x0000
#define ATH5K_MMAP_LENGTH 0x10000

#define AR5K_PCICFG 0x4010 
#define AR5K_PCICFG_EEAE 0x00000001 
#define AR5K_PCICFG_CLKRUNEN 0x00000004 
#define AR5K_PCICFG_LED_PEND 0x00000020 
#define AR5K_PCICFG_LED_ACT 0x00000040 
#define AR5K_PCICFG_SL_INTEN 0x00000800 
#define AR5K_PCICFG_BCTL		 0x00001000 
#define AR5K_PCICFG_SPWR_DN 0x00010000 

#define AR5211_EEPROM_ADDR 0x6000 
#define AR5211_EEPROM_DATA 0x6004
#define AR5211_EEPROM_COMD 0x6008
#define AR5211_EEPROM_COMD_READ 0x0001
#define AR5211_EEPROM_COMD_WRITE 0x0002
#define AR5211_EEPROM_COMD_RESET 0x0003
#define AR5211_EEPROM_STATUS 0x600C
#define AR5211_EEPROM_STAT_RDERR 0x0001
#define AR5211_EEPROM_STAT_RDDONE 0x0002
#define AR5211_EEPROM_STAT_WRERR 0x0003
#define AR5211_EEPROM_STAT_WRDONE 0x0004
#define AR5211_EEPROM_CONF 0x6010

/* Atheros 5k devices */
const struct pci_id ath5k_ids[] = {
	{ ATHEROS_PCI_VID, 0x0007, "AR5000 802.11a Wireless Adapter" },
	{ ATHEROS_PCI_VID, 0x0011, "AR5210 802.11a NIC" },
	{ ATHEROS_PCI_VID, 0x0012, "AR5211 802.11ab NIC" },
	{ ATHEROS_PCI_VID, 0x0013, "Atheros AR5001X+ Wireless Network Adapter" },
	{ ATHEROS_PCI_VID, 0x001a, "AR2413 802.11bg NIC" },
	{ ATHEROS_PCI_VID, 0x001b, "AR5413 802.11abg NIC" },
	{ ATHEROS_PCI_VID, 0x001c, "AR5001 Wireless Network Adapter" },
	{ ATHEROS_PCI_VID, 0x001d, "AR5007G Wireless Network Adapter" },
	{ ATHEROS_PCI_VID, 0x0020, "AR5513 802.11abg Wireless NIC" },
	{ ATHEROS_PCI_VID, 0x0207, "AR5210 802.11abg" },
	{ ATHEROS_PCI_VID, 0x1014, "AR5212 802.11abg" },

	{ 0, 0, "" }
};


static bool ath5k_eeprom_lock(struct pcidev *dev) { return true; }

static bool ath5k_eeprom_release(struct pcidev *dev) { return true; }

static bool ath5k_eeprom_read16(struct pcidev *dev, uint32_t addr, uint16_t *value)
{
	int timeout = 10000 ;
 	unsigned long int status ;

 	PCI_OUT32(AR5211_EEPROM_CONF, 0),
 	usleep( 5 ) ;
 
 	/** enable eeprom read access */
 	PCI_OUT32( AR5211_EEPROM_COMD, PCI_IN32(AR5211_EEPROM_COMD) | AR5211_EEPROM_COMD_RESET) ;
 	usleep( 5 ) ;
 
 	/** set address */
 	PCI_OUT32( AR5211_EEPROM_ADDR, addr >> 1) ;
 	usleep( 5 ) ;
 
 	PCI_OUT32( AR5211_EEPROM_COMD, PCI_IN32(AR5211_EEPROM_COMD) | AR5211_EEPROM_COMD_READ) ;
 
 	while (timeout > 0) {
 		usleep(1) ;
 		status = PCI_IN32(AR5211_EEPROM_STATUS) ;
 		if (status & AR5211_EEPROM_STAT_RDDONE) {
 			if (status & AR5211_EEPROM_STAT_RDERR) {
 				printf( "\neeprom read access failed at %04x!\n", addr);
				return false;
 			}
 			status = PCI_IN32(AR5211_EEPROM_DATA) ;
			*value = status & 0x0000ffff;
 			return true;
 		}
 		timeout-- ;
 	}
 	printf( "\neeprom read timeout at %04x!\n", addr);
	return false;
}

static bool ath5k_eeprom_write16(struct pcidev *dev, uint32_t addr, uint16_t value)
{
 	int timeout = 10000 ;
 	unsigned long int status ;
 	unsigned long int pcicfg ;
 	int i ;
 	unsigned short int sdata ;

 	/** enable eeprom access */
 	pcicfg = PCI_IN32( AR5K_PCICFG ) ;
	PCI_OUT32(AR5K_PCICFG, ( pcicfg & ~AR5K_PCICFG_SPWR_DN ) ) ;
	usleep( 500 ) ;
 	PCI_OUT32(AR5K_PCICFG, pcicfg | AR5K_PCICFG_EEAE /* | 0x2 */) ;
 	usleep( 50 ) ;
 
 	PCI_OUT32( AR5211_EEPROM_STATUS, 0);
 	usleep( 50 ) ;
 
 	/* VT_WLAN_OUT32( AR5211_EEPROM_CONF, 1) ; */
 	PCI_OUT32( AR5211_EEPROM_CONF, 0) ;
 	usleep( 50 ) ;
 
 	i = 100 ;
 retry:
 	/** enable eeprom write access */
 	PCI_OUT32(AR5211_EEPROM_COMD, AR5211_EEPROM_COMD_RESET);
 	usleep( 500 ) ;
 
 	/* Write data */
 	PCI_OUT32(AR5211_EEPROM_DATA, value);
 	usleep( 5 ) ;
 
 	/** set address */
 	PCI_OUT32(AR5211_EEPROM_ADDR, addr >> 1);
 	usleep( 5 ) ;
 
 	PCI_OUT32(AR5211_EEPROM_COMD, AR5211_EEPROM_COMD_WRITE);
 	usleep( 5 ) ;
 
 	for ( timeout = 10000 ; timeout > 0 ; --timeout ) {
 		status = PCI_IN32( AR5211_EEPROM_STATUS );
 		if ( status & 0xC ) {
 			if ( status & AR5211_EEPROM_STAT_WRERR ) {
 				printf("\neeprom write access failed!\n");
				return false;
			}

 			PCI_OUT32( AR5211_EEPROM_STATUS, 0 );
 			usleep( 10 ) ;
 			break ;
 		}
 		usleep( 10 ) ;
 		timeout--;
 	}
 	if (!dev->ops->eeprom_read16( dev, addr, &sdata)) {
 		fprintf( stderr, "\nWrite verify: read failed!\n");
		return false;
	}
 	if ( ( sdata != value ) && i ) {
 		--i ;
 		fprintf( stderr, "\nRetrying eeprom write!\n");
 		goto retry ;
 	}
	return true;
}

struct io_driver io_ath5k = {
	.name			 = "ath5k",
	.valid_ids		  = (struct pci_id*) &ath5k_ids,
	.mmap_size        = ATH5K_MMAP_LENGTH,
	.eeprom_size      = ATH5K_EEPROM_SIZE,
	.eeprom_signature = ATH5K_EEPROM_SIGNATURE,
	.eeprom_writable  = true,

	.init_device	 = NULL,
	.eeprom_init     = NULL,
	.eeprom_check    = NULL,
	.eeprom_lock     = &ath5k_eeprom_lock,
	.eeprom_release  = &ath5k_eeprom_release,
	.eeprom_read16   = &ath5k_eeprom_read16,
	.eeprom_write16  = &ath5k_eeprom_write16,
	.eeprom_patch11n = NULL,
	.eeprom_parse    = NULL,
	.pdata			 = NULL
};


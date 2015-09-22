/*
****************************************************************************
*
* iwleeprom - EEPROM reader/writer for intel wifi cards.
* Copyright (C) 2010, Alexander "ittrium" Kalinichenko <alexander@kalinichenko.org>
* ICQ: 152322, Skype: ittr1um		
* Copyright (C) 2010, Gennady "ShultZ" Kozlov <qpxtool@mail.ru>
*
* 
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
****************************************************************************
*/

#ifndef iwleeprom_h_included
#define iwleeprom_h_included

#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>

#if BYTE_ORDER == BIG_ENDIAN
#define cpu2le16(x) __bswap_16(x)
#define cpu2be16(x) x
#define le2cpu16(x) __bswap_16(x)
#define be2cpu16(x) x
#elif BYTE_ORDER == LITTLE_ENDIAN
#define cpu2le16(x) x
#define cpu2be16(x) __bswap_16(x)
#define le2cpu16(x) x
#define be2cpu16(x) __bswap_16(x)
#else
#error Unsupported BYTE_ORDER!
#endif

/* PCI R/W macros */
#define PCI_IN32(a)    (*((volatile uint32_t *)(dev->mem + (a))))
#define PCI_IN16(a)    (*((volatile uint16_t *)(dev->mem + (a))))
#define PCI_OUT32(a,v) (*((volatile uint32_t *)(dev->mem + (a))) = (v))
#define PCI_OUT16(a,v) (*((volatile uint16_t *)(dev->mem + (a))) = (v))

struct pcidev
{
	unsigned int class,
				ven,  dev,
				sven, sdev;
	int 			idx;
	char			*device;

	struct io_driver *ops;
	unsigned char   *mem;
	bool 			eeprom_locked;
	char			*forced_driver;
};

struct pci_id
{
	unsigned int	ven, dev;
	char name[64];
};

enum byte_order
{
	order_unknown = 0,
	order_be,
	order_le
};

extern unsigned int  debug;
#define EEPROM_SIZE_MAX  0x4000

extern bool preserve_mac;
extern bool preserve_calib;

extern bool buf_read16(struct pcidev* dev, uint32_t addr, uint16_t *value);
extern bool buf_write16(struct pcidev* dev, uint32_t addr, uint16_t value);

struct io_driver {
	const char		*name;
	const struct pci_id *valid_ids;
	uint32_t		mmap_size;
	uint32_t		eeprom_size;
	uint16_t		eeprom_signature;
	bool			eeprom_writable;

	bool (*init_device)(struct pcidev *dev);
	bool (*eeprom_init)(struct pcidev *dev);
	bool (*eeprom_check)(struct pcidev *dev);
	bool (*eeprom_lock)(struct pcidev *dev);
	bool (*eeprom_release)(struct pcidev *dev);
	bool (*eeprom_read16)(struct pcidev *dev, uint32_t addr, uint16_t *value);
	bool (*eeprom_write16)(struct pcidev *dev, uint32_t addr, uint16_t value);

	void (*eeprom_patch11n)(struct pcidev *dev);
	void (*eeprom_parse)(struct pcidev *dev);
	void			*pdata;
};

#endif


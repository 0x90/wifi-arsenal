/*
 * Copyright (c) 2012 Qualcomm Atheros, Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef EDUMP_H
#define EDUMP_H

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <byteswap.h>
#include <argp.h>
#include <pciaccess.h>

#include "eep_common.h"
#include "eep_def.h"
#include "eep_4k.h"
#include "eep_9287.h"
#include "eep_9003.h"

#if __BYTE_ORDER == __BIG_ENDIAN
#define REG_READ(_reg) \
	bswap_32(*((volatile uint32_t *)(edump->io_map + (_reg))))
#else
#define REG_READ(_reg) \
	(*((volatile uint32_t *)(edump->io_map + (_reg))))
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define MS(_v, _f)  (((_v) & _f) >> _f##_S)

enum {
	false = 0,
	true = 1
};

typedef int bool;

#define ATHEROS_VENDOR_ID       0x168c
#define AR5416_DEVID_PCI        0x0023
#define AR5416_DEVID_PCIE       0x0024
#define AR9160_DEVID_PCI        0x0027
#define AR9280_DEVID_PCI        0x0029
#define AR9280_DEVID_PCIE       0x002a
#define AR9285_DEVID_PCIE       0x002b
#define AR9287_DEVID_PCI        0x002d
#define AR9287_DEVID_PCIE       0x002e
#define AR9300_DEVID_PCIE       0x0030
#define AR9485_DEVID_PCIE       0x0032
#define AR9580_DEVID_PCIE       0x0033
#define AR9462_DEVID_PCIE       0x0034
#define AR9565_DEVID_PCIE       0x0036
#define AR1111_DEVID_PCIE       0x0037

#define AR_SREV                 0x4020
#define AR_SREV_ID              0x000000FF
#define AR_SREV_VERSION         0x000000F0
#define AR_SREV_VERSION_S       4
#define AR_SREV_REVISION        0x00000007
#define AR_SREV_VERSION2        0xFFFC0000
#define AR_SREV_VERSION2_S      18
#define AR_SREV_TYPE2           0x0003F000
#define AR_SREV_TYPE2_S         12
#define AR_SREV_REVISION2       0x00000F00
#define AR_SREV_REVISION2_S     8

#define AR_SREV_VERSION_5416_PCI        0xD
#define AR_SREV_VERSION_5416_PCIE       0xC
#define AR_SREV_VERSION_9160            0x40
#define AR_SREV_VERSION_9280            0x80
#define AR_SREV_VERSION_9285            0xC0
#define AR_SREV_VERSION_9287            0x180
#define AR_SREV_VERSION_9300            0x1c0
#define AR_SREV_VERSION_9330            0x200
#define AR_SREV_VERSION_9485            0x240
#define AR_SREV_VERSION_9462            0x280
#define AR_SREV_VERSION_9565            0x2c0
#define AR_SREV_VERSION_9340            0x300
#define AR_SREV_VERSION_9550            0x400

#define AR_SREV_9280_20_OR_LATER(edump) \
	(((edump)->macVersion >= AR_SREV_VERSION_9280))
#define AR_SREV_9285(_ah) \
	(((edump)->macVersion == AR_SREV_VERSION_9285))
#define AR_SREV_9287(_ah) \
	(((edump)->macVersion == AR_SREV_VERSION_9287))
#define AR_SREV_9300_20_OR_LATER(edump) \
	(((edump)->macVersion >= AR_SREV_VERSION_9300))
#define AR_SREV_9485(edump) \
	(((edump)->macVersion == AR_SREV_VERSION_9485))
#define AR_SREV_9330(edump) \
	(((edump)->macVersion == AR_SREV_VERSION_9330))
#define AR_SREV_9340(edump) \
	(((edump)->macVersion == AR_SREV_VERSION_9340))
#define AR_SREV_9462(edump) \
	(((edump)->macVersion == AR_SREV_VERSION_9462))
#define AR_SREV_9550(edump) \
	(((edump)->macVersion == AR_SREV_VERSION_9550))
#define AR_SREV_9565(edump) \
	(((edump)->macVersion == AR_SREV_VERSION_9565))

#define AH_WAIT_TIMEOUT 100000 /* (us) */
#define AH_TIME_QUANTUM 10

enum dump_data {
	DUMP_BASE_HEADER = 1,
	DUMP_MODAL_HEADER = 2,
	DUMP_POWER_INFO = 3,
	DUMP_ALL = 4
};

struct edump {
	struct pci_device *pdev;
	pciaddr_t base_addr;
	pciaddr_t size;
	void *io_map;

	uint32_t macVersion;
	uint16_t macRev;

	struct eeprom_ops *eep_ops;
	enum eep_map eep_map;

	union {
		struct ar5416_eeprom_def def;
		struct ar5416_eeprom_4k map4k;
		struct ar9287_eeprom map9287;
		struct ar9300_eeprom eep_93k;
	} eeprom;
};

struct eeprom_ops {
	bool (*fill_eeprom)(struct edump *edump);
	int (*check_eeprom)(struct edump *edump);
	int (*get_eeprom_ver)(struct edump *edump);
	int (*get_eeprom_rev)(struct edump *edump);
	void (*dump_base_header)(struct edump *edump);
	void (*dump_modal_header)(struct edump *edump);
	void (*dump_power_info)(struct edump *edump);
};

extern struct eeprom_ops eep_def_ops;
extern struct eeprom_ops eep_4k_ops;
extern struct eeprom_ops eep_9287_ops;
extern struct eeprom_ops eep_9003_ops;

bool pci_eeprom_read(struct edump *edump, uint32_t off, uint16_t *data);
bool hw_wait(struct edump *edump, uint32_t reg, uint32_t mask,
	     uint32_t val, uint32_t timeout);

#endif /* EDUMP_H */

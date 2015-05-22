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

#include "edump.h"

const char *argp_program_version = PACKAGE_VERSION;
const char *argp_program_bug_address = PACKAGE_BUGREPORT;

int dump;

static struct argp_option argp_cmd_options[] = {
	{"base", 'b', 0, 0, "Dump base header", 0},
	{"modal", 'm', 0, 0, "Dump modal header", 0},
	{"power", 'p', 0, 0, "Dump power calibration info", 0},
	{"all", 'a', 0, 0, "Dump everything", 0},
	{ 0 }
};

static error_t argp_parser(int key, char *arg, struct argp_state *state)
{
	switch(key) {
	case 'b':
		dump = DUMP_BASE_HEADER;
		break;
	case 'm':
		dump = DUMP_MODAL_HEADER;
		break;
	case 'p':
		dump = DUMP_POWER_INFO;
		break;
	case 'a':
		dump = DUMP_ALL;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static struct argp argp = {argp_cmd_options, argp_parser};

static struct pci_id_match pci_id[] = {
	{ATHEROS_VENDOR_ID, PCI_MATCH_ANY, PCI_MATCH_ANY, PCI_MATCH_ANY},
	{ 0 }
};

static struct {
	uint32_t version;
	const char * name;
} mac_bb_names[] = {
	/* Devices with external radios */
	{ AR_SREV_VERSION_5416_PCI,	"5416" },
	{ AR_SREV_VERSION_5416_PCIE,	"5418" },
	{ AR_SREV_VERSION_9160,		"9160" },
	/* Single-chip solutions */
	{ AR_SREV_VERSION_9280,		"9280" },
	{ AR_SREV_VERSION_9285,		"9285" },
	{ AR_SREV_VERSION_9287,         "9287" },
	{ AR_SREV_VERSION_9300,         "9300" },
	{ AR_SREV_VERSION_9330,         "9330" },
	{ AR_SREV_VERSION_9485,         "9485" },
	{ AR_SREV_VERSION_9462,         "9462" },
	{ AR_SREV_VERSION_9565,         "9565" },
	{ AR_SREV_VERSION_9340,         "9340" },
	{ AR_SREV_VERSION_9550,         "9550" },
};

static const char *
mac_bb_name(uint32_t mac_bb_version)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(mac_bb_names); i++) {
		if (mac_bb_names[i].version == mac_bb_version) {
			return mac_bb_names[i].name;
		}
	}

	return "????";
}

static int is_supported_chipset(struct pci_device *pdev)
{
	if (pdev->vendor_id != ATHEROS_VENDOR_ID)
		return 0;

	if ((pdev->device_id != AR5416_DEVID_PCI) &&
	    (pdev->device_id != AR5416_DEVID_PCIE) &&
	    (pdev->device_id != AR9160_DEVID_PCI) &&
	    (pdev->device_id != AR9280_DEVID_PCI) &&
	    (pdev->device_id != AR9280_DEVID_PCIE) &&
	    (pdev->device_id != AR9285_DEVID_PCIE) &&
	    (pdev->device_id != AR9287_DEVID_PCI) &&
	    (pdev->device_id != AR9287_DEVID_PCIE) &&
	    (pdev->device_id != AR9300_DEVID_PCIE) &&
	    (pdev->device_id != AR9485_DEVID_PCIE) &&
	    (pdev->device_id != AR9580_DEVID_PCIE) &&
	    (pdev->device_id != AR9462_DEVID_PCIE) &&
	    (pdev->device_id != AR9565_DEVID_PCIE) &&
	    (pdev->device_id != AR1111_DEVID_PCIE)) {
		fprintf(stderr, "Device ID: 0x%x not supported\n", pdev->device_id);
		return 0;
	}

	printf("Found Device ID: 0x%04x\n", pdev->device_id);
	return 1;
}

static struct edump* init_pci_device(struct pci_device *pdev)
{
	int err;
	struct edump *edump;

	if (!pdev->regions[0].base_addr) {
		fprintf(stderr, "Invalid base address\n");
		return NULL;
	}

	edump = malloc(sizeof(struct edump));
	if (edump == NULL) {
		fprintf(stderr, "Unable to alloc memory for edump\n");
		return NULL;
	}

	memset(edump, 0, sizeof(struct edump));

	edump->pdev = pdev;
	edump->base_addr = pdev->regions[0].base_addr;
	edump->size = pdev->regions[0].size;
	pdev->user_data = (intptr_t)edump;

	if ((err = pci_device_map_range(pdev, edump->base_addr, edump->size,
					0, &edump->io_map)) != 0) {
		fprintf(stderr, "%s\n", strerror(err));
		goto map_fail;
	}

	printf("Mapped IO region at: %p\n", edump->io_map);
	return edump;

map_fail:
	free(edump);
	return NULL;
}

static void cleanup_pci_device(struct edump *edump)
{
	int err;

	printf("\nFreeing Mapped IO region at: %p\n", edump->io_map);

	if ((err = pci_device_unmap_range(edump->pdev, edump->io_map,
					  edump->size)) != 0)
		fprintf(stderr, "%s\n", strerror(err));

	free(edump);
}

static void hw_read_revisions(struct edump *edump)
{
	uint32_t val;

	val = REG_READ(AR_SREV) & AR_SREV_ID;

	if (val == 0xFF) {
		val = REG_READ(AR_SREV);
		edump->macVersion = (val & AR_SREV_VERSION2) >> AR_SREV_TYPE2_S;
		edump->macRev = MS(val, AR_SREV_REVISION2);
	} else {
		edump->macVersion = MS(val, AR_SREV_VERSION);
		edump->macRev = val & AR_SREV_REVISION;
	}

	printf("Atheros AR%s MAC/BB Rev:%x\n",
	       mac_bb_name(edump->macVersion), edump->macRev);
}

bool hw_wait(struct edump *edump, uint32_t reg, uint32_t mask,
	     uint32_t val, uint32_t timeout)
{
	int i;

	for (i = 0; i < (timeout / AH_TIME_QUANTUM); i++) {
		if ((REG_READ(reg) & mask) == val)
			return true;

		usleep(AH_TIME_QUANTUM);
	}

	return false;
}

bool pci_eeprom_read(struct edump *edump, uint32_t off, uint16_t *data)
{
	(void)REG_READ(AR5416_EEPROM_OFFSET + (off << AR5416_EEPROM_S));

	if (!hw_wait(edump,
		     AR_EEPROM_STATUS_DATA,
		     AR_EEPROM_STATUS_DATA_BUSY |
		     AR_EEPROM_STATUS_DATA_PROT_ACCESS, 0,
		     AH_WAIT_TIMEOUT)) {
		return false;
	}

	*data = MS(REG_READ(AR_EEPROM_STATUS_DATA),
		   AR_EEPROM_STATUS_DATA_VAL);

	return true;
}

int register_eep_ops(struct edump *edump)
{
	if (AR_SREV_9300_20_OR_LATER(edump)) {
		edump->eep_map = EEP_MAP_9003;
		edump->eep_ops = &eep_9003_ops;
	} else if (AR_SREV_9287(edump)) {
		edump->eep_map = EEP_MAP_9287;
		edump->eep_ops = &eep_9287_ops;
	} else if (AR_SREV_9285(edump)) {
		edump->eep_map = EEP_MAP_4K;
		edump->eep_ops = &eep_4k_ops;
	} else {
		edump->eep_map = EEP_MAP_DEFAULT;
		edump->eep_ops = &eep_def_ops;
	}

	if (!edump->eep_ops->fill_eeprom(edump)) {
		fprintf(stderr, "Unable to fill EEPROM data\n");
		return -1;
	}

	if (!edump->eep_ops->check_eeprom(edump)) {
		fprintf(stderr, "EEPROM check failed\n");
		return -1;
	}

	return 0;
}

void dump_device(struct edump *edump)
{
	hw_read_revisions(edump);

	if (register_eep_ops(edump) < 0)
		return;

	switch(dump) {
	case DUMP_BASE_HEADER:
		edump->eep_ops->dump_base_header(edump);
		break;
	case DUMP_MODAL_HEADER:
		edump->eep_ops->dump_modal_header(edump);
		break;
	case DUMP_POWER_INFO:
		edump->eep_ops->dump_power_info(edump);
		break;
	case DUMP_ALL:
		edump->eep_ops->dump_base_header(edump);
		edump->eep_ops->dump_modal_header(edump);
		edump->eep_ops->dump_power_info(edump);
		break;
	}
}

int main(int argc, char *argv[])
{
	struct edump *edump;
	struct pci_device_iterator *iter;
	struct pci_device *pdev;
	int ret = 0, cnt = 0;;

	dump = DUMP_ALL;

	if (argp_parse(&argp, argc, argv, 0, 0, NULL) != 0)
		return -EINVAL;

	if ((ret = pci_system_init()) != 0) {
		fprintf(stderr, "%s\n", strerror(ret));
		return ret;
	} else {
		printf("Initializing PCI\n");
	}

	iter = pci_id_match_iterator_create(pci_id);
	if (iter == NULL) {
		ret = -EINVAL;
		fprintf(stderr, "Iter creation failed\n");
		goto iter_fail;
	}

	while((pdev = pci_device_next(iter)) != NULL) {
		if ((ret = pci_device_probe(pdev)) != 0) {
			fprintf(stderr, "%s\n", strerror(ret));
			continue;
		}

		if (!is_supported_chipset(pdev))
			continue;

		edump = init_pci_device(pdev);
		if (edump == NULL)
			continue;

		cnt++;
		dump_device(edump);
		cleanup_pci_device(edump);
	}

	if (!cnt)
		printf("No supported card found\n");

	pci_iterator_destroy(iter);

iter_fail:
	pci_system_cleanup();
	return ret;
}

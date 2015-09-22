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

#define _GNU_SOURCE

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <dirent.h>
#include <getopt.h>

//#define DEBUG

#include "iwlio.h"
#include "ath5kio.h"
#include "ath9kio.h"

static struct option long_options[] = {
	{"device",    1, NULL, 'd'},
	{"nodev",     0, NULL, 'n'},
	{"preserve-mac", 0, NULL, 'm'},
	{"preserve-calib", 0, NULL, 'c'},
	{"read",      0, NULL, 'r'},
	{"write",     0, NULL, 'w'},
	{"ifile",     1, NULL, 'i'},
	{"ofile",     1, NULL, 'o'},
	{"bigendian", 0, NULL, 'b'},
	{"help",      0, NULL, 'h'},
	{"list",      0, NULL, 'l'},
	{"drivers",   0, NULL, 'L'},
	{"driver",    1, NULL, 'F'},
	{"debug",     1, NULL, 'D'},
	{"show",      0, NULL, 's'},
	{"init",      0, NULL, 'I'},
	{"patch11n",  0, NULL, 'p'}
};

int mem_fd;
unsigned int offset;
bool eeprom_locked;
enum byte_order dump_order;
uid_t ruid,euid,suid;

void die(  const char* format, ... ); 

char	*ifname = NULL,
		*ofname = NULL;
bool patch11n = false,
	 init_device = false,
	 parse = false,
	 nodev = false,
	 preserve_mac = false,
	 preserve_calib = false;

unsigned int  debug = 0;

uint16_t buf[EEPROM_SIZE_MAX/2];

struct pcidev dev;

#define DEVICES_PATH "/sys/bus/pci/devices"

static struct io_driver *iodrivers[] = {
	&io_iwl4965,
	&io_iwl5k,
	&io_iwl6k,
	&io_ath5k,
	&io_ath9k,
	&io_ath9300,
	NULL
};

void init_card()
{
	if ((mem_fd = open("/dev/mem", O_RDWR | O_SYNC)) < 0) {
		printf("cannot open /dev/mem\n");
		exit(1);
	}

	dev.mem = (unsigned char *)mmap(NULL, dev.ops->mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, mem_fd, offset);
	if (dev.mem == MAP_FAILED) {
		perror("mmap failed");
		exit(1);
	}
}

void release_card()
{
	if (dev.mem != NULL)
		munmap(dev.mem, dev.ops->mmap_size);
}

void init_dump(struct pcidev *dev, char *filename)
{
	FILE *fd;
	uint32_t eeprom_size;
	int d;

	seteuid(ruid);
	if (!(fd = fopen(filename, "rb")))
		die("Can't read file '%s'\n", filename);
	eeprom_size = 2 * fread(buf, 2, EEPROM_SIZE_MAX/2, fd);
	fclose(fd);
	seteuid(suid);

	for(d=0; !dev->ops && iodrivers[d]; d++) {
		if (dev->forced_driver) {
			if(!strcmp(dev->forced_driver, iodrivers[d]->name)) {
				dev->ops = iodrivers[d];
			}
		} else {
			if ( iodrivers[d]->eeprom_signature == le2cpu16(*(uint16_t*)buf)) {
				dump_order = order_le;
				dev->ops = iodrivers[d];
			} else if ( iodrivers[d]->eeprom_signature == be2cpu16(*(uint16_t*)buf)) {
				dump_order = order_be;
				dev->ops = iodrivers[d];
			}
		}
	}

	if (!dev->ops)
		die("No usable IO driver found for this dump!\n");

	printf(" Using IO driver%s: %s\n", dev->forced_driver ? " (forced)":"" ,dev->ops->name);
	dev->ops->eeprom_size    = eeprom_size;
	dev->ops->eeprom_read16  = &buf_read16;
	dev->ops->eeprom_write16 = &buf_write16;


	printf("  byte order: %s ENDIAN\n", (dump_order == order_le) ? "LITTLE":"BIG");
}

void fixate_dump(struct pcidev *dev, char *filename)
{
	FILE *fd;
	seteuid(ruid);

	if (!(fd = fopen(filename, "wb")))
		die("Can't create file '%s'\n", filename);
	fwrite(buf, dev->ops->eeprom_size, 1, fd);
	printf("Dump file written: '%s'\n", filename);
	fclose(fd);

	seteuid(suid);
}

bool buf_read16(struct pcidev* dev, uint32_t addr, uint16_t *value)
{
	if (addr >= EEPROM_SIZE_MAX) return 0;
	if (dump_order == order_le)
		*value = le2cpu16(buf[addr >> 1]);	
	else
		*value = be2cpu16(buf[addr >> 1]);
	return true;
}

bool buf_write16(struct pcidev* dev, uint32_t addr, uint16_t value)
{
	if (addr >= EEPROM_SIZE_MAX) return false;
	if (dump_order == order_le)
		buf[addr >> 1] = cpu2le16(value);
	else
		buf[addr >> 1] = cpu2be16(value);
	return true;
}

void eeprom_read(char *filename)
{
	uint32_t addr = 0;
	uint16_t data;
	FILE *fd;
	
	printf("Saving dump with byte order: %s ENDIAN\n", (dump_order == order_le) ? "LITTLE":"BIG");

	for (addr = 0; addr < dev.ops->eeprom_size; addr += 2)
	{
		if (!dev.ops->eeprom_read16(&dev, addr, &data)) return;
		buf_write16(&dev, addr, data);

		if (0 ==(addr & 0x7F)) printf("%04x [", addr);
		printf("x");
		if (0x7E ==(addr & 0x7F)) printf("]\n");
		fflush(stdout);
	}

	seteuid(ruid);
	if (!(fd = fopen(filename, "wb")))
		die("Can't create file '%s'\n", filename);
	fwrite(buf, dev.ops->eeprom_size, 1, fd);
	fclose(fd);
	seteuid(suid);

	printf("\nEEPROM has been dumped to '%s'\n", filename);
}

void eeprom_write(char *filename)
{
	unsigned int addr = 0;
	enum byte_order order = order_unknown;
	uint16_t value;
	uint16_t evalue;
	size_t   size;
	FILE *fd;
	char c;

	seteuid(ruid);
	if (!(fd = fopen(filename, "rb")))
		die("Can't read file '%s'\n", filename);
	size = 2 * fread(buf, 2, dev.ops->eeprom_size/2, fd);
	fclose(fd);
	seteuid(suid);

	printf("About to write device EEPROM, press 'Y' if you are sure... ");
	scanf("\n%c", &c);
	if ('Y' != c) return;

	printf("Writing data to EEPROM...\n  '.' = match, 'x' = write\n");
	for(addr=0; addr<size;addr+=2)
	{
		if (order == order_unknown) {
			if ( buf[addr/2] && dev.ops->eeprom_signature == le2cpu16(buf[addr/2]) ) {
				order = order_le;
			} else if ( buf[addr/2] && dev.ops->eeprom_signature == be2cpu16(buf[addr/2]) ) {
				order = order_be;
			} else {
				die("Invalid EEPROM signature!\n");
			}
			printf("Dump file byte order: %s ENDIAN\n", (order == order_le) ? "LITTLE":"BIG");
		}
		if (order == order_be)
			value = be2cpu16( buf[addr/2] );
		else
			value = le2cpu16( buf[addr/2] );
		if (!dev.ops->eeprom_read16(&dev, addr, &evalue)) return;

		if (0 ==(addr & 0x7F)) printf("%04x [", addr);
		if (evalue != value) {
			dev.ops->eeprom_write16(&dev, addr, value);
			printf("x");
		} else {
			printf(".");
		}
		if (0x7E ==(addr & 0x7F)) printf("]\n");
		fflush(stdout);
	}

	printf("\nEEPROM has been written from '%s'\n", filename);
}

void die(  const char* format, ... ) {
	va_list args;
	fprintf(stderr, "\n\E[31;60m");
	va_start( args, format );
	vfprintf( stderr, format, args );
	va_end( args );
	fprintf(stderr, "\E[0m");

	release_card();
	exit(1);
}

unsigned int read_id(const char *device, const char* param)
{
	FILE *f;
	unsigned int id;
	char path[512];
	sprintf(path, DEVICES_PATH "/%s/%s", device, param);
	if (!(f = fopen(path, "r")))
		return 0;
	fscanf(f,"%x", &id);
	fclose(f);
	return id;
}

void check_device(struct pcidev *id)
{
	int d,i;

	id->idx = -1;
	id->class = (read_id(id->device,"class") >> 8);
	if (!id->class) {
		printf("No such PCI device: %s\n", id->device);
	}
	id->ven   = read_id(id->device,"vendor");
	id->dev   = read_id(id->device,"device");
	id->sven  = read_id(id->device,"subsystem_vendor");
	id->sdev  = read_id(id->device,"subsystem_device");

// look for IO driver for this device

	for(d=0; iodrivers[d]; d++) {
		for(i=0; id->idx<0 && iodrivers[d]->valid_ids[i].ven; i++)
			if(id->ven==iodrivers[d]->valid_ids[i].ven && id->dev==iodrivers[d]->valid_ids[i].dev) {
				id->idx = i;
				id->ops = iodrivers[d];
			}
	}
}

void list_supported(bool show_devices)
{
	int d,i;
	printf("Available IO drivers:\n");

	for(d=0; iodrivers[d]; d++) {
		printf("-> IO driver: %s, %s\n",
				iodrivers[d]->name,
				iodrivers[d]->eeprom_writable ? "RW" : "RO");

		if (show_devices) {
			for(i=0; iodrivers[d]->valid_ids[i].ven; i++)
				printf("  [%04x:%04x]  %s\n",
					iodrivers[d]->valid_ids[i].ven,
					iodrivers[d]->valid_ids[i].dev,
					iodrivers[d]->valid_ids[i].name);
			printf("\n");
		}
	}
}

void map_device()
{
	FILE *f;
	char path[512];
	unsigned char data[64];
	int i;
	unsigned int addr;
	sprintf(path, DEVICES_PATH "/%s/%s", dev.device, "config");
	if (!(f = fopen(path, "r")))
		return;
	fread(data, 64, 1, f);
	fclose(f);

	for (i=0x10; !offset && i<0x28;i+=4) {
		addr = ((unsigned int*)data)[i/4];
		if ((addr & 0xF) == 4)
			offset = addr & 0xFFFFFFF0;
	}
}

void search_card()
{
	DIR  *dir;
	struct dirent *dentry;
	struct pcidev id;
	struct pcidev *ids = NULL;
	int i,cnt=0;

	dir = opendir(DEVICES_PATH);
	if (!dir)
		die("Can't list PCI devices\n");
	if (debug)
		printf("PCI devices:\n");
	id.device = (char*) malloc(256 * sizeof(char));
	do {
		dentry = readdir(dir);
		if (!dentry || !strncmp(dentry->d_name, ".", 1))
			continue;

		strcpy(id.device, dentry->d_name);
		check_device(&id);
		if (debug) {
			printf("    %s: class %04x   id %04x:%04x   subid %04x:%04x",
				id.device,
				id.class,
				id.ven,  id.dev,
				id.sven, id.sdev
			);
			if (id.idx < 0)
				printf("\n");
			else
				printf(" [%s, %s] %s \n", 
					id.ops->eeprom_writable ? "RW" : "RO",
					id.ops->name,
					id.ops->valid_ids[id.idx].name);
		}
		if (id.idx >=0 ) {
			if(!cnt)
				ids = (struct pcidev*) malloc(sizeof(id));
			else
				ids = (struct pcidev*) realloc(ids, (cnt+1)*sizeof(id));
			ids[cnt].device = (char*) malloc(256 * sizeof(char));
			ids[cnt].class = id.class;
			ids[cnt].ven = id.ven; ids[cnt].sven = id.sven;
			ids[cnt].dev = id.dev; ids[cnt].sdev = id.sdev;
			ids[cnt].idx = id.idx;
			ids[cnt].ops = id.ops;
			memcpy(ids[cnt].device, id.device, 256);
			cnt++;
		}
	}
	while (dentry);
	printf("Supported devices detected: %s\n", cnt ? "" : "\n  NONE");
	if (!cnt) goto nodev;

	for (i=0; i<cnt; i++) {
		printf("  [%d] %s [%s] %s (%04x:%04x, %04x:%04x)\n", i+1,
			ids[i].device,
			ids[i].ops->eeprom_writable ? "RW" : "RO",
			ids[i].ops->valid_ids[ids[i].idx].name,
			ids[i].ven,  ids[i].dev,
			ids[i].sven, ids[i].sdev);
	}
	i++;
	while(i<=0 || i>cnt) {
		if (!i)	goto out;
		printf("Select device [1-%d] (or 0 to quit): ", cnt);
		scanf("%d", &i);
	}
	i--;
	dev.device = (char*) malloc(256 * sizeof(char));
	memcpy(dev.device, ids[i].device, 256);

out:
	free(id.device);
	for (i=0; i<cnt; i++) free(ids[i].device);
	free(ids);
	return;
nodev:
	free(id.device);
	exit(1);
}

int main(int argc, char** argv)
{
	char c;
	dev.device = NULL;
	dev.mem    = NULL;
	dev.ops    = NULL;
	dev.forced_driver = NULL;
	dump_order = order_le;
	getresuid(&ruid, &euid, &suid);

	while (1) {
		c = getopt_long(argc, argv, "rwlLF:d:mcni:o:bhpsID:", long_options, NULL);
		if (c == -1)
			break;
		switch(c) {
			case 'l':
				list_supported(true);
				exit(0);
			case 'L':
				list_supported(false);
				exit(0);
			case 'F':
				printf("Forced driver name: %s\n", optarg);
				dev.forced_driver = optarg;
				break;
			case 'd':
				dev.device = optarg;
				break;
			case 'n':
				nodev = true;
				break;
			case 'm':
				preserve_mac = true;
				break;
			case 'c':
				preserve_calib = true;
				break;
			case 'r':
				die("option -r deprecated. use -o instead\n");
				break;
			case 'o':
				ofname = optarg;
				break;
			case 'w':
				die("option -w deprecated. use -i instead\n");
				break;
			case 'i':
				ifname = optarg;
				break;
			case 'b':
				dump_order = order_be;
				break;
			case 's':
				parse = true;
				break;
			case 'p':
				patch11n = true;
				break;
			case 'I':
				init_device = true;
				break;
			case 'D':
				debug = atoi(optarg);
				if (debug)
					printf("debug level: %s\n", optarg);
				break;
			case 'h':
				die("EEPROM reader/writer for intel wifi cards\n\n"
					"Usage:\n"
					"\t%s [-d device [-m] [-c] | -n] [-I] [-i filename ] [-o filename [-b] ] [-P] [-p] [-D debug_level]\n"
					"\t%s -l\n"
					"\t%s -h\n\n"
					"Options:\n"
					"\t-d <device> | --device <device>\t\t"
					"device in format 0000:00:00.0 (domain:bus:dev.func)\n"
					"\t-n | --nodev\t\t\t\t"
					"don't touch any device, file-only operations\n"
					"\t-m | --preserve-mac\t\t\t"
					"don't change card's MAC while writing full eeprom dump\n"
					"\t-c | --preserve-calib\t\t\t"
					"don't change calibration data while writing full eeprom dump\n"
					"\t\t\t\t\t\t(not supported by ath9k)\n"
					"\t-o <filename> | --ofile <filename>\t"
					"dump eeprom to binary file\n"
					"\t-i <filename> | --ifile <filename>\t"
					"write eeprom from binary file\n"
					"\t-b | --bigendian\t\t\t"
					"save dump in big-endian byteorder (default: little-endian)\n"
					"\t-p | --patch11n\t\t\t\t"
					"patch device eeprom to enable 802.11n\n"
					"\t-I | --init\t\t\t\t"
					"init device (useful if driver didn't it)\n"
					"\t-s | --show\t\t\t\t"
					"show available modes/channels\n"
					"\t-l | --list\t\t\t\t"
					"list known cards\n"
					"\t-L | --drivers\t\t\t\t"
					"list available IO drivers\n"
					"\t-F | --driver <driver_name>\t\t"
					"force using specified IO driver (nodev mode only)\n"
					"\t-D <level> | --debug <level>\t\t"
					"set debug level (0-1, default 0)\n"
					"\t-h | --help\t\t\t\t"
					"show this info\n", argv[0], argv[0], argv[0]);
			default:
				return 1;
		}
	}

	if (nodev) goto _nodev;

	if (!dev.device) search_card();
	if (!dev.device) exit(1);
	check_device(&dev);

	if (!dev.class)	exit(2);
	if (dev.idx < 0)
		die("Selected device not supported\n");

	printf("Using device %s [%s] %s \n",
		dev.device,
		dev.ops->eeprom_writable ? "RW" : "RO",
		dev.ops->valid_ids[dev.idx].name);
	printf("IO driver: %s\n",
		dev.ops->name);

	if (debug)
		printf("Supported ops: %s%s%s%s\n",
			dev.ops->eeprom_read16 ? " read" : "",
			(dev.ops->eeprom_writable && dev.ops->eeprom_write16)  ? " write" : "",
			dev.ops->eeprom_parse ? " parse" : "",
			dev.ops->eeprom_patch11n ? " patch11n" : ""
		);

	map_device();

	if (!offset)
		die("Can't obtain memory address\n");

	if (debug)
		printf("address: %08x\n", offset);

	if(!ifname && !ofname && !patch11n && !parse)
		printf("No file names given nor actions selected!\nNo EEPROM actions will be performed, just write-enable test\n");

	init_card();

	if (init_device && dev.ops->init_device && !dev.ops->init_device(&dev))
		die("Device init failed!\n");

	if (dev.ops->eeprom_init && !dev.ops->eeprom_init(&dev))
		die("Basic eeprom init failed!\n");

	if (dev.ops->eeprom_check && !dev.ops->eeprom_check(&dev))
		die("eeprom check failed!\n");

	if (dev.ops->eeprom_lock && !dev.ops->eeprom_lock(&dev))
		die("Failed to lock eeprom!\n");

	if (ofname)
		eeprom_read(ofname);

	if (parse && dev.ops->eeprom_parse)
		dev.ops->eeprom_parse(&dev);

	if (ifname && dev.ops->eeprom_writable)
		eeprom_write(ifname);

	if (patch11n && dev.ops->eeprom_writable)
		dev.ops->eeprom_patch11n(&dev);

	if (parse && dev.ops->eeprom_parse && (ifname || patch11n)) {
		printf("\n\ndevice capabilities after eeprom writing:\n");
		dev.ops->eeprom_parse(&dev);
	}

	if (dev.ops->eeprom_release && !dev.ops->eeprom_release(&dev))
		die("Failed to unlock eeprom!\n");

	release_card();
	return 0;

_nodev:
	if (dev.device)
		die("Don't use '-d' and '-n' options simultaneously\n");

	printf("Device-less operation...\n");

	if (!ifname)
		die("No input file given!\n");
	if (patch11n && !ofname)
		die("Have to specify output file for 802.11n patch!\n");
	init_dump(&dev, ifname);

	if (dev.ops->eeprom_init && !dev.ops->eeprom_init(&dev))
		die("Basic eeprom init failed!\n");

	if (dev.ops->eeprom_check)
		dev.ops->eeprom_check(&dev);

	if (parse && dev.ops && dev.ops->eeprom_parse)
		dev.ops->eeprom_parse(&dev);

	if (patch11n && dev.ops && dev.ops->eeprom_patch11n)
		dev.ops->eeprom_patch11n(&dev);

	if (ofname)
		fixate_dump(&dev, ofname);
	
	if (dev.ops->eeprom_release)
		dev.ops->eeprom_release(&dev);
	return 0;
}


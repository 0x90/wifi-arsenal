/**
	ath9k_caldata tools.
	@author: Álvaro Fernández Rojas <noltari@gmail.com>
*/

#ifndef ATH9K_CALDATA_H
#define ATH9K_CALDATA_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>

#define ERROR_NO			0
#define ERROR_ARGS			1
#define ERROR_OPTS			2
#define ERROR_FILE			3
#define ERROR_MEM			4
#define ERROR_RED			5
#define ERROR_WRT			6
#define ERROR_CDO			7
#define ERROR_CDR			8
#define ERROR_CDW			9

#define ATH9K_EEPROM_SIZE	2048
#define ATH9K_EEPROM_MAGIC	0xA55A

#define ATH9K_CALDATA_SIZE	6
uint8_t caldata_magic[ATH9K_CALDATA_SIZE] = {0xa5, 0x5a, 0, 0, 0, 0x03};

#define ATH9K_MAGC_OFF	0
#define ATH9K_CLEN_OFF	(0x200 >> 1)
#define ATH9K_CSUM_OFF	(0x202 >> 1)
#define ATH9K_AFTR_OFF	(0x204 >> 1)
#define ATH9K_REGD_OFF	(0x208 >> 1)
#define ATH9K_CAPS_OFF	(0x20A >> 1)

int ath9k_caldata_offset(uint8_t* caldata, int length, int* offset);
int ath9k_caldata_read(uint8_t* in, int in_off, uint16_t* out);
int ath9k_caldata_info(uint16_t* caldata);
int ath9k_caldata_patch(uint16_t* caldata, int patch_regd, int caldata_regd, int patch_caps, int caldata_caps);
int ath9k_caldata_write(uint16_t* in, uint8_t* out, int out_off);

#endif /* ATH9K_CALDATA_H */

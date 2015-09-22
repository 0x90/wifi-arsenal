#!/bin/bash
#

dd if=eeprom_dump.rom of=eeprom_4k.rom bs=1 count=512
dd if=padding.bin of=eeprom_4k.rom bs=1 seek=512 count=1536
dd if=eeprom_4k.rom of=eeprom_4k.rom bs=1 seek=2048 count=2048


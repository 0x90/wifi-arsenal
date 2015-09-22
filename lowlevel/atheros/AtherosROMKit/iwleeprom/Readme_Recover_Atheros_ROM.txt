To generate a full 4K Atheros ROM, place your original eeprom_dump.rom here and run ./create4krom.sh
Afterwards you will have eeprom_4k.rom, for use with the custom ath9k driver which supports ROM by placing it in C char format in romimp.c
You can also use this full 4k ROM when the card reacts again to flash it with ./iwleeprom -i eeprom_4k.rom
Reboot afterwards and your card should work fine again...


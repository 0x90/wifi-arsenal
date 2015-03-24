#!/bin/sh
#
# Created by ZigFisher  v.0.1  2012.12.30
# More info in http://blog.flyrouter.net
# Very simple and quick example to run directly on the device


NEWMAC=$1
WLANMAC=`ifconfig wifi0 | head -n 1 | awk '{print $5}' | tr 'a-z' 'A-Z'`
PERSISTENT="/etc/persistent/"
CURRDATE=`date '+%Y%m%d%H%M'`
HEXDUMP="65000"

#clear
if [ -n "$NEWMAC" ] ; then
    echo -e "Go to $PERSISTENT dir..."
    cd $PERSISTENT
    #
    echo -e "\nExtract original EEPROM from FLASH..."
    dd if=/dev/mtd5 of=EEPROM_ORIG.bin
    #
    echo -e "\nYou have $WLANMAC MAC in WLAN interface and change it to $NEWMAC "
    echo "Create new EEPROM file and write CRC..."
    fixsum EEPROM_ORIG.bin $WLANMAC $NEWMAC
    #
    echo -e "\nBackup original and new EEPROM..."
    mv EEPROM_ORIG.bin EEPROM_ORIG_$CURRDATE.bin
    mv EEPROM_NEW.bin  EEPROM_NEW_$CURRDATE.bin
    cfgmtd -w -p /etc/
    #
    #echo -e "\nDump CRC for debug of original and new EEPROMs..."
    #hexdump -C -s $HEXDUMP EEPROM_ORIG_$CURRDATE.bin
    #hexdump -C -s $HEXDUMP EEPROM_NEW_$CURRDATE.bin
    #
    echo -e "\nWarning, write new EEPROM  to FLASH and reboot..."
    mtd -r write EEPROM_NEW_$CURRDATE.bin EEPROM
else
    echo "You have $WLANMAC MAC in WLAN interface, please insert new MAC in command line"
    echo "Example: $0 00:27:22:XX:XX:XX"
    echo -e "\nEnjoy !"
fi
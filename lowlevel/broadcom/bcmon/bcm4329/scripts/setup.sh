#!/system/bin/sh
CUR_DIR=`dirname $0`
CUR_DIR=`readlink -f $CUR_DIR`
DRIVER_NAME="bcm4329"
DRIVER_FLNM="bcm4329.ko"
FW_PATH="$CUR_DIR/fw_bcm4329.bcmon.bin"

IS_BCM_LOADED=`lsmod | grep bcm4329 | wc -l`

if [ $IS_BCM_LOADED == 1 ]; then 
	IS_BCM_PATCHED=`grep "bcmon_loaded" /proc/kallsyms | wc -l`
	if [ $IS_BCM_PATCHED == 0 ]; then 
		echo Original module loaded. disabling WiFi 
		svc wifi disable
	fi
fi
echo LOADING MODULE
rmmod $DRIVER_NAME 2>/dev/null
insmod $DRIVER_FLNM firmware_path=$FW_PATH
ifconfig eth0 up

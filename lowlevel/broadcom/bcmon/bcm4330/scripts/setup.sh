#!/system/bin/sh
CUR_DIR=`dirname $0`
CUR_DIR=`readlink -f $CUR_DIR`
DRIVER_NAME="dhd"
DRIVER_FLNM="dhd.ko"
FW_PATH="$CUR_DIR/bcm4330_sta.bcmon.bin"

IS_BCM_LOADED=`lsmod | grep dhd | wc -l`

if [ $IS_BCM_LOADED == 1 ]; then 
	IS_BCM_PATCHED=`grep "bcmon_loaded" /proc/kallsyms | wc -l`
	if [ $IS_BCM_PATCHED == 0 ]; then 
		echo Original module loaded. disabling WiFi 
		svc wifi disable
	fi
fi

echo LOADING MODULE
rmmod $DRIVER_NAME 2>/dev/null
echo "Assuming firmware path: $FW_PATH"
insmod $DRIVER_FLNM iface_name=wlan0 firmware_path=$FW_PATH nvram_path=/system/etc/wifi/nvram_net.txt
ifconfig wlan0 up

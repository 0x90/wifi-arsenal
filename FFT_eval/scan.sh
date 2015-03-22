#!/bin/sh

# configure wlanX
ATH9K_IFACE=wlan0

# get phyX
PHY_NO=`iw $ATH9K_IFACE info | awk '$1 == "wiphy" {print $2}'`
ATH9K_PATH=/sys/kernel/debug/ieee80211/phy$PHY_NO/ath9k
OUT_NAME=samples_out_tmp
SCAN_CMD="iw $ATH9K_IFACE scan"

# sanity check only
if [ ! -d $ATH9K_PATH ]; then
	echo "Seems $ATH9K_IFACE doesn't exist, please compile ath9k with debugfs support"
	exit 1
fi

# you can setup output file: ./scan.sh output_file
if [ $# -eq 1 ]; then
	OUT_NAME=$1
fi

# you can setup frequency or frequency list: ./scan.sh out_file 5180 or ./scan.sh out_file "5180 5200 5220 5240"
if [ $# -eq 2 ]; then
OUT_NAME=$1
SCAN_CMD="iw $ATH9K_IFACE scan freq $2"
fi

ifconfig $ATH9K_IFACE up
echo chanscan > $ATH9K_PATH/spectral_scan_ctl
echo "Scanning: $SCAN_CMD"
$SCAN_CMD | grep freq ; echo ""
$SCAN_CMD | grep freq ; echo ""
$SCAN_CMD | grep freq ; echo ""
$SCAN_CMD | grep freq ; echo ""
$SCAN_CMD | grep freq ; echo ""
$SCAN_CMD | grep freq ; echo ""
$SCAN_CMD | grep freq ; echo ""
$SCAN_CMD | grep freq ; echo ""
$SCAN_CMD | grep freq ; echo ""
$SCAN_CMD | grep freq ; echo ""
cat $ATH9K_PATH/spectral_scan0 > $OUT_NAME
echo disable > $ATH9K_PATH/spectral_scan_ctl
./fft_eval $OUT_NAME 2>/dev/null  1>/dev/null&

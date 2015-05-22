/*
 *  Wireless Network Monitor
 *
 *  Copyright 2011 David Garcia Villalba, Daniel López Rovira, Marc Portoles Comeras and Albert Cabellos Aparicio
 *
 *  This file is part of wmon.
 *
 *  wmon is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  wmon is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with wmon.  If not, see <http://www.gnu.org/licenses/>.
 */


/*
This class contain the airmon-ng script code from the aircrack-ng suite.

aircrack-ng Author:     Thomas d'Otreppe <tdotreppe@aircrack-ng.org> [from AUTHORS file]
aircrack-ng webpage:    www.aircrack-ng.org
License:                GNU General Public License, version 2 (http://www.gnu.org/licenses/gpl-2.0.html)
*/

#include "AirmonNG.h"
#include <sstream>
#include <cstdio>
#include <cstdlib>

std::string AirmonNG::createMonitorInterface(const std::string& interface) {
    std::stringstream ss;
    ss << script << "airmonNGFun start " << interface << " | grep 'monitor mode enabled on' | tr -s ' ' | cut -d' ' -f5 | head -c -2";

    FILE *output = popen(ss.str().c_str(), "r");
    char buffer[CREATEMONITORCMDBUFFER];
    
    std::string monInterface;
    if (fgets(buffer, sizeof(buffer), output) != NULL) monInterface = std::string(buffer);
    else monInterface = "";

    pclose(output);
    return monInterface;
}

void AirmonNG::deleteMonitorInterface(const std::string& interface) {
    std::stringstream ss;
    ss << script << "airmonNGFun stop " << interface << " > /dev/null";
    system(ss.str().c_str());
}

const char* AirmonNG::script =
"#!/bin/bash\n\
\n\
airmonNGFun() {\n\
USERID=\"\"\n\
IFACE=\"\"\n\
KISMET=/etc/kismet/kismet.conf\n\
CH=$3; [ x$3 = \"x\" ] && CH=10\n\
IFACE_FOUND=\"false\"\n\
MADWIFI=0\n\
MAC80211=0\n\
USE_IW=0\n\
IW_SOURCE=\"http://wireless.kernel.org/download/iw/iw-0.9.19.tar.bz2\"\n\
IW_ERROR=\"\"\n\
UDEV_ISSUE=0\n\
\n\
if [ -f \"`which iw 2>&1`\" ]\n\
then\n\
	USE_IW=1\n\
fi\n\
\n\
if [ \"x$MON_PREFIX\"=\"x\" ]\n\
then\n\
MON_PREFIX=\"mon\"\n\
fi\n\
\n\
PROCESSES=\"wpa_action\\|wpa_supplicant\\|wpa_cli\\|dhclient\\|ifplugd\\|dhcdbd\\|dhcpcd\\|NetworkManager\\|knetworkmanager\\|avahi-autoipd\\|avahi-daemon\\|wlassistant\\|wifibox\"\n\
PS_ERROR=\"invalid\"\n\
\n\
usage() {\n\
	printf \"usage: `basename $0` <start|stop|check> <interface> [channel or frequency]\\n\"\n\
	echo\n\
	exit\n\
}\n\
\n\
startStdIface() {\n\
	iwconfig $1 mode monitor >/dev/null 2>&1\n\
	if [ ! -z $2 ]\n\
	then\n\
	    if [ $2 -lt 1000 ]\n\
	    then\n\
		iwconfig $1 channel $2 >/dev/null 2>&1\n\
	    else\n\
		iwconfig $1 freq \"$2\"000000 > /dev/null 2>&1\n\
	    fi\n\
	fi\n\
	iwconfig $1 key off >/dev/null 2>&1\n\
	ifconfig $1 up\n\
	printf \" (monitor mode enabled)\"\n\
}\n\
\n\
\n\
stopStdIface() {\n\
	ifconfig $1 down >/dev/null 2>&1\n\
	iwconfig $1 mode Managed >/dev/null 2>&1\n\
	ifconfig $1 down >/dev/null 2>&1\n\
	printf \" (monitor mode disabled)\"\n\
}\n\
\n\
getModule() {\n\
    if [ -f \"/sys/class/net/$1/device/driver/module/srcversion\" ]\n\
    then\n\
        srcver1=`cat \"/sys/class/net/$1/device/driver/module/srcversion\"`\n\
        for j in `lsmod | awk '{print $1}' | grep -v \"^Module$\"`\n\
        do\n\
            srcver2=\"`modinfo $j 2>/dev/null | grep srcversion | awk '{print $2}'`\"\n\
            if [ $srcver1 = \"$srcver2\" ]\n\
            then\n\
                MODULE=$j\n\
                break\n\
            fi\n\
        done\n\
    else\n\
        MODULE=\"\"\n\
    fi\n\
#    return 0\n\
}\n\
\n\
getDriver() {\n\
   if [ -e \"/sys/class/net/$1/device/driver\" ]\n\
   then\n\
       DRIVER=\"`ls -l \"/sys/class/net/$1/device/driver\" | sed 's/^.*\\/\\([a-zA-Z0-9_-]*\\)$/\\1/'`\"\n\
       BUS=\"`ls -l \"/sys/class/net/$1/device/driver\" | sed 's/^.*\\/\\([a-zA-Z0-9_-]*\\)\\/.*\\/.*$/\\1/'`\"\n\
   else\n\
       DRIVER=\"\"\n\
       BUS=\"\"\n\
   fi\n\
   if [ x$(echo $DRIVER | grep ath5k) != \"x\" ]\n\
   then\n\
       DRIVER=\"ath5k\"\n\
   fi\n\
   if [ x$(echo $DRIVER | grep ath9k) != \"x\" ]\n\
   then\n\
       DRIVER=\"ath9k\"\n\
   fi\n\
}\n\
\n\
scanProcesses() {\n\
    match=`ps -A -o comm= | grep $PROCESSES | grep -v grep | wc -l`\n\
    if [ $match -gt 0 -a x\"$1\" != xkill ]\n\
    then\n\
        printf \"\\n\\n\"\n\
        echo \"Found $match processes that could cause trouble.\"\n\
        echo \"If airodump-ng, aireplay-ng or airtun-ng stops working after\"\n\
        echo \"a short period of time, you may want to kill (some of) them!\"\n\
        echo -e \"\\nPID\\tName\"\n\
    else\n\
        if [ x\"$1\" != xkill ]\n\
        then\n\
            return\n\
        fi\n\
    fi\n\
\n\
    if [ $match -gt 0 -a x\"$1\" = xkill ]\n\
    then\n\
        echo \"Killing all those processes...\"\n\
    fi\n\
\n\
    i=1\n\
    while [ $i -le $match ]\n\
    do\n\
        pid=`ps -A -o pid= -o comm= | grep $PROCESSES | grep -v grep | head -n $i | tail -n 1 | awk '{print $1}'`\n\
        pname=`ps -A -o pid= -o comm= | grep $PROCESSES | grep -v grep | head -n $i | tail -n 1 | awk '{print $2}'`\n\
        if [ x\"$1\" != xkill ]\n\
        then\n\
            printf \"$pid\\t$pname\\n\"\n\
        else\n\
            kill $pid\n\
        fi\n\
        i=$(($i+1))\n\
    done\n\
}\n\
\n\
checkProcessesIface() {\n\
    if [ x\"$1\" = x ]\n\
    then\n\
        return\n\
    fi\n\
\n\
    match2=`ps -o comm= -p 1 2>&1 | grep $PS_ERROR | grep -v grep | wc -l`\n\
    if [ $match2 -gt 0 ]\n\
    then\n\
	return\n\
    fi\n\
\n\
    for i in `ps auxw | grep $1 | grep -v \"grep\" | grep -v \"airmon-ng\" | awk '{print $2}'`\n\
    do\n\
        pname=`ps -o comm= -p $i`\n\
        echo \"Process with PID $i ($pname) is running on interface $1\"\n\
    done\n\
}\n\
\n\
getStack() {\n\
    if [ x\"$1\" = x ]\n\
    then\n\
        return\n\
    fi\n\
\n\
    if [ -d /sys/class/net/$1/phy80211/ ]\n\
    then\n\
        MAC80211=1\n\
    else\n\
        MAC80211=0\n\
    fi\n\
}\n\
\n\
#you need to run getDriver $iface prior to getChipset\n\
getChipset() {\n\
    if [ x\"$1\" = x ]\n\
    then\n\
        return\n\
    fi\n\
\n\
    CHIPSET=\"Unknown \"\n\
\n\
    if [ x$DRIVER = \"xOtus\" -o x$DRIVER = \"xarusb_lnx\" -o x$DRIVER = \"xar9170\" ]\n\
    then\n\
	CHIPSET=\"AR9001U\"\n\
    fi\n\
\n\
    if [ x$DRIVER = \"xzd1211rw\" -o x$DRIVER = \"xzd1211rw_mac80211\" ]\n\
    then\n\
        CHIPSET=\"ZyDAS 1211\"\n\
    fi\n\
\n\
    if [ x$DRIVER = \"xacx\" -o x$DRIVER = \"xacx-mac80211\" -o x$DRIVER = \"xacx1xx\" ]\n\
    then\n\
        CHIPSET=\"TI ACX1xx\"\n\
    fi\n\
\n\
    if [ x$DRIVER = \"adm8211\" ]\n\
    then\n\
        CHIPSET=\"ADMtek 8211\"\n\
    fi\n\
\n\
    if [ x$DRIVER = \"xat76_usb\" ]\n\
    then\n\
        CHIPSET=\"Atmel   \"\n\
    fi\n\
\n\
    if [ x$DRIVER = \"xb43\" -o x$DRIVER = \"xb43legacy\" -o x$DRIVER = \"xbcm43xx\" ]\n\
    then\n\
        CHIPSET=\"Broadcom\"\n\
    fi\n\
\n\
    if [ x$DRIVER = \"xprism54\" -o x$DRIVER = \"xp54pci\" -o x$DRIVER = \"xp54usb\" ]\n\
    then\n\
        CHIPSET=\"PrismGT \"\n\
    fi\n\
\n\
    if [ x$DRIVER = \"xhostap\" ]\n\
    then\n\
        CHIPSET=\"Prism 2/2.5/3\"\n\
    fi\n\
\n\
    if [ x$DRIVER = \"xr8180\" -o x$DRIVER = \"xrtl8180\" ]\n\
    then\n\
        CHIPSET=\"RTL8180/RTL8185\"\n\
    fi\n\
\n\
    if [ x$DRIVER = \"xr8187\" -o x$DRIVER = \"xrtl8187\" ]\n\
    then\n\
        CHIPSET=\"RTL8187 \"\n\
    fi\n\
\n\
    if [ x$DRIVER = \"xrt2570\" -o x$DRIVER = \"xrt2500usb\" ]\n\
    then\n\
        CHIPSET=\"Ralink 2570 USB\"\n\
    fi\n\
\n\
    if [ x$DRIVER = \"xrt2400\" -o x$DRIVER = \"xrt2400pci\" ]\n\
    then\n\
        CHIPSET=\"Ralink 2400 PCI\"\n\
    fi\n\
\n\
    if [ x$DRIVER = \"xrt2500\" -o x$DRIVER = \"xrt2500pci\" ]\n\
    then\n\
        CHIPSET=\"Ralink 2560 PCI\"\n\
    fi\n\
\n\
    if [ x$DRIVER = \"xrt61\" -o x$DRIVER = \"xrt61pci\" ]\n\
    then\n\
        CHIPSET=\"Ralink 2561 PCI\"\n\
    fi\n\
\n\
    if [ x$DRIVER = \"xrt73\" -o x$DRIVER = \"xrt73usb\" ]\n\
    then\n\
        CHIPSET=\"Ralink 2573 USB\"\n\
    fi\n\
\n\
    if [ x$DRIVER = \"xipw2100\" ]\n\
    then\n\
        CHIPSET=\"Intel 2100B\"\n\
    fi\n\
\n\
    if [ x$DRIVER = \"xipw2200\" ]\n\
    then\n\
        CHIPSET=\"Intel 2200BG\"\n\
    fi\n\
\n\
    if [ x$DRIVER = \"xipw3945\" -o x$DRIVER = \"xipwraw\" -o x$DRIVER = \"xiwl3945\" ]\n\
    then\n\
        CHIPSET=\"Intel 3945ABG\"\n\
    fi\n\
\n\
    if [ x$DRIVER = \"xipw4965\" -o x$DRIVER = \"xiwl4965\" ]\n\
    then\n\
        CHIPSET=\"Intel 4965AGN\"\n\
    fi\n\
\n\
    if [ x$DRIVER = \"xiwlagn\" ]\n\
    then\n\
        CHIPSET=\"Intel 4965/5xxx\"\n\
    fi\n\
\n\
    if [ x$DRIVER = \"xath_pci\" -o x$DRIVER = \"xath5k\" -o x$DRIVER = \"xath9k\" ]\n\
    then\n\
        CHIPSET=\"Atheros \"\n\
    fi\n\
\n\
    if [ x$DRIVER = \"xorinoco\" ]\n\
    then\n\
        CHIPSET=\"Hermes/Prism\"\n\
    fi\n\
}\n\
\n\
getPhy() {\n\
    PHYDEV=\"\"\n\
    if [ x\"$1\" = x ]\n\
    then\n\
        return\n\
    fi\n\
\n\
    if [ x$MAC80211 = \"x\" ]\n\
    then\n\
        return\n\
    fi\n\
\n\
    PHYDEV=\"`ls -l \"/sys/class/net/$1/phy80211\" | sed 's/^.*\\/\\([a-zA-Z0-9_-]*\\)$/\\1/'`\"\n\
}\n\
\n\
getNewMon() {\n\
    i=0\n\
\n\
    while [ -d /sys/class/net/$MON_PREFIX$i/ ]\n\
    do\n\
        i=$(($i+1))\n\
    done\n\
\n\
    MONDEV=\"$MON_PREFIX$i\"\n\
}\n\
\n\
if [ x\"`which id 2> /dev/null`\" != \"x\" ]\n\
then\n\
	USERID=\"`id -u 2> /dev/null`\"\n\
fi\n\
\n\
if [ x$USERID = \"x\" -a x$UID != \"x\" ]\n\
then\n\
	USERID=$UID\n\
fi\n\
\n\
if [ x$USERID != \"x\" -a x$USERID != \"x0\" ]\n\
then\n\
	echo Run it as root ; exit ;\n\
fi\n\
\n\
iwpriv > /dev/null 2> /dev/null ||\n\
  { echo Wireless tools not found ; exit ; }\n\
\n\
if [ x\"$1\" = xcheck ] || [ x\"$1\" = xstart ]\n\
then\n\
    scanProcesses\n\
    for iface in `iwconfig 2>/dev/null | egrep '(IEEE|ESSID|802\\.11|WLAN)' | sed 's/^\\([a-zA-Z0-9_]*\\) .*/\\1/' | grep -v wifi`\n\
    do\n\
#         getModule $iface\n\
#         getDriver $iface\n\
        checkProcessesIface $iface\n\
    done\n\
\n\
    if [ x\"$2\" = xkill ]\n\
    then\n\
        scanProcesses \"$2\"\n\
    fi\n\
    if [ x\"$1\" = xcheck ]\n\
    then\n\
        exit\n\
    fi\n\
fi\n\
\n\
printf \"\\n\\n\"\n\
\n\
if [ $# -ne \"0\" ]\n\
then\n\
    if [ x$1 != \"xstart\" ] && [ x$1 != \"xstop\" ]\n\
    then\n\
        usage\n\
    fi\n\
\n\
    if [ x$2 = \"x\" ]\n\
    then\n\
        usage\n\
    fi\n\
fi\n\
\n\
SYSFS=0\n\
if [ -d /sys/ ]\n\
then\n\
    SYSFS=1\n\
fi\n\
\n\
printf \"Interface\\tChipset\\t\\tDriver\\n\\n\"\n\
\n\
\n\
for iface in `ifconfig -a 2>/dev/null | egrep UNSPEC | sed 's/^\\([a-zA-Z0-9_]*\\) .*/\\1/'`\n\
do\n\
\n\
 if [ x\"`iwpriv $iface 2>/dev/null | grep ipwraw-ng`\" != \"x\" ]\n\
 then\n\
        printf \"$iface\\t\\tIntel 3945ABG\\tipwraw-ng\"\n\
        if [ x$1 = \"xstart\" ] && [ x$2 = x$iface ]\n\
        then\n\
                cp $KISMET~ $KISMET 2>/dev/null &&\n\
                echo \"source=ipw3945,$iface,Centrino_abg\" >>$KISMET\n\
                startStdIface $iface $CH\n\
                iwconfig $iface rate 1M 2> /dev/null >/dev/null\n\
                iwconfig $iface txpower 16 2> /dev/null >/dev/null\n\
        fi\n\
        if [ x$1 = \"xstop\" ] && [ x$2 = x$iface ]\n\
        then\n\
                stopStdIface $iface\n\
                iwconfig $iface txpower 15 2> /dev/null >/dev/null\n\
                iwconfig $iface rate 54M 2> /dev/null >/dev/null\n\
        fi\n\
        echo\n\
        continue\n\
 fi\n\
\n\
 if [ -e \"/proc/sys/dev/$iface/fftxqmin\" ]\n\
 then\n\
    MADWIFI=1\n\
    ifconfig $iface up\n\
    printf \"$iface\\t\\tAtheros\\t\\tmadwifi-ng\"\n\
    if [ x$1 = \"xstart\" ] && [ x$2 = x$iface ]\n\
    then\n\
        IFACE=`wlanconfig ath create wlandev $iface wlanmode monitor -bssid | grep ath`\n\
        cp $KISMET~ $KISMET 2>/dev/null &&\n\
        echo \"source=madwifi_g,$iface,Atheros\" >>$KISMET\n\
        ifconfig $iface up 2>/dev/null >/dev/null\n\
        if [ $CH -lt 1000 ]\n\
        then\n\
            iwconfig $IFACE channel $CH 2>/dev/null >/dev/null\n\
        else\n\
            iwconfig $IFACE freq \"$CH\"000000 2>/dev/null >/dev/null\n\
        fi\n\
        ifconfig $IFACE up 2>/dev/null >/dev/null\n\
        UDEV_ISSUE=$?\n\
    fi\n\
    if [ x$1 = \"xstop\" ] && [ x$2 = x$iface ]\n\
    then\n\
            echo \"$iface does not support 'stop', do it on ath interface\"\n\
    fi\n\
    echo\n\
    continue\n\
 fi\n\
done\n\
\n\
if [ $MADWIFI -eq 1 ]\n\
then\n\
	sleep 1s\n\
fi\n\
\n\
for iface in `iwconfig 2>/dev/null | egrep '(IEEE|ESSID|802\\.11|WLAN)' | sed 's/^\\([a-zA-Z0-9_]*\\) .*/\\1/' | grep -v wifi`\n\
do\n\
 getModule  $iface\n\
 getDriver  $iface\n\
 getStack   $iface\n\
 getChipset $DRIVER\n\
\n\
\n\
 if [ x$MAC80211 = \"x1\" ]\n\
 then\n\
    getPhy $iface\n\
    getNewMon\n\
    printf \"$iface\\t\\t$CHIPSET\\t$DRIVER - [$PHYDEV]\"\n\
    if [ x$1 = \"xstart\" ] && [ x$2 = x$iface ]\n\
    then\n\
        if [ $USE_IW = 1 ]\n\
        then\n\
            IW_ERROR=`iw dev $iface interface add $MONDEV type monitor 2>&1 | grep \"nl80211 not found\"`\n\
            if [ x$IW_ERROR = \"x\" ]\n\
            then\n\
                sleep 1s\n\
		if [ ! -z $3 ]\n\
                then\n\
            	    if [ $3 -lt 1000 ]\n\
            	    then\n\
                	iwconfig $MONDEV channel $3 >/dev/null 2>&1\n\
            	    else\n\
                	iwconfig $MONDEV freq \"$3\"000000 >/dev/null 2>&1\n\
            	    fi\n\
            	fi\n\
                ifconfig $MONDEV up\n\
                printf \"\\n\\t\\t\\t\\t(monitor mode enabled on $MONDEV)\"\n\
            else\n\
                if [ -f /sys/class/ieee80211/\"$PHYDEV\"/add_iface ]\n\
                then\n\
                    echo -n \"$MONDEV\" > /sys/class/ieee80211/\"$PHYDEV\"/add_iface\n\
                    sleep 1s\n\
                    if [ $3 -lt 1000 ]\n\
                    then\n\
                        iwconfig $MONDEV mode Monitor channel $3 >/dev/null 2>&1\n\
                    else\n\
                        iwconfig $MONDEV mode Monitor freq \"$3\"000000 >/dev/null 2>&1\n\
                    fi\n\
                    ifconfig $MONDEV up\n\
                    printf \"\\n\\t\\t\\t\\t(monitor mode enabled on $MONDEV)\"\n\
                else\n\
                    printf \"\\n\\nERROR: nl80211 support is disabled in your kernel.\\nPlease recompile your kernel with nl80211 support enabled.\\n\"\n\
                fi\n\
            fi\n\
        else\n\
            if [ -f /sys/class/ieee80211/\"$PHYDEV\"/add_iface ]\n\
            then\n\
                echo -n \"$MONDEV\" > /sys/class/ieee80211/\"$PHYDEV\"/add_iface\n\
                sleep 1s\n\
                if [ $3 -lt 1000 ]\n\
                then\n\
                    iwconfig $MONDEV mode Monitor channel $3 >/dev/null 2>&1\n\
                else\n\
                    iwconfig $MONDEV mode Monitor freq \"$3\"000000 >/dev/null 2>&1\n\
                fi\n\
                ifconfig $MONDEV up\n\
                printf \"\\n\\t\\t\\t\\t(monitor mode enabled on $MONDEV)\"\n\
            else\n\
                printf \"\\n\\nERROR: Neither the sysfs interface links nor the iw command is available.\\nPlease download and install iw from\\n$IW_SOURCE\\n\"\n\
            fi\n\
        fi\n\
    fi\n\
    if [ x$1 = \"xstop\" ] && [ x$2 = x$iface ]\n\
    then\n\
        z=\"`echo $iface | cut -b -${#MON_PREFIX}`\"\n\
        if [ x$z = \"x$MON_PREFIX\" ]\n\
        then\n\
            if [ $USE_IW = 1 ]\n\
            then\n\
                IW_ERROR=`iw dev \"$iface\" interface del 2>&1 | grep \"nl80211 not found\"`\n\
                if [ x$IW_ERROR = \"x\" ]\n\
                then\n\
                    printf \" (removed)\"\n\
                else\n\
                    if [ -f /sys/class/ieee80211/\"$PHYDEV\"/remove_iface ]\n\
                    then\n\
                        echo -n \"$iface\" > /sys/class/ieee80211/\"$PHYDEV\"/remove_iface\n\
                        printf \" (removed)\"\n\
                    else\n\
                        printf \"\\n\\nERROR: nl80211 support is disabled in your kernel.\\nPlease recompile your kernel with nl80211 support enabled.\\n\"\n\
                fi\n\
                fi\n\
            else\n\
                if [ -f /sys/class/ieee80211/\"$PHYDEV\"/remove_iface ]\n\
                then\n\
                    echo -n \"$iface\" > /sys/class/ieee80211/\"$PHYDEV\"/remove_iface\n\
                    printf \" (removed)\"\n\
                else\n\
                    printf \"\\n\\nERROR: Neither the sysfs interface links nor the iw command is available.\\nPlease download and install iw from\\n$IW_SOURCE\\n\"\n\
                fi\n\
	    fi\n\
        else\n\
            ifconfig $iface down\n\
            iwconfig $iface mode managed\n\
            printf \"\\n\\t\\t\\t\\t(monitor mode disabled)\"\n\
        fi\n\
    fi\n\
    echo\n\
    continue\n\
 fi\n\
\n\
\n\
 if [ x$DRIVER = \"xorinoco\" ] || [ x\"`iwpriv $iface 2>/dev/null | grep get_rid`\" != \"x\" ] || [ x\"`iwpriv $iface 2>/dev/null | grep dump_recs`\" != \"x\" ]\n\
 then\n\
    printf \"$iface\\t\\tHermesI\\t\\torinoco\"\n\
    if [ x$1 = \"xstart\" ] && [ x$2 = x$iface ]\n\
    then\n\
        cp $KISMET~ $KISMET 2>/dev/null &&\n\
        echo \"source=orinoco,$iface,HermesI\" >>$KISMET\n\
        if [ $CH -lt 1000 ]\n\
        then\n\
            iwconfig $iface mode Monitor channel $CH >/dev/null 2>&1\n\
        else\n\
            iwconfig $iface mode Monitor freq \"$CH\"000000 >/dev/null 2>&1\n\
        fi\n\
        iwpriv $iface monitor 1 $CH >/dev/null 2>&1\n\
        ifconfig $iface up\n\
        printf \" (monitor mode enabled)\"\n\
    fi\n\
    if [ x$1 = \"xstop\" ] && [ x$2 = x$iface ]\n\
    then\n\
        ifconfig $iface down\n\
        iwpriv $iface monitor 0 >/dev/null 2>&1\n\
        iwconfig $iface mode Managed >/dev/null 2>&1\n\
        printf \" (monitor mode disabled)\"\n\
    fi\n\
    echo\n\
    continue\n\
 fi\n\
\n\
\n\
 if [ x$DRIVER = \"xipw2100\" ] || [ x\"`iwpriv $iface 2>/dev/null | grep set_crc_check`\" != \"x\" ]\n\
 then\n\
    printf \"$iface\\t\\tIntel 2100B\\tipw2100\"\n\
    if [ x$1 = \"xstart\" ] && [ x$2 = x$iface ]\n\
    then\n\
        cp $KISMET~ $KISMET 2>/dev/null &&\n\
        echo \"source=ipw2100,$iface,Centrino_b\" >>$KISMET\n\
        startStdIface $iface $CH\n\
    fi\n\
    if [ x$1 = \"xstop\" ] && [ x$2 = x$iface ]\n\
    then\n\
        stopStdIface $iface\n\
    fi\n\
    echo\n\
    continue\n\
 fi\n\
\n\
\n\
 if [ x$DRIVER = \"xarusb_lnx\" ] || [ x$DRIVER = \"Otus\" ]\n\
 then\n\
    printf \"$iface\\t\\tAR9001USB\\tOtus\"\n\
    if [ x$1 = \"xstart\" ] && [ x$2 = x$iface ]\n\
    then\n\
	echo \"Monitor mode not yet supported\"\n\
    fi\n\
    if [ x$1 = \"xstop\" ] && [ x$2 = x$iface ]\n\
    then\n\
	stopStdIface $iface\n\
    fi\n\
    echo\n\
    continue\n\
 fi  \n\
\n\
 if [ x$DRIVER = \"xipw2200\" ] || [ x\"`iwpriv $iface 2>/dev/null | grep sw_reset`\" != \"x\" ]\n\
 then\n\
    MODINFO=`modinfo ipw2200  2>/dev/null | awk '/^version/ {print $2}'`\n\
    if { echo \"$MODINFO\" | grep -E '^1\\.0\\.(0|1|2|3)$' ; }\n\
    then\n\
    	echo \"Monitor mode not supported, please upgrade\"\n\
    else\n\
	printf \"$iface\\t\\tIntel 2200BG\\tipw2200\"\n\
	if [ x$1 = \"xstart\" ] && [ x$2 = x$iface ]\n\
	then\n\
	    cp $KISMET~ $KISMET 2>/dev/null &&\n\
	    echo \"source=ipw2200,$iface,Centrino_g\" >>$KISMET\n\
	    startStdIface $iface $CH\n\
	fi\n\
	if [ x$1 = \"xstop\" ] && [ x$2 = x$iface ]\n\
	then\n\
	    stopStdIface $iface\n\
	fi\n\
\n\
    	if { echo \"$MODINFO\" | grep -E '^1\\.0\\.(5|7|8|11)$' ; }\n\
	then\n\
		printf \" (Warning: bad module version, you should upgrade)\"\n\
	fi\n\
     fi\n\
     echo\n\
     continue\n\
 fi\n\
\n\
\n\
 if [ x$DRIVER = \"xcx3110x\" ] || [ x\"`iwpriv $iface 2>/dev/null | grep set_backscan`\" != \"x\" ]\n\
 then\n\
     printf \"$iface\\t\\tNokia 770\\t\\tcx3110x\"\n\
     if [ x$1 = \"xstart\" ] || [ x$1 = \"xstop\" ]\n\
     then\n\
     	printf \" (Enable/disable monitor mode not yet supported)\"\n\
     fi\n\
     echo\n\
     continue\n\
 fi\n\
\n\
\n\
 if [ x$DRIVER = \"xipw3945\" ] || [ x\"`iwpriv $iface 2>/dev/null | grep set_preamble | grep -v set_crc_check`\" != \"x\" ]\n\
  then\n\
        printf \"$iface\\t\\tIntel 3945ABG\\tipw3945\"\n\
        if [ x$1 = \"xstart\" ] && [ x$2 = x$iface ]\n\
         then\n\
                cp $KISMET~ $KISMET 2>/dev/null &&\n\
                echo \"source=ipw3945,$iface,Centrino_g\" >>$KISMET\n\
                startStdIface $iface $CH\n\
        fi\n\
        if [ x$1 = \"xstop\" ] && [ x$2 = x$iface ]\n\
         then\n\
                stopStdIface $iface\n\
        fi\n\
        echo\n\
        continue\n\
 fi\n\
\n\
\n\
 if [ x\"`iwpriv $iface 2>/dev/null | grep inact_auth`\" != \"x\" ]\n\
 then\n\
     if [ -e \"/proc/sys/net/$iface/%parent\" ]\n\
     then\n\
        printf \"$iface\\t\\tAtheros\\t\\tmadwifi-ng VAP (parent: `cat /proc/sys/net/$iface/%parent`)\"\n\
	if [ x$2 = x$iface ] && [ x$1 = \"xstop\" ]\n\
	then\n\
		wlanconfig $iface destroy\n\
		printf \" (VAP destroyed)\"\n\
	fi\n\
	if [ x$1 = \"xstart\" ]\n\
	then\n\
		if [ $iface = \"$IFACE\" ]\n\
		then\n\
			printf \" (monitor mode enabled)\"\n\
		fi\n\
		if [ x$2 = x$iface ]\n\
		then\n\
			printf \" (VAP cannot be put in monitor mode)\"\n\
		fi\n\
	fi\n\
\n\
	echo \"\"\n\
        continue\n\
\n\
     fi\n\
     printf \"$iface\\t\\tAtheros\\t\\tmadwifi\"\n\
     if [ x$1 = \"xstart\" ] && [ x$2 = x$iface ]\n\
     then\n\
         cp $KISMET~ $KISMET 2>/dev/null &&\n\
         echo \"source=madwifi_g,$iface,Atheros\" >>$KISMET\n\
         startStdIface $iface $CH\n\
     fi\n\
     if [ x$1 = \"xstop\" ] && [ x$2 = x$iface ]\n\
     then\n\
         stopStdIface $iface\n\
     fi\n\
     echo\n\
     continue\n\
 fi\n\
\n\
\n\
 if [ x$DRIVER = \"xprism54\" ] || [ x\"`iwpriv $iface 2>/dev/null | grep getPolicy`\" != \"x\" ]\n\
 then\n\
     printf \"$iface\\t\\tPrismGT\\t\\tprism54\"\n\
     if [ x$1 = \"xstart\" ] && [ x$2 = x$iface ]\n\
     then\n\
         cp $KISMET~ $KISMET 2>/dev/null &&\n\
         echo \"source=prism54g,$iface,Prism54\" >>$KISMET\n\
         ifconfig $iface up\n\
         if [ $CH -lt 1000 ]\n\
         then\n\
             iwconfig $iface mode Monitor channel $CH\n\
         else\n\
             iwconfig $iface mode Monitor freq \"$CH\"000000\n\
         fi\n\
         iwpriv $iface set_prismhdr 1 >/dev/null 2>&1\n\
         printf \" (monitor mode enabled)\"\n\
     fi\n\
     if [ x$1 = \"xstop\" ] && [ x$2 = x$iface ]\n\
     then\n\
         stopStdIface $iface\n\
     fi\n\
     echo\n\
     continue\n\
 fi\n\
\n\
\n\
 if [ x$DRIVER = \"xhostap\" ] || [ x\"`iwpriv $iface 2>/dev/null | grep antsel_rx`\" != \"x\" ]\n\
 then\n\
     printf \"$iface\\t\\tPrism 2/2.5/3\\tHostAP\"\n\
     if [ x$1 = \"xstart\" ] && [ x$2 = x$iface ]\n\
     then\n\
         cp $KISMET~ $KISMET 2>/dev/null &&\n\
         echo \"source=hostap,$iface,Prism2\" >>$KISMET\n\
         if [ $CH -lt 1000 ]\n\
         then\n\
             iwconfig $iface mode Monitor channel $CH\n\
         else\n\
             iwconfig $iface mode Monitor freq \"$CH\"000000\n\
         fi\n\
         iwpriv $iface monitor_type 1 >/dev/null 2>&1\n\
         ifconfig $iface up\n\
         printf \" (monitor mode enabled)\"\n\
     fi\n\
     if [ x$1 = \"xstop\" ] && [ x$2 = x$iface ]\n\
     then\n\
         stopStdIface $iface\n\
     fi\n\
     echo\n\
     continue\n\
 fi\n\
\n\
\n\
 if [ x$DRIVER = \"xwlan-ng\" ] || [ x\"`wlancfg show $iface 2>/dev/null | grep p2CnfWEPFlags`\" != \"x\" ]\n\
 then\n\
     printf \"$iface\\t\\tPrism 2/2.5/3\\twlan-ng\"\n\
     if [ x$1 = \"xstart\" ] && [ x$2 = x$iface ]\n\
     then\n\
         cp $KISMET~ $KISMET 2>/dev/null &&\n\
         echo \"source=wlanng,$iface,Prism2\" >>$KISMET\n\
         wlanctl-ng $iface lnxreq_ifstate ifstate=enable >/dev/null\n\
         wlanctl-ng $iface lnxreq_wlansniff enable=true channel=$CH \\\n\
                           prismheader=true wlanheader=false \\\n\
                           stripfcs=true keepwepflags=true >/dev/null\n\
         echo p2CnfWEPFlags=0,4,7 | wlancfg set $iface\n\
         ifconfig $iface up\n\
         printf \" (monitor mode enabled)\"\n\
     fi\n\
     if [ x$1 = \"xstop\" ] && [ x$2 = x$iface ]\n\
     then\n\
         ifconfig $iface down\n\
         wlanctl-ng $iface lnxreq_wlansniff enable=false  >/dev/null\n\
         wlanctl-ng $iface lnxreq_ifstate ifstate=disable >/dev/null\n\
         printf \" (monitor mode disabled)\"\n\
     fi\n\
     echo\n\
     continue\n\
 fi\n\
\n\
\n\
 if [ x$SYSFS = \"x\" ] && [ x\"`iwpriv $iface 2>/dev/null | grep get_RaAP_Cfg`\" != \"x\" ]\n\
 then\n\
    if [ x\"`iwconfig $iface | grep ESSID | awk -F\\  '{ print $2}' | grep -i rt61`\" != \"x\" ]\n\
    then\n\
    	printf \"$iface\\t\\tRalink 2561 PCI\\trt61\"\n\
    fi\n\
\n\
    if [ x\"`iwconfig $iface | grep ESSID | awk -F\\  '{ print $2}' | grep -i rt73`\" != \"x\" ]\n\
    then\n\
        printf \"$iface\\t\\tRalink 2573 USB\\trt73\"\n\
    fi\n\
\n\
    if [ x$1 = \"xstart\" ] && [ x$2 = x$iface ]\n\
    then\n\
         startStdIface $iface $CH\n\
         iwpriv $iface rfmontx 1\n\
         if [ x\"`iwpriv $iface 2>/dev/null | grep forceprismheader`\" != \"x\" ]\n\
         then\n\
             iwpriv $iface forceprismheader 1\n\
         fi\n\
         if [ x\"`iwpriv $iface 2>/dev/null | grep forceprism`\" != \"x\" ]\n\
         then\n\
             iwpriv $iface forceprism 1\n\
         fi\n\
    fi\n\
    if [ x$1 = \"xstop\" ] && [ x$2 = x$iface ]\n\
     then\n\
     	stopStdIface $iface\n\
    fi\n\
    echo\n\
    continue\n\
\n\
 fi\n\
\n\
\n\
 if [ x$DRIVER = \"xrt61\" ]\n\
 then\n\
    printf \"$iface\\t\\tRalink 2561 PCI\\trt61\"\n\
\n\
    if [ x$1 = \"xstart\" ] && [ x$2 = x$iface ]\n\
    then\n\
         startStdIface $iface $CH\n\
         iwpriv $iface rfmontx 1\n\
         if [ x\"`iwpriv $iface 2>/dev/null | grep forceprismheader`\" != \"x\" ]\n\
         then\n\
             iwpriv $iface forceprismheader 1\n\
         fi\n\
         if [ x\"`iwpriv $iface 2>/dev/null | grep forceprism`\" != \"x\" ]\n\
         then\n\
             iwpriv $iface forceprism 1\n\
         fi\n\
    fi\n\
    if [ x$1 = \"xstop\" ] && [ x$2 = x$iface ]\n\
     then\n\
     	stopStdIface $iface\n\
    fi    \n\
    echo\n\
    continue\n\
\n\
 fi\n\
\n\
\n\
 if [ x$DRIVER = \"xrt73\" ]\n\
 then\n\
    printf \"$iface\\t\\tRalink 2573 USB\\trt73\"\n\
\n\
    if [ x$1 = \"xstart\" ] && [ x$2 = x$iface ]\n\
    then\n\
         startStdIface $iface $CH\n\
         iwpriv $iface rfmontx 1\n\
         if [ x\"`iwpriv $iface 2>/dev/null | grep forceprismheader`\" != \"x\" ]\n\
         then\n\
             iwpriv $iface forceprismheader 1\n\
         fi\n\
         if [ x\"`iwpriv $iface 2>/dev/null | grep forceprism`\" != \"x\" ]\n\
         then\n\
             iwpriv $iface forceprism 1\n\
         fi\n\
    fi\n\
    if [ x$1 = \"xstop\" ] && [ x$2 = x$iface ]\n\
     then\n\
     	stopStdIface $iface\n\
    fi    \n\
    echo\n\
    continue\n\
\n\
 fi\n\
\n\
\n\
 if [ x$DRIVER = \"xrt2500\" ] || [ x\"`iwpriv $iface 2>/dev/null | grep bbp`\" != \"x\" ]\n\
 then\n\
     printf \"$iface\\t\\tRalink 2560 PCI\\trt2500\"\n\
     if [ x$1 = \"xstart\" ] && [ x$2 = x$iface ]\n\
     then\n\
         cp $KISMET~ $KISMET 2>/dev/null &&\n\
         echo \"source=rt2500,$iface,Ralink_g\" >>$KISMET\n\
         iwconfig $iface mode ad-hoc 2> /dev/null >/dev/null\n\
         startStdIface $iface $CH\n\
     fi\n\
     if [ x$1 = \"xstop\" ] && [ x$2 = x$iface ]\n\
     then\n\
         stopStdIface $iface\n\
     fi\n\
     echo\n\
     continue\n\
 fi\n\
\n\
\n\
 if [ x$DRIVER = \"xrt2570\" ] || [ x\"`iwpriv $iface 2>/dev/null | grep wpapsk`\" != \"x\" ] && [ x\"`iwpriv $iface 2>/dev/null | grep get_RaAP_Cfg`\" = \"x\" ]\n\
 then\n\
     printf \"$iface\\t\\tRalink 2570 USB\\trt2570\"\n\
     if [ x$1 = \"xstart\" ] && [ x$2 = x$iface ]\n\
     then\n\
         cp $KISMET~ $KISMET 2>/dev/null &&\n\
         echo \"source=rt2500,$iface,Ralink_g\" >>$KISMET\n\
         iwconfig $iface mode ad-hoc 2> /dev/null >/dev/null\n\
         startStdIface $iface $CH\n\
         if [ x\"`iwpriv $iface 2>/dev/null | grep forceprismheader`\" != \"x\" ]\n\
         then\n\
             iwpriv $iface forceprismheader 1\n\
         fi\n\
         if [ x\"`iwpriv $iface 2>/dev/null | grep forceprism`\" != \"x\" ]\n\
         then\n\
             iwpriv $iface forceprism 1\n\
         fi\n\
     fi\n\
     if [ x$1 = \"xstop\" ] && [ x$2 = x$iface ]\n\
     then\n\
         stopStdIface $iface\n\
     fi\n\
     echo\n\
     continue\n\
 fi\n\
\n\
\n\
 if [ x$DRIVER = \"xr8180\" ] || [ x\"`iwpriv $iface 2>/dev/null | grep debugtx`\" != \"x\" ]\n\
 then\n\
     printf \"$iface\\t\\tRTL8180/RTL8185\\tr8180\"\n\
     if [ x$1 = \"xstart\" ] && [ x$2 = x$iface ]\n\
     then\n\
         cp $KISMET~ $KISMET 2>/dev/null &&\n\
         echo \"source=rt8180,$iface,Realtek\" >>$KISMET\n\
         if [ $CH -lt 1000 ]\n\
         then\n\
             iwconfig $iface mode Monitor channel $CH\n\
         else\n\
             iwconfig $iface mode Monitor freq \"$CH\"000000\n\
         fi\n\
         if [ x\"`iwpriv $iface 2>/dev/null | grep prismhdr`\" != \"x\" ]\n\
         then\n\
            iwpriv $iface prismhdr 1 >/dev/null 2>&1\n\
         fi\n\
         ifconfig $iface up\n\
         printf \" (monitor mode enabled)\"\n\
     fi\n\
     if [ x$1 = \"xstop\" ] && [ x$2 = x$iface ]\n\
     then\n\
         stopStdIface $iface\n\
     fi\n\
     echo\n\
     continue\n\
 fi\n\
\n\
\n\
 if [ x$DRIVER = \"xr8187\" ] || [ x\"`iwpriv $iface 2>/dev/null | grep badcrc`\" != \"x\" ]\n\
 then\n\
     printf \"$iface\\t\\tRTL8187\\t\\tr8187\"\n\
     if [ x$1 = \"xstart\" ] && [ x$2 = x$iface ]\n\
     then\n\
         cp $KISMET~ $KISMET 2>/dev/null &&\n\
         echo \"source=rt8180,$iface,Realtek\" >>$KISMET\n\
         if [ $CH -lt 1000 ]\n\
         then\n\
             iwconfig $iface mode Monitor channel $CH\n\
         else\n\
             iwconfig $iface mode Monitor freq \"$CH\"000000\n\
         fi\n\
         if [ x\"`iwpriv $iface 2>/dev/null | grep rawtx`\" != \"x\" ]\n\
         then\n\
             iwpriv $iface rawtx 1 >/dev/null 2>&1\n\
         fi\n\
         ifconfig $iface up\n\
         printf \" (monitor mode enabled)\"\n\
     fi\n\
     if [ x$1 = \"xstop\" ] && [ x$2 = x$iface ]\n\
     then\n\
         stopStdIface $iface\n\
     fi\n\
     echo\n\
     continue\n\
 fi\n\
\n\
\n\
 if [ x$DRIVER = \"xzd1211rw\" ] || [ x\"`iwpriv $iface 2>/dev/null | grep get_regdomain`\" != \"x\" ]\n\
 then\n\
     printf \"$iface\\t\\tZyDAS 1211\\tzd1211rw\"\n\
     if [ x$1 = \"xstart\" ] && [ x$2 = x$iface ]\n\
     then\n\
         cp $KISMET~ $KISMET 2>/dev/null &&\n\
         echo \"source=zd1211,$iface,ZyDAS\" >>$KISMET\n\
         startStdIface $iface $CH\n\
     fi\n\
     if [ x$1 = \"xstop\" ] && [ x$2 = x$iface ]\n\
     then\n\
         stopStdIface $iface\n\
     fi\n\
     echo\n\
     continue\n\
 fi\n\
\n\
\n\
 if [ x$DRIVER = \"xzd1211\" ] || [ x\"`iwpriv $iface 2>/dev/null | grep dbg_flag`\" != \"x\" ]\n\
 then\n\
     printf \"$iface\\t\\tZyDAS 1211\\tzd1211\"\n\
     if [ x$1 = \"xstart\" ] && [ x$2 = x$iface ]\n\
     then\n\
         cp $KISMET~ $KISMET 2>/dev/null &&\n\
         echo \"source=zd1211,$iface,ZyDAS\" >>$KISMET\n\
         startStdIface $iface $CH\n\
     fi\n\
     if [ x$1 = \"xstop\" ] && [ x$2 = x$iface ]\n\
     then\n\
         stopStdIface $iface\n\
     fi\n\
     echo\n\
     continue\n\
 fi\n\
\n\
\n\
 if [ x$DRIVER = \"xacx\" ] || [ x\"`iwpriv $iface 2>/dev/null | grep GetAcx1`\" != \"x\" ]\n\
 then\n\
     printf \"$iface\\t\\tTI ACX1xx\\tacx\"\n\
     if [ x$1 = \"xstart\" ] && [ x$2 = x$iface ]\n\
     then\n\
         cp $KISMET~ $KISMET 2>/dev/null &&\n\
         echo \"source=acx100,$iface,TI\" >>$KISMET\n\
         iwpriv $iface monitor 2 $CH 2> /dev/null >/dev/null\n\
         startStdIface $iface $CH\n\
     fi\n\
     if [ x$1 = \"xstop\" ] && [ x$2 = x$iface ]\n\
     then\n\
         stopStdIface $iface\n\
     fi\n\
     echo\n\
     continue\n\
 fi\n\
\n\
\n\
 if [ x$DRIVER = \"xbcm43xx\" ] || [ x\"`iwpriv $iface 2>/dev/null | grep write_sprom`\" != \"x\" ]\n\
 then\n\
     printf \"$iface\\t\\tBroadcom\\tbcm43xx\"\n\
     if [ x$1 = \"xstart\" ] && [ x$2 = x$iface ]\n\
     then\n\
         cp $KISMET~ $KISMET 2>/dev/null &&\n\
         echo \"source=bcm43xx,$iface,broadcom\" >>$KISMET\n\
         startStdIface $iface $CH\n\
     fi\n\
     if [ x$1 = \"xstop\" ] && [ x$2 = x$iface ]\n\
     then\n\
         stopStdIface $iface\n\
         ifconfig $iface up\n\
     fi\n\
     echo\n\
     continue\n\
 fi\n\
\n\
\n\
 if [ x$DRIVER = \"xislsm\" ] || [ x\"`iwpriv $iface 2>/dev/null | grep set_announcedpkt`\" != \"x\" ]\n\
 then\n\
    printf \"$iface\\t\\tPrismGT\\t\\tislsm\"\n\
    if [ x$1 = \"xstart\" ] && [ x$2 = x$iface ]\n\
    then\n\
         startStdIface $iface $CH\n\
    fi\n\
    if [ x$1 = \"xstop\" ] && [ x$2 = x$iface ]\n\
     then\n\
     	stopStdIface $iface\n\
    fi    \n\
    echo\n\
    continue\n\
\n\
 fi\n\
\n\
\n\
 if [ x$DRIVER = \"xat76c503a\" ] || [ x\"`iwpriv $iface 2>/dev/null | grep set_announcedpkt`\" != \"x\" ]\n\
  then\n\
     printf \"$iface\\t\\tAtmel\\t\\tat76c503a\"\n\
     if [ x$1 = \"xstart\" ] && [ x$2 = x$iface ]\n\
     then\n\
          startStdIface $iface $CH\n\
     fi\n\
     if [ x$1 = \"xstop\" ] && [ x$2 = x$iface ]\n\
      then\n\
      	 stopStdIface $iface\n\
     fi     \n\
     echo\n\
     continue\n\
\n\
 fi\n\
\n\
\n\
 if [ x$DRIVER = \"xndiswrapper\" ] || [ x\"`iwpriv $iface 2>/dev/null | grep ndis_reset`\" != \"x\" ]\n\
 then\n\
     printf \"$iface\\t\\tUnknown\\t\\tndiswrapper\"\n\
     if [ x$2 = x$iface ]\n\
     then\n\
         echo \" (MONITOR MODE NOT SUPPORTED)\"\n\
     fi\n\
     if [ x$1 = \"xstop\" ] && [ x$2 = x$iface ]\n\
     then\n\
         stopStdIface $iface\n\
     fi\n\
     echo\n\
     continue\n\
 fi\n\
\n\
\n\
 if [ x$DRIVER != \"x\" ]\n\
 then\n\
     if [ x$CHIPSET = \"x\" ]\n\
     then\n\
         printf \"$iface\\t\\tUNKNOWN\\t\\t$DRIVER\"\n\
     else\n\
         printf \"$iface\\t\\t$CHIPSET\\t\\t$DRIVER\"\n\
     fi\n\
\n\
     if [ x$1 = \"xstart\" ] && [ x$2 = x$iface ]\n\
     then\n\
         startStdIface $iface $CH\n\
     fi\n\
     if [ x$1 = \"xstop\" ] && [ x$2 = x$iface ]\n\
     then\n\
         stopStdIface $iface\n\
     fi\n\
     echo\n\
     continue\n\
 fi\n\
\n\
printf \"$iface\\t\\tUnknown\\t\\tUnknown (MONITOR MODE NOT SUPPORTED)\\n\"\n\
\n\
done\n\
\n\
echo\n\
\n\
if [ $UDEV_ISSUE != 0 ] ; then\n\
	echo udev renamed the interface. Read the following for a solution:\n\
	echo http://www.aircrack-ng.org/doku.php?id=airmon-ng#interface_athx_number_rising_ath0_ath1_ath2...._ath45\n\
	echo \n\
fi\n\
}\n";


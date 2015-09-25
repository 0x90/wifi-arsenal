#Copyright (c) 2006 - 2009, Intel Corporation
#Author: Jeff Zheng <jeff.zheng@intel.com>
#Contact: WiFi Test Development <wifi-test-devel@lists.sourceforge.net>
#
#This program is free software; you can redistribute it and/or 
#modify it under the terms of the GNU General Public License version 
#2 as published by the Free Software Foundation.
#
#This program is distributed in the hope that it will be useful, but 
#WITHOUT ANY WARRANTY; without even the implied warranty of 
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
#General Public License for more details.
#
#You should have received a copy of the GNU General Public License 
#along with this program; if not, write to the Free Software Foundation, 
#Inc., 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
#

. iwl_common.sh

iwl_keyvalue=(0 $iwl_keyvalue1 $iwl_keyvalue2 $iwl_keyvalue3 $iwl_keyvalue4)
iwl_displaykey=(0 $iwl_displaykey1 $iwl_displaykey2 $iwl_displaykey3 $iwl_displaykey4)

# iwl_connect
# Connect to AP with give options. The options are same as iwl_test
iwl_connect()
{
    local i
    local keyindex
    local key
    local wpa_conf
    local essid
    local ap_mac
    local ibss
    local lhost # Local machine ip
    local dhcp
    local supplicant
    ifconfig wlan0 up
    sleep 6
    OPTIND=1
    while getopts "m:c:b:h:f:r:s:w:k:e:1:2:3:4:a:t:l:p:x:idSA:" Option
    do
        case $Option in
	    c) iw dev wlan0 set channel $OPTARG;;
	    s) essid=$OPTARG;;
	    k) keyindex=$OPTARG;;
	    x) wpa_conf=$OPTARG;;
	    i) ibss=1;;
	    S) supplicant=1;;
	    A) ap_mac=$OPTARG;;
	    ?) echo $Options not necessary;;
        esac
    done
    if [ -z "$supplicant" -o "$supplicant" != "1" ]; then
        [ -z "$essid" ] && essid=$iwl_essid
        for i in 1 2 3 4 5
        do    
            sleep 3
            [ -z "$ap_mac" ] && ap_mac=$iwl_ap_mac
            iw dev wlan0 scan|grep $ap_mac - && break
        done
        [ $? -ne 0 ] && { tet_infoline "Cannot scan $ap_mac"; return; }
        tet_infoline "There is $ap_mac"

        [ -z "$channel" ] && channel=$iwl_channel
        if [ -z $ibss ]; then
            if [ ! -z "$keyindex" ]; then
                key=${iwl_keyvalue[$keyindex]}
                tet_infoline "With key $((keyindex-1)):$key"
                iw dev wlan0 connect $essid $ap_mac key d:$((keyindex-1)):$key
            else
                iw dev wlan0 connect $essid $ap_mac
            fi
            [ $? -ne 0 ] && { tet_infoline "Associate to $essid $ap_mac failed"; return; }
            sleep 6
        else
	    ifconfig wlan0 down
	    sleep 2
            iw dev wlan0 set type ibss || { tet_infoline "set ibss failed"; return;}
	    ifconfig wlan0 up
	    sleep 3
	    freq=`iw list |grep "MHz \[$channel\]" |awk '{print $2}'`
            if [ ! -z "$keyindex" ]; then
            	key=${iwl_keyvalue[$keyindex]}
                tet_infoline "With key $((keyindex-1)):$key"
                iw dev wlan0 ibss join $essid $freq key $((keyindex-1)):$key
            else
                iw dev wlan0 ibss join $essid $freq
            fi
            [ $? -ne 0 ] && { tet_infoline "Associate to $essid failed"; return; }
        fi
    else
        iwl_connect_with_wpa 1 1  "$wpa_conf" ||  \
            { tet_infoline "wpa_supplicant with $wpa_conf failed"; return 1; }
    fi

    i=1
    while [ $i -lt 30 ]; do
          #iw dev wlan0 station dump|grep "$iwl_ap_mac" && break
          iw dev wlan0 link|grep "$iwl_ap_mac" && break
          sleep 2
          i=$((i+1))
          echo $i
    done
    [ $i -lt 30 ] || { tet_infoline "Cannot associat"; return 1;}
    tet_infoline "Associated to $essid"

    [ -z $lhost ] && lhost=${iwl_host[1]}
    if [ -z $dhcp ]; then
        ifconfig wlan0 $lhost || return 1
    else
        dhclient wlan0 &
        sleep 200 # Wait enough time to get IP?
    fi

}

iwl_connect_with_wpa()
{
    local conf=$3
    wpa_supplicant -Dnl80211 -iwlan0 -c $conf &
    i=1
    while [ $i -le 20 ]
    do
        sleep 5
        iw dev wlan0 station dump|grep "$iwl_ap_mac" && break
        i=$((i+1))
    done
    iw dev wlan0 station dump|grep "$iwl_ap_mac" || { tet_infoline "Not associated"; return 1;}
    tet_infoline "Associated"
}

get_chans()
{
    allchans=`iw list|grep "MHz \[" |awk -F[ '{print $2}'|awk -F] '{print $1}'`
    [ -z "$allchans" ] && return
    chans=""
    for chan in $@
    do
        echo $allchans |grep $chan >/dev/null && chans="$chans $chan"
    done
    echo $chans
}

# Set these environment variables at run time:
# iwl_ap_mac iwl_channel iwl_apchans, iwl_chans

iwl_startup()
{
    if [ -z "$iwl_ap_mac" ]; then
	iwl_ssh $iwl_apset_cmd --reset
	ifconfig wlan0 up || { iwl_load_module; ifconfig wlan0 up; }
	for i in 1 2 3 4 5
	do
	    iw dev wlan0 scan |grep -i $iwl_essid -7 > /tmp/aplist && break
	done
	iwl_ap_mac=`cat /tmp/aplist |grep BSS |awk '{print $2}'`
	iwl_channel=`cat /tmp/aplist |grep channel |awk '{print $5}'`
	# TODO: Need find a way to get iwl_apchans, here is just a workaround
	if [ ! -z "$iwl_channel" ]; then
	    echo " 1 2 3 4 5 6 7 8 9 10 11 " | grep " $iwl_channel " && \
	    	iwl_apchans="1 2 3 4 5 6 7 8 9 10 11"
	    echo " 36 40 44 48 " | grep " $iwl_channel " && \
	    	iwl_apchans="36 40 44 48"
	    echo " 149 153 157 161 165 " | grep " $iwl_channel " && \
	    	iwl_apchans="149 153 157 161 165"
	fi
    fi
    iwl_chans=`get_chans "$iwl_apchans"`
    [ -z "$iwl_chans" ] && iwl_chans=$iwl_channel
}
#export iwl_ap_mac iwl_channel iwl_apchans iwl_chans

startup() # start-up function()
{
    tet_infoline "Inside startup..."
    mkdir -p $TMPDIR
    iwl_startup
}

cleanup() # clean-up function()
{
    tet_infoline "Inside cleanup..."
}



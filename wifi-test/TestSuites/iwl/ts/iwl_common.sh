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


iwl_ehost=`hostname -s |awk '{print tolower($0)}'`
[ -f ./iwl_env.sh ] && . ./iwl_env.sh
iwl_keyvalue1=1111000000
iwl_keyvalue2=2222000000
iwl_keyvalue3=11112222333344445555666611
iwl_keyvalue4=12345678901234567890123456
iwl_displaykey1=1111-0000-00
iwl_displaykey2=2222-0000-00
iwl_displaykey3=1111-2222-3333-4444-5555-6666-11
iwl_displaykey4=1234-5678-9012-3456-7890-1234-56
iwl_keyvalue=(0 $iwl_keyvalue1 $iwl_keyvalue2 $iwl_keyvalue3 $iwl_keyvalue4)
iwl_displaykey=(0 $iwl_displaykey1 $iwl_displaykey2 $iwl_displaykey3 $iwl_displaykey4)
#iwcom=(essid mode freq channel rate txpower rts frag key power ecn)
#iwcwrd=(ESSID: Mode: Frequency Channel "Bit Rate=" "Tx-Power=" "RTS thr:" "Fragment thr:" "Power Management:" "Security mode:")
iwl_srv=($iwl_esrv $iwl_wsrv)
iwl_host=($iwl_ehost $iwl_whost)
iwl_peer=($iwl_epeer $iwl_wpeer)
iwl_card=5    # Default 5000 serial cards
# 3945 card
lspci -n | grep 8086:4222 && iwl_card=3
lspci -n | grep 8086:4227 && iwl_card=3
# 4965 card
lspci -n | grep 8086:4229 && iwl_card=4
lspci -n | grep 8086:4230 && iwl_card=4

export iwl_essid iwl_ap_mac iwl_wap iwl_apset_cmd iwl_card

# tet_title <test case title>. Put it here so that we can use
# original tet
tet_title(){
        tet_output 202 0 "$*"
}

is3945()
{
    test $iwl_card -eq 3
}

is4965()
{
    test $iwl_card -eq 4
}

is5000()
{
    test $iwl_card -eq 5
}

isagn()
{
    test $iwl_card -ne 3
}

    
iwl_ssh()
{
    ssh "$@"
    if [ $? -ne 0 ]; then
        tet_infoline "iwl_ssh failed, restart network"
        service network restart
        ssh "$@"
    fi
}

iwl_load_iwlwifi()
{
    ifconfig wlan0 down
    modprobe iwlagn -r
    modprobe iwl3945 -r
    sleep 2
    is3945 && modprobe iwl3945 debug=0x40000
    is4965 && modprobe iwlagn debug=0x40000
    is5000 && modprobe iwlagn debug50=0x40000
    sleep 4
}

iwl_load_evp()
{
    modprobe -r iwmc3200wifi
    sleep 5
    modprobe iwmc3200wifi
    sleep 5
    ifconfig wlan0 up
    if [ $? -ne 0 ]; then
        modprobe -r iwmc3200wifi; sleep 2
        modprobe -r iwmc3200top; sleep 2
        modprobe -r sdhci-pci
        sleep 5
        modprobe sdhci-pci
    fi
    sleep 10
}

iwl_load_hwsim()
{
    modprobe -r mac80211_hwsim
    sleep 1
    modprobe mac80211_hwsim
    sleep 1
    ifconfig wlan0 up
    ifconfig wlan1 up
    sleep 1
}

iwl_load_module()
{
    pkill -9 wpa_supplicant
    rm -rf /var/run/wpa_supplicant
    $iwl_load_module_vendor
    tet_infoline "Module loaded"
}

# iwl_test <options>
# Set both AP & DUT options and test the connection with both ping & copy
# option description        default        value
# m    MODE            MIXED        A-ONLY/MIXED/G-ONLY/B-ONLY
# c    CHANNEL            1        1 - 11 (b/g),149 153 ... 165 (a)
# s    SSID    Just for testing fault essids, will not set to AP
# b    BCAST            enable        enable/disable
# q    QOS            off        on/off
# f    FRAG            2352        256 - 2352
# r    RTS            2347        0 - 2347
########################################################################################
# w    WEP            disable        enable|disable
# k    KEYIDX            1        1 - 4
#          Please enable WEP before set a key index.
#         The key value for each index are fixed in AP and won't be changed during testing.
#        keyvalue1:           || keyvalue2:           || keyvalue3:     || keyvalue4:
########################################################################################
# a    AUTH            open        open/shared/radius/wpa/psk (b) open/shared/auto/wpa/psk/wpa2/psk2 (a/g)
# t    WPA-CRYPTO        AES        AES/TKIP/AES+TKIP
# x    WPA config file in DUT
#        The below value for Radiusd Server and PSK secret are fixed:
#        Server IP:192.168.50.74  ||  Raiused Secret:sharedsecret  ||   Raiused Port: 1812
#        PSK-KEY:sharedsecret
########################################################################################
# i    It's ibss network, will not set ap_mac
# d    Get IP address through dhcp. unset to assign static IP. Notes:
#    You need to kill dhclient in the test cases
# A    ap_mac
#
iwl_test()
{
    iwl_test_bss $@
    return $?
}

# Connect to ap, ping to server
iwl_test_bss()
{
    #iwl_apset $@ && iwl_connect $@ && iwl_check  ${iwl_srv[1]}
    iwl_apset $@ || iwl_fail "Set AP failed"
    iwl_connect $@ || iwl_fail "Associate failed"
    iwl_check ${iwl_srv[1]} || iwl_fail "Ping or scp to ${iwl_srv[1]} failed"
    return $?
}

# Setup a cell ap in peer machine and connect the cell ap through wireless
iwl_test_ibss()
{
    # Peer machine might have the essid, so need an uniq essid
    essid=${iwl_host[0]}-ibss-`date +%H%M%S`
    #iwl_ibss_ap -s $essid $@ -i && iwl_connect -s $essid $@ -i && iwl_check ${iwl_peer[1]}
    iwl_ibss_ap -s $essid $@ -i || iwl_fail "Set ad-hoc cell at peer failed"
    iwl_connect -s $essid $@ -i || iwl_fail "Associate failed"
    iwl_check ${iwl_peer[1]} || iwl_fail "Ping or scp to ${iwl_srv[1]} failed"

    return $?
}

# Setup a cell ap in test machine and connect to the cell from a peer
iwl_test_ibss_cell()
{
    # Peer machine might have the essid, so need an uniq essid
    essid=${iwl_host[0]}-ibss-`date +%H%M%S`
    iwl_connect -s $essid $@ -i || iwl_fail "Setup cell failed"
    tet_infoline "Setup cell $essid success"
    iwl_ssh ${iwl_peer[0]} mkdir -p /tmp/${iwl_host[0]}
    scp iwl_association.sh iwl_common.sh iwl_env.sh \
        $TVS_ROOT/tsets/iwl/tvs_env ${iwl_peer[0]}:/tmp/${iwl_host[0]}
    iwl_ssh ${iwl_peer[0]} /tmp/${iwl_host[0]}/iwl_association.sh -s \
    	$essid -i -l ${iwl_peer[1]} -p ${iwl_host[1]} \
	|| iwl_fail "Associate to cell $essid failed"
    iwl_check ${iwl_peer[1]} || \
	iwl_fail "Ping and scp from/to ${iwl_peer[1]} failed"
    tet_infoline "Associate to cell $essid success"
}

# Preparing to setup cell app in peer machine
iwl_ibss_ap()
{
    iwl_ssh ${iwl_peer[0]} mkdir -p /tmp/${iwl_host[0]}
    scp iwl_association.sh iwl_common.sh iwl_env.sh \
    $TVS_ROOT/tsets/iwl/tvs_env ${iwl_peer[0]}:/tmp/${iwl_host[0]}
    iwl_ssh ${iwl_peer[0]} /tmp/${iwl_host[0]}/iwl_association.sh $@ \
    	-l ${iwl_peer[1]} -p ${iwl_host[1]}
    if [ $? -ne 0 ]; then
        tet_infoline "IBSS cell setup at ${iwl_peer[0]} failed"
        return 1
    else
        tet_infoline "IBSS cell setup at ${iwl_peer[0]} success"
    return 0
    fi
}

iwl_test_peer()
{
    iwl_apset $@ || return $?
    #iwl_bss_peer $@ && iwl_connect $@ && iwl_check ${iwl_peer[1]}
    iwl_bss_peer $@ || iwl_fail "Peer machine failed to associate to AP"
    iwl_connect $@ || iwl_fail "Associate failed"
    iwl_check ${iwl_peer[1]} || iwl_fail "Ping or scp to peer ${iwl_srv[1]} failed"
    return $?
}

iwl_bss_peer()
{
    iwl_ibss_ap $@ 
    if [ $? -ne 0 ]; then
        tet_infoline "Associate ${iwl_peer[0]} to AP failed"
        return 1
    else
        tet_infoline "Associate ${iwl_peer[0]} to AP success"
        return 0
    fi
}

# Check if can ping to peer machine and copy from/to peer machine
iwl_check()
{
    iwl_ping $1 || { tet_infoline "ping to $1 failed"; return 1; }
    tet_infoline "ping to $1 success"
    iwl_scp_copy $1 /tmp/5M || { tet_infoline "scp file to $1 failed"; \
                return 1; } 
    tet_infoline "scp file to $1  success"
}

# Check if can ping to peer machine
iwl_ping()
{
    local i
    for i in 1 2 3 4 5 
    do
        ping -I wlan0 -c 5 $1 && return 0
        sleep 5
    done
    return 1
}

# iwl_connect
# Connect to AP with give options. The options are same as iwl_test
iwl_connect()
{
    local i
    local mode
    local channel
    local broadcast
    local frag
    local rts
    local keyindex
    local key
    local encrypt_width
    local wep
    local authtype
    local crypto
    local wpa_conf
    local essid
    local ap_mac
    local ibss
    local lhost # Local machine ip
    local phost # Peer machine ip
    local dhcp
    local supplicant
    ifconfig wlan0 down
    mode=$iwl_band
    OPTIND=1
    while getopts "m:c:b:h:f:r:s:w:k:e:1:2:3:4:a:t:l:p:x:idSA:" Option
    do
        case $Option in
	    m) mode=$OPTARG;;
	    c) channel=$OPTARG;;
	    b) ;;
	    h) ;;
	    f) frag=$OPTARG;;
	    r) rts=$OPTARG;;
	    s) essid=$OPTARG;;
	    w) ;;
	    k) keyindex=$OPTARG;;
	    e) ;;
	    1) keyvalue1=$OPTARG;;
	    2) keyvalue2=$OPTARG;;
	    3) keyvalue3=$OPTARG;;
	    4) keyvalue4=$OPTARG;;
	    a) authtype=$OPTARG;;
	    t) ;;
	    l) lhost=$OPTARG;;
	    p) phost=$OPTARG;;
	    x) wpa_conf=$OPTARG;;
	    i) ibss=1; iwconfig wlan0 mode ad-hoc;;
	    d) dhcp=1;;
	    S) supplicant=1;;
	    A) ap_mac=$OPTARG;;
        esac
    done
    sleep 2
    #W/A : Disable key off; will enable if fix bug 2093
    #iwconfig wlan0 key off
    #sleep 2
    if [ ! -z "$keyindex" ]; then
        key=${iwl_keyvalue[$keyindex]}
        tet_infoline "Set key to [$keyindex] $key"
        iwconfig wlan0 key [$keyindex] $key
    fi
    if [ ! -z "$keyvalue1" ]; then
        iwconfig wlan0 key $keyvalue1
    fi
    if [ ! -z "$keyvalue2" ]; then
        iwconfig wlan0 key [2] $keyvalue2
        iwconfig wlan0 key [2]
    fi
    if [ ! -z "$keyvalue3" ]; then
        iwconfig wlan0 key [3] $keyvalue3
        iwconfig wlan0 key [3]
    fi
    if [ ! -z "$keyvalue4" ]; then
        iwconfig wlan0 key [4] $keyvalue4
        iwconfig wlan0 key [4]
    fi

    if [ "$authtype" == "shared" ]; then
        tet_infoline "Set shared key"
        iwconfig wlan0 key restricted
    fi
    
    ifconfig wlan0 up
    sleep 2
    [ -z "$frag" ] || { iwconfig wlan0 frag $frag; \
            tet_infoline "Set frag to $frag"; }
    [ -z "$rts" ] || { iwconfig wlan0 rts $rts; \
            tet_infoline "set rts to $rts"; }
    sleep 2
    [ -z "$essid" ] && essid=$iwl_essid

    # scan essid until found the AP, this makes assocation easier
    #ifconfig wlan0 up
    sleep 2
    for i in 1 2 3 4 5
    do
        iwlist wlan0 scan |grep $essid - && break
        # Check through mac address
        if [ ! -z "$ap_mac" ]; then
            iwlist wlan0 scan |grep $ap_mac - && break
        elif [ "$essid" == "$iwl_essid" ]; then
            iwlist wlan0 scan |grep $iwl_ap_mac - && break
        fi
        sleep 3
    done

    #if [ -z "$authtype" -o  "$authtype" == "open" -o "$authtype" == "shared" ]; then
     if [ -z "$supplicant" -o "$supplicant" != "1" ]; then
        [ -z "$channel" ] && channel=$iwl_channel
        if [ -z $ibss ]; then
            ifconfig wlan0 up
            sleep 3
            [ -z "$ap_mac" ] || iwconfig wlan0 ap $ap_mac
            if [ -z "iwl_evp" -o "$iwl_evp" != "1" ]; then
                for i in 1 2 3 4 5
                do
                    # Seperate ap <> according to Yi's suggestion
                    # iwconfig wlan0 essid $essid channel $channel ap $ap_mac
                    # iwconfig wlan0 channel $channel essid $essid
		    # Sometime using channel and essid does not work.
                    iwconfig wlan0 channel $channel
                    iwconfig wlan0 essid $essid
                    sleep 6
                    quality=`iwconfig wlan0 |grep Link |awk '{print $2}' |awk -F: '{print $2}'`
                [ "$quality" != 0 ] && break
                done
            else
                iwconfig wlan0 essid $essid
                sleep 6
            fi
            tet_infoline "Associating to $essid"
        else
            # SP needs dedicated sequence for IBSS network
            ifconfig wlan0 down
            if [ ! -z "$keyindex" ]; then
               key=${iwl_keyvalue[$keyindex]}
               iwconfig wlan0 key [$keyindex] $key
            fi
            ifconfig wlan0 up
            sleep 3
            iwconfig wlan0 essid $essid
            tet_infoline "Associating to IBSS cell $essid"
        fi
    else
        #[ -z "$crypto" ] && return 1
        #iwl_connect_with_wpa "$authtype" "$crypto" "$wpa_conf" || return 1
        iwl_connect_with_wpa 1 1  "$wpa_conf" || return 1
        tet_infoline "Associating with wpa_supplicant"
    fi

    i=1
    while [ $i -lt 30 ]; do
        iwconfig wlan0 |grep Not-Associated || break
        sleep 2
        i=$((i+1))
        echo $i
    done
    [ $i -lt 30 ] || { tet_infoline "Cannot associate"; return 1;}
    tet_infoline "Associated"

    [ -z $lhost ] && lhost=${iwl_host[1]}
    if [ -z $dhcp ]; then
        ifconfig wlan0 $lhost || return 1
    else
        dhclient wlan0 &
        sleep 200 # Wait enough time to get IP?
    fi
}

# iwl_apset <options>
# Set AP with give options. The options are same as iwl_test
iwl_apset()
{
    local apset_str
    local keyidx
    local key
    local mode
    mode=$iwl_band
    iwl_ssh $iwl_apset_cmd --reset || return 1
    tet_infoline "apset with --reset success"
    OPTIND=1
    while getopts "m:c:h:b:q:f:r:s:n:w:k:e:1:2:3:4:a:t:" Option
    do
        case $Option in
	    m) mode=$OPTARG;;
	    c) apset_str="$apset_str CHANNEL $OPTARG";;
	    h) apset_str="$apset_str CHANNEL-WIDTH $OPTARG";;
	    b) apset_str="$apset_str BCAST $OPTARG";;
	    f) apset_str="$apset_str FRAG $OPTARG";;
	    s) apset_str="$apset_str SSID $OPTARG";;
	    n) apset_str="$apset_str NOSSID $OPTARG";;
	    w) apset_str="$apset_str WEP $OPTARG";;
	    k) apset_str="$apset_str KEYIDX $OPTARG"
	       keyidx=$OPTARG
	       ;;
	    e) apset_str="$apset_str ENCRYPT $OPTARG";;
	    1) apset_str="$apset_str KEY1 $OPTARG";;
	    2) apset_str="$apset_str KEY2 $OPTARG";;
	    3) apset_str="$apset_str KEY3 $OPTARG";;
	    4) apset_str="$apset_str KEY4 $OPTARG";;
	    a) apset_str="$apset_str AUTH $OPTARG";;
	    t) apset_str="$apset_str WPA-CRYPTO $OPTARG";;
        esac
    done
    apset_str="MODE $mode $apset_str"

    echo apset_str is $apset_str
    [ -z "$apset_str" ] || iwl_ssh $iwl_apset_cmd $apset_str
    if [ $? -ne 0 ]; then
        tet_infoline "apset with $apset_str fails"
        return 1
    else
        tet_infoline " apset with $apset_str success"
        return 0
    fi
}

iwl_connect_with_wpa()
{
    local conf=$3
    wpa_supplicant -Dwext -iwlan0 -c $conf &
    i=1
    while [ $i -le 20 ]
    do
        sleep 5
        #wpa_cli status |grep "wpa_state=COMPLETED" && break
        iwconfig wlan0 |grep Not-Associated || break
        i=$((i+1))
    done
    #wpa_cli status |grep "wpa_state=COMPLETED" || { tet_infoline "Not associated"; return 1;}
    iwconfig wlan0 |grep Not-Associated && { tet_infoline "Not associated"; return 1;}
    tet_infoline "Associated"
}

iwl_close_wpa()
{
    pkill -9 wpa_supplicant
}

# iwl_scp_copy <peer machine> <file>
# Copy file to a machine and copy back and check if they are same
iwl_scp_copy()
{
    local target=${iwl_srv[1]}
    local file=$2
    local file1=$2_${iwl_ehost}
    if [ -n "$1" -a "$1" != ${iwl_srv[1]} ]; then
        target=$1
    fi
    if [ ! -e $file ]; then
        dd if=/dev/zero of=/tmp/5M bs=1MB count=5
        file=/tmp/5M
    fi

    scp -o ConnectTimeout=60 ${file} $target:${file1} || return 1
    tet_infoline "scp ${file} $target:${file1} success"
    scp -o ConnectTimeout=60 $target:${file1} ${file1} || return 1
    tet_infoline "scp $target:${file1} ${file1} success"
    md1=`md5sum ${file} |awk '{print $1}'`
    md2=`md5sum ${file1} |awk '{print $1}'`
    iwl_ssh $target rm -f ${file1}
    rm -f ${file1}
    if [ $md1 == $md2 ]; then
        return 0
    else
        return 1
    fi
}

iwl_ftp_copy()
{
    echo jjj
}

tpstart()
{
    iwl_tpstart $@
}

iwl_arrayno()
{
    echo $#
}

iwl_tpstart()
{
    local fn=`iwl_arrayno  ${FUNCNAME[@]}`
    local tpno=$((fn-3))
    local tpname=${FUNCNAME[$tpno]}
    local postfix
    case $iwl_band in
        A-ONLY) postfix=_a;;
        B-ONLY) postfix=_b;;
        G-ONLY) postfix=_g;;
        N-ONLY|N5-ONLY) postfix=_n;;
        N2.4-ONLY) postfix=_n2;;
        *) postfix="";;
    esac
    tet_output "201" 0 "${tpname}${postfix}"
    #[ -z "$1" ] || tet_output "202" 0 "$1"
    tet_title "$@"
    FAIL=N
    dmesg -c > /dev/null 2>&1
}

tpresult()
{
    iwl_tpresult $@
}

iwl_tpresult()
{
    tet_infoline "$@"
    dmesg |grep Error && { FAIL=Y; tet_infoline "Error in dmesg"; }
    pkill -9 wpa_supplicant
    if [ $FAIL = N ]
    then
        dmesg -c >/dev/null 2>&1
        tet_result PASS
    else
        dmesg -c
        tet_result FAIL
    fi
    exit
}

iwl_fail()
{
    #local msg=`iwconfig wlan0`
    [ -z "$1" ] || tet_infoline "$@"
    FAIL=Y
    tpresult
    #tet_result FAIL
    #tet_infoline $msg
    #pkill -9 wpa_supplicant
}

get_chans()
{
    #allchans=`iwlist wlan0 channel |grep "^ *Channel" |awk '{print $2}'`
    #since "iwlist" can not list all the supported channels, hard code here.
    is3945 && allchans="01 02 03 04 05 06 07 08 09 10 11 12 13 34 36 38 40 44 46 48 52 56 60 64"
    is4965 && allchans="01 02 03 04 05 06 07 08 09 10 11 36 40 44 48 52 56 60 64 149 153 157 161 165"
    is5000 && allchans="01 02 03 04 05 06 07 08 09 10 11 12 13 36 40 44 48 52 56 60 64 149 153 157 161 165"

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
    if [ -z "$iwl_essid" ]; then
	case $iwl_band in
	    # 5GHz band
	    A-ONLY|N-ONLY|N5-ONLY) iwl_essid=$iwl_ap"-5g";;
	    # 2.4GHz band
	    B-ONLY|G-ONLY|N2.4-ONLY) iwl_essid=$iwl_ap"-2.4g";;
	esac
    fi

    if [ -z "$iwl_ap_mac" ]; then
	iwl_ssh $iwl_apset_cmd --reboot
	ifconfig wlan0 up || { iwl_load_module; ifconfig wlan0 up; }
	for i in 1 2 3 4 5
	do
	    iwlist wlan0 scan |grep -i $iwl_essid -10 > /tmp/aplist && break
	done
	iwl_ap_mac=`cat /tmp/aplist |grep Address |awk '{print $5}'`
	iwl_channel=`cat /tmp/aplist |grep Channel: |awk -F: '{print $2}'`
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



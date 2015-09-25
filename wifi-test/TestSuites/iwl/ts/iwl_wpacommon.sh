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

wpa()
{
    #tpname=$1
    #shift
    #iwl_tpstart $tpname
    iwl_load_module
    iwl_test $@ || iwl_fail
    iwl_close_wpa
    iwl_tpresult
}

wpa2()
{
    # $1
    # 1: mode=0(BSS), proto=WPA
    # 2: mode=0(BSS), proto=RSN (WPA2)
    # 3: mode=1 (IBSS), proto=WPA
    # 4: mode=1 (IBSS), proto=RSN (WPA2)
    # key_idx=$2
    # key_mgmt=(0 WPA-PSK WPA-EAP IEEE8021X NONE WPA-NONE)
    # pair_idx=$3
    # pair=(0 CCMP TKIP)
    # group_idx=$4
    # group=(0 CCMP TKIP WEP104 WEP40 SHARED-WEP104 SHARED-WEP40)
    str=" -S "
    [ $1 -eq 1 -a $2 -eq 1 ] && str=$str" -a psk"
    [ $1 -eq 1 -a $2 -eq 2 ] && str=$str" -a wpa"
    [ $1 -eq 2 -a $2 -eq 1 ] && str=$str" -a psk2"
    [ $1 -eq 2 -a $2 -eq 2 ] && str=$str" -a wpa2"
    [ $2 -eq 3 ] && str=$str" -a radius"
    
    if [ $3 -eq 1 -a $4 -eq 2 ]; then
    	str=$str" -t TKIP+AES"
    else
    	[ $3 -eq 1 ] && str=$str" -t AES"
    	[ $3 -eq 2 ] && str=$str" -t TKIP"
    fi
    [ $4 -eq 3 ] && str=$str" -w enable -k 3" # key3 is 128bit
    [ $4 -eq 4 ] && str=$str" -w enable -k 1" # key1 is 64 (or 40) bit
    [ $4 -eq 5 ] && str=$str" -w enable -k 3 -a shared" # AUTH:shared
    [ $4 -eq 6 ] && str=$str" -w enable -k 1 -a shared" # AUTH:shared
    iwl_genconf wpa_supplicant.conf $@
    
    [ $8 -eq 1 ] && str=$str" -f 300"
    
    info=`cat wpa_supplicant.conf`
    tet_infoline "The wpa_supplicant.conf is"
    tet_infoline "$info"
    #wpa "wpa_test" $str -x wpa_supplicant.conf
    #shift 6
    #wpa $str $@ -x wpa_supplicant.conf
    wpa $str -x wpa_supplicant.conf
}

iwl_genconf()
{
    file=$1
    mode=$2
    # 1: mode=0(BSS), proto=WPA
    # 2: mode=0(BSS), proto=RSN (WPA2)
    # 3: mode=1 (IBSS), proto=WPA
    # 4: mode=1 (IBSS), proto=RSN (WPA2)
    key_idx=$3
    key_mgmt=(0 WPA-PSK WPA-EAP IEEE8021X NONE WPA-NONE)
    # 1: WPA-PSK
    # 2: WPA-EAP
    # 3: IEEE8021X
    # 4: NONE
    # 5: WPA-NONE
    pair_idx=$4
    pair=(0 CCMP TKIP)
    # 1: CCMP
    # 2: TKIP
    group_idx=$5
    group=(0 CCMP TKIP WEP104 WEP40 SHARED-WEP104 SHARED-WEP40)
    # 1: CCMP
    # 2: TKIP
    # 3: WEP104
    # 4: WEP40
    # 5: SHARED-WEP104
    # 6: SHARED-WEP40
    eap_idx=$6
    eap=(0 TLS PEAP TTLS MD5 MSCHAPV2 OTP GTC )
    # 1: TLS
    # 2: PEAP
    # 3: TTLS
    # 4: MD5
    # 5: MSCHAPV2
    # 6: OTP
    # 7: GTC
    phase2_idx=$7
    phase2=(0 MD5 MSCHAPV2 PAP CHAP MSCHAP OTP GTC)
    # 1: MD5
    # 2: MSCHAPV2
    # 3: PAP
    # 4: CHAP
    # 5: MSCHAP
    # 6: OTP
    # 7: GTC
    #iwl_essid=otc-11215947-asus
    Head="ctrl_interface=/var/run/wpa_supplicant\n\
ctrl_interface_group=wheel\n\
network={\n\
scan_ssid=1\n"

    printf "$Head" > $file
    echo 'ssid="'$iwl_essid'"' >> $file
    case $mode in
    	1) echo proto=WPA >> $file;;
    	2) echo proto=RSN >> $file;;
    	3) echo mode=1 >> $file
    	   echo proto=WPA >> $file;;
    	4) echo mode=1 >> $file
    	   echo proto=RSN >> $file;;
    esac
    [ $key_idx -ne 0 ] && echo key_mgmt=${key_mgmt[$key_idx]} >> $file
    case "${key_mgmt[$key_idx]}" in
        WPA-EAP | IEEE8021X )
    	echo 'identity="root"' >> $file
    	echo 'password="wireless"' >> $file
    	echo 'ca_cert="wpa/root.pem"' >> $file;;
        WPA-PSK)
    	echo 'psk="sharedsecret"' >> $file;;
    esac
    [ $group_idx != 0 && $group_idx -le 4 ] && echo group=${group[$group_idx]} >> $file
    # WEP104, using key3
    [ $group_idx -eq 3 ] && printf "wep_key2=$iwl_keyvalue3\nwep_tx_keyidx=2\n" >> $file
    # WEP40, using key1
    [ $group_idx -eq 4 ] && printf "wep_key0=$iwl_keyvalue1\nwep_tx_keyidx=0\n" >> $file
    [ $group_idx -eq 5 ] && printf "wep_key2=$iwl_keyvalue3\nwep_tx_keyidx=2\nauth_alg=SHARED\n" >> $file
    [ $group_idx -eq 6 ] && printf "wep_key0=$iwl_keyvalue1\nwep_tx_keyidx=0\nauth_alg=SHARED\n" >> $file
    [ $pair_idx -ne 0 ] && echo pairwise=${pair[$pair_idx]} >> $file
    [ $eap_idx -ne 0 ] && echo eap=${eap[$eap_idx]} >> $file
    if [ "${eap[$eap_idx]}" == "TLS" ] ;then
    	echo 'client_cert="wpa/cert-clt.pem"' >> $file
    	echo 'private_key="wpa/cert-clt.pem"' >> $file
    	echo 'private_key_passwd="whatever"' >> $file
    fi
    [ $phase2_idx -ne 0 ] && echo phase2='"auth='${phase2[$phase2_idx]}'"' >> $file
    echo } >> $file
    echo 
}


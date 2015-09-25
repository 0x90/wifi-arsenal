#!/bin/bash
#
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

set -x

tet_startup="startup"	    # startup function
tet_cleanup="cleanup"	    # cleanup function

iclist="ic1 ic2 ic3 ic4 ic5 ic6 ic7 ic8 ic9 ic10 ic11 ic12 ic13 ic14 ic15 ic16 ic17 ic18 ic19 ic20 ic21 ic22 ic23 ic24"
ic1="iwcg1"
ic2="iwcg2"
ic3="iwcg4"
ic4="iwcg5"
ic5="iwcg7"
ic6="iwcg8"
ic7="iwcg9"
ic8="iwcg10"
ic9="iwcg11"
ic10="iwcg12"
ic11="iwcg13"
ic12="iwcg14"
ic13="iwcg15"
ic14="iwcg16"
ic15="iwcg18"
ic16="iwcg19"
ic17="iwcg20"
ic18="pros2"
ic19="pros3"
ic20="pros4"
ic21="pros5"
ic22="pros6"
ic23="pros7"
ic24="iwpriv1"

# iwl_param_set <param> <value> <param+value in iwconfig results>
iwl_param_set()
{
    iwconfig wlan0 $1 $2
    sleep 5
    iwconfig wlan0 |grep "$3" - || return 1
    tet_infoline "iwconfig wlan0 $1 $2 success"
}

iwcg1()
{
    tpstart "Load Module"
    iwl_load_module
    iwconfig wlan0 || iwl_fail
    tpresult
}

iwcg2()
{
    tpstart "IWCG essid"
    tet_infoline "Well iwconfig wlan0 any will fail"
    iwl_load_module
    iwconfig wlan0 essid && iwl_fail # Should return error
    #for i in abcdefghijklmnopqrstuvwxyz "ab c" any
    for i in abcdefghijklmnopqrstuvwxyz "ab c"
    do
	iwconfig wlan0 essid "$i"
	iwconfig wlan0 |grep "$i" - || { iwl_fail; break; }
	tet_infoline "iwconfig wlan0 essid $i success"
    done
    tpresult
}

iwcg4()
{
    tpstart "IWCG frequency"
    iwl_load_module
    clist=`iwlist wlan0 freq |grep "Channel [0123456789]* :" |awk '{print $2}'`
    flist=`iwlist wlan0 freq |grep "Channel [0123456789]* :" |awk '{print $4}'`
    for i in $flist
    do
	iwconfig wlan0 freq ${i}G
	iwconfig wlan0 |grep ${i} - || { iwl_fail; break; }    
	tet_infoline "iwconfig wlan0 freq ${i}G success"
	iwlist wlan0 chan |grep "Current Frequency[=:]$i" - || { iwl_fail; break; }    
    done
    tpresult

}

iwcg5()
{
    tpstart "IWCG channels"
    iwl_load_module
    clist=`iwlist wlan0 freq |grep "Channel [0123456789]* :" |awk '{print $2}'`
    for i in $clist
    do
	iwconfig wlan0 channel ${i}
	j=`expr $i + 0 ` # Transfer from "01" to "1"
	iwlist wlan0 chan |grep Current - | grep "Channel $j" -|| { iwl_fail; break; }    
	tet_infoline "iwconfig wlan0 channel ${i} success"
    done
    tpresult

}

iwcg7()
{
    tpstart "IWCG mode"
    iwl_load_module
    for i in ad-hoc managed monitor
    do
	iwconfig wlan0 mode ${i}
	iwconfig  wlan0 |grep -i Mode:${i} - || iwl_fail
	tet_infoline "Change mode to ${i} success"
    done
    tpresult

}

iwcg8()
{
    tpstart "IWCG ap"
    iwl_load_module
    iwconfig wlan0 ap $iwl_ap_mac
    iwconfig wlan0 |grep "$iwl_ap_mac" - || { iwl_fail; break; }
    tet_infoline "Associate to $iwl_ap_mac success"
    tpresult

}

iwcg9()
{
    tpstart "IWCG nick"
    iwl_load_module
    for i in abcdefghijklmnopqrstuvwxyz "ab c" any
    do
	iwconfig wlan0 nick "$i"
	iwconfig wlan0 |grep "$i" - || { iwl_fail; break; }
	tet_infoline "Change nick to $i success"
    done
    tpresult
}

iwcg10()
{
    tpstart "IWCG Bit Rate"
    iwl_load_module
    iwl_test_bss
    tet_infoline "Associate to AP success"
    local rate
    #FIXME: if your AP support more than 54 Mb/s bitrate???
    for i in 1 2 5.5 6 9 11 12 18 24 36 48 54
    do
        iwlist wlan0 scan | grep $iwl_ap_mac -8 - | grep "[: ]$i Mb/s"
        if [ $? -ne 1 ]; then
	    rate="$i"
            iwl_param_set rate "$rate" "Bit Rate=$rate Mb" || { iwl_fail; break; }
            iwl_check ${iwl_srv[1]} || { iwl_fail; tpresult; }
            tet_infoline "Set to bitrate $i success"
        fi
    done
    tpresult
}

iwcg11()
{
    tpstart "IWCG RTS"
    iwl_load_module
    iwl_test_bss
    tet_infoline "Associate to AP success"
    for i in 256 500 1000 2000 2344
    do
        iwl_param_set rts $i "RTS thr=$i" || { iwl_fail; break; }
    done
    iwl_param_set rts off "RTS thr:off" ||  iwl_fail
    tpresult
}

iwcg12()
{
    tpstart "IWCG Fragments"
    iwl_load_module
    iwl_test_bss
    tet_infoline "Associate to AP success"
    for i in 256 500 1000 2000 2344
    do
        iwl_param_set frag $i "Fragment thr[=:]$i" || { iwl_fail; break; }
    done
    iwl_param_set frag off "Fragment thr[=:]off" ||  iwl_fail
    tpresult
}

iwcg13()
{
    tpstart "IWCG key"
    iwl_load_module
    iwconfig wlan0 key 2222000000 [2]
    iwconfig wlan0 |grep "Encryption .* \[2\]" - || iwl_fail
    tet_infoline "iwconfig wlan0 key 2222000000 [2] success"
    iwconfig wlan0 key off
    iwconfig wlan0 key s:aaaaa [4]
    iwconfig wlan0 |grep "Encryption key:6161-6161-61.*\[4\]" - || iwl_fail
    tet_infoline "iwconfig wlan0 key s:aaaaa [4] success"
    iwconfig wlan0 key off
    iwconfig wlan0 |grep "Encryption key:off" -|| iwl_fail
    tet_infoline "iwconfig wlan0 key off success"
    tpresult
}

iwcg14()
{
    tpstart "IWCG Power"
    tet_infoline "Current driver does not support some functionality here"
    iwl_load_module
    iwconfig wlan0 power off || iwl_fail
    iwconfig wlan0 power period 2 || iwl_fail
    iwconfig wlan0 power timeout 300u || iwl_fail
    tpresult
}

iwcg15()
{
    tpstart "IWCG txpower"
    iwl_load_module
    iwl_test_bss
    local value=`iwconfig wlan0 | grep Tx-Power | sed "s/Tx-Power=//" | awk '{print $4}'`
    local i=1
    while [ $i -lt $value ]
    do
        iwl_param_set txpower $i "Tx-Power=$i" || { iwl_fail; break; }
        iwl_check ${iwl_srv[1]} || { iwl_fail; tpresult; }
        i=$((i+1))
    done
    tpresult
}

iwcg16()
{
    tpstart "IWCG retry"
    iwl_load_module
    iwconfig wlan0 retry lifetime 5 || { iwl_fail; break; }
    iwconfig wlan0 retry lifetime 5u || { iwl_fail; break; }
    iwconfig wlan0 retry lifetime 5m || { iwl_fail; break; }
    iwconfig wlan0 retry lifetime 5 || { iwl_fail; break; }
    tpresult
}

iwcg18()
{
    tpstart "IWCG channels/frequencies"
    local chans=(01 02 03 04 05 06 07 08 09 10 11 36 40 44 48 52 56 60)
    local freqs=(2.412 2.417 2.422 2.427 2.432 2.437 2.442 2.447 2.452 2.457 2.462 5.18  5.2 5.22 5.24 5.26 5.28 5.3 5.32)
    local i=0
    iwl_load_module
    for k in ${chans[@]}
    do
        iwl_param_set channel $k "Frequency:${freqs[$i]} GHz" || { iwl_fail; break; }
        i=$((i+1))
    done
    tpresult
}

iwcg19()
{
    tpstart "IWCG channel freqency map"
    local chans=(01 02 03 04 05 06 07 08 09 10 11 36 40 44 48 52 56 60)
    local freqs=(2.412 2.417 2.422 2.427 2.432 2.437 2.442 2.447 2.452 2.457 2.462 5.18  5.2 5.22 5.24 5.26 5.28 5.3 5.32)
    local i=0
    iwl_load_module
    iwconfig wlan0 key [2] 11112222333344445555666677
    ifconfig wlan0 up
    for k in ${chans[@]}
    do
        iwl_param_set channel $k "Frequency:${freqs[$i]} GHz" || { iwl_fail; break; }
        i=$((i+1))
    done
    tpresult
}

iwcg20()
{
    tpstart "IWCG IBSS channel/frequency"
    local chans=(01 02 03 04 05 06 07 08 09 10 11)
    local freqs=(2.412 2.417 2.422 2.427 2.432 2.437 2.442 2.447 2.452 2.457 2.462)
    local i=0
    iwl_load_module
    iwconfig wlan0 mode ad-hoc
    ifconfig wlan0 up
    for k in ${chans[@]}
    do
        iwl_param_set channel $k "Frequency:${freqs[$i]} GHz" || { iwl_fail; break; }
        i=$((i+1))
    done
    tpresult
}

pros2()
{
    tpstart "Promiscuous mode monitor to managed mode"
    iwl_load_module
    iwconfig wlan0 mode monitor
    tet_infoline "Set mode to monitor"
    ifconfig wlan0 up
    ifconfig wlan0 down
    iwconfig wlan0 mode managed
    iwconfig wlan0 channel 4
    iwconfig wlan0 |grep -i Mode:Managed - || iwl_fail
    tet_infoline "Set mode to managed success"
    tpresult
}

pros3()
{
    tpstart "Promiscuous mode managed to monitored mode"
    iwl_load_module
    iwconfig wlan0 mode managed
    tet_infoline "Set mode to managed"
    ifconfig wlan0 up
    ifconfig wlan0 down
    iwconfig wlan0 mode monitor
    iwconfig wlan0 channel 4
    iwconfig wlan0 |grep -i Mode:Monitor - || iwl_fail
    tet_infoline "Set mode to monitor success"
    tpresult
}

pros4()
{
    tpstart "Promiscuous mode Monitor to adhoc"
    iwl_load_module
    ifconfig wlan0 down
    iwconfig wlan0 mode monitor
    tet_infoline "Set mode to monitor"
    ifconfig wlan0 up
    ifconfig wlan0 down
    iwl_test_ibss || fail
    tet_infoline "Set mode to adhoc success"
    tpresult
}

pros5()
{
    tpstart "Promiscuous mode Adhoc to monitor"
    iwl_load_module
    iwconfig wlan0 mode ad-hoc
    tet_infoline "Set mode to adhoc"
    ifconfig wlan0 up
    ifconfig wlan0 down
    iwconfig wlan0 mode monitor
    tet_infoline "Set mode to monitor success"
    iwconfig wlan0 channel 4
    iwconfig wlan0 |grep -i Mode:Monitor - || iwl_fail
    tpresult
}

pros6()
{
    tpstart "Promiscuous mode driver unload"
    iwl_load_module
    ifconfig wlan0 down
    iwconfig wlan0 mode monitor
    iwconfig wlan0 channel 4
    ifconfig wlan0 up
    modprobe -r iwl4965 || iwl_fail
    tpresult
}

pros7()
{
    tpstart "Promiscuous monitored mode"
    iwl_load_module
    ifconfig wlan0 down
    iwconfig wlan0 mode monitor
    tet_infoline "Set mode to monitor"
    iwconfig wlan0 mode managed
    tet_infoline "Set mode to managed"
    iwconfig wlan0 up
    iwl_test || iwl_fail
    tet_infoline "Associate to AP success"
    tpresult
}

iwpriv1()
{
    tpstart "IWCG iwpriv"
    iwpriv wlan0 || iwl_fail
    tpresult

}

. iwl_common.sh
. $TVS_ROOT/lib/TVSFunctions.sh

# execute shell test case manager - must be last line
. $TET_ROOT/lib/xpg3sh/tcm.sh

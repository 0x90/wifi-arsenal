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

tet_startup="startup"			# startup function
tet_cleanup="cleanup"			# cleanup function

iclist="ic1 ic2 ic3 ic4 ic5 ic6 ic7 ic8 ic9 ic10 ic11 ic12 ic13 ic14 ic15 ic16 ic17 ic18 ic19 ic20 ic21 ic22 ic23 ic24 ic25 ic26 ic27 ic28 ic29 ic30 ic31 ic32 ic33 ic34 ic35 ic36 ic37 ic38 ic39 ic40 ic41 ic42 ic43 ic44 ic45 ic46 ic47 ic48 ic49 ic50 ic51 ic52 ic53 ic54 ic55 ic56 ic57 ic58 ic59"
ic1="perf1111"
ic2="perf1112"
ic3="perf1121"
ic4="perf1122"
ic5="perf1131"
ic6="perf1132"
ic7="perf1141"
ic8="perf1142"
ic9="perf1151"
ic10="perf1152"
ic11="perf1161"
ic12="perf1162"
ic13="perf1171"
ic14="perf1172"
ic15="perf2111"
ic16="perf2112"
ic17="perf2121"
ic18="perf2122"
ic19="perf2131"
ic20="perf2132"
ic21="perf2141"
ic22="perf2142"
ic23="perf2151"
ic24="perf2152"
ic25="perf2161"
ic26="perf2162"
ic27="perf2171"
ic28="perf2172"
ic29="perf1211"
ic30="perf1212"
ic31="perf1221"
ic32="perf1222"
ic33="perf1231"
ic34="perf1232"
ic35="perf2211"
ic36="perf2212"
ic37="perf2221"
ic38="perf2222"
ic39="perf2231"
ic40="perf2232"
ic41="perf1311"
ic42="perf1312"
ic43="perf1321"
ic44="perf1322"
ic45="perf1331"
ic46="perf1332"
ic47="perf2311"
ic48="perf2312"
ic49="perf2321"
ic50="perf2322"
ic51="perf2331"
ic52="perf2332"
ic53="perf21421"
ic54="perf21511"
ic55="perf21521"
ic56="perf21611"
ic57="perf21621"
ic58="perf21711"
ic59="perf21721"

perf_tool=(0 iperf scp)
perf_mode=(0 BSS PEER IBSS)
perf_security=(0 Open WEP40 WEP104 WPA-PSK WPA-EAP WPA2-PSK WPA2-EAP)
perf_updown=(0 Upload Download)
perf_frag=(0 Frag)
perf_file_size=300

# perf <tool> <mode> <security> <upload>
# tool: 1: iperf 2: scp
# mode: 1: BSS AP (Another machine wire correct to AP) 
#	2: BSS Peer (Two wireless machine)
#	3: IBSS
# security: 1: None 2: WEP40 3: WEP104 4: WPA PSK 
#	5: WPA EAP 6: WPA2 PSK 7: WPA2 EAP
# updown: 1: Upload 2: Download
perf()
{    
    local str=""
    local peer=${iwl_peer[1]};
    local peer_name=${iwl_peer[0]};
    local hn=`hostname -s`
    tpstart
    perf_title=`get_title $@`
    case $iwl_band in
        B-ONLY|G-ONLY|N2.4-ONLY)
            str="$str -c 1"
            ;;
        A-ONLY|N-ONLY|N5-ONLY)
            # TODO: Need change back to 149, now workaround is using channel 48 because of bug #1931
            str="$str -c 48"
            ;;
    esac
    # TODO: Should merge after bug #1931 resolved
    case $iwl_band in
        B-ONLY)
            perf_file_size=50
            ;;
        G-ONLY)
            perf_file_size=100
            ;;
        A-ONLY)
            perf_file_size=100
            ;;
        N2.4-ONLY|N-ONLY|N5-ONLY)
            perf_file_size=300
            ;;
    esac
    iwl_load_module
    perf_connect $2 $3 $5
    if [ $2 -eq 1 ]; then
        peer=${iwl_srv[1]}
        peer_name=${iwl_srv[0]}
    fi
    if [ $1 -eq 1 ]; then
        perf_iperf $peer $4
    else
        # Prepare file to be download
        if [ $4 -eq 2 ]; then
            ssh $peer_name "dd if=/dev/zero of=/tmp/perf.$hn bs=1MB count=$perf_file_size"
        else
            dd if=/dev/zero of=/tmp/perf bs=1MB count=$perf_file_size
        fi
        perf_scp $peer $4
    fi
    #tet_infoline "data transfer rate is $iwl_rate"
    tpresult $iwl_rate

    return $?
}

# perf_iperf <peer machine> <updown>
perf_iperf()
{
    if [ $2 -eq 1 ]; then
	ssh $1 "pkill -9 iperf"
	ssh $1 "/usr/local/bin/iperf -s" &
    else
	pkill -9 iperf
	iperf -s &
    fi
    sleep 3
    i=1
    iwl_rate=0
    while [ $i -lt 4 ]; do
	if [ $2 -eq 1 ]; then
	    ipeer=`echo $1 |sed "s/test@//"`
	    rate=`iperf -fm -c $ipeer -t 100 |tail -n 1 | sed "s/.*Bytes//" | awk '{print $1}'`
	else
	    rate=`ssh $1 "/usr/local/bin/iperf -fm -c ${iwl_host[1]} -t 100" |tail -n 1 | sed "s/.*Bytes//" | awk '{print $1}'`
	fi
	if [ ! -z $rate ]; then
	    iret=`echo "$rate >= $iwl_rate" |bc`
	    [ $iret -eq 1 ] && iwl_rate=$rate
	fi
	i=$((i+1))
    done
    if [ $2 -eq 1 ]; then
	ssh $1 "pkill -9 iperf"
    else
	pkill -9 iperf
    fi
}

# perf_scp <peer machine> <updown>
perf_scp()
{
    local hn=`hostname -s`
    local iret=1
    i=1
    iwl_rate=0
    # Get the best transfer rate
    while [ $i -lt 4 ]; do
	if [ $2 -eq 1 ]; then
	    dur1=`(set +x; time -p scp /tmp/perf ${1}:/tmp/perf.$hn)2>&1`
	else
	    dur1=`(set +x; time -p scp ${1}:/tmp/perf.$hn /tmp/perf.$hn)2>&1`
	fi
	if [ $? -ne 0 ]; then
            tet_infoline "scp file failed"
            iwl_fail; break;
        fi
	dur=`echo $dur1 |awk '{print $5}'`
	rate=`echo "scale=3; $perf_file_size*8/$dur" |bc -l`
	if [ ! -z $rate ]; then
	    iret=`echo "$rate >= $iwl_rate" |bc`
	    [ $iret -eq 1 ] && iwl_rate=$rate
	fi
	i=$((i+1))
    done
	
}


# TODO: Need hack wpa in iwl_wpacommon.sh
# perf_connect  <mode> <security>
perf_connect()
{
    # security: 1: None 2: WEP40 3: WEP104 4: WPA PSK 
    #	5: WPA EAP 6: WPA2 PSK 7: WPA2 EAP
    if [ ! -z $3 ] && [ $3 -eq 1 ]; then
        case $2 in
            2) str="$str -w enable -k 1 -f 300";;
            3) str="$str -w enable -k 3 -f 300";;
            4) wpa2 1 2 2 2 1 0 0 1; return $?;;
            5) wpa2 2 1 1 1 0 0 0 1; return $?;;
            6) wpa2 2 1 1 1 0 0 0 1; return $?;;
            7) wpa2 2 2 1 1 1 0 0 1; return $?;;
        esac
    else
        case $2 in
            2) str="$str -w enable -k 1";;
            3) str="$str -w enable -k 3";;
            4) wpa2 1 2 2 2 1 0; return $?;;
            5) wpa2 2 1 1 1 0 0; return $?;;
            6) wpa2 2 1 1 1 0 0; return $?;;
            7) wpa2 2 2 1 1 1 0; return $?;;
        esac
    fi

    # mode: 1: BSS AP (Another machine wire correct to AP) 
    #	2: BSS Peer (Two wireless machine)
    #	3: IBSS
    case $1 in
	1) iwl_test_bss $str;;
	2) iwl_test_peer $str;;
	3) iwl_test_ibss $str;;
    esac
    return $?
}

# get_title <tool> <mode> <security> <upload>
get_title()
{
    echo "${perf_tool[$1]}_${perf_mode[$2]}_${perf_security[$3]}_${perf_updown[$4]}_${perf_frag[$5]}"
}

perf1111()
{
    #tpstart "PERF: iperf BSS Open Upload"
    perf 1 1 1 1 || iwl_fail
}

perf1112()
{
    #tpstart "PERF: iperf BSS Open Download"
    perf 1 1 1 2 || iwl_fail
}

perf1121()
{
    #tpstart "PERF: iperf BSS WEP40 Upload"
    perf 1 1 2 1 || iwl_fail 
}

perf1122()
{
    #tpstart "PERF: iperf BSS WEP40 Download"
    perf 1 1 2 2 || iwl_fail
}

perf1131()
{
    #tpstart "PERF: iperf BSS WEP104 Upload"
    perf 1 1 3 1 || iwl_fail 
}

perf1132()
{
    #tpstart "PERF: iperf BSS WEP104 Download"
    perf 1 1 3 2 || iwl_fail
}

perf1141()
{
    #tpstart "PERF: iperf BSS WPA-PSK Upload"
    perf 1 1 4 1 || iwl_fail
}

perf1142()
{
    #tpstart "PERF: iperf BSS WPA-PSK Download"
    perf 1 1 4 2 || iwl_fail
}

perf1151()
{
    #tpstart "PERF: iperf BSS WPA-EAP Upload"
    perf 1 1 5 1 || iwl_fail 
}

perf1152()
{
    #tpstart "PERF: iperf BSS WPA-EAP Download"
    perf 1 1 5 2 || iwl_fail
}

perf1161()
{
    #tpstart "PERF: iperf BSS WPA2-PSK Upload"
    perf 1 1 6 1 || iwl_fail 
}

perf1162()
{
    #tpstart "PERF: iperf BSS WPA2-PSK Download"
    perf 1 1 6 2 || iwl_fail
}

perf1171()
{
    #tpstart "PERF: iperf BSS WPA2-EAP Upload"
    perf 1 1 7 1 || iwl_fail 
}

perf1172()
{
    #tpstart "PERF: iperf BSS WPA2-EAP Download"
    perf 1 1 7 2 || iwl_fail
}

perf2111()
{
    #tpstart "PERF: scp BSS Open Upload"
    perf 2 1 1 1 || iwl_fail
}

perf2112()
{
    #tpstart "PERF: scp BSS Open Download"
    perf 2 1 1 2 || iwl_fail
}

perf2121()
{
    #tpstart "PERF: scp BSS WEP40 Upload"
    perf 2 1 2 1 || iwl_fail 
}

perf2122()
{
    #tpstart "PERF: scp BSS WEP40 Download"
    perf 2 1 2 2 || iwl_fail
}

perf2131()
{
    #tpstart "PERF: scp BSS WEP104 Upload"
    perf 2 1 3 1 || iwl_fail 
}

perf2132()
{
    #tpstart "PERF: scp BSS WEP104 Download"
    perf 2 1 3 2 || iwl_fail
}

perf2141()
{
    #tpstart "PERF: scp BSS WPA-PSK Upload"
    perf 2 1 4 1 || iwl_fail
}

perf2142()
{
    #tpstart "PERF: scp BSS WPA-PSK Download"
    perf 2 1 4 2 || iwl_fail
}

perf2151()
{
    #tpstart "PERF: scp BSS WPA-EAP Upload"
    perf 2 1 5 1 || iwl_fail 
}

perf2152()
{
    #tpstart "PERF: scp BSS WPA-EAP Download"
    perf 2 1 5 2 || iwl_fail
}

perf2161()
{
    #tpstart "PERF: scp BSS WPA2-PSK Upload"
    perf 2 1 6 1 || iwl_fail 
}

perf2162()
{
    #tpstart "PERF: scp BSS WPA2-PSK Download"
    perf 2 1 6 2 || iwl_fail
}

perf2171()
{
    #tpstart "PERF: scp BSS WPA2-EAP Upload"
    perf 2 1 7 1 || iwl_fail 
}

perf2172()
{
    #tpstart "PERF: scp BSS WPA2-EAP Download"
    perf 2 1 7 2 || iwl_fail
}

perf1211()
{
    #tpstart "PERF: iperf PEER Open Upload"
    perf 1 2 1 1 || iwl_fail
}

perf1212()
{
    #tpstart "PERF: iperf PEER Open Download"
    perf 1 2 1 2 || iwl_fail
}

perf1221()
{
    #tpstart "PERF: iperf PEER WEP40 Upload"
    perf 1 2 2 1 || iwl_fail 
}

perf1222()
{
    #tpstart "PERF: iperf PEER WEP40 Download"
    perf 1 2 2 2 || iwl_fail
}

perf1231()
{
    #tpstart "PERF: iperf PEER WEP104 Upload"
    perf 1 2 3 1 || iwl_fail 
}

perf1232()
{
    #tpstart "PERF: iperf PEER WEP104 Download"
    perf 1 2 3 2 || iwl_fail
}

perf2211()
{
    #tpstart "PERF: scp PEER Open Upload"
    perf 2 2 1 1 || iwl_fail
}

perf2212()
{
    #tpstart "PERF: scp PEER Open Download"
    perf 2 2 1 2 || iwl_fail
}

perf2221()
{
    #tpstart "PERF: scp PEER WEP40 Upload"
    perf 2 2 2 1 || iwl_fail 
}

perf2222()
{
    #tpstart "PERF: scp PEER WEP40 Download"
    perf 2 2 2 2 || iwl_fail
}

perf2231()
{
    #tpstart "PERF: scp PEER WEP104 Upload"
    perf 2 2 3 1 || iwl_fail 
}

perf2232()
{
    #tpstart "PERF: scp PEER WEP104 Download"
    perf 2 2 3 2 || iwl_fail
}

perf1311()
{
    #tpstart "PERF: iperf IBSS Open Upload"
    perf 1 3 1 1 || iwl_fail
}

perf1312()
{
    #tpstart "PERF: iperf IBSS Open Download"
    perf 1 3 1 2 || iwl_fail
}

perf1321()
{
    #tpstart "PERF: iperf IBSS WEP40 Upload"
    perf 1 3 2 1 || iwl_fail 
}

perf1322()
{
    #tpstart "PERF: iperf IBSS WEP40 Download"
    perf 1 3 2 2 || iwl_fail
}

perf1331()
{
    #tpstart "PERF: iperf IBSS WEP104 Upload"
    perf 1 3 3 1 || iwl_fail 
}

perf1332()
{
    #tpstart "PERF: iperf IBSS WEP104 Download"
    perf 1 3 3 2 || iwl_fail
}

perf2311()
{
    #tpstart "PERF: scp IBSS Open Upload"
    perf 2 3 1 1 || iwl_fail
}

perf2312()
{
    #tpstart "PERF: scp IBSS Open Download"
    perf 2 3 1 2 || iwl_fail
}

perf2321()
{
    #tpstart "PERF: scp IBSS WEP40 Upload"
    perf 2 3 2 1 || iwl_fail 
}

perf2322()
{
    #tpstart "PERF: scp IBSS WEP40 Download"
    perf 2 3 2 2 || iwl_fail
}

perf2331()
{
    #tpstart "PERF: scp IBSS WEP104 Upload"
    perf 2 3 3 1 || iwl_fail 
}

perf2332()
{
    #tpstart "PERF: scp IBSS WEP104 Download"
    perf 2 3 3 2 || iwl_fail
}
perf21421()
{
    #tpstart "PERF: scp BSS WPA-PSK Download Frag"
    perf 2 1 4 2 1 || iwl_fail
}

perf21511()
{
    #tpstart "PERF: scp BSS WPA-EAP Upload Frag"
    perf 2 1 5 1 1 || iwl_fail
}

perf21521()
{
    #tpstart "PERF: scp BSS WPA-EAP Download Frag"
    perf 2 1 5 2 1 || iwl_fail
}

perf21611()
{
    #tpstart "PERF: scp BSS WPA2-PSK Upload Frag"
    perf 2 1 6 1 1 || iwl_fail
}

perf21621()
{
    #tpstart "PERF: scp BSS WPA2-PSK Download Frag"
    perf 2 1 6 2 1 || iwl_fail
}

perf21711()
{
    #tpstart "PERF: scp BSS WPA2-EAP Upload Frag"
    perf 2 1 7 1 1 || iwl_fail
}
perf21721()
{
    #tpstart "PERF: scp BSS WPA2-EAP Download Frag"
    perf 2 1 7 2 1 || iwl_fail
}

. iwl_wpacommon.sh
. iwl_common.sh

tpstart()
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
        	*) 	postfix="";;
    esac
    tet_output "201" 0 "${tpname}${postfix}"
    #tet_title "$@"
    FAIL=N
    dmesg -c > /dev/null 2>&1
}

tpresult()
{
    tet_title "${perf_title} $@ Mbits/s"
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
    [ -z "$1" ] || tet_infoline "$@"
    FAIL=Y
    tpresult
}

wpa()
{
    iwl_test $@ || iwl_fail
}

. $TVS_ROOT/lib/TVSFunctions.sh

# execute shell test case manager - must be last line
. $TET_ROOT/lib/xpg3sh/tcm.sh

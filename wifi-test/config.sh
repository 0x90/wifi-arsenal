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
#!/bin/bash

TET_ROOT=/usr/tet
TVS_ROOT=$TET_ROOT/TVS
build_dir=`pwd`
export TET_ROOT TVS_ROOT build_dir

full=0
listing=0
download_tet=0
radius=0

OPTIND=1
while getopts "flrt" Option
do
    case $Option in
        f) full=1;;
	l) listing=1;;
	r) radius=1;;
	t) read -p "TET license is Artistic, will you download? (y/n)" down 
	   if [ "$down" != "y" ]; then
		echo Sorry, this test suite does not work without TET
		echo We will support none-TET in the future
		exit
	   fi
	  download_tet=1;;
    esac

done
cat << EOF
The test environment is like this:
  --------------
 | Test Machine |
  --------------\
                 \ ---------                    --------
                  | Test    |     -------      |  AP    |   ------------
                  | machine |----| Server |----| network|--| AP (Cisco) |
                  | network |     -------      |        |   ------------
                 / ---------                    --------
  ------------- /
 | Peer Machine |
  --------------

+ There are two networks. The first is test machine network.  The other is 
  AP network. Server connects to both network so that test machine can set
  different parameters in APs
+ Two machines needed: Test Machine is the target machine,
  Peer Machine is used as its peer in IBSS testing. 
+ You should run this script in Test Machine as root. You also need to input the 
  hostname of Peer Machine and Server, and root password of Peer machine and Server
+ We define default value for: AP network IP address: 192.168.1.*, Test Machine(101)
  Peer Machine(102), Server(100), AP1(11). You need use -f to set these values

EOF

iwl_apnet=192.168.1
iwl_whost=${iwl_apnet}.101
iwl_wpeer=${iwl_apnet}.102
iwl_wsrv=${iwl_apnet}.100
iwl_wap=${iwl_apnet}.11
iwl_ap=wifi-test-cisco
#read -p "The hostname of machine Test Machine: " iwl_ehost || exit 1
#[ -z "$iwl_ehost" ] || iwl_ehost=`hostname -s`
iwl_ehost=`hostname -s`

read -p "The hostname of machine Peer Machine: " iwl_epeer 
[ -z "$iwl_epeer" ] && exit 1

read -p "The hostname of machine Server: " iwl_esrv 
[ -z "$iwl_esrv" ] && exit 1

if [  $full -eq 1 ]; then
    read -p "The IP address of machine Server in AP network: " iwl_wsrv 
    [ -z "$iwl_wsrv" ] && exit 1
    net=`echo $iwl_wsrv | awk -F. '{printf "%d.%d.%d",$1,$2,$3}'`
    read -p "The IP address of AP1 (${net}.1): " iwl_wap
    [ -z "$iwl_wap" ] && iwl_wap=${net}.1
    read -p "The IP address of $iwl_ehost (${net}.101): " iwl_whost
    [ -z "$iwl_whost" ] && iwl_whost=${net}.101
    read -p "The IP address of $iwl_epeer (${net}.102): " iwl_wpeer
    [ -z "$iwl_wpeer" ] && iwl_wpeer=${net}.102
fi

eap_server=$iwl_wsrv
eap_auth_port="1812"
eap_key="sharedsecret"
if [ $radius -eq 1 ]; then
    read -p "IP address of eap server ($iwl_wsrv): " eap_server
    [ -z "$eap_server" ] && eap_server=$iwl_wsrv
    read -p "eap authentication port (1812): " eap_auth_port
    [ -z "$eap_auth_port" ] && eap_auth_port="1812"
    read -p "eap shared secret (sharedsecret): " eap_key
    [ -z "$eap_key" ] && eap_key="sharedsecret"
fi

echo Test Machine: $iwl_ehost Peer Machine: $iwl_epeer Server: $iwl_esrv
echo Wireless IP address: Server : $iwl_wsrv AP: $iwl_wap, 
echo ${iwl_ehost}: $iwl_whost ${iwl_epeer}: $iwl_wpeer

grep -v "^ *StrictHostKeyChecking.*"  /etc/ssh/ssh_config > /tmp/jjj
echo "StrictHostKeyChecking no" >> /tmp/jjj
cp /tmp/jjj /etc/ssh/ssh_config

if [ ! -f ~/.ssh/id_rsa.pub ]; then
    ssh-keygen -P "" -f ~/.ssh/id_rsa
fi
echo copying ssh key to $iwl_esrv, might request password for root@$iwl_esrv
ssh-copy-id -i ~/.ssh/id_rsa.pub $iwl_esrv
echo copying ssh key to $iwl_epeer, might request password for root@$iwl_epeer
ssh-copy-id -i ~/.ssh/id_rsa.pub $iwl_epeer

# Build & install TVS, you must first install tet
if [ $download_tet -eq 1 ]; then
    mkdir -p $build_dir/tet
    cd $build_dir/tet
    wget http://tetworks.opengroup.org/tet/tet3.7a-unsup.src.tar.gz
    tar zxf tet3.7a-unsup.src.tar.gz
    sh configure -t lite
    cd src; make; make install
    cd .. 
    mkdir -p $TET_ROOT;
    cp -r bin inc lib $TET_ROOT
fi
#cd $build_dir/tvs
cd $build_dir
make; make install

cd $build_dir
#cat 1>tvs_env << EOF
cat 1>$TVS_ROOT/tsets/iwl/tvs_env << EOF
iwl_band=G-ONLY
iwl_ap=$iwl_ap
iwl_wap=$iwl_wap
iwl_apset_cmd="$iwl_esrv /usr/local/bin/apset/cisco/apset.cisco"
iwl_esrv=$iwl_esrv
iwl_wsrv=$iwl_wsrv
iwl_epeer=$iwl_epeer
iwl_wpeer=$iwl_wpeer
iwl_whost=$iwl_whost
iwl_load_module_vendor=iwl_load_iwlwifi

export iwl_band
export iwl_ap iwl_wap iwl_apset_cmd
export iwl_esrv iwl_wsrv
export iwl_whost iwl_ehost
export iwl_epeer iwl_wpeer
export iwl_load_module_vendor

env
EOF

if [ $listing -eq 1 ]; then
#cat 1>TVSListing << EOF
cat 1>$TVS_ROOT/etc/TVSListing << EOF
iwl Start_G_Band
iwl sanity
EOF

fi

# Setting cisco apset default value
cd $build_dir
cat 1>apset/cisco/config.pm << EOF
package config;

\$ap = "$iwl_wap";
\$ssid_2g="${iwl_ap}-2.4g";
\$ssid_5g="${iwl_ap}-5g";
\$EAP_Server="$eap_server";
\$EAP_Auth_Port="$eap_auth_port";
#\$EAP_Acct_Port="1813";

# In general, you don't need change these values
\$Shared_Secret="$eap_key";
\$channel_2g=11;
\$channel_5g=149;
\$KEYVALUE1="1111000000";
\$KEYVALUE2="2222000000";
\$KEYVALUE3="11112222333344445555666611";
\$KEYVALUE4="12345678901234567890123456";

\$AP_Login="Cisco";
\$AP_Password="Cisco";
\$AP_Enable_Password="Cisco";
\$psk_key="sharedsecret";

EOF

# All apset script are in /usr/local/bin/apset in server
scp -r apset $iwl_esrv:/usr/local/bin


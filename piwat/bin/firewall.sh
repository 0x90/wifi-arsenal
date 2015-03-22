#!/bin/bash

lan="wlan2"
internet="eth0"

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


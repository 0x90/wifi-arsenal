#!/usr/bin

# Install script for fresh Kali Linux (1.0.7) install on Raspberry Pi

# Change SSH host keys
rm /etc/ssh/ssh_host_*
dpkg-reconfigure openssh-server
service ssh restart

# Install git
apt-get update && apt-get install -y ntp libxml2-dev libxslt-dev pyrit

# Downlaod snoopy-ng from https://github.com/sensepost/snoopy-ng
git clone https://github.com/sensepost/snoopy-ng.git

# Install snoopy via insall.sh
(cd snoopy-ng && bash ./install.sh)

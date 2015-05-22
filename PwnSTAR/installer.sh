#!/bin/bash

# Version: 20140506

# Copyright (C) 2014  VulpiArgenti

warn="\e[1;31m"      # warning           red
info="\e[1;34m"      # info              blue
q="\e[1;32m"         # questions         green

echo -e "$info\n      PwnSTAR INSTALLER"
echo -e "$info      =================\n"
if [[ "$(id -u)" != "0" ]]; then
    echo -e "$warn\nThis script must be run as root" 1>&2
exit 0
fi
echo -e "$warn\nImportant: run this installer from the same directory as the git clone eg /git/PwnSTAR\n"
sleep 1
echo -e "$q\nWhere are we installing PwnSTAR? e.g. /usr/bin"
read var
if [[ ! $var =~ ^/ ]];then  # if "/" is omitted eg "opt"
    var="/""$var"           # then add it
fi
if [[ ! -d $var/PwnSTAR/ ]];then
    mkdir $var/PwnSTAR/
fi
chmod 744 pwnstar && cp -bi --preserve pwnstar $var/
cp How_to_use.txt $var/PwnSTAR/
if [[ -x $var/pwnstar ]];then
    echo -e "$info\nPwnSTAR installed to $var\n"
else
    echo -e "$warn\nFailed to install PwnSTAR!\n"
fi

echo -e "$info\nSetting web page permissions"
cd html/
for folder in $(find $PWD -maxdepth 1 -mindepth 1 -type d); do
    chgrp -R www-data $folder
    chmod -f 774 $folder/*.php
    chmod -f 664 $folder/formdata.txt
    cp -Rb --preserve $folder /var/www/
    if [[ $? == 0 ]];then
        echo -e "$info\n$folder moved successfully..."
    else
        echo -e "$warn\nError moving $folder!\nPlease check manually"
    fi
done

declare -a progs=(Eterm macchanger aircrack-ng ferret sslstrip apache2 dsniff)
for i in ${progs[@]}; do
    echo -e "$info"
    if [[ ! -x /usr/bin/"$i" ]] && [[ ! -x /usr/sbin/"$i" ]] && [[ ! -x /usr/share/"$i" ]];then
	i="$(tr [A-Z] [a-z] <<< "$i")" 	# to deal with Eterm/eterm
	apt-get install "$i"
    else
	echo -e "$info\n$i already present"
    fi
done

if [[ ! -x /usr/sbin/dhcpd ]];then
    echo -e "$q\nInstall isc-dhcp-server? (y/n)"
    read var
    if [[ $var == y ]];then
        apt-get install isc-dhcp-server
    fi
else
    echo -e "$info\nIsc-dhcp-server already present"
fi

if [[ ! -e /usr/sbin/incrond ]];then 
    echo -e "$q\nInstall incron?"
    read var
    if [[ $var == y ]];then
        apt-get install incron
    fi
else
    echo -e "$info\nIncron already present\n"
fi

if [[ ! -x  /usr/bin/mdk3 ]] && [[ ! -x /usr/sbin/mdk3 ]] && [[ ! -x  /usr/share/mdk3 ]];then
    if [[ $(cat /etc/issue) =~ Kali ]];then
	apt-get install mdk3
    else
	echo -e "$info\nInstalling MDK3 to usr/bin"
	wget http://homepages.tu-darmstadt.de/~p_larbig/wlan/mdk3-v6.tar.bz2
	tar -xvjf mdk3-v6.tar.bz2
	cd mdk3-v6
	sed -i 's|-Wall|-w|g' ./Makefile
	sed -i 's|-Wextra||g' ./Makefile
	sed -i 's|-Wall||g' ./osdep/common.mak
	sed -i 's|-Wextra||g' ./osdep/common.mak
	sed -i 's|-Werror|-w|g' ./osdep/common.mak
	sed -i 's|-W||g' ./osdep/common.mak
	make
	chmod +x mdk3
	cp -Rb --preserve mdk3 /usr/bin
	cd ..
    fi
else
    echo -e "$info\nMDK3 already present\n"
fi

echo -e "$info\nFinished. \nIf there were no error messages, you can safely delete the git clone.

Run by typing \"pwnstar\" (presuming your installation directory is on the path).

The README is in $var/PwnSTAR/

Note: this script does not install metasploit\n"
sleep 2
exit 0

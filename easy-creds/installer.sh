#!/bin/bash
# installer easy-creds v3.8-DEV
# Last updated 09/03/2013 - J0hnnyBrav0

##################################################
f_debian(){
	#Which DHCP server to install
	dhcpinstall=$(apt-cache search isc-dhcp-server)
	if ( ! -z "${dhcpinstall}" ) ; then
		dhcpserver="isc-dhcp-server" #New version
	else
		dchpserver="dhcp3-server" #Old version for older distros
	fi

	clear
	f_Banner
	if [ ! -e /etc/lsb-release ] && [ ! -e /etc/issue ]; then echo -n -e "\e[1;31m[!]\e[0m I can't confirm this is a Debian\Ubuntu machine. Installs may fail."; read; fi
	f_install

	echo -e "\n\e[1;33m[*]\e[0m Installing pre-reqs for Debian/Ubuntu...\n"
	echo -e "\e[1;33m[*]\e[0m Running 'updatedb'\n"
	updatedb

	reqs="cmake gcc g++ subversion wget libssl-dev libpcap0.8 libpcap0.8-dev libssl-dev libssl0.9.8 libssl1.0.0 libtool hostapd dsniff ipcalc ${dhcpserver} aircrack-ng xterm"

	for i in $reqs; do
		dpkg -s "$i" &> /tmp/ec-install/checkinstall
		isinstalled=$(cat /tmp/ec-install/checkinstall | grep -o "Status: install ok installed")
		if [ ! -e /usr/bin/$i ] && [ ! -e /usr/sbin/$i ] && [ ! -e /usr/local/sbin/$i ] && [ ! -e /usr/local/bin/$i ] && [ -z "$isinstalled" ]; then
				echo -e "\e[1;33m[-]\e[0m $i is not installed, will attempt to install..."
			if [ ! -z $(apt-get install -y "$i" | grep -o "E: Couldn") ]; then
				echo -e "\e[1;31m[-]\e[0m $i could not be installed from the repository"
				touch /tmp/ec-install/$i-fail
			else
				dpkg -s "$i" &> /tmp/ec-install/checkinstall
				isinstalled=$(cat /tmp/ec-install/checkinstall | grep -o "Status: install ok installed")				
				if [ ! -z "$isinstalled" ]; then
					update=1
					echo -e "\t\e[1;32m[+]\e[0m $i was successfully installed from the repository."
				else
					echo -e "\t\e[1;31m[!]\e[0m Something went wrong, unable to install $i."
					touch /tmp/ec-install/$i-fail
				fi
			fi
		else
			echo -e "\e[1;32m[+]\e[0m I found $i installed on your system"
		fi
        done
echo -n -e "\e[1;31m[!]\e[0m If you received an error for libssl this is expected as long as one of them installed properly.\n\n"
sleep 5

if [ -e /tmp/ec-install/aircrack-ng-fail ]; then
	f_aircrackinstall
fi
f_sslstripinstall
f_ettercapinstall
f_hamsterinstall
f_ferretinstall
f_frinstall
f_asleapinstall
f_metasploitinstall

if [ "$update" == "1" ]; then
	echo -e "\e[1;33m[*]\e[0m Running 'updatedb' again because we installed some new stuff\n"
	updatedb
	echo -e "\n\e[1;33m...happy hunting!\e[0m\n\n"
else
	echo -e "\n\e[1;33m...happy hunting!\e[0m\n\n"
fi

rm -rf /tmp/ec-install/
}

##################################################
f_rhfedora(){
	clear
	f_Banner
	if [ ! -e /etc/redhat-release ]; then echo -n -e "\e[1;31m[!]\e[0m I can't confirm this is a Red Hat/Fedora machine. Installs may fail."; read; fi
	f_install

        echo -e "\n\e[1;33m[*]\e[0m Installing pre-reqs for Red Hat/Fedora...\n"
	echo -e "\e[1;33m[*]\e[0m Running 'updatedb'\n"
	updatedb

	reqs="gcc gcc-c++ libstdc++ libstdc++-devel subversion wget openssl-devel libtool libpcap libpcap-devel hostapd dsniff dhcp ipcalculator aircrack-ng"

	for i in $reqs; do
		if [ -z $(rpm -qa $i) 2>/dev/null ]; then
			echo -e "\e[1;33m[-]\e[0m $i is not installed, will attempt to install..."
			yum install -y $i &>/dev/null

			if [ -z $(rpm -qa $i) ];then
				echo -e "\t\e[1;31m[-]\e[0m $i could not be installed from the repository"
			else
				update=1
				echo -e "\t\e[1;32m[+]\e[0m $i was successfully installed from the repository."
			fi
		else
			echo -e "\e[1;32m[+]\e[0m I found $i installed on your system"
		fi
        done

f_sslstripinstall
f_ettercapinstall
f_hamsterinstall
f_ferretinstall
f_frinstall
f_asleapinstall
f_metasploitinstall

if [ "$update" == "1" ]; then
	echo -e "\e[1;33m[*]\e[0m Running 'updatedb' again because we installed some new stuff\n"
	updatedb
	echo -e "\n\e[1;33m...happy hunting!\e[0m\n\n"
else
	echo -e "\n\e[1;33m...happy hunting!\e[0m\n\n"
fi
rm -rf /tmp/ec-install/

}

##################################################
f_microsoft(){
clear
f_Banner
echo "Seriously!?!?! easy-creds doesn't run on Windows!!!"
echo -e "You need to learn you some Linux!\nHere's some links...\n"
echo -e "- http://www.ubuntu.com\n- http://www.debian.org\n- http://fedoraproject.org\n- http://www.gentoo.org"
echo -e "\nA whole world of awesomness awaits!\n\n"

echo "                 .88888888:."
echo "                88888888.88888."
echo "             .8888888888888888."
echo "              888888888888888888"
echo "              88' _\`88'_  \`88888"
echo "              88 88 88 88  88888"
echo "              88_88_::_88_:88888"
echo "              88:::,::,:::::8888"
echo "              88\`:::::::::'\`8888"
echo "             .88  \`::::'    8:88."
echo "            8888            \`8:888." 
echo "          .8888'             \`888888." 
echo "         .8888:..  .::.  ...:'8888888:." 
echo "        .8888.'     :'     \`'::\`88:88888" 
echo "       .8888        '         \`.888:8888." 
echo "      888:8         .           888:88888 "
echo "    .888:88        .:           888:88888:" 
echo "    8888888.       ::           88:888888" 
echo "    \`.::.888.      ::          .88888888" 
echo "   .::::::.888.    ::         :::\`8888'.:." 
echo "  ::::::::::.888   '         .::::::::::::" 
echo "  ::::::::::::.8    '      .:8::::::::::::." 
echo " .::::::::::::::.        .:888::::::::::::: "
echo " :::::::::::::::88:.__..:88888:::::::::::'" 
echo "  \`'.:::::::::::88888888888.88:::::::::'" 
echo "        \`':::_:' -- '' -'-' \`':_::::'\` "

sleep 10

f_mainmenu
}

##################################################
f_aircrackinstall(){
if [ ! -e /usr/bin/aircrack-ng ] && [ ! -e /usr/sbin/aircrack-ng ] && [ ! -e /usr/local/sbin/aircrack-ng ] && [ ! -e /usr/local/bin/aircrack-ng ]; then
	update=1
	echo -e "\n\e[1;33m[*]\e[0m Downloading and installing aircrack-ng from SVN"
	svn co http://trac.aircrack-ng.org/svn/trunk/ /tmp/ec-install/aircrack-ng
	cd /tmp/ec-install/aircrack-ng/
	make && make install > /dev/null
	airodump-ng-oui-update > /dev/null
	cd $path
	echo -e "\n\e[1;32m[+]\e[0m Aircrack-ng has been installed..."
	sleep 5
fi

}

##################################################
f_ettercapinstall(){
etterupdate=
if [ ! -e /usr/bin/ettercap ] && [ ! -e /usr/local/bin/ettercap ] && [ ! -e /usr/sbin/ettercap ] && [ ! -e /usr/local/sbin/ettercap ]; then
	etterupdate=1
	update=1
	echo -e "\e[1;33m[-]\e[0m ettercap is not installed, will attempt to install..."
	sleep 2
	echo -e "\e[1;33m[-]\e[0m Getting ettercap prerequisites..."
	sleep 2
	if [ "$mainchoice" == "1" ]; then
		apt-get -y install cmake libpcap0.8 libpcap0.8-dev libnet1 libnet1-dev libnet6-1.3-0 libnet6-1.3-dev libpthread-stubs0 libpthread-stubs0-dev zlibc libtool automake flex bison libncurses5 libncurses5-dev libgtk2.0-dev libgtk2.0-0 libpcre3-dev libpcre3 > /dev/null 2>&1
		echo -e "\n\e[1;33m[*]\e[0m Downloading and installing ettercap from source..."
		wget http://prdownloads.sourceforge.net/ettercap/ettercap-0.7.6.tar.gz?download -O /tmp/ec-install/ettercap-0.7.6.tar.gz
		cd /tmp/ec-install/
		tar xvf ettercap-0.7.6.tar.gz &> /dev/null
		cd ettercap
		mkdir build && cd build
		cmake .. &> /dev/null
		make install
		cd $path
		echo -e "\n\e[1;32m[+]\e[0m ettercap has been installed..."
		sleep 5
	else
		yum install -y ettercap &>/dev/null
		echo -e "\n\e[1;32m[+]\e[0m ettercap has been installed..."
	fi
fi

if [ -z $etterupdate ]; then
	echo -e "\e[1;32m[+]\e[0m I found ettercap installed on your system"
	sleep 2
fi

}

##################################################
f_frinstall(){
if [ ! -e /usr/bin/radiusd ] && [ ! -e /usr/sbin/radiusd ] && [ ! -e /usr/local/sbin/radiusd ] && [ ! -e /usr/local/bin/radiusd ]; then
	update=1
	echo -e "\e[1;33m[-]\e[0m free-radius is not installed, will attempt to install..."
	sleep 2
	echo -e "\n\e[1;33m[*]\e[0m Downloading freeradius server 2.1.11 and the wpe patch..."
	wget ftp://ftp.freeradius.org/pub/radius/old/freeradius-server-2.1.11.tar.bz2 -O /tmp/ec-install/freeradius-server-2.1.11.tar.bz2
	wget http://www.opensecurityresearch.com/files/freeradius-wpe-2.1.11.patch -O /tmp/ec-install/freeradius-wpe-2.1.11.patch
	cd /tmp/ec-install
	tar jxvf freeradius-server-2.1.11.tar.bz2 &> /dev/null
	mv freeradius-wpe-2.1.11.patch /tmp/ec-install/freeradius-server-2.1.11/freeradius-wpe-2.1.11.patch
	cd freeradius-server-2.1.11
	patch -p1 < freeradius-wpe-2.1.11.patch &> /dev/null
	echo -e "\n\e[1;33m[*]\e[0m Installing the patched freeradius server..."
	sleep 3
	./configure && make && make install &> /dev/null
	cd /usr/local/etc/raddb/certs/
	./bootstrap &> /dev/null
	cd $path
	echo -e "\n\e[1;32m[+]\e[0m The patched freeradius server has been installed"
	sleep 5
else
	echo -e "\e[1;32m[+]\e[0m I found free-radius installed on your system"
	sleep 2
fi
}

##################################################
f_asleapinstall(){
if [ ! -e /opt/asleap ]; then mkdir /opt/asleap; fi

if [ ! -e /usr/bin/asleap ] && [ ! -e /usr/sbin/asleap ] && [ ! -e /usr/local/sbin/asleap ] && [ ! -e /usr/local/bin/asleap ]; then
	update=1
	echo -e "\e[1;33m[-]\e[0m asleap is not installed, will attempt to install..."
	sleep 2
	echo -e "\n\e[1;33m[-]\e[0m Downloading and installing asleap from source..."
	wget http://www.willhackforsushi.com/code/asleap/2.2/asleap-2.2.tgz -O /tmp/ec-install/asleap.tgz
	cd /tmp/ec-install
	tar xvf asleap.tgz
	cd asleap-2.2
	make
	mv /tmp/ec-install/asleap-2.2/* /opt/asleap/
	cd /usr/bin
	ln -f -s /opt/asleap/asleap asleap
	cd $path
	echo -e "\n\e[1;32m[+]\e[0m asleap has been installed..."
	sleep 5
else
	echo -e "\e[1;32m[+]\e[0m I found asleap installed on your system"
	sleep 2
fi
}

##################################################
f_ferretinstall(){
if [ ! -e /opt/sidejack ]; then mkdir /opt/sidejack; fi

if [ ! -e /usr/bin/ferret ] && [ ! -e /usr/sbin/ferret ] && [ ! -e /usr/local/sbin/ferret ] && [ ! -e /usr/local/bin/ferret ]; then
	update=1
	echo -e "\e[1;33m[-]\e[0m ferret is not installed, will attempt to install..."
	sleep 2
	echo -e "\n\e[1;33m[*]\e[0m Downloading and installing ferret from SVN"
	svn checkout http://ferret.googlecode.com/svn/trunk/ /tmp/ec-install/ferret
	cd /tmp/ec-install/ferret/
	make #&> /dev/null
	if [ ! -e /opt/sidejack ]; then mkdir /opt/sidejack; fi
	cp /tmp/ec-install/ferret/bin/ferret /opt/sidejack/ferret
	cd /usr/bin
	ln -f -s /opt/sidejack/ferret ferret
	cd $path
	echo -e "\n\e[1;32m[+]\e[0m ferret has been installed..."
	sleep 5
else
	echo -e "\e[1;32m[+]\e[0m I found ferret installed on your system"
	sleep 2
fi

}

##################################################
f_hamsterinstall(){
if [ ! -e /opt/sidejack ]; then mkdir /opt/sidejack; fi

if [ ! -e /usr/bin/hamster ] && [ ! -e /usr/sbin/hamster ] && [ ! -e /usr/local/sbin/hamster ] && [ ! -e /usr/local/bin/hamster ] && [ -z $(locate hamster.js) ]; then
	update=1
	echo -e "\e[1;33m[-]\e[0m hamster is not installed, will attempt to install..."
	sleep 2
	echo -e "\n\e[1;33m[*]\e[0m Downloading and installing hamster from source..."
	cd /tmp/ec-install
	wget http://www.brav0hax.com/erratasec.zip -O /tmp/ec-install/erratasec.zip
	unzip erratasec.zip &> /dev/null
	cd hamster/build/gcc4/
	make &> /dev/null
	cp /tmp/ec-install/hamster/bin/* /opt/sidejack
	rm -rf /tmp/ec-install/ferret
	cd /usr/bin
	ln -f -s /opt/sidejack/hamster hamster
	cd $path
	echo -e "\n\e[1;32m[+]\e[0m hamster has been installed..."
	sleep 5
else
	echo -e "\e[1;32m[+]\e[0m I found hamster installed on your system"
	sleep 2
fi

}

##################################################
f_metasploitinstall(){

if [ ! -e /usr/bin/msfconsole ] && [ ! -e /usr/sbin/msfconsole ] && [ ! -e /usr/local/sbin/msfconsole ] && [ ! -e /usr/local/bin/msfconsole ]; then
	update=1
	echo -e "\n\e[1;33m[*]\e[0m Downloading Metasploit from www.metasploit.com, this will take a while to complete"

	machine=$(uname -m)
	if [ "$machine" == "x86_64" ]; then
		wget http://downloads.metasploit.com/data/releases/metasploit-latest-linux-x64-installer.run -O /tmp/ec-install/metasploit-latest-linux-x64-installer.run
		echo -e "\n\e[1;33m[*]\e[0m The Metasploit installer will walk you through the rest of the process"
		sleep 5
		chmod 755 /tmp/ec-install/metasploit-latest-linux-x64-installer.run
		/tmp/ec-install/metasploit-latest-linux-x64-installer.run
	else
		wget http://downloads.metasploit.com/data/releases/metasploit-latest-linux-installer.run -O /tmp/ec-install/metasploit-latest-linux-installer.run
		echo -e "\n\e[1;33m[*]\e[0m The Metasploit installer will walk you through the rest of the process"
		sleep 5
		chmod 755 /tmp/ec-install/metasploit-latest-linux-installer.run
		/tmp/ec-install/metasploit-latest-linux-installer.run
	fi

	cd /usr/bin
	msfprogs="msfconsole msfupdate msfencode msfpayload"
	for z in $msfprogs; do
		if [ ! -e /usr/bin/$z ]; then
			ln -f -s /usr/local/bin/$z $z
		fi
	done

	echo -e "\n\e[1;32m[+]\e[0m Metasploit has been installed..."
	sleep 2
	echo -e "\n\e[1;33m[*]\e[0m Updating the Metasploit framework"
	sleep 2
	msfupdate
else
	echo -e "\e[1;32m[+]\e[0m I found metasploit installed on your system"
	sleep 2
fi
}
##################################################
f_sslstripinstall(){

if [ ! -e /usr/bin/sslstrip ] && [ ! -e /usr/sbin/sslstrip ] && [ ! -e /usr/local/sbin/sslstrip ] && [ ! -e /usr/local/bin/sslstrip ] && [[ -z $(locate sslstrip.py) ]]; then
	if [ ! -e /opt/sslstrip ]; then mkdir /opt/sslstrip; fi
	update=1
	echo -e "\n\e[1;33m[*]\e[0m Downloading sslstrip from thoughtcrime.org..."
	wget http://www.thoughtcrime.org/software/sslstrip/sslstrip-0.9.tar.gz -O /tmp/ec-install/sslstrip-0.9.tar.gz
	cd /tmp/ec-install
	tar -zxvf sslstrip-0.9.tar.gz
	cp -R sslstrip-0.9/* /opt/sslstrip/
	chmod 755 /opt/sslstrip/sslstrip.py
	cd /usr/bin
	ln -f -s /opt/sslstrip/sslstrip.py sslstrip
	cd $path
	echo -e "\n\e[1;32m[+]\e[0m SSLStrip has been installed..."
	sleep 5
else
	echo -e "\e[1;32m[+]\e[0m I found sslstrip installed on your system"
	sleep 2
fi

}

##################################################
f_install(){
	while [[ $valid != 1 ]]; do
		read -e -p "Please provide the path you'd like to place the easy-creds folder. [/opt] : " easycredpath
		if [ -z $easycredpath ]; then
			easycredpath="/opt"
			valid=1
		elif [ -e $easycredpath ]; then
			valid=1
		else
			echo "Not a valid file path."
		fi
	done

	# Remove the ending slash if it exists in path
	easycredpath=$(echo $easycredpath | sed 's/\/$//g')

	if [ $PWD == $easycredpath/easy-creds ]; then
		echo -e "\e[1;33m[*]\e[0m OK...keeping the folder where it is..."
		sleep 3
		chmod 755 $easycredpath/easy-creds/easy-creds.sh
		ln -f -s $easycredpath/easy-creds/easy-creds.sh /usr/bin/easy-creds
	else
		# CD out of folder, mv folder to specified path and create symbolic link
		cd ..
		mv $PWD/easy-creds $easycredpath/easy-creds
		chmod 755 $easycredpath/easy-creds/easy-creds.sh
		ln -f -s $easycredpath/easy-creds/easy-creds.sh /usr/bin/easy-creds
	fi

}

##################################################
f_Banner(){
	echo -e " ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ "
	echo -e "||\e[1;36me\e[0m |||\e[1;36ma\e[0m |||\e[1;36ms\e[0m |||\e[1;36my\e[0m |||\e[1;36m-\e[0m |||\e[1;36mc\e[0m |||\e[1;36mr\e[0m |||\e[1;36me\e[0m |||\e[1;36md\e[0m |||\e[1;36ms\e[0m ||"
	echo -e "||__|||__|||__|||__|||__|||__|||__|||__|||__|||__||"
	echo -e "|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|"
	echo -e "\e[1;33m 	Version 3.8 - DEV\e[0m"
	echo -e "\e[1;33m 		   Installer\e[0m"
	echo
}

##################################################
f_mainmenu(){
mkdir /tmp/ec-install
clear
f_Banner
	echo "Please choose your OS to install easy-creds"
	echo "1.  Debian/Ubuntu and derivatives"
	echo "2.  Red Hat or Fedora"
	echo "3.  Microsoft Windows"
	echo "4.  Exit"
	echo
	read -p "Choice: " mainchoice

	case $mainchoice in
	1) f_debian ;;
	2) f_rhfedora ;;
	3) f_microsoft ;;
	*) clear;exit ;;
	esac

}
# run as root
if [ "$(id -u)" != "0" ]; then
	echo -e "\e[1;31m[!]\e[0m This script must be run as root" 1>&2
	exit 1
else
	f_mainmenu
fi

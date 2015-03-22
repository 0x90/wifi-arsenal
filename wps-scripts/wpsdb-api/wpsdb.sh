#!/bin/bash
# Script para trabajar con la api de wpsdb.site40.net
# base de datos colaborativa de PIN's WPS de los usuarios
# Version 0.3
#
# USO: chmod +x wpsdb.sh
#      ./wpsdb.sh AABBCC
#      *Donde AABBCC corresponde a los datos de un BSSID tipo: AA:BB:CC:DD:EE:FF
#
# ----------------------------------------------------------------------------------
#                  @mark__os  -  ciberentropia.blogspot.com.es
# ----------------------------------------------------------------------------------

# Funcion para comprobar los PIN's WPS contra la api de wpsdb
api_connect() {
STREAM=$(wget -q -O- "http://wpsdb.site40.net/api.php?TIPE=MAC&BSSID="$BSSID"" | grep "<tr>" | tail -n1 | sed 's/[^0-9!X]*//g')
STREAM_COMA=`echo "$STREAM" | sed 's/\(.\)/\1,/g'`
CUENTA=$(echo "$STREAM" | awk '{ print length; }')
# Como los PIN's son de 8 numeros, dividimos todo el string entre 8 para saber cuantos pines hay, de esta manera
# sabremos cuantas iteraciones tiene que hacer el loop while
let TOTAL_PINS=$CUENTA/8
LOOP=1
while [ "$LOOP" -le "$TOTAL_PINS" ]
do
   echo "$STREAM_COMA" | awk -F, '{ print $1$2$3$4$5$6$7$8 }'
   STREAM_COMA=`echo "$STREAM_COMA" | cut -c 17-`
   let LOOP=$LOOP+1
done
}

#Funcion para comprobar que se haya introducido bien el BSSID
bssid_check() {
if [ "$(echo "$BSSID" | awk '{ print length; }')" -ne "6" ]
   then
      echo -e "\nERROR"
      echo -e "\nUSO:  $0 AABBCC"
      echo -e "\n* Donde AABBCC corresponde a los datos de un BSSID (MAC_AP) tipo: AA:BB:CC:DD:EE:FF\n"
      exit 1
fi
}

################
# Main Program #
################

# Pedimos los 3 primeros bytes de la mac, en caso de que no se hayan introducido como parámetro
if [ "$1" == "" ]
   then
      echo -en "BSSID: "
      read BSSID
      export BSSID=$BSSID
   else
      export BSSID=$1
fi

# Comprobamos el BSSID contenga solo la parte de fabricante AABBCC, en
# una MAC tipo AA:BB:CC:DD:EE:FF
bssid_check

# Llamamos a la funcion que conecta con la API
api_connect

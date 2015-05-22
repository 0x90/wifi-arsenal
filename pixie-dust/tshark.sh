#!/bin/bash

code () {
  if [ "$1" == "M1" ]; then echo "0x04"; fi
  if [ "$1" == "M2" ]; then echo "0x05"; fi
  if [ "$1" == "M3" ]; then echo "0x07"; fi
  if [ "$1" == "M4" ]; then echo "0x08"; fi
  if [ "$1" == "M5" ]; then echo "0x09"; fi
  if [ "$1" == "M6" ]; then echo "0x0a"; fi
  if [ "$1" == "M7" ]; then echo "0x0b"; fi
  if [ "$1" == "M8" ]; then echo "0x0c"; fi
  if [ "$1" == "MF" ]; then echo "0x0f"; fi
}

for pkt_type in "M1" "M2" "M3" "M4" "M5" "M6" "M7" "M8" "MF";
do
  for i in "wps.enrollee_nonce" "wps.registrar_nonce" "wps.authenticator" "wps.encrypted_settings" "wps.r_hash1" "wps.r_hash2" "wps.e_hash1" "wps.e_hash2"
  do
    value=$(tshark -r $1 -Y "wps.message_type == $(code ${pkt_type})" -e ${i} -Tfields -Eoccurrence=a -Equote=n  | tail -n 1 | tr -d ':' )
    if [ ! -z "${value}" ];
    then
      printf "%-3s %-25s : %s\n" "${pkt_type}" ${i} "${value}"
    fi
  done
done

name () {
  if [ "$1" == "AP" ];      then echo "0x02"; fi
  if [ "$1" == "Client" ];  then echo "0x01"; fi
}
# Infos sur l'AP
for w in "Client" "AP";
do
  for i in "wps.manufacturer" "wps.device_name" "wps.os_version" "wlan.ta" "wps.model_name" "wps.model_number" "wps.serial_number";
  do 
    x=$(tshark -r $1 -Y "(wlan.fc.ds == $(name ${w})) and (llc.type == 0x888e)" -e ${i} -Tfields -Eoccurrence=a -Equote=n | grep -v ^$ | sort -u | tr -d '\n')
    printf "%-25s : %s\n" "${w} ${i}" "${x}";
  done
done

echo
echo "Please post this information on this thread : http://www.crack-wifi.com/forum/topic-11198-pixie-dust-attack-participez-a-la-recherche-avec-vos-echantillons.html"
echo "Thanks !"

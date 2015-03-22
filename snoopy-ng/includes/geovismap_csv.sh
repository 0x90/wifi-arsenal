#!/bin/bash
# Helper script to make .csv
# glenn@sensepost.com

db="/root/snoopy-ng/snoopy.db"
outdir="/root/Desktop/Results"
mkdir -p $outdir
echo "The following are available:"
sqlite3 $db "SELECT DISTINCT location from sessions"
echo ""

for name in `sqlite3 $db "SELECT DISTINCT location from sessions"`; do


cat > /tmp/cmds.txt << EOL

.output $outdir/$name.gps.csv
.mode csv

SELECT
"<b>SSID: </b>" ||
wigle.ssid ||
"<br>"||
"<b>Address: </b>" ||
shortaddress ||
"<br>" ||
"<a href='https://maps.google.com/maps?q=&layer=c&cbp=11,0,0,0,0&cbll="||
lat || "," || long || "'>" ||
"<img height='240' width='240' src='http://maps.googleapis.com/maps/api/streetview?size=240x240&sensor=false&location="||
lat ||","|| long || "'>" ||
"</a>"

,lat,long FROM wifi_client_ssids,wigle,sessions
WHERE sessions.location='$name'
AND wifi_client_ssids.run_id = sessions.run_id
AND wigle.ssid = wifi_client_ssids.ssid
AND wigle.overflow=0
GROUP BY wigle.ssid HAVING COUNT(*) < 6;

EOL

sqlite3 $db < /tmp/cmds.txt

sed -i '1s/^/\"name\",\"latitude\",\"longitude\"\n/' $outdir/$name.gps.csv

echo "Written to $outdir/$name.gps.csv"



#### and again
cat > /tmp/cmds2.txt << EOL

.output $outdir/$name.address.csv
.mode csv

SELECT wigle.ssid,shortaddress,city,country
FROM wifi_client_ssids,wigle,sessions
WHERE sessions.location='$name'
AND wifi_client_ssids.run_id = sessions.run_id
AND wigle.ssid = wifi_client_ssids.ssid
AND wigle.overflow=0
GROUP BY wigle.ssid HAVING count(*) < 6 ;

EOL

sqlite3 $db < /tmp/cmds2.txt

sed -i '1s/^/\"ssid\",\"address\",\"city\",\"country\"\n/' $outdir/$name.address.csv

echo "Written to $outdir/$name.address.csv"


#### third foobar

#cat > /tmp/cmds.txt << EOL

#.output $outdir/$name.manufac.csv
#.mode csv

#SELECT wifi_client_ssids.mac,wifi_client_ssids.ssid
#FROM wifi_client_ssids,sessions
#WHERE wifi_client_ssids.run_id=sessions.run_id
#AND sessions.location='$name'
#GROUP BY wifi_client_ssids.mac;

#EOL

#sqlite3 snoopy.db < /tmp/cmds.txt

#sed -i '1s/^/\"ssid\",\"mac\"\n/' $outdir/$name.manufac.csv

#echo "Written to $outdir/$name.manufac.csv"


done

echo "Press any key to exit"
read -n 1

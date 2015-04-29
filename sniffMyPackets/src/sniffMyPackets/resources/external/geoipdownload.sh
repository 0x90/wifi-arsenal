#!/bin/sh
mkdir /opt/geoipdb
wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz -O /tmp/geoipdb.dat.gz
gzip -d /tmp/geoipdb.dat.gz
mv /tmp/geoipdb.dat /opt/geoipdb/

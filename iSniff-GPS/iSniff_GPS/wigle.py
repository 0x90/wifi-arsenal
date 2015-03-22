#!/usr/bin/python

import re
import requests
#import simplekml
from bs4 import BeautifulSoup

# parse lat/lon from hrefs in results page like
# <a href="/gps/gps/Map/onlinemap2/?maplat=39.89233017&maplon=-86.15497589&mapzoom=17&ssid=NETGEAR&netid=00:00:85:E7:0C:01">Get Map</a>

def getLocation(BSSID='',SSID=''):
	payload = {'netid':BSSID, 'ssid':SSID}
	cookie = dict(auth='isniff:841981133:1416119202:eiewXk78tQeXklwin17pYw')
	r = requests.post('https://wigle.net/gps/gps/main/confirmquery/',cookies=cookie,data=payload)
	soup = BeautifulSoup(r.text)
	apdict={}
	count=1
	result_href=soup.findAll('a',href=re.compile('maplon'))
	for link in result_href:
		s=link.get('href')
		lat = float(re.search(r"maplat=([^&]*)",s).group(1))       #(-?\d{1,3}\.\d+)",s).group(1)
		lon = float(re.search(r"maplon=([^&]*)",s).group(1))       #(-?\d{1,3}\.\d+)",s).group(1)
		ssid_result = re.search(r"ssid=([^&]*)",s).group(1) #match any number of non-& characters
		bssid_result = re.search(r"netid=(\w\w:\w\w:\w\w:\w\w:\w\w:\w\w)",s).group(1)
		#print lon,lat,ssid_result,bssid_result
		if SSID and ssid_result==SSID: # exact case sensitive match
			id = '%s [%s] [%s]' % (SSID,bssid_result,count)
			apdict[id]=(lat,lon)
			count+=1
	return apdict


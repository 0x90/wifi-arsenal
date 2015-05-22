#!/usr/bin/python
#Simple API to Interact with Wigle and OpenStreetView
# glenn@sensepost.com // 2013
import time
from random import randint
import re
import sys
from collections import deque
import requests
from BeautifulSoup import BeautifulSoup
from pprint import pprint as pp
import math
import socket
import sys
import logging
import os
import urllib2
import httplib2
import urllib
import json
import sys
requests_log = logging.getLogger("requests")
requests_log.setLevel(logging.ERROR)

url = {'land':"https://wigle.net/", 'login': "https://www.wigle.net/api/v1/jsonLogin", 'query':"https://wigle.net/gps/gps/main/confirmquery/"}

class Wigle(object):

    def __init__(self,user,passw,email,proxy=''):
        self.user = user
        self.password = passw
        self.proxies = {"http":proxy,"https":proxy}
        self.cookies = None
        self.email = email

        if not self.user or not self.password:
            logging.error("Please supply Wigle credentials!")
            sys.exit()

        if not self.email:
            logging.error("Please supply email address to Wigle for OpenStreetView lookups!")
            sys.exit()

    def login(self):
        """Login to Wigle service, and set cookies"""
        logging.debug("[+] Logging into wigle with %s:%s via proxy '%s'" %(self.user,self.password,self.proxies))
        payload={'credential_0':self.user, 'credential_1':self.password}
        try:
            r = requests.post(url['login'],data=payload,proxies=self.proxies,timeout=10)
        except Exception, requests.exceptions.ConnectionError:
            logging.error('error: Unable to connect to %s' %url['login'])
            return False
        else: 
            if( 'Please login' in r.text or 'auth' not in r.cookies):
                logging.debug("Error logging in with credentials %s:%s." %(self.user,self.password))
                return False
                #return {'result':'fail', 'error':'Unable to login to wigle'}
            else:
                logging.debug("Successfully logged in with credentials %s:%s." %(self.user,self.password))
                cookies=dict(auth=r.cookies['auth'])
                self.cookies = cookies
                return True

    def lookupSSID(self,ssid):
        """Lookup the co-ordinates (Wigle) and address (OpenStreetMaps) of an SSID. Provide a Wigle cookie"""
        assert ssid
        if not self.cookies:
            logging.debug("Cookies not set - have you successfully logged in?")
            return {'error':'Cookie not set - have you succuessfully logged in?'}
        payload={'longrange1': '', 'longrange2': '', 'latrange1': '', 'latrange2':'', 'statecode': '', 'Query': '', 'addresscode': '', 'ssid': ssid.replace("_","\_"), 'lastupdt': '', 'netid': '', 'zipcode':'','variance': ''}

        results =self.__queryWigle(payload)
        if results and 'error' not in results:
            locations=self.__fetch_locations(results,ssid)
            if (locations != None and locations[0]['overflow'] == 0):
                for l in locations:
                    address = self._getAddress(l['lat'],l['long'])
                    retries = 5
                    while not address and retries > 0:
                        print address
                        logging.error("Failed to lookup address, trying again")
                        address = self._getAddress(l['lat'],l['long'])
                        retries-=1
                        time.sleep(0.75)
                    if address:
                        l.update(address)
            return locations
        else:
            return results

    def fetchNearbySSIDs(self,lat='',lng='',radius=500,address=''):
        """Fetch nearby SSIDs from (lat,long) or an address. Radius is 500m by default"""
        assert address or (lat and lng)
        if address:
            logging.info("Fetching co-ordinates for address '%s'" % address)
            url = "http://maps.googleapis.com/maps/api/geocode/json?address=%s&sensor=false"%address
            try:
                r = requests.get(url,proxies=self.proxies)
            except Exception, requests.exceptions.ConnectionError:
                logging.error('error: Unable to connect to %s' %url)
            else:
                res = json.loads(r.text)
                r = res.get('results')
                if r:
                    if len(r) > 1:
                        logging.warning("Got %d possible GPS co-ordinates for address. Will use the first one ('%s')"%(len(r),r[0]["formatted_address"]))
                    add = r[0]["formatted_address"]
                    logging.debug("Using address '%s'" % add)
                    lat = float(r[0]["geometry"]["location"]["lat"])
                    lng = float(r[0]["geometry"]["location"]["lng"])

        if not lat or not lng:
            logging.error("Unable to determine GPS co-ordinates")
        else:
            lat1,lng1,lat2,lng2 = self.__getSquare(lat,lng,radius)
            lat1 = round(lat1,11) #Wigle nuance
            lat2 = round(lat2,11)
            lng1 = round(lng1,11)
            lng2 = round(lng2,11)
            logging.debug("[-] Looking for SSIDs near by (%s %s)" %(lat,lng))
            payload={'longrange1': lng1, 'longrange2': lng2, 'latrange1': lat1, 'latrange2':lat2, 'statecode': '', 'Query': '', 'addresscode': '', 'ssid': '', 'lastupdt': '', 'netid': '', 'zipcode':'','variance': '0.010'}
            results = self.__queryWigle(payload)
            if results and 'error' not in results:
                ssid_list = self.__fetch_ssids(results)
                keys = ssid_list.keys()
                for key in keys:
                    slat,slng = ssid_list[key][0], ssid_list[key][1]
                    dist_from_point = self._haversine(lat,lng,slat,slng)
                    ssid_list[key] = (slat,slng,dist_from_point)
                return ssid_list
            else:
                return results

    def __fetch_ssids(self,text):
        """Pull out SSIDs from a Wigle result page"""
        soup=BeautifulSoup(text)
        #print soup
        results=soup.findAll("tr", {"class" : "search"})
        ssids={}
        for line in results:
                try:
                        row=line.findAll('td')
                        ssids[row[2].string]=( float(row[12].string), float(row[13].string) )
                except Exception:
                        pass
        return ssids #.keys()

    def __queryWigle(self,payload):
        """Pass a payload to Wigle, and get the response back"""
        if not self.cookies:
            logging.debug("Cookies not set - have you successfully logged in?")
            return {'error':'Cookie not set - have you succuessfully logged in?'}

        try:
            r = requests.post(url['query'],data=payload,proxies=self.proxies,cookies=self.cookies,timeout=10)
            if( r.status_code == 200 and r.text):
                if('too many queries' in r.text):
                    logging.debug("User %s has been shunned" %(self.user))
                    return {'error':'User "%s" has been shunned' %self.user}
                elif('An Error has occurred:' in r.text):
                    logging.debug("An error occured whilst processing Wigle query.")
                    return {'error':'Text response contained "An Error has occurred"'}
                elif('Showing stations' in r.text):
                    # Lines below are useful when debugging failure, e.g. when Wigle changes their HTML
                    #logging.debug("Writing HTML response to /tmp/%s.html" % payload['ssid'] ) #DD
                    #f = open("/tmp/%s.html"%payload['ssid'], 'w') #DD
                    #f.write(r.text) #DD
                    #f.close() #DD
                    return r.text
                else:
                    logging.debug("Unknown error occured")
                    return {'error':'Unknown error occured'}
            else:
                logging.debug("Bad status - %s" %r.status_code)
                return {'error':'Bad HTTP status - %s'%r.status_code}
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout), e:
            logging.error("Exception - '%s'" %(str(e)))
            return {'error':e}

    def __fetch_locations(self,text,ssid):
        """Parse Wigle page to extract GPS co-ordinates"""
        soup=BeautifulSoup(text)
        results=soup.findAll("tr", {"class" : "search"})
        locations=[]
        overflow=0
        if (len(results)>99 ):
            overflow=1
        for line in results:
            try:
                row=line.findAll('td')
                if( row[2].string.lower() == ssid.lower()):
                    locations.append({'ssid':ssid,'mac':row[1].string, 'last_seen':row[9].string, 'last_update':row[14].string, 'lat':float(row[12].string), 'long':float(row[13].string),'overflow':overflow})
            except Exception:
                pass
        # Sort by last_update
        sorted=False
        while not sorted:
            sorted=True
            for i in range(0,len(locations)-1):
                if( int(locations[i]['last_update']) < int(locations[i+1]['last_update'])):
                    sorted=False
                    locations[i],locations[i+1] = locations[i+1],locations[i]
        # Remove duplicates within proximity of each other, keeping the most recent
        # TODO: Update this to find the great circle average
        remove_distance=5000 #5 kilometres
        tD={}
        for i in range(0,len(locations)-1):
            for j in range(i+1,len(locations)):
                dist=self._haversine(float(locations[i]['lat']),float(locations[i]['long']),float(locations[j]['lat']),float(locations[j]['long']))
                if (dist < remove_distance):
                    #logging.debug(" %d and %d are %d metres apart, thus, DELETION! :P" % (j,dist))
                    tD[j]=1
        tmp=[]
        for i in range(0,len(locations)):
            if (i not in tD):
                tmp.append(locations[i])
        locations=tmp
        if( len(locations) == 0):
            locations.append({'ssid':ssid,'overflow':-1}) #No results, just return the ssid
        return locations        # Return list of locations

    def __getSquare(self,lat, lng, m):
        """Calcuate crude radius around a GPS point. Returns bottom left, and top right co-ordinates for given radius m"""
        offset = 0.00001/1.1132 #http://en.wikipedia.org/wiki/Decimal_degrees
        m = math.sqrt(( m**2)/2 ) #Pythag
        diff = offset * m
        latRange1 = lat - diff
        latRange2 = lat + diff
        longRange1 = lng - diff
        longRange2 = lng + diff
        return(latRange1,longRange1,latRange2,longRange2)

    def _haversine(self, lat1, lon1, lat2, lon2):
        """Calculate distance between points on a sphere"""
        R = 6372.8 # In kilometers
        dLat = math.radians(lat2 - lat1)
        dLon = math.radians(lon2 - lon1)
        lat1 = math.radians(lat1)
        lat2 = math.radians(lat2)

        a = math.sin(dLat / 2) * math.sin(dLat / 2) + math.sin(dLon / 2) * math.sin(dLon / 2) * math.cos(lat1) * math.cos(lat2)
        c = 2 * math.asin(math.sqrt(a))
        return R * c * 1000.0 # In metres

    def _getAddress(self,gps_lat,gps_long):
        """Get street address from GPS coordinates"""
        lookup_url = "http://nominatim.openstreetmap.org/reverse?zoom=18&addressdetails=1&format=json&email=%s&lat=%s&lon=%s" %(self.email,gps_lat,gps_long)
        try:
            req = requests.get(lookup_url)
            if req.status_code == 200 and 'json' in req.headers['content-type']:
                #addj = json.loads(req.text.encode('UTF8'))
                addj = json.loads(req.text.encode('utf-8'))
                longaddress = addj.get('display_name', '')
                compound_address = addj.get('address', {})
                city = compound_address.get('city', '')
                country = compound_address.get('country', '')
                country_code = compound_address.get('country_code', '')
                county = compound_address.get('county', '')
                postcode = compound_address.get('postcode', '')
                housenumber = compound_address.get('house_number', '')
                road = compound_address.get('road', '')
                state = compound_address.get('state', '')
                suburb = compound_address.get('suburb', '')
                shortaddress = "%s %s, %s" %(housenumber, road, city)
                shortaddress = shortaddress.strip()
    
            return {'longaddress':longaddress, 'shortaddress':shortaddress, 'city':city, 'country':country, 'code':country_code, 'county':county, 'postcode':postcode, 'road':road, 'state':state, 'suburb':suburb}
        except Exception,e:
            logging.error("Unable to retrieve address from OpenStreetMap - '%s'" % str(e))
        


if __name__ == "__main__":
    #logging.basicConfig(level=logging.DEBUG)
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--ssid", help="Fetch SSID location.")
    parser.add_argument("-c", "--coords", help="Fetch SSIDs around GPS co-ordaintes (comma separates).")
    parser.add_argument("-a","--address", help="Fetch SSIDs around street address.")
    parser.add_argument("-r","--radius", help="Specificy radius for -c and -a.", default=500,type=int)
    parser.add_argument("-u", "--user", help="Wigle username")
    parser.add_argument("-p", "--password", help="Wigle password")
    parser.add_argument("-e", "--email", help="Your email, for OpenStreetView lookups (be polite, use your real one)")
    parser.add_argument("-x", "--proxy", help="Proxy to use.")
    args = parser.parse_args()

    if not args.ssid and not (args.coords or args.address):
        print "[!] No operation specified! Try --help."
        sys.exit(-1)

    wig = Wigle(args.user,args.password,args.email,args.proxy)
    print "[+] Logging into Wigle..."
    if wig.login():
        if args.ssid:
            print "[+] Looking up address of '%s'..."%args.ssid
            results = wig.lookupSSID(args.ssid)
            if 'error' in results:
                print "Error observed! Failed to lookup!"
                sys.exit(-1)
            if results[0]['overflow']:
                print "[!] Too many results for '%s'"%args.ssid
            else:
                for r in results:
                    print "Address:\t%s" %r['longaddress']
                    print "Co-ordinates:\t(%f, %f)\n" %(r['lat'],r['long'])
        else:
            lat,lng=None,None
            if args.coords:
                lat,lng=args.coords.split(",")
                lat,lng=float(lat),float(lng)
            ssids = wig.fetchNearbySSIDs(address=args.address,lat=lat,lng=lng,radius=args.radius)
            if 'error' in ssids:
                print "Error: '%s'" % ssids['error']
                sys.exit(-1)
            else:
                ssids = sorted(ssids.items(), key=lambda (k,v): v[2])
                for s in ssids:
                    print s
                    ssid = s[0]
                    lat,lng,dist = s[1]
                    print "SSID:\t\t'%s'" % ssid
                    print "Co-ords:\t(%f,%f)" % (lat,lng)
                    print "Distance:\t%f metres\n" % dist

    else:
        logging.error("Failed to login to Wigle")

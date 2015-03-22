#!/usr/bin/env python
# encoding: utf-8
import urllib2 as ul
#import socket as sckt
import simplejson as json
#import ujson as json

from wpp.util.net import connectRetry
from wpp.config import GOOG_FAIL_LIMIT, GOOG_FAIL_CACHE_TIME
 

def genLocReq(macs=None, rsss=None, cellinfo={}, atoken=None):
    """
    Request format:
    {
      "version": "1.1.0",
      "host": "maps.google.com",
      "access_token": "2:k7j3G6LaL6u_lafw:4iXOeOpTh1glSXe",
      "home_mobile_country_code": 310,
      "home_mobile_network_code": 410,
      "radio_type": "gsm",
      "carrier": "Vodafone",
      "request_address": true,
      "address_language": "en_GB",
      "location": {
        "latitude": 51.0,
        "longitude": -0.1
      },
      "cell_towers": [
        {
          "cell_id": 42,
          "location_area_code": 415,
          "mobile_country_code": 310,
          "mobile_network_code": 410,
          "age": 0,
          "signal_strength": -60,
          "timing_advance": 5555
        }, ],
      "wifi_towers": [
        {
          "mac_address": "01-23-45-67-89-ab",
          "signal_strength": 8,
          "age": 0
        },
      ]
    }
    Response format:
    {
      "location": {
        "latitude": 51.0,
        "longitude": -0.1,
        "altitude": 30.1,
        "accuracy": 1200.4,
        "altitude_accuracy": 10.6,
        "address": {
          "street_number": "100",
          "street": "Amphibian Walkway",
          "postal_code": "94043",
          "city": "Mountain View",
          "county": "Mountain View County",
          "region": "California",
          "country": "United States of America",
          "country_code": "US"
        }
      },
      "access_token": "2:k7j3G6LaL6u_lafw:4iXOeOpTh1glSXe"
    }
    """
    req = {} 
    # lac, cid, rss
    try:
        lac = cellinfo['lac'] 
        cid = cellinfo['cid']
        if int(lac) != 0 and int(cid) != 0:
            req['cell_towers'] = [ { 'cell_id':cid, 'location_area_code':lac } ]
            req['cell_towers'][0]['signal_strength'] = int(cellinfo['rss'])
    except KeyError: pass
    # mcc
    try:
        req['home_mobile_country_code'] = int(cellinfo['mcc'])
    except KeyError:
        req['home_mobile_country_code'] = 460 
    # mnc
    try:
        req['home_mobile_network_code'] = int(cellinfo['mnc'])
    except KeyError:
        req['home_mobile_country_code'] = 0 
    # wifi
    if len(macs): 
        req['wifi_towers'] = [{'mac_address':m, 'signal_strength':int(rsss[i])} for i,m in enumerate(macs)]
    req['version'] = '1.1.0'
    if atoken: req['access_token'] = atoken
    req_json = json.dumps(req)
    return req_json


def fail_limit(f):
    def dec(*args, **kw):
		# FIXME: count failure for reqs with only cell info, ignoring
		# wlan-enabled ones which should be monitered as well.
		# TODO: failcnt_cell & failcnt_wlan.
        if not kw['macs'] and 'mc' in kw:
            cell = kw['cellinfo']
            mcc = cell['mcc']; mnc = cell['mnc'] 
            lac = cell['lac']; cid = cell['cid']
            if int(mcc) != 460 or int(lac) <= 0 or int(cid) <= 0: 
                return []
            mc = kw['mc']
            key = 'failcnt:%s%s_%s_%s' % (mcc, mnc, lac, cid)
            fail_count = mc.get(key)
            if fail_count and int(fail_count) >= GOOG_FAIL_LIMIT:
                return []
        loc = f(*args, **kw)
        if not loc and not kw['macs'] and 'mc' in kw: 
            mc.incr(key)
            if not fail_count: 
                mc.expire(key, GOOG_FAIL_CACHE_TIME)
        return loc
    return dec
	
@fail_limit
@connectRetry(try_times=2, timeout=3)
def googleLocation(macs=[], rsss=[], cellinfo=None, mc=None):
    req_content = genLocReq(macs=macs, rsss=rsss, cellinfo=cellinfo)
    req_url = "http://www.google.com/loc/json"
    resp = ul.urlopen(req_url, req_content)
    ret_content = dict( eval(resp.read()) )
    if not 'location' in ret_content: 
        return []
    gloc = ret_content['location'] 
    accuracy = gloc['accuracy']
    if accuracy > 8000: 
        return []
    gh = gloc['altitude'] if ('altitude' in gloc) else 0
    return [ gloc['latitude'], gloc['longitude'], gh, accuracy ]


@connectRetry(try_times=1)
def googleGeocoding(latlon=(0,0), format='json', sensor='false', lang='zh_CN'):
    """wrapper for google reverse geocoding api.
    http://maps.google.com/maps/api/geocode/json?latlng=24.47726,112.64043\&sensor=false\&language=zh_CN
    """
    url = 'http://maps.google.com/maps/api/geocode/%s' % format
    params = 'latlng=%s,%s&sensor=%s&language=%s' % (latlon[0],latlon[1],sensor,lang)
    url = '%s?%s' % (url, params)
    resp = ul.urlopen(url)
    data = json.load(resp)
    return data


def parseGoogleGeocoding(geodict=None):
    """ 
    geodict: dict from google reverse geocoding api.
    geoaddr: [ province, city, district ].
    """
    geoaddr = []
    if type(geodict) is dict and 'status' in geodict:
        if geodict['status'] == 'OK':
            results = geodict['results']
            addr_components = []
            # addrlvls: {'sublocality':0, 'route':2, 'street_address':1}
            addrlvls = dict([ (res['types'][0],i) for i,res in enumerate(results) ])
            if 'sublocality' in addrlvls:
                res = results[ addrlvls['sublocality'] ]
                addr_components = res['address_components'][::-1][1:] 
            else:
                for res in results:
                    if res['types'][0] in ('street_address', 'route'):
                        for addr in res['address_components'][::-1]:
                            if addr['types'][0] in ('administrative_area_level_1','locality','sublocality'):
                                addr_components.append(addr)
                            else: pass
                    else: pass
            #for res in results:
            #    if res['types'][0] == 'sublocality':
            #        addr_components = res['address_components'][::-1][1:] 
            #        break
            #    elif res['types'][0] in ('street_address','route'):
            #        for addr in res['address_components'][::-1]:
            #            if addr['types'][0] in ('administrative_area_level_1','locality','sublocality'):
            #                addr_components.append(addr)
            #            else: pass
            #        break
            #    else: pass
                #import pprint as pp
                #pp.pprint(geodict)
            if addr_components:
                geoaddr = [ x['long_name'] for x in addr_components if not x['long_name'].isdigit() ]
                #if len(geoaddr) == 2: geoaddr.append(None)  # geoaddr:[province,city,None]
        else: 
            print 'ERROR: %s !!!' % geodict['status']
            if geodict['status'] == 'OVER_QUERY_LIMIT': geoaddr = None
    else: print 'ERROR: Geocoding Failed !!!'
    return geoaddr
        

def googleAreaLocation(latlon=None):
    """
    Google reverse geocoding: from lat/lon to area name: province, city, district.

    Parameter
    --------
    latlon: (latitude, longitude)

    Return
    --------
    geoaddr: [ province, city, district ]
    """
    # geodict: dict returned by google reverse geocoding api.
    geodict = googleGeocoding(latlon)
    # geoaddr: [ province, city, district ].
    geoaddr = parseGoogleGeocoding(geodict)
    return geoaddr


if __name__ == "__main__":
    import sys, os
    from wpp.util.net import setProxy
    try:
        import psyco
        psyco.bind(genLocReq)
        psyco.bind(parseGoogleGeocoding)
    except ImportError:
        pass

    #setProxy()

    #latlon = (24.47726, 112.64043)
    #latlon = (22.51637, 113.30049)
    #latlon = (30.628662, 104.048456)
    #latlon = (35.275769, 107.863598)
    #latlon = (31.984866, 120.509039)
    #latlon = (36.216297, 113.086912) # weird geocoding results.
    #latlon = (22.797012, 113.757158)
    #latlon = (28.832358, 121.628340)
    #latlon = (41.794252, 123.395062)
    #latlon = (41.772399, 123.410308)
    #latlon = (22.863804, 113.296862)
    latlon = (29.896468, 121.494344) # google has no result.
    geoaddr = googleAreaLocation(latlon)
    geoaddr = '>'.join(geoaddr)
    print geoaddr

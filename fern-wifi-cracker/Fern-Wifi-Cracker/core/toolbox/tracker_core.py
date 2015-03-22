#-------------------------------------------------------------------------------
# Name:        Fern_Track
# Purpose:     Tracking geographical location of Access points using mac address
#
# Author:      Saviour Emmanuel Ekiko
#
# Created:     14/06/2011
# Copyright:   (c) Fern Wifi Cracker 2011
# Licence:     <GNU GPL v3>
#
#
#-------------------------------------------------------------------------------
# GNU GPL v3 Licence Summary:
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.



import re
import json
import httplib

class Fern_Geolocation(object):
    def __init__(self):
        self.mac_address = str()

    def _fern_geo_access(self):
        geo_data = dict()
        api_key='{"version":"1.1.0","request_address":true,"wifi_towers":[{"mac_address":"%s","ssid":"","signal_strength":-50}]}'%(self.mac_address)
        api_data = httplib.HTTPConnection('www.google.com')
        api_data.request('POST','/loc/json',api_key)
        data_ = api_data.getresponse()
        if(data_):
            geo_data = json.loads(data_.read())
        return geo_data


    def get_fern_map(self):
        self._location_source = '''<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html style="height:100%">
  <head>
    <meta http-equiv="content-type" content="text/html; charset=UTF-8"/>
    <title>Google Maps</title>
    <script src="http://maps.google.com/maps?file=api&amp;v=2&amp;sensor=false&amp;key=ABQIAAAAzr2EBOXUKnm_jVnk0OJI7xSosDVG8KKPE1-m51RBrvYughuyMxQ-i1QfUnH94QxWIa6N4U6MouMmBA" type="text/javascript"></script>
  </head>
  <body onload="initialize()" onunload="GUnload()" style="height:100%;margin:0">


    <div id="map" style="width: 100%; height: 100%;"></div>


    <script type="text/javascript">
    function initialize(){
        if (GBrowserIsCompatible()) {
	  var latitude = ''' + str(self.get_coordinates()[0]) + ''';
	  var longitude = ''' + str(self.get_coordinates()[1]) + ''';
          var map = new GMap2(document.getElementById("map"));
          map.setCenter(new GLatLng(latitude,longitude),18);

          map.setMapType(G_SATELLITE_MAP);
          map.setUIToDefault();
          map.enableRotation();

          var Icon = new GIcon(G_DEFAULT_ICON);
          Icon.iconSize = new GSize(40, 40);
          Icon.image = "http://google-maps-icons.googlecode.com/files/wifi-logo.png";

          var point = new GLatLng(latitude,longitude);

          markerOptions = { icon:Icon };
          map.addOverlay(new GMarker(point, markerOptions));
	   }
    }

    </script>
  </body>

</html>
'''
        return self._location_source



    def isValid_Mac(self,mac_address):
        hex_digits = re.compile('([0-9a-f]{2}:){5}[0-9a-f]{2}',re.IGNORECASE)
        if re.match(hex_digits,mac_address):
            return True
        else:
            return False


    def set_mac_address(self,mac_address):
        if self.isValid_Mac(mac_address):
            mac_process = str(mac_address).replace(':','-')
            self.mac_address = mac_process


    def get_coordinates(self):
        geo_data = self._fern_geo_access()
        longitude = float(geo_data['location']['longitude'])
        latitude = float(geo_data['location']['latitude'])
        return (latitude,longitude)


    def get_all_geoinfo(self):
        return self._fern_geo_access()


    def get_location(self):
        location_process = self._fern_geo_access()
        location_data = location_process['location']
        return location_data

    def get_address(self):
        geo_data = self._fern_geo_access()
        address = geo_data['location']['address']
        return address


# mac_address = 00:CA:C9:67:23:45
#
# mac_location = Fern_Geolocation()
#
# if mac_location.isValid_Mac(mac_address):
#   mac_location.set_mac_address(mac_address)
#
# mac_location.get_fern_map() // Returns html source with map info
#
# mac_location.get_coordinates() // Returns latitude and longitude


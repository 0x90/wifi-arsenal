#!/usr/bin/env python
# -*- coding: UTF-8 -*-

'''
   Copyright 2010 Filia Dova, Georgios Migdos

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
'''

from xml.dom.minidom import parse
import os
import sys
import shutil
import math

class MapGenerator:
		
	def parseXMLFile(self, XMLFilename, outputDictionary, referenceDictionary):
		dom = parse(XMLFilename)
		for network in dom.getElementsByTagName('network'):
			latitude = ""
			longtitude = ""
			essid = ""
			channel = ""
			quality = ""
			qualityNum = 0
			security = ""
			address = ""
			frequency = ""
			signal = ""
			noise = ""
			for lat in network.getElementsByTagName('latitude'):
				if(len(lat.childNodes)>0):
					latitude = lat.childNodes[0].nodeValue
			for lon in network.getElementsByTagName('longtitude'):
				if(len(lon.childNodes)>0):
					longtitude = lon.childNodes[0].nodeValue
			for ssid in network.getElementsByTagName('essid'):
				if(len(ssid.childNodes)>0):
					essid = ssid.childNodes[0].nodeValue
			for chan in network.getElementsByTagName('channel'):
				if(len(chan.childNodes)>0):
					channel = chan.childNodes[0].nodeValue
			for qual in network.getElementsByTagName('quality'):
				if(len(qual.childNodes)>0):
					qualityNum = eval(qual.childNodes[0].nodeValue)*100
					quality = str(qualityNum)+"%"
			for sec in network.getElementsByTagName('security'):
				if(len(sec.childNodes)>0):
					security = sec.childNodes[0].nodeValue
			for mac in network.getElementsByTagName('address'):
				if(len(mac.childNodes)>0):
					address = mac.childNodes[0].nodeValue
			for freq in network.getElementsByTagName('frequency'):
				if(len(freq.childNodes)>0):
					frequency = freq.childNodes[0].nodeValue
			for sig in network.getElementsByTagName('signal'):
				if(len(sig.childNodes)>0):
					signal = sig.childNodes[0].nodeValue
			for nois in network.getElementsByTagName('noise'):
				if(len(nois.childNodes)>0):
					noise = nois.childNodes[0].nodeValue
					
			referenceKey = essid+":"+address
			newReferenceEntry = [essid, address, qualityNum]
			key = latitude+","+longtitude
			entry = [essid, channel, quality, security, address, frequency, signal, noise]
			
			try:
				referenceEntry = referenceDictionary[referenceKey]
				if(referenceEntry[2]<newReferenceEntry[2]):
					referenceDictionary[referenceKey] = newReferenceEntry
					try:
						mark = outputDictionary[key]
						networks = mark[1:]
						for network in networks:
							if((network[0]==newReferenceEntry[0])and(network[4]==newReferenceEntry[1])):
								mark.remove(network)
								mark.append(entry)
					except KeyError:
						outputDictionary[key] = []
						outputDictionary[key].append([latitude, longtitude])
						outputDictionary[key].append(entry)
					
			except KeyError:
				referenceDictionary[referenceKey] = newReferenceEntry
				try:
					mark = outputDictionary[key]
					mark.append(entry)
				except KeyError:
					outputDictionary[key] = []
					outputDictionary[key].append([latitude, longtitude])
					outputDictionary[key].append(entry)
				
	
	def generateOpenStreetMapsMap(self, outputDir, inputXMLFilesList, centerLon, centerLat):
		marks = {}
		refDict = {}
		
		htmlfile = "index.html"
		
		wifiMarker = os.path.join(os.path.dirname(__file__), "img", "marker.png")
		wifiMarkerFew = os.path.join(os.path.dirname(__file__), "img", "marker-few.png")
		wifiMarkerMany = os.path.join(os.path.dirname(__file__), "img", "marker-many.png")
		wifiMarkerOpen = os.path.join(os.path.dirname(__file__), "img", "marker-open.png")
		wifiMarkerFewOpen = os.path.join(os.path.dirname(__file__), "img", "marker-few-open.png")
		wifiMarkerManyOpen = os.path.join(os.path.dirname(__file__), "img", "marker-many-open.png")
		wifiIcon = os.path.join(os.path.dirname(__file__), "img", "wifi.png") 
		lockedIcon = os.path.join(os.path.dirname(__file__), "img", "locked.png")	
		
		script1 = os.path.join(os.path.dirname(__file__), "scripts", "bluff-min.js")	
		script2 = os.path.join(os.path.dirname(__file__), "scripts", "excanvas.js")
		script3 = os.path.join(os.path.dirname(__file__), "scripts", "js-class.js")
		bgImg = os.path.join(os.path.dirname(__file__), "img", "bg.png")
		
		if(not os.path.exists(outputDir)):
			os.mkdir(outputDir)
		elif(not os.path.isdir(outputDir)):
			print "Invallid output directory:\n\t"+outputDir
			exit(1)
		
		shutil.copy(wifiMarker, os.path.join(outputDir, "marker.png"))
		shutil.copy(wifiMarkerFew, os.path.join(outputDir, "marker-few.png"))
		shutil.copy(wifiMarkerMany, os.path.join(outputDir, "marker-many.png"))
		shutil.copy(wifiMarkerOpen, os.path.join(outputDir, "marker-open.png"))
		shutil.copy(wifiMarkerFewOpen, os.path.join(outputDir, "marker-few-open.png"))
		shutil.copy(wifiMarkerManyOpen, os.path.join(outputDir, "marker-many-open.png"))
		shutil.copy(wifiIcon, os.path.join(outputDir, "wifi.png"))
		shutil.copy(lockedIcon, os.path.join(outputDir, "locked.png"))
		shutil.copy(bgImg, os.path.join(outputDir, "bg.png"))
		shutil.copy(script1, os.path.join(outputDir, "bluff-min.js"))
		shutil.copy(script2, os.path.join(outputDir, "excanvas.js"))
		shutil.copy(script3, os.path.join(outputDir, "js-class.js"))
		
		for fname in inputXMLFilesList:
			self.parseXMLFile(fname, marks, refDict)
		
		outputFilePath = os.path.join(outputDir, htmlfile)
		outputFile = open(outputFilePath, "w")
		tempStr = '''<!DOCTYPE html>
  <html>
  <head>
    <meta http-equiv="Content-type" content="text/html;charset=UTF-8" />
    <title>WNMC</title>
    <style type="text/css">
#map {
		position: absolute;
        right: 0px;
        left: 0px;
        height: 100%;
        border: 0px;
        padding: 0px;        
     }
body {
        border: 0px;
        margin: 0px;
        padding: 0px;
        height: 100%;  
        font-family: Arial, Tahoma;      
     }
.info_header{
	font-size:16px;
}
.item-header{
	font-size:14px;
	font-weight: bold;
	text-decoration:underline;
}
.properties-item{
	font-size:12px;
	font-weight: bold;
}
ul.network{
	font-size:14px;
	list-style-image: url('wifi.png');
}
ul.properties{
	font-size:12px;
	list-style-type: disc;
	list-style-image: none;
	margin-left: 0;
	padding-left: 0;
}
    </style>
    <script type="text/javascript" src="js-class.js"></script>
	<script type="text/javascript" src="bluff-min.js"></script>
	<script type="text/javascript" src="excanvas.js"></script>
    <script type="text/javascript" src="http://www.openlayers.org/api/OpenLayers.js"></script>
    <script type="text/javascript" src="http://www.openstreetmap.org/openlayers/OpenStreetMap.js"></script>
    <script type="text/javascript" src="http://api.maps.yahoo.com/ajaxymap?v=3.0&amp;appid=euzuro-openlayers"></script> 
    <script type="text/javascript">
	// <!--
        var map;
        
        var fromProjection = new OpenLayers.Projection("EPSG:4326");   // Transform from WGS 1984
        var toProjection   = new OpenLayers.Projection("EPSG:900913"); // to Spherical Mercator Projection
 
        function init(){
            map = new OpenLayers.Map('map',
                    { maxExtent: new OpenLayers.Bounds(-20037508.34,-20037508.34,20037508.34,20037508.34),
                      numZoomLevels: 18,
                      maxResolution: 156543.0399,
                      units: 'm'
                    });
            map.addLayer(new OpenLayers.Layer.OSM());
            
            var markers = new OpenLayers.Layer.Markers( "Markers" );
	    map.addLayer(markers);\n\n\n\n'''
	    	outputFile.write(tempStr.encode('utf-8'))
		for k,v in marks.iteritems():
			lat = v[0][0]
			lon = v[0][1]
			
			description = "<ul class=\"network\">"
			foundOpen = False
			for network in v[1:]:
				essid = network[0]+"&nbsp;"
				essid = essid.replace("'", "&lsquo;")
				channel = network[1]
				quality = network[2]
				security = network[3]
				address = network[4]
				frequency = network[5]
				signal = network[6]
				noise = network[7]
				security_string=""
				if(security=="on"):
					security_string = "<img src=\"locked.png\">"
				else:
					foundOpen = True
				description = description + "<li><span class=\"item-header\">"+ essid + "</span> "+security_string+"<ul class=\"properties\"><li><span class=\"properties-item\">Addr:</span>&nbsp;&nbsp;" + address + "</li><li><span class=\"properties-item\">Ch:</span>&nbsp;&nbsp;" + channel + ",&nbsp;&nbsp;<span class=\"properties-item\">Q:</span>&nbsp;&nbsp;" + quality+ "</li><li><span class=\"properties-item\">Freq:</span>&nbsp;&nbsp;" + frequency+ "</li><li><span class=\"properties-item\">S:</span>&nbsp;&nbsp;" + signal+ " dBm,&nbsp;&nbsp;<span class=\"properties-item\">N:</span>&nbsp;&nbsp;" + noise+ " dBm</li></ul></li><br>"
			description = description + "</ul>"
			icon = 'marker.png'
			l = len(v[1:])
			if(not foundOpen):
				if ((l>1) and (l<=4) ):
					icon = 'marker-few.png'
				elif (l>4):
					icon = 'marker-many.png'
			else:
				icon = 'marker-open.png'
				if ((l>1) and (l<=4) ):
					icon = 'marker-few-open.png'
				elif (l>4):
					icon = 'marker-many-open.png'
			tempStr = "            setMarker(markers, " +lon+", "+lat+", '"+description+"', '"+icon+"');\n\n"
			outputFile.write(tempStr.encode('utf-8'))
			
		tempStr = '''\n\n\n\n            map.addControl(new OpenLayers.Control.LayerSwitcher());
 
            var lonLat = new OpenLayers.LonLat('''+centerLon+", "+centerLat+''').transform( fromProjection, toProjection);
            if (!map.getCenter()) map.setCenter (lonLat, 16);
        }
        
        function setMarker(markers, lon, lat, contentHTML, icon){
		var lonLatMarker = new OpenLayers.LonLat(lon, lat).transform( fromProjection, toProjection);
		var feature = new OpenLayers.Feature(markers, lonLatMarker);
		feature.closeBox = true;
		feature.popupClass = OpenLayers.Class(OpenLayers.Popup.FramedCloud, {minSize: new OpenLayers.Size(300, 180) } );
		feature.data.popupContentHTML = contentHTML;
		feature.data.overflow = "auto";

		var icon = new OpenLayers.Icon(icon,new OpenLayers.Size(20, 50), new OpenLayers.Pixel(-10,-50));
		var marker = new OpenLayers.Marker(lonLatMarker, icon);
		marker.feature = feature;

		var markerClick = function(evt) {
			if (this.popup == null) {
				this.popup = this.createPopup(this.closeBox);
				map.addPopup(this.popup);
				this.popup.show();
			} else {
				this.popup.toggle();
			}
			OpenLayers.Event.stop(evt);
		};
		marker.events.register("mousedown", feature, markerClick);

		markers.addMarker(marker);
	}
	
	
        // -->
    </script>\n\n'''
		outputFile.write(tempStr.encode('utf-8'))
		tempStr = '''     
  </head>
  <body onload="init()">
    <div id="map"></div>\n\n'''
		outputFile.write(tempStr.encode('utf-8'))
		stats = Stats(50, inputXMLFilesList).getStats()
		tempStr = '''
		<div style="position:absolute; bottom:35px; right: 30px; overflow: hidden; width: 342px; height:365px;">
			<div style="position:absolute; border-style:solid; border-width:1px; background-image: url('bg.png'); bottom: 305px; right: 0px; height:58px; width: 340px;">
				<div style="position:absolute; bottom: 10px; right: 20px;">
					<div style="left:10px; width: 300px; text-align: center;">
						<img style="position: absolute; bottom:-5px; left:0px;" src="marker.png" alt="marker" />
						<span style="position: absolute; bottom:4px; left:32px; font-family: arial; font-weight:bold; font-size: 14px; color: rgb(66,66,66);"> : 1 WN</span>
						<img style="position: absolute; bottom:-5px; left:100px;" src="marker-few.png" alt="marker-few" />
						<span style="position: absolute; bottom:4px; left:127px; font-family: arial; font-weight:bold; font-size: 14px; color: rgb(66,66,66);"> : 2-4 WNs</span>
						<img style="position: absolute; bottom:-5px; right:65px;" src="marker-many.png" alt="marker-many" />
						<span style="position: absolute; bottom:4px; right:0px; font-family: arial; font-weight:bold; font-size: 14px; color: rgb(66,66,66);"> : >4 WNs</span>
					</div>
				</div>
			</div>
			<div style="position:absolute; border-style:solid; border-width:1px; background-image: url('bg.png'); bottom: 250px; right: 0px; height:45px; width: 340px;">
				<div style="position:absolute; bottom: 10px; right: 20px;">
					<div style="left:10px; width: 300px; text-align: center;">
						<span style="font-family: arial; font-weight:bold; font-size: 14px; color: rgb(66,66,66);">Networks: '''+ str(stats[0]) + " - Open: "+ str(stats[2]) +'''</span>
					</div>
				</div>
			</div>
			<div style="position:absolute; border-style:solid; border-width:1px; background-image: url('bg.png'); bottom: 0px; right: 0px; height:240px; width: 340px;">
				<div style="position:absolute; bottom: 10px; right: 20px;">
					<div style="left:10px; width: 300px; text-align: center;">
						<span style="font-family: arial; font-weight:bold; font-size: 14px; color: rgb(66,66,66);">Access Points / Channel</span>
					</div>
					
					<div style="top:40px; left:10px;">
						<canvas id="graph1" width="300" height="200"></canvas>
					</div>
				</div>
			</div>
        </div>

        <script type="text/javascript">
            var g = new Bluff.Mini.Bar('graph1', '300x200');
            g.title = '';
            g.tooltips = true;
            g.hide_mini_legend = true;

            g.set_theme({
                colors: ['#4062D6'],
                marker_color: '#aea9a9',
                font_color: '#2911A9',
                background_colors: ['#CCCCCC', '#F3F3F3']
            });

            g.data("", '''
		outputFile.write(tempStr.encode('utf-8'))
		tempStr = str(stats[1])
		outputFile.write(tempStr.encode('utf-8'))
		tempStr = ''');
            g.labels = {0: '1', 1: '2', 2: '3', 3: '4', 4: '5', 5: '6', 7: '8', 8: '9', 9: '10', 10: '11', 11: '12', 12: '13', 13: '14'};

            g.draw();
        </script>
        '''
		outputFile.write(tempStr.encode('utf-8'))

		tempStr = '''</body>
</html>'''
		outputFile.write(tempStr.encode('utf-8'))
		outputFile.close()


class Stats:
	
	def __init__(self, minDistance, XMLFilenames):
		self.clear()
		for fname in XMLFilenames:
			self.parseXMLFile(fname)
		self.runStats(minDistance)
		
	def clear(self):
		self.networks = []
		self.total = 0
		self.totalOpen = 0
		self.channelsCounter = [0,0,0,0,0,0,0,0,0,0,0]
	
	def getStats(self):
		return self.total, self.channelsCounter, self.totalOpen
	
	def getNetworksList(self):
		return self.networks
		
	def parseXMLFile(self, XMLFilename):		
		dom = parse(XMLFilename)
		for network in dom.getElementsByTagName('network'):
			latitude = ""
			longtitude = ""
			essid = ""
			channel = ""
			quality = ""
			security = ""
			address = ""
			frequency = ""
			signal = ""
			noise = ""
			for lat in network.getElementsByTagName('latitude'):
				if(len(lat.childNodes)>0):
					latitude = lat.childNodes[0].nodeValue
			for lon in network.getElementsByTagName('longtitude'):
				if(len(lon.childNodes)>0):
					longtitude = lon.childNodes[0].nodeValue
			for ssid in network.getElementsByTagName('essid'):
				if(len(ssid.childNodes)>0):
					essid = ssid.childNodes[0].nodeValue
			for chan in network.getElementsByTagName('channel'):
				if(len(chan.childNodes)>0):
					channel = chan.childNodes[0].nodeValue
			for qual in network.getElementsByTagName('quality'):
				if(len(qual.childNodes)>0):
					quality = str(eval(qual.childNodes[0].nodeValue)*100)+"%"
			for sec in network.getElementsByTagName('security'):
				if(len(sec.childNodes)>0):
					security = sec.childNodes[0].nodeValue
			for mac in network.getElementsByTagName('address'):
				if(len(mac.childNodes)>0):
					address = mac.childNodes[0].nodeValue
			for freq in network.getElementsByTagName('frequency'):
				if(len(freq.childNodes)>0):
					frequency = freq.childNodes[0].nodeValue
			for sig in network.getElementsByTagName('signal'):
				if(len(sig.childNodes)>0):
					signal = sig.childNodes[0].nodeValue
			for nois in network.getElementsByTagName('noise'):
				if(len(nois.childNodes)>0):
					noise = nois.childNodes[0].nodeValue
			
			entry = [essid, int(channel), quality, security, address, frequency, signal, noise, float(latitude), float(longtitude)]
			self.networks.append(entry)
			
	
	def runStats(self, minDistance):
		self.channelsCounter = [0,0,0,0,0,0,0,0,0,0,0,0,0,0]
		self.total = len(self.networks)
		for network in self.networks:			
			chn = network[1]
			self.channelsCounter[chn-1] = self.channelsCounter[chn-1]+1
			if(network[3]!="on"):
				self.totalOpen += 1
		
	def calculate_distance(self, lat1, lon1, lat2, lon2):
		'''
		* Calculates the distance between two points given their (lat, lon) co-ordinates.
		* It uses the Spherical Law Of Cosines (http://en.wikipedia.org/wiki/Spherical_law_of_cosines):
		*
		* cos(c) = cos(a) * cos(b) + sin(a) * sin(b) * cos(C)                        (1)
		*
		* In this case:
		* a = lat1 in radians, b = lat2 in radians, C = (lon2 - lon1) in radians
		* and because the latitude range is  [-π/2, π/2] instead of [0, π]
		* and the longitude range is [-π, π] instead of [0, 2π]
		* (1) transforms into:
		*
		* x = cos(c) = sin(a) * sin(b) + cos(a) * cos(b) * cos(C)
		*
		* Finally the distance is arccos(x)
		'''
		
		if ((lat1 == lat2) and (lon1 == lon2)):
			return 0
	
		try:
			delta = lon2 - lon1
			a = math.radians(lat1)
			b = math.radians(lat2)
			C = math.radians(delta)		
			x = math.sin(a) * math.sin(b) + math.cos(a) * math.cos(b) * math.cos(C)		
			distance = math.acos(x) # in radians
			distance  = math.degrees(distance) # in degrees
			distance  = distance * 60 # 60 nautical miles / lat degree
			distance = distance * 1852 # conversion to meters
			distance  = round(distance)
			return distance;
		except:
			return 0


if(len(sys.argv)<5):
	print "Usage:\n\tpython mapgenerator.py <longtigude> <latitude> <output_dir> <input_files>\n"
	print "\tlongtitude:\tThe longtitude of the default center of the map."
	print "\tlatitude:\tThe latitude of the default center of the map."
	print "\toutput_dir:\tThe location where the resulting html file and images will be saved."
	print "\tinput_files:\tThe XML files that were generated by the scanner application.\n"
else:
	generator = MapGenerator()
	#lon="23.70823"
	#lat="37.97009"
	generator.generateOpenStreetMapsMap(sys.argv[3], sys.argv[4:], sys.argv[1], sys.argv[2])


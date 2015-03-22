#!/usr/bin/env python


class Icon(object):
    """ Icon properities that can be used by different icon type of Point """
    def __init__(self, id='icon'):
        self.id = id
        self.image = ""             # default Google Maps icon
        self.shadow = ""
        self.iconSize = (12, 20)    # these settings match above icon
        self.shadowSize = (22, 20)
        self.iconAnchor = (6, 20)
        self.infoWindowAnchor = (5, 1)


class Point(object):
    """ icon properities that can be used by your points """
    def __init__(self, loc=[39.92263,116.47287], txt='new point', iconid='icon'):
        self.loc = loc       # (lat, lon)
        self.txt = txt       # comment
        self.iconid = iconid # id of icon type

    def getAttrs(self):
        return [ self.loc[0], self.loc[1], self.txt, self.iconid ]

        
class Map(object):
    """ Basic map class that contains map properties and a list of points """
    def __init__(self, id="map", pointlist=None):
        self.id      = id      # div id        
        self.width   = "1000px" # map div width
        self.height  = "600px" # map div height
        self.center  = (39.8957421333,116.344589908)  # center of init view
        self.zoom    = "1"     # zoom level
        self.navctls = True    # show google map navigation controls
        self.mapctls = True    # show toogle map type (sat/map/hybrid) controls
        if pointlist == None: self.points = [] # empty point list
        else: self.points = pointlist          # supplied point list
    
    def __str__(self):
        return self.id
    
    def addpoint(self, point):
        """ Add a point (lat, long, html, icon) """
        self.points.append(point)
        self.points = GMap._chkIcons(self.points)


class GMap(object):
    """
    Python wrapper class for Google Maps API.
    GMap Holds all the maps and necesary html/javascript for a complete page/view. 
    It allows you to hold more than one map per page.
    """
    
    def __str__(self):
        return "GMap"
    
    _icons = [] # static attr, shared in this 'Map' module.
    def __init__(self, key=None, maplist=None, iconlist=None):
        """ Default values """
        if key == None:  # google key
            #self.key = "ABQIAAAAQQRAsOk3uqvy3Hwwo4CclBTrVPfEE8Ms0qPwyRfPn-\
            #        DOTlpaLBTvTHRCdf2V6KbzW7PZFYLT8wFD0A"     # borrowed 
            self.key = "ABQIAAAAUSoeJtepJhkFJBWO1OU4thR2L4ipJp-\
                    hfOESjcOm0U8jmW_-4RSJ9nbM2O84oU28-VALYyIZBa0JmQ" # own
        else: self.key = key
        if maplist == None: self.maps = [ Map() ]
        else: self.maps = maplist
        if iconlist == None: GMap._icons = [ Icon() ]
        else: GMap._icons = iconlist

        for map in self.maps:
            map.points = GMap._chkIcons(map.points)

    @staticmethod
    def _chkIcons(points):
        """ Icon id validation state check.
            points: Point object list.
        """
        gmap_icons = [ icon.id for icon in GMap._icons ]
        for point in points:
            if not point.iconid in gmap_icons:
                newid = gmap_icons[0]
                print '\nInvalid icon id: \'%s\'! (point: %s)\nResetting to \'%s\'\n' %\
                        (point.iconid, point.getAttrs()[:2], newid)
                point.iconid = newid  # first existing icon id
        return points
    
    def addicon(self, icon):
        GMap._icons.append(icon)
        
    def _navcontroljs(self,map):
        """ Navigation bar control """    
        if map.navctls:
            return  "%s%s.gmap.addControl(new GSmallMapControl());\n" % \
                ('\t'*4, map.id)
        else: return ""    
    
    def _mapcontroljs(self,map):
        """ Map type(map/satellite/hybrid) bar control"""    
        if map.mapctls:
            return  "%s%s.gmap.addControl(new GMapTypeControl());\n\n\
                %s.gmap.setMapType(G_SATELLITE_MAP);\n" % \
                ('\t'*4, map.id, map.id)
        else: return ""     
    
    def _mapjs(self,map):
        js = "%s_points = %s;\n" % (map.id, [point.getAttrs() for point in map.points])
        
        js = js.replace("(", "[")
        js = js.replace(")", "]")
        js = js.replace("u'", "'")
        js = js.replace("''","")    
        for icon in GMap._icons:
            js = js.replace("'" + icon.id + "'", icon.id)
        js += "%s var %s = new Map('%s', %s_points, %s, %s, %s);\n\n%s\n%s" % \
              ('\t'*4, map.id, map.id, map.id, map.center[0], map.center[1], map.zoom, 
               self._mapcontroljs(map), self._navcontroljs(map))
        return js
    
    def _iconjs(self,icon):
        js = """var %s = new GIcon(); 
                %s.image = "%s";
                %s.shadow = "%s";
                %s.iconSize = new GSize(%s, %s);
                %s.shadowSize = new GSize(%s, %s);
                %s.iconAnchor = new GPoint(%s, %s);
                %s.infoWindowAnchor = new GPoint(%s, %s); """ % \
            (icon.id, icon.id, icon.image, icon.id, icon.shadow, 
             icon.id, icon.iconSize[0], icon.iconSize[1], 
             icon.id, icon.shadowSize[0], icon.shadowSize[1], 
             icon.id, icon.iconAnchor[0], icon.iconAnchor[1], 
             icon.id, icon.infoWindowAnchor[0], icon.infoWindowAnchor[1])
        return js
     
    def _buildicons(self):
        js = ""
        if (len(GMap._icons) > 0):
            for icon in GMap._icons: 
                js = js + self._iconjs(icon) + '\n\t\t\t\t\t'  
        return js
    
    def _buildmaps(self):
        js = ""
        for map in self.maps: 
            js = js + self._mapjs(map) + '\n'
        return js

    def gmapjs(self):
        """ Returns complete js frame for rendering google map """
        
        self.js = """\n<script src=\"http://maps.google.com/maps?file=api&amp;v=2&amp;\
                    sensor=false&amp;key=%s\" type="text/javascript"></script>
        <script type="text/javascript">

        function load() {
            if (GBrowserIsCompatible()) {
            function Point(lat,long,html,icon) {
                  this.gpoint = new GMarker(new GLatLng(lat,long),icon);
                  this.html = html;
                  
               }               
               function Map(id,points,lat,long,zoom) {
                  this.id = id;
                  this.points = points;
                  this.gmap = new GMap2(document.getElementById(this.id));
                  this.gmap.setCenter(new GLatLng(lat, long), zoom);
                  this.markerlist = markerlist;
                  this.addmarker = addmarker;
                  this.array2points = array2points;
                   
                  function markerlist(array) {
                     for (var i in array) {
                        this.addmarker(array[i]);
                     }
                  }
                  function array2points(map_points) {            
                      for (var i in map_points) {  
                        points[i] = new Point(map_points[i][0], map_points[i][1], \
                                map_points[i][2], map_points[i][3]);         }
                      return points;   
                    }                  
                  function addmarker(point) {
                     if (point.html) {
                       // change click to mouseover or other mouse action
                       GEvent.addListener(point.gpoint, "click", function() { 
                           point.gpoint.openInfoWindowHtml(point.html);
                        
                       });
                     }
                     this.gmap.addOverlay(point.gpoint);  
                  }
                  this.points = array2points(this.points);
                  this.markerlist(this.points);
            }  
                    %s

                    %s
            }
        }
        </script>
        """ % (self.key, self._buildicons(),self._buildmaps())
        return self.js 
    
    def genHTML(self):
        """returns a complete html page containing google map(s)"""
        # select the max value for width/height of all self.maps
        map_width  = max([ map.width  for map in self.maps ])
        map_height = max([ map.height for map in self.maps ])
        self.html = """
            <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
            "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
            <html xmlns="http://www.w3.org/1999/xhtml">
              <head>
                <meta http-equiv="content-type" content="text/html; charset=utf-8"/>
                <title>GMap v2</title>
                %s
              </head>

              <body onload="load()" onunload="GUnload()">
                <div id="map" style="width: %s; height: %s"></div>
              </body>
            </html> """ % (self.gmapjs(), map_width, map_height)
        return self.html


if __name__ == "__main__":

    gmap = GMap()          # add an icon & map by default

    icon2 = Icon('icon2')  # add an extra type of icon
    icon2.image  = "kml/icons/bluedot.png" 
    icon2.shadow = "kml/icons/dotshadow.png" 
    gmap.addicon(icon2)
    print 'icon types: (img: null when default)\n%s' % ('-'*35)
    for icon in gmap._icons: 
        print 'id:\'%-5s\' img:\'%s\'' % (icon.id, icon.image)

    gmap.maps[0].zoom = 17
    apoint = Point(loc=[39.922625,116.472771], txt='<u>hello</u>!', iconid='icon2')     
    gmap.maps[0].addpoint(apoint)
    print 'maps: \n%s' % ('-'*35)
    for map in gmap.maps: 
        for point in map.points:
            print 'id:\'%-5s\'pts:\n\'%s\'' % (map.id, point.getAttrs())
    
    open('html/map.htm','wb').write(gmap.genHTML())   # generate test file

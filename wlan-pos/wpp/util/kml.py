#!/usr/bin/env python
import sys
import csv
import os
import time
import random
import pprint 
import pylibkml
#from config import icon_types


def genKML(data, kmlfile, icons):
    """
    Generating KML file with input data.

    Parameters
    ----------
    data: [ [mandatory, optional], ... ] =
           [ [[lat,lon,title,desc], [mac,rss,noise,encrypt]], ... ],
        "desc" is either description for physical address or bssid for WLAN AP.
    kmlfile: abs path & filename.
    icons: icons used for pinpointing, {'key':['"key fullname"', iconfile]}.
    """
    optional = 0

    kmlout = open(kmlfile,'w')
    # KML Header
    kmlout.write('<?xml version="1.0" encoding="UTF-8"?>\n')
    kmlout.write('<kml xmlns="http://earth.google.com/kml/2.0">\n')
    kmlout.write('<Document>\n')
    for type in icons:
        kmlout.write(' <Style id=%s> \n\
                        <IconStyle>\n\
                          <Icon>\n\
                              <href>%s</href>\n\
                          </Icon>\n\
                        </IconStyle>\n\
                       </Style>\n'
                  % (icons[type][0], icons[type][1]) )
    kmlout.write('<name>WLAN Locationing Mapping</name>\n')
    kmlout.write('<Folder>\n')
    kmlout.write('<name>Offline Calibration/Online Location</name>\n')
    kmlout.write('<visibility>1</visibility>\n')

    for line in data:
        print line
        if len(line) == 2:
            optional = 1
            mac = line[1][0]; rss = line[1][1]; noise = line[1][2]; encrypt = line[1][3]
        title=line[0][2]; desc=line[0][3]; lat = line[0][0]; lon = line[0][1]
        kmlout.write('\n')
        kmlout.write(' <Placemark>\n')
        kmlout.write(' <name>%s</name>\n' % title)
        kmlout.write(' <description><![CDATA[\n\
                        <p style="font-size:8pt;font-family:monospace;">(%s, %s)</p>\n\
                        <ul>\n\
                        <li> %s </li>\n'
                        % (lon, lat, desc) )
        if optional == 1:
            kmlout.write('<li> %s </li>\n\
                         <li> %s </li>\n'
                         % (mac,encrypt) )
        kmlout.write('</ul> ]]>\n\
                       </description>\n')
        kmlout.write(' <View>\n\
                        <longitude>%s</longitude>\n\
                        <latitude>%s</latitude>\n\
                       </View>\n'
                         % (lon,lat) )
        if optional == 1:
            if encrypt =='on': styleurl = '#encrypton'
            elif encrypt == 'off': styleurl = '#encryptoff'
        else: styleurl = '#reddot'
        kmlout.write(' <styleUrl>%s</styleUrl>\n' % styleurl )

        kmlout.write(' <Point>\n\
                        <extrude>1</extrude>\n\
                        <altitudeMode>relativeToGround</altitudeMode>\n\
                        <coordinates>%s,%s,0</coordinates>\n\
                       </Point>\n' 
                       % (lon,lat) )
        kmlout.write(' </Placemark>\n')
    # KML Footer
    kmlout.write('</Folder>\n')
    kmlout.write('</Document>\n')
    kmlout.write('</kml>')
    kmlout.close()


def genKML_FPP(csvfile, kmlfile):
    """
    csvfile: FPP-WPP compatible upload sampling csv data collected by MS,
        format: spid,servid,time,imsi,imei,useragent,mcc,mnc,lac,cid,cellrss,lat,lon,h,wlanmacs,wlanrsss.
        e.g. 12,34,20100921-133623,4600,86200,MT710,460,0,7,41,-87,39.92,116.34,52,00:24:01:c8:f4:b2,-79
    kmlfile: name of output KML file.
    """
    if not os.path.isfile(csvfile):
        sys.exit('\n%s is NOT a file!' % (csvfile))
        
    rawdat = csv.reader( open(csvfile,'r') )

    #icon_href = 'http://maps.google.com/mapfiles/kml/shapes/shaded_dot.png'
    #icon_href = 'http://maps.google.com/mapfiles/kml/pushpin/wht-pushpin.png'
    icon_href = 'http://maps.google.com/mapfiles/kml/paddle/wht-blank.png'
    balloon_txt = '<![CDATA[<BODY bgcolor="ffffff">\n<h3>Wireless Sample Data'+\
      '<TABLE BORDER=1>\n'+\
      '<tr><td><b>Cell ID, RSSI</b></td><td>$[cellid],$[cellrss]</td></tr>\n'+\
      '<tr><td><b>Date/Time</b></td><td>$[datetime]</td></tr>\n'+\
      '<tr><td><b>Latitude,Longitude</b></td><td>$[lat],$[lon]</td></tr>\n'+\
      '<tr><td><b>UserAgent</b></td><td>$[useragent]</td></tr>\n'+\
      '<tr><td><b>WLAN APs</b></td><td>$[wlanmacs]</td></tr>\n'+\
      '<tr><td><b>WLAN RSSIs</b></td><td>$[wlanrsss]</td></tr>\n'+\
      '</TABLE></BODY>'

    cids_recs = {}
    try:
        for rec in rawdat:
            cid = rec[6]
            if not cid in cids_recs:
                cids_recs[cid] = [ rec ]
            else:
                cids_recs[cid].append(rec)
    except csv.Error, e:
        sys.exit('\nERROR: %s, line %d: %s!\n' % (csvfile, rawdat.line_num, e))
    #pp.pprint(cids_recs)
    print 'cid count:', len(cids_recs)

    folders = []
    styles = []

    for cid in cids_recs:
        cid_recs = cids_recs[cid]

        libKml = pylibkml.Kml()

        randval = hex( random.randint(1, 16777215) )[2:] # int(0xffffff)=16777215
        hexcode = 'ff' + (6 - len(randval)) * '0' + randval
        #print 'hex: %s: %s' % (hexcode, len(hexcode))
        iconstyleicon = libKml.create_iconstyleicon({'href': icon_href})
        iconstyle = libKml.create_iconstyle({'color':hexcode, 
                                             'scale':1.0, 
                                         'colormode':'normal', 
                                              'icon':iconstyleicon})
        styleid = 'style-cid%s'%(cid)
        balloonstyle = libKml.create_balloonstyle({'text':balloon_txt, 'bgcolor':'ffffffff'})
        styles.append(libKml.create_style({'id':styleid, 
                                 'balloonstyle':balloonstyle, 
                                    'iconstyle':iconstyle}))
        placemarks = []
        for cid_rec in cid_recs:
            # cid_rec: compatible with fpp-wpp rawdata spec, which defines the sampling data format: 
            # IMEI,IMSI,UserAgent,MCC,MNC,LAC,CI,rss,lat,lon,h,wlanmacs,wlanrsss,Time
            uagent = cid_rec[2]; datetime = cid_rec[13]
            #cellmml = "%s|%s|%s"%(cid_rec[3],cid_rec[4],cid_rec[5]) # mcc,mnc,lac
            cellrss = cid_rec[7] #cid = cid_rec[6] 
            lat = cid_rec[8]; lon = cid_rec[9]
            wlanmacs = cid_rec[11]; wlanrsss = cid_rec[12]

            # neusoft format, deprecated.
            #uagent = cid_rec[5]; datetime = cid_rec[2]
            ##cellmml = "%s|%s|%s"%(cid_rec[6],cid_rec[7],cid_rec[8]) # mcc,mnc,lac
            #cellrss = cid_rec[10] #cid = cid_rec[9] 
            #lat = cid_rec[11]; lon = cid_rec[12]
            #wlanmacs = cid_rec[14]; wlanrsss = cid_rec[15]

            if lon and lat:
                coord = libKml.create_coordinates(float(lon),float(lat))
            else:
                continue
            point = libKml.create_point({'coordinates':coord})

            data = []
            data.append(libKml.create_data({'name':'useragent','value':uagent}))
            data.append(libKml.create_data({'name':'datetime','value':datetime}))
            data.append(libKml.create_data({'name':'lat','value':lat}))
            data.append(libKml.create_data({'name':'lon','value':lon}))
            data.append(libKml.create_data({'name':'cellid','value':cid})) 
            data.append(libKml.create_data({'name':'cellrss','value':cellrss})) 
            data.append(libKml.create_data({'name':'wlanmacs','value':wlanmacs})) 
            data.append(libKml.create_data({'name':'wlanrsss','value':wlanrsss})) 
            extdata = libKml.create_extendeddata({'data':data})

            placemarks.append(libKml.create_placemark({'name':cid, 
                                                      'point':point, 
                                               'extendeddata':extdata, 
                                                   'styleurl':'#'+styleid}))
        folders.append(libKml.create_folder({'name':cid,
                                        'placemark':placemarks}))

    document = libKml.create_document({'folder':folders, 'style':styles})
    kml = libKml.create_kml({'document':document})

    #label = time.strftime('%Y%m%d-%H%M%S')
    label = 'neusoft'
    if not kmlfile:
        kmlfile = '%s/radiomap_%s.kml' % (kmlpath, label)
    kfile = open(kmlfile, 'w')
    kfile.write(pylibkml.Utilities().SerializePretty(kml))
    kfile.close()


if __name__ == "__main__":

    #homedir = os.path.expanduser('~')
    #for type in icon_types:
    #    icon_types[type][1] = os.getcwd() + icon_types[type][1]

    arglen = len(sys.argv)
    if (not arglen==2) and (not arglen==3):
        sys.exit('\nPlease type: %s <csv file> [label]\n' % (sys.argv[0]))
    else:
        csvfile = sys.argv[1]
        if arglen == 3:
            label = sys.argv[2]
        else:
            label = 'cmri'

    pp = pprint.PrettyPrinter(indent=2)

    kmlpath = 'kml'
    kmlfile = '%s/radiomap_%s.kml' % (kmlpath, label)
    genKML_FPP(csvfile, kmlfile)

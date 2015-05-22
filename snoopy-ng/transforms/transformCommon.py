from MaltegoTransform import *
from datetime import datetime
from sqlalchemy import create_engine, MetaData, select, and_
import logging
import re
from dateutil import parser
import os
logging.basicConfig(level=logging.DEBUG,filename='/tmp/maltego_logs.txt',format='%(asctime)s %(levelname)s: %(message)s',datefmt='%Y-%m-%d %H:%M:%S')
logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO) #Log SQL queries

if not os.path.isdir("/etc/transforms"):
    print "ERROR: '/etc/tranforms' symlink doesn't exist"
    exit(-1)
f = open("/etc/transforms/db_path.conf")
dbms = f.readline().strip()

try:
    db = create_engine(dbms)
#db.echo = True
    metadata = MetaData(db)
    metadata.reflect()
except Exception,e:
    print "ERROR: Unable to communicate with DB specified in /etc/transforms/db_path.txt ('%s'). Error was '%s'" % (dbms,str(e))
    exit(-1)


TRX = MaltegoTransform()
TRX.parseArguments(sys.argv)

start_time = "2000-01-01 00:00:00.0"
end_time = "2037-01-01 00:00:00.0"
drone, location, mac, ssid, domain, observation = (None,)*6

filters = []

mtk = metadata.tables['mtk']
users = metadata.tables['users']
sess  = metadata.tables['sessions']

#Hack to know if we're local or TDS
#Option One, TDS (this should be made into the new TRX):
if len(sys.argv) < 2:
    from Maltego import *
    MaltegoXML_in = sys.stdin.read()
    TRX = MaltegoTransform()
    print "Content-type: xml\n\n"
    if MaltegoXML_in <> '':
        m = MaltegoMsg(MaltegoXML_in)

        #This method of extraction feels horrendous. Find a better way.
        drone = m.AdditionalFields.get('properties.drone')
        location = m.AdditionalFields.get('properties.dronelocation')
        start_time = m.AdditionalFields.get('properties.start_time')
        end_time = m.AdditionalFields.get('properties.end_time')
        mac = m.AdditionalFields.get('properties.mac')
        ssid = m.AdditionalFields.get('properties.ssid')
        domain = m.AdditionalFields.get('properties.fqdn')
        observation = m.AdditionalFields.get('properties.observation')
        #shadowKey = m.AdditionalFields.get("properties.ShadowKey")
        shadowKey = m.TransformSettings.get("ShadowKey")
        #In case variables were not properties.*
        if shadowKey is None:
            shadowKey = m.AdditionalFields.get("ShadowKey")
        if drone is None:
            drone = m.AdditionalFields.get('drone')
        if location is None:
            location = m.AdditionalFields.get('location')
        if start_time is None:
            start_time = m.AdditionalFields.get('start_time')
        if end_time is None:
            end_time = m.AdditionalFields.get('end_time')
        if mac is None:
            mac = m.AdditionalFields.get('mac')
        if ssid is None:
            ssid = m.AdditionalFields.get('ssid')
        if domain is None:
            domain = m.AdditionalFields.get('fqdn')
        if observation is None:
            observation = m.AdditionalFields.get('observation')

        #If no start and end times specified fetch all. 
        #It might make more sense to just remove the time filter.
        if start_time is None:
            start_time = "2000-01-01 00:00:00.0"
        if end_time is None:
           end_time = "2037-01-01 00:00:00.0"

        if not shadowKey or shadowKey == ' ':
            TRX.addException("Bad shadow key entered! Please obtain it via your www.ShadowLightly.com account.")
            TRX.throwExceptions()
            exit(0)
        ss = select([mtk.c.mtkey]).where(mtk.c.mtkey == shadowKey)
        r = db.execute(ss).fetchall()
        logging.debug("Key is %s" %shadowKey)
        logging.debug("Query is %s" %str(ss))
        logging.debug("Results of R: %s" %str(r))
        logging.debug( "Length of R: %d" %len(r))
        if len(r) < 1:
            TRX.addException("Bad shadow key entered! Please obtain it via your www.ShadowLightly.com account.")
            TRX.throwExceptions()
            exit(0)
        #loging.error(len(r))

        # The dirtiest hack of dirty hacks.
        if not shadowKey:
            shadowKey = "derpderpderp"
        if shadowKey and str(m.Type) == "snoopy.Snoopy":
            filters.append( mtk.c.mtkey == shadowKey )
            filters.append( mtk.c.user == users.c.user )
            filters.append( sess.c.drone == users.c.drone )

#Option Two, Local:
else:

    drone = TRX.getVar("properties.drone")
    if TRX.getVar("drone"):
        drone = TRX.getVar("drone")
    
    location = TRX.getVar("properties.dronelocation")
    if TRX.getVar("location"):
        location = TRX.getVar("location")
    
    start_time = TRX.getVar("properties.start_time", "2000-01-01 00:00:00.0")
    if TRX.getVar("start_time"):
        start_time = TRX.getVar("start_time", "2000-01-01 00:00:00.0")
    
    end_time = TRX.getVar("properties.end_time", "2037-01-01 00:00:00.0")
    if TRX.getVar("end_time"):
        end_time = TRX.getVar("end_time", "2037-01-01 00:00:00.0")
    
    mac = TRX.getVar("properties.mac")
    if TRX.getVar("mac"):
        mac = TRX.getVar("mac")
    
    ssid = TRX.getVar("properties.ssid")
    if TRX.getVar("ssid"):
        ssid = TRX.getVar("ssid")   #Manually overide
    
    domain = TRX.getVar("fqdn")
    
    
    observation = TRX.getVar("properties.observation")


# Done parsing Maltego input

st_obj = parser.parse(start_time)
et_obj = parser.parse(end_time)

try:
    proxs = metadata.tables['wifi_client_obs']
    vends = metadata.tables['vendors']
    ssids = metadata.tables['wifi_client_ssids']
    wigle = metadata.tables['wigle']
#    sess  = metadata.tables['sessions'] 
    cookies = metadata.tables['cookies']
    leases = metadata.tables['dhcp_leases']
    sslstrip = metadata.tables['sslstrip']
    wpa = metadata.tables['wpa_handshakes']
    gps = metadata.tables['gpsd']

#    mtk = metadata.tables['mtk']
#    users = metadata.tables['users']

except Exception, e:
    logging.warning("WARNING: Unable to query at least one table from supplied db (%s)" % dbms)
    logging.warning("Error was %s" %str(e))
    #exit(-1)

#filters = []
s = select([proxs], and_(*filters))
#filters.append(proxs.c.num_probes>1)

#logging.debug(filters)

if proxs is not None:
    filters.append(proxs.c.run_id == sess.c.runn_id)

if start_time is not None:
    filters.append(proxs.c.first_obs >= st_obj)

if end_time is not None:
    filters.append(proxs.c.last_obs <= et_obj)

if drone is not None:
    filters.append(sess.c.drone == drone)

if location is not None:
    filters.append(sess.c.location == location)

if mac:# is not None:
    filters.append(proxs.c.mac == mac)

if ssid is not None:
    filters.append(ssids.c.ssid == ssid)

#!/usr/bin/env python
# Parse GPS info by listening NMEA0183 GPGLL sentence from serial port.
from __future__ import division
import sys,serial,string,errno,time

def getGPS(sport="/dev/rfcomm0"):
    """
    Generally, Bluez likes to use /dev/rfcomm0, but pyserial uses /dev/ttyS*.
    """
    try: ser = serial.Serial(port=sport, baudrate=4800) #default:/dev/ttyS0
    except serial.serialutil.SerialException: 
        print '\nCan NOT open port: %s\nExiting...' % sport
        sys.exit(99)
    except: raise
    ser.open()

    while True:
        try: line = ser.readline()
        except OSError, (err_no, err_str):
            delay = 0.1
            if err_no == errno.EAGAIN: #11
                print 'GPS read: %s, wait %.1f sec...' % (err_str, delay)
            else: raise
            time.sleep(delay)
            continue
        except serial.serialutil.SerialException, err: 
            print '\n!!!GPS read: %s, Exiting...\n' % err.message
            sys.exit(99)
        except: raise
        sentence = line.split(',')

        # $GPGLL,3955.36937,N,11628.37507,E,011217.000,A,A*55
        # $GPGGA,011217.000,3955.36937,N,11628.37507,E,1,04,4.0,41.3,M,-7.9,M,,*75
        # $GPRMC,011217.000,A,3955.36937,N,11628.37507,E,,,271209,,,A*6D
        if sentence[0] == '$GPGLL' and len(sentence) == 8:
            try:
                # Format of sentence[5](utc): hhmmss
                #time = string.atof(sentence[5])
                lat_tmp = string.atof(sentence[1])
                lon_tmp = string.atof(sentence[3])
                # Ugly 2 line for lat/lon check coming up.
                if lat_tmp < 3900 or lon_tmp < 11600:
                    continue
            except: continue

        elif sentence[0] == '$GPGGA' and len(sentence) == 15:
            try:
                #time = string.atof(sentence[1])
                lat_tmp = string.atof(sentence[2])
                lon_tmp = string.atof(sentence[4])
                # Ugly 2 line for lat/lon check coming up.
                if lat_tmp < 3900 or lon_tmp < 11600:
                    continue
            except: continue

        elif sentence[0] == '$GPRMC' and len(sentence) == 13:
            try:
                #time = string.atof(sentence[1])
                lat_tmp = string.atof(sentence[3])
                lon_tmp = string.atof(sentence[5])
                # Ugly 2 line for lat/lon check coming up.
                if lat_tmp < 3900 or lon_tmp < 11600:
                    continue
            except: continue
        else: continue

        print line

        #time: utc field of GLL,GGA,RMC sentence.
        #hour = int(time/10000)
        #min = int(time/100)-hour*100
        #sec = int(time)-hour*10000-min*100

        lat_int = int(lat_tmp/100)
        lat = lat_int + (lat_tmp - lat_int*100)/60
        lon_int = int(lon_tmp/100)
        lon = lon_int + (lon_tmp - lon_int*100)/60

        gps = [ lat, lon ]
        break

    #sleep(.2)
    ser.close()
    return gps

if __name__ == "__main__":
    from time import sleep,strftime
    timestamp = strftime('%Y%m%d-%H%M%S')
    gps = getGPS()
    gps.insert(0,timestamp)
    from pprint import pprint
    pprint(gps)

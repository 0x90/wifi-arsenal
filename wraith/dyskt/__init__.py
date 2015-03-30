#!/usr/bin/env python

""" dyskt: Dynamic Small Kill Team (Wraith Sensor)

DySKT is a 802.11 sensor consisting of an optional collection radio (i.e.
spotter), a mandatory reconnaissance radio (i.e. shooter) and an RTO which relays
collected data to Nidus, the data storage system (i.e. HQ). DySKT collects data
in the form of raw 802.11 packets with the reconnaissance (and collection if
present) radios, forwarding that date along with any geolocational data (if a
gps device is present) to higher. The reconnaissance radio will also partake in
assaults in directed to.

REVISIONS:
dyskt 0.1.4
 includes: dyskt 0.0.8, radio 0.0.4, collate 0.0.8, pf 0.0.6, dysktd, dyskt.conf,
  dyskt.log.conf dyskt
 changes:
  - consolidates radio related processes, sniffer and tuner, into a the RadioController
    class
   o cleans up the interprocess communication and minimizes the number of
     shared communication objects and the number of sub process
   o radio class now subclasses mp.Process

dyskt 0.1.5
 desc: utilizes a new internal communication SOP to streamline and simplify
  interprocess communications
 includes: dyskt 0.0.10 internal 0.0.1 rto 0.0.11 (previously collator) rdoctl 0.0.5
  dyskt.conf dyskt.log.conf dysktd
 changes:
  - streamlined inter-process communication methods/objects
   o replaced interprocess Pipes with a single Queue
   o removed the Queue used by children to communicate with DySKT and made
    each connection dual-ended
  - scan pattern config modified
   o added band and width specification to scan and pass configuration
   o added optional initial channel and channel width
  - modified gps processing
   o removed pf.py and pushed gps polling as a thread into rto
 - removed signal handling as a means to pass commands
   o need to code command interface
 - added mac spoofing cability on start of each radio
 - added platform/system details
 - added regulatory domain setting/resetting capability to sensor
 - modified antenna specification to support more than 1 antenna
 - removed internal.py and the Report class, using just a simple Tuple instead
 - modified gps poller to send front line trace even in cases of static gps
   configuration. Determine if:
    a) this will slow down RTO processing of frames
    b) if it will result in unneccessary db storage or traffic
 - check specified nic for wireless capabilities/presence during conf processing
 - fixed issue with radio being reset after initialization errors

TODO:
     ** After testing remove set raw capability from python **
      3) implement adaptive scan pattern
     26) gps device
       o identify/handle device failing or being removed
       o uniquely identify with a permanent id w/out hardcoding in conf file
     31) add interface (tcpserver? or socket?) to allow finer control of pausing,
         holding, listening
          o better define hold, listen, pause
           - hold stop scanning on current channel
           - listen stop scanning on specified channel
           - pause stop scanning and recording
     41) need to handle tuner thread failure in rdoctl
     42) consider sending multiple frames as a single compressed/encrypted
         packet for efficiency and security
     43) why does iw.regget in dyskt.py not reflect the actual change to the
         regulatory domain
"""
__name__ = 'dyskt'
__license__ = 'GPL v3.0'
__version__ = '0.1.5'
__date__ = 'December 2014'
__author__ = 'Dale Patterson'
__maintainer__ = 'Dale Patterson'
__email__ = 'wraith.wireless@yandex.com'
__status__ = 'Development'

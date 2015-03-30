![](widgets/icons/wraith-banner.png?raw=true)
# WRAITH: Wireless assault, reconnaissance, collection and exploitation toolkit.

> "You knew that I reap where I have not sown and gather where I scattered no seed."

## 1 DESCRIPTION:
Attack vectors, rogue devices, interfering networks are best visualized and identified
over time. Current tools i.e. Kismet, Aircrack-ng and Wireshark are excellent tools
but none are completely suitable for collecting and analyzing the 802.11 environment
over a period of time without that is, implementing a custom interface.

While originally intending to develop such a custom interface to one or more Kismet
based sensors, Wraith evolved. Kismet did not offer enough information, Wireshark
offered too much. Wraith is an attempt to develop a toolsuite that eases the
collection, collation and analysis of temporal 802.11 data in order to provide
administrators with the ability to view their network(s) from a bird's eye view and
drill down as necessary to a single device. Wraith allows the user to decide what
data to view, how to view it and 'when' to view it.

Once the reconnaissance and collection development is stable, assault plug-ins will
be developed to aid WLAN administrators in the security testing of their networks.

## 2. REQUIREMENTS: 
 * linux (preferred 3.x kernel, tested on 3.13.0-43)
   - NOTE: some cards i.e. rosewill usb nics were not fully supported through iw
     on earlier kernels
 * Python 2.7
 * iw 3.17
 * postgresql 9.x (tested on 9.3.5)
 * pyscopg 2.5.3
 * mgrs 1.1
 * macchanger 1.7.0

## 3. MODULES: Currently consists of four components/modules

###  a. Radio (v 0.0.4): 802.11 network interface objects and functions

Objects/functions to manipulate wireless nics and parse 802.11 captures.
Partial support of 802.11-2012

#### Standards
* Currently Supported: 802.11a\b\g
* Partially Supported: 802.11n
* Not Supported: 802.11s\y\u\ac\ad\af

### b. DySKT (v 0.1.5) : Dynamic Small Kill Team (Wraith Sensor)

An 802.11 sensor consisting of an optional collection radio (i.e. spotter), a
mandatory reconnaissance radio (i.e. shooter) and an RTO which relays collected
data to Nidus, the data storage system (i.e. HQ). DySKT collects data in the form
of raw 802.11 packets with the reconnaissance (and collection if present) radios,
forwarding that date along with any geolocational data (if a gps device is present)
to higher.

### c. Nidus (v 0.0.6): Data Storage Manager

Nidus is the Data Storage manager processing data received from DySKT. Nidus is the
interface to the backend Postgresql database, processing data in terms of raw 802.11
frames, gps location, and 'device' details/status. 

### d. wraith-rt: GUI

In progress gui. Currently configured to provide start/stop of services, display
and editing of configuration files, some manipulation of backened storage.

## 4. ARCHITECTURE/HEIRARCHY: Brief Overview of the project file structure

* wraith/               Top-level package
 - \_\_init\_\_.py      initialize the top-level
 - wraith-rt.py         the main Panel gui
 - subpanels.py         child panels
 - wraith.conf          gui configuration file
 - LICENSE              software license
 - README.md            this file
 - CONFIGURE.txt        setup details
 * widgets              gui subpackage
     *  icons           icons folder
     -  \_\_init\_\_.py initialize widgets subpackage
     -  panel.py        defines Panel and subclasses for gui
 * utils                utility functions
    -  \_\_init\_\_.py  initialize utils subpackage
    - bits.py           bitmask functions
    - timestamps        timestamp conversion functions
    - cmdline.py        various cmdline utilities for testing processes
 *  radio               subpackage for radio/radiotap
     - \_\_init\_\_.py  initialize radio subpackage
     - iwtools.py       iwconfig, ifconfig interface and nic utilities
     - iw.py            iw 3.17 interface
     - radiotap.py      radiotap parsing
     - mpdu.py          IEEE 802.11 MAC (MPDU) parsing
     - dott1u.py        contstants for 802.11u (not currently used)
     - channels.py      802.11 channel, freq utilities
     - mcs.py           mcs index functions
     - oui.py           oui/manuf related functions
 *  dyskt               subpackage for wraith sensor
     - \_\_init\_\_.py  initialize dyskt package
     - dyskt.conf       configuration file for dyskt
     - dyskt.log.conf   configuration file for dyskt logging
     - dyskt.py         primary module
     - rdoctl.py        radio controler with tuner, sniffer
     - rto.py           data collation and forwarding
     - dysktd           dyskt daemon
 *  nidus               subpackage for datamanager
     - \_\_init\_\_.py  initialize nidus package
     - nidus.conf       nidus configuration
     - nidus.log.conf   nidus logging configuration
     - nidus.py         nidus server
     - nmp.py           nidus protocol definition
     - nidusdb.py       interface to storage system
     - simplepcap.py    pcap writer
     - nidus.sql        sql tables definition
     - nidusd           nidus daemon

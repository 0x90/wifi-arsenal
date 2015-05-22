     SensePost presents:
     
      /$$$$$$                                                   
     /$$__  $$                                                  
    | $$  \__/ /$$$$$$$   /$$$$$$   /$$$$$$   /$$$$$$  /$$   /$$
    |  $$$$$$ | $$__  $$ /$$__  $$ /$$__  $$ /$$__  $$| $$  | $$
     \____  $$| $$  \ $$| $$  \ $$| $$  \ $$| $$  \ $$| $$  | $$
     /$$  \ $$| $$  | $$| $$  | $$| $$  | $$| $$  | $$| $$  | $$
    |  $$$$$$/| $$  | $$|  $$$$$$/|  $$$$$$/| $$$$$$$/|  $$$$$$$
     \______/ |__/  |__/ \______/  \______/ | $$____/  \____  $$
                                            | $$       /$$  | $$
                                            | $$      |  $$$$$$/
                                            |__/       \______/
                            
                                                   Version: 2.0
    Code:    glenn@sensepost.com // @glennzw
    Visit:   www.sensepost.com // @sensepost
    License: Non-commercial use

Welcome to Snoopy Version 2.0!

0. Quick Setup
==============
Strapped for time? Try this:

**To install and setup Snoopy:**

    bash install.sh

**To save data from the wireless, sysinfo, and heartbeat plugins locally:**

    snoopy -v -m wifi:mon=True -m sysinfo -m heartbeat -d myDrone -l London

**To sync data from a client to a server:**
 
 _Server:_
 
    snoopy_auth --create myDrone     # Create account
    snoopy -v -m server              # Start server plugin

_Client:_
 
    snoopy -v -m wifi:mon=True -s http://<server>:9001/ -d myDrone -l London -k <key>

1. INTRODUCTION AND OVERVIEW
=============================
Snoopy is a distributed, sensor, data collection, interception, analysis, and visualization framework. It is written in a modular format, allowing for the collection of arbitrary data from various sources via Python plugins. 

1. Architecture

    Each Snoopy instance can run multiple plugins simultaneously. A plugin collects data, which is queried by the main Snoopy process and is written to a local database. Snoopy can sync data between clients (drones) and a server, and clients (drones) can also pull replicas of data from a server. Each Snoopy instance can run plugins appropriate for its position in the greater picture. Here's a diagram to depict one possible setup:
    
        Drone01                     Server01
        +---------------+           +--------------+
        | Plugins:      |           | Plugins:     |
        |   * WiFi      |           |  *Server     |
        |   * Bluetooth |====3G====>|              |<=========================\
        |   * GSM       |           |              |                          ||
        |   * FitBit    |           |              |                          ||
        +---------------+           +--------------+                          ||
                                                                              ||
        Drone02                      Server02               Server03          ||
        +---------------+            +--------------+       +-------------+   ||
        | Plugins:      |            | Plugins:     |       | Plugins:    |   ||
        |   * WiFi      |            |  * Server    |       |  * Server   |   ||
        |   * Cookie    |=====Xbee==>|  * Heartbeat |==3G==>|  * Wigle    |<==\
        |     thief     |   ||       |              |       |  * DataViz  |   ||
        |   * GPS       |   ||       |              |       |             |   ||
        +---------------+   ||       +--------------+       +-------------+   ||
                            ||                                             Internet
        Drone03             ||                             Laptop01           || 
        +---------------+   ||                            +--------------+    ||                                
        | Plugins:      |   ||                            | Plugins:     |    ||
        |   * Thermal   |   ||                            |  *RemotePull |    ||
        |   * Camera    |===/                             |              |====/
        |   * Heat      |                                 |  Run:        |
        |               |                                 |   *Maltego   |
        +---------------+                                 +--------------+

In the above illustration, there are three drones running and syncing their data to two separate servers. One syncs over 3G, the other two over Xbee. The second server syncs its data to a third server. Finally, a client (laptop) pulls all data from the first and third servers, and runs Maltego to explore the data.

2. Setup & Installation

Running 'sh install.sh' within the snoopy-ng.git directory will install all of the required packages. It offers to install aircrack from source, which is required for distros without this package (the aircrack suite is used for the wireless plugins).We cannot recommend Maltego enough for data exploration, a community edition (with some restrictions) can be downloaded for free from the Paterva website at http://paterva.com.

---

2. USAGE
========

Basic
-----   
  
To see all available flags and options, we have made two commands for you: 
    
root@kali:~# snoopy --help (shorthand -h)

This command gives you all running options, such as which server to sync to, to the name of the drone and its location. In addition, it also introduces how one would run the various plugins. 

root@kali:~# snoopy --list (shorthand -i)

This command lists all available plugins and the parameters required by each plugin to function correctly. To get more verbose information about each plugin, use '-ii' or '-iii'. To get information about one specific plugin use '-i -m <pluginName>'.

Plugins can be specified with the --plugin (or shorthand -m) option. Numerous plugins can be specified, and will be started in the order entered. Each plugin will be given 60 seconds to indicate its ready state, after which it times out and the next plugin will be initiated. This can be useful if subsequent plugins depend on actions of prior ones.
   
Each plugin can take numerous parameters (as indicated in the --list output) in the form of comma separated key value pairs. Below we use the 'example' plugin, which simply generates random numbers.
   
       snoopy --plugin example:x=1,v=True
       
If drone / location options are not supplied default values are supplied. Alternatively, they can be specified as below.
   
       snoopy --plugin example:x=1,v=True --drone myDrone --location Cansas

Data Synchronization
--------------------
       
Data can be synchronized to a remote machine by supplying the --server (-s) option. The remote machine should be running the server plugin (--plugin server). A key should be generated for a drone name before hand. The below illustrates this.
   
   **Server**

        root@server:~# snoopy_auth --create myDrone01 --verbose
        [+] Creating new Snoopy server sync account
        [+] Key for 'myDrone01' is 'GWWVF'
        [+] Use this value in client mode to sync data to a remote server.
        root@kali:~# snoopy --plugin server
        [+] Running webserver on '0.0.0.0:9001'
        [+] Plugin server caught data for 2 tables.
        
   **Client**
    
        root@client:~# snoopy --plugin example:x=1 --drone myDrone --key GWWVF --server http://<server_ip>:9001/ --verbose
        [+] Starting Snoopy with plugins: example
        [+] Plugin example created new random number: 21
        [+] Snoopy successfully sunc 2 elements over 2 tables.
         

   **Remote Data Pull**

Data can be pulled from a server using the *local_sync* plugin. For example, assume the server as above is running, and perform this operation from the client:
   
    root@client:~# snoopy --plugin local_sync:server_url=http://<server_ip>:9001/ --drone myDrone --key GWWVF
    [+] Plugin local_sync pulled 888 records from remote server.
    
Database Storage
----------------
The default behaviour is to store all data inside a SQLITE file *snoopy.db*. This can be overiden with the parameter --dbms. See the SQL Alchemy documentation on how to specify different database engines (http://docs.sqlalchemy.org/en/rel_0_9/dialects/index.html). As an example, below we use MySQL:

        root@client:~# snoopy -v --plugin example --dbms=mysql://glenn:secret@localhost/snoopy_db
        [+] Capturing local only. Saving to 'mysql://glenn:secret@localhost/snoopy_db'   

It might be useful to use SQLITE storage on smaller devices, and have the server plugin saving to MySQL (or similar). A further example may be of use where we specify the file location to store data, such as on a removable media:

        root@client:~# snoopy -v --plugin example --dbms=sqlite:////media/USB01/snoopy.db
        
There is a --flush (-f) option to 'flush' data from local storage once it has been synchronized with an upstream server.


Starting Services on Boot
-------------------------
Snoopy can be started with an upstart script (see the ./setup/upstarts folder). Other sample upstart scripts are provided in the same directory - e.g. one to bring up a PPP connection from a 3G modem, and one to create a SSH remote command channel.

Debian based systems (e.g. Kali) don't seem to support upstart. In the interim, the suppied rc.local file can be used to start Snoopy and related services on boot.

---    
    
3. DATA VISUALIZATION 
=====================

Maltego is the preferred tool to perform visualization. Instructions are below:

1. Open Maltego
2. Select 'Import Configuration'
3. Choose 'snoopy_entities.mtz' from the transforms folder

This should import both entities as well as transforms. To get started, drag the 'Base of Operations' entity from the Snoopy tab in the Palette menu onto a blank graph. As an example, perform the following operations on the entity:

1. Right click, select Transforms, Select 'Get Drones'
2. On desired drone, right click, select 'Get Location'
3. On desired location, right click, select 'Get Clients'
4. On desired clients, right click, select 'Get Observations'

Transforms exist to fetch domains and cookies (from passive monitoring), lookup SSID street addresses, and several are bidirectional (e.g. can lookup clients from Location, or Locations from client). It's best to play.

Database Specification
-----------------------
If not using the default sqlite format edit the following file to specify the location of the data:

        snoopy_ng/transforms/db_path.conf
        

Graph Sharing
--------------
The Snoopy graph can be shared by multiple analysts simultaneously by using Maltego's colaboration function. Select Collaboration, and 'Share Current Graph'.

---

4. COMMERCIAL USAGE
===================
The license under which Snoopy is released forbids gaining financially (or otherwise) from its use (see LICENSE.txt). We have a separate license available for commercial use, which includes extra functionality such as:

    * Syncing data via XBee
    * Advanced plugins
    * Extra/custom transforms
    * Web interface
    * Prebuilt drones

Get in contact (glenn@sensepost.com / research@sensepost.com) if
you'd like to engage with us.

---

5. APPENDIX
===========
Writing Plugins
---------------
See the plugins/example.py file to understand how plugins should be written. Any file placed in the plugins folder will be treated as a plugin, and should have the following properties:

1. Supply plugin information and optional paramter defintions.
2. Supply SQL table schema definitions for the data it will be collecting.
3. Return data in the format defined above when queried.

Otherwise, the plugin can do whatever you like.


Hardware
---------
Snoopy will run on any Linux device with sufficient support to install files from the *install.sh* file. i.e. Python, and related packages. Hardware support will vary for what plugins are required, but for the most common scenario of collecting WiFi data and uploading via 3G, the following is recommended:

* BeagleBone Black
* Powered USB hub (with Y splitter to save on two plugs)
* Alfa AWUS036h WiFi adapter
* Huawei E160 Modem
* BlueNext BN903S GPS
* At least a 2A power adapter (will vary on what peripherals you have)

Operating System
----------------
Kali 1.05 and Ubuntu 12.04 have been tested. Similar systems should work.

Extra Notes:
------------
 * You can run as many plugins at one as you like. Plugins initiate sequentially, in the order supplied on the command line.
 * The next plugin will only start initiating when the prior one has indicated
    that is is ready (with a 60 second timeout). This is useful if subsequant
    plugins depend on prior ones.
 * If you don't specify a drone or location, default ones will be provided.
 * You can run Snoopy with no plugins in order to only sync data.
 
 Known Issues
 ------------
 An error condition occurs when collecinting data locally, sycning to a remote server, and then pulling a replica from the server. e.g.:
 
 **Server**
 
        root@kali:~# snoopy -m server -m wigle:username=u,password=p,email=a@a.com
        [+] Running webserver on '0.0.0.0:9001'
        [+] Plugin server caught data for 2 tables.
 
         
**Client**

		root@client:~# snoopy -m wifi -m local_sync:server_url=http://1.1.1.1:9001/ -d myDrone -l London -k secretkey -s http://1.1.1.1:9001/

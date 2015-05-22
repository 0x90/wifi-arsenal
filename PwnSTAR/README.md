#PwnSTAR

##Platforms

Designed for Kali Linux. I also have it working in Linux Mint 16. Should run on any flavour of Linux with a little tweaking.

##Installing
###Installer script

Clone from github https://github.com/SilverFoxx/PwnSTAR.git
Change directory to path/to/clone/PwnSTAR
Run `./installer.sh`. This automates the steps below.

###Manually
Place each of the web folders separately into /var/www.
Set permissions correctly eg make script and php executable, formdata.txt writable, make group www-data etc.
Do not move the index files out of their respective folders; the script will move them to the correct location as required.

"hotspot_3" is a simple phishing web page, used with basic menu option 4.

"portal_simple" is a captive portal which allows you to edit the index.html with the name of the portal eg "Joe's CyberCafe". It is used for sniffing.

"portal_hotspot3" phishes credentials, and then allows clients through the portal to the internet. They can then be sniffed.

"portal_pdf" forces the client to download a malicious pdf (with classical Java applet) in order to pass through the portal 

##Usage
###Basic Menu
	
    1) Honeypot: get the victim onto your AP, then use nmap, metasploit etc
                 no internet access given
	
    2) Grab WPA handshake
	
    3) Sniffing: provide internet access, then be MITM
	
    4) Simple web server with dnsspoof: redirect the victim to your webpage
       
    5) Karmetasploit
    
    6) Browser_autopwn
    
1) Relies on auto-connections ie the device connnects without the owner being aware. You can then attempt to exploit it.
   Target the fake-AP ESSID to something the device has likely connected to previously eg Starbucks WiFi
   
2) Sometimes it is quicker to steal the handshake than sniff it passively. Set up the AP with the same name and channel as the target, and then DOS the target.
   Airbase will save a pcap containing the handshake to /root/PwnSTAR-n.cap.
   
3) Provides an open network, so you can sniff the victim's activities.

4) Uses apache to serve a webpage. There is an option to load your own page eg one you have cloned. The provided page (hotspot_3) asks for email details.
   Note the client is forced to the page by DNS spoofing. They can only proceed to the internet if you manually stop dnsspoof. 
   DNS-caching in the client is a problem with this technique. The captive portal in the advanced menu is a much better way of hosting hotspot_3

5&6) Provides all the config files to properly set-up Karmetasploit and Browser_autopwn.

###Advanced Menu

    a) Captive portals (phish/sniff)
    
    b) Captive portal + PDF exploit (targets Adobe Reader < v9.3)

    c) MSXML 0day (CVE-2012-1889: MSXML Uninitialized Memory Corruption)
    
    d) Java_jre17_jmxbean
    
    e) Choose another browser exploit
         
  
a) Uses iptables rules to route the clients. This is a fully functioning captive portal, and can track and block/allow multiple connections simultaneously. 
Avoids the problems of dns-spoofing. There are two built-in web options:
           
1) Serves hotspot3. Does not allow clients onto the internet until credentials have been given.

2) Allows you to add a personal header to the index.php.
You could probably copy the php functions from this page onto a cloned page, and load that instead.
     
b) A captive portal which blocks the client until they have downloaded a pdf. This contains a malicious java applet.
Includes a virgin pdf to which you can add your own payload.
   
c&d) Launches a couple of example browser exploits

e) Gives a skeleton framework for loading any browser exploit of your choice. 
Edit PwnSTAR browser_exploit_fn directly for more control.
   
Have fun!
Vulpi

P.S __READ THE SCRIPT__: it is heavily commented.

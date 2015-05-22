#!/usr/bin/env python
import logging, os, uuid, hashlib
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from common.entities import pcapFile
from canari.maltego.message import Field, Label, UIMessage
from canari.framework import configure #, superuser

__author__ = 'catalyst256'
__copyright__ = 'Copyright 2013, Sniffmypackets Project'
__credits__ = []

__license__ = 'GPL'
__version__ = '0.1'
__maintainer__ = 'catalyst256'
__email__ = 'catalyst256@gmail.com'
__status__ = 'Development'

__all__ = [
    'dotransform'
]


#@superuser
@configure(
    label='L1 - Extract UDP Streams [SmP]',
    description='Extracts all UDP streams from a pcap file',
    uuids=[ 'sniffMyPackets.v2.pcap_2_udp_streams' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=False
)
def dotransform(request, response):
    
    pcap = request.value

    convos = []
    stream_file = []
    try:
        tmpfolder = request.fields['sniffMyPackets.outputfld']
    except:
        return response + UIMessage('No output folder defined, run the L0 - Prepare pcap transform')

    pkts = rdpcap(pcap)

    # Find all the UDP streams within the pcap file
    for p in pkts:
        s_ip = ''
        d_ip = ''
        s_port = ''
        d_port = ''
        if p.haslayer(IP) and p.haslayer(UDP):
            if p[IP].src is not None:
                s_ip = p[IP].src
            if p[IP].dst is not None:
                d_ip = p[IP].dst
            if p[UDP].sport is not None:
                s_port = p[UDP].sport
            if p[UDP].dport is not None:
                d_port = p[UDP].dport
            convo = s_ip, s_port, d_ip, d_port
            duplicate = d_ip, d_port, s_ip, s_port
            if convo not in convos:
                convos.append(convo)
            if duplicate in convos:
                convos.remove(duplicate)
            else:
                pass
        else:
            pass

    # Create the individual pcap files using tshark

    counter = -1
    for s_ip, s_port, d_ip, d_port in convos:
        counter += 1
        dumpfile = tmpfolder + '/udp-stream' + str(counter) + '.dump'
        cmd = 'tshark -r ' + pcap + ' -R "(ip.addr eq ' + s_ip + ' and ip.addr eq ' + d_ip + ') and (udp.port eq ' + str(s_port) + ' and udp.port eq ' + str(d_port) + ')" -w ' + dumpfile
        # print cmd
        if dumpfile not in stream_file:
            stream_file.append(dumpfile)
        os.popen(cmd)

    # print stream_file[0]
    # Now for the long bit...
    for s in stream_file:
        cut = tmpfolder + '/udp-stream' + s[52:-5] + '.pcap'
        cmd = 'editcap ' + s + ' -F libpcap ' + cut
        os.popen(cmd)
        remove = 'rm ' + s
        os.popen(remove)

        # Count the number of packets
        cmd = 'tshark -r ' + cut + ' | wc -l'
        pktcount = os.popen(cmd).read()

        # Hash the file and return a SHA1 sum
        fh = open(cut, 'rb')
        sha1sum = hashlib.sha1(fh.read()).hexdigest()

        # Hash the file and return a MD5 sum
        fh = open(cut, 'rb')
        md5sum = hashlib.md5(fh.read()).hexdigest()

        e = pcapFile(cut)
        e.sha1hash = sha1sum
        e.outputfld = tmpfolder
        e.md5hash = md5sum
        e += Field('pcapsrc', request.value, displayname='Original pcap File', matchingrule='loose')
        e += Field('pktcnt', pktcount, displayname='Number of packets', matchingrule='loose')
        e.linklabel = 'UDP - # of pkts:' + str(pktcount)
        response += e
    return response

    
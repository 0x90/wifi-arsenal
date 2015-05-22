#!/usr/bin/env python
import os, glob, subprocess
from common.entities import pcapFile, SnortFile
from canari.maltego.message import Field, Label, UIMessage
from canari.config import config
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
    label='L9 - Run pcap through Snort [SmP]',
    description='Runs a pcap through Snort and outputs to HTML file',
    uuids=[ 'sniffMyPackets.v2.pcap_through_snort' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
    devNull = open('/dev/null', 'w')
    pcap = request.value
    file_list = []
    try:
        folder = request.fields['sniffMyPackets.outputfld']
    except:
        return response + UIMessage('No output folder defined, run the L0 - Prepare pcap transform')
    # Use need to change the locations in sniffMyPackets.conf if they are different to the defaults for snort
    snort_path = config['locations/snort']
    snort_conf = config['locations/snort_conf']
    snort_folder = folder + '/snort'
    if not os.path.exists(snort_folder):
        os.makedirs(snort_folder)
    cmd = snort_path + ' -c ' + snort_conf + ' -r ' + pcap + ' -l ' + snort_folder + ' -D'
    subprocess.call(cmd, shell=True, stdout=devNull)
    file_list = glob.glob(snort_folder+'/*')
    
    for x in file_list:
        e = SnortFile(x)
        e += Field('pcapsrc', request.value, displayname='Original pcap File', matchingrule='loose')
        e += Field('sniffMyPackets.outputfld', folder, displayname='Folder Location')
        e += Field('disclaimer', 'Snort is a registered trademark of Sourcefire, Inc', displayname='Disclaimer')
        response += e
    return response
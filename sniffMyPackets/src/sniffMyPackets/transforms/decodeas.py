#!/usr/bin/env python
import os
from canari.easygui import multenterbox
from common.entities import pcapFile, DecodeAs
from canari.maltego.message import Field, Label
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
    label='L0 - Generate Decode As Script [SmP]',
    description='Allows you to decode a pcap file as another traffic type',
    uuids=[ 'sniffMyPackets.v2.decode_as_pcap' ],
    inputs=[ ( 'sniffMyPackets', pcapFile ) ],
    debug=True
)
def dotransform(request, response):
    
    pcap = request.value
    folder = request.fields['sniffMyPackets.outputfld']

    msg = 'Enter the new protocol type & port'
    title = 'L0 - Decode As [SmP]'
    fieldNames = ["Port", "Traffic Type", "Protocol"]
    fieldValues = []
    fieldValues = multenterbox(msg, title, fieldNames)

    d_port = fieldValues[0]
    d_type = fieldValues[1]
    d_proto = fieldValues[2]

    # Create lua script template for user defined decode as
    lua = []
    lua.append('do \n')
    lua.append('\tlocal ' + d_proto + '_dissector_table=DissectorTable.get("' + d_proto + '.port")\n')
    lua.append('\tlocal ' + d_type + '_dissector=' + d_proto + '_dissector_table:get_dissector(' + d_port + ')\n')
    lua.append('\t' + d_proto + '_dissector_table:add(' + d_port + ',' + d_type + '_dissector)\n')
    lua.append('end')
    lau_out =  ''.join(lua)

    # Write lua script to file for later use.
    lua_file = folder + '/decodes.lua'
    f = open(lua_file, 'w')
    f.write(lau_out)
    f.close

    e = DecodeAs(lua_file)
    e += Field('pcapsrc', request.value, displayname='Original pcap File', matchingrule='loose')
    e += Field('sniffMyPackets.outputfld', folder, displayname='Folder Location')
    response += e
    return response

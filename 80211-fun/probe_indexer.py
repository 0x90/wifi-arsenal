#!/usr/bin/env python
#
# Copyright (c) 2014 Alexander Schrijver <alex@flupzor.nl>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

import sys

from sqlalchemy import create_engine, Column, Integer, String, Table, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

# Required for various scapy-internal registries.
import scapy.all

from scapy.utils import PcapReader
from scapy.layers.dot11 import RadioTap, Dot11, Dot11ProbeReq, Dot11Elt
from scapy.packet import NoPayload

Base = declarative_base()

class ServiceSet(Base):
    __tablename__ = 'servicesets'

    id = Column(Integer, primary_key=True)
    nwid = Column(String, unique=True)

node_serviceset_table = Table('node_serviceset', Base.metadata,
    Column('serviceset_id', Integer, ForeignKey('servicesets.id')),
    Column('node_id', Integer, ForeignKey('nodes.id')),
)

class Node(Base):
    __tablename__ = 'nodes'

    id = Column(Integer, primary_key=True)
    addr = Column(String, unique=True)

    probereqs_seen = Column(Integer)

    servicesets = relationship("ServiceSet", secondary=node_serviceset_table)

def main():

    # Setup SQLAlchemy
    engine = create_engine('sqlite:///test.db', echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    pcap_filename = sys.argv[1]

    print "Reading file: {0}".format(pcap_filename)

    for packet_data in PcapReader(pcap_filename):
        radiotap_frame = packet_data
        dot11_frame = radiotap_frame.payload
        dot11_probe_req = dot11_frame.payload

        assert(isinstance(radiotap_frame, RadioTap))
        assert(isinstance(dot11_frame, Dot11))
        assert(isinstance(dot11_probe_req, Dot11ProbeReq))

        dot11_elem = dot11_probe_req.payload

        ssid = None

        while not isinstance(dot11_elem, NoPayload):
            assert(isinstance(dot11_elem, Dot11Elt))

            # 802.11 elem type mapping (See 8.4.2.1, Table 8-54 From 802.11-2012.pdf)
            dot11_elem_types = {
                0: "SSID",
                1: "Supported rates",
                2: "FH Parameter Set",
                3: "DSSS Parameter Set",
                4: "CF Parameter Set",
                5: "TIM",
                6: "IBSS Parameter Set",
                7: "Country",
                8: "Hopping Pattern Parameters",
                # XXX: add more.
            }

            dot11_elem_type = "Unknown"
            if dot11_elem.ID in dot11_elem_types.keys():
                dot11_elem_type = dot11_elem_types[dot11_elem.ID]

            if dot11_elem.ID == 0 and dot11_elem.len > 0:
                assert(ssid is None)

                ssid = dot11_elem.info
                print("SSID: {0}".format(ssid))

            print "802.11 Element: {0} ({1})".format(dot11_elem_type, dot11_elem.ID)
            dot11_elem = dot11_elem.payload

        node = session.query(Node).filter_by(addr=dot11_frame.addr2).first()
        if not node:
            node = Node(addr=dot11_frame.addr2, probereqs_seen=0)
            session.add(node)

        node.probereqs_seen += 1

        service_set = session.query(ServiceSet).filter_by(nwid=ssid).first()

        if not service_set:
            service_set = ServiceSet(nwid=ssid)
            session.add(service_set)

        if not service_set in node.servicesets:
            node.servicesets.append(service_set)

        session.commit()


if __name__ == '__main__':
    main()

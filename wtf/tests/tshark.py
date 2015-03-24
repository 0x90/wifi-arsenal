# Copyright cozybit, Inc 2010-2011
# All rights reserved
# author: johan@cozybit.com, brian@cozybit.com

import wtf
import unittest
wtfconfig = wtf.conf
from scapy.layers.dot11 import *
import scapy.utils as utils
import commands
from lxml import etree
import binascii
from socket import htonl, htons


class dot11Packet():
    pkt = None

    def __init__(self, packet):
        # First, create the basic packet
        proto = packet.xpath("proto[@name='wlan']")[0]
        frame_ctl = proto.xpath("field[@name='wlan.fc']")[0]
        self.type = int(
            frame_ctl.xpath("field[@name='wlan.fc.type']")[0].get("show"))
        self.subtype = int(
            frame_ctl.xpath("field[@name='wlan.fc.subtype']")[0].get("show"))
        addr1 = proto.xpath("field[@name='wlan.da']")[0].get(
            "show").encode("ascii", "ignore")
        addr2 = proto.xpath("field[@name='wlan.sa']")[0].get(
            "show").encode("ascii", "ignore")
        addr3 = proto.xpath("field[@name='wlan.bssid']")[0].get(
            "show").encode("ascii", "ignore")

        if self.type == 0:
            mgmt = packet.xpath("proto[@name='wlan_mgt']")[0]
            fixed = mgmt.xpath("field[@name='wlan_mgt.fixed.all']")[0]
            tagged = mgmt.xpath("field[@name='wlan_mgt.tagged.all']")[0]
            if self.subtype == 0x8:
                self.pkt = Dot11(addr1=addr1, addr2=addr2, addr3=addr3)
                caps = int(
                    fixed.xpath("field[@name='wlan_mgt.fixed.capabilities']")[0].get("value"), 16)
                self.pkt = self.pkt / Dot11Beacon(cap=caps)
            else:
                raise Exception("Unsupported mgmt subtype %d" % self.subtype)
            for t in tagged:
                ID = int(
                    t.xpath("field[@name='wlan_mgt.tag.number']")[0].get("value"), 16)
                length = int(
                    t.xpath("field[@name='wlan_mgt.tag.length']")[0].get("value"))
                info = ""
                if length != 0:
                    for v in t.xpath("field"):
                        name = v.get("name")
                        if name == "wlan_mgt.tag.number" or name == "wlan_mgt.tag.length":
                            continue
                        s = v.get("value").encode("ascii", "ignore")
                        info += binascii.unhexlify("".join(map(lambda x,
                                                   y: x + y, s[0::2], s[1::2])))
                self.pkt = self.pkt / Dot11Elt(ID=ID, info=info)
        else:
            raise Exception("Unsupported type %d" % self.type)


def tshark_xml_parser(txt):
    pkts = []

    tree = etree.fromstring(txt)
    for packet in tree.xpath("packet"):
        pkt = dot11Packet(packet)
        pkts.append(pkt)
    return pkts


class TestTShark(unittest.TestCase):

    # write the specified packets to tshark and return his XML txt output
    def do_tshark_xml(self, pkts):
        name = "/tmp/" + self.id().split(".")[-1] + ".pcap"
        wrpcap(name, pkts, 105)
        err, out = commands.getstatusoutput("tshark -Tpdml -n -r " + name)
        if err != 0:
            self.failIf(True, "Failed to invoke tshark")
        # Save the xml to a tml file for debugging
        open("/tmp/tshark-test.xml", "w").writelines(out)
        return out

    def do_tshark(self, pkts):
        return tshark_xml_parser(self.do_tshark_xml(pkts))

    def expectEquals(self, p1, p2):
        self.failIf(p1.command() != p2.command(),
                    "EXPECTED:\n" + p1.command().replace("/", "\n/") +
                    "\nBUT GOT:\n" + p2.command().replace("/", "\n/"))

    def expectField(self, f, name=None, showname=None, value=None):
        if name == None and showname == None:
            failIf(True,
                   "Can't find a field unless you tell me the name and/or showname")
        if name == None:
            fields = f.xpath("field[@showname='" + showname + "']")
            if len(fields) == 0:
                self.failIf(True, "No field with showname " + showname)
        else:
            fields = f.xpath("field[@name='" + name + "']")
            if len(fields) == 0:
                self.failIf(True, "No field named " + name)

        # There may be multiple matching fields.  Try them all.
        for field in fields:
            if (value == None):
                _value = None
            elif type(value) == int or type(value) == long:
                _value = int(field.get("value"), 16)
            elif (type(value) == str):
                _value = field.get("value")
            else:
                self.failIf(True, "Unsupported value type " +
                            repr(type(value)))

            if (showname == None):
                _showname = None
            else:
                _showname = field.get("showname")
                if _showname == None:
                    self.failIf(True, "Failed to find showname " + showname)

            if value == _value and showname == _showname:
                return field

        self.failIf(True, "No field with " + name + " had value " + str(value)
                    + " and showname " +
                    repr(showname) + ".\n" + "Candidates are\n"
                    + "\n".join(map(lambda f: "value: " + f.get("value") + " showname: " + str(f.get("showname")), fields)))

    def expectFixed(self, tree, name, showname, value):
        proto = name.split(".")[0]
        fixed = tree.xpath("packet/proto[@name='" + proto + "']")[0]

        # For some reason, action frames to not print as pretty as other mgt
        # frames.
        if showname != None and showname.startswith("Action"):
            fixed = fixed.xpath("field[@show='Fixed parameters']")
            if len(fixed) == 0:
                self.failIf(True, "Failed to find fixed action fields")
            fixed = fixed[0]
        else:
            fixed = self.expectField(fixed, proto + '.fixed.all')
        return self.expectField(fixed, name, showname, value)

    # For some reason, the top-level IE XML stanza in tshark's output does not
    # contain the IE number.  So we depend only on the showname.
    def expectTagged(self, tree, proto, showname):
        tagged = tree.xpath("packet/proto[@name='" + proto + "']")
        if len(tagged) == 0:
            self.failIf(True, "Failed to find proto " + proto)
        tagged = tagged[0]
        tagged = self.expectField(tagged, proto + '.tagged.all')
        return self.expectField(tagged, proto + '.tag', showname)

    def do_hwmp_preq(self, flags, hopcount, ttl, pdid, orig_sta, orig_sn,
                     lifetime, metric, orig_ext=None, targs=[]):
        base_pkt = Dot11(addr1="00:11:22:33:44:55",
                         addr2="00:11:22:33:44:55",
                         addr3="00:11:22:33:44:55") \
            / Dot11Action(category="Mesh")
        base_pkt = base_pkt / Dot11Mesh(mesh_action="HWMP")

        if orig_ext == None:
            info = struct.pack("<BBBI6sIIIB", flags, hopcount, ttl, pdid,
                               utils.mac2str(orig_sta), orig_sn, lifetime,
                               metric, len(targs))
        else:
            info = struct.pack("<BBBI6sI6sIIB", flags, hopcount, ttl, pdid,
                               utils.mac2str(orig_sta), orig_sn,
                               utils.mac2str(orig_ext), lifetime, metric,
                               len(targs))

        for t in targs:
            info += struct.pack("<B6sI", t["flags"],
                                utils.mac2str(t["addr"]), t["sn"])
        pkt = base_pkt / Dot11Elt(ID="PREQ", info=info)

        xml = self.do_tshark_xml(pkt)
        tree = etree.fromstring(xml)
        ie = self.expectTagged(tree, "wlan_mgt", "Tag: Path Request")
        self.expectField(ie, 'wlan_mgt.tag.number',
                         'Tag Number: Path Request (130)', 130)
        self.expectField(ie, 'wlan.hwmp.flags', 'HWMP Flags: 0x%02X' %
                         flags, flags)
        self.expectField(ie, 'wlan.hwmp.hopcount', 'HWMP Hop Count: %d' %
                         hopcount, hopcount)
        self.expectField(ie, 'wlan.hwmp.ttl', 'HWMP TTL: %d' % ttl, ttl)
        self.expectField(ie, 'wlan.hwmp.pdid', 'HWMP Path Discovery ID: %d' %
                         pdid, htonl(pdid))
        self.expectField(ie, 'wlan.hwmp.orig_sta',
                         'Originator STA Address: ' +
                             orig_sta + ' (' + orig_sta + ')',
                         binascii.hexlify(utils.mac2str(orig_sta)))
        self.expectField(
            ie, 'wlan.hwmp.orig_sn', 'HWMP Originator Sequence Number: %d' %
            orig_sn, htonl(orig_sn))
        if orig_ext != None:
            self.expectField(ie, 'wlan.hwmp.orig_ext',
                             'Originator External Address: ' +
                                 orig_ext + ' (' + orig_ext + ')',
                             binascii.hexlify(utils.mac2str(orig_ext)))
        self.expectField(ie, 'wlan.hwmp.lifetime', 'HWMP Lifetime: %d' %
                         lifetime, htonl(lifetime))
        self.expectField(ie, 'wlan.hwmp.metric', 'HWMP Metric: %d' %
                         metric, htonl(metric))
        self.expectField(ie, 'wlan.hwmp.targ_count', 'HWMP Target Count: %d' %
                         len(targs), len(targs))
        for t in targs:
            self.expectField(ie, 'wlan.hwmp.targ_flags',
                             'HWMP Per-Target Flags: 0x%02X' % t["flags"], t["flags"])
            self.expectField(ie, 'wlan.hwmp.targ_sta',
                             'Target STA Address: ' +
                                 t["addr"] + ' (' + t["addr"] + ')',
                             binascii.hexlify(utils.mac2str(t["addr"])))
            self.expectField(
                ie, 'wlan.hwmp.targ_sn', 'Target HWMP Sequence Number: %d' %
                t["sn"], htonl(t["sn"]))

    def do_hwmp_prep(self, flags, hopcount, ttl, targ_sta, targ_sn,
                     lifetime, metric, orig_sta, orig_sn, targ_ext=None):
        base_pkt = Dot11(addr1="00:11:22:33:44:55",
                         addr2="00:11:22:33:44:55",
                         addr3="00:11:22:33:44:55") \
            / Dot11Action(category="Mesh")
        base_pkt = base_pkt / Dot11Mesh(mesh_action="HWMP")

        if targ_ext == None:
            info = struct.pack("<BBB6sIII6sI", flags, hopcount, ttl,
                               utils.mac2str(targ_sta), targ_sn, lifetime,
                               metric, utils.mac2str(orig_sta), orig_sn)
        else:
            info = struct.pack("<BBB6sI6sII6sI", flags, hopcount, ttl,
                               utils.mac2str(
                                   targ_sta), targ_sn, utils.mac2str(targ_ext),
                               lifetime, metric, utils.mac2str(orig_sta), orig_sn)

        pkt = base_pkt / Dot11Elt(ID="PREP", info=info)

        xml = self.do_tshark_xml(pkt)
        tree = etree.fromstring(xml)
        ie = self.expectTagged(tree, "wlan_mgt", "Tag: Path Reply")
        self.expectField(ie, 'wlan_mgt.tag.number',
                         'Tag Number: Path Reply (131)', 131)
        self.expectField(ie, 'wlan.hwmp.flags', 'HWMP Flags: 0x%02X' %
                         flags, flags)
        self.expectField(ie, 'wlan.hwmp.hopcount', 'HWMP Hop Count: %d' %
                         hopcount, hopcount)
        self.expectField(ie, 'wlan.hwmp.ttl', 'HWMP TTL: %d' % ttl, ttl)
        self.expectField(ie, 'wlan.hwmp.targ_sta',
                         'Target STA Address: ' +
                             targ_sta + ' (' + targ_sta + ')',
                         binascii.hexlify(utils.mac2str(targ_sta)))
        self.expectField(
            ie, 'wlan.hwmp.targ_sn', 'Target HWMP Sequence Number: %d' %
            targ_sn, htonl(targ_sn))
        if targ_ext != None:
            self.expectField(ie, 'wlan.hwmp.targ_ext',
                             'Target External Address: ' +
                                 targ_ext + ' (' + targ_ext + ')',
                             binascii.hexlify(utils.mac2str(targ_ext)))
        self.expectField(ie, 'wlan.hwmp.lifetime', 'HWMP Lifetime: %d' %
                         lifetime, htonl(lifetime))
        self.expectField(ie, 'wlan.hwmp.metric', 'HWMP Metric: %d' %
                         metric, htonl(metric))
        self.expectField(ie, 'wlan.hwmp.orig_sta',
                         'Originator STA Address: ' +
                             orig_sta + ' (' + orig_sta + ')',
                         binascii.hexlify(utils.mac2str(orig_sta)))
        self.expectField(
            ie, 'wlan.hwmp.orig_sn', 'HWMP Originator Sequence Number: %d' %
            orig_sn, htonl(orig_sn))

    def do_hwmp_perr(self, ttl, targs=[]):
        base_pkt = Dot11(addr1="00:11:22:33:44:55",
                         addr2="00:11:22:33:44:55",
                         addr3="00:11:22:33:44:55") \
            / Dot11Action(category="Mesh")
        base_pkt = base_pkt / Dot11Mesh(mesh_action="HWMP")

        info = struct.pack("<BB", ttl, len(targs))
        for t in targs:
            if t["flags"] & (1 << 6):
                info += struct.pack("<B6sI6sH", t["flags"],
                                    utils.mac2str(t["addr"]), t["sn"], t["ext"], t["reason"])
            else:
                info += struct.pack("<B6sIH", t["flags"],
                                    utils.mac2str(t["addr"]), t["sn"], t["reason"])
        pkt = base_pkt / Dot11Elt(ID="PERR", info=info)

        xml = self.do_tshark_xml(pkt)
        tree = etree.fromstring(xml)
        ie = self.expectTagged(tree, "wlan_mgt", "Tag: Path Error")
        self.expectField(ie, 'wlan_mgt.tag.number',
                         'Tag Number: Path Error (132)', 132)
        self.expectField(ie, 'wlan.hwmp.targ_count', 'HWMP Target Count: %d' %
                         len(targs), len(targs))
        for t in targs:
            self.expectField(ie, 'wlan.hwmp.targ_flags',
                             'HWMP Per-Target Flags: 0x%02X' % t["flags"], t["flags"])
            self.expectField(ie, 'wlan.hwmp.targ_sta',
                             'Target STA Address: ' +
                                 t["addr"] + ' (' + t["addr"] + ')',
                             binascii.hexlify(utils.mac2str(t["addr"])))
            self.expectField(
                ie, 'wlan.hwmp.targ_sn', 'Target HWMP Sequence Number: %d' %
                t["sn"], htonl(t["sn"]))
            self.expectField(ie, 'wlan_mgt.fixed.reason_code',
                             None, htons(t["reason"]))

    def test_beacon(self):
        addr1s = "ff:ff:ff:ff:ff:ff"
        addr2s = "42:00:00:00:01:00"
        addr3s = "42:00:00:00:02:00"
        pkt = Dot11(addr1=addr1s, addr2=addr2s, addr3=addr3s)\
            / Dot11Beacon(cap="ESS")\
            / Dot11Elt(ID="SSID", info="fooSSID")\
            / Dot11Elt(ID="Rates", info='\x82\x84\x0b\x16')\
            / Dot11Elt(ID="DSset", info="\x03")\
            / Dot11Elt(ID="TIM", info="\x00\x01\x00\x00")
        pkts = self.do_tshark(pkt)
        self.expectEquals(pkt, pkts[0].pkt)

    def test_mesh_config_ie(self):
        addr1s = "ff:ff:ff:ff:ff:ff"
        addr2s = "42:00:00:00:01:00"
        addr3s = "42:00:00:00:02:00"
        base_pkt = Dot11(addr1=addr1s, addr2=addr2s, addr3=addr3s)\
            / Dot11Beacon(cap=0) \
            / Dot11Elt(ID="SSID", info="")\
            / Dot11Elt(ID="Rates", info='\x82\x84\x0b\x16')\
            / Dot11Elt(ID="DSset", info="\x03")\
            / Dot11Elt(ID="TIM", info="\x00\x01\x00\x00") \
            / Dot11Elt(ID="MeshID", info="")

        mc = binascii.unhexlify("01020304050607")
        pkt = base_pkt / Dot11Elt(ID="MeshConfig", info=mc)
        xml = self.do_tshark_xml(pkt)
        tree = etree.fromstring(xml)
        path = "packet/proto[@name='wlan_mgt']/field[@name='wlan_mgt.tagged.all']" + \
               "/field[@name='wlan_mgt.tag' and @showname='Tag: Mesh Configuration']"
        mc = tree.xpath(path)[0]
        self.expectField(mc, 'wlan_mgt.tag.number',
                         "Tag Number: Mesh Configuration (113)", 113)
        self.expectField(mc, 'wlan.mesh.config.ps_protocol',
                         "Path Selection Protocol: 0x01", 1)
        self.expectField(mc, 'wlan.mesh.config.ps_metric',
                         "Path Selection Metric: 0x02", 2)
        self.expectField(mc, 'wlan.mesh.config.cong_ctl',
                         "Congestion Control: 0x03", 3)
        self.expectField(mc, 'wlan.mesh.config.sync_method',
                         "Synchronization Method: 0x04", 4)
        self.expectField(mc, 'wlan.mesh.config.auth_protocol',
                         "Authentication Protocol: 0x05", 5)
        self.expectField(mc, 'wlan.mesh.config.formation_info',
                         "Formation Info: 0x06", 6)
        self.expectField(mc, 'wlan.mesh.config.cap',
                         "Capability: 0x07", 7)

    def test_mesh_id_ie(self):
        addr1s = "ff:ff:ff:ff:ff:ff"
        addr2s = "42:00:00:00:01:00"
        addr3s = "42:00:00:00:02:00"
        pkt = Dot11(addr1=addr1s, addr2=addr2s, addr3=addr3s)\
            / Dot11Beacon(cap=0) \
            / Dot11Elt(ID="SSID", info="")\
            / Dot11Elt(ID="Rates", info='\x82\x84\x0b\x16')\
            / Dot11Elt(ID="DSset", info="\x03")\
            / Dot11Elt(ID="TIM", info="\x00\x01\x00\x00") \
            / Dot11Elt(ID="MeshID", info="thisisatest")
        xml = self.do_tshark_xml(pkt)
        tree = etree.fromstring(xml)
        meshid = tree.xpath("packet/proto[@name='wlan_mgt']")[0]
        meshid = meshid.xpath("field[@name='wlan_mgt.tagged.all']")[0]
        meshid = meshid.xpath(
            "field[@name='wlan_mgt.tag' and @showname='Tag: Mesh ID: thisisatest']")[0]
        self.expectField(meshid, "wlan_mgt.tag.number",
                         "Tag Number: Mesh ID (114)", 114)
        self.expectField(meshid, "wlan.mesh.id", "Mesh ID: thisisatest",
                         binascii.hexlify("thisisatest"))

    def test_mesh_action_fixed_fields(self):
        base_pkt = Dot11(addr1="00:11:22:33:44:55",
                         addr2="00:11:22:33:44:55",
                         addr3="00:11:22:33:44:55") \
            / Dot11Action(category="Mesh") \

        pkt = base_pkt / Dot11Mesh(mesh_action="HWMP")
        xml = self.do_tshark_xml(pkt)
        tree = etree.fromstring(xml)
        action = self.expectFixed(
            tree, 'wlan_mgt.fixed.action', 'Action: 0x0d', 0x0d)
        self.expectField(action, "wlan_mgt.fixed.mesh_action",
                         "Mesh Action code: HWMP Mesh Path Selection (0x01)", 0x01)

        pkt = base_pkt / Dot11Mesh(mesh_action="TBTT Adjustment Response")
        pkt = pkt / Dot11MeshTBTTAdjResp(status=0)
        xml = self.do_tshark_xml(pkt)
        tree = etree.fromstring(xml)
        action = self.expectFixed(
            tree, 'wlan_mgt.fixed.action', 'Action: 0x0d', 0x0d)
        self.expectField(action, "wlan_mgt.fixed.mesh_action",
                         "Mesh Action code: TBTT Adjustment Response (0x0a)", 0x0A)
        self.expectField(action, "wlan_mgt.fixed.status_code",
                         "Status code: Successful (0x0000)", 0)

    def test_multihop_fixed_fields(self):
        base_pkt = Dot11(addr1="00:11:22:33:44:55",
                         addr2="00:11:22:33:44:55",
                         addr3="00:11:22:33:44:55") \
            / Dot11Action(category="Multihop")
        base_pkt = base_pkt / Dot11Multihop(multihop_action="Proxy Update")

        # ...with no address extension
        pkt = base_pkt / \
            Dot11MeshControl(mesh_ttl=5, mesh_sequence_number=0x99)
        xml = self.do_tshark_xml(pkt)
        tree = etree.fromstring(xml)
        action = self.expectFixed(
            tree, 'wlan_mgt.fixed.action', 'Action: 0x0e', 0x0e)
        self.expectField(action, 'wlan_mgt.fixed.mesh_flags',
                         'Mesh Flags: 0x00', 0x00)
        self.expectField(action, 'wlan_mgt.fixed.mesh_ttl',
                         'Mesh TTL: 0x05', 0x05)
        self.expectField(action, 'wlan_mgt.fixed.mesh_sequence',
                         'Sequence Number: 0x00000099', htonl(0x99))

        # ...with one address extension
        pkt = base_pkt / Dot11MeshControl(mesh_flags=1, mesh_ttl=5,
                                          mesh_sequence_number=0x1111,
                                          mesh_addr4="00:44:44:44:44:44")
        xml = self.do_tshark_xml(pkt)
        tree = etree.fromstring(xml)
        action = self.expectFixed(
            tree, 'wlan_mgt.fixed.action', 'Action: 0x0e', 0x0e)
        self.expectField(action, 'wlan_mgt.fixed.mesh_flags',
                         'Mesh Flags: 0x01', 0x01)
        self.expectField(action, 'wlan_mgt.fixed.mesh_addr4',
                         'Mesh Extended Address 4: 00:44:44:44:44:44 (00:44:44:44:44:44)',
                         "004444444444")

        # ...with two address extension
        pkt = base_pkt / Dot11MeshControl(mesh_flags=2,
                                          mesh_addr5="00:55:55:55:55:55",
                                          mesh_addr6="00:66:66:66:66:66")
        xml = self.do_tshark_xml(pkt)
        tree = etree.fromstring(xml)
        action = self.expectFixed(
            tree, 'wlan_mgt.fixed.action', 'Action: 0x0e', 0x0e)
        self.expectField(action, 'wlan_mgt.fixed.mesh_flags',
                         'Mesh Flags: 0x02', 0x02)
        self.expectField(action, 'wlan_mgt.fixed.mesh_addr5',
                         'Mesh Extended Address 5: 00:55:55:55:55:55 (00:55:55:55:55:55)',
                         "005555555555")
        self.expectField(action, 'wlan_mgt.fixed.mesh_addr6',
                         'Mesh Extended Address 6: 00:66:66:66:66:66 (00:66:66:66:66:66)',
                         "006666666666")

    def test_selfprot_fixed_fields(self):
        base_pkt = Dot11(addr1="00:11:22:33:44:55",
                         addr2="00:11:22:33:44:55",
                         addr3="00:11:22:33:44:55") \
            / Dot11Action(category="Self-protected")
        pkt = base_pkt / \
            Dot11SelfProtected(selfprot_action="Mesh Peering Open")
        pkt = pkt / Dot11MeshPeeringOpen(cap=0)
        xml = self.do_tshark_xml(pkt)
        tree = etree.fromstring(xml)
        action = self.expectFixed(
            tree, 'wlan_mgt.fixed.action', 'Action: 0x0f', 0x0f)
        self.expectField(action, 'wlan_mgt.fixed.selfprot_action',
                         'Self-protected Action code: Mesh Peering Open (0x01)', 0x01)
        self.expectField(action, 'wlan_mgt.fixed.capabilities',
                         'Capabilities Information: 0x0000', 0x0)

        pkt = base_pkt / \
            Dot11SelfProtected(selfprot_action="Mesh Peering Confirm")
        pkt = pkt / Dot11MeshPeeringConfirm(cap=0, AID=9)
        xml = self.do_tshark_xml(pkt)
        tree = etree.fromstring(xml)
        action = self.expectFixed(
            tree, 'wlan_mgt.fixed.action', 'Action: 0x0f', 0x0f)
        self.expectField(action, 'wlan_mgt.fixed.selfprot_action',
                         'Self-protected Action code: Mesh Peering Confirm (0x02)', 0x02)
        self.expectField(action, 'wlan_mgt.fixed.capabilities',
                         'Capabilities Information: 0x0000', 0x0)
        self.expectField(action, 'wlan_mgt.fixed.aid',
                         '..00 0000 0000 1001 = Association ID: 0x0009', 0x9)

    def test_mesh_peering_mgt_close_ie(self):
        base_pkt = Dot11(addr1="00:11:22:33:44:55",
                         addr2="00:11:22:33:44:55",
                         addr3="00:11:22:33:44:55") \
            / Dot11Action(category="Self-protected")
        base_pkt = base_pkt / \
            Dot11SelfProtected(selfprot_action="Mesh Peering Close")

        # Try one with proto_id = 1, local link id = 0x99, reason = 77 (0x4d)
        info = binascii.unhexlify("010099004d00")
        pkt = base_pkt / Dot11Elt(ID="MeshPeeringMgmt", info=info)
        xml = self.do_tshark_xml(pkt)
        tree = etree.fromstring(xml)
        action = self.expectFixed(
            tree, 'wlan_mgt.fixed.action', 'Action: 0x0f', 0x0f)
        self.expectField(action, 'wlan_mgt.fixed.selfprot_action',
                         'Self-protected Action code: Mesh Peering Close (0x03)', 0x03)
        ie = self.expectTagged(
            tree, "wlan_mgt", "Tag: Mesh Peering Management")
        self.expectField(ie, 'wlan_mgt.tag.number',
                         'Tag Number: Mesh Peering Management (117)', 117)
        self.expectField(ie, 'wlan.peering.proto',
                         'Mesh Peering Protocol ID: Authenticated mesh peering exchange protocol (0x0001)',
                         0x0100)
        self.expectField(ie, 'wlan.peering.local_id',
                         "Local Link ID: 0x0099", 0x9900)
        self.expectField(ie, 'wlan_mgt.fixed.status_code',
                         "Status code: Authentication is rejected because the offered finite cyclic group is not supported (0x004d)",
                         0x4d00)

        # ...now try the same thing with a 16B PMK ID on the end.
        pmkid = "000102030405060708090a0b0c0d0e0f"
        info += binascii.unhexlify(pmkid)
        pkt = base_pkt / Dot11Elt(ID="MeshPeeringMgmt", info=info)
        xml = self.do_tshark_xml(pkt)
        tree = etree.fromstring(xml)
        ie = self.expectTagged(
            tree, "wlan_mgt", "Tag: Mesh Peering Management")
        self.expectField(ie, 'wlan_mgt.pmkid.akms', 'PMKID: ' + pmkid, pmkid)

        # ...and now one with the optional peer link id before the status code.
        info = binascii.unhexlify("0100990088004e00")
        pkt = base_pkt / Dot11Elt(ID="MeshPeeringMgmt", info=info)
        xml = self.do_tshark_xml(pkt)
        tree = etree.fromstring(xml)
        ie = self.expectTagged(
            tree, "wlan_mgt", "Tag: Mesh Peering Management")
        self.expectField(ie, 'wlan.peering.peer_id',
                         "Peer Link ID: 0x0088", 0x8800)

        # ...and again with the pmk
        pmkid = "000102030405060708090a0b0c0d0e0f"
        info += binascii.unhexlify(pmkid)
        pkt = base_pkt / Dot11Elt(ID="MeshPeeringMgmt", info=info)
        xml = self.do_tshark_xml(pkt)
        tree = etree.fromstring(xml)
        ie = self.expectTagged(
            tree, "wlan_mgt", "Tag: Mesh Peering Management")
        self.expectField(ie, 'wlan_mgt.pmkid.akms', 'PMKID: ' + pmkid, pmkid)

    def test_hwmp_preq_ie(self):

        # do the most basic packet (albeit illegal): no external addr and no
        # targets
        self.do_hwmp_preq(flags=0, hopcount=9, ttl=3, pdid=123,
                          orig_sta="00:22:33:44:99:aa", orig_sn=4321,
                          lifetime=1024, metric=40)

        # now do the same thing but with an external address
        self.do_hwmp_preq(flags=(1 << 6), hopcount=9, ttl=3, pdid=123,
                          orig_sta="00:22:33:44:99:aa", orig_sn=4321,
                          lifetime=1024, metric=40, orig_ext="00:00:00:44:44:44")

        # now do the same thing but with a target
        self.do_hwmp_preq(flags=(1 << 6), hopcount=9, ttl=3, pdid=123,
                          orig_sta="00:22:33:44:99:aa", orig_sn=4321,
                          lifetime=1024, metric=40, orig_ext="00:00:00:44:44:44",
                          targs=[{"flags": 0, "addr": "00:33:33:33:33:33", "sn": 93}])

        # now try no ext address and a few targets
        self.do_hwmp_preq(flags=0, hopcount=9, ttl=3, pdid=123,
                          orig_sta="00:22:33:44:99:aa", orig_sn=4321,
                          lifetime=1024, metric=40,
                          targs=[
                              {"flags": 0, "addr":
                                  "00:33:33:33:33:33", "sn": 93},
                              {"flags": 0, "addr":
                               "00:33:33:33:33:38", "sn": 45},
                              {"flags": 0, "addr": "00:33:33:33:33:39", "sn": 7}])

    def test_hwmp_prep_ie(self):

        self.do_hwmp_prep(
            flags=0, hopcount=30, ttl=19, targ_sta="00:99:88:88:88:88",
            targ_sn=23, lifetime=987, metric=456, orig_sta="00:99:88:88:88:87",
            orig_sn=9)
        self.do_hwmp_prep(
            flags=(1 << 6), hopcount=30, ttl=19, targ_sta="00:99:88:88:88:88",
            targ_sn=23, lifetime=987, metric=456, orig_sta="00:99:88:88:88:87",
            orig_sn=9, targ_ext="00:44:44:44:44:44")

    def test_hwmp_perr_ie(self):

        self.do_hwmp_perr(ttl=99)

        self.do_hwmp_perr(ttl=2,
                          targs=[{"flags": 0, "addr": "00:33:33:33:33:33", "sn": 93, "reason": 57}])

        self.do_hwmp_perr(ttl=2,
                          targs=[{"flags": (1 << 6), "addr": "00:33:33:33:33:33", "sn": 93, "reason": 57, "ext": "00:11:33:55:77:99"}])

        self.do_hwmp_perr(ttl=3,
                          targs=[
                              {"flags": 0, "addr": "00:33:33:33:33:33",
                                  "sn": 93, "reason": 54},
                              {"flags": 0, "addr": "00:33:33:33:33:38",
                               "sn": 45, "reason": 55},
                              {"flags": 0, "addr": "00:33:33:33:33:39", "sn": 7, "reason": 56}])

        self.do_hwmp_perr(ttl=44,
                          targs=[
                              {"flags": 0, "addr": "00:33:33:33:33:33",
                                  "sn": 93, "reason": 54},
                              {"flags": (1 << 6), "addr": "00:33:33:33:33:38", "sn":
                                  45, "reason": 55, "ext": "55:33:55:77:55:44"},
                              {"flags": 0, "addr": "00:33:33:33:33:39", "sn": 7, "reason": 56}])

    def test_mesh_data_frame_addressing(self):
        # These tests are inspired by table 9-13 in the 11s standard.  Note
        # that mesh data frames always have the QoS header, and when they have
        # the MeshControl field, they always have the MeshControlPresent bit in
        # the QoS header set.  We fudge this a bit using scapy by setting the
        # TXOP field to 1.  Have a look at Table 7-4 of 11s draft v12 and
        # you'll see what I mean.

        # table entry 1
        pkt = Dot11(addr1="00:11:11:11:11:11",
                    addr2="00:22:22:22:22:22",
                    addr3="00:33:33:33:33:33",
                    addr4="00:44:44:44:44:44",
                    type="Data",
                    subtype=0x8,
                    FCfield="to-DS+from-DS") \
            / Dot11QoS(TXOP=1) \
            / Dot11MeshControl(mesh_ttl=5, mesh_sequence_number=0x99)
        data = struct.pack("<IIII", 1, 2, 3, 4)
        pkt = pkt / Packet(data)
        pkt = pkt / \
            Packet(struct.pack("<I", 0xffffffff & binascii.crc32(data)))
        xml = self.do_tshark_xml(pkt)
        tree = etree.fromstring(xml)
        header = tree.xpath("packet/proto[@name='wlan']")[0]
        meshctl = self.expectField(header, "", None, value="000599000000")
        self.expectField(meshctl, 'wlan_mgt.fixed.mesh_flags',
                         'Mesh Flags: 0x00', 0x00)

        # table entry 2
        pkt = Dot11(addr1="00:11:11:11:11:11",
                    addr2="00:22:22:22:22:22",
                    addr3="00:33:33:33:33:33",
                    type="Data",
                    subtype=0x8,
                    FCfield="from-DS") \
            / Dot11QoS(TXOP=1) \
            / Dot11MeshControl(mesh_ttl=5, mesh_sequence_number=0x99)
        data = struct.pack("<IIII", 1, 2, 3, 4)
        pkt = pkt / Packet(data)
        pkt = pkt / \
            Packet(struct.pack("<I", 0xffffffff & binascii.crc32(data)))
        xml = self.do_tshark_xml(pkt)
        tree = etree.fromstring(xml)
        header = tree.xpath("packet/proto[@name='wlan']")[0]
        meshctl = self.expectField(header, "", None, value="000599000000")
        self.expectField(meshctl, 'wlan_mgt.fixed.mesh_flags',
                         'Mesh Flags: 0x00', 0x00)

        # table entry 3
        pkt = Dot11(addr1="00:11:11:11:11:11",
                    addr2="00:22:22:22:22:22",
                    addr3="00:33:33:33:33:33",
                    addr4="00:44:44:44:44:44",
                    type="Data",
                    subtype=0x8,
                    FCfield="from-DS+to-DS") \
            / Dot11QoS(TXOP=1) \
            / Dot11MeshControl(
                mesh_flags=2, mesh_ttl=5, mesh_sequence_number=0x99,
                mesh_addr5="00:55:55:55:55:55",
                mesh_addr6="00:66:66:66:66:66")
        data = struct.pack("<IIII", 1, 2, 3, 4)
        pkt = pkt / Packet(data)
        pkt = pkt / \
            Packet(struct.pack("<I", 0xffffffff & binascii.crc32(data)))
        xml = self.do_tshark_xml(pkt)
        tree = etree.fromstring(xml)
        header = tree.xpath("packet/proto[@name='wlan']")[0]
        meshctl = self.expectField(
            header, "", None, value="020599000000005555555555006666666666")
        self.expectField(meshctl, 'wlan_mgt.fixed.mesh_flags',
                         'Mesh Flags: 0x02', 0x02)
        self.expectField(meshctl, 'wlan_mgt.fixed.mesh_addr5',
                         "Mesh Extended Address 5: 00:55:55:55:55:55 (00:55:55:55:55:55)",
                         "005555555555")
        self.expectField(meshctl, 'wlan_mgt.fixed.mesh_addr6',
                         "Mesh Extended Address 6: 00:66:66:66:66:66 (00:66:66:66:66:66)",
                         "006666666666")

        # table entry 4
        pkt = Dot11(addr1="00:11:11:11:11:11",
                    addr2="00:22:22:22:22:22",
                    addr3="00:33:33:33:33:33",
                    type="Data",
                    subtype=0x8,
                    FCfield="from-DS") \
            / Dot11QoS(TXOP=1) \
            / Dot11MeshControl(
                mesh_flags=1, mesh_ttl=5, mesh_sequence_number=0x99,
                mesh_addr4="00:44:44:44:44:44")
        data = struct.pack("<IIII", 1, 2, 3, 4)
        pkt = pkt / Packet(data)
        pkt = pkt / \
            Packet(struct.pack("<I", 0xffffffff & binascii.crc32(data)))
        xml = self.do_tshark_xml(pkt)
        tree = etree.fromstring(xml)
        header = tree.xpath("packet/proto[@name='wlan']")[0]
        meshctl = self.expectField(
            header, "", None, value="010599000000004444444444")
        self.expectField(meshctl, 'wlan_mgt.fixed.mesh_flags',
                         'Mesh Flags: 0x01', 0x01)
        self.expectField(meshctl, 'wlan_mgt.fixed.mesh_addr4',
                         "Mesh Extended Address 4: 00:44:44:44:44:44 (00:44:44:44:44:44)",
                         "004444444444")

    def test_rann_ie(self):
        base_pkt = Dot11(addr1="00:11:22:33:44:55",
                         addr2="00:11:22:33:44:55",
                         addr3="00:11:22:33:44:55") \
            / Dot11Action(category="Mesh") \

        pkt = base_pkt / Dot11Mesh(mesh_action="HWMP")
        xml = self.do_tshark_xml(pkt)
        tree = etree.fromstring(xml)
        action = self.expectFixed(
            tree, 'wlan_mgt.fixed.action', 'Action: 0x0d', 0x0d)

        info = binascii.unhexlify("010203444444444444050505050606060607070707")
        pkt = pkt / Dot11Elt(ID="RANN", info=info)
        xml = self.do_tshark_xml(pkt)
        tree = etree.fromstring(xml)
        action = self.expectFixed(
            tree, 'wlan_mgt.fixed.action', 'Action: 0x0d', 0x0d)
        ie = self.expectTagged(tree, "wlan_mgt", "Tag: Root Announcement")
        self.expectField(ie, 'wlan_mgt.tag.number',
                         'Tag Number: Root Announcement (126)', 126)
        self.expectField(ie, "wlan_mgt.tag.length", "Tag length: 21", "15")
        self.expectField(ie, "wlan.rann.flags", "RANN Flags: 0x01", "01")
        self.expectField(ie, "wlan.hwmp.hopcount", "HWMP Hop Count: 2", "02")
        self.expectField(ie, "wlan.hwmp.ttl", "HWMP TTL: 3", "03")
        self.expectField(ie, "wlan.rann.root_sta",
                         "Root STA Address: 44:44:44:44:44:44 (44:44:44:44:44:44)", "444444444444")
        self.expectField(ie, "wlan.rann.rann_sn",
                         "Root STA Sequence Number: 84215045", "05050505")
        self.expectField(ie, "wlan.rann.interval",
                         "RANN Interval: 101058054", "06060606")
        self.expectField(ie, "wlan.hwmp.metric",
                         "HWMP Metric: 117901063", "07070707")

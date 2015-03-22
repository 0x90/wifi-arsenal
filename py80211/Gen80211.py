from binascii import a2b_hex
import random
import pdb


class packetGenerator:
    """
    A collection of code for building 802.11 packets
    This code allows building both valid 802.11 packets as 
    well as malformed packets
    """
    def __init__(self):
        """
        intialize packet hex values
        """
        # seed the random number generator with system time
        random.seed()
        # packet headers are in little endian
        self.packetTypes = {
                "deauth": [0,12],  # deauthentication packet header
                "disass": [0,10],  # disassoication packet header
                "auth":   [0,11],  # authentication packet header
                "assos":  [0,0],   # association packet header
                "data":   [2,0],   # data packet header
                "reass":  [0,2]    # reassoication packet header
                }
        # the oldbcast address may not always work
        # note this also contains some multi cast addresses
        self.packetBcast = {
                "oldbcast": '\x00\x00\x00\x00\x00\x00',  # old broadcast address
                "l2": '\xff\xff\xff\xff\xff\xff',     # layer 2 mac broadcast
                "ipv6m": '\x33\x33\x00\x00\x00\x16',  # ipv6 multicast
                "stp": '\x01\x80\xc2\x00\x00\x00',    # Spanning Tree multicast 802.1D
                "cdp": '\x01\x00\x0c\xcc\xcc\xcc',    # CDP/VTP mutlicast address
                "cstp": '\x01\x00\x0C\xCC\xCC\xCD',   # Cisco shared STP Address
                "stpp": '\x01\x80\xc2\x00\x00\x08',   # Spanning Tree multicast 802.1AD
                "oam": '\x01\x80\xC2\x00\x00\x02',    # oam protocol 802.3ah
                "ipv4m": '\x01\x00\x5e\x7F\x00\xCD',  # ipv4 multicast
                "ota" : '\x01\x0b\x85\x00\x00\x00'    # Over the air provisioning multicast
                } 
        self.deauthPacketReason = [
                '\x0a\x00',  # Requested capability set is too broad 
                '\x01\x00',  # unspecified 
                '\x05\x00',  # disassociated due to insufficent resources at the ap
                '\x04\x00',  # Inactivity timer expired
                '\x08\x00',  # Station has left BSS or EBSS
                '\x02\x00'   # Prior auth is not valid
                ]  #reason codes
                # add more reason codes?
       
        # bits are shown in little endian
        self.capabilities = {
            "xmas": self.bit2hex('1111111111111111'),  # xmas setting, flag all 16 bits
            "apnw": self.bit2hex('1100000000000001'),  # pretend to be an AP but not support wep
            "apw":  self.bit2hex('1000110000000001'),  # pretend to be ap but support wep and short preamble
            "empty": self.bit2hex('0000000000000000'), # unset all bits
            }

    def wdsPacketEngine(self, allow_bcast, destination_addr, source_addr, bss_id_addr, channel):
        """
        Generate a wds packet to the AP
        """
        packets = []
        channel = int(channel)
        if allow_bcast == True:
            for bcast in self.packetBcast:
                    packets.append([self.wdsBuildPacket(
                        self.packetTypes['data'],  # packet type
                        destination_addr,         # destinaion
                        self.packetBcast[bcast],  # source
                        bss_id_addr,              # bssid
                        ),
                        channel, source_addr])

        if allow_bcast == False:
            packets.append([
                self.wdsBuildPacket(
                    self.packetTypes['data'],  # packet type
                    destination_addr,         # destinaion
                    source_addr,              # source
                    bss_id_addr,              # bssid
                    ),
                    channel, source_addr])
        return packets

    def reassPacketEngine(self, allow_bcast, destination_addr, source_addr, bss_id_addr, channel, frameType = ['reass']):
        """
        Generate a reassoication packet
        """
        return self.authPacketEngine(allow_bcast, destination_addr, source_addr, bss_id_addr, channel, frameType)
    
    def authPacketEngine(self, allow_bcast, source_addr, destination_addr, bss_id_addr, channel, frameType = ["auth","assos"]):
        """
        Build each packet based on options
        Options are packets with broadcast address or no broadcast addresses
        allow_bcast is a boolen var on if bcast addresses are allowed to be used
        source_addr is expecting a string mac addy in format of "xx:xx:xx:xx:xx:xx"
        destination_addr is expecting a string mac addy in format of "xx:xx:xx:xx:xx:xx"
        bss_id_addr is expecing the bssid mac addy in format of "xx:xx:xx:xx:xx:xx"`
        channel is expected as int, no check is done if its a valid 802.11 channel
        """
        packets = []
        channel = int(channel)

        #maybe flag all bits?
        #flag the MFP bits? maybe put it required to be on but put protection capable off?
        #above is all number 4
        
        #MFP
        #spoofed assoc responce can cause deauth

        #look into support RSN parts of packet
        # extented bit to packets, going to require user to provide essid of network

        if allow_bcast == True:
            for ptype in frameType:  # send an auth packet
                for bcast in self.packetBcast:
                        packets.append([self.authBuildPacket(
                            self.packetTypes[ptype],  # packet type
                            destination_addr,         # destinaion
                            self.packetBcast[bcast],  # source
                            bss_id_addr,              # bssid
                            ptype                     # expected packet type
                            ),
                            channel, source_addr])

        if allow_bcast == False:
            for ptype in frameType:  # send an auth packet
                packets.append([
                    self.authBuildPacket(
                        self.packetTypes[ptype],  # packet type
                        destination_addr,         # destinaion
                        source_addr,              # source
                        bss_id_addr,              # bssid
                        ptype                     # expected packet type
                        ),
                        channel, source_addr])
        return packets

    def deauthPacketEngine(self, allow_bcast, destination_addr, source_addr, bss_id_addr, channel, frameType = ['deauth','disass']):
        """
        Build each packet based on options
        Options are packets with broadcast address
        or no broadcast addresses
        allow_bcast is a boolen var on if bcast addresses are allowed to be used
        destination_addr is expecting a string mac addy in format of "xx:xx:xx:xx:xx:xx"
        source_addr is expecting a string mac addy in format of "xx:xx:xx:xx:xx:xx"
        bss_id_addr is expecting the bssid mac addy in format of "xx:xx:xx:xx:xx:xx"
        channel is expected as int, no check is done if its a valid 802.11 channel
        a list of frames types to send, these can be overloaded
        """
        packets = []
        channel = int(channel)
        if allow_bcast == False:
            # broadcast packets will not be sent
            # tx two packets with random reasons one two and one from
            for btype in frameType:
                packets.append([
                    self.deauthBuildPacket(
                        self.packetTypes[btype],  # packet type
                        destination_addr,         # destinaion
                        source_addr,              # source
                        bss_id_addr,              # bssid
                        self.randomDictObj(self.deauthPacketReason)  # resoncode
                        ),
                    channel])
                # reverse the source and dst to get packets to go to both ap and client
                packets.append([
                    self.deauthBuildPacket(
                        self.packetTypes[btype],  # packet type
                        source_addr,              # destination
                        destination_addr,         # source
                        bss_id_addr,              # bssid
                        self.randomDictObj(self.deauthPacketReason)  # reasoncode
                        ),
                    channel])

        if allow_bcast == True:
            # broadcast packets will be sent
            # tx two packets with random reasons one too bssid and one from bssid
            for btype in frameType: 
                packets.append([
                    self.deauthBuildPacket(
                        self.packetTypes[btype],
                        destination_addr,
                        source_addr,
                        bss_id_addr,
                        self.randomDictObj(self.deauthPacketReason)
                        ),
                    channel])
                packets.append([
                    self.deauthBuildPacket(
                        self.packetTypes[btype],
                        source_addr,
                        destination_addr,
                        bss_id_addr,
                        self.randomDictObj(self.deauthPacketReason)
                        ),
                    channel])
                # send bcast packets one too and one from
                for bcast in self.packetBcast:
                    packets.append([
                        self.deauthBuildPacket(
                            self.packetTypes[btype],   # packet type
                            self.packetBcast[bcast],   # destination
                            source_addr,               # source
                            bss_id_addr,               # bssid
                            self.randomDictObj(self.deauthPacketReason) # reasoncode
                            ),
                        channel])
                    packets.append([
                        self.deauthBuildPacket(
                            self.packetTypes[btype],   # packet type
                            source_addr,               # destination
                            self.packetBcast[bcast],   # source
                            bss_id_addr,               # bssid
                            self.randomDictObj(self.deauthPacketReason) # reasoncode
                            ),channel])
        return packets
    
    def authBuildPacket(self, bptype, dstAddr, srcAddr, bssid, ptype):
        """
        Constructs the packets to be sent
        ptype = expected packet type
        """
        # packetParts positions are as follows 
        # 0:bptype 1:destination_addr 2:source_addr 3:bss_id_addr 4:reason
        packet = [self.genPtype(bptype)] # packet subtype & flags
        packet.append('\x00\x00')        # duration
        packet.append(dstAddr)       # destain_addr
        packet.append(srcAddr)       # source_addr
        packet.append(bssid)         # bss_id_addr
        packet.append('\x90\x00')    # seq number set to 9
        if ptype in ['assos', 'reass']:         # assoication packet type we need to change a few bits
            # known bug here, where the ssid, and supported rates are needed
            packet.append(self.randomDictObj(self.capabilities)) # capabilities field
            packet.append('\x01\x00')   # listen interval
            packet.append('\x00\x00')   # set broadcast bssid
        else:
            packet.append('\x00\x00\x01\x00\x00\x00')  # set to open system auth
        return "".join(packet)

    def deauthBuildPacket(self, btype ,dstAddr, srcAddr, bssid, reasonCode):
        """
        Constructs the deauth/disassoicate packets to be sent
        """
        # packetParts positions are as follows 
        # 0:type 1:destination_addr 2:source_addr 3:bss_id_addr 4:reason
        packet = [self.genPtype(btype)]  # subtype & flags
        packet.append('\x00\x00')        # duration
        packet.append(dstAddr)       # destain_addr
        packet.append(srcAddr)       # source_addr
        packet.append(bssid)         # bss_id_addr
        packet.append('\x90\x00')    # seq number #set to 9
        packet.append(reasonCode)    # reason code
        return "".join(packet)

    def wdsBuildPacket(self, btype ,dstAddr, srcAddr, bssid):
        """
        Contructs the WDS 4 address packet to be sent
        """
        # packetParts positions are as follows 
        # 0:type 1:destination_addr 2:source_addr 3:bss_id_addr 4:reason
        if dstAddr == bssid:
            dsDir = True
        else:
            dsDir = False
        packet = [self.genPtype(btype)] # subtype & flags
        packet.append('\x00\x00')    # duration
        packet.append(dstAddr)       # destain_addr
        packet.append(srcAddr)       # source_addr
        packet.append(bssid)         # bss_id_addr
        packet.append('\x90\x00')    # seq number , set to 9
        packet.append(srcAddr)       # wds src addr
        return "".join(packet)

    def randomDictObj(self, dictObject):
        """
        provide a random object value from a given dictionary or list
        dictObject = Dictionary object to pull random values from
        """
        if type(dictObject) is not list: 
            dictObjectList = dictObject.values()
        else:
            dictObjectList = dictObject
        return random.choice(dictObjectList)

    def randomMac(self):
        """
        # really not needed replaced by randomDictOjb
        # left in for the time being since its not being used
        # will most likely delete
        return a random mac address from self.packetBcast
        """
        return self.packetBcast.values()[
            random.randrange(0,
                len(self.packetBcast.values(), 1))]
    
    def convertHex(self, mac):
        """
        # set for removal? 
        convert a mac address to hex
        """
        return a2b_hex(mac.replace(":", ""))
    
    def randDeauthReason(self):
        """
        #set for removal
        Generate a random reason code for the kick
        """
        return self.deauthPacketReason[
            random.randrange(
                0 ,len(self.deauthPacketReason), 1)]

    def bit2hex(self, bits):
        """
        convert a string of bits to hex... the easy way
        string of bits to base 2 returns and int
        then preform an chr on the int
        currently expects 16 bits
        """
        # this can also be done as
        # hex(int(bits, 2))
        # however the hex bytes drop leading 0's and this causes offset issues
        # in the packet creation
        fbit = int(bits[0:8], 2)
        sbit = int(bits[8:16], 2)
        return chr(fbit) + chr(sbit)
    
    def genPtype(self, ptype, fromds = "adhoc"):
        """
        generate a framecontrol in little endian
        ptype is list [type,subtype] as int
        if fromds is false then packet is from client to ap
        if fromds is true then packet is from ap to clinet
        returns 2 bytes as string
        """
        # set the type
        pbyte = 0 | int(ptype[0]) << 2
        # set the subtype
        pbyte = pbyte | int(ptype[1]) << 4
        if fromds == "client":
            # from client to ap
            flags = '\x02'
        elif fromds == "ap":
            # from ap to client
            flags = '\x01'
        elif fromds == "adhoc":
            # managment frame or adhoc
            flags = '\x00'

        return chr(pbyte) + flags


if __name__ == "__main__":
  for bits in packetGenerator().capabilities:
    pass

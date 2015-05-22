from core.wpscrypto import WpsCrypto
from scapy.all import *

class WPS(object):

	wpscrypto = WpsCrypto()

	tags = {
			0x104A : {'name' : 'WPS Version                      ', 'type' : 'hex', 'desc' : { 0x10 : '1.0', 0x11 : '1.1'}},
			0x1044 : {'name' : 'WPS State                        ', 'type' : 'hex', 'desc' : { 0x01 : 'Not Configured', 0x02 : 'Configured'}},
			0x1012 : {'name' : 'Device Password ID               ', 'type' : 'hex', 'desc' : { 0x0000 : 'Pin', 0x0004 : 'PushButton'}},
			0x1053 : {'name' : 'Selected Registrar Config Methods', 
					  'desc' : { 
									0x0001 : 'USB',
									0x0002 : 'Ethernet',
									0x0004 : 'Label',
									0x0008 : 'Display',
									0x0010 : 'External NFC',
									0x0020 : 'Internal NFC',
									0x0040 : 'NFC Interface',
									0x0080 : 'Push Button',
									0x0100 : 'Keypad'
								}, 
					  'type' : 'hex'},
			0x1057 : {'name' : 'AP Setup Locked                  ', 'type' : 'hex'},
			0x1041 : {'name' : 'Selected Registrar               ', 'type' : 'hex'},			
			0x103B : {'name' : 'Response Type                    ', 'type' : 'hex'},
			0x1047 : {'name' : 'UUID-E                           ', 'type' : 'hex'},
			0x1021 : {'name' : 'Manufacturer                     ', 'type' : 'str'},
			0x1023 : {'name' : 'Model Name                       ', 'type' : 'str'},
			0x1024 : {'name' : 'Model Number                     ', 'type' : 'str'},
			0x1042 : {'name' : 'Serial Number                    ', 'type' : 'str'},
			0x1054 : {'name' : 'Primary Device Type              ', 'type' : 'hex'},
			0x1011 : {'name' : 'Device Name                      ', 'type' : 'str'},
			0x1008 : {'name' : 'Config Methods                   ', 'type' : 'hex'},
			0x103C : {'name' : 'RF Bands                         ', 'type' : 'hex'},
			0x1045 : {'name' : 'SSID                             ', 'type' : 'str'},
			0x102D : {'name' : 'OS Version                       ', 'type' : 'str'},
            0xFF00 : {'name' : 'Vendor                           ', 'type' : 'str'},
            0xFF01 : {'name' : 'Vendor Type                      ', 'type' : 'str'},
            0xFF02 : {'name' : 'Opcode                           ', 'type' : 'hex'},
            0xFF03 : {'name' : 'Flags                            ', 'type' : 'hex'},
            0x1022 : {'name' : 'Message Type                     ', 'type' : 'hex'},
            0x1020 : {'name' : 'MAC                              ', 'type' : 'hex'},
            0x101A : {'name' : 'Enrollee Nonce                   ', 'type' : 'hex'},
            0x1032 : {'name' : 'Public Key                       ', 'type' : 'hex'},
            0x1010 : {'name' : 'Encryption Type Flags            ', 'type' : 'hex'},
            0x100d : {'name' : 'Connection Type Flags            ', 'type' : 'hex'},
            0x1008 : {'name' : 'Config Methods                   ', 'type' : 'hex'},
            0x100D : {'name' : 'Wifi Protected Setup State       ', 'type' : 'hex'},
            0x1002 : {'name' : 'Association State                ', 'type' : 'hex'},
            0x1009 : {'name' : 'Configuration Error              ', 'type' : 'hex'},
            0x102D : {'name' : 'OS Version                       ', 'type' : 'hex'},
            0x1004 : {'name' : 'Authentication Type              ', 'type' : 'hex'},
            0x1005 : {'name' : 'Authenticator                    ', 'type' : 'hex'},
            0x1048 : {'name' : 'UUID R                           ', 'type' : 'hex'},
            0x1039 : {'name' : 'Registrar Nonce                  ', 'type' : 'hex'},
            0x1014 : {'name' : 'E Hash 1                         ', 'type' : 'hex'},
            0x1015 : {'name' : 'E Hash 2                         ', 'type' : 'hex'},
            0x103D : {'name' : 'R Hash 2                         ', 'type' : 'hex'},
            0x103E : {'name' : 'R Hash 2                         ', 'type' : 'hex'},
            0x1018 : {'name' : 'Encrypted Settings               ', 'type' : 'hex'},
            0x103F : {'name' : 'R-S1                             ', 'type' : 'hex'},
            0x101e : {'name' : 'Key Wrap Algorithm               ', 'type' : 'hex'},
            0x1016 : {'name' : 'E-S1                             ', 'type' : 'hex'},
            0x1017 : {'name' : 'E-S2                             ', 'type' : 'hex'}, 
            0x100F : {'name' : 'Encryption Type                  ', 'type' : 'hex'},
            0x1003 : {'name' : 'Auth Type                        ', 'type' : 'hex'},
            0x1027 : {'name' : 'Network Key                      ', 'type' : 'hex'},
            0x1028 : {'name' : 'Network Key Index                ', 'type' : 'hex'}
	}

	message_types = {
					  0x04 : 'M1',
					  0x05 : 'M2',
					  0x07 : 'M3',
					  0x08 : 'M4',
					  0x09 : 'M5',
					  0x0a : 'M6',
					  0x0b : 'M7',
					  0x0c : 'M8',
					  0x0f : 'WSC_DONE',
					  0x0e : 'WSC_NACK'
					}
	
	#Converts an array of bytes ('\x01\x02\x03...') to an integer value
	def str_int(self, string):
		intval = 0
		shift = (len(string)-1) * 8;

		for byte in string:
			try:
				intval += int(ord(byte)) << shift
				shift -= 8
			except Exception,e:
				print 'Caught exception converting string to int:',e
				return False
		return intval

	def parse_tags(self, packet):
		header = "\x00\x50\xF2\x04"
		offset = len(header)
		elt = None
		eltcount = 1
		data = {'info': []}
		taglen = 0

		if (packet.haslayer(Dot11ProbeResp) or packet.haslayer(Dot11Beacon)) and packet.haslayer(Dot11Elt):
			
			data['bssid'] = packet[Dot11].addr3.upper()
			
			try:
				while elt != packet.lastlayer(Dot11Elt):
					elt = packet.getlayer(Dot11Elt, nb=eltcount)
					eltcount += 1

					if elt.ID == 0:
						data['essid'] = elt.info

					if elt.ID == 221:
						if elt.info.startswith(header):
							while (offset < elt.len):
								#Get tag number and length
								tag = int((ord(elt.info[offset]) * 0x100) + ord(elt.info[offset + 1]))
								#tag = self.str_int(elt.info[offset:offset + 2])
								offset += 2
								
								taglen = int((ord(elt.info[offset]) * 0x100) + ord(elt.info[offset + 1]))
								#taglen = self.str_int(elt.info[offset:offset + 2])
								offset += 2

								#Get the tag data
								#tagdata = elt.info[offset:offset + taglen]
								tagdata = self.str_int(elt.info[offset:offset + taglen])
								offset += taglen

								#Lookup the tag name and type
								try:
									tagname = self.tags[tag]['name']
								except KeyError:
									tagname = 'Unkown - (%s)' % hex(tagname)

								try:
									tagdesc =  self.tags[tag]['desc'][tagdata]
								except KeyError:
									tagdesc = None

								try:
									datatype = self.tags[tag]['type']
								except KeyError:
									datatype = 'hex'

								#Append to dic
								data['info'].append((tagname, hex(tagdata), tagdesc, datatype))

				try:
					if (len(data['essid']) > 0 and len(data['bssid']) > 0 and len(data['info']) > 0):
						return data
				except KeyError:
					pass

			except Exception, e:
				print 'Exception processing WPS packet:', str(e)				
				
					
	def parse_message(self, packet):

		d = {}
		message_type = None

		if (packet.haslayer(EAP) and packet[EAP].code == 1 and packet[EAP].type == 254):

			wpscrypto.last_msg_buffer = str(packet[Raw])[:-4]
			disasm = wpscrypto.disassemble_EAP_Expanded(packet[Raw], has_FCS=True, has_start=True)

			for e in disasm:
				d[e[0]] = e[1]

			if 0x1022 in d:
				if ord(d[0x1022]) in self.message_types:
					message_type = self.message_types[ord(d[0x1022])]
				
				if message_type == 'M1':
					wpscrypto.ENonce = d[0x101a]
					wpscrypto.PK_E = d[0x1032]            
					wpscrypto.EnrolleeMAC = d[0x1020]
				
				elif message_type == 'M3':
					wpscrypto.EHash1 = d[0x1014]
					wpscrypto.EHash2 = d[0x1015]

				elif message_type == 'M7':
					encrypted = d[0x1018]
					x = self.decrypt(encrypted[:16], encrypted[16:])
					wpscrypto.dump_EAP_Expanded(x)
				
				elif message_type == 'WSC_NACK':
					if self.m4_sent:
						wireless.send_wcs_nack()
					else:
						print 'got NACK before M4 - something is wrong'
						self.has_retry = True
	
			return message_type
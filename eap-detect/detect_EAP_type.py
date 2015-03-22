from scapy.all import * 
def eap_name_from_code(type_number):
	output="Invalid"
	if type_number==25:
		output="PEAP"
	elif type_number==13:
		output="EAP-TLS"
	elif type_number==21:
		output="EAP-TTLS"
	elif type_number==43:
		output="EAP-FAST"
	elif type_number==17:
		output="LEAP"
	return output

conf.iface="mon0"
output="Invalid"
while (output=="Invalid"):
	packets=sniff(iface="mon0",count=10, filter="wlan proto 0x888e",timeout=20)
	#packets=rdpcap("/home/raiton/Bureau/captured_pcpap/cap")
	packet_iter=packets.__iter__()
	i=0
	while i<len(packets):
		pkt=packet_iter.next()
		try:
			if (pkt[5].code==1) and (pkt[5].id!=0):
	 			if pkt[5].id==2:
	 				type_number= pkt[5].type
	 				break
	 			elif pkt[5].id==1:
					pkt=packet_iter.next()
					if pkt[5].type==3:
						pkt=packet_iter.next()
						type_number= pkt[5].type
						break
					else:
						type_number= pkt[5].type
						break

		except Exception, e:
			pass
		i+=1
	output= eap_name_from_code(type_number)
	print output


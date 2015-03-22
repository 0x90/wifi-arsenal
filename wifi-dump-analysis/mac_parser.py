#Author : Abhinav Narain 
#Date : 15 Jan, 2012 
#Purpose : Defines all the parsing functions for mac headers and radiotap header 
import sys
import struct
from header import *
from collections import defaultdict
Station=set()
Bismark_mac=[]
bismark_status =0

ieee80211= radiotap_rx()
mcs_rate=mcs_flags()
channel_flags=channel_flag()
flags=flag()	 

def print_hex_mac(src_mac_address):
        return "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB",src_mac_address)

def print_chaninfo(flags) :	
        if (IS_CHAN_FHSS(flags)) :
                return "FHSS"
        if (IS_CHAN_A(flags)) :
                if (flags & IEEE80211_CHAN_HALF) :
                        return "11a/10Mhz"
                elif (flags & IEEE80211_CHAN_QUARTER) :
                        return"11a/5Mhz"
                else:
                        return "11a"
        if (IS_CHAN_ANYG(flags)) :
                if (flags & IEEE80211_CHAN_HALF):
                        return  "11g/10Mhz"
                elif (flags & IEEE80211_CHAN_QUARTER) :
                        return "11g/5Mhz"
                else :
                        return "11g"
        elif (IS_CHAN_B(flags)):
                return "11b"
        if (flags & IEEE80211_CHAN_TURBO):
                return "Turbo"
        if (flags & IEEE80211_CHAN_HT20):
                return "ht/20"
        elif (flags & IEEE80211_CHAN_HT40D):
                return "ht/40-"
        elif (flags & IEEE80211_CHAN_HT40U):
                return "ht/40+"

def parse_radiotap(frame,radiotap_len,present_flag,offset,monitor_elem,frame_elem):	
	if radiotap_len == 58 :
		actual_rate =-1 # this is filled at the end of the parse with ht/non ht rate
		radiotap_data_retries = 0 
		tsf=0
		if present_flag & 1<<ieee80211.IEEE80211_RADIOTAP_TSFT :
			tsf=list(struct.unpack('<Q',frame[offset:offset+8]))[0]
			offset +=8			
		if present_flag & 1<<ieee80211.IEEE80211_RADIOTAP_FLAGS : 			
			radiotap_flags= list(struct.unpack('B',frame[offset]))[0] #bad fcs; short preambl
			rad_flag_elem=[]
			if radiotap_flags & flags.IEEE80211_RADIOTAP_F_SHORTPRE :
				rad_flag_elem.append(1)
			else :
				rad_flag_elem.append(0)
			if radiotap_flags & flags.IEEE80211_RADIOTAP_F_WEP :
				rad_flag_elem.append(1)
			else :
				rad_flag_elem.append(0)
			if radiotap_flags & flags.IEEE80211_RADIOTAP_F_BADFCS :
				rad_flag_elem.append(1)
			else :
				rad_flag_elem.append(0)
			if radiotap_flags & flags.IEEE80211_RADIOTAP_F_FRAG:
				rad_flag_elem.append(1)	
			else :
				rad_flag_elem.append(0)
			frame_elem[tsf].append(rad_flag_elem)
			offset +=1
		if present_flag & 1<<ieee80211.IEEE80211_RADIOTAP_RATE :
			radiotap_rate=  list(struct.unpack('B',frame[offset]))[0]
			if radiotap_rate >= 0x80 and radiotap_rate <=0x8f :
				#print "rate = ", radiotap_rate & 0x7f
				actual_rate = radiotap_rate & 0x7f
			else:
				actual_rate =  (radiotap_rate*1.0/2)
			offset +=1
		else :
			radiotap_rate=  list(struct.unpack('B',frame[offset]))[0]
			offset +=1                        
		if present_flag & 1<<ieee80211.IEEE80211_RADIOTAP_CHANNEL : 			
			#print "offset before channel ",offset 
			radiotap_freq=list(struct.unpack('<H',frame[offset:offset+2]))[0] #18:20
			offset += 2
			#print "radiotap freq = " , radiotap_freq 
			radiotap_fhss=list(struct.unpack('<H',frame[offset:offset+2]))[0] #20:22
			frame_elem[tsf].append(radiotap_freq)
                        protocol=print_chaninfo(radiotap_fhss)
			frame_elem[tsf].append(protocol)
			offset += 2
		if present_flag & 1<<ieee80211.IEEE80211_RADIOTAP_DBM_ANTSIGNAL :
			#print "dbm signal offset[22] " ,offset
			radiotap_signal=list(struct.unpack('b',frame[offset]))[0]
			#print "signal with sign" ,struct.unpack('b',frame[offset])
			frame_elem[tsf].append(radiotap_signal)
			offset += 1
		if present_flag & 1<<ieee80211.IEEE80211_RADIOTAP_DBM_ANTNOISE : 
			radiotap_noise=list(struct.unpack('b',frame[offset]))[0]#23
			frame_elem[tsf].append(radiotap_noise)
			monitor_elem[tsf].append(radiotap_noise)
			#print "noise with sign " ,radiotap_noise
			offset += 1
		if present_flag & 1<<ieee80211.IEEE80211_RADIOTAP_ANTENNA :
			radiotap_antenna= list(struct.unpack('B',frame[offset]))[0]#24
			frame_elem[tsf].append(radiotap_antenna)
			offset += 1
			#padding 
			offset += 1
		if present_flag & 1<<ieee80211.IEEE80211_RADIOTAP_RX_FLAGS :
			radiotap_rx_flags= list(struct.unpack('<H',frame[offset:offset+2]))[0]#26:28
                        rad_rx_flags_elem=[]
			if radiotap_rx_flags & flags.IEEE80211_RADIOTAP_F_RX_BADPLCP:
				print "bad plcp"
                                rad_rx_flags_elem.append(1)
                        else :
                                rad_rx_flags_elem.append(0)
			if radiotap_rx_flags & flags.IEEE80211_RADIOTAP_F_HOMESAW_RX_AGG:
				#print "rx aggregate " 
                                rad_rx_flags_elem.append(1)
                        else :
                                rad_rx_flags_elem.append(0)
			if radiotap_rx_flags & flags.IEEE80211_RADIOTAP_F_HOMESAW_FAILED_PHY:
				print "failed phy "
				sys.exit(1)
                                rad_rx_flags_elem.append(1)
                        else :
                                rad_rx_flags_elem.append(0)
                                frame_elem[tsf].append(rad_rx_flags_elem)
			offset += 2
		if present_flag & 1<<ieee80211.IEEE80211_RADIOTAP_MCS :
			mcs_known=list(struct.unpack('B',frame[offset]))[0]
			offset += 1 
			mcs_flags=list(struct.unpack('B',frame[offset]))[0]
			offset += 1 
			mcs=list(struct.unpack('B',frame[offset]))[0]
			offset += 1 
			bandwidth=0
			can_calculate_rate = 1 
			gi_length=0
			if (mcs_known & mcs_rate.IEEE80211_RADIOTAP_MCS_HAVE_BW) :
                           if ((mcs_flags & mcs_rate.IEEE80211_RADIOTAP_MCS_BW_MASK) \
                                       == mcs_rate.IEEE80211_RADIOTAP_MCS_BW_40):
				   bandwidth = 1
			   else :
				   bandwidth = 0
			else :
				bandwidth = 0;
				can_calculate_rate =0

			if (mcs_known & mcs_rate.IEEE80211_RADIOTAP_MCS_HAVE_GI) :
				if (mcs_flags & mcs_rate.IEEE80211_RADIOTAP_MCS_SGI) :
					gi_length = 1
				else :
					gi_length = 0
			else :
				gi_length = 0;
				can_calculate_rate = 0

			if (mcs_known & mcs_rate.IEEE80211_RADIOTAP_MCS_HAVE_MCS) :
				pass  # Wireshark null
                        else :
                                can_calculate_rate = 0 
                        if (can_calculate_rate and mcs <= mcs_rate.MAX_MCS_INDEX \
                                    and ht_rates[mcs][bandwidth][gi_length] != 0.0) :
                                if (radiotap_rate ==0) :
                                        actual_rate= ht_rates[mcs][bandwidth][gi_length]
                
                if (actual_rate ==-1):
                        print "actual rate can't be negative"
                frame_elem[tsf].append(actual_rate)
                #print "Data Rate in rx :", actual_rate
		homesaw_oui_1=list(struct.unpack('B',frame[offset]))[0]
		offset +=1 
		homesaw_oui_2=list(struct.unpack('B',frame[offset]))[0]
		offset +=1 
		homesaw_oui_3=list(struct.unpack('B',frame[offset]))[0]
		offset +=1 
		homesaw_namespace=list(struct.unpack('B',frame[offset]))[0]
		offset +=1 
		skip_len=int(list(struct.unpack('>H',frame[offset:offset+2]))[0])
		offset +=2
		if present_flag & 1<<ieee80211.IEEE80211_RADIOTAP_PHYERR_COUNT :
			radiotap_phyerr_count = list(struct.unpack('<I',frame[offset:offset+4]))[0]
			#print " phy count= ",radiotap_phyerr_count
			monitor_elem[tsf].append(radiotap_phyerr_count)
			offset += 4
		if present_flag & 1<<ieee80211.IEEE80211_RADIOTAP_CCK_PHYERR_COUNT :
			radiotap_cck_phyerr_count = list(struct.unpack('<I',frame[offset:offset+4]))[0]
			monitor_elem[tsf].append(radiotap_cck_phyerr_count) 
			offset += 4
		if present_flag & 1<<ieee80211.IEEE80211_RADIOTAP_OFDM_PHYERR_COUNT :
			radiotap_ofdm_phyerr_count = list(struct.unpack('<I',frame[offset:offset+4]))[0]
			monitor_elem[tsf].append(radiotap_ofdm_phyerr_count)
			offset += 4
		if present_flag & 1<<ieee80211.IEEE80211_RADIOTAP_RX_QUEUE_TIME :
			radiotap_rx_queue_time =  list(struct.unpack('<I',frame[offset:offset+4]))[0]
			frame_elem[tsf].append(radiotap_rx_queue_time)
			offset +=4
		if present_flag & 1<<ieee80211.IEEE80211_RADIOTAP_CAPLEN :
			radiotap_caplen=  list(struct.unpack('<H',frame[offset:offset+2]))[0]
			frame_elem[tsf].append(radiotap_caplen)
			offset +=2
		if present_flag & 1<<ieee80211.IEEE80211_RADIOTAP_RSSI :
			radiotap_rssi= list(struct.unpack('B',frame[offset]))[0]
			#TODO : FIX THIS IN NEXT VERSION ; instead of constant, get the real value, though redundant field
		if present_flag & 1<<ieee80211.IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE :
			pass # radiotap artifact  
		if present_flag & 1<<ieee80211.IEEE80211_RADIOTAP_VENDOR_NAMESPACE :
			pass #radiotap artifact 
		if present_flag & 1<<ieee80211.IEEE80211_RADIOTAP_EXT :
			pass #radiotap artifact
		radiotap_calc_rssi =radiotap_signal-radiotap_noise 
		frame_elem[tsf].append(radiotap_calc_rssi)
		if (not( homesaw_oui_1 ==11 and homesaw_oui_2 ==11 and  homesaw_oui_3 ==11 )):
			print homesaw_oui_1, homesaw_oui_2,  homesaw_oui_3 
			print "homesaw oui are corrupted " 
			for i in range(0,58):
                                print ord(frame[i]) ," ",
                                print "homesaw namespace= " ,homesaw_namespace 
			return (0,frame_elem,monitor_elem)				
		if homesaw_namespace != 1:
			print "homesaw namespace must be 1, but it is " ,homesaw_namespace,
                        print "phyerr is encoded in this byte "
	elif radiotap_len == 42:
		tsf=0
		radiotap_rate =0
                bandwidth= -1
                gi_length=-1
                mcs=-1
                actual_rate=-1
		#print "in TXPATH"
		if present_flag & 1<<ieee80211.IEEE80211_RADIOTAP_TSFT :
			tsf=list(struct.unpack('<Q',frame[offset:offset+8]))[0]
			offset +=8
		if present_flag & 1<<ieee80211.IEEE80211_RADIOTAP_RATE :
			radiotap_rate=list(struct.unpack('<H',frame[offset:offset+2]))[0] #
                        if radiotap_rate >= 0x80 and radiotap_rate <=0x8f :
                                actual_rate = radiotap_rate & 0x7f
			else:
                                actual_rate =(radiotap_rate*1.0 /2)
			offset +=2                 
		if present_flag & 1<<ieee80211.IEEE80211_RADIOTAP_TX_FLAGS :
			radiotap_tx_flags=list(struct.unpack('<H',frame[offset:offset+2]))[0]
                        rad_txflags_elem=[]
			if radiotap_tx_flags & flags.IEEE80211_RADIOTAP_F_TX_RTS:
				print " TX RTS SHIIIIT "                                
                                rad_txflags_elem.append(1)
                        else :
                                rad_txflags_elem.append(0)

			if radiotap_tx_flags & flags.IEEE80211_RADIOTAP_F_TX_RTS:
				print "TX CTS shhiiiit "
                                rad_txflags_elem.append(1)
                        else :
                                rad_txflags_elem.append(0)

			if radiotap_tx_flags & flags.IEEE80211_RADIOTAP_F_TX_AGG:
                                rad_txflags_elem.append(1)
                        else :
                                rad_txflags_elem.append(0)
                        frame_elem[tsf].append(rad_txflags_elem)
			offset +=2
		if present_flag & 1<<ieee80211.IEEE80211_RADIOTAP_DATA_RETRIES :
			radiotap_data_retries=list(struct.unpack('B',frame[offset]))[0]
			#print "Data retries =",radiotap_data_retries 
			offset +=1
                        frame_elem[tsf].append(radiotap_data_retries)
		if present_flag & 1<<ieee80211.IEEE80211_RADIOTAP_MCS :
			mcs_known=list(struct.unpack('B',frame[offset]))[0]
			offset += 1 
			mcs_flags=list(struct.unpack('B',frame[offset]))[0]
			offset += 1 
			mcs=list(struct.unpack('B',frame[offset]))[0]
			offset += 1 
			can_calculate_rate = 1 
			if (mcs_known & mcs_rate.IEEE80211_RADIOTAP_MCS_HAVE_BW) :
                           if ((mcs_flags & mcs_rate.IEEE80211_RADIOTAP_MCS_BW_MASK) \
                                       == mcs_rate.IEEE80211_RADIOTAP_MCS_BW_40):
				   bandwidth = 1
			   else :
				   bandwidth = 0
			else :
				bandwidth = 0;
				can_calculate_rate =0

			if (mcs_known & mcs_rate.IEEE80211_RADIOTAP_MCS_HAVE_GI) :
				if (mcs_flags & mcs_rate.IEEE80211_RADIOTAP_MCS_SGI) :
					gi_length = 1
				else :
					gi_length = 0
			else :
				gi_length = 0
				can_calculate_rate = 0

			if (mcs_known & mcs_rate.IEEE80211_RADIOTAP_MCS_HAVE_MCS) :
				pass  # Wireshark has nothing 
                        else :
                                can_calculate_rate = 0 
                        if (can_calculate_rate and mcs <= mcs_rate.MAX_MCS_INDEX \
                                    and ht_rates[mcs][bandwidth][gi_length] != 0.0) :
                                if (radiotap_rate ==0) :
                                        actual_rate= ht_rates[mcs][bandwidth][gi_length]
                                else :
                                        print "should not be reaching here " 
                                        sys.exit(1)
                        else :
                                print "802.11 rate not supported,add neg rate"
                                        
                       # print "Data Rate in tx :",  ht_rates[mcs][bandwidth][gi_length]

                frame_elem[tsf].append(actual_rate)
		if present_flag & 1<<ieee80211.IEEE80211_RADIOTAP_TOTAL_TIME :
			radiotap_tx_total_time=list(struct.unpack('<I',frame[offset:offset+4]))[0]
			frame_elem[tsf].append(radiotap_tx_total_time)
			offset += 4
		if present_flag & 1<<ieee80211.IEEE80211_RADIOTAP_CONTENTION_TIME :
			radiotap_rx_contention_time=list(struct.unpack('<I',frame[offset:offset+4]))[0]
			frame_elem[tsf].append(radiotap_rx_contention_time)
			#print " contention time", radiotap_rx_contention_time
			offset += 4
		if present_flag & 1<<ieee80211.IEEE80211_RADIOTAP_RATES_TRIED : #10 max			
			rates_tried =frame[offset:offset+10]
                        rad_rate_retries=[]
                        if ord(rates_tried[1])>1 :
                                rad_rate_retries.append([ht_rates[ord(rates_tried[0])][bandwidth][gi_length],ord(rates_tried[1])-1])
			for r_i in range (2,10,2):
                                if ord(rates_tried[r_i])>0 :
                                        try:
                                                rad_rate_retries.append([ht_rates[ord(rates_tried[r_i])][bandwidth][gi_length],ord(rates_tried[r_i+1])])
                                        except:
                                                print "indices are ",rates_tried[r_i],bandwidth,gi_length
			offset +=10
                        #rint "final rate retries array" ,rad_rate_retries
                        #f len(rad_rate_retries):
                        #       for i in range(0,10):
                        #               print ord( rates_tried[i]),
                        frame_elem[tsf].append(rad_rate_retries)
		#print "Last elem=8 :", struct.unpack('B',frame[offset]) # last element location=39
		if present_flag & 1<<ieee80211.IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE :
			pass
		if present_flag & 1<<ieee80211.IEEE80211_RADIOTAP_VENDOR_NAMESPACE :
			pass
		if present_flag & 1<<ieee80211.IEEE80211_RADIOTAP_EXT :
			pass			

        return (1,frame_elem,monitor_elem)
        



def parse_mgmt_fc(frame_control):
        def FC_SUBTYPE(fc) :
                return (((fc) >> 4) & 0xF)

	if FC_SUBTYPE(frame_control) ==   ST_BEACON :
                return 1 
	elif FC_SUBTYPE(frame_control) == ST_ASSOC_REQUEST :
                return 2
	elif FC_SUBTYPE(frame_control) == ST_ASSOC_RESPONSE :
                return 3
	elif FC_SUBTYPE(frame_control) == ST_REASSOC_REQUEST :
                return 4 
	elif FC_SUBTYPE(frame_control) == ST_REASSOC_RESPONSE :
                return 5
	elif FC_SUBTYPE(frame_control) == ST_PROBE_REQUEST :
                return 6 
	elif FC_SUBTYPE(frame_control) == ST_PROBE_RESPONSE :
                return 7
	elif FC_SUBTYPE(frame_control) == ST_DISASSOC :
                return 8 
	elif FC_SUBTYPE(frame_control) == ST_ATIM :
                return 9 
	elif FC_SUBTYPE(frame_control) == ST_AUTH :
                return 10
	elif FC_SUBTYPE(frame_control) == ST_DEAUTH :
                return 11
	elif FC_SUBTYPE(frame_control) == ST_ACTION :
                return 12



def parse_data_fc(fc,radiotap_len,frame_elem):
	tsf= 0
	for key in frame_elem.keys():
                tsf=key
	def FC_TO_DS(fc) :
		return ((fc) & 0x0100)
	def FC_FROM_DS(fc) :
		return ((fc) & 0x0200)
        
        if ( not(FC_TO_DS(fc)) and not(FC_FROM_DS(fc))) :#	ADDR2 , 1 There shouldn't be such frames
		#print "part 1 data" src, dest
		print "1" ,frame_elem[tsf][11],frame_elem[tsf][12]
		#print "frame is ", frame_elem
                return 1
        elif ( not(FC_TO_DS(fc)) and  FC_FROM_DS(fc)) :
                #		ADDR3,2
                # print "part 2 data"
                if radiotap_len ==42 :
                        # 7th is the dest mac address ; i.e the client connected
                        a=frame_elem[tsf][7].split(':')                   
                        if  not (a[0] =='ff' and a[1] =='ff' and a[2] =='ff' ) :
                                if not (a[0] =='33' and a[1] =='33'  ) :                                 
                                        if not (a[0] =='01' and a[1] =='00' and a[2] =='5e' ) :                        
                                                global Station
                                                Station.add(frame_elem[tsf][7])
                        global bismark_status
                        if bismark_status == 0:
                                Bismark_mac=frame_elem[tsf][6]
                                bismark_status =1
                return 2                
                
        elif (FC_TO_DS(fc) and not(FC_FROM_DS(fc))) :                
                #  part 3 data : index of mac header ADDR 2,3
                #print "last three bytes of fucked up mac address"
                #print frame_elem[tsf][11][3], frame_elem[tsf][11][4],frame_elem[tsf][11][5]
                #print "bad fcs ", frame_elem[tsf][0], frame_elem[tsf][2]
                #for key in Station.keys():
                   #     if key == frame_elem[11]:
                    #            Station[frame_elem[tsf][11]].append(tsf)                                
                #print "part 3 data" 
                #try : src, dest 
                #print "3",frame_elem[tsf][11], frame_elem[tsf][12] 
                #except :
                 #       pass
                return 3
        elif (FC_TO_DS(fc) and (FC_FROM_DS(fc))) :#		ADDR4,3	There shouldn't be such frames	
		#print " fucking hte last shit on the code planet 4"
		#print frame_elem src,dest
		#print "src is " ,frame_elem[tsf][11]
		#print "dest is " ,frame_elem[tsf][12]
                return 4 

        return -1 

def parse_ctrl_fc(frame_control):
	def FC_SUBTYPE(fc) :
		return (((fc) >> 4) & 0xF)

	if FC_SUBTYPE(frame_control) ==  CTRL_BA  :
                return 1
	elif FC_SUBTYPE(frame_control) == CTRL_BA :
                return 2
	elif FC_SUBTYPE(frame_control) == CTRL_PS_POLL :
                return 3
	elif FC_SUBTYPE(frame_control) == CTRL_RTS :
                return 4
	elif FC_SUBTYPE(frame_control) == CTRL_CTS :
                return 5
	elif FC_SUBTYPE(frame_control) == CTRL_ACK :
                return 6
	elif FC_SUBTYPE(frame_control) == CTRL_CF_END :
                return 7
	elif FC_SUBTYPE(frame_control) == CTRL_END_ACK :
                return 8


def parse_frame_control(frame_control,radiotap_len,frame_elem) :	
	tsf= 0
	for key in frame_elem.keys():
                tsf=key
        def FC_MORE_FLAG(fc):
                return ((fc) & 0x0400)
        def FC_RETRY(fc) :       
                return ((fc) & 0x0800)
        def FC_POWER_MGMT(fc):
                return ((fc) & 0x1000)
        def FC_MORE_DATA(fc):
                return ((fc) & 0x2000)
        def FC_WEP(fc) :
                return ((fc) & 0x4000)
        def FC_ORDER(fc):
                return ((fc) & 0x8000)
        def FC_TYPE(fc) :
                return (((fc) >> 2) & 0x3)
        def FC_SUBTYPE(fc) :
                return (((fc) >> 4) & 0xF)
        type_list=[]
        frame_type,frame_subtype=0,0
	if FC_TYPE(frame_control)==T_DATA:
		#print "Data"
		frame_subtype=parse_data_fc(frame_control,radiotap_len,frame_elem)
                frame_type=1
	if FC_TYPE(frame_control)==T_MGMT:
		#print "Mgmt "
		frame_subtype=parse_mgmt_fc(frame_control)
                frame_type=2
	if FC_TYPE(frame_control)==T_CTRL :
		#print "ctrl " 
		frame_subtype=parse_ctrl_fc(frame_control)
                frame_type=3
        mac_flags=[]
	if FC_WEP(frame_control):
                mac_flags.append(1)
        else:
                mac_flags.append(0)
	if FC_RETRY(frame_control):
                mac_flags.append(1)
        else:
                mac_flags.append(0)
	if FC_ORDER(frame_control):
                mac_flags.append(1)
        else:
                mac_flags.append(0)
	if FC_POWER_MGMT(frame_control):
                mac_flags.append(1)
        else:
                mac_flags.append(0)
	if FC_MORE_FLAG(frame_control):
                mac_flags.append(1)
        else:
                mac_flags.append(0)
	if FC_MORE_DATA(frame_control):
                mac_flags.append(1)
        else:
                mac_flags.append(0)
        frame_elem[tsf].append(mac_flags)
        frame_elem[tsf].append([frame_type,frame_subtype])

def parse_data_frame(frame,radiotap_len,frame_elem):
	tsf= 0
	for key in frame_elem:
		tsf=key
	offset = radiotap_len
	pkt_len =list(struct.unpack('>I',frame[offset:offset+4]))[0]-radiotap_len
	offset +=4        
	src_mac_address= frame[offset:offset+6]	
	offset +=6
	dest_mac_address= frame[offset:offset+6]
	offset +=6        
	src  = print_hex_mac(src_mac_address)
	dest = print_hex_mac(dest_mac_address)
	frame_elem[tsf].append(src)
	frame_elem[tsf].append(dest)
	frame_control= list(struct.unpack('>H',frame[offset:offset+2]))[0]
	offset +=2
	sequence_control_bytes = list(struct.unpack('>H',frame[offset:offset+2]))[0]
	frame_fragment_number=seqctl_frag_number(sequence_control_bytes)
	frame_sequence_number =seqctl_seq_number(sequence_control_bytes)
	offset +=2
	frame_elem[tsf].append(frame_sequence_number)
	frame_elem[tsf].append(frame_fragment_number)
	parse_frame_control(frame_control,radiotap_len,frame_elem)
	frame_elem[tsf].append(pkt_len)
        #print pkt_len, frame_sequence_number 

def parse_err_data_frame(frame,radiotap_len,frame_elem):
	tsf=0
	for key in frame_elem:
		tsf=key
	offset = radiotap_len
	pkt_len =list(struct.unpack('>I',frame[offset:offset+4]))[0]-radiotap_len
	offset +=4
	src_mac_address= frame[offset:offset+6]
	offset +=6	
	if int(list(struct.unpack('B',src_mac_address[3]))[0])!=0 &  \
                    int(list(struct.unpack('B',src_mac_address[4]))[0]) != 0 \
                    & int(list(struct.unpack('B',src_mac_address[5]))[0]):
		sys.exit(1)
	dest_mac_address= frame[offset:offset+6]
	offset +=6

	src=print_hex_mac(src_mac_address)	
	dest=print_hex_mac(dest_mac_address)
	
	if int(list(struct.unpack('B',dest_mac_address[3]))[0]) !=0 &  \
                    int(list(struct.unpack('B',dest_mac_address[4]))[0]) != 0 & \
                    int(list(struct.unpack('B',dest_mac_address[5]))[0]) !=0 :
		print "this should not happen with all the frames btw ..."
		sys.exit(1) 
	frame_elem[tsf].append(src)
	frame_elem[tsf].append(dest)

	frame_control= list(struct.unpack('>H',frame[offset:offset+2]))[0]
	offset +=2	
	sequence_control_bytes = list(struct.unpack('>H',frame[offset:offset+2]))[0]
	frame_fragment_number=seqctl_frag_number(sequence_control_bytes)
	frame_sequence_number =seqctl_seq_number(sequence_control_bytes )
	frame_elem[tsf].append(frame_sequence_number)
	frame_elem[tsf].append(frame_fragment_number)
	parse_frame_control(frame_control,radiotap_len,frame_elem)
	frame_elem[tsf].append(pkt_len)

def parse_mgmt_beacon_frame(frame,radiotap_len,frame_elem):
	tsf=0
	for key in frame_elem:
		tsf=key
	def CAPABILITY_ESS(cap)  :
		((cap) & 0x0001)

	def CAPABILITY_PRIVACY(cap):
		 ((cap) & 0x0010)

	offset = radiotap_len
	pkt_len =list(struct.unpack('>I',frame[offset:offset+4]))[0]-radiotap_len
	offset +=4
	src_mac_address= frame[offset:offset+6]	
	src=print_hex_mac(src_mac_address)
	offset +=6
	frame_control= list(struct.unpack('>H',frame[offset:offset+2]))[0]
	offset +=2	
	sequence_control_bytes = list(struct.unpack('>H',frame[offset:offset+2]))[0]
	frame_elem[tsf].append(src)
	frame_fragment_number=seqctl_frag_number(sequence_control_bytes)
	frame_sequence_number =seqctl_seq_number(sequence_control_bytes )
	offset +=2
	ht_support=list(struct.unpack('B',frame[offset]))[0]
	offset +=1 
	cap_info = list(struct.unpack('B',frame[offset]))[0]
	offset +=1
	cap_ess=-1
	private=-1
	if CAPABILITY_ESS(cap_info):
                cap_ess=1 #print "ESS"
	else :
                cap_ess=0 #print "IBSS" 

	if CAPABILITY_PRIVACY(cap_info):
                private=1 # print "PRIVACY"
	else:
                private=0 # print "NOT PRIVATE"


	frame_elem[tsf].append(frame_sequence_number)
	frame_elem[tsf].append(frame_fragment_number)
	frame_elem[tsf].append(ht_support)
	frame_elem[tsf].append(cap_ess)
	frame_elem[tsf].append(private)
	frame_elem[tsf].append(pkt_len)
	parse_frame_control(frame_control,radiotap_len,frame_elem)


def parse_mgmt_common_frame(frame,radiotap_len,frame_elem):
	tsf=0
	for key in frame_elem:
		tsf=key
	offset = radiotap_len
	pkt_len =list(struct.unpack('>I',frame[offset:offset+4]))[0]-radiotap_len 
	offset +=4
	src_mac_address= frame[offset:offset+6]	
	src=print_hex_mac(src_mac_address)
	offset +=6
	frame_control= list(struct.unpack('>H',frame[offset:offset+2]))[0]
	offset +=2	
	sequence_control_bytes = list(struct.unpack('>H',frame[offset:offset+2]))[0]
	frame_elem[tsf].append(src)
	frame_fragment_number=seqctl_frag_number(sequence_control_bytes)
	frame_sequence_number =seqctl_seq_number(sequence_control_bytes )
	offset +=2 
	frame_elem[tsf].append(frame_sequence_number)
	frame_elem[tsf].append(frame_fragment_number)
	frame_elem[tsf].append(pkt_len)
	parse_frame_control(frame_control,radiotap_len,frame_elem)


def parse_mgmt_err_frame(frame,radiotap_len,frame_elem):
	tsf=0
	for key in frame_elem:
		tsf=key
	offset = radiotap_len
	pkt_len =list(struct.unpack('>I',frame[offset:offset+4]))[0]-radiotap_len
	offset +=4
	src_mac_address= frame[offset:offset+6]	
	src=print_hex_mac(src_mac_address )
	offset +=6
	frame_control= list(struct.unpack('>H',frame[offset:offset+2]))[0]
	offset +=2	
	sequence_control_bytes = list(struct.unpack('>H',frame[offset:offset+2]))[0]
	frame_fragment_number=seqctl_frag_number(sequence_control_bytes)
	frame_sequence_number =seqctl_seq_number(sequence_control_bytes )
	offset +=2 
	frame_elem[tsf].append(frame_sequence_number)
	frame_elem[tsf].append(frame_fragment_number)
	frame_elem[tsf].append(pkt_len)
	parse_frame_control(frame_control,radiotap_len,frame_elem)


def parse_ctrl_frame(frame,radiotap_len,frame_elem):
	tsf=0
	for key in frame_elem:
		tsf=key
	offset = radiotap_len
	pkt_len =list(struct.unpack('>I',frame[offset:offset+4]))[0]-radiotap_len
	offset +=4
	src_mac_address= frame[offset:offset+6]	 
	src= print_hex_mac(src_mac_address)
	offset +=6
	frame_control= list(struct.unpack('>H',frame[offset:offset+2]))[0]
	parse_frame_control(frame_control,radiotap_len,frame_elem)
	offset +=2	
	frame_elem[tsf].append(src)
	frame_elem[tsf].append(pkt_len)

def parse_ctrl_err_frame(frame,radiotap_len,frame_elem):
        tsf=0
	for key in frame_elem:
		tsf=key
	offset = radiotap_len
	pkt_len =list(struct.unpack('>I',frame[offset:offset+4]))[0]-radiotap_len
	offset +=4
	src_mac_address= frame[offset:offset+6]		      
	src=print_hex_mac(src_mac_address)
	offset +=6
	frame_control= list(struct.unpack('>H',frame[offset:offset+2]))[0]
	parse_frame_control(frame_control,radiotap_len,frame_elem)
	offset +=2	
	frame_elem[tsf].append(src)
	frame_elem[tsf].append(pkt_len)

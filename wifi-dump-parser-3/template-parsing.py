#Author : Abhinav Narain
#Date : May 6, 2013
#Purpose : To read the binary files with data from BISmark deployment in homes
#          Gives the frames: transmitted and received by the Access point in human readable form 
#          To test the output of the files with the dumps on clients; and understanding the trace 
#
# Contention delay
# 


import os,sys,re
import gzip
import struct 

from  header import *
from mac_parser import * 
from stats import *
from rate import *

try:
    import cPickle as pickle
except ImportError:
    import pickle

missing_files=[]
tx_time_data_series=[]
tx_time_mgmt_series=[]
tx_time_ctrl_series=[]
rx_time_data_series=[]
rx_time_mgmt_series=[]
rx_time_ctrl_series=[]



if len(sys.argv) !=5 :
	print len(sys.argv)
	print "Usage : python station-process.py data/<data.gz> mgmt/<mgmt.gz> ctrl/<ctrl.gz> <outputfile> "
	sys.exit(1)
#compare regular expression for filenameif argv[1] for the lexicographic /time ordering so that we load them in order in the first place
data_f_dir=sys.argv[1]
mgmt_f_dir=sys.argv[2]
ctrl_f_dir=sys.argv[3]
output_type=sys.argv[4]

data_fs=os.listdir(data_f_dir)
ctrl_fs=os.listdir(ctrl_f_dir)

data_file_header_byte_count=0
ctrl_file_header_byte_count=0
mgmt_file_header_byte_count=0
file_counter=0
file_timestamp=0
filename_list=[]
unix_time=set()
for data_f_n in data_fs :
    filename_list.append(data_f_n.split('-'))
    unix_time.add(int(data_f_n.split('-')[1]))
    if not (data_f_n.split('-')[2]=='d'):
        print "its not a data file ; skip "
        continue 

filename_list.sort(key=lambda x : int(x[3]))
filename_list.sort(key=lambda x : int(x[1]))

for data_f_name_list in filename_list : #data_fs :    
    data_f_name="-".join(data_f_name_list)
    data_f= gzip.open(data_f_dir+data_f_name,'rb')
    data_file_content=data_f.read()
    data_f.close()
    data_file_current_timestamp=0
    data_file_seq_n=0
    bismark_id_data_file=0
    start_64_timestamp_data_file=0
    for i in xrange(len(data_file_content )):
        if data_file_content[i]=='\n':
            bismark_data_file_header = str(data_file_content[0:i])
            ents= bismark_data_file_header.split(' ')
            bismark_id_data_file=ents[0]
            start_64_timestamp_data_file= int(ents[1])
            data_file_seq_no= int(ents[2])
            data_file_current_timestamp=int(ents[3])
            data_file_header_byte_count =i
            break

    data_contents=data_file_content.split('\n----\n')
    header_and_correct_data_frames = data_contents[0]
    err_data_frames = data_contents[1]
    correct_data_frames_missed=data_contents[2]
    err_data_frames_missed=data_contents[3]

    ctrl_f_name = data_f_name
    ctrl_f_name =re.sub("-d-","-c-",ctrl_f_name)

    try :
        ctrl_f= gzip.open(ctrl_f_dir+ctrl_f_name,'rb')	
        ctrl_file_content=ctrl_f.read()
    except :
        print  "CTRL file not present ", ctrl_f_name 
        missing_files.append([ctrl_f_name,data_file_current_timestamp])
        continue 
    ctrl_f.close()
    
    
    mgmt_f_name = data_f_name
    mgmt_f_name = re.sub("-d-","-m-",mgmt_f_name)
    try : 
        mgmt_f= gzip.open(mgmt_f_dir+mgmt_f_name,'rb')
        mgmt_file_content=mgmt_f.read()
    except :
        print "MGMT file not present ",mgmt_f_name 
        missing_files.append([mgmt_f_name,data_file_current_timestamp])
        continue 

    mgmt_f.close()

    mgmt_file_current_timestamp=0
    mgmt_file_seq_no=0
    bismark_id_mgmt_file=0
    start_64_timestamp_mgmt_file=0
	
    ctrl_file_current_timestamp=0
    ctrl_file_seq_no=0
    bismark_id_ctrl_file=0
    start_64_timestamp_ctrl_file=0

    for i in xrange(len(mgmt_file_content )):
        if mgmt_file_content[i]=='\n':
            bismark_mgmt_file_header = str(mgmt_file_content[0:i])
            ents= bismark_mgmt_file_header.split(' ')
            bismark_id_mgmt_file=ents[0]
            start_64_timestamp_mgmt_file=int(ents[1])
            mgmt_file_seq_no= int(ents[2])
            mgmt_file_current_timestamp= int(ents[3])
            mgmt_file_header_byte_count =i
            break
    mgmt_contents=mgmt_file_content.split('\n----\n')
    header_and_beacon_mgmt_frames = mgmt_contents[0] 
    common_mgmt_frames = mgmt_contents[1]
    err_mgmt_frames=mgmt_contents[2]
    beacon_mgmt_frames_missed=mgmt_contents[3]
    common_mgmt_frames_missed=mgmt_contents[4]
    err_mgmt_frames_missed=mgmt_contents[5]

    for i in xrange(len(ctrl_file_content )):
        if ctrl_file_content[i]=='\n':
            bismark_ctrl_file_header = str(ctrl_file_content[0:i])
            ents= bismark_ctrl_file_header.split(' ')
            bismark_id_ctrl_file= ents[0]
            start_64_timestamp_ctrl_file= int(ents[1])
            ctrl_file_seq_no= int(ents[2])
            ctrl_file_current_timestamp=int(ents[3])
            ctrl_file_header_byte_count =i
            break
    ctrl_contents=ctrl_file_content.split('\n----\n')
    header_and_correct_ctrl_frames = ctrl_contents[0]
    err_ctrl_frames = ctrl_contents[1]
    correct_ctrl_frames_missed=ctrl_contents[2]
    err_ctrl_frames_missed=ctrl_contents[3]
    #done with reading the binary blobs from file ; now check for timestamps are correct
    if (not (ctrl_file_current_timestamp == mgmt_file_current_timestamp == data_file_current_timestamp )) :
        print "timestamps don't match " 		
        sys.exit(1)
    else :
        file_timestamp=ctrl_file_current_timestamp	
    if (not (ctrl_file_seq_no == mgmt_file_seq_no == data_file_seq_no)):
        print "sequence number don't match "
        sys.exit(1)

	
    if (len(ctrl_contents) != 4 or  len(data_contents) != 4 or len(mgmt_contents) !=6) :
        print "for ctrl " ,len (ctrl_contents) ,"for data", len(data_contents), "for mgmt", len(mgmt_contents) 
        print "file is malformed or the order of input folders is wrong "
        continue 
    '''
    if  (data_file_current_timestamp < t1-1):
        continue 


    if (data_file_current_timestamp >t2-1):
        break 
    print t1, data_file_current_timestamp, t2
   ''' 
        #The following code block parses the data file 	
	#print "----------done with missed .. now with actual data "
    correct_data_frames=header_and_correct_data_frames[data_file_header_byte_count+1:]
    data_index=0
    for idx in xrange(0,len(correct_data_frames)-DATA_STRUCT_SIZE ,DATA_STRUCT_SIZE ):	
        global file_timestamp
        frame=correct_data_frames[data_index:data_index+DATA_STRUCT_SIZE]
        offset,success,tsf= 8,-1,0
        header = frame[:offset]
        frame_elem=defaultdict(list)
        monitor_elem=defaultdict(list)        
        (version,pad,radiotap_len,present_flag)=struct.unpack('<BBHI',header)
        (success,frame_elem,monitor_elem)=parse_radiotap(frame,radiotap_len,present_flag,offset,monitor_elem,frame_elem)  
        if success:
            for key in frame_elem.keys():
                tsf=key                                    
            parse_data_frame(frame,radiotap_len,frame_elem)
            temp=frame_elem[tsf]
            temp.insert(0,tsf)
            #print temp
            if radiotap_len == RADIOTAP_RX_LEN:
                rx_time_data_series.append(temp)                
            elif radiotap_len ==RADIOTAP_TX_LEN :
                tx_time_data_series.append(temp)
            else :
                print "impossible radiotap len detected ; Report CERN", radiotap_len 
            
        else:
            print "success denied; correct data frame"                    
        data_index=data_index+DATA_STRUCT_SIZE
        del frame_elem
        del monitor_elem

        '''
    data_index=0
    for idx in xrange(0,len(err_data_frames)-DATA_ERR_STRUCT_SIZE,DATA_ERR_STRUCT_SIZE ):	
        frame=err_data_frames[data_index:data_index+DATA_ERR_STRUCT_SIZE]
        offset,success,tsf= 8,-1,0
        header = frame[:offset]
        frame_elem=defaultdict(list)
        monitor_elem=defaultdict(list)
        (version,pad,radiotap_len,present_flag)=struct.unpack('<BBHI',header)
        (success,frame_elem,monitor_elem)=parse_radiotap(frame,radiotap_len,present_flag,offset,monitor_elem,frame_elem)
        if success:
            for key in frame_elem.keys():
                tsf=key
            parse_err_data_frame(frame,radiotap_len,frame_elem)
            temp=frame_elem[tsf]
            temp.insert(0,tsf)
            if radiotap_len == RADIOTAP_RX_LEN:                
                rx_time_data_series.append(temp)
            elif radiotap_len ==RADIOTAP_TX_LEN :
                tx_time_series.append(temp)
                print "wrong err data tx frame " 
            else :
                print "impossible radiotap len detected ; Report CERN" 
            
        else :
            print "success denied; incorrect data frame" 
                   
        data_index= data_index+DATA_ERR_STRUCT_SIZE
        del frame_elem
        del monitor_elem    
        '''

    #The following code block parses the mgmt files     
    beacon_mgmt_frames=header_and_beacon_mgmt_frames[mgmt_file_header_byte_count+1:]
    mgmt_index=0
    for idx in xrange(0,len(beacon_mgmt_frames)-MGMT_BEACON_STRUCT_SIZE ,MGMT_BEACON_STRUCT_SIZE ):
        global file_timestamp
        frame=beacon_mgmt_frames[mgmt_index:mgmt_index+MGMT_BEACON_STRUCT_SIZE]
        offset,success,tsf= 8,-1,0
        header = frame[:offset]
        frame_elem,monitor_elem=defaultdict(list),defaultdict(list)
        (version,pad,radiotap_len,present_flag)=struct.unpack('<BBHI',header)
        if not( radiotap_len ==RADIOTAP_RX_LEN or  radiotap_len == RADIOTAP_TX_LEN) :
            print "the radiotap header is not correct "
            sys.exit(1)
        (success,frame_elem,monitor_elem)=parse_radiotap(frame,radiotap_len,present_flag,offset,monitor_elem,frame_elem)
        if success :
            for key in frame_elem.keys():
                tsf=key
            temp=frame_elem[tsf]
            temp.insert(0,tsf)
            parse_mgmt_beacon_frame(frame,radiotap_len,frame_elem)
            if radiotap_len== RADIOTAP_TX_LEN :
                tx_time_mgmt_series.append(temp)
                print temp                
        else :
            print "beacon success denied"

        mgmt_index=mgmt_index+MGMT_BEACON_STRUCT_SIZE
        del frame_elem
        del monitor_elem

    mgmt_index=0
    for idx in xrange(0,len(common_mgmt_frames)-MGMT_COMMON_STRUCT_SIZE,MGMT_COMMON_STRUCT_SIZE ):
        global file_timestamp
        frame=common_mgmt_frames[mgmt_index:mgmt_index+MGMT_COMMON_STRUCT_SIZE]
        offset,success,tsf= 8,-1,0
        header = frame[:offset]
        frame_elem,monitor_elem=defaultdict(list),defaultdict(list)
        (version,pad,radiotap_len,present_flag)=struct.unpack('<BBHI',header)
        if not( radiotap_len ==RADIOTAP_RX_LEN or  radiotap_len == RADIOTAP_TX_LEN) :
            print "the radiotap header is not correct "
            sys.exit(1)
        (success,frame_elem,monitor_elem)=parse_radiotap(frame,radiotap_len,present_flag,offset,monitor_elem,frame_elem)
        if success==1 :
            for key in frame_elem.keys():
                tsf=key
            temp=frame_elem[tsf]
            temp.insert(0,tsf)
            parse_mgmt_common_frame(frame,radiotap_len,frame_elem)
            if radiotap_len== RADIOTAP_TX_LEN :
                tx_time_mgmt_series.append(temp)
        else :
            print "common mgmt success denied"

        mgmt_index= mgmt_index+MGMT_COMMON_STRUCT_SIZE
        del frame_elem
        del monitor_elem
        '''         
    mgmt_index=0
    for idx in xrange(0,len(err_mgmt_frames)-MGMT_ERR_STRUCT_SIZE,MGMT_ERR_STRUCT_SIZE ):
        global file_timestamp
        frame=err_mgmt_frames[mgmt_index:mgmt_index+MGMT_ERR_STRUCT_SIZE]
        offset,success,tsf= 8,-1,0
        header = frame[:offset]
        frame_elem,monitor_elem=defaultdict(list),defaultdict(list)
        (version,pad,radiotap_len,present_flag)=struct.unpack('<BBHI',header)
        if not( radiotap_len ==RADIOTAP_RX_LEN or  radiotap_len == RADIOTAP_TX_LEN) :
            print "the radiotap header is not correct "
            sys.exit(1)
        (success,frame_elem,monitor_elem)=parse_radiotap(frame,radiotap_len,present_flag,offset,monitor_elem,frame_elem)
        if success==1 :
            for key in frame_elem.keys():
                tsf=key
            temp=frame_elem[tsf]
            temp.insert(0,tsf)
            parse_mgmt_err_frame(frame,radiotap_len,frame_elem)                                                                                            
            if radiotap_len== RADIOTAP_TX_LEN :
                tx_time_mgmt_common_series.append(temp)
                print "err: mgmt tx frame" 
        else:
            print "success denied"
        mgmt_index= mgmt_index+MGMT_ERR_STRUCT_SIZE
        del frame_elem
        del monitor_elem
    '''    
    #print "----------done with missed .. now with actual ctrl data "        
    correct_ctrl_frames=header_and_correct_ctrl_frames[ctrl_file_header_byte_count+1:]
    ctrl_index=0
    for idx in xrange(0,len(correct_ctrl_frames)-CTRL_STRUCT_SIZE ,CTRL_STRUCT_SIZE ):			
        global file_timestamp
        frame=correct_ctrl_frames[ctrl_index:ctrl_index+CTRL_STRUCT_SIZE]
        offset,success,tsf= 8,-1,0
        header = frame[:offset]
        frame_elem, monitor_elem=defaultdict(list),defaultdict(list)
        (version,pad,radiotap_len,present_flag)=struct.unpack('<BBHI',header)
        if not( radiotap_len ==RADIOTAP_RX_LEN or radiotap_len == RADIOTAP_TX_LEN) :
            print "the radiotap header is not correct "		
            sys.exit(1)
        (success,frame_elem,monitor_elem)=parse_radiotap(frame,radiotap_len,present_flag,offset,monitor_elem,frame_elem)
        if success :
            for key in frame_elem.keys():
                tsf=key
            parse_ctrl_frame(frame,radiotap_len,frame_elem)
            temp=frame_elem[tsf]
            temp.insert(0,tsf)
            if radiotap_len ==RADIOTAP_TX_LEN :
                tx_time_ctrl_series.append(temp)
            elif radiotap_len ==RADIOTAP_RX_LEN :
                rx_time_ctrl_series.append(temp)
        else :
            print "ctrl success denied"
        
        ctrl_index=ctrl_index+CTRL_STRUCT_SIZE
        
        del frame_elem
        del monitor_elem

        '''
    ctrl_index=0
    for idx in xrange(0,len(err_ctrl_frames)-CTRL_ERR_STRUCT_SIZE,CTRL_ERR_STRUCT_SIZE):			
        global file_timestamp
        frame=err_ctrl_frames[ctrl_index:ctrl_index+CTRL_ERR_STRUCT_SIZE]
        offset,success,tsf= 8,-1,0
        header = frame[:offset]
        frame_elem,monitor_elem=defaultdict(list),defaultdict(list)
        (version,pad,radiotap_len,present_flag)=struct.unpack('<BBHI',header)
        if not( radiotap_len ==RADIOTAP_RX_LEN or  radiotap_len == RADIOTAP_TX_LEN) :	
            print "the radiotap header is not correct "		
            sys.exit(1)
        (success,frame_elem,monitor_elem)=parse_radiotap(frame,radiotap_len,present_flag,offset,monitor_elem,frame_elem)
        if success ==1:
            for key in frame_elem.keys():
                tsf=key
            parse_ctrl_err_frame(frame,radiotap_len,frame_elem)
            temp=frame_elem[tsf]
            temp.insert(0,tsf)
            if radiotap_len == RADIOTAP_RX_LEN:
                rx_time_ctrl_series.append(temp)
            elif radiotap_len ==RADIOTAP_TX_LEN :
                tx_time_ctrl_series.append(temp)
                print "wrong: ctrl frame " 
        else :
            print "success denied"
        ctrl_index= ctrl_index+CTRL_ERR_STRUCT_SIZE
        del frame_elem
        del monitor_elem
        '''
    file_counter +=1
    if file_counter %10 == 0:
        print file_counter


print "now processing the files to calculate time "

tx_time_data_series.sort(key=lambda x:x[0])
tx_time_ctrl_series.sort(key=lambda x:x[0])
tx_time_mgmt_series.sort(key=lambda x:x[0])

mgmt_zero_queue_tx=[]
mgmt_retx_count=[]

ctrl_zero_tx=[]
ctrl_retx_count=[]

Station_list=list(Station)
Station_tx_retx_count = defaultdict(list)

for i in range(0,len(tx_time_ctrl_series)):
    frame=tx_time_ctrl_series[i]
    c_frame_tx_flags_radiotap=frame[1]
    c_frame_retx=frame[2]
    c_frame_mpdu_queue_size=frame[5]
    c_frame_retx=frame[2]

    if c_frame_tx_flags_radiotap[0]==0 :
        ctrl_retx_count.append(c_frame_retx)

    if c_frame_mpdu_queue_size ==0 and c_frame_retx==0 :
        ctrl_zero_tx.append()
        
        
for i in range(0,len(tx_time_mgmt_series)):
    frame=tx_time_mgmt_series[i]
    c_frame_tx_flags_radiotap=frame[1]
    c_frame_retx=frame[2]
    c_frame_mpdu_queue_size=frame[5]
    c_frame_retx=frame[2]
    c_frame_total_time=frame[4]
    if c_frame_tx_flags_radiotap[0]==0 :
        ctrl_retx_count.append(c_frame_retx)

    if c_frame_mpdu_queue_size ==0 and c_frame_retx==0 :
        ctrl_zero_tx.append(c_frame_total_time)


print "in tx looping "
Station_tx_series=defaultdict(list)
for j in range(0,len(Station_list)):
    for i in range(0,len(tx_time_data_series)):
        frame = tx_time_data_series[i]
        if frame[11]==Station_list[j] : 
            width, half_gi, shortPreamble= 0,0,0 
            phy,kbps=frame[7],temp[0]*500
            prop_time=(frame[-1]*8.0 *1000000)/ (frame[3] *1000000) #frame[-1] is the size of frame in bytes                    
            temp= frame[10]
            abg_rix,pktlen= temp[0], frame[17]  
            airtime,curChan=-1,-23
            if abg_rix == -1 :
                n_rix=temp[-1][0]
                airtime=ath_pkt_duration(n_rix, pktlen, width, half_gi,shortPreamble)
            else :
                airtime= -1 #ath9k_hw_computetxtime(phy,kbps,pktlen,abg_rix,shortPreamble,curChan)

            Station_tx_series[frame[11]].append([frame[0],frame[1],frame[2],frame[3],frame[4],frame[5],frame[6],frame[8],frame[7],frame[9],frame[13],frame[14],frame[15],frame[16],frame[17],airtime,prop_time]) 
            # 0      ,1          ,2     ,3              ,4            ,5        ,6          ,7       ,8          ,9                ,10        ,11
            #time [0],txflags[1],retx[2],success_rate[3],total_time[4],Q len [5],A-Q len [6], Q-no[7],phy_type[8],retx_rate_list[9],seq no[13],fragment no[14],mac-layer-flags[15], frame-prop-type[16], framesize[17],prop time,temp 
# 12                  ,13                  ,14            ,16, 17
            
            
            
            
print"format:tsf, txflags, retx, successful bitrate, total time,Qlen,AMPDU-Q len,Q no, phy-type,retx rate list,seq no, frag no, mac-layer flags, frame prop type,frame size, frame-prop time"

for j in Station_tx_series.keys():
    #j is the station name  
    print "TX Station :", j 
    list_of_frames= Station_tx_series[j]
    for i in range(1,len(list_of_frames)):                
        frame=list_of_frames[i]
        ''' #used when looking for consecutive frames 
        previous_frame=list_of_frames[i-1]
        c_frame_departure=frame[0]
        p_frame_departure=previous_frame[0]
        c_frame_total_time=frame[4]
        p_frame_total_time=previous_frame[4]
        c_frame_mpdu_queue_size=frame[5]
        p_frame_mpdu_queue_size=previous_frame[5]
        c_frame_ampdu_queue_size=frame[6]
        p_frame_ampdu_queue_size=previous_frame[6]
        c_frame_queue_no=frame[7]
        p_frame_queue_no=previous_frame[7]
        c_frame_phy_flag=frame[8]
        p_frame_phy_flag=previous_frame[8]
        c_frame_seq_no=frame[10] 
        p_frame_seq_no=previous_frame[10]
        c_frame_frag_no=frame[11]
        p_frame_frag_no=previous_frame[11]        
        c_frame_size= frame[-1]
        p_frame_size= previous_frame[-1]        
        c_frame_tx_flags=frame[1]
        '''

        c_tx_flags_radiotap=frame[1]
        #if c_tx_flags_radiotap[0]==0 :
            
        c_frame_mpdu_queue_size= frame[5]
        c_frame_retx= frame[2]
        if c_frame_mpdu_queue_size ==0 and c_frame_retx==0 :            
            print frame




        # 0      ,1          ,2     ,3              ,4            ,5        ,6          ,7       ,8          ,9                ,10        ,11
#time [0],txflags[1],retx[2],success_rate[3],total_time[4],Q len [5],A-Q len [6], Q-no[7],phy_type[8],retx_rate_list[9],seq no[12],fragment no[13],mac-layer-flags[14], frame-prop-type[15], framesize[16],prop time 
# 12                  ,13                  ,14            ,16

    print "done with a station " 

print "in rx_looping "
Station_rx_series=defaultdict(list)
print "RECIVED FRAMES "
print "format : time,flags,freq, rx_flags,success rate, rx_queue_time,framesize , signal,RSSI, seq number,frag no,retry frame,prop time"

for i in range(0,len(rx_time_data_series)):
    frame = rx_time_data_series[i]
    for i in range(0,len(Station_list)):
        if frame[12]==Station_list[i] :
            prop_time=(frame[10]*8.0 *1000000)/ (frame[8] *1000000)
            Station_rx_series[frame[12]].append([frame[0],frame[1],frame[2],frame[7],frame[8],frame[9] ,frame[10],frame[4],frame[11],frame[14],frame[15],frame[16][1],prop_time]) 
            #print frame[12],frame[0],frame[1],frame[2],frame[7],frame[8],frame[9],frame[10],frame[4],frame[11],frame[14],frame[15],frame[16][1],prop_time
            #time [0],flags[1],freq[2], rx_flags[7],success rate [8], rx_queue_time[9],framesize [10], signal [4],RSSI [11], seq number [14], fragment no [15],retry frame [16][1],prop time 
'''
for j in Station_rx_series.keys():
    list_of_frames= Station_rx_series[j]
    print "RX Station ",j
    for i in range(1,len(list_of_frames)):
        frame= list_of_frames[i]
        print frame
'''

for i in range(0,len(missing_files)):
	print missing_files[i]
print "number of files that can't be located ", len(missing_files)

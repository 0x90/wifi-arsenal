#Author : Abhinav Narain
#Date : May 6, 2013
#Purpose : To read the binary files with data from BISmark deployment in homes
#          Gives the frames: transmitted and received by the Access point in human readable form 
#          To test the output of the files with the dumps on clients; and understanding the trace 
#  Percentage of frames which are RTS/CTS/ACK 
#
# 


import os,sys,re
import gzip
import struct 

from  header import *
from mac_parser import * 
from utils import *
from rate import *

try:
    import cPickle as pickle
except ImportError:
    import pickle

tx_time_ctrl_series=[]
rx_time_ctrl_series=[]



if len(sys.argv) !=3 :
	print len(sys.argv)
	print "Usage : python station-process.py ctrl/<ctrl.gz> <outputfile> "
	sys.exit(1)
#compare regular expression for filenameif argv[1] for the lexicographic /time ordering so that we load them in order in the first place
ctrl_f_dir=sys.argv[1]
output_type=sys.argv[2]

ctrl_fs=os.listdir(ctrl_f_dir)

ctrl_file_header_byte_count=0
file_counter=0
file_timestamp=0
filename_list=[]
unix_time=set()
for ctrl_f_n in ctrl_fs :
    filename_list.append(ctrl_f_n.split('-'))
    unix_time.add(int(ctrl_f_n.split('-')[1]))
    if not (ctrl_f_n.split('-')[2]=='c'):
        print "its not a data file ; skip "
        continue 

filename_list.sort(key=lambda x : int(x[3]))
filename_list.sort(key=lambda x : int(x[1]))

for ctrl_f_name_list in filename_list : #data_fs :    
    ctrl_f_name="-".join(ctrl_f_name_list)
    ctrl_f= gzip.open(ctrl_f_dir+ctrl_f_name,'rb')
    ctrl_file_content=ctrl_f.read()
    ctrl_f.close()
    ctrl_file_current_timestamp=0
    ctrl_file_seq_n=0
    bismark_id_ctrl_file=0
    start_64_timestamp_ctrl_file=0
    for i in xrange(len(ctrl_file_content )):
        if ctrl_file_content[i]=='\n':
            bismark_ctrl_file_header = str(ctrl_file_content[0:i])
            ents= bismark_ctrl_file_header.split(' ')
            bismark_id_ctrl_file=ents[0]
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

    ctrl_f= gzip.open(ctrl_f_dir+ctrl_f_name,'rb')	
    ctrl_file_content=ctrl_f.read()
    ctrl_f.close()
	
    ctrl_file_current_timestamp=0
    ctrl_file_seq_no=0
    bismark_id_ctrl_file=0
    start_64_timestamp_ctrl_file=0

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
    file_timestamp=ctrl_file_current_timestamp	
    if (len(ctrl_contents) != 4 ) :
        print "file is malformed or the order of input folders is wrong "
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
            print "ctrl: parsing success denied"
        ctrl_index=ctrl_index+CTRL_STRUCT_SIZE
        del frame_elem
        del monitor_elem

    file_counter +=1
    if file_counter %10 == 0:
        print file_counter

if __name__ =='__main__':
    print "now processing the files to calculate time "
    tx_time_ctrl_series.sort(key=lambda x:x[0])
    rx_time_ctrl_series.sort(key=lambda x:x[0])
    print "number of tx frames ",len(tx_time_ctrl_series)
    print "number of rx frames ",len(rx_time_ctrl_series)
#print"format:tsf, txflags, retx, successful bitrate, total time,Qlen,AMPDU-Q len,Q no, phy-type,retx rate list,seq no, frag no, mac-layer flags, frame prop type,frame size, frame-prop time"
#time [0],txflags[1],retx[2],success_rate[3],total_time[4],Q len [5],A-Q len [6], Q-no[7],phy_type[8],retx_rate_list[9],seq no[12],fragment no[13],mac-layer-flags[14], frame-prop-type[15], framesize[16],prop time 
# 12                  ,13                  ,14            ,16
    rts_count=0
    cts_count=0
    ack_count=0
    print "in rx_looping "
    print "format : time,flags,freq, rx_flags,success rate, rx_queue_time,framesize , signal,RSSI, seq number,frag no,retry frame,prop time"
    for i in range(0,len(rx_time_ctrl_series)):
        frame = rx_time_ctrl_series[i]
        if (frame[13][0] ==3 and frame[13][1]==5):
            cts_count=cts_count+1
        if (frame[13][0] ==3 and frame[13][1]==4):
            rts_count=rts_count+1
        if (frame[13][0] ==3 and frame[13][1]==6):	
            ack_count=ack_count+1

    #print frame[12],frame[0],frame[1],frame[2],frame[7],frame[8],frame[9],frame[10],frame[4],frame[11],frame[14],frame[15],frame[16][1],prop_time
    #time [0],flags[1],freq[2], rx_flags[7],success rate [8], rx_queue_time[9],framesize [10], signal [4],RSSI [11], seq number [14], fragment no [15],retry frame [16][1],prop time 

    print "Ack count ", ack_count 
    print "RTS count ", rts_count 
    print "CTS count ", cts_count 
    print "RTS*100/RTS+CTS", ((rts_count) *100.0)/(rts_count+cts_count)

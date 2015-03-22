#Author : Abhinav Narain
#Date : Aug 26, 2013
#Purpose : To read the binary files with data from BISmark deployment in homes
#          Gives the frames: transmitted and received by the Access point in human readable form 
#          To test the output of the files with the dumps on clients; and understanding the trace 
# Gives a dictionary of Contention delay per Access Class at Access Point (not classified Contention delays also) 
# Gives the router ID with the rates and the number 
# of frames which were transmitted and retransmitted 
# at that rate
#
import os,sys,re
import gzip
import struct 
from collections import defaultdict

from  header import *
from mac_parser import * 
from utils import *
from rate import * 


try:
    import cPickle as pickle
except ImportError:
    import pickle

tx_time_data_series=[]
retransmission_count_table= {65.0 :0, 58.5:0} #defaultdict(list)
frame_count_table={65.0 :0, 58.5:0} #defaultdict(list)
contention_time=[]
contention_time_per_access_class=defaultdict(list)
def file_reader(t1,t2,data_fs):
    global damaged_frames
    file_count=0
    for data_f_n in data_fs :
        filename_list.append(data_f_n.split('-'))
        if not (data_f_n.split('-')[2]=='d'):
            print "its not a data file ; skip "
            continue 

    filename_list.sort(key=lambda x : int(x[3]))
    filename_list.sort(key=lambda x : int(x[1]))
    tt=0
    for data_f_name_list in filename_list : #data_fs :    
        file_count=file_count+1
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

    #done with reading the binary blobs from file ; now check for timestamps are correct
        '''
        if  (data_file_current_timestamp < t1-1):
            continue 
        if (data_file_current_timestamp >t2+1):
            break 
        '''
        correct_data_frames=header_and_correct_data_frames[data_file_header_byte_count+1:]
        data_index=0
        for idx in xrange(0,len(correct_data_frames)-DATA_STRUCT_SIZE ,DATA_STRUCT_SIZE ):	
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
                    if radiotap_len ==RADIOTAP_TX_LEN :
                        tx_time_data_series.append(temp)
                    elif radiotap_len==RADIOTAP_RX_LEN :
                        pass 
                    else:
                        print "success denied; incorrect data frame"
                        damaged_frames +=1
            data_index=data_index+DATA_STRUCT_SIZE
            del frame_elem
            del monitor_elem

        if file_count %10 == 0:
            print file_count


def contention_delay():
    tx_time_data_series.sort(key=lambda x:x[0])    
    Station_list=list(Station)
    Station_tx_retx_count = defaultdict(list)
    frame_count=0
    for i in range(0,len(tx_time_data_series)):
        frame = tx_time_data_series[i]
        mpdu_q_size=frame[5]
        ampdu_q_size=frame[5]
        retx=frame[2]
        tsf=frame[0]
        total_time=-1
        rate=frame[3]
        if retx >=0:
            total_time=frame[4]
            frame_count +=1
        if retx ==0:
            if frame_count_table.has_key(rate)==1:
                temp=frame_count_table[rate]
                temp =temp+1                    
                frame_count_table[rate] =temp
            else :
                frame_count_table[rate]=1        
        if retx>0 :
            if retransmission_count_table.has_key(rate)==1:
                temp=retransmission_count_table[rate]
                temp =temp+retx                    
                retransmission_count_table[rate] =temp
            else :
                retransmission_count_table[rate]=retx			
        if mpdu_q_size ==0 and retx==0 :
            if total_time==-1:
                print "error: ",total_time
            contention_time.append([total_time])
    # 0      ,1          ,2     ,3              ,4            ,5        ,6          ,7       ,8          ,9                ,10        ,11
    #time [0],txflags[1],retx[2],success_rate[3],total_time[4],Q len [5],A-Q len [6], Q-no[7],phy_type[8],retx_rate_list[9],seq no[13],fragment no[14],mac-layer-flags[15], farme-prop-type[16], framesize[17],
# 12                  ,13                  ,14

    print "frame_count", frame_count 
    print "damaged_frames",damaged_frames
    print "retx table " , len(retransmission_count_table)
    print "frame count", len(frame_count_table)
    pickle_object= []
    pickle_object.append(router_id)
    pickle_object.append(retransmission_count_table)
    pickle_object.append(frame_count_table)
    pickle_object.append(contention_time)
    f_d= output_file+'.pickle'
    output_device = open(f_d, 'wb')
    pickle.dump(pickle_object,output_device)
    output_device.close()

def contention_delay_per_access_class():
    tx_time_data_series.sort(key=lambda x:x[0])    
    Station_list=list(Station)
    Station_tx_retx_count = defaultdict(list)
    for i in range(0,len(tx_time_data_series)):
        frame = tx_time_data_series[i]
        mpdu_q_size=frame[5]
        ampdu_q_size=frame[5]
        q_number=frame[8]
        retx=frame[2]
        tsf=frame[0]
        total_time=-1
        rate=frame[3]
        if retx >=0:
            total_time=frame[4]
        if mpdu_q_size ==0 and retx==0 :
            if total_time==-1:
                print "error: ",total_time
            contention_time_per_access_class[q_number].append([total_time])

    print "damaged_frames",damaged_frames
    pickle_object= []
    pickle_object.append(router_id)
    pickle_object.append(contention_time_per_access_class)
    f_d= output_file+'.pickle'
    output_device = open(f_d, 'wb')
    pickle.dump(pickle_object,output_device)
    output_device.close()

if __name__=='__main__':
    if len(sys.argv) !=6 :
	print len(sys.argv)
	print "Usage : python contention-data-frames.py data/<data.gz> <router_id> <t1> <t2> <outputfile> "
	sys.exit(1)
    data_f_dir=sys.argv[1]
    router_id= sys.argv[2]
    time1 =sys.argv[3]
    time2 =sys.argv[4]
    output_file=sys.argv[5]
    data_fs=os.listdir(data_f_dir)
    [t1,t2] = timeStamp_Conversion(time1,time2,router_id)
    data_file_header_byte_count=0
    filename_list=[]
    damaged_frames=0
    print "now processing the files to calculate time "
    file_reader(t1,t2,data_fs)
    #contention_delay()
    contention_delay_per_access_class()


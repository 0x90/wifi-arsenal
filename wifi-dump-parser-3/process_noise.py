#Author : Abhinav Narain
#Date : Sept-5, 2013
#Purpose : To read the binary files with data from BISmark deployment in homes
#          Gives the frames: transmitted and received by the Access point in human readable form 
#          To test the output of the files with the dumps on clients; and understanding the trace 
#
# Pickles the noise sample from each home  
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

missing_files=[]
Noise= []
unix_time=set()
def read_raw_file(t1,t2):
    data_fs=os.listdir(data_f_dir)
    file_counter,file_timestamp=0,0
    data_file_header_byte_count, ctrl_file_header_byte_count, mgmt_file_header_byte_count=0,0,0
    filename_list=[]
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
        
        if  (data_file_current_timestamp < t1-1):
            continue 


        if (data_file_current_timestamp >t2+1):
            break 
       
        #The following code block parses the data file 	
        #print "----------done with missed .. now with actual data "
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
                if len(monitor_elem)>0:
                    Noise.append(monitor_elem[tsf][0])
            else:
                print "success denied; correct data frame"                    
            data_index=data_index+DATA_STRUCT_SIZE
            del frame_elem
            del monitor_elem

            
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
                if len(monitor_elem)>0:
                    Noise.append(monitor_elem[tsf][0])
            else :
                print "success denied; incorrect data frame" 
                       
            data_index= data_index+DATA_ERR_STRUCT_SIZE
            del frame_elem
            del monitor_elem    
            

        #The following code block parses the mgmt files     
        beacon_mgmt_frames=header_and_beacon_mgmt_frames[mgmt_file_header_byte_count+1:]
        mgmt_index=0
        for idx in xrange(0,len(beacon_mgmt_frames)-MGMT_BEACON_STRUCT_SIZE ,MGMT_BEACON_STRUCT_SIZE ):
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
                if len(monitor_elem)>0:
                    Noise.append(monitor_elem[tsf][0])

            else :
                print "beacon success denied; beacon frame"

            mgmt_index=mgmt_index+MGMT_BEACON_STRUCT_SIZE
            del frame_elem
            del monitor_elem

        mgmt_index=0
        for idx in xrange(0,len(common_mgmt_frames)-MGMT_COMMON_STRUCT_SIZE,MGMT_COMMON_STRUCT_SIZE ):
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
                if len(monitor_elem)>0:
                    Noise.append(monitor_elem[tsf][0])
            else :
                print "common mgmt success denied; common frame"

            mgmt_index= mgmt_index+MGMT_COMMON_STRUCT_SIZE
            del frame_elem
            del monitor_elem
                
        mgmt_index=0
        for idx in xrange(0,len(err_mgmt_frames)-MGMT_ERR_STRUCT_SIZE,MGMT_ERR_STRUCT_SIZE ):
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
                if len(monitor_elem)>0:
                    Noise.append(monitor_elem[tsf][0])
            else:
                print "success denied; incorrect management frame"
            mgmt_index= mgmt_index+MGMT_ERR_STRUCT_SIZE
            del frame_elem
            del monitor_elem
        
        #print "----------done with missed .. now with actual ctrl data "        
        correct_ctrl_frames=header_and_correct_ctrl_frames[ctrl_file_header_byte_count+1:]
        ctrl_index=0
        for idx in xrange(0,len(correct_ctrl_frames)-CTRL_STRUCT_SIZE ,CTRL_STRUCT_SIZE ):
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
                if len(monitor_elem)>0:
                    Noise.append(monitor_elem[tsf][0])
            else :
                print " success denied; control frame"
            
            ctrl_index=ctrl_index+CTRL_STRUCT_SIZE            
            del frame_elem
            del monitor_elem
        
        ctrl_index=0
        for idx in xrange(0,len(err_ctrl_frames)-CTRL_ERR_STRUCT_SIZE,CTRL_ERR_STRUCT_SIZE):			
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
                if len(monitor_elem)>0:
                    Noise.append(monitor_elem[tsf][0])
            else :
                print "success denied; incorrect control frame "

            ctrl_index= ctrl_index+CTRL_ERR_STRUCT_SIZE
            del frame_elem
            del monitor_elem
            
        file_counter +=1
        if file_counter %10 == 0:
            print file_counter


if __name__=='__main__':
    if len(sys.argv) !=8 :
	print len(sys.argv)
	print "Usage : python file.py data/<data.gz> mgmt/<mgmt.gz> ctrl/<ctrl.gz> <routerId> <t1> <t2> <outputfile> "
        sys.exit(1)
    data_f_dir=sys.argv[1]
    mgmt_f_dir=sys.argv[2]
    ctrl_f_dir=sys.argv[3]
    router_id=sys.argv[4]
    time1=sys.argv[5]
    time2=sys.argv[6]
    outfile_name=sys.argv[7]
    [t1,t2] = timeStamp_Conversion(time1,time2,router_id)
    read_raw_file(t1,t2)
    output_device = open(outfile_name, 'wb')
    pickle.dump([router_id,Noise],output_device)
    output_device.close()

    for i in range(0,len(missing_files)):
	print missing_files[i]
    print "number of files that can't be located ", len(missing_files)

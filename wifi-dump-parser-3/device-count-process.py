#Author : Abhinav Narain
#Date : Sept 8, 2013
#Purpose : To read the binary files with data from BISmark deployment in homes
#Creates a map of mac addresses seen every minute
#Creates a map of nearby networks seen at home
import os,sys,re
import gzip
import struct 


from  header import *
from mac_parser import * 
from utils import *

try:
    import cPickle as pickle
except ImportError:
    import pickle

#List of corresponding files which were missing
missing_files=[]

#The unique set of devices seen in the time period
ap_macs,device_macs=set(), set()
#device map has the list of devices seen per minute
device_map=defaultdict(list)
#ap map has the list of Access Points seen per minute
ap_map=defaultdict(list)
ap_network=defaultdict(set)

def file_reader() : 
    data_fs=os.listdir(data_f_dir)
    data_file_header_byte_count=0
    mgmt_file_header_byte_count=0
    file_timestamp=0
    file_counter=0 
    for data_f_name in data_fs :
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

        #done with reading the binary blobs from file ; now check for timestamps are correct
        if (not ( mgmt_file_current_timestamp == data_file_current_timestamp )) :
            print "timestamps don't match " 		
            sys.exit(1)
        else :
            file_timestamp=mgmt_file_current_timestamp	
        if (not ( mgmt_file_seq_no == data_file_seq_no)):
            print "sequence number don't match "
            sys.exit(1)


        if ( len(data_contents) != 4 or len(mgmt_contents) !=6) :
            print "for data", len(data_contents), "for mgmt", len(mgmt_contents) 
            print "file is malformed or the order of input folders is wrong "
            continue
        
        #The following code block parses the data file 	
        #print "----------done with missed .. now with actual data "
        correct_data_frames=header_and_correct_data_frames[data_file_header_byte_count+1:]
        data_index=0
        device_local_map=set()
        rate=[]
        for idx in xrange(0,len(correct_data_frames)-DATA_STRUCT_SIZE ,DATA_STRUCT_SIZE ):	
            frame=correct_data_frames[data_index:data_index+DATA_STRUCT_SIZE]
            offset,success,tsf= 8,-1,0
            header = frame[:offset]
            frame_elem=defaultdict(list)
            monitor_elem=defaultdict(list)        
            (version,pad,radiotap_len,present_flag)=struct.unpack('<BBHI',header)
            (success,frame_elem,monitor_elem)=parse_radiotap(frame,radiotap_len,present_flag,offset,monitor_elem,frame_elem)   
            if success==1:
                for key in frame_elem.keys():
                    tsf=key                                    
                parse_data_frame(frame,radiotap_len,frame_elem)
                temp=frame_elem[tsf]
                temp.insert(0,tsf)
                if radiotap_len ==RADIOTAP_RX_LEN : #if the destn address is 0x1 then, it is a multicast frame
                    a= temp[12].split(':')
                    [f_type,f_subtype]=temp[17]
                    if not(int(a[0],16) &0x1) and f_type==1 and f_subtype==3:
                        device_macs.add(temp[12])
                        device_local_map.add(temp[12])
                    try:
                        b= temp[13].split(':')
                    except :
                        print "problem with mac element "
                        print frame_elem
                        sys.exit(1)
                        continue
                    if not(int(b[0],16) &0x1) and f_type==1 and f_subtype==3:
                        device_macs.add(temp[13])   
                        device_local_map.add(temp[13])
                        
                    if not(int(b[0],16) &0x1) and not(int(a[0],16) &0x1) and f_type==1 and f_subtype==3:
                        if temp[12] in Station:
                            ap_network[temp[13]].add(temp[12])
                        if temp[13] in ap_network.keys(): 
                            ap_network[temp[13]].add(temp[12])
                            
                elif radiotap_len ==RADIOTAP_TX_LEN:
                    pass 
            else:
                print "data frames; success denied"                    
            data_index=data_index+DATA_STRUCT_SIZE
            del frame_elem
            del monitor_elem
        device_map[file_timestamp]=device_local_map
        del device_local_map
        #The following code block parses the mgmt files 
        beacon_mgmt_frames=header_and_beacon_mgmt_frames[mgmt_file_header_byte_count+1:]
        mgmt_index=0
        ap_local_map=set()
        for idx in xrange(0,len(beacon_mgmt_frames)-MGMT_BEACON_STRUCT_SIZE ,MGMT_BEACON_STRUCT_SIZE ):		
            frame=beacon_mgmt_frames[mgmt_index:mgmt_index+MGMT_BEACON_STRUCT_SIZE]
            offset,success,tsf= 8,-1,0
            header = frame[:offset]
            frame_elem,monitor_elem=defaultdict(list),defaultdict(list)
            (version,pad,radiotap_len,present_flag)=struct.unpack('<BBHI',header)
            if not( radiotap_len == RADIOTAP_RX_LEN or  radiotap_len == RADIOTAP_TX_LEN) :
                print "the radiotap header is not correct"	
                sys.exit(1)
            (success,frame_elem,monitor_elem)=parse_radiotap(frame,radiotap_len,present_flag,offset,monitor_elem,frame_elem)
            if success ==1:
                for key in frame_elem.keys():
                    tsf=key 
                parse_mgmt_beacon_frame(frame,radiotap_len,frame_elem)
                temp=frame_elem[tsf]
                temp.insert(0,tsf)
                if radiotap_len== RADIOTAP_RX_LEN:
                    a= temp[12].split(':')
                    if  not (int(a[0],16) & 0x1):
                        ap_macs.add(temp[12])
                        ap_local_map.add(temp[12])
                        if not(temp[12] in ap_network.keys()):
                            ap_network[temp[12]].add('')
            else :
                print "success denied; beacon frames" 
            mgmt_index=mgmt_index+MGMT_BEACON_STRUCT_SIZE
            del frame_elem
            del monitor_elem

        ap_map[file_timestamp]=ap_local_map
        del ap_local_map
        #he following code block parses the ctrl files 

        file_counter +=1
        if file_counter %10 == 0:
            print file_counter
                
if __name__=='__main__':
    if len(sys.argv) !=5:	
	print len(sys.argv)
        print "Usage : python reader.py data/<data.gz> mgmt/<mgmt.gz>  <router_id> <o/p pickle> "
        sys.exit(1)

    data_f_dir=sys.argv[1]
    mgmt_f_dir=sys.argv[2]
    router_id=sys.argv[3]
    output_file=sys.argv[4]
    file_reader()
    print "no of unique mac address of devices ", len(device_macs)
    #print "router macs ", device_macs
    print "no of unique mac address of aps", len(ap_macs)
    print " mac address of APs ", ap_macs
    print "Len of ap network", len(ap_network)
    for i,j in ap_network.iteritems():
          print i, j
    print "done; writing to a file "
    global_list=[router_id,ap_macs,device_macs,ap_map,device_map,ap_network]
    output_device = open(output_file+router_id+'.pickle', 'wb')
    pickle.dump(global_list,output_device)
    output_device.close()
    print "finished writing files" 
    for i in range(0,len(missing_files)):
	print missing_files[i]
    print "number of files that can't be located ", len(missing_files)

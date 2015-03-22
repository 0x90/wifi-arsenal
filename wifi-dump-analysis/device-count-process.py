#Author : Abhinav Narain
#Date : Feb 5, 2012
#Purpose : To read the binary files with data from BISmark deployment in homes

import os,sys,re
import gzip
import struct 


from  header import *
from mac_parser import * 
from stats import *

try:
    import cPickle as pickle
except ImportError:
    import pickle

missing_files=[]

ap_macs =set()
device_macs=set()
rate_map,ap_map,device_map=defaultdict(list),defaultdict(list),defaultdict(list)

if len(sys.argv) !=9:	
	print len(sys.argv)
	print "Usage : python reader.py data/<data.gz> mgmt/<mgmt.gz> ctrl/<ctrl.gz>><o/p dev map> <o/p dev macs> <o/p ap map> <output ap macs> <rate>"
	sys.exit(1)
#compare regular expression for filenameif argv[1]

data_f_dir=sys.argv[1]
mgmt_f_dir=sys.argv[2]
ctrl_f_dir=sys.argv[3]
output_dev_map_filename=sys.argv[4]
output_dev_macs_filename=sys.argv[5]
output_ap_map_filename=sys.argv[6]
output_ap_macs_filename=sys.argv[7]
output_rate_filename=sys.argv[8]


data_fs=os.listdir(data_f_dir)
ctrl_fs=os.listdir(ctrl_f_dir)

data_file_header_byte_count=0
ctrl_file_header_byte_count=0
mgmt_file_header_byte_count=0
file_counter=0
file_timestamp=0
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
    #frame_coint[timestamp].append([mgmt missed+collected correct,missed+collected incorr])

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
	
        #The following code block parses the data file 	
	#print "----------done with missed .. now with actual data "
    correct_data_frames=header_and_correct_data_frames[data_file_header_byte_count+1:]
    data_index=0
    device_local_map=set()
    rate=[]
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
            if radiotap_len ==58 :
                rate.append(frame_elem[tsf][7])
                a= frame_elem[tsf][11].split(':')
                if  not (a[0] =='ff' and a[1] =='ff' and a[2] =='ff' ):
                    if not (a[0] =='33' and a[1] =='33'  ) :
                        device_macs.add(frame_elem[tsf][11])
                        device_local_map.add(frame_elem[tsf][11])            
                a= frame_elem[tsf][12].split(':')
                if  not (a[0] =='ff' and a[1] =='ff' and a[2] =='ff' ):
                    if not (a[0] =='33' and a[1] =='33'  ) :
                        device_macs.add(frame_elem[tsf][12])
                        device_local_map.add(frame_elem[tsf][12])
            elif radiotap_len ==42 :
                rate.append(frame_elem[tsf][2])
        else:
            print "success denied"                    
        data_index=data_index+DATA_STRUCT_SIZE
        del frame_elem
        del monitor_elem
    device_map[file_timestamp]=device_local_map
    def histogram(L):
        d = {}
        for x in L:
            if x in d:
                d[x] += 1
            else:
                d[x] = 1
        return d
    rate_map[file_timestamp]= histogram(rate)
    rate=[]
    del device_local_map
    #The following code block parses the mgmt files 
    beacon_mgmt_frames=header_and_beacon_mgmt_frames[mgmt_file_header_byte_count+1:]
    mgmt_index=0
    ap_local_map=set()
    for idx in xrange(0,len(beacon_mgmt_frames)-MGMT_BEACON_STRUCT_SIZE ,MGMT_BEACON_STRUCT_SIZE ):		
        global file_timestamp
        frame=beacon_mgmt_frames[mgmt_index:mgmt_index+MGMT_BEACON_STRUCT_SIZE]
        offset,success,tsf= 8,-1,0
        header = frame[:offset]
        frame_elem,monitor_elem=defaultdict(list),defaultdict(list)
        (version,pad,radiotap_len,present_flag)=struct.unpack('<BBHI',header)
        if not( radiotap_len ==58 or  radiotap_len == 42) :
            print "the radiotap header is not correct "		
            sys.exit(1)
        (success,frame_elem,monitor_elem)=parse_radiotap(frame,radiotap_len,present_flag,offset,monitor_elem,frame_elem)
        if success :
            for key in frame_elem.keys():
                tsf=key           
            parse_mgmt_beacon_frame(frame,radiotap_len,frame_elem)
            if radiotap_len== 58:
                a= frame_elem[tsf][11].split(':')            
                if  not (a[0] =='ff' and a[1] =='ff' and a[2] =='ff' ) :
                    if not (a[0] =='33' and a[1] =='33' ) :
                        ap_macs.add(frame_elem[tsf][11])
                        ap_local_map.add(frame_elem[tsf][11])
        else :
            print "success denied"        
        mgmt_index=mgmt_index+MGMT_BEACON_STRUCT_SIZE
        del frame_elem
        del monitor_elem

    ap_map[file_timestamp]=ap_local_map
    del ap_local_map      
    #he following code block parses the ctrl files 

    file_counter +=1
    if file_counter %10 == 0:
        print file_counter


#not needed for phy errs

print "mac address of devices "
print device_macs
print "done with printing device macs "
print device_map
print "mac address of aps"
print ap_macs
print "==========="
print ap_map
print "rate maps are " 
print rate_map
print "done; writing to a file "
f_d= output_dev_macs_filename
output_device = open(f_d, 'wb')
pickle.dump(device_macs,output_device )
output_device.close()

print "done with device map set print "

f_ap= output_dev_map_filename
output_ap = open(f_ap, 'wb')
pickle.dump(device_map,output_ap )
output_ap.close()

f_ap= output_ap_macs_filename
output_ap = open(f_ap, 'wb')
pickle.dump(ap_macs,output_ap )
output_ap.close()

f_ap= output_ap_map_filename
output_ap = open(f_ap, 'wb')
pickle.dump(ap_map,output_ap )
output_ap.close()


f_ap= output_rate_filename
output_ap = open(f_ap, 'wb')
pickle.dump(rate_map,output_ap )
output_ap.close()


print "done with access point map set print "
for i in range(0,len(missing_files)):
	print missing_files[i]
print "number of files that can't be located ", len(missing_files)	

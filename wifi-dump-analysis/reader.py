#Author : Abhinav Narain
#Date : Jan 10, 2012
#Purpose : TESTING : To read the binary files with data from BISmark deployment inside homes 

import os,sys
import gzip
import struct 

from  header import *
from mac_parser import * 

if len(sys.argv) !=4:
	print len(sys.argv)
	print "Usage : python reader.py data/<data.gz> mgmt/<mgmt.gz> ctrl/<ctrl.gz> "
	sys.exit(1)
#compare regular expression for filenameif argv[1]

data_f_dir=sys.argv[1]
mgmt_f_dir=sys.argv[2]
ctrl_f_dir=sys.argv[3]


data_fs=os.listdir(data_f_dir)
ctrl_fs=os.listdir(ctrl_f_dir)


data_file_header_byte_count=0
ctrl_file_header_byte_count=0
mgmt_file_header_byte_count=0
#The following code block parses the data file 

for data_f_name in data_fs :
	data_f= gzip.open(data_f_dir+data_f_name,'rb')
	data_file_content=data_f.read()
	data_f.close()
	for i in xrange(len(data_file_content )):
		if data_file_content[i]=='\n':
			bismark_data_file_header = str(data_file_content[0:i])
			ents= bismark_data_file_header.split(' ')
			bismark_id_data_file=ents[0]
			start_64_timestamp_data_file=ents[1]
			data_file_seq_no= ents[2]
			data_file_current_timestamp=ents[3]
			print "current timestamp" , data_file_current_timestamp
			print "file seq no ", data_file_seq_no
			print "start_timestamp_64" , start_64_timestamp_data_file
			print "bismark id ",bismark_id_data_file
			data_file_header_byte_count =i
			break
	data_contents=data_file_content.split('\n----\n')
	print " data content length is " , len(data_contents)
	header_and_correct_data_frames = data_contents[0]
	err_data_frames = data_contents[1]
	correct_data_frames_missed=data_contents[2]
	err_data_frames_missed=data_contents[3]
	#devices_connected= data_contents[4]
	print "size of data_contents[0], [1], [2],[3] ", len(data_contents[0]),len(data_contents[1]),len(data_contents[2]),len(data_contents[3])
	val1= struct.unpack('I',correct_data_frames_missed)
	print val1 , "fu1"
	val2= struct.unpack('I',err_data_frames_missed)
	print val2, "fu"
	print "----------done with missed .. now with actual data "
	correct_data_frames=header_and_correct_data_frames[data_file_header_byte_count+1:]
	print "looper is ",len(correct_data_frames)
	data_index=0
	count =0
	for idx in xrange(0,len(correct_data_frames)-DATA_STRUCT_SIZE ,DATA_STRUCT_SIZE ):	
		data_index=data_index+DATA_STRUCT_SIZE
		frame=correct_data_frames[data_index:data_index+DATA_STRUCT_SIZE]
		#	print "len of frame is ", data_index, len(correct_data_frames)
		offset= 8
		header = frame[:offset]
		(version,pad,radiotap_len,present_flag)=struct.unpack('<BBHI',header)
		parse_radiotap(frame,radiotap_len,present_flag,offset)
		parse_data_frame(frame,radiotap_len)
	data_index=0
	err_count=0
	for idx in xrange(0,len(err_data_frames)-DATA_ERR_STRUCT_SIZE,DATA_ERR_STRUCT_SIZE ):	
		data_index= data_index+DATA_ERR_STRUCT_SIZE
		frame=err_data_frames[data_index:data_index+DATA_ERR_STRUCT_SIZE]
		offset= 8
		header = frame[:offset]
		(version,pad,radiotap_len,present_flag)=struct.unpack('<BBHI',header)
		parse_radiotap(frame,radiotap_len,present_flag,offset)
		parse_err_data_frame(frame,radiotap_len)
		err_count +=1
	print err_count 
print "cOUNT BAD IS ", count_bad
#The following code block parses the mgmt files 
mgmt_f_dir= sys.argv[2]
mgmt_fs=os.listdir(mgmt_f_dir)

for mgmt_f_name in mgmt_fs :
	mgmt_f =gzip.open(mgmt_f_dir+mgmt_f_name,'rb')
	mgmt_file_content=mgmt_f.read()
	mgmt_f.close()
	for i in xrange(len(mgmt_file_content )):
		if mgmt_file_content[i]=='\n':
			bismark_mgmt_file_header = str(mgmt_file_content[0:i])
			ents= bismark_mgmt_file_header.split(' ')
			bismark_id_mgmt_file=ents[0]
			start_64_timestamp_mgmt_file=ents[1]
			mgmt_file_seq_no= ents[2]
			mgmt_file_current_timestamp=ents[3]
			print "current timestamp" , mgmt_file_current_timestamp
			print "file seq no ", mgmt_file_seq_no
			print "start_timestamp_64" , start_64_timestamp_mgmt_file
			print "bismark id ",bismark_id_mgmt_file
			mgmt_file_header_byte_count =i
			break
	mgmt_contents=mgmt_file_content.split('\n----\n')
	print "mgmt content length is " , len(mgmt_contents)
	header_and_beacon_mgmt_frames = mgmt_contents[0] 
	common_mgmt_frames = mgmt_contents[1]
	err_mgmt_frames=mgmt_contents[2]
	beacon_mgmt_frames_missed=mgmt_contents[3]
	common_mgmt_frames_missed=mgmt_contents[4]
	err_mgmt_frames_missed=mgmt_contents[5]

	print "size of data_contents[0],[1], [2],[3],[4], [5]", len(mgmt_contents[0]),len(mgmt_contents[1]),len(mgmt_contents[2]),len(mgmt_contents[3]),len(mgmt_contents[4]), len(mgmt_contents[5])
	val1= struct.unpack('I',beacon_mgmt_frames_missed)
	print val1 , "fu1"
	val2= struct.unpack('I',common_mgmt_frames_missed)
	print val2, "fu2"
	val3=struct.unpack('I',err_mgmt_frames_missed)
	print val3 , "fu3"

	print "----------done with missed .. now with actual data "
	beacon_mgmt_frames=header_and_beacon_mgmt_frames[mgmt_file_header_byte_count+1:]
	print "looper is ",len(beacon_mgmt_frames)
	mgmt_index=0
	count =0
	for idx in xrange(0,len(beacon_mgmt_frames)-MGMT_BEACON_STRUCT_SIZE ,MGMT_BEACON_STRUCT_SIZE ):		
		frame=beacon_mgmt_frames[mgmt_index:mgmt_index+MGMT_BEACON_STRUCT_SIZE]
		#	print "len of frame is ", data_index, len(correct_data_frames)
		offset= 8
		header = frame[:offset]
		(version,pad,radiotap_len,present_flag)=struct.unpack('<BBHI',header)

		parse_radiotap(frame,radiotap_len,present_flag,offset)
		parse_mgmt_beacon_frame(frame,radiotap_len)
		mgmt_index=mgmt_index+MGMT_BEACON_STRUCT_SIZE
	mgmt_index=0
	for idx in xrange(0,len(common_mgmt_frames)-MGMT_COMMON_STRUCT_SIZE ,MGMT_COMMON_STRUCT_SIZE ):	
		frame=common_mgmt_frames[mgmt_index:mgmt_index+MGMT_COMMON_STRUCT_SIZE]
		#	print "len of frame is ", data_index, len(correct_data_frames)
		offset= 8
		header = frame[:offset]
		(version,pad,radiotap_len,present_flag)=struct.unpack('<BBHI',header)
#		for i in range (0,MGMT_COMMON_STRUCT_SIZE):
#			print list(struct.unpack('B',frame[i]))[0], " " ,
#		print "\n----"
		parse_radiotap(frame,radiotap_len,present_flag,offset)
		parse_mgmt_common_frame(frame,radiotap_len)
		mgmt_index=mgmt_index+MGMT_COMMON_STRUCT_SIZE

	mgmt_index=0
	err_count=0
	print "THE ERR MGMT FRAME BLOB SIZE ::", len(err_mgmt_frames)

	for idx in xrange(0,len(err_mgmt_frames)-MGMT_ERR_STRUCT_SIZE,MGMT_ERR_STRUCT_SIZE ):	
		frame=err_mgmt_frames[mgmt_index:mgmt_index+MGMT_ERR_STRUCT_SIZE]
		offset= 8
		err_count +=1
		header = frame[:offset]
		(version,pad,radiotap_len,present_flag)=struct.unpack('<BBHI',header)
		
#		for i in range (0,MGMT_COMMON_STRUCT_SIZE*8):
#			if i % MGMT_COMMON_STRUCT_SIZE ==0:
#				print "\n"
#			print  list(struct.unpack('B',frame[i]))[0], " ",

		if not( radiotap_len ==58 or  radiotap_len == 42) :
			print "MGMT ERR " 
			print mgmt_index
			print "version, pad " , version, pad 
			print "radiotap_len " , radiotap_len
			print  "err count = ", err_count
			print  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFf"
			print mgmt_index/MGMT_ERR_STRUCT_SIZE
			for i in range (0,8):
				print list(struct.unpack('B',frame[i]))[0], " ",
				sys.exit(1)

		parse_radiotap(frame,radiotap_len,present_flag,offset)
		parse_mgmt_err_frame(frame,radiotap_len)
		mgmt_index= mgmt_index+MGMT_ERR_STRUCT_SIZE

#The following code block parses the ctrl files 

for ctrl_f_name in ctrl_fs :
	ctrl_f= gzip.open(ctrl_f_dir+ctrl_f_name,'rb')
	ctrl_file_content=ctrl_f.read()
	for i in xrange(len(ctrl_file_content )):
		if ctrl_file_content[i]=='\n':
			bismark_ctrl_file_header = str(ctrl_file_content[0:i])
			ents= bismark_ctrl_file_header.split(' ')
			bismark_id_ctrl_file=ents[0]
			start_64_timestamp_ctrl_file=ents[1]
			ctrl_file_seq_no= ents[2]
			ctrl_file_current_timestamp=ents[3]
			print "current timestamp" , ctrl_file_current_timestamp
			print "file seq no ", ctrl_file_seq_no
			print "start_timestamp_64" , start_64_timestamp_ctrl_file
			print "bismark id ",bismark_id_ctrl_file
			ctrl_file_header_byte_count =i
			break
	ctrl_f.close()
	ctrl_contents=ctrl_file_content.split('\n----\n')
	print " ctrl content length is " , len(ctrl_contents)
	header_and_correct_ctrl_frames = ctrl_contents[0]
	err_ctrl_frames = ctrl_contents[1]
	correct_ctrl_frames_missed=ctrl_contents[2]
	err_ctrl_frames_missed=ctrl_contents[3]
	print "size of ctrl_contents[0], [1], [2],[3] ", len(ctrl_contents[0]),len(ctrl_contents[1]),len(ctrl_contents[2]),len(ctrl_contents[3])
	val1= struct.unpack('I',correct_ctrl_frames_missed)
	print val1 , "fu1"
	val2= struct.unpack('I',err_ctrl_frames_missed)
	print val2, "fu"
	print "----------done with missed .. now with actual data "
	correct_ctrl_frames=header_and_correct_ctrl_frames[ctrl_file_header_byte_count+1:]
	print "looper is ",len(correct_ctrl_frames)
	ctrl_index=0
	count =0
	for idx in xrange(0,len(correct_ctrl_frames)-CTRL_STRUCT_SIZE ,CTRL_STRUCT_SIZE ):	
		ctrl_index=ctrl_index+CTRL_STRUCT_SIZE
		frame=correct_ctrl_frames[ctrl_index:ctrl_index+CTRL_STRUCT_SIZE]
 #	print "len of frame is ", data_index, len(correct_data_frames)
		offset= 8
		header = frame[:offset]
		(version,pad,radiotap_len,present_flag)=struct.unpack('<BBHI',header)
		parse_radiotap(frame,radiotap_len,present_flag,offset)
		parse_ctrl_frame(frame,radiotap_len)

	ctrl_index=0
	err_count=0
	for idx in xrange(0,len(err_ctrl_frames)-CTRL_ERR_STRUCT_SIZE,CTRL_ERR_STRUCT_SIZE):	
		ctrl_index= ctrl_index+CTRL_ERR_STRUCT_SIZE
		frame=err_ctrl_frames[ctrl_index:ctrl_index+CTRL_ERR_STRUCT_SIZE]
		offset= 8
		header = frame[:offset]
		(version,pad,radiotap_len,present_flag)=struct.unpack('<BBHI',header)
		parse_radiotap(frame,radiotap_len,present_flag,offset)
		parse_ctrl_err_frame(frame,radiotap_len)
		err_count +=1
		print err_count 



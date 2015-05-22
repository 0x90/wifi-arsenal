#Author : Abhinav Narain
#Date : 9-sept-2013
#Purpose : To plot the #devices,AP inside homes 

from magicplott import *

def pickle_reader(input_folder):
    print "the pickle reader called " 
    data_fs=os.listdir(input_folder)
    home_device_table=defaultdict(list)
    home_ap_table=defaultdict(list)
    for f_name in data_fs :
        #router_id,ap_macs,device_macs,ap_map,device_map,rate_map ; maps are of times 
	_f_content= pickle.load(open(input_folder+f_name,'rb'))
	router_id= _f_content[0]
        ap_mac=_f_content[1]
        device_mac=_f_content[2]
        home_device_table[router_id]=device_mac
        home_ap_table[router_id]=ap_mac
        
    return [home_ap_table,home_device_table]


def pickle_reader_time_map(input_folder):
    print "the pickle reader called " 
    data_fs=os.listdir(input_folder)
    home_device_table=defaultdict(list)
    home_ap_table=defaultdict(list)
    for f_name in data_fs :
        #router_id,ap_macs,device_macs,ap_map,device_map,rate_map ; maps are of times 
	_f_content= pickle.load(open(input_folder+f_name,'rb'))
	router_id= _f_content[0]
        ap_map=_f_content[3]
        device_map=_f_content[4]
        home_device_table[router_id]=device_map
        home_ap_table[router_id]=ap_map
        
    return [home_ap_table,home_device_table]


if __name__=='__main__':    
    '''
    This main function is for plotting the number 
    of distinct devices and Access Points seen by 
    the BISmark Access Points inside homes 
    '''

    if len(sys.argv) !=4:
        print "usage : python unpickeler.py <data_folder_2GHz> <data_folder_5GHz> <filename(without png extention)>  "
        sys.exit(0)

    input_folder = sys.argv[1]
    input_folder5 = sys.argv[2]
    outfile_name = sys.argv[3]

    home_ap_2_table=defaultdict(list)
    home_ap_5_table=defaultdict(list)
    home_device_2_table=defaultdict(list)
    home_device_5_table=defaultdict(list)
    [home_ap_2_table,home_device_2_table]=pickle_reader(input_folder)
    [home_ap_5_table,home_device_5_table]=pickle_reader(input_folder5)
    new_list_2=[]
    for k,v in home_ap_2_table.iteritems():
        list_devices=home_device_2_table[k]
        new_list_devices= [x for x in list_devices if x not in v]
        new_list_2.append([k,len(new_list_devices),len(v)])
        
    new_list_2.sort(key=lambda x: x[1])
    labels_2,home_device_count_2,home_ap_count_2=[],[],[]
    for i in new_list_2 :
        labels_2.append(i[0])
        home_device_count_2.append(i[1])
        home_ap_count_2.append(i[2])

    new_list_5=[]
    for k,v in home_ap_5_table.iteritems():        
        list_devices=home_device_5_table[k]
        new_list_devices= [x for x in list_devices if x not in v]
        new_list_5.append([k,len(new_list_devices),len(v)])

    new_list_5.sort(key=lambda x: x[1])
    labels_5,home_device_count_5,home_ap_count_5=[],[],[]
    for i in new_list_5 :
        labels_5.append(i[0])
        home_device_count_5.append(i[1])
        home_ap_count_5.append(i[2])

    
    bar_graph_plotter(labels_5, 
                      home_device_count_5,
                      'RouterID',
                      'Device Count',
                      'Number of Devices observed in homes(5 GHz)',
                      outfile_name+'5_devices.png'
                      )

    bar_graph_plotter(labels_2, 
                      home_device_count_2,
                      'RouterID',
                      'Device Count',
                      'Number of Devices observed in homes(2.4 GHz)',
                      outfile_name+'2_4_devices.png'
                      )

    new_list_2.sort(key=lambda x: x[2])
    labels_2,home_device_count_2,home_ap_count_2=[],[],[]
    for i in new_list_2 :
        labels_2.append(i[0])
        home_device_count_2.append(i[1])
        home_ap_count_2.append(i[2])

    new_list_5.sort(key=lambda x: x[2])
    labels_5,home_device_count_5,home_ap_count_5=[],[],[]
    for i in new_list_5 :
        labels_5.append(i[0])
        home_device_count_5.append(i[1])
        home_ap_count_5.append(i[2])

    bar_graph_plotter(labels_5, 
                      home_ap_count_5,
                      'RouterID',
                      'Access Points Count',
                      'Number of Access Points observed in homes(5 GHz)',
                      outfile_name+'5_ap.png'
                      )

    bar_graph_plotter(labels_2, 
                      home_ap_count_2,
                      'RouterID',
                      'Device Count',
                      'Number of Devices and Access Points observed in homes(2.4 GHz)',
                      outfile_name+'2_4_ap.png'
                      )

#Date : 15 Sept, 2012
#Partially written; needs to be completed

if 0:# __name__=='__main__':

    '''
    This function is for plotting the number of Devices 
    and Access Points witnessed by BISmark Access Point 
    *persistently*
    '''

    if len(sys.argv) !=3:
        print "usage : python unpickeler.py data_folder_2GHz filename.png  "
        sys.exit(0)

    input_folder = sys.argv[1]
    outfile_name = sys.argv[2]

    home_ap_2_table=defaultdict(list)
    home_device_2_table=defaultdict(list)

    [home_ap_2_table,home_device_2_table]=pickle_reader_time_map(input_folder)
    new_list_2=[]
    for k,ap_time_map in home_ap_2_table.iteritems():
        for time,list_of_aps in ap_time_map.iteritems():
            print time, len(list_of_aps)
        print "++++"

    sys.exit(1)
    new_list_devices= [x for x in list_devices if x not in v]
    new_list_2.append([k,len(new_list_devices),len(v)])
        
    new_list_2.sort(key=lambda x: x[1])
    labels_2,home_device_count_2,home_ap_count_2=[],[],[]
    for i in new_list_2 :
        labels_2.append(i[0])
        home_device_count_2.append(i[1])
        home_ap_count_2.append(i[2])

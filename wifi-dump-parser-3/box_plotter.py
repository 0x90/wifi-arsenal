from magicplott import *
#Date : 5 Sept
#Author : Abhinav Narain
# Purpose : Plot the nosie variation across homes 
#Plot the variation in RTS frames across homes 

rts_cts_by_rts_cts_ack_table={
	'OWC43DC7A3EDEC' : [21.7721855356, 44.7886540886,5.38103836057, 8.9494472027,3.82154064508],
	'OWC43DC7B0AE54' :[67.8342086906, 58.6362424386,2.5155062229, 71.1648758139],
	'OWC43DC7B0AE78' :[34.8144651043,  40.0996057175,55.9545580986,46.2288654254],
	'OW2CB05DA0D183' :[47.4911976743, 75.5331349768, 34.1926574561,81.1208467535],
	'OW4C60DEE6C9AB' :[158.5296430925, 44.7886540886, 55.8561315252],
	'OWC43DC79DE112' :[86.7056836887, 86.7056836887],
	'OW2CB05DA0D4DA' :[36.9320621833, 2.76863979077],
	'OW4C60DEE6B037' :[96.3261417494],
	'OW4C60DEE6B01C' :[56.2198416351],
	'OW4C60DED0F74B' :[14.9446227292],
	'OWC43DC7A37C01' :[33.5884624235],
	'OWC43DC7A3F0D4' : [6.95356960505],
	'OW100D7F64CA77' :[16.8372412667],
	'OWA021B7A9BEF0' :[41.3661465888],
	'OWC43DC7B0CAB6' :[36.8959254415, 43.2899356466],
	'OWC43DC7B0AE1B'  :[74.1524313863, 30.9053809915],
	'OWA021B7A9BDA6' :[90.6079014512, 94.3398283114],
	'OWC43DC79DE0D6' :[42.0440720943, 52.17800888],
	'OW204E7F91A331' :[35.295720526, 58.3850852036],
	'OWC43DC78EE081' :[22.5508769127,20.6543558959],
	'OWC43DC7B0AEDB' :[70.5078620962, 58.2127649423],
	'OWC43DC7A3EE3A' :[82.6092285594,  82.1648744213], 
	'OWA021B7A9BF83' : [45.2364026263],
	'OWC43DC7B0AE69' :[71.071849844, 53.4809707791],
}

rts_by_rts_cts_table={
	'OWC43DC7A3EDEC' : [(202260*100.0 / (50094+ 202260)), (166207*100.0/( 620052 + 166207)),100*90236/(90236+43696), 4210*100/(4210+1432), (89980 *100.0)/( 16322+ 89980)  ], 
	'OWC43DC7B0AE54' : [3729878 *100.0 / (2352690 +3729878), 1571087 *100.0 / (1571087 +984291), 1665338 *100.0 / (898281+ 1665338), (2790668 *100.0) / (2790668 +1757344)],
	'OWC43DC7B0AE78' : [144593 *100.0 / (811846 +144593) ,429117*100.0/( 429117+ 756330) , 709746 *100.0 / (709746+ 925625) , 107709 *100.0 / (107709 +1053641)],    
	'OW2CB05DA0D183' : [2665968 *100.0 / (2665968+ 2185217), 2571173 *100.0 / (2571173 +2237249), 1142463 *100.0 / (1142463+ 1439548) ,2882244 *100.0 / (2882244 +2561007)],
	'OW4C60DEE6C9AB' : [148982 *100.0 / (148982 +401700), 166207 *100.0 / (166207 +620052), 401210 *100.0 / (401210 + 1066416)],
	'OWC43DC79DE112' : [3781503 *100.0 / (3781503 +2453990), 3781503*100/( 3781503+ 2453990)],
	'OW2CB05DA0D4DA' : [106 *100.0 / (106+ 8494) , 1 *100.0 / (1+ 1354)], 
	'OW4C60DEE6B037' : [48006 *100.0 / (48006 +750740)],    
	'OW4C60DEE6B01C' : [510711 *100.0 / (510711 +438493)] ,
	'OW4C60DED0F74B' : [152797 *100.0 / (152797 +167133)] ,
	'OWC43DC7A37C01' : [172374 *100.0 / (172374 + 690303)],        
	'OWC43DC7A3F0D4' : [251504 *100.0 / (251504+ 444825) ],
	'OW100D7F64CA77' : [15070 *100.0 / (15070 + 73620) ],
	'OWA021B7A9BEF0' : [289443 *100.0 / (289443+ 8004)],
	'OWC43DC7B0CAB6' : [114045 *100.0 /  (114045 +150249) , 865625 *100.0 / (865625+ 372194) ],
	'OWC43DC7B0AE1B' : [2789568 *100.0 / (2789568 +1270113), 60284 *100.0 / (60284+ 65279)]    ,
	'OWA021B7A9BDA6' : [640259 *100.0 / (640259+ 603387), 3460023 *100.0 / (3460023+ 3186733)],
	'OWC43DC79DE0D6' : [ 707167 *100.0 / (707167+ 51651) , 2383065 *100.0 / (2383065+ 209272) ],
	'OW204E7F91A331' : [ 10411 *100.0 / (10411+ 116529), 128347 *100.0 / (128347 +8256)]     ,
	'OWC43DC78EE081' : [328988 *100.0 / (328988 + 55820) , 210666 *100.0 / (210666 + 40620) ],
	'OWC43DC7B0AEDB' : [764583 *100.0 /  (764583 +1426183), 16401 *100.0 / (16401+ 715674) ],
	'OWC43DC7A3EE3A' : [1505555*100.0 /  (1505555+ 988183), 576166 *100.0 / (576166 +415836)],
	'OWA021B7A9BF83' : [264229 *100.0 / (264229+ 312921) ],
	'OWC43DC7B0AE69' : [1165795 *100.0 / (1165795 +3009114) ,1177221 *100.0 / (1177221 +1805217)]
}

if  __name__=='__main__':
   '''
   This main works to plot the RTS+CTS percentage for each home to the 
   RTS+CTS+ACK frames in the home
   '''
   if len(sys.argv)!=2:
       print "Usage : file.py <imagefile.png> "
       sys.exit(1)
   image_file=sys.argv[1]
   home_labels=[]
   home_vals=[]
   for k,v in rts_cts_by_rts_cts_ack_table.iteritems():
   	home_labels.append(k)
	home_vals.append(v)
   
   plotter_boxplot(home_labels,
                   home_vals,
                   'RouterIds',
                   'Percentage of RTS+CTS frames in Control traffic',
                   'Distribution of Control Traffic in homes',
                   image_file)


def pickle_reader(input_folder):
    '''
    reads noise values from pickle files and returns a map
    '''
    data_fs=os.listdir(input_folder)
    Noise=defaultdict(list)
    for f_name in data_fs :
       print "reading file"
       _f_content= pickle.load(open(input_folder+f_name,'rb'))
       router_id= _f_content[0]
       noise_list=_f_content[1]
       Noise[router_id]=noise_list

    return Noise
        
if 0: #__name__=='__main__':   
   '''
   This main works to plot noise box plots 
   '''
   if len(sys.argv)!=3:
       print "Usage : file.py <data folder> <imagefile.png> "
       sys.exit(1)
   data_f=sys.argv[1]
   image_file=sys.argv[2]
   label=[]
   vals=[]
   Noise=pickle_reader(data_f)   
   for k,v in Noise.iteritems():
      label.append(k)
      vals.append(v)
   plotter_boxplot(label,
                   vals,
                   'RouterIds',
                   'Noise Variation (dBm)',
                   'Noise Floor in different homes',
                   image_file)

if 0: #__name__=='__main__': 
    if len(sys.argv)!=2:                                                
        print "Usage : file.py <imagefile.png> "
        sys.exit(1)
    image_file=sys.argv[1]
    home_labels=[]
    home_vals=[]
    for k,v in rts_by_rts_cts_table.iteritems():
    	home_labels.append(k)
 	home_vals.append(v)
    plotter_boxplot(home_labels,
                    home_vals,
                    'RouterIds',
                    'Percentage',
                    'Percentage of RTS Frames out of RTS and CTS frame',
                    image_file)

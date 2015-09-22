////////////////////////////////////////////////////////
//                                      
// Click Trace Analysis for SSIDs     
//                                      
// Authors:  T.Huehn {T-labs/TU-Berlin}
// Date:    June 2011                   
// License: GPL v3                         
//                                      
////////////////////////////////////////////////////////  

define($TRACE tracefile)
define($WLAN mon0)

//tee :: Tee(2)

fd :: FromDump($TRACE, TIMING true, FORCE_IP false, ACTIVE false, END_CALL restarter.step)
	-> rx_status :: Classifier
		(
			!16/52%ff, // 52 => bad FSC
			-        // all bad_fcs
		);

//ProgressBar(fd.filepos, fd.filesize);

rx_status[1]
	-> bad_fsc :: Counter
	-> Discard;

rx_status[0]
	-> ok :: Counter
	-> RadiotapDecap()
	-> wifi_class :: Classifier 
		(
			0/08%0c,		//wifi_class[0] classifies all data frames (from and to DS)
	        0/04%0c,		//wifi_class[1] classifies all control frames
	        0/00%0c,		//wifi_class[2] classifies all management frames
			-				//wifi_class[3]everything else
		);

wifi_class[0] -> Discard;
wifi_class[1] -> Discard;
wifi_class[3] -> Discard;

wifi_class[2]
	-> mgt_class :: Classifier
		(
//			0/00%f0, // assoc req
//			0/10%f0, // assoc resp
//			0/20%f0, // reassoc req
//			0/30%f0, // reassoc resp
//			0/40%f0, // probe req
//			0/50%f0, // probe resp
			0/80%f0, // beacon
//			0/90%f0, // ATIM
//			0/a0%f0, // disassoc
//			0/b0%f0, // auth
//			0/c0%f0, // deauth
			-        // reserved
		);
mgt_class[1] -> Discard;

mgt_class[0]
//	-> c :: Counter
//	-> RadiotapEncap()
//	-> ToDump(test-beacon.pcap, SNAPLEN 0, ENCAP 802_11)
	-> ssid :: Classifier
		(
//			38/776c616e3801,	//all ssid=wlan8
//			38/656475726f616d01, //all ssid=eduroam
			38/656475726f616d2e, //all ssid=eduroam.
//			38/01, //all hidden ssid and zero ssids
			-	//the rest
		);

ssid[1] -> Discard;

ssid[0]
	-> c :: Counter
//	-> PrintWifi()
	-> Discard;

test :: FromDump($TRACE, TIMING true, FORCE_IP false, ACTIVE false, END_CALL restarter.step) -> Print(TIMESTAMP true) -> Discard;
restarter :: Script(init first_offset $(test.filepos),
				print "First Offset: " $first_offset,
				write test.active true,
				pause,
				write test.filepos $first_offset,
				write test.reset_timing,
				loop)

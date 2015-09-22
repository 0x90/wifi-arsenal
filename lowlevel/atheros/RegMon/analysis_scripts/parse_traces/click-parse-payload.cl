/////////////////////////////////////////////////////
// click script to parse the payload of the packets
// and separete CRC errors 
// Thomas Huehn Dez. 2010
/////////////////////////////////////////////////////

define($IN in.txt)
define($FILTER_PORT 55550)
define($crc_flase_dump crc_false.pcap, $encap_wireless 802_11_RADIO, $snaplen 0);

from_dump :: FromDump(FILENAME $IN, FORCE_IP true, STOP true)
	-> radio_cl :: Classifier		    //classification of packets with CRC test ok
(
	16/12,   	    //wifi_cl[0] classifies all correct CRC frames
        16/52,              //wifi_cl[1] classifies all brocken CRC frames
	-		    //everything else
);

radio_cl[0] -> ip_cl :: IPClassifier(dst udp port $FILTER_PORT,
					-);
	ip_cl[0] -> ToIPSummaryDump(FILENAME -, CONTENTS timestamp payload payload_len, HEADER false);
	ip_cl[1] -> Discard();

radio_cl[1] -> Discard();

radio_cl[2] -> ip_cl;
//Discard();


//show progress bar ;)
//ProgressBar(fd.filepos, fd.filesize);

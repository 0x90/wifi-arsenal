#!/bin/bash
#
# preprocessing of tcpdump trace files
#	1) -use tshark to extract interesting fiels (could be adapted to individual useage)
#	2) -format the timestamp to have one colum wih the date and one with the timestamp#	
#	3) -extract the payload from the packet's data part - which holds the configuration with CLICK
#

# static configuration
PARSER_DIR=/data/nfs/thomas/experiments/scripts/parser-scripts
CLICK=/usr/local/bin/click
CONVERTTIME=$PARSER_DIR/convert_time.pl

#read mac list for all nodes
    source $PARSER_DIR/mac-list.sh

#tshark options
    TSHARK=/usr/local/bin/tshark
    TSHARK_WIRELESS="-e "frame.time_epoch" -e "radiotap.mactime" -e "frame.len" -e "radiotap.datarate" -e "radiotap.channel.freq" -e "radiotap.dbm_antsignal" -e "radiotap.dbm_antnoise" \
		-e "radiotap.antenna" -e "wlan.duration" -e "wlan.fc.type_subtype" -e "wlan.sa" -e "wlan.da" -e "wlan.bssid" -e "wlan.seq" -e "udp.length""
    TSHARK_WIRED="-e "frame.time_epoch" -e "frame.len" -e "udp.length""
    
    #filter packets regarding  source mac and dest mac, proto UDP, port 9999, crc check ok
    TSHARK_FILTER_CRC_OK="radiotap.flags.badfcs == 0"
    #filter packets regarding  source mac and dest mac, proto UDP, port 9999, crc check false
    TSHARK_FILTER_CRC_FALSE="radiotap.flags.badfcs == 1"
    

SENDER=
INPUT=
OUTPUT=
TYPE=
PAYLOAD=

### FUNCTION DEFINITIONS ###

#parse the input file from $1 and put it to $2
_parse_wired_wo ()
{
	$TSHARK -r $1 $TSHARK_WIRED -T fields -E "header=y" -E "separator=," -R "udp.srcport == 55550"  > $2
}

_parse_wired_w ()
{
	$TSHARK -r $1 $TSHARK_WIRED -T fields -E "header=y" -E "separator=," -R "udp.srcport == 55550" > $2
	#extract payload trace
	$CLICK $PARSER_DIR/click-parse-payload.cl IN=$1 FILTER_PORT=55550 | sed "s/\(*\).*/\1/" > $2.payload	#replace dots with spaces
}

_parse_wireless_wo ()
{
        TMP_SRC="${3}[1]" 	#[1] specifies the second array column, which is the nodes MAC in this case
	TMP_DST="${4}[1]"
	#wireless trace with crc ok
	$TSHARK -r $1 $TSHARK_WIRELESS -T fields -E "header=y" -E "separator=," -R "$TSHARK_FILTER_CRC_OK"  > $2
	#wireless trace with broken crc
	$TSHARK -r $1 $TSHARK_WIRELESS -T fields -E "header=y" -E "separator=," -R "$TSHARK_FILTER_CRC_FALSE"  > $2.broken_crc
}

#new parser without the destination and source MAC
_parse_wireless_w ()
{
	#wireless trace with crc ok
	$TSHARK -r $1 $TSHARK_WIRELESS -T fields -E "header=y" -E "separator=," -R "$TSHARK_FILTER_CRC_OK"  > $2
	#generate 2x pcap where CRC is broken - one to count and one with errored payload , crc ok packets are in the payload trace vi click
	$TSHARK -r $1 $TSHARK_WIRELESS -T fields -E "header=y" -E "separator=," -R "$TSHARK_FILTER_CRC_FALSE" > $2.broken_crc
#	$TSHARK -r $1 $TSHARK_WIRELESS -T fields -E "header=y" -E "separator=," -R "$TSHARK_FILTER_CRC_FALSE" > $2.payload.broken_crc
	#extract payload trace from crc ok packets
	$CLICK $PARSER_DIR/click-parse-payload.cl IN=$1 FILTER_PORT=9999 | sed "s/\(*\).*/\1/" > $2.payload	#replace dots with spaces
}

usage ()
{
cat << EOF
	usage: $0 options

	This script parses BOWL tcpdump wifi traces with configuration in the packet payload to an CSV file.

	OPTIONS:
	   -t   parsing type [wired or wireless] wired=(tshark & time correction for ethernet), wireless=(tshark & time correction for 802.11)
	   -p	payload to be parsed, boolean [0,1]
           -s   source
           -d   destination
	   -o	specify output file
	   -i	specify input file
	   -v   Verbose
	   -h   Show this message
EOF
}

# MAINPROGRAMM

while getopts "h v s:d:p:t:i:o:" OPTION
do
	case $OPTION in
		h)
			usage
			exit1
			;;
		v)      VERBOSE=1
			;;
		s)
			SENDER=$OPTARG
			;;
	        d)      
		        RECEIVER=$OPTARG
		        ;;
		i)
			INPUT=$OPTARG
			;;
		o)
			OUTPUT=$OPTARG
			;;
		t)
			TYPE=$OPTARG
			;;
		p)
			PAYLOAD=$OPTARG
			;;
		?)
			usage
			exit
			;;
        esac
done

if [ -z $TYPE ]
then
        usage
        exit 1
fi


if [ -z $TYPE ] || [ -z $INPUT ] || [ -z $OUTPUT ] || [ -z PAYLOAD ]; then
	echo "INPUT file & OUTPUT file & PAYLOAD & TYPE are needed !"
	exit 1
else
	case "$TYPE" in
		wired)
			case "$PAYLOAD" in
				0)
					_parse_wired_wo $INPUT $OUTPUT
					#echo "parse_wired without payload"
					;;
				1)
					_parse_wired_w $INPUT $OUTPUT
					#echo "parse_wired with payload"
					;;
			esac
			;;
		wireless)
			case "$PAYLOAD" in
				0)
				        _parse_wireless_wo $INPUT $OUTPUT 
					#echo "parse_wireless without payload  source= $SENDER destination= $RECEIVER"
					;;
				1)
					_parse_wireless_w $INPUT $OUTPUT
					#echo "parse_wireless with payload source= $SENDER destinatio= $RECEIVER"
					;;
			esac
			;;
		*)
			echo "wrong input specification -> use help with -h -> restart again"
			exit
			;;
	esac
fi

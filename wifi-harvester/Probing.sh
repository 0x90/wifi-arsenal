#!/bin/sh
# Written By SYChua, syworks@gmail.com

LineWidth=80
FolderUnassociated="/SYWorks/Unassociated"
FolderSave="/SYWorks/Save"
FolderDB="/SYWorks/Database"
FolderTemp="/SYWorks/Temp"



Norm="\033[0m"
Bold="\033[1m"
Italic="\033[3m"
Uline="\033[4m"
Blink="\033[5m"
Outline="\033[6m"
Invert="\033[7m"
Nondisp="\033[8m"
Strike="\033[9m"
BoldOff="\033[22m"
ItalicOff="\033[23m"
UlineOff="\033[24m"
BlinkOff="\033[25m"
OutlineOff="\033[26m"
InvertOff="\033[27m"
NondispOff="\033[28m"
StrikeOff="\033[29m"
#Standard Color
Black=$Norm"\033[30m"
Red="\033[31m"
Green="\033[32m"
Brown="\033[33m"
Blue="\033[34m"
Purple="\033[35m"
Cyan="\033[36m"
Gray=$Norm"\033[37m"
DGray="\033[1;30m"
LRed="\033[1;31m"
LGreen="\033[1;32m"
Yellow="\033[1;33m"
LBlue="\033[1;34m"
Pink="\033[1;35m"
LCyan="\033[1;36m"
White="\033[1;37m"
#White=$Norm"\033[1;30m"
#Bold High Intensty
BI_Black="\033[0;90m"
BI_Red="\033[0;91m"
BI_Green="\033[0;92m"
BI_Yellow="\033[0;93m"
BI_Blue="\033[0;94m"
BI_Purple="\033[0;95m"
BI_Cyan="\033[0;96m"
BI_White="\033[0;97m"
#High Intensity
IBlack="\033[1;90m"
IRed="\033[1;91m"
IGreen="\e[1;92m"
IYellow="\033[1;93m"
IBlue="\033[1;94m"
IPurple="\033[1;95m"
ICyan="\033[1;96m"
IWhite="\033[1;97m"

CQuestion=$Bold$Green
CSelect=$Bold$Yellow
COption=$Bold$White
CTitle=$Bold$Red$Underline
CInfo1=$Bold$Blue
CInfo2=$Bold$Yellow
CInfo3=$Bold$Pink
CCaption=$Norm$Green
CCaptionB=$Bold$Green
CWarn=$Bold$Red
CTitle=$Red$Uline$Bold
CSubTitle=$Yellow$Uline$Bold
CText=$Norm$Gray
CDetail=$Bold$Cyan

#WIFI_MON="mon1"
STYPE="All"
#DELAY=1

Exiting(){
echo -e $White"Exiting..."

Close_Console $CONSOLE_PROBE 
clear
}

Drawline(){
	LnStr="_"
	if [ "$2" != "" ]; then 
		LnStr=$2;
	fi
	
	for lc in `seq 0 $1`; do echo -ne $LnStr; done;}

DisplayHead(){
clear
echo -e $Bold$Red"Probing Devices"
echo -e "~~~~~~~~~~~~~~~~"
echo -e $Norm$Yellow"Scripted 15 Jul 2011 - SYWorks, Updated 22 Aug 2011."
echo -e $Norm$Gray"The application will be using the Airodump-NG to detect on probing devices. It will then re-arrange and display for easier user viewing."
echo ""
View="1"
}

DisplayAirGraph(){
if [ -f $MonitoredSSIDFile ]; then 
	xterm -geometry 100x3-0-10 -iconic -bg black -fg white -fn 5x8 -title "Processing Graph" -e "cd /pentest/wireless/airgraph-ng; ./airgraph-ng.py -i $FolderUnassociated/NTA-01.csv -o $FolderUnassociated/Graph-CPG.png -g CPG; ./airgraph-ng.py -i $FolderUnassociated/NTA-01.csv -o $FolderUnassociated/Graph-CAPR.png -g CAPR ; exit; exec bash"
#	if [ -f $FolderUnassociated/Graph-CAPR.png ]; then 
#		xterm -geometry 49x3-255-10 -iconic -bg black -fg white -fn 5x8 -title "Display Client to AP Relationship" -e "display $FolderUnassociated/Graph-CAPR.png ; exit; exec bash" &
#	fi
	if [ -f $FolderUnassociated/Graph-CPG.png ]; then 
		xterm -geometry 49x3-0-10 -iconic -bg black -fg white -fn 5x8 -title "Display Common Probe Graph" -e "display $FolderUnassociated/Graph-CPG.png ; exit; exec bash" &
	fi
else
	prints $CWarn"File Not Found !.. Operation Cancelled !"
	echo ""
	PressAnyKey 5
fi
}

Convert_Signal(){
	SIGNAL=`echo $1| sed 's/-//g'`
	SIGNAL=$(($SIGNAL-1))
	if [ $SIGNAL -le 1 ]; then
		SIGNALSTR="E"
		SIGNALSTR2="  Unk  "
	fi
	if [ $SIGNAL -gt 1 ] && [ $SIGNAL -le 40 ]; then
		SIGNALSTR="VG"
		SIGNALSTR2="V.Good"
	fi
	if [ $SIGNAL -gt 40 ] && [ $SIGNAL -le 55 ]; then
		SIGNALSTR="G"
		SIGNALSTR2=" Good "
	fi
	if [ $SIGNAL -gt 55 ] && [ $SIGNAL -le 70 ]; then
		SIGNALSTR="A"
		SIGNALSTR2=" Avg  "
	fi
	if [ $SIGNAL -gt 70 ] && [ $SIGNAL -le 84 ]; then
		SIGNALSTR="P"
		SIGNALSTR2=" Poor "
	fi
	if [ $SIGNAL -ge 85 ] ; then
		SIGNALSTR="VP"
		SIGNALSTR2="V.Poor"
	fi
}


function ParseNotAssociated {
	DisplayHead
	i=0
	#Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
#	cl_array=`cat $FolderUnassociated/dump-01.csv | grep -a associated | awk -F , '{print $1 $2 $3 $4 $5 $6 $7}'`
#	cl_array=`cat $FolderUnassociated/dump-01.csv | grep -a associated`
	echo -e $Bold$Green"Detected Unassociated Probing Devices - $White" $STYPE
	echo -e $Norm$Green"Interface Used\t: $BI_Red$WIFI_MON"
	echo ""
	if [ "$View" == "" ]; then
		LineWidth=80
		echo -e $Bold$Red"SN\tDevice MAC\t\tFirst Found\t\tLast Seen"	
	else
		LineWidth=140
		echo -e $Bold$Red"SN\tDevice MAC\t\tFirst Found\t\tLast Seen\t\tPower\t\tPacket\tOUI Name$Yellow"	
	fi
	echo -ne $Norm$Yellow
	Drawline $LineWidth "~"
	echo ""

	if [ "$IndS" == "1" ]; then
		echo -e "Detected Unassociated Probing Devices" >> $AskSaveFile
		echo -e "SN\tDevice MAC\t\tFirst Found\t\tLast Seen\t\tPWR\tPackets"	 >> $AskSaveFile
	fi
	
#	cat $FolderUnassociated/dump-01.csv | grep -a -n Station | awk -F : '{print $1}'`

	cat $FolderUnassociated/NTA-01.csv | grep -a associated &> $FolderUnassociated/notassociated.csv
	while IFS=, read CLNMAC FTS LTS POWER PACKETS BSSID ESSID;do 
	i=$(($i+1))
	#echo -e " $Bold$Yellow"$i"$Bold$Green)\t"$CLNMAC"\t"$FTS"\t"$LTS"\t"$POWER"\t"$PACKETS"\t"$BSSID"\t[ $Bold$Yellow$ESSID$Green ]"
	POWER=`echo $POWER| sed 's/ //g'`
	PACKETS=`echo $PACKETS| sed 's/ //g'`
	ESSID=`echo $ESSID| sed 's/ \,/\,/g'`
	ESSID=`echo $ESSID| sed 's/\,/\ | /g'`
	NSESSID=`echo $ESSID| sed 's/ //g'`
	FTS=`echo $FTS`
	LTS=`echo $LTS`
	ESL=${#NSESSID}
	OUI=`echo $CLNMAC | sed 's/://g' | cut -c 1-6`
	OUIName=`cat $FolderDB/mac-oui.db | grep $OUI | awk '{print $2" "$3" "$4" "$5" "$6" "$7}'`
	OUIName=`echo $OUIName`
	Convert_Signal $POWER

	if [ "$FilterOn" == "1" ]; then
		PASS=0
		PASSCT=0
		if [ "$FilterMAC" != "" ]; then
			PASSCT=$((PASSCT+1))
			CLNMAC_A=`echo $CLNMAC | sed 's/://g'` 
			MACContain=`echo $CLNMAC_A | grep $FilterMAC`
			if [ "$MACContain" != "" ]; then
				PASS=$((PASS+1))
			fi
		fi
		if [ "$FilterOUI" != "" ]; then
			PASSCT=$((PASSCT+1))
			FilterOUIU=`echo $FilterOUI | tr 'a-z' 'A-Z'`
			OUINameU=`echo $OUIName | tr 'a-z' 'A-Z'`
			OUIContain=`echo $OUINameU | grep $FilterOUIU`
			if [ "$OUIContain" != "" ]; then
				PASS=$((PASS+1))
			fi
		fi
		if [ "$FilterESSID" != "" ]; then
			PASSCT=$((PASSCT+1))
			FilterESSIDU=`echo $FilterESSID | tr 'a-z' 'A-Z'` 
			ESSIDU=`echo $ESSID | tr 'a-z' 'A-Z'` 
			ESSIDContain=`echo $ESSIDU | grep $FilterESSIDU`
			if [ "$ESSIDContain" != "" ]; then
				PASS=$((PASS+1))
			fi
		fi


	fi

	if [ "$STYPE" == "All" ]; then
		if [ "$PASS" == "$PASSCT" ]; then
		if [ "$ESL" == "1" ]; then
			if [ "$View" == "" ]; then
				echo -e $Bold$Yellow"$i$Green)\t$Cyan$CLNMAC\t$Green$FTS\t$LTS"
				echo -e $Bold$Red"\tOUI\t:$White $OUIName"
				echo -e $Bold$Red"\tPower\t:$Green $POWER$Bold$Blue [ $Cyan$SIGNALSTR2$Blue ]\t\t$Red\tPacket\t:$Green $PACKETS"
				echo -ne $Norm$Gray
				Drawline $LineWidth "-"
				echo
			else
				echo -e $BoldOff$Norm$Yellow"$i$Green)\t$Cyan$CLNMAC\t$Green$FTS\t$LTS\t$POWER$Blue [ $Cyan$SIGNALSTR2$Blue ]$Green\t$PACKETS$White\t$OUIName$Yellow"
			fi

		else
			if [ "$View" == "" ]; then
				echo -e $Bold$Yellow"$i$Green)\t$Cyan$CLNMAC\t$Green$FTS\t$LTS$Yellow"
				echo -e $Bold$Red"\tOUI\t:$White $OUIName"
				echo -e $Bold$Red"\tPower\t:$Green $POWER$Bold$Blue [ $Cyan$SIGNALSTR2$Blue ]\t\t$Red$Red\tPacket\t:$Green $PACKETS"
				echo -e $Bold$Red"\tProbed\t: $Norm$Pink$ESSID$Yellow"
				echo -ne $Norm$Gray
				Drawline $LineWidth "-"
				echo
			else
				echo -e $Bold$Yellow"$i$Green)\t$Cyan$CLNMAC\t$Green$FTS\t$LTS\t$POWER$Blue [ $Cyan$SIGNALSTR2$Blue ]$Green\t$PACKETS$White\t$OUIName$Yellow"
				echo -e $Bold$Red"\tProbed\t: $Norm$Pink$ESSID$Yellow"
			fi
		fi
		fi
	fi

	if [ "$STYPE" == "No ESSID" ]; then
		if [ "$PASS" == "$PASSCT" ]; then
		if [ "$ESL" == "1" ]; then
			if [ "$View" == "" ]; then
				echo -e $Bold$Yellow"$i$Green)\t$Cyan$CLNMAC\t$Green$FTS\t$LTS"
				echo -e $Bold$Red"\tOUI\t:$White $OUIName"
				echo -e $Bold$Red"\tPower\t:$Green $POWER$Bold$Blue [ $Cyan$SIGNALSTR2$Blue ]\t\t$Red\tPacket\t:$Green $PACKETS"
				echo -ne $Norm$Gray
				Drawline $LineWidth "-"
				echo
			else
				echo -e $Bold$Yellow"$i$Green)\t$Cyan$CLNMAC\t$Green$FTS\t$LTS\t$POWER$Blue [ $Cyan$SIGNALSTR2$Blue ]$Green\t$PACKETS$White\t$OUIName$Yellow"
			fi
		fi
		fi
	fi

	if [ "$STYPE" == "With ESSID" ]; then
		if [ "$PASS" == "$PASSCT" ]; then
		if [ "$ESL" != "1" ]; then
			if [ "$View" == "" ]; then
				echo -e $Bold$Yellow"$i$Green)\t$Cyan$CLNMAC\t$Green$FTS\t$LTS"
				echo -e $Bold$Red"\tOUI\t:$White $OUIName"
				echo -e $Bold$Red"\tPower\t:$Green $POWER$Bold$Blue [ $Cyan$SIGNALSTR2$Blue ]\t\t$Red\tPacket\t:$Green $PACKETS"
				echo -e $Bold$Red"\tProbed\t: $Norm$Pink$ESSID$Yellow"
				echo -ne $Norm$Gray
				Drawline $LineWidth "-"
				echo
			else
				echo -e $Bold$Yellow"$i$Green)\t$Cyan$CLNMAC\t$Green$FTS\t$LTS\t$POWER$Blue [ $Cyan$SIGNALSTR2$Blue ]$Green\t$PACKETS$White\t$OUIName$Yellow"
				echo -e $Bold$Red"\tProbed\t: $Norm$Pink$ESSID$Yellow"
			fi
		fi
		fi
	fi
	if [ "$IndS" == "1" ]; then
		if [ "$ESL" == "1" ]; then
			echo -e "$i)\t$CLNMAC\t$FTS\t$LTS\t$POWER\t$PACKETS\t$OUIName" >> $AskSaveFile
		else
			echo -e "$i)\t$CLNMAC\t$FTS\t$LTS\t$POWER\t$PACKETS\t$OUIName"  >> $AskSaveFile
			echo -e "\tProbed : $ESSID" >> $AskSaveFile
		fi
	fi
#	echo "Probing : $ESSID"
	done < $FolderUnassociated/notassociated.csv
	if [ "$IndS" == "1" ]; then
			echo ""
			echo -e $White"Probing Devices Detail Saved to $Red$AskSaveFile$White ..."
			sleep 2
	fi
	IndS=0
	echo ""
	if [ "$FilterOn" == "1" ]; then
		echo -e $Pink$Uline"Filter On"$UlineOff
		if [ "$FilterMAC" != "" ]; then
			echo -e $White"MAC Filter\t:$Red "$FilterMAC
		fi
		if [ "$FilterESSID" != "" ]; then
			echo -e $White"ESSID Filter\t:$Red "$FilterESSID
		fi
		if [ "$FilterOUI" != "" ]; then
			echo -e $White"OUI Filter\t:$Red "$FilterOUI
		fi
	fi
	if [ "$View" == "" ]; then
		echo -ne $Norm$Blue
		Drawline $LineWidth
		echo ""
		echo ""

	echo -e $Bold$Red"X$Norm$DGray = Exit$Bold$Red\tA$Norm$DGray = All ESSID$Bold$Red\t\tN$Norm$DGray = No ESSID$Bold$Red\t\tE$Norm$DGray = With ESSID"
		echo -e $Bold$Red"P$Norm$DGray = Pause$Bold$Red\tS$Norm$DGray = Save Detail$Bold$Red\t\tT$Norm$DGray = Refresh Rate$Bold$Red\tV$Norm$DGray = Change View"
		echo -e $Bold$Red"F$Norm$DGray = Filter$Bold$Red\tC$Norm$DGray = Clear Filter$Bold$Red\tG$Norm$DGray = Probing Graph$Bold$Red"
	else
		echo -ne $Bold$Blue
		Drawline $LineWidth "~"
		echo ""
		echo -e $Bold$Red"X$Norm$DGray = Exit$Bold$Red\tA$Norm$DGray = All ESSID$Bold$Red\t\tN$Norm$DGray = No ESSID$Bold$Red\t\tE$Norm$DGray = With ESSID$Bold$Red\t\tP$Norm$DGray = Pause$Bold$Red\tT$Norm$DGray = Refresh Rate"
		echo -e $Bold$Red"F$Norm$DGray = Filter$Bold$Red\tC$Norm$DGray = Clear Filter$Bold$Red\tS$Norm$DGray = Save Detail$Bold$Red\t\tV$Norm$DGray = Change View$Bold$Red\t\tG$Norm$DGray = Probing Graph$Bold$Red"
	fi
	echo ""
	echo -ne $Norm$Green"Refreshing every $Bold$Red$DELAY$Norm$Green second..."
	any_key=""
	read -n1 -t $DELAY any_key
  	case $any_key in
		p|P) echo -e "$Bold\033[36m"
			read -s -n 1 -p "Paused - Press any Key to continue..";;
		e|E) STYPE="With ESSID";;
		n|N) STYPE="No ESSID";;
		a|A) STYPE="All";;
		s|S) SaveProbe;;
		t|T) SetRefresh;;
		g|G) DisplayAirGraph;;
		x|X) Exiting
			exit;;
		c|C)	FilterOn=""
			PASS=0
			PASSCT=0
			FilterMAC=""
			FilterESSID=""
			FilterOUI="";;
		v|V) 	if [ "$View" == "1" ]; then
				View=""
			else
				View="1"
			fi;;
		f|F) 	echo ""
			echo ""	
			echo -e $Yellow$Uline$Bold"Filter Options :$UlineOff "
			echo -e $Bold$White"1|m) MAC Filter"
			echo -e "2|s) ESSID Filter"
			echo -e "3|o) OUI Name Filter"
			echo -ne $CQuestion"Select Filter Option : $CSelect"
			read filteropt
			if [ "$filteropt" == "" ]; then
				any_key=""
			else
				echo ""
				case $filteropt in
					1|m|M) echo -ne $Green$Bold"Enter the MAC Address $Gray< Blank - Remove >$CQuestion : $Yellow$Bold"
						read FilterMAC
						if [ "$FilterMAC" != "" ]; then
							FilterMAC=`echo $FilterMAC | sed 's/://g' | sed 's/ //g' | sed 's/-//g'`
							FilterMAC=`echo $FilterMAC | tr '[a-z]' '[A-Z]'`
							FilterOn=1
						fi;;
					2|s|S) echo -ne $CQuestion"Enter the ESSID $Gray< Blank - Remove >$CQuestion : $CSelect"
						read FilterESSID
						if [ "$FilterESSID" != "" ]; then
							FilterOn=1
						fi;;
					3|o|O) echo -ne $CQuestion"Enter OUI Name $Gray< Blank - Remove >$CQuestion : $CSelect"
						read FilterOUI
						if [ "$FilterOUI" != "" ]; then
							FilterOn=1
						fi;;
				esac
			fi
			choice="";;
		*) ParseNotAssociated;;
	esac

ParseNotAssociated
	read choice
	if [ "$choice" == "" ]; then 
		ParseNotAssociated
	fi
}

SaveProbe(){
	SavFile="Probe-"$(date | awk '{print $3" "$2" "$6"-"$4}')
	SavFile=`echo $SavFile | sed 's/://g'`
	SavFile=`echo $SavFile | sed 's/ /./g'`
	IndS=0
	echo ""
	echo ""
	echo -n -e $Bold$Green"Enter the location and filename to be saved :$Gray < Default - $FolderSave/$SavFile >$Green : $Yellow" 
	read -p "" AskSaveFile;
	if [ "$AskSaveFile" == "" ]; then
		AskSaveFile=$FolderSave/$SavFile
		IndS="1"
	fi
	echo -e $White"Application will save the detail to $Red$AskSaveFile$White on next refresh"
	echo -e "$Bold\033[36m"
	read -s -n 1 -p "Press any Key to continue.."
}

Close_Console(){
	PID=$1 && shift
	until [ "$PID" == "" ];
	do
#		echo -n "Closing =$PID="
		kill $PID &> /dev/null
		PID=$1 && shift
	done
#	PressAnyKey
}


SetRefresh(){
	echo ""
	echo -ne $Bold$Green"Enter the refreshing rate in second, $Norm$Gray < Default - 5 > $BoldGreen : $Yellow" 
	read -p "" DELAY;
	if [ "$DELAY" == "" ]; then
		DELAY=5
	else
		if [ $((DELAY)) -eq 0 ]; then
			DELAY=5
		fi
	fi


}



DisplayHead
mkdir "/SYWorks" &> /dev/null
mkdir $FolderUnassociated &> /dev/null
mkdir $FolderSave &> /dev/null
mkdir $FolderDB &> /dev/null
mkdir $FolderTemp &> /dev/null


if [ "$1" == "" ]; then
	echo -ne $Bold$Green"Enter the capturing interface,$Norm$Gray Example - mon0 $BoldGreen : $Yellow" 
	read -p "" WIFI_MON;
	if [ "$WIFI_MON" == "" ]; then
		Exiting
	fi
else
	WIFI_MON=$1
fi
if [ "$2" == "" ]; then
	SetRefresh
else
	DELAY=$2
fi


rm $FolderUnassociated/*.* &> /dev/null
rm $FolderUnassociated/notas*.* &> /dev/null
#echo $1
#echo $2
#gnome-terminal --zoom=0.28  --geometry 0x0 -e "bash -c \"airodump-ng -w $FolderUnassociated/NTA -a $WIFI_MON; exec bash\"" &
CONSOLE_PROBE=`ps -eo pid,args | grep "Probing Unassociated Client Console" | cut -c 1-6`
Close_Console $CONSOLE_PROBE
#gnome-terminal --zoom=0.3 --geometry 10x10 --title "Probing Unassociated Client Console" -e "bash -c \"airodump-ng -w $FolderUnassociated/NTA -a $WIFI_MON; exec bash\"" &
xterm -geometry 100x3-0-0 -iconic -bg black -fg white -fn 5x8 -title "Probing Unassociated Client Console" -hold -e "airodump-ng -w $FolderUnassociated/NTA -a $WIFI_MON; exec bash" & 
echo $! >> $FolderTemp/PID
CONSOLE_PROBE=`ps -eo pid,args | grep "Probing Unassociated Client Console" | grep "xterm" | cut -c 1-6`

#gnome-terminal --geometry 100x50 --title "Probing Unassociated Client Console" -e "bash -c \"airodump-ng -w $FolderUnassociated/NTA -a $WIFI_MON; exec bash\"" &

#CONSOLE_PROBE=`ps -eo pid,args | grep "Probing Unassociated Client Console" | grep "gnome" | cut -c 1-6`


ParseNotAssociated


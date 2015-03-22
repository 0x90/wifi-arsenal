#!/bin/bash
clear;
echo "0===============================0";
echo "0 WPSPin.sh (2015) Rıza SABUNCU 0";
echo "0 github.com/rizasabuncu        0";
echo "0===============================0";
printf "\n\n";

MAC=$1

if [ -z $MAC ];

	then

	echo "0========   USAGE   ============0";
	echo "0 ./wpspin.sh 12456             0";
	echo "0===============================0";


	
else

	pin=$(echo "ibase=16; $MAC" | bc);
	chksum=$(echo "ibase=16; $MAC" | bc);

	i=0;

	for (( ; ; ))
	do
		if [ $chksum -eq 0 ]; then


			chksum=$(echo "(10-$i%10)%10" | bc);
			break;

		fi

		j=$(echo "$i+3*($chksum%10)" | bc);
		k=$(echo "$chksum/10" | bc);
		i=$(echo "$j+$k%10" | bc);
		chksum=$(echo "$k/10" | bc);

	done

	wpspin=$(echo "$pin$chksum");

	check=${#wpspin};

	if [ $check -gt 8 ];
		then

		wpspin=$(echo "$pin");

	fi

	echo "0========   RESULT  ============0";
	printf "Your WPS Pin : ";
	echo "$wpspin";
	printf "\n\n";

	
fi
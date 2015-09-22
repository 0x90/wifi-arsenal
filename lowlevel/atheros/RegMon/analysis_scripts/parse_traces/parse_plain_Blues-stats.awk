#!/usr/bin/gawk
# parse Minstrel-Blues Stats without mac
# Thomas Huehn 2012

BEGIN{
	#adapt fieldseperator to table
	FS = ","

	start_seq = 1;
	ratesize = 1;
	max_utility = 0;

	#check if header should be printed
	if (header == 1)
		print "timestamp minstrel max_utility datarate thr Pr r_Pr d_Pr s_Pr s_Pwr d_Pwr r_Pwr a_Pwr"

	#power mapping from Blues
	#dBm2uW[0]=1000;
	#dBm2uW[1]=1259;
	#dBm2uW[2]=1585;
	#dBm2uW[3]=1995;
	#dBm2uW[4]=2512;
	#dBm2uW[5]=3162;
	#dBm2uW[6]=3981;
	#dBm2uW[7]=5012;
	#dBm2uW[8]=6310;
	#dBm2uW[9]=7943;

	#TODO: Utility Funktion
	#function utility(T,P,W){
	#
	#	if (P >= 0 && P <= 9)
	#		P_mW = dBm2uW[P];
	#	if (P <= 19)
	#		P_mW = dBm2uW[P - 10]*10;
	#	if (P <= 29)
	#		P_mW = dBm2uW[P - 20]*100;
	#	if (P <= 39)
	#		P_mW = dBm2uW[P - 30]*1000;
	#}
}
{
#remove spaces from datarate field
sub(/^[[:blank:]]*/, "", $3)

#remove dot from timestamp field
sub(/\./, "", $1)

#typical values: in 5GHz it is 6MBit in 2,4GHz 1Mbit 
if (NR == 1){
	lowest_bit_rate=$3;
	timestamp = $1;
}

#print ouput after each round through all bitrates
if (NR !=1 && $3 == lowest_bit_rate){
	#print output file
	for (i = 1; i < 6; i++) {
		#printf("%d %s\n", timestamp, rate[i]);
		print(timestamp, rate[i]);
	}
	#reset roundsize
	roundsize = 1;
	#next roud's timestamp
	timestamp = $1;

	#1st rate
	if (index($2,"A") !=0){
		if (index($2,"x") !=0)
			max_utility = 1;
		#format: ratename, max_utility, datarate, thr, sampl_Pwr, ref_Pwr
		d_Pwr = $24 + 2;
		rate[1]=sprintf("%s %d %d %d %d %d %d %d %d %d %d %d", "1st-best", max_utility, $3*10, $4*10, $5*10, $21*10, $22*10, $23*10, $24, d_Pwr, $25, $26);
		max_utility = 0;
	}
	#2nd rate
	if (index($2,"B") !=0 ){
		if (index($2,"x") !=0)
			max_utility = 1;
		d_Pwr = $24 + 2;
		rate[2]=sprintf("%s %d %d %d %d %d %d %d %d %d %d %d", "2nd-best", max_utility, $3*10, $4*10, $5*10, $21*10, $22*10, $23*10, $24, d_Pwr, $25, $26);
		max_utility = 0;
	}
	#3rd rate
	if (index($2,"C") !=0 ){
		if (index($2,"x") !=0)
			max_utility = 1;
		d_Pwr = $24 + 2;
		rate[3]=sprintf("%s %d %d %d %d %d %d %d %d %d %d %d", "3rd-best", max_utility, $3*10, $4*10, $5*10, $21*10, $22*10, $23*10, $24, d_Pwr, $25, $26);
		max_utility = 0;
	}
	#4th rate
	if (index($2,"D") !=0 ){
		if (index($2,"x") !=0)
			max_utility = 1;
		d_Pwr = $24 + 2;
		rate[4]=sprintf("%s %d %d %d %d %d %d %d %d %d %d %d", "4th-best", max_utility, $3*10, $4*10, $5*10, $21*10, $22*10, $23*10, $24, d_Pwr, $25, $26);
		max_utility = 0;
	}
	#highest probability
	if (index($2,"P") !=0 ){
		if (index($2,"x") !=0)
			max_utility = 1;
		d_Pwr = $24 + 2;
		rate[5]=sprintf("%s %d %d %d %d %d %d %d %d %d %d %d", "high-pr", max_utility, $3*10, $4*10, $5*10, $21*10, $22*10, $23*10, $24, d_Pwr, $25, $26);
		max_utility = 0;
	}
}
else {
	roundsize = roundsize + 1;

	#1st rate
	if (index($2,"A") !=0){
		if (index($2,"x") !=0)
			max_utility = 1;
		#format: ratename, max_utility, datarate, thr, sampl_Pwr, ref_Pwr
		d_Pwr = $24 + 2;
		rate[1]=sprintf("%s %d %d %d %d %d %d %d %d %d %d %d", "1st-best", max_utility, $3*10, $4*10, $5*10, $21*10, $22*10, $23*10, $24, d_Pwr, $25, $26);
		max_utility = 0;
	}
	#2nd rate
	if (index($2,"B") !=0 ){
		if (index($2,"x") !=0)
			max_utility = 1;
		d_Pwr = $24 + 2;
		rate[2]=sprintf("%s %d %d %d %d %d %d %d %d %d %d %d", "2nd-best", max_utility, $3*10, $4*10, $5*10, $21*10, $22*10, $23*10, $24, d_Pwr, $25, $26);
		max_utility = 0;
	}
	#3rd rate
	if (index($2,"C") !=0 ){
		if (index($2,"x") !=0)
			max_utility = 1;
		d_Pwr = $24 + 2;
		rate[3]=sprintf("%s %d %d %d %d %d %d %d %d %d %d %d", "3rd-best", max_utility, $3*10, $4*10, $5*10, $21*10, $22*10, $23*10, $24, d_Pwr, $25, $26);
		max_utility = 0;
	}
	#4th rate
	if (index($2,"D") !=0 ){
		if (index($2,"x") !=0)
			max_utility = 1;
		d_Pwr = $24 + 2;
		rate[4]=sprintf("%s %d %d %d %d %d %d %d %d %d %d %d", "4th-best", max_utility, $3*10, $4*10, $5*10, $21*10, $22*10, $23*10, $24, d_Pwr, $25, $26);
		max_utility = 0;
	}
	#highest probability
	if (index($2,"P") !=0 ){
		if (index($2,"x") !=0)
			max_utility = 1;
		d_Pwr = $24 + 2;
		rate[5]=sprintf("%s %d %d %d %d %d %d %d %d %d %d %d", "high-pr", max_utility, $3*10, $4*10, $5*10, $21*10, $22*10, $23*10, $24, d_Pwr, $25, $26);
		max_utility = 0;
	}
}
}

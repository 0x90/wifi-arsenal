#!/usr/bin/gawk
# USAGE: cat tracefile.txt | gawk --non-decimal-data -f parse_trace.awk
# Thomas Huehn 2012

BEGIN{

	#mac clock rate, if not specifyed at script start, defaul=80211a=40MHz            
	if (clock == "")
		MHz = 40;
	else
		MHz = clock;

	#check if header should be printed
	if (header == 1)
	    print "ktime d_ktime d_tsf d_mac d_tx rel_tx d_rx rel_rx d_ed rel_ed d_idle rel_idl d_others rel_others noise rssi nav d_read e_mac_k e_mac_tsf reset tx_start tx_air rx_start rx_air burst_start burst_air";
}
{
#
if (NR == 1) {
	sub(/0*/,"",$1); 	#delete leading zeros
	time 		= $1
	full_tsf_old	= $2;	#64bit tsf in $2
	sub(/0*/,"",$2); 	#delete leading zeros
	tsf_1_old	= strtonum(sprintf("%d", "0x" $2));
    mac_old		= sprintf("%d", "0x" $3);
	tx_old		= sprintf("%d", "0x" $4);
	rx_old		= sprintf("%d", "0x" $5);
	ed_old		= sprintf("%d", "0x" $6);
	#noise
	noise_raw	= sprintf("%d", "0x" $8);
	noise		= -1 - xor(rshift(noise_raw, 19), 0x1ff);
    pot_reset	= 0;
	tx_start	= 0;
	tx_paket	= 0;
	tx_end		= 0;
	rx_start	= 0;
	rx_paket	= 0;
	rx_end		= 0;
	ed_start	= 0;
	ed_paket	= 0;
	ed_end		= 0;
	prev_error  = 0;
}
else if (NR > 1) {
	#check if valid input at timestamp
	if ($1 ~ /[^[:digit:]]/)
		next
	
	#delete leading zeros in kernel timestamp at $1 and tsf at $2 
	sub(/0*/,"",$1);
	full_tsf = $2;		#64bit tsf in $2
	sub(/0*/,"",$2);
	
    #kernel time_diff in usec
	if(prev_error == 0){
		if(strtonum($1) - strtonum(time) <= 0){
			k_time_diff	= "NA";
			prev_error	= 1;
		}
		else{ 
			k_time_diff  =  sprintf("%.0f",(strtonum($1) - strtonum(time))/1000);
		}
	}
	else {
		k_time_diff	= "NA";
		prev_error	= 0;
	}

	#tsf diff
	tsf_1 = strtonum(sprintf("%d", "0x" $2));
	if (tsf_1  > tsf_1_old){
		tsf_1_diff	= tsf_1 - tsf_1_old;
		#check plausibility of delta_tsf exeeds 2x k_time
		if (k_time_diff != "NA" && tsf_1_diff > k_time_diff * 2){
			tsf_1_diff	= "NA";
		}
	}
	else {
		tsf_1_diff	= "NA";
	}
	
	# read duration of our two MIB register readings in usec
	read_duration	= sprintf("%d", "0x" $7) - sprintf("%d", "0x" substr(full_tsf,9,8));

    #d_mac states
    if (sprintf("%d", "0x" $3) + 0 > mac_old + 0) {
		
		d_mac		= sprintf("%d", "0x" $3) - mac_old;
		
		#sending
		if (sprintf("%d", "0x" $4) - tx_old  <= d_mac +0){
	    	d_tx	= sprintf("%d", "0x" $4) - tx_old;
			rel_tx	= sprintf("%.1f",d_tx / d_mac *100);
		}
		else {
			d_tx 	= 0;
			rel_tx	= sprintf("%.1f",0);
		}
		
		#receiving
		if (sprintf("%d", "0x" $5) - rx_old <= d_mac){
			d_rx	= sprintf("%d", "0x" $5) - rx_old;
			rel_rx	= sprintf("%.1f",d_rx / d_mac *100);
		}
		else {
			d_rx 	= 0;
			rel_rx	= sprintf("%.1f",0);
		}
			
		#full busy
		if (sprintf("%d", "0x" $6) - ed_old <= d_mac){
			d_ed	= sprintf("%d", "0x" $6) - ed_old;
			rel_ed	= sprintf("%.1f",d_ed / d_mac *100);
		}
		else {
			d_ed 	= 0;
			rel_ed	= sprintf("%.1f",0);
		}

		#calculate channel idle states
		if (d_mac - d_ed > 0) {
			d_idle		= d_mac - d_ed;		
			rel_idle	= sprintf("%.1f",d_idle / d_mac *100);
		}
		else {
			d_idle		= 0;
			rel_idle	= sprintf("%.1f",0);
		}
	
		#calculate busy that is triggered from other sources but rx & tx
		if (d_ed - d_tx - d_rx > 0) {
			d_others	= d_ed - d_tx - d_rx;
			rel_others	= sprintf("%.1f",d_others / d_mac *100);
		}
		else {
			d_others	= 0;
			rel_others	= sprintf("%.1f",0);
		}			
    }
    else {
	    pot_reset	= 1;
	    d_mac		= sprintf("%d", "0x" $3);
	    d_tx		= sprintf("%d", "0x" $4);
	    d_rx		= sprintf("%d", "0x" $5);
	    d_ed		= sprintf("%d", "0x" $6);
		#validate input data in case of a reset
		if (d_mac - d_ed > 0)
			d_idle = d_mac - d_ed
		else
			d_idle = 0;
		if (d_ed - (d_tx + d_rx) > 0)
			d_others = d_ed - (d_tx + d_rx);
		else
			d_others = 0;

		if (d_mac > 0){
			rel_tx		= sprintf("%.1f",d_tx / d_mac *100);
			rel_rx		= sprintf("%.1f",d_rx / d_mac *100);
			rel_ed		= sprintf("%.1f",d_ed / d_mac *100);
			rel_idle	= sprintf("%.1f",d_idle / d_mac *100);
			rel_others	= sprintf("%.1f",d_others / d_mac *100);
		}
		else {
			rel_tx		= "NA";
			rel_rx		= "NA";
			rel_ed		= "NA";
			rel_idle	= "NA";
			rel_others	= "NA";
		}
    }
	
	#expected mac counts
	if (k_time_diff != "NA")
		k_exp_mac	= sprintf("%.0f", k_time_diff * MHz);
	else
		k_exp_mac 	= "NA";

	if (tsf_1_diff  != "NA")
	    	tsf_exp_mac = tsf_1_diff * MHz;
	else
		tsf_exp_mac = "NA";

# TODO: this pkt. estimation makes only sense if sample freq. is sufficient , we could check at least for plausibility
	#potential tx packet borders
	if(d_tx > 0 && tx_paket == 0){
		tx_start	= 1;
		tx_paket	= 1;
		tx_airtime	= d_tx + (read_duration - 2) * MHz;
	}
	else if (d_tx == d_mac && tx_paket == 1){
		tx_start	= 0;
		#check if MIB reset
		if (pot_reset == 1)
			tx_airtime	= tx_airtime + tsf_exp_mac;
		else
			tx_airtime	= tx_airtime + d_tx + (read_duration - 2) * MHz;
	}
	else if (d_tx < d_mac && tx_paket == 1){
		tx_start	= 0;
		tx_paket	= 0;
		tx_airtime	= tx_airtime + d_tx + (read_duration - 2) * MHz;
		tx_end		= sprintf("%.0f",tx_airtime / MHz);
		tx_airtime	= 0;
	}
	else if (d_tx == 0 && tx_paket == 0){
		tx_start	= 0;
		tx_paket	= 0;
		tx_end		= 0;
		tx_airtime	= 0;
	}
	
	#potential rx packet borders
	if(d_rx > 0 && rx_paket == 0){
		rx_start	= 1;
		rx_paket	= 1;
		rx_airtime	= d_rx + (read_duration - 2) * MHz;
	}
	else if (d_rx == d_mac && rx_paket == 1){
		rx_start	= 0;
		#check if MIB reset
		if (pot_reset == 1)
			rx_airtime	= rx_airtime + tsf_exp_mac;
		else
			rx_airtime	= rx_airtime + d_rx + (read_duration - 2) * MHz;
	}
	else if (d_rx < d_mac && rx_paket == 1){
		rx_start	= 0;
		rx_paket	= 0;
		rx_airtime	= rx_airtime + d_rx + (read_duration - 2) * MHz;		
		rx_end		= sprintf("%.0f",rx_airtime / MHz);
		rx_airtime	= 0;
	}
	else if (d_rx == 0 && rx_paket == 0){
		rx_start	= 0;
		rx_paket	= 0;
		rx_end		= 0;
		rx_airtime	= 0;
	}

	#potential interference burst borders
	if(d_others > 0 && others_burst == 0){
		others_start	= 1;
		others_burst	= 1;
		others_airtime	= d_others + (read_duration - 2) * MHz;
	}
	else if (d_others == d_mac && others_burst == 1){
		others_start	= 0;
		#check if MIB reset
		if (pot_reset == 1)
			others_airtime	= others_airtime + tsf_exp_mac;
		else
			others_airtime	= others_airtime + d_others + (read_duration - 2) * MHz;
	}
	else if (d_others < d_mac && others_burst == 1){
		others_start	= 0;
		others_burst	= 0;
		others_airtime	= others_airtime + d_others + (read_duration - 2) * MHz;
		others_end		= sprintf("%.0f",others_airtime / MHz);
		others_airtime	= 0;
	}
	else if (d_others == 0 && others_burst == 0){
		others_start	= 0;
		others_burst	= 0;
		others_end		= 0;
		others_airtime	= 0;
	}

    #noise calculation
	noise_raw	= sprintf("%d", "0x" $8);
	noise		= -1 - xor(rshift(noise_raw, 19), 0x1ff);
	
	#rssi calculation
	rssi = sprintf("%d", "0x" $9);

	#nav
	nav = sprintf("%d", "0x" $10);

	#final print
	print $1 , k_time_diff, tsf_1_diff, d_mac, d_tx, rel_tx, d_rx, rel_rx, d_ed, rel_ed, d_idle, rel_idle, d_others, rel_others, noise, rssi, nav, read_duration, k_exp_mac, tsf_exp_mac, pot_reset, tx_start, tx_end, rx_start, rx_end, others_start, others_end

	#refresh lines
	time_old	=time;
	time 		= $1;
	tsf_1_old	= strtonum(sprintf("%d", "0x" $2));
    mac_old		= sprintf("%d", "0x" $3);
	tx_old		= sprintf("%d", "0x" $4);
	rx_old		= sprintf("%d", "0x" $5);
	ed_old		= sprintf("%d", "0x" $6);
	pot_reset	= 0;
	tx_end		= 0;
	rx_end		= 0;
	ed_end		= 0;
}

}
END{

}

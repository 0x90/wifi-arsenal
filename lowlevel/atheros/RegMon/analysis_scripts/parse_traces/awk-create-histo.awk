BEGIN {
meet=0;
}

/bits\/sec/ {  
thr = $7;
jitter = $9;
if( $8 == "Mbits/sec" ) print MOD, TX, thr*1000, jitter;
if( $8 == "Kbits/sec" ) print MOD, TX, thr, jitter;
if( $8 == "bits/sec" ) print MOD, TX, thr/1000, jitter;
meet = 1;
 }

END {
if(meet == 0)
	print SENS, MOD, TX, 0, 0;
}

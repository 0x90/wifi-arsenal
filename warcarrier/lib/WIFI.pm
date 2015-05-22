#!/usr/bin/perl -w
# This will return an array of hashes with 
# information that we want (BSSIDs only, etc)
use strict;
package lib::WIFI;
sub aps{
	my @lines = `cat $_[1] | tr -cd '\11\12\15\40-\176'`; # get rid of bin crap
	my @APs=(); # Array of hashes of AP data
	foreach (@lines){ 
		if($_ =~ m/^[A-F0-9]{2,}:/){
			$_ =~ s/,\s+/,/g; # WTF kind os csv is this?
			my @spltAPs=(split(/,/,$_)); # split the line up
			my ($ls,$lm,$lh) = localtime; # local time
			$spltAPs[2] =~ s/.* //;
			my ($rh,$rm,$rs) = split(/:/,$spltAPs[2]); # report time	
			foreach($rs,$rm,$rh){ $_ =~ s/^0//; }
			if(($lh > $rh && $lm <= 1)||($lh == $rh && (($lm - $rm) < 2))){ # kinda crazy!
				my $hash = {}; # im fuckkmning druibnk.
				$hash->{'BSSID'} = $spltAPs[0];
				if($spltAPs[13] && ($spltAPs[13] =~ m/[0-9A-Z]/i)){
					$hash->{'ESSID'} = $spltAPs[13];
				}else{
					$hash->{'ESSID'} = 'NULL'; # for binary garbage that leaks from airodump-ng
				}
				$hash->{'CH'} = $spltAPs[3]; # channel
				$hash->{'SEC'} = $spltAPs[5]; # Security Type
				$hash->{'PWR'} = $spltAPs[8]; # Power Level in dbm
				push (@APs,$hash); # done creating hash, push into array
			}
		}elsif($_ =~ m/^Stat/){
			last; # got to the stations, we are done reading the file.
		}
	}	
	return @APs;
}
return 1;

#!/usr/bin/perl

use strict;

my $iterator = 0;

while (<>) {
    
    my @tokens = split(/\s+/);

    if ($iterator == 0) {
	# We do not want to mess up the column titles that
	# tshark wrote into the first row
	$tokens[0] =~ s/\./_/g;
	print "$tokens[0],date,";

	my $argnum;
	foreach $argnum (1 .. $#tokens-1) {
	    $tokens[$argnum] =~ s/\./_/g;
            print "$tokens[$argnum],"
        }
        $tokens[$#tokens] =~ s/\./_/g;
	print "$tokens[$#tokens]\n";

	$iterator = 1;
    
    } else {
	
	$tokens[1] =~ s/,/-/g;
	my $date = $tokens[0] . "-" . $tokens[1] . $tokens[2];

	$tokens[3] = &read_time($tokens[3]);
	print "$tokens[3],";

	print "$date,";

	my $argnum;
	foreach $argnum (4 .. $#tokens-1) {
	    print "$tokens[$argnum],";
	}
	print "$tokens[$#tokens]\n";
    }
}


sub read_time($) {

    my @tokens = split(/:/, shift);

    return ($tokens[0]*60 + $tokens[1])*60 + $tokens[2];
}

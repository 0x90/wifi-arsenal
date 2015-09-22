#!/usr/bin/perl

#use strict;
use Switch;

use constant UINT_MAX => 2**32-1;
use constant INT64_MIN => -2**63;
use constant INT64_MAX => 2**63-1;

use constant UNKNOWN => 0;
# Default mode in first iteration (record all mac addresses):
use constant READ_NEIGHBORS => 1;
# As we spot the first global section, we record its structure:
use constant READ_GLOBAL_FIELDS => 2;
# As we spot the first neighbor section, we record its structure:
use constant READ_NEIGHBOR_FIELDS => 3;


use constant WRITE_TO_GLOBAL_OUT => 4;
use constant WRITE_TO_NB_OUT => 5;


# Specify a trace file and the destination path of the parsed trace
($#ARGV == 1) or die "Usage ./process_config_trace.pl [input file] [output path]\n";                                                                                                             
my %mac_to_host = ();
$mac_to_host{"00:0B:6B:2C:FC:57"} = "af";
$mac_to_host{"00:0B:6B:2C:FC:44"} = "a";
$mac_to_host{"00:0B:6B:2C:FC:38"} = "bib";
$mac_to_host{"00:0B:6B:2C:FC:4F"} = "c";
$mac_to_host{"00:0B:6B:2C:FC:2B"} = "eb";
$mac_to_host{"00:0B:6B:2C:FC:5C"} = "en";
$mac_to_host{"00:0B:6B:2C:FC:5F"} = "ew";
$mac_to_host{"00:0B:6B:2C:FC:32"} = "hft";
$mac_to_host{"00:0B:6B:2C:EE:BA"} = "ma";
$mac_to_host{"00:0B:6B:2C:FC:04"} = "sg";
$mac_to_host{"00:0B:6B:2C:EE:C0"} = "tc";
$mac_to_host{"00:0B:6B:2C:FC:0B"} = "tel";
$mac_to_host{"00:0B:6B:2C:EE:CA"} = "vws";


$mac_to_host{"00:0B:6B:84:B0:30"} = "tel-16-1";
$mac_to_host{"00:0B:6B:84:B4:A0"} = "tel-16-2";
$mac_to_host{"00:0B:6B:84:B5:DE"} = "tel-16-3";
$mac_to_host{"00:0B:6B:84:B3:A6"} = "tel-16-4";
$mac_to_host{"00:0B:6B:84:B3:88"} = "tel-16-5";

$mac_to_host{"00:0B:6B:84:B3:94"} = "tel-17-1";
$mac_to_host{"06:0B:6B:84:B2:7B"} = "tel-17-2";


# Trace file name:
my $realname = `basename $ARGV[0]`;
my @name = split(/\./, "$realname");
my $NAME=$name[0];
my $DELEMETER=",";

my $PATH=$ARGV[1];

if ($PATH !~ m/.*\/$/) {
    $PATH = $PATH . "/";
}

my $global_result_file = "$PATH" . "$NAME" . "-global.csv";

# Array to record occuring neighbor mac addresses during
# first iteration.
my %sections= ();

# We use these arrays to record the names of the fields
# (which also represents the order of the fields in the
# wprobe trace) as well as the length of the output vector.
# We employ the length of the output vector to distinguish 
# whether we are dealing with a stats vector, tx/rx tuple or
# a simple value.
#my @global_fields;
#my @neighbor_fields;
my %global_fields = ();
my %neighbor_fields = ();

my $is_first_global_section = 1;
my $is_first_neighbor_section = 1;


# fixup for wprobe string
my $timelen = 0;

# First iteration:
# * Check if the trace contains neighbor sections
# * Get fields of global sections
# * Get fields of neighbor sections
# * Get list of sections (MAC addresses)

sub parse_values {
	# hash is a regular hash
	# key is a string
	# value is a sting einther containg zero 
	my ($hash, $key, $value) = @_;


	my @array = split (/;/, $value);

	switch ($#array+1) {
		case (6) {
			$hash->{$key} = $array[0];
			$hash->{"$key"."_avg"} = $array[1];
			$hash->{"$key"."_dev"} = $array[2];
			$hash->{"$key"."_n"} = $array[3];
			$hash->{"$key"."_sum"} = $array[4];
			$hash->{"$key"."_sumq"} = $array[5];
		}
		case (2) {
			$hash->{$key."_tx"} = $array[0];
			$hash->{$key."_rx"} = $array[0];
		}
		case (1) {
			$hash->{$key} = $array[0];
		}
		else {
			print "found $key @array:";
			print "no vaild value format found \n";
		}
	}
}

my $parse_mode = READ_NEIGHBORS;

open IN, $ARGV[0];

while (<IN>) {

	switch ("$_") {

		case (m/^\s/){
		}

		case (m/global/) {
			$parse_mode = READ_GLOBAL_FIELDS;
			next;
		}

		case (m/(([0-9a-fA-F]{2}[:-]{1}){5}([0-9a-fA-F]{2}))/) {
			my $candidate_mac = $_;
			chomp($candidate_mac);
			$sections{$candidate_mac}="";

			$parse_mode = READ_NEIGHBOR_FIELDS;
			next;
		} else {
			my @tokens = split(/\=/);
			if ($tokens[0] !~ m/\[/) {
				switch ($parse_mode) {
					chomp($tokens[1]);
					my @sub_fields = split(/\;/, $tokens[1]);
					my $len = $#sub_fields + 1;
					case (READ_GLOBAL_FIELDS) {
						# record field name and length of output vector
						if ($tokens[0] !~ m/timestamp/) {
							parse_values(\%global_fields,$tokens[0], $tokens[1]);
							# clear stats and split timestamp for wprobe stats
							for my $key (keys %global_fields){
								if ($global_fields{"timesec"}) {
									$timelen=length($global_fields{"timesec"});
								}
								$global_fields{$key} = "";
							}
#							$global_fields{$tokens[0]} = "";
						}
					}
					case (READ_NEIGHBOR_FIELDS) {
						# record field name and length of output vector
						parse_values(\%neighbor_fields,$tokens[0], $tokens[1]);
#						$neighbor_fields{$tokens[0]} = "";
					} else {
						next;
					}
				}
			}
		}
	}
}
close IN;

# Write column titles into the global result file
open GLOBAL_OUT, ">$global_result_file";

# Print out the global colum names in the header of the output
print GLOBAL_OUT "timestamp";
for my $key (sort keys %global_fields) {
	if ($key !~ m/timestamp/) {
		print GLOBAL_OUT "$DELEMETER $key";
	}
}
close GLOBAL_OUT;


# Create hash map for sections
for my $neighbor (sort keys %sections) {
	print $neighbor;
	my $tmp = $neighbor;
	$tmp = substr $tmp, 1, 17;
	$tmp = uc($tmp);
	$sections{$neighbor} = [$PATH . $NAME."-neighbor-" . $mac_to_host{$tmp}.".csv"];

	print "$neighbor: $sections{$neighbor}[0]\n";

	# Write column titles into neighbor files
	open NB_OUT, ">>$sections{$neighbor}[0]";

	print NB_OUT "timestamp";
	for my $key (sort keys %neighbor_fields) {
		chomp($key);
			print NB_OUT "$DELEMETER $key";
	}
	close NB_OUT;
}

# Second iteration:
# * Sort stuff into global and neighbor files
my $write_mode = "UNKNOWN";

my %clean_fields = ();
open GLOBAL_OUT, ">>$global_result_file";
my $is_global_out = 1;
open IN, $ARGV[0];
while (<IN>) {
	if (m/^\s+/) {
		next;
	}
    my @tokens = split(/\=/);
    chomp($tokens[0]);
    chomp($tokens[1]);

    switch ("$tokens[0]") {

	case (m/\[global\]/) {
	    if ( !($write_mode eq "UNKNOWN")) {
			# write global stats to file and store new global fiels as the second array element
			my %tmp_fields = ();
			open GLOBAL_OUT, ">>$global_result_file";
			for my $key ( sort keys %{$sections{"global"}[1]}) {
				print GLOBAL_OUT "$DELEMETER ".$sections{"global"}[1]{$key};
			}
			close GLOBAL_OUT;

			# write neighbor stats to output and store new neighbor fields in the second array element
			for my $neighbor (sort keys %sections) {
				if ( !($neighbor eq "global") ) {
					open NB_OUT, ">>$sections{$neighbor}[0]";
					for my $key (sort keys %{$sections{$neighbor}[1]}) {
						print NB_OUT "$DELEMETER ".$sections{$neighbor}[1]{$key};
					}
					close NB_OUT;
				}
			}
		}
		#%clean_fields = %global_fields;
		foreach my $neighbor (keys %sections) {
			%{$sections{$neighbor}[1]} = %neighbor_fields;
		}
		$write_mode = "global";
		%{$sections{$write_mode}[1]} = %global_fields;
	}

	case (m/(([0-9a-fA-F]{2}[:-]{1}){5}([0-9a-fA-F]{2}))/) {
		$write_mode = $tokens[0];
	}

	case (m/timestamp/) {
    		$tokens[1] =~ s/\s*$//g;
		if ( $write_mode eq "UNKNOWN" ) {
			next;
		}
		chomp($tokens[1]);
		my $timestamp = $tokens[1];
		if ($timelen) {
			my $seconds=substr $tokens[1], 0, $timelen-1;
			my $useconds=substr $tokens[1], $timelen, length($tokens[1]-1);
			$timestamp=$seconds.".".$useconds;
		}
#		$timestamp = $tokens[1]; # / 1000000;

		open GLOBAL_OUT, ">>$global_result_file";
		print GLOBAL_OUT "\n$timestamp";
		close GLOBAL_OUT;

		for my $neighbor (keys %sections) {
			if ( !($neighbor eq "global")) {
				open NB_OUT, ">>$sections{$neighbor}[0]";
				print NB_OUT "\n$timestamp";
				close NB_OUT;
			}
		}
	} else {
    		$tokens[1] =~ s/\s*$//g;
		if ( $write_mode eq "UNKNOWN" ) {
			next;
		}
		parse_values(\%{$sections{$write_mode}[1]},$tokens[0], $tokens[1]);
#		$sections{$write_mode}[1]{$tokens[0]} = $tokens[1];
	}
    }
}


sub subtract_counters {

    if (($_[0] > 0 && $_[1] < 0) ||
	($_[0] < 0 && $_[1] > 0)) {
	print "Warning: Both of the arguments should be negative or non-negative\n";
    }

    if ($_[1] < $_[0]) {
	return UINT_MAX - $_[1] + $_[0];
    } else {
	return $_[1] - $_[0];
    }
}


sub subtract_previous_stats {

    my @diff = (0, 0, 0, 0, 0, 0);

    foreach my $i (0 .. 5) {
	if ($i < 3) {
	    $diff[$i] = $_[$i+6];
	}
	
	if ($i == 3) {
	    if ($_[$i+6] < $_[$i]) {
		$diff[$i] = UINT_MAX - $_[$i] + $_[$i+6];
	    } else {
		$diff[$i] = $_[$i+6] - $_[$i];
	    }
	}

	if ($i > 3) {
	    if (($_[$i] > 0 && $_[$i+6] < 0) ||
		($_[$i] < 0 && $_[$i+6] > 0)) {
		print "Warning: Both of the arguments should be negative or non-negative\n";
	    }

	    if ($_[$i] > 0 && $_[$i+6] > 0) {
		if ($_[$i+6] < $_[$i]) {
		    $diff[$i] = INT64_MAX - $_[$i] + $_[$i+6];
		} else {
		    $diff[$i] = $_[$i+6] - $_[$i];
		}
	    }
		
	    if ($_[$i] < 0 && $_[$i+6] < 0) {
		if ($_[$i+6] > $_[$i]) {
		    $diff[$i] = INT64_MIN - $_[$i] + $_[$i+6];
		} else {
		    $diff[$i] = $_[$i+6] - $_[$i];
		}
	    }
	}    
    }  
    return @diff;
}

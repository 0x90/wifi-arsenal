#!/usr/bin/perl -w

use strict;
use constant COUNTER_MAX => "FFFFFFFF";
use constant COUNTER_THRESHOLD	 => "FCB94400";
use Getopt::Long;
use Data::Dumper;

my %opt;
GetOptions(\%opt, "columns=s", "trace=s", "mac_mhz=i");
$opt{mac_mhz} = 40 unless defined($opt{mac_mhz});

my $threshold = 2 ** 32 - $opt{mac_mhz} * (10 ** 6);

my $overflow = 0;

my @columns;
my @is_counter_register;
my @calc_noise_offset = ();
my @counter_register_state;
my $argnum = 0;


# ARGVs at odd positions are our columns'/registers' names
# ARGVs at even positions tell us whether we have a counter register or not
# Our very last ARGV is the file to parse
my @colargs = split /\s+/, $opt{columns};

my $c = 0;
while ($opt{columns} =~ m/(\w*)\s+(\d+)\s+(\d+)/g) {
	push @columns, "$1";
	push @is_counter_register, "$2";
	push @calc_noise_offset, "$3";
}

#foreach my $arg (@colargs) {
#    if ($argnum % 2 == 0) {
#	push(@columns, $arg);
#    } else {
#	push(@is_counter_register, $arg);
#    }
#    $argnum++;
#}
#print "\n";

# print column titles
my $column;
#foreach $column (0 .. $#columns) {
#    if ($column == $#columns) {
#	print "$columns[$column]\n";
#    } else {
#	print "$columns[$column],";
#    }
#}
print join(",", @columns).",potential_reset,expected_mac_count\n";

#print "$ARGV[$#ARGV]\n";

my $fh;
if (!defined($opt{trace})) {
	$fh = \*STDIN;
} else {
	open FILE, $opt{trace};
	$fh = \*FILE;
}

my $init = 1;
my $ignore_diff = 0;
my $time_before = 0;

while (<$fh>) {
    my @tokens = split(/\s+/);
    if ($init == 1) {
	# in the first iteration, we need to put the counter registers initial
        # state into the counter_register_state array
	foreach $argnum (0 .. $#is_counter_register) {
	    if ($is_counter_register[$argnum] == 1) {
		$counter_register_state[$argnum] = $tokens[$argnum];
	    } else {
		$counter_register_state[$argnum] = 0;
	    }
	    $time_before = $tokens[0] if ($argnum == 0);
	}
	
	$init = 0;

    } else {

	#print the timestamp
    	my @resultbuf = ("$tokens[0]");
	my $time_diff = $tokens[0] - $time_before;
	$time_before = $tokens[0];
	my $potential_reset = 0;
	# if the current register is a counter register, subtract the registers
	# previous state and print the difference, otherwise just convert the
	# value to dec and print it 
	foreach $argnum (1 .. $#is_counter_register) {
		if ($is_counter_register[$argnum] == 1) {
			my $reg_old = hex($counter_register_state[$argnum]);
			my $reg_new = hex( $tokens[$argnum]);
			my $diff = &diff($reg_old, $reg_new, $argnum);
			push @resultbuf, "$diff";
			$potential_reset = 1 if ($argnum == 1 && ($reg_new - $reg_old) < 0 && $reg_old < $threshold);
#			print "reset detected, old: $reg_old vs. new: $reg_new diff: $diff threshold: ".hex(COUNTER_THRESHOLD)."\n" if ($argnum == 1 && $potential_reset == 1);  
			$counter_register_state[$argnum] = $tokens[$argnum];
		} else {
			my $value = hex(substr($tokens[$argnum], 2, 8));
			if ($calc_noise_offset[$argnum] == 0) {
				push @resultbuf, "$value";
			}
			# Berechnung des noise floors aus dem cca register, wenn 2. argument beim parser start = 2 ist
			if ($calc_noise_offset[$argnum] == 1) {
				my $shifted = -1 - (($value >> 20) ^ hex("0x1ff"));
				push @resultbuf, "$shifted";
			}
		}
	}
	my $expected_mac_count = int($time_diff * $opt{mac_mhz} * (10 ** 6));
	push @resultbuf, "$potential_reset", "$expected_mac_count";
	print join(",",@resultbuf)."\n";
    }
}

sub diff {
	my ($r_b4, $r_now, $arg) = @_;
	my $r_diff = $r_now - $r_b4;
	my $res;
	# if (NOT on maccounter row AND diff < 0) OR (on maccounter row AND diff < 0 AND old_register < threshold)
	$res = $r_now if (($arg != 1 && $r_diff < 0) || ($arg == 1 && $r_diff < 0 && $r_b4 < $threshold));
	# if (maccounter AND diff < 0 AND old_register >= threshold)
	$res = (hex(COUNTER_MAX) - $r_b4 + $r_now) if ($arg == 1 && $r_diff < 0 && $r_b4 >= $threshold);
	# else
	$res = $r_diff unless defined($res);
#	print "diff: $r_now - $r_b4 = $res\n" if ($arg == 1);
	return $res;
}


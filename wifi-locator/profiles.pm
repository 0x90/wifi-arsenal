#!/usr/bin/perl

use XML::Simple;
use Data::Dumper;
use strict;
use warnings;
my $debug=1;

my @profiles;
my $xml = new XML::Simple;

sub import_profile_data{
	my $chipset = shift;
	
	my @files = <profiles/*>;
	foreach my $file (@files){
		if($file =~ m/^profiles\/$chipset\_([0-9]+)_([0-9]+).xml/){
			my ($x,$y) = ($1, $2);
			if ($debug) {print "Attempting import of $file";}
			my $data = $xml->XMLin($file);
			my @cells;

			#Populate array of cells
			foreach my $cell (@{$data->{cell}}){
		        	my %current_cell = xml_cell_to_hash_cell($cell);
				push(@cells,\%current_cell);
                	}
			my %profile = ();
			$profile{'x'} = $x;
			$profile{'y'} = $y;
			$profile{'cells'} = \@cells;
			push(@profiles,\%profile);
			if ($debug) {print "... done.\n";}	
		}
	}
	return \@profiles;

}

#current xml keys: 'frequency', 'signal', 'address', 'quality', 'essid', 'noise'
sub xml_cell_to_hash_cell {     
        my $cell = shift;
        my %current_cell = ();
        $current_cell{'frequency'} = $cell->{frequency};
        $current_cell{'signal'} = $cell->{signal};
        $current_cell{'signal'} =~ s/ dBm//; #for easy maths
        $current_cell{'address'} = $cell->{address};
        $current_cell{'quality'} = $cell->{quality};
        $current_cell{'essid'} = $cell->{essid};
        $current_cell{'noise'} = $cell->{noise};
	$current_cell{'noise'} =~ s/ dBm//;
        return %current_cell;
}

1;

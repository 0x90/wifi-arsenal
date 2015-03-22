#!/usr/bin/perl

use XML::Simple;
use Data::Dumper;
use strict;
use warnings;
use profiles;

#Could take a while.
print "Starting profile import...\n";
my @profiles = @{import_profile_data("rt2860")};
print "Done with profile import.\n";
my $xml = new XML::Simple;

open(my $XML_INPUT, "./iwlist ra0 scan |");

my $data = $xml->parse_fh($XML_INPUT);

my @cells;

#Populate array of cells
foreach my $cell (@{$data->{cell}}){
	my %current_cell = xml_cell_to_hash_cell($cell);
	push(@cells,\%current_cell);
}

my @deltas;

my ($best_delta,$best_x,$best_y) = (-99999,0,0);
#Generate change value.
#Somewhat verbose in order to prevent the array of pointers to hashes with pointers 
#to arrays of pointers to hashes from being a total goat screw.
foreach my $profile_ptr (@profiles){
	my %profile = %{$profile_ptr};
	my @profile_cells = @{$profile{'cells'}};
	my $delta_sum=0;
	foreach my $profile_cell (@profile_cells){
		foreach my $cell_ptr (@cells){
			my %cell = %{$cell_ptr};
			if(${$profile_cell}{'address'} eq $cell{'address'}){
				#This algorithm is kind of dumb but should work fine until I whip up something sexier.
				${$profile_cell}{'delta'} = abs($cell{'signal'}-${$profile_cell}{'signal'}) + 
					abs($cell{'noise'}-${$profile_cell}{'noise'})-90;
				$delta_sum-=${$profile_cell}{'delta'};
#				print "updated inbetween dsum to:$delta_sum\n";
			}
		}
	}

	my %entry = ();
	$entry{'x'}=$profile{'x'};
	$entry{'y'}=$profile{'y'};
	$entry{'delta'}=$delta_sum;
	print "My delta sum is $delta_sum\n";
	$profile{'delta_sum'}=$delta_sum;
	push(@deltas,\%entry);

	if($profile{'delta_sum'}>$best_delta && $profile{'delta_sum'}!=0){
		$best_x = $profile{'x'};
		$best_y = $profile{'y'};
		$best_delta = $profile{'delta_sum'};
	}
}

#my @sorted_deltas = sort { ${$a}{'delta_sum'} <=> ${$b}{'delta_sum'} } @deltas;
foreach my $d (@deltas){
#	print ${$d}{'delta_sum'},"\n";
}

print "Best delta value: $best_delta\nClosest x: $best_x\nClosest y: $best_y\n";

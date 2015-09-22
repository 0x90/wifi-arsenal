#!/usr/bin/perl
use strict;
my $main_path="PARAM_main_path";
my $result_path="PARAM_result_path";
my %new;
my %old;
my @node_ip=(
	"10.10.1.10",
	"10.10.2.10",
	"10.10.4.10",
	"10.10.5.10",
	"10.10.6.18",
	"10.10.7.10",
	"10.10.8.18",
	"10.10.9.10",
	"10.10.10.18",
	"10.10.12.26",
	"10.10.13.10",
);
my @tx_power;
my $tx_number = 11;
my @datarate=(6,9,12,18,24,36,48,54);
my @direction=(
	"MA-to-EB",
#	"EB-to-MA",
);

my @parameters = (
	"noise",
	"phy_busy",
	"phy_tx",
	"phy_rx",
	"frames",
	"less_4",
	"less_8",
	"less_12",
	"less_16",
	"less_20",
	"less_24",
	"less_28",
	"less_32",
	"less_36",
	"bigger_36",
	"beacon",
	"data",
	"other",
	"less_100",
	"less_200",
	"less_600",
	"less_1200",
	"big"
);

my $i;
for($i=0; $i<=$tx_number; $i++) {
	$tx_power[$i] = $i*2 + 1;
}

sub reset_data() {
	foreach my $key (@parameters) {
		$old{$key} = [];
		$new{$key} = [];
	}
}

sub calculate_results($$) {
	my $prefix = shift;
	my $first = shift;
	my %diff;
	foreach my $key (keys %new) {
		my @new = @{$new{$key}};
		my @old = @{$old{$key}};
		my @diff = ();

		next unless @new > 0 and @old > 0;
		foreach my $i (0 .. $#new) {
			$diff[$i] = $new[$i] - $old[$i];
		}
		$diff{$key} = \@diff;
	}
	my $line = "";
	foreach my $key (@parameters) {
		next unless $diff{$key};
		foreach my $value (@{$diff{$key}}) {
			$line .= "\t$value";
		}
	}
	return "" unless length($line) > 0;
	if ($first) {
		my $info = "datarate\ttx_power";
		foreach my $key (@parameters) {
			my @types = ("");
			my $len = $#{$diff{$key}} + 1;
			if ($len == 3) {
				@types = ("_n", "_s", "_ss");
			} elsif ($len == 2) {
				@types = ("_tx", "_rx");
			} elsif ($len == 1) {
				@types = ("");
			} 
			foreach my $type (@types) {
				$info .= "\t$key$type";
			}
		}
		$prefix = "$info\n$prefix";
	}
	return "$prefix$line\n";
}

foreach my $node (@node_ip) {
	foreach my $direction (@direction) {
		my $my_file = "$result_path/$node-wprobe-$direction.data";
		my $first = 1;
		open (OUTPUT, ">$my_file");
		foreach my $datarate (@datarate) {
			foreach my $tx_power (@tx_power) {
				my $file = "$main_path/$node-wprobe-$direction-$tx_power.dBm-$datarate.MBit";
				my $line;
				reset_data();
				open(MYDATA, $file) or die("Error: cannot open file $file\n");
				while($line = <MYDATA>) {
					if ($line =~ m/\[global\]/) {
						my $out_line = calculate_results("$datarate\t$tx_power", $first);
						if (length($out_line) > 0) {
							print OUTPUT $out_line;
							$first = 0;
						}
						%old = %new;
						next;
					}
					next if $line =~ /^\[/;

					chomp($line);
					my ($key, $value) = split(/=/,$line, 2);

					next unless $new{$key};
					my @values = split /;/, $value;
					if ($#values == 5) {
						@values = @values[3 .. 5];

					} elsif ($#values < 0 || $#values >= 2) {
						next;
					}
					$new{$key} = \@values;
				}
			}
		}
		close(OUTPUT);
	}
}

#	[global]
#	noise=-104;-104.00;0.14;73388;-7632056;793704580
#	phy_busy=11;35.27;39.98;73388;2588635;208636889
#	phy_rx=9;33.40;39.68;73388;2451278;197439802
#	phy_tx=0;0.00;0.05;73388;17;179
#	frames=40628
#	probereq=3


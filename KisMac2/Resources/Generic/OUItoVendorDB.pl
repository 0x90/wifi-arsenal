#!/usr/bin/perl
use utf8;

# OUItoVendorDB.pl
# 4/18/08 for the KisMAC project
# by Garrett Reid

# This script takes the IEE OUI as input,
# then generates a vendor.db file usable by KisMAC.

# The latest OUI can be attained by pointing a browser to
# http://standards.ieee.org/develop/regauth/oui/oui.txt


my $download = "no";

# Parse arguments
while($ARGV[0] =~ /^-/) {
	$current = shift @ARGV;
	
	if($current =~ /^-{1,2}h/) {
		printUsage();
	} elsif ($current =~ /^-{1,2}d/) {
		$download = "yes";
	} elsif ($current =~ /^-{1,2}f/) {
		$download = "force";
	}
}

# Check if usage is valid
printUsage() if($#ARGV < 0 || $#ARGV > 1);

# Set the output files
$ouiFile = $ARGV[0];
$vendorOut = ($ARGV[1] ? $ARGV[1] : "vendor.db");

if($download ne "no"){
	print "Downloading latest OUI... ";
	
	$vMod = 14;
	$oMod = 14;
	
	if(-e $vendorOut){
		$vMod = -M $vendorOut;
	}
	if(-e $ouiFile){
		$oMod = -M $ouiFile;
	}
	
	if($download ne "force" && $vMod < 7){
		print "already updated vendors in last 7d (-f forces update).\n";
		if($vMod <= $oMod){
			print "Skipping execution...\n";
			exit;
		}
	} else {
		$error = system("curl -sf http://standards.ieee.org/develop/regauth/oui/oui.txt -o $ouiFile");
		
		if($error != 0){
			print STDERR "There was an error (code $error) during download.\n";
			exit;
		}
		
		print "done!\n";
	}
}



# Read the OUI
open(OUIIN, "<$ouiFile") || die("Can't read $ouiFile");
print "Reading OUI... ";
my @oui = <OUIIN>;
close(OUIIN);
print "done!\n";

# Open the output file, print the header
open(OUTFILE, ">$vendorOut") || die "Can't write to $vendorOut";
binmode OUTFILE, ":utf8";
print "Writing header to output file... ";
printHeader();
print "done!\n";

# Do the actual work
print "Parsing OUI and writing to output file... ";
for(my $i = 0; $i < @oui; $i++){
	# If it's possible to split the line
	if($oui[$i] =~ s/([0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2})\s+\(hex\)\s+(.+)$/$1 $2/){
		
		my $line = $oui[$i];
		$line =~ s/^ +//;
		$line =~ s/^(.+?)\s+\.\s+$/$1/;
		$line =~ s/&/&amp;/g;
		
		# Chomp off trailing newline
		chomp $line;
		
		# Split apart mac address and name
		my @thisVendor = split(/ /, $line, 2);
		
		# Change - into : in the mac address
		$thisVendor[0] =~ s/-/:/g;
		
		# Print stuff out
		print OUTFILE "\t<key>$thisVendor[0]</key>\n" .
				"\t<string>$thisVendor[1]</string>\n";
	}
}
print "done!\n";

# And tack on the footer
print "Adding footer to output file... ";
printFooter();
print "done!\n";

# Hooray, all done.


sub printUsage() {
print STDERR <<END_USAGE;
Usage:\t$0 [-d(ownload) [-f(orce)]] oui.txt [outputfile]

\tParses the OUI file given, and saves to vendor.db in the
\tcurrent directory, or outputfile if specified.

\tIf the -d(ownload) flag is specified, will attempt to download
\tthe latest OUI.txt from IEEE to the location specified.
\tIf the vendor database was modified in the last week, it
\twill not be updated, unless the -f(orce) option is used.
END_USAGE
exit;
}

sub printHeader() {
print OUTFILE <<END_HEADER;
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>01:00:0C</key>
	<string>Cisco-multicast</string>
	<key>01:00:10</key>
	<string>Hughes-multicast</string>
	<key>01:00:1D</key>
	<string>Enterasys-multicast</string>
	<key>01:00:5E</key>
	<string>multicast</string>
	<key>01:00:5E:00:00:01</key>
	<string>all-hosts-multicast</string>
	<key>01:00:5E:00:00:02</key>
	<string>all-routers-multicast</string>
	<key>01:00:5E:00:00:04</key>
	<string>DVMRP-multicast</string>
	<key>01:00:5E:00:00:05</key>
	<string>OSPF-multicast</string>
	<key>01:00:5E:00:00:06</key>
	<string>OSPF-designated-multicast</string>
	<key>01:00:5E:00:00:09</key>
	<string>RIP2-multicast</string>
	<key>01:00:5E:00:00:0C</key>
	<string>DHCP-agent-multicast</string>
	<key>01:00:5E:00:00:0D</key>
	<string>PIM-multicast</string>
	<key>01:00:5E:00:00:0E</key>
	<string>RSVP-encapsulation</string>
	<key>01:00:5E:00:00:10</key>
	<string>IGRP-multicast</string>
	<key>01:00:5E:00:00:12</key>
	<string>VRRP-multicast</string>
	<key>01:00:5E:00:00:EB</key>
	<string>DNS-multicast</string>
	<key>01:00:5E:00:01:01</key>
	<string>NTP-multicast</string>
	<key>01:00:5E:00:01:08</key>
	<string>NIS-plus-multicast</string>
	<key>01:00:5E:00:01:8D</key>
	<string>DHCP-server-multicast</string>
	<key>01:00:5E:00:07:06</key>
	<string>Tivoli-multicast</string>
	<key>01:00:5E:00:07:13</key>
	<string>PolyCom-multicast</string>
END_HEADER
}

sub printFooter() {
	print OUTFILE "</dict>\n</plist>\n";
}

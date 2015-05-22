#!/usr/bin/perl -w
#===============================================================================
#
#         FILE:  colorize.pl
#
#        USAGE:  colorize.pl -[style][foregroundcolor][backgroundcolor]:[string] 
#
#  DESCRIPTION:  colorize lines via string search from STDIN and outputs them via STDOUT
#
# REQUIREMENTS:  just perl
#         BUGS:  ---
#       AUTHOR:  Daniel Flinkmann ( Daniel AT Flinkmann.de ) 
#      VERSION:  0.4a
#      CREATED:  01/11/08 01:07:09 CEST
#      WEBSITE:	 HTTP://WWW.FLINKMANN.DE/
#===============================================================================

use strict;

# prototype 
#
sub about (); 

# variables 
#
my $VERSION = "0.4a" ;
my $row ; 
my $argscount = $#ARGV;  
my $argsnum ; 
my @searchstring ; 
my @colorcode ; 
my @paintway ;
my @colorpresets = ("u18", "u28", "u38", "u48", "u78", "l10", "l20", "l30", "l40", "l70", "l11", "l22", "l33", "l74", "l76") ;

# main 
#
if ($argscount == -1) { 
	print "Error: No options entered ! \n" ; 
	about() ; 
}

foreach $argsnum (0 .. $argscount) {
	my $tempstring = $ARGV[$argsnum] ; 
	if ($ARGV[$argsnum] =~ /^[-|+]:/) {
		($paintway[$argsnum],$searchstring[$argsnum]) = $ARGV[$argsnum] =~ m/^([-|+]):(.*)$/  ; 
		$tempstring  = $paintway[$argsnum] .(shift @colorpresets).":".$searchstring[$argsnum] ;
	}  
	($paintway[$argsnum], my $ttype, my $tfcol, my $tbcol, $searchstring[$argsnum]) = $tempstring =~ m/^([-|+])(i|u|n|l|b)([0-7])([0-8]):(.*)$/ ;  
	my $type ; 
	if (defined $ttype) {
		if ($ttype eq 'i') {		$type = "7" ;
		 } elsif ($ttype eq 'u') { 	$type = "4" ;
		 } elsif ($ttype eq 'n') {	$type = "0" ;
		 } elsif ($ttype eq 'l') {	$type = "1" ;
		 } elsif ($ttype eq 'b') {	$type = "5" ; 
		 } else {      about() ;
		}
	} else {
	print "Error: Option: ". $ARGV[$argsnum]." is not correct !!\n"  ;
	about (); 
	}
	$colorcode[$argsnum]="\033[".$type.";".($tfcol+30).";".($tbcol+40)."m" ;

	}
while (defined($row = <STDIN>)) {
	foreach $argsnum (0 .. $argscount) {
		if ($row =~ /$searchstring[$argsnum]/) {
			chomp $row ;

			if ($paintway[$argsnum] =~ /-/) {
				$row = $colorcode[$argsnum] . $row . "\033[0m\n";
			}
			if ($paintway[$argsnum] =~ /\+/) {
				$row =~ s/($searchstring[$argsnum])/$colorcode[$argsnum]$1\033[0m/g;
				$row .= "\n"; 
			}
		}
	}
	print $row ; 
} 
exit 0 ; 

# Usage sub 
#

sub about () {
	print "colorize, The stdin-stdout line colorizer, version:$VERSION by daniel flinkmann, www.flinkmann.de \n"; 
	print "\nUsage:\t" ;
	print "Colorize with matching string:\n";
	print "$0 [-+]<style><foreground color><background color>:<searchstring>\n\n" ; 
	print "Quick-Usage:\n" ; 
	print "$0 -:<searchstring> -:<searchstring> -:<searchstring> \n" ;
	print "$0 +:<searchstring> +:<searchstring> +:<searchstring> \n\n" ; 
	print "- will colorize whole matching rows, + will colorize the matched portion only. \n" ;
	print "<style>            : n = normal, l = light, u=underscore, i = inverted, b = blinking \n" ; 
	print "<foreground color> : 0 = black, 1 = red, 2 = green, 3 = yellow, 4 = blue, 5 = purple, 6 = cyan, 7 = white \n"; 
	print "<background color> : 0 = black, 1 = red, 2 = green, 3 = yellow, 4 = blue, 5 = purple, 6 = cyan, 7 = white 8 = no Background \n";
	print "<searchstring>     : string \n\n" ;
	print "Note: You can enter as much search strings as you like, however the latter can overwrite the earlier\n"; 
	print "(Searchstrings in +:<searchstring> can be regular expressions, but not in -:<searchstring>)\n\n"; 
	print "Examples:\n"; 
	print "Normal colorisation with users chosen colors\n" ; 
	print "ls -lF / \| $0 -n17:usr -u34:home +l58:etc \n" ;
	print "Prints out the root directory with red/white \"usr\" dir (whole row), underscored yellow/blue \"home\" directory (whole row) and the word etc will be colorized in light purple with no background color.\n\n"; 
	print "Example of a quick colorisation with preset colors: \n"; 
	print "ls -lF / \| $0 -:usr +:home \n" ; 
	print "Prints out the root directory with the first preset color \"usr\" dir (whole row) and second preset  \"home\" directory (only matched word) \n";
	exit (-1) ; 
}


#!/usr/bin/perl
# shuffle reaver session file
# IMPORTANT! Remember to shuffle session before attack, otherwise you loose your

# testing shuffled file against your PIN and showing if it was found faster than in original session file
# cat testSessionFile_shuffled | gawk 'BEGIN { cnt=0; }{ cnt++; if(/1233/){ print cnt; exit; }}'
# cat testSessionFile | gawk 'BEGIN { cnt=0; }{ cnt++; if(/1233/){ print cnt; exit; }}'

use strict;
use List::Util qw(shuffle);    
if (!$ARGV[0]){
    print "Script purpouse is to shuffle PINs in reaver session file.\n";
    print "This way you can increase probability of finding correct PIN earlier";
    print "Usage $0 [REAVER_SESSION_FILE_PATH]\n";
    print "After execute script will make a copy of your original file named {YOUR_FILE_NAME}_shuffled";
    print "Remember to shuffle session before attack, otherwise you loose your checked PINs\n";
}
my $filename = $ARGV[0];
if (! -f $filename) {
  print "Sorry $filename isn't a file\n";
  print "Usage $0 [REAVER_SESSION_FILE_PATH]\n";
  exit;
}
open FILE_IN, "<$filename";
open FILE_OUT, ">${filename}_shuffled";
my @pinsPart1;
my @pinsPart2;
my $cnt1 = 0;
my $cnt2 = 0;
while (<FILE_IN>) {
   # $_ =~ s/\n//g;
   # skip first 3 lines (not pins)
   if($. <= 3){
      print FILE_OUT "$_";
      next;
   }
   # 4 digits + \n
   if(length("$_")==5){   
      @pinsPart1[$cnt1++] = $_;
   }
   # 3 digits + \n
   elsif(length("$_")==4){
      @pinsPart2[$cnt2++] = $_;      
   }
}
close FILE_IN;
my @pinsPart1Shuffle = shuffle @pinsPart1;
my @pinsPart2Shuffle = shuffle @pinsPart2;
for my $el (@pinsPart1Shuffle){
    print FILE_OUT "$el";
}
for my $el (@pinsPart2Shuffle){
    print FILE_OUT "$el";
}
close FILE_OUT;
print "File ${filename}_shuffled has been created\n";
print "Your original ${filename} remains untouched\n";
print "To replace your session file with shuffled, execute following command:\n";
print "cp ${filename}_shuffled ${filename}\n";



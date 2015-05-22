#!/usr/bin/perl -w
#
# Written because Net::GPSD3 is awful
# WeakNetLabs@Gmail.com
# 
package lib::GPSO;
use strict;
my $gpsd;
sub new {
	my ($class_name) = @_;
	my $self = {};
	bless ($self, $class_name);
	$self->{_created} = 1;
	return $self;
}
sub packet{
	$gpsd = `cat gps.$_[1]`;
	if($gpsd eq ''){
		$gpsd = 'Retrieving Data';
	}
	return $gpsd;
}
return 1;

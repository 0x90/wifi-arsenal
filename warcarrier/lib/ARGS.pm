#!/usr/bin/perl -w
#
# Getting arguments;
# written out of frustration by douglas berdeaux.
#
package lib::ARGS;
my @args;
sub new{ # create an object
        my ($class_name) = @_;
        my $self = {};
        bless ($self, $class_name);
        $self->{_created} = 1;
	@args = @_; # we pass it @ARGV
        return $self;
}
sub getarg{ # pass this method an argument "flag"
	for($i=0;$i<$#args;$i++){ # e.g. '-f','--file',etc
		if($args[$i] eq $_[1]){
			return $args[$i+1];
		}
	}
	if($_[2] > 0){
		die("The Argument: " . $_[1] . " was required.\n");
	}
	return "NULL"; # nothing is there
}
1;

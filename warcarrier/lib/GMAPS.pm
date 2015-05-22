#!/usr/bin/perl -w
use strict;
package lib::GMAPS; # by Douglas Berdeaux
my $slat; # This is pretty abstract - code that generates code.
my $slon; # starting lat and lon
sub new{ # create new maps object, my $map = lib::GMPAS::new();
        my ($class_name) = @_;
        my $self = {};
        bless ($self, $class_name);
        $self->{_created} = 1;
	$slat = $_[1];
	$slon = $_[2]; # get these for the map creation
        return $self;  # Google Maps API allows a map center position.
}
sub center_map{
	return "\t\tcenter: new google.maps.LatLng(" . $slat . "," . $slon . "),";
}
sub pos_mark{ # create a position object and marker:
	my $icon = '';
	if($_[4] eq 'bt'){ 
		$icon = '"../../includes/html/style/bt.png"';
	}elsif($_[4] eq 'wf'){
		$icon = '"../../includes/html/style/wifi.png"';
	}elsif($_[4] eq 'wp'){
		$icon = '"../../includes/html/style/wp.png"';
	}
	my $p = 'var p' . $_[1] . ' = new google.maps.LatLng(' . $_[2] . ',' . $_[3] . ');'; # pos complete
	$p .= 'var m' . $_[1] . ' = new google.maps.Marker({position:p' . $_[1] . ',title:"Access Point",'
		. 'icon:'.$icon.', draggable:true }); m' . $_[1] . '.setMap(map);'."\n".'var c'.$_[1].' = '; # marker complete
	return $p; # these increment togther p0->m0, p1->m1, etc..
}
sub con_str{ # create content string for InfoWindow: (ADD 1 to $_[n])
	my $c = '\'<div class="infowindow"><b>BSSID:</b>' . $_[1]
		. '<br /><b>ESSID:</b>' . $_[5]
		. '<br /><b>Channel:</b>' . $_[2]
		. '<br /><b>Power:</b>' . $_[3]
		. '<br /><b>Security:</b>' . $_[4]
		. '<br /><b>Lat:</b>' . $_[6]
		. '<br /><b>Lon:</b>' . $_[7]
		. '</div>\';'; # complete
	return $c;
}
sub con_str_bt{
	chomp $_[4];
	my $c = '\'<div class="infowindow"><b>MAC:</b>' . $_[1]
		. '<br /><b>Name:</b>' . $_[2]
                . '<br /><b>Lat:</b>' . $_[3]
                . '<br /><b>Lon:</b>' . $_[4]
		. '</div>\';'; # complete
	return $c;
}
sub info_win{
	my $inf = 'var iw' . $_[1] . ' = new google.maps.InfoWindow({ content: c' . $_[1]. ' });';
	$inf .= 'google.maps.event.addListener(m' . $_[1] . ',"click",function(){iw' . $_[1] . '.open(map,m' . $_[1] . ');});';
	return $inf;
}
sub wp_str{
	my $wps = '\'<div class="infowindow"><b>Lat:</b>' . $_[1]
		. '<br /><b>Lon:</b>' . $_[2]
		. '<br /><b>Waypoint #:</b>'.$_[3]
		. '<br /><b>Date:</b>' . $_[4]
		. '<br /><b>Desc:</b>' . $_[5]
		. '</div>\';'; # complete
	return $wps; # return the Waypoint string
}
1;

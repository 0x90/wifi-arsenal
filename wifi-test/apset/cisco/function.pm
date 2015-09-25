#
# Copyright (C) 2006 Intel Corporation.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2, as published by the Free Software Foundation.

# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License # for more details.

# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 59 Temple
# Place - Suite 330, Boston, MA 02111-1307 USA.

# Authors:
#       Mi, Jun <jun.mi@intel.com>
#	Zheng, jiajia <jiajia.zheng@intel.com>
# Contact: WiFi Test Development <wifi-test-devel@lists.sourceforge.net>
package function;
#BEGIN {}
use Net::Telnet;
use config;
###System Level Variables, do not change
###-------------------------------------------------------------------------
	$telnet = new Net::Telnet (Timeout =>0, Errmode=> 'return');
	$ibss = new Net::Telnet (Timeout =>5, Errmode=> 'return', Prompt=> '/linux:/');
	$scan = new Net::Telnet (Timeout =>120, Errmode=> 'return');
	use Exporter();
	@ISA = qw(Exporter);
	@EXPORT = qw($match);
	$match = "$1";
###-------------------------------------------------------------------------
###End of System Level Variables
sub sloth {select(undef, undef, undef, 0.05)}
sub cisco
	{
	print "Connecting to ap $config::ap using $config::AP_Login $config::AP_Password and $config::AP_Enable_Password\n";
	@Login_Commands=
		(
		$config::AP_Login,
		$config::AP_Password,
		'enable',
		$config::AP_Enable_Password,
		);
	print "Connecting to access point\nSleeping to clear cache\n";
#	sleep 1;
	$telnet->open("$config::ap");
        for (@Login_Commands){$telnet->print("$_");}#sleep 1;};
	print "Connected to access point\n";
	sleep 1;
	}

sub reboot
        {
        cisco;
        print "rebooting AP...\n";
        $telnet->print('reload'); sleep 1;
        $telnet->print('yes'); sleep 1;
        $telnet->print('y'); sleep 3; 
        }

sub stfrag
	{
	cisco;
        print "Setting fragmentation\n";
	@Set_Frag_Commands=
		(
		'conf t',
		"interface dot11radio $_[0]",
	 	"fragment-threshold $_[1]"
		);
	for (@Set_Frag_Commands){$telnet->print("$_"); sleep 1;}
	}

sub aprate
	{
	if ($_[1]!~m/not_entered/)
	{
		cisco;
		if ($_[2] eq "no "){
                print "Disable rate $_[1]\n";}
                else {
                print "Enable rate $_[1]\n";}
		my @AP_Rate_Commands=
			(
			"conf t",
			"interface dot11radio$_[0]",
			"$_[2]speed $_[1]"
			);
		for (@AP_Rate_Commands){$telnet->print("$_");sleep 1;}
	}
	}

sub mscrate
	{
		cisco;
		if ($_[2] eq "no "){
		print "Disable MSC rates $_[1] --->legacy mode\n";}
		else {
		print "Enable MSC rates $_[1] --->11n mode\n";}
		$telnet->print("conf t");
		$telnet->print("interface dot11radio$_[0]");sleep 1;
		$telnet->print("$_[2]speed $_[1]");sleep 1;
	}

sub apauth
	{
	cisco;
	print "Setting $_[3]$_[2] on radio $_[0]\n";
	$telnet->print("conf t");#sleep 1;
	$telnet->print("dot11 ssid $_[1]");#sleep 1;        
	$telnet->print("$_[3]authentication $_[2]"); sleep 1;
	print "Finished, freezing proccess for 2 seconds\n";
	sleep 2;	
	print "Releasing proccess to script\n";
	}

sub setwpa
	{
	cisco;
	print "Enable wpa\n";
	$telnet->print("conf t");#sleep 1;
	$telnet->print("interface dot11Radio $_[0]");# sleep 1;
	$telnet->print("encryption mode ciphers $_[2]"); sleep 1;
	$telnet->print("exit");# sleep 1;
	$telnet->print("dot11 ssid $_[1]");# sleep 1;
	$telnet->print("authentication open eap eap_methods"); sleep 1;
	$telnet->print("authentication key-management wpa"); sleep 1;
	print "Finished\n";
        sleep 2;
        print "Releasing proccess to script\n";
	}

sub nowpa
	{
	cisco;
        print "Disable wpa and wpa-psk\n";
        $telnet->print("conf t");#sleep 1;
	$telnet->print("dot11 ssid $_[1]");# sleep 1;
	$telnet->print("no wpa-psk ascii"); sleep 1;
        $telnet->print("no authentication open eap eap_methods"); sleep 1;
        $telnet->print("no authentication key-management"); sleep 1;
	$telnet->print("exit");# sleep 1;
	$telnet->print("interface dot11Radio $_[0]");# sleep 1;
        $telnet->print("no encryption mode");# sleep 1;
        print "Finished\n";
        sleep 2;
        print "Releasing proccess to script\n";
        }

sub setpsk
	{
	cisco;
	print "Enable wpa-psk\n";
	$telnet->print("conf t");# sleep 1;
	$telnet->print("interface dot11Radio $_[0]");# sleep 1;
	$telnet->print("encryption mode ciphers $_[2]");# sleep 1;
	$telnet->print("exit");# sleep 1;
	$telnet->print("dot11 ssid $_[1]");# sleep 1;
	$telnet->print("authentication key-management wpa"); sleep 1;
	$telnet->print("wpa-psk ascii $config::psk_key"); sleep 1;
	$telnet->print("authentication open");# sleep 1;
	print "Finished\n";
        sleep 2;
        print "Releasing proccess to script\n";
	}

sub set8021x
        {
        cisco;
	print "Enable IEEE8021X\n";
	$telnet->print("conf t");
	$telnet->print("interface dot11Radio $_[0]");
	$telnet->print("encryption mode ciphers $_[2]");
	$telnet->print("exit");
	$telnet->print("dot11 ssid $_[1]");# sleep 1;
        $telnet->print("authentication open eap eap_methods");# sleep 1;
	print "Finished\n";
        sleep 2;
        print "Releasing proccess to script\n";
        }

sub qos
        {
        cisco;
        print "Enable WMM on dot11Radio $_[0]\n";
        $telnet->print("conf t");
        $telnet->print("interface dot11Radio $_[0]");
        $telnet->print("dot11 qos mode wmm"); sleep 1;
        print "Finished\n";
        print "Releasing proccess to script\n";
        }

sub activate
        {
        cisco;
        print "Activate dot11Radio $_[0]\n";
        $telnet->print("conf t");
        $telnet->print("interface dot11Radio $_[0]");
        $telnet->print("no shutdown"); sleep 1;
        $telnet->print("exit"); sleep 1;
        print "Finished\n";
        sleep 2;
        print "Releasing proccess to script\n";
        }

sub radius
        {
        cisco;
        print "Activate radius server $_[0] $_[1] $_[2]\n";
        $telnet->print("conf t"); sleep 1;
        $telnet->print("aaa group server radius rad_eap"); sleep 1;
        $telnet->print("server $_[0] auth-port $_[1]"); sleep 1;
#        $telnet->print("exit"); sleep 1; 
        $telnet->print("aaa new-model"); sleep 1;
        $telnet->print("aaa authentication login eap_methods group rad_eap"); sleep 1;
        $telnet->print("radius-server host $_[0] auth-port $_[1] key $_[2]"); sleep 1;
        $telnet->print("end"); sleep 1;
#        $telnet->print("exit");
        print "Finished\n";
        sleep 2;
        print "Releasing proccess to script\n";
        }

sub ssidbcast
        {
        cisco;
        print "Setting ssid broadcast\n";
        $telnet->print("conf t");#sleep 1;
        $telnet->print("dot11 ssid $_[1]");#sleep 1;
        $telnet->print("$_[2]guest-mode");#sleep 1;
        print "Finished\n";
        sleep 2;
        print "Releasing proccess to script\n";
        }

sub chanset
	{
	if ($_[1]!~m/not_entered/)
        	{
		cisco;
		print "I will now set radio $_[0]\'s channel to $_[1]\n";
		$telnet->print('configure terminal');#sleep 1;
		$telnet->print("interface dot11radio $_[0]");
		$telnet->print("channel $_[1]");
		print "Freezing proccess for 2 seconds\n";
		sleep 2;
		print "Releasing proccess\n";
		}
	}

sub chanwidth
	{
        if ($_[1]!~m/not_entered/)
                {
                cisco;
                print "I will now set radio $_[0]\'s channel to $_[1]\n";
                $telnet->print('configure terminal');#sleep 1;
                $telnet->print("interface dot11radio $_[0]");
                $telnet->print("channel width $_[1]");
                print "Freezing proccess for 2 seconds\n";
                sleep 2;
                print "Releasing proccess\n";
                }
        }

sub setwep
	{
	cisco;
	print "Setting wep on ap $config::ap\n";
	$telnet->print('configure terminal');#sleep 1;
	$telnet->print("interface dot11radio $_[0]");
	$telnet->print("encryption mode wep mandatory");
	print "Releasing proccess to script after 2 seconds\n";
	sleep 2;
	print "finished\n";
        }


sub keyset
	{
	if ($_[1]!~m/not_entered/)
        {
		cisco;
		print "Setting keys on ap $config::ap\n";
        	$telnet->print('configure terminal'); 
		$telnet->print("interface dot11radio $_[1]"); 
		
	if($_[0] eq "add")
		{
		if ($_[3] eq "40") 
			{
			$key = (substr($_[4],0,10))
			}
		if ($_[3] eq "128")
			{
			$key = (substr($_[4],0,26))
			}
		print "encryption key $_[2] size $_[3] $_[4] transmit_key\n";
		$telnet->print("encryption key $_[2] size $_[3] $_[4] transmit-key");sleep 1;
		$telnet->print("encryption mode wep mandatory");sleep 1;
		}
	if ($_[0] eq "rem")
		{
		$telnet->print("no encryption key 1");
		$telnet->print("no encryption key 2");
		$telnet->print("no encryption key 3");
		$telnet->print("no encryption key 4");
		$telnet->print("no encryption mode");
		}
	print "Releasing proccess to script after 2 seconds\n";
	sleep 2;
	print "finished\n";
	}
	}

sub createssid
	{
	cisco;
	print "Now I will $_[0] $_[2] from radio $_[1]\n";
	if ($_[0] eq "add") 
		{
		$telnet->print('conf t');
		$telnet->print("interface Dot11Radio$_[1]");
		$telnet->print("ssid $_[2]"); sleep 1;
		$telnet->print("exit");
		$telnet->print("dot11 ssid $_[2]"); sleep 1;
		$telnet->print("authentication open"); sleep 1;
		$telnet->print("no authentication shared");
		$telnet->print("no authentication network-eap");
		$telnet->print("guest-mode"); sleep 1;
		}
	else 
		{
		$telnet->print('conf t');
                $telnet->print("interface Dot11Radio$_[1]");
		$telnet->print("no ssid $_[2]"); sleep 1;
		}
	print "Complete, freezing proccess for 2 seconds\n";
	sleep 2;
	print "Releasing proccess\n";
	}

sub radiost
        {
	cisco;
        $telnet->print('conf t');sleep 1;
	$telnet->print('interface Dot11Radio$_[0]');
	sleep 1;
	if ($_[1] eq "down"){$telnet->print('shutdown')}
        if ($_[1] eq "up"){$telnet->print('no shutdown')};
        }

sub apchk
        {
        until (($1 eq 0) || ($i eq 14))
                {
                sleep 17;
                $i++;
                `ping -c4 $ap` =~ /, *([\w0-9%]+)% packet loss/i;
                print $i;
                }
        if ($i ne 14) {$match = "pass"} else {$match = "fail"}
        sndd;
        }

sub sndd{aa->export_to_level(1, @export);}

sub proload
	{
	print "loading AP profile $_[0], should complete in 4\n";
	cisco;
	$telnet->print('cd pro');sloth;
	$telnet->print("del nvram:/startup-config");sloth;
	for (1..2){$telnet->print("\n")};
	$telnet->print("copy $_[0] start");sloth;
	for (1..2){$telnet->print("\n")};
	$telnet->print("reload");sloth;
	for (1..2){$telnet->print("\n")};
	for (1..2){$telnet->print("\n")};
	&apchk;
	}

sub prosave
	{
	cisco;
	$telnet->print('cd pro');sleep 1;
	$telnet->print("copy run $_[0]");sleep 1;
	$telnet->print("\n");
	}
return 1;
#END {}

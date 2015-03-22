On the server side place, do the following:

1. Make apprpriate changes in ./includes/webserverOptions.py to relfect your database
requirements (default will be to save to sqlite (snoopy.db)).

2. Install these packages and the SSL key:
apt-get install apache2
apt-get install libapache2-mod-wsgi
a2enmod ssl
service apache2 restart
mkdir /etc/apache2/ssl
openssl req -x509 -nodes -days 1000 -newkey rsa:2048 -keyout /etc/apache2/ssl/apache.key -out /etc/apache2/ssl/apache.crt

cp ./setup/apache/snoopy /etc/apache2/sites-available/
ln -s /etc/apache2/sites-available/snoopy /etc/apache2/sites-enabled/snoopy

a2ensite snoopy
service apache restart

Ensure the key generated is reflected in your client SETTINGS file.

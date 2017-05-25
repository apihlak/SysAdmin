#!/bin/bash
#Created by Magical Unicorns
#For Web Services

export LC_ALL=C

#Enter variables
echo -n "Enter hostname (ex. host89): "
read HOST
echo -n "Enter domain (ex. sander89.yks): "
read DOMEEN
echo -n "Enter IP (ex. 10.10.10.81): "
read IPADDR
echo -n "Enter site1 name, besides www and webmail (ex. shop): "
read SITE1
echo -n "Enter site2 name, besides www and webmail (ex. scada): "
read SITE2
echo -n "Enter MySQL root password, (ex. kala): "
read SQLPASS
echo -e "\e[92mNOTE:\e[39m Roundcubemail users password is kala "

#For main-site cert, we need for ex. sander89, not sander89.yks
MAIN=$(echo $DOMEEN| cut -d . -f1)

#Entered correct variables? 
echo -n "Is it correct fqdn? [$HOST.$DOMEEN] server's IP [$IPADDR] and sites [$SITE1], [$SITE2]. If not then enter [n]| "
read answer
if echo "$answer" | grep -iq "^n" ;
then
echo "Bye!"
    exit 1
fi

#Backup old files, just in case
cp -r /etc/apache2 /etc/backup_apache2
cp -r /opt/roundcube /opt/backup_roundcube
cp -r /var/www /var/backup_www
echo -e "\e[92mNOTE:\e[39m Backup of old files completed"

#Remove enabled sites, don't worry we are re-enabling them soon
rm /etc/apache2/sites-enabled/*
echo -e "\e[92mNOTE:\e[39m Removed sites-enabled"

echo -e "\e[92mNOTE:\e[39m Checking for installed packages. PAM, APACHE2, PHP5, PHP5-MYSQL"
#Install required packages
#For PAM authentication on secondary site
apt-get update > /dev/null 2>&1 && apt-get install libapache2-mod-authnz-external pwauth -y
apt-get install apache2 -y

#PHP5
apt-get install php5 php5-mysql -y

#Change conf
cat > /etc/apache2/ports.conf << "EOF"
Listen 80

<IfModule ssl_module>
        Listen 443
</IfModule>

<IfModule mod_gnutls.c>
        Listen 443
</IfModule>
EOF
echo -e "\e[92mNOTE:\e[39m /etc/apache2/ports.conf is overwritten"

echo -e "\e[92mNOTE:\e[39m Checking for www content folders exist"
#Checking if folders exist
if [ -d /var/www/html/ ]; then
        echo -e "\e[92mNOTE:\e[39m /var/www/html/ exists, OK"
else
        echo -e "\e[92mNOTE:\e[39m Creating /var/www/html/"
        mkdir /var/www/html/
fi

if [ -d /var/www/vhosts/ ]; then
        echo -e "\e[92mNOTE:\e[39m /var/www/vhosts exists, OK"
else
        echo -e "\e[92mNOTE:\e[39m Creating /var/www/vhosts/"
        mkdir /var/www/vhosts/
fi

if [ -d /var/www/vhosts/webmail/ ]; then
        echo -e "\e[92mNOTE:\e[39m /var/www/vhosts/webmail exists, OK"
else
        echo -e "\e[92mNOTE:\e[39m Creating /var/www/vhosts/webmail"
        mkdir /var/www/vhosts/webmail/
fi

if [ -d /var/www/vhosts/$SITE1/ ]; then
        echo -e "\e[92mNOTE:\e[39m /var/www/vhosts/$SITE1 exists, OK"
else
        echo -e "\e[92mNOTE:\e[39m Creating /var/www/vhosts/$SITE1"
        mkdir /var/www/vhosts/$SITE1/
fi

if [ -d /var/www/vhosts/$SITE2/ ]; then
        echo -e "\e[92mNOTE:\e[39m /var/www/vhosts/$SITE2 exists, OK"
else
        echo -e "\e[92mNOTE:\e[39m Creating /var/www/vhosts/$SITE2"
        mkdir /var/www/vhosts/$SITE2/
fi

cat > /etc/apache2/apache2.conf << "EOF"
Mutex file:${APACHE_LOCK_DIR} default
PidFile ${APACHE_PID_FILE}
Timeout 300
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 5

User ${APACHE_RUN_USER}
Group ${APACHE_RUN_GROUP}
HostnameLookups Off
ErrorLog ${APACHE_LOG_DIR}/error.log
LogLevel warn
IncludeOptional mods-enabled/*.load
IncludeOptional mods-enabled/*.conf
Include ports.conf

<Directory />
  Options FollowSymLinks
  AllowOverride None
  Require all denied
</Directory>

<Directory /usr/share>
  AllowOverride None
  Require all granted
</Directory>

<Directory /var/www/>
  Options Indexes FollowSymLinks
  AllowOverride None
  Require all granted
</Directory>

AccessFileName .htaccess

<FilesMatch "^\.ht">
  Require all denied
</FilesMatch>

LogFormat "%v:%p %h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" vhost_combined
LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined
LogFormat "%h %l %u %t \"%r\" %>s %O" common
LogFormat "%{Referer}i -> %U" referer
LogFormat "%{User-agent}i" agent

IncludeOptional conf-enabled/*.conf
IncludeOptional sites-enabled/*.conf
EOF
echo -e "\e[92mNOTE:\e[39m /etc/apache2/apache2.conf is overwritten"

#Main site
cat > /etc/apache2/sites-available/0-www.conf << EOF
include /etc/apache2/mods-available/status.load
include /etc/apache2/mods-available/status.conf
include /etc/apache2/conf-available/phpmyadmin.conf

<VirtualHost *:80>
  ServerName www.$DOMEEN
  DocumentRoot /var/www/html
  UserDir public_html
  ErrorLog \${APACHE_LOG_DIR}/www.$DOMEEN-error.log
  LogLevel warn
  CustomLog \${APACHE_LOG_DIR}/www.$DOMEEN-access.log combined

  <Location "/phpinfo">
        Order Deny,Allow
        Allow from 127.0.0.0/24
        Deny from all
  </Location>

  #httpd status module
  <Location "/server-status">
        SetHandler server-status
        Order Deny,Allow
        Allow from 127.0.0.0/24
        Allow from $IPADDR/24
        Deny from all
  </Location>

#Redirect to HTTPS
<If "%{SERVER_PROTOCOL} != 'HTTPS'">
  Redirect "/" "https://www.$DOMEEN/"
</If>

#Alternatiiv
#RewriteEngine On
# This will enable the Rewrite capabilities
#RewriteCond %{HTTPS} !=on
# This checks to make sure the connection is not already HTTPS
#RewriteRule ^/?(.*) https://%{SERVER_NAME}/$1 [R,L]

</VirtualHost>
EOF
echo -e "\e[92mNOTE:\e[39m /etc/apache2/sites-available/0-www.conf is overwritten"

#HTTPS Main site
cat > /etc/apache2/sites-available/0-www-ssl.conf << EOF
include /etc/apache2/mods-available/status.load
include /etc/apache2/mods-available/status.conf

<VirtualHost *:443>
  ServerName www.$DOMEEN
  DocumentRoot /var/www/html
  UserDir public_html

  SSLEngine on
  SSLCertificateFile /etc/ssl/certs/$MAIN.pem
  SSLCertificateKeyFile /etc/ssl/private/$MAIN.key

  ErrorLog \${APACHE_LOG_DIR}/www.$DOMEEN-error.log
  LogLevel warn
  CustomLog \${APACHE_LOG_DIR}/www.$DOMEEN-access.log combined

  <Location "/phpinfo">
        Order Deny,Allow
        Allow from 127.0.0.0/24
        Deny from all
  </Location>

  #httpd status module
  <Location "/server-status">
        SetHandler server-status
        Order Deny,Allow
        Allow from 127.0.0.0/24
        Allow from $IPADDR/24
        Deny from all
  </Location>

</VirtualHost>
EOF
echo -e "\e[92mNOTE:\e[39m /etc/apache2/sites-available/0-www-ssl.conf is overwritten"

cat > /etc/apache2/sites-available/webmail.conf << EOF
<VirtualHost *:80>
  ServerName webmail.$DOMEEN
  DocumentRoot /var/www/vhosts/webmail
  UserDir disabled

  #Redirect webmail to roundcube
  RedirectMatch "^/$" "https://webmail.$DOMEEN/roundcube/"
 
#Alternatiiv
#RewriteEngine On
# This will enable the Rewrite capabilities
#RewriteCond %{HTTPS} !=on
# This checks to make sure the connection is not already HTTPS
#RewriteRule ^/?(.*) https://%{SERVER_NAME}/$1 [R,L]

  ErrorLog \${APACHE_LOG_DIR}/webmail.$DOMEEN-error.log
  LogLevel warn
  CustomLog \${APACHE_LOG_DIR}/webmail.$DOMEEN-access.log combined
  
 #Redirect to HTTPS
<If "%{SERVER_PROTOCOL} != 'HTTPS'">
  Redirect "/" "https://webmail.$DOMEEN/"
</If>

Alias /roundcube /opt/roundcube

<Directory /opt/roundcube>
 Options +FollowSymLinks
 DirectoryIndex index.php

 <IfModule mod_php5.c>
 AddType application/x-httpd-php .php
 php_flag magic_quotes_gpc Off
 php_flag track_vars On
 php_flag register_globals Off
</IfModule>

 AllowOverride All
 Require all granted
</Directory>

# Protecting basic directories:
<Directory /opt/roundcube/plugins/enigma/home>
 Options -FollowSymLinks
 AllowOverride None
 Require all denied
</Directory>

<Directory /opt/roundcube/config>
 Options -FollowSymLinks
 AllowOverride None
 Require all denied
</Directory>

<Directory /opt/roundcube/temp>
 Options -FollowSymLinks
 AllowOverride None
 Require all denied
</Directory>

<Directory /opt/roundcube/logs>
 Options -FollowSymLinks
 AllowOverride None
 Require all denied
</Directory>

</VirtualHost>
EOF
echo -e "\e[92mNOTE:\e[39m /etc/apache2/sites-available/webmail.conf is overwritten"

cat > /etc/apache2/sites-available/webmail-ssl.conf << EOF
<VirtualHost *:443>
  SSLEngine on
  SSLCertificateFile /etc/ssl/certs/webmail.pem
  SSLCertificateKeyFile /etc/ssl/private/webmail.key
  ServerName webmail.$DOMEEN
  DocumentRoot /var/www/vhosts/webmail
  UserDir disabled

  #Redirect to roundcube
  RedirectMatch "^/$" "https://webmail.$DOMEEN/roundcube/"

  LogLevel warn
  ErrorLog \${APACHE_LOG_DIR}/webmail.$DOMEEN-error.log
  CustomLog \${APACHE_LOG_DIR}/webmail.$DOMEEN-access.log combined

Alias /roundcube /opt/roundcube

<Directory /opt/roundcube>
 Options +FollowSymLinks
 DirectoryIndex index.php

 <IfModule mod_php5.c>
 AddType application/x-httpd-php .php
 php_flag magic_quotes_gpc Off
 php_flag track_vars On
 php_flag register_globals Off
</IfModule>

 AllowOverride All
 Require all granted
</Directory>

# Protecting basic directories:
<Directory /opt/roundcube/plugins/enigma/home>
 Options -FollowSymLinks
 AllowOverride None
 Require all denied
</Directory>

<Directory /opt/roundcube/config>
 Options -FollowSymLinks
 AllowOverride None
 Require all denied
</Directory>

<Directory /opt/roundcube/temp>
 Options -FollowSymLinks
 AllowOverride None
 Require all denied
</Directory>

<Directory /opt/roundcube/logs>
 Options -FollowSymLinks
 AllowOverride None
 Require all denied
</Directory>

</VirtualHost>
EOF
echo -e "\e[92mNOTE:\e[39m /etc/apache2/sites-available/webmail-ssl.conf is overwritten"

#Other virtual hosts
cat > /etc/apache2/sites-available/$SITE1.conf << EOF
<VirtualHost *:80>
  ServerName $SITE1.$DOMEEN
  DocumentRoot /var/www/vhosts/$SITE1
  UserDir disabled

  ErrorLog \${APACHE_LOG_DIR}/$SITE1.$DOMEEN-error.log
  LogLevel warn
  CustomLog \${APACHE_LOG_DIR}/$SITE1.$DOMEEN-access.log combined

  Alias "/alias/one.html" "/var/www/alias/one.html"

  <Location "/alias">
        AuthType Basic
        AuthUserFile /etc/htpasswd/.htpasswd
        AuthName "Login with htpasswd utility"
        Require valid-user
  </Location>

#Redirect from HTTP tp HTTPS
<If "%{SERVER_PROTOCOL} != 'HTTPS'">
  Redirect "/" "https://$SITE1.$DOMEEN/"
</If>

#Alternatiiv
#RewriteEngine On
# This will enable the Rewrite capabilities
#RewriteCond %{HTTPS} !=on
# This checks to make sure the connection is not already HTTPS
#RewriteRule ^/?(.*) https://%{SERVER_NAME}/$1 [R,L]

</VirtualHost>
EOF
echo -e "\e[92mNOTE:\e[39m /etc/apache2/sites-available/$SITE1.conf is overwritten"

cat > /etc/apache2/sites-available/$SITE1-ssl.conf << EOF
<VirtualHost *:443>
  SSLEngine on
  SSLCertificateFile /etc/ssl/certs/$SITE1.pem
  SSLCertificateKeyFile /etc/ssl/private/$SITE1.key
  ServerName $SITE1.$DOMEEN
  DocumentRoot /var/www/vhosts/$SITE1
  UserDir disabled

  ErrorLog \${APACHE_LOG_DIR}/$SITE1.$DOMEEN-error.log
  LogLevel warn
  CustomLog \${APACHE_LOG_DIR}/$SITE1.$DOMEEN-access.log combined

  Alias "/alias/one.html" "/var/www/alias/one.html"

  <Location "/alias">
        AuthType Basic
        AuthUserFile /etc/htpasswd/.htpasswd
        AuthName "Login with htpasswd utility"
        Require valid-user
  </Location>

</VirtualHost>
EOF
echo -e "\e[92mNOTE:\e[39m /etc/apache2/sites-available/$SITE1-ssl.conf is overwritten"

cat > /etc/apache2/sites-available/$SITE2.conf << EOF
<VirtualHost *:80>
  ServerName $SITE2.$DOMEEN
  DocumentRoot /var/www/vhosts/$SITE2
  UserDir disabled

  ErrorLog \${APACHE_LOG_DIR}/$SITE2.$DOMEEN-error.log
  LogLevel warn
  CustomLog \${APACHE_LOG_DIR}/$SITE2.$DOMEEN-access.log combined

  Alias "/alias/two.html" "/var/www/alias/two.html"

  <Location "/alias">
        AuthType Basic
        AuthName "Login with PAM"
        AuthBasicProvider external
        AuthExternal pwauth
        Require valid-user
  </Location>

  <IfModule mod_authnz_external.c>
        AddExternalAuth pwauth /usr/sbin/pwauth
        SetExternalAuthMethod pwauth pipe
  </IfModule>

#Redirect from HTTP tp HTTPS
<If "%{SERVER_PROTOCOL} != 'HTTPS'">
  Redirect "/" "https://$SITE2.$DOMEEN/"
</If>

#Alternatiiv
#RewriteEngine On
# This will enable the Rewrite capabilities
#RewriteCond %{HTTPS} !=on
# This checks to make sure the connection is not already HTTPS
#RewriteRule ^/?(.*) https://%{SERVER_NAME}/$1 [R,L]

</VirtualHost>
EOF
echo -e "\e[92mNOTE:\e[39m /etc/apache2/sites-available/$SITE2.conf is overwritten"

cat > /etc/apache2/sites-available/$SITE2-ssl.conf << EOF
<VirtualHost *:443>
  SSLEngine on
  SSLCertificateFile /etc/ssl/certs/$SITE2.pem
  SSLCertificateKeyFile /etc/ssl/private/$SITE2.key
  ServerName $SITE2.$DOMEEN
  DocumentRoot /var/www/vhosts/$SITE2
  UserDir disabled

  ErrorLog \${APACHE_LOG_DIR}/$SITE2.$DOMEEN-error.log
  LogLevel warn
  CustomLog \${APACHE_LOG_DIR}/$SITE2.$DOMEEN-access.log combined

  Alias "/alias/two.html" "/var/www/alias/two.html"

  <Location "/alias">
        AuthType Basic
        AuthName "Login with PAM"
        AuthBasicProvider external
        AuthExternal pwauth
        Require valid-user
  </Location>

  <IfModule mod_authnz_external.c>
        AddExternalAuth pwauth /usr/sbin/pwauth
        SetExternalAuthMethod pwauth pipe
  </IfModule>

</VirtualHost>
EOF
echo -e "\e[92mNOTE:\e[39m /etc/apache2/sites-available/$SITE2-ssl.conf is overwritten"

cat > /etc/apache2/mods-available/status.conf << "EOF"
<IfModule mod_status.c>
        # Allow server status reports generated by mod_status,
        # with the URL of http://servername/server-status
        # Uncomment and change the "192.0.2.0/24" to allow access from other hosts.

        <Location /server-status>
                SetHandler server-status
                #Require local
                #Require ip 192.0.2.0/24
        </Location>

        # Keep track of extended status information for each request
        ExtendedStatus On

        # Determine if mod_status displays the first 63 characters of a request or
        # the last 63, assuming the request itself is greater than 63 chars.
        # Default: Off
        #SeeRequestTail On


        <IfModule mod_proxy.c>
                # Show Proxy LoadBalancer status in mod_status
                ProxyStatus On
        </IfModule>


</IfModule>
EOF
echo -e "\e[92mNOTE:\e[39m /etc/apache2/mods-available/status.conf is overwritten"

###########################CONTENT#############################
cat > /var/www/html/index.html << EOF
<!DOCTYPE html>
<html>
<body>

<h1>Welcome to www.$DOMEEN</h1>
<p>Please choose a link:</p>
<p><a href="http://$DOMEEN/~user/">User's site</a></p>
<p><a href="http://webmail.$DOMEEN">Webmail</a></p>
<p><a href="http://webmail.$DOMEEN/roundcube">Roundcube</a></p>
<p><a href="http://$SITE1.$DOMEEN">$SITE1</a></p>
<p><a href="http://$SITE2.$DOMEEN">$SITE2</a></p>
<p><a href="http://$SITE1.$DOMEEN/alias/one.html">Alias for Site1</a></p>
<p><a href="http://$SITE2.$DOMEEN/alias/two.html">Alias for Site2</a></p>
<p><a href="http://www.$DOMEEN/phpmyadmin">phpmyadmin</a></p>
<p><a href="http://www.$DOMEEN/server-status">Server status</a></p>

</body>
</html>

EOF

cat > /var/www/vhosts/$SITE1/index.html << EOF
<!DOCTYPE html>
<html>
<body>

<h1>Welcome to $SITE1</h1>

</body>
</html>
EOF

cat > /var/www/vhosts/$SITE2/index.html << EOF
<!DOCTYPE html>
<html>
<body>

<h1>Welcome to $SITE2</h1>

</body>
</html>
EOF

###########################CONTENT#############################

echo -e "\e[92mNOTE:\e[39m Creating user's /home/user/public_html dir"
#UserDir
mkdir /home/user/public_html
chown user:user /home/user/public_html/
chmod 705 /home/user/public_html/
touch /home/user/public_html/index.html
chown user:user /home/user/public_html/index.html

cat > /home/user/public_html/index.html << EOF
<!DOCTYPE html>
<html>
<body>

<h1>Welcome to User's site</h1>

</body>
</html>
EOF

#PHP5 for Apache Server

echo -e "\e[92mNOTE:\e[39m Creating /var/www/html/phpinfo dir and file"
mkdir /var/www/html/phpinfo
cat > /var/www/html/phpinfo/phpinfo.php << "EOF"
     <?php echo phpinfo(); ?>
EOF

echo -e "\e[92mNOTE:\e[39m Creating /var/www/alias and aliases one.html two.html, and adding content"
#Creating aliases for two virtual hosts
mkdir /var/www/alias

cat > /var/www/alias/one.html << EOF
<!DOCTYPE html>
<html>
<body>

<h1>Alias 1</h1>

</body>
</html>
EOF
cat > /var/www/alias/two.html << EOF
<!DOCTYPE html>
<html>
<body>

<h1>Alias 2</h1>

</body>
</html>
EOF

echo -e "\e[92mNOTE:\e[39m HTTP authentication. Insert password for user to create /etc/htpasswd/.htpasswd"
#htpasswd
rm -r /etc/htpasswd/
mkdir /etc/htpasswd
#Creating the password file
htpasswd -c /etc/htpasswd/.htpasswd user
echo -e "\e[92mNOTE:\e[39m PAM authentication. Adding user to the file, insert password again"
#Adding user to htpasswd
htpasswd /etc/htpasswd/.htpasswd user

#MySQL
#Reconfigure mysql, askes for new root password
echo -e "\e[92mNOTE:\e[39m setting up MySQL"
echo "mysql-server-5.5 mysql-server/root_password password $SQLPASS" | debconf-set-selections
echo "mysql-server-5.5 mysql-server/root_password_again password $SQLPASS" | debconf-set-selections
apt-get install mysql-server mysql-client -y
dpkg-reconfigure mysql-server-5.5 -f noninteractive

#Creating a user tester
echo -e "\e[92mNOTE:\e[39m adding user tester to sql"
mysql --user=root --password="$SQLPASS" --execute="GRANT SELECT ON *.* TO 'tester'@'localhost';"

#phpmyadmin
echo -e "\e[92mNOTE:\e[39m setting up phpmyadmin"
apt-get install phpmyadmin -y
rm /etc/apache2/conf-enabled/phpmyadmin.conf

#Roundcube
#Removing old files
echo -e "\e[92mNOTE:\e[39m setting up roundcube"
rm -r /opt/roundcube
mkdir /opt/roundcube
cd /opt/roundcube/
wget --no-check-certificate https://downloads.sourceforge.net/project/roundcubemail/roundcubemail/1.1.4/roundcubemail-1.1.4-complete.tar.gz
tar -xf roundcubemail-1.1.4-complete.tar.gz 
mv roundcubemail-1.1.4/* /opt/roundcube/
mv roundcubemail-1.1.4/.htaccess /opt/roundcube/
rm -r roundcubemail-1.1.4
rm roundcubemail-1.1.4-complete.tar.gz
chown -R root:root /opt/roundcube
cd

mysql --user=root --password="$SQLPASS" --execute="DROP DATABASE roundcubemail; CREATE DATABASE roundcubemail; GRANT ALL PRIVILEGES ON roundcubemail.* TO roundcube@localhost IDENTIFIED BY 'kala'; flush privileges;"

#Importing Roundcube tables from the download files into our new database
mysql --defaults-file=/etc/mysql/debian.cnf roundcubemail < /opt/roundcube/SQL/mysql.initial.sql

cp -pf /opt/roundcube/config/config.inc.php.sample /opt/roundcube/config/config.inc.php

cat > /opt/roundcube/config/config.inc.php << EOF
<?php
\$config = array();
\$config['db_dsnw'] = 'mysql://roundcube:kala@localhost/roundcubemail';
\$config['default_host'] = '$DOMEEN';
\$config['smtp_server'] = 'localhost';
\$config['smtp_port'] = 25;
\$config['smtp_user'] = '';
\$config['smtp_pass'] = '';
\$config['support_url'] = '';
\$config['product_name'] = 'Roundcube Webmail';
\$config['des_key'] = 'rcmail-!24ByteDESkey*Str';
\$config['plugins'] = array(
    'archive',
    'zipdownload',
);
\$config['skin'] = 'larry';
EOF

#HTTPS
echo -e "\e[92mNOTE:\e[39m Creating HTTPS certs"
openssl req -new -x509 -days 3650 -nodes -out /etc/ssl/certs/$MAIN.pem -keyout /etc/ssl/private/$MAIN.key -subj "/C=EE/ST=Tartumaa/L=Tartu/O=Lab/CN=www.$DOMEEN/emailAddress=mailuser@$DOMEEN"
openssl req -new -x509 -days 3650 -nodes -out /etc/ssl/certs/webmail.pem -keyout /etc/ssl/private/webmail.key -subj "/C=EE/ST=Tartumaa/L=Tartu/O=Lab/CN=webmail.$DOMEEN/emailAddress=mailuser@$DOMEEN"
openssl req -new -x509 -days 3650 -nodes -out /etc/ssl/certs/$SITE1.pem -keyout /etc/ssl/private/$SITE1.key -subj "/C=EE/ST=Tartumaa/L=Tartu/O=Lab/CN=$SITE1.$DOMEEN/emailAddress=mailuser@$DOMEEN"
openssl req -new -x509 -days 3650 -nodes -out /etc/ssl/certs/$SITE2.pem -keyout /etc/ssl/private/$SITE2.key -subj "/C=EE/ST=Tartumaa/L=Tartu/O=Lab/CN=$SITE2.$DOMEEN/emailAddress=mailuser@$DOMEEN"

#For reference. Mods enabled on my machine:
#access_compat.load    authz_host.load       env.load              php5.conf             status.conf
#alias.conf            authz_user.load       filter.load           php5.load             status.load
#alias.load            autoindex.conf        mime.conf             rewrite.load          userdir.conf
#auth_basic.load       autoindex.load        mime.load             setenvif.conf         userdir.load
#authn_core.load       deflate.conf          mpm_prefork.conf      setenvif.load         
#authn_file.load       deflate.load          mpm_prefork.load      socache_shmcb.load    
#authnz_external.load  dir.conf              negotiation.conf      ssl.conf              
#authz_core.load       dir.load              negotiation.load      ssl.load 

echo -e "\e[92mNOTE:\e[39m enabling mods and sites"
#Enable modules and sites
a2enmod userdir
#PAM module
a2enmod authnz_external
a2enmod ssl
a2enmod rewrite
a2enmod status
a2ensite 0-www.conf
a2ensite 0-www-ssl.conf
a2ensite webmail.conf 
a2ensite webmail-ssl.conf
a2ensite $SITE1.conf
a2ensite $SITE1-ssl.conf
a2ensite $SITE2.conf
a2ensite $SITE2-ssl.conf

#Config check
echo -e "\e[92mNOTE:\e[39m checking conf"
apachectl configtest
#--TODO-- # If ok continue, if not display error and show logs

#Restarts
echo -e "\e[92mNOTE:\e[39m restarting mysql and apache2"
service mysql restart
service apache2 restart
update-rc.d mysql enable
update-rc.d apache2 enable

#Show logs
#--TODO--

#Check sites
#http://www.$DOMEEN/~user/
#http://www.$DOMEEN/phpinfo/phpinfo.php
#http://$SITE1.$DOMEEN/alias/one.html
#http://$SITE2.$DOMEEN/alias/two.html
#http://www.$DOMEEN/phpmyadmin
#http://webmail.$DOMEEN/roundcube
#http://www.$DOMEEN/server-status
#http://webmail.$DOMEEN/server-status

undcu�

#!/bin/bash
#Created by Magical Unicorns
#For Mail

export LC_ALL=C

#Enter variables
echo -n "Enter hostname (ex. host89): "
read HOST
echo -n "Enter domain (ex. sander89.yks): "
read DOMEEN
echo -n "Enter IP (ex. 10.10.10.81): "
read IPADDR

echo -e "\e[92mNOTE:\e[39m Checking if POSTFIX, DOVECOT, PROCMAIL, SPAMASSASSIN and ALPINE are installed"
apt-get update > /dev/null 2>&1
apt-get install postfix dovecot-imapd dovecot-common procmail spamassassin alpine -y
echo -e "\e[95mALERT:\e[39m Script adds procmail under 'mailuser'. Please check if this user exists!"
#Entered correct variables? 
echo -n "Is it correct? FQDN [$HOST.$DOMEEN] and IP [$IPADDR]? If not then enter [n]| "
read answer
if echo "$answer" | grep -iq "^n" ;
then
    echo "Bye!"
    exit 1
fi

#hostname -f needs to return FQDN
FQDN1="$HOST.$DOMEEN"
FQDN2=$(hostname -f)
if [[ $FQDN2 == $FQDN1 ]]; then
  echo -e "\e[92mSUCCESS:\e[39m FQDN correct"
else
  #Add hostname
cat > /etc/hostname << EOF
$HOST
EOF
    echo -e "\e[95mALERT:\e[39m Reboot your machine! And start program again. Changed your /etc/hostname to $HOST"
    exit 1
fi

#Backup old files
cp -r /etc/postfix /etc/backup_postfix
cp -r /etc/dovecot /etc/backup_dovecot
cp /home/mailuser/.procmailrc  /home/mailuser/.backup_procmailrc 

echo -e "\e[92mNOTE:\e[39m Backup of old files completed"

#Write text what is in EOF
#NB! Writes over files!
#Setting up NTP
type ntpd > /dev/null 2>&1

if [ $? -ne 0 ]
then
  echo -e "\e[92mNOTE:\e[39m /etc/postfix/main.cf Starting to update and install ntp"
  apt-get install ntp -y
fi
cat >> /etc/ntp.conf << "EOF"
server ntp.ut.ee
EOF
service ntp restart

#Check if certificates exist, if not create them
POSTFIXKEY=$(openssl rsa -noout -modulus -in /etc/ssl/private/postfix.key | openssl md5 | cut -d' ' -f2)
POSTFIXPEM=$(openssl x509 -noout -modulus -in /etc/ssl/certs/postfix.pem | openssl md5 | cut -d' ' -f2)
DOVECOTKEY=$(openssl rsa -noout -modulus -in /etc/ssl/private/dovecot.key | openssl md5 | cut -d' ' -f2)
DOVECOTPEM=$(openssl x509 -noout -modulus -in /etc/ssl/certs/dovecot.pem | openssl md5 | cut -d' ' -f2)
if [ -e /etc/ssl/certs/dovecot.pem ] && [ -e /etc/ssl/private/dovecot.key ] && [ -e /etc/ssl/certs/postfix.pem ] && [ -e /etc/ssl/private/postfix.key ]; then
        echo -e "\e[92mSUCCESS:\e[39m Certs Exist"

  #Check if the checksums match, if not recreate them
  if [ $POSTFIXKEY == $POSTFIXPEM ] && [ $DOVECOTKEY == $DOVECOTPEM ]; then
    echo -e "\e[92mSUCCESS:\e[39m Checksums Match"
  else
    openssl req -new -x509 -days 3650 -nodes -out /etc/ssl/certs/dovecot.pem -keyout /etc/ssl/private/dovecot.key -subj "/C=EE/ST=Tartumaa/L=Tartu/O=Lab/CN=$HOST.$DOMEEN" > /dev/null 2>&1
    cp /etc/ssl/certs/dovecot.pem /etc/ssl/certs/postfix.pem
    cp /etc/ssl/private/dovecot.key /etc/ssl/private/postfix.key
    chmod 640 /etc/ssl/private/dovecot.key
    chmod 640 /etc/ssl/private/postfix.key
    chgrp ssl-cert /etc/ssl/private/dovecot.key
    chgrp ssl-cert /etc/ssl/private/postfix.key
    echo -e "\e[95mALERT:\e[39m Cert checksums didn't mach, created new ones"
  fi
else
  openssl req -new -x509 -days 3650 -nodes -out /etc/ssl/certs/dovecot.pem -keyout /etc/ssl/private/dovecot.key -subj "/C=EE/ST=Tartumaa/L=Tartu/O=Lab/CN=$HOST.$DOMEEN" > /dev/null 2>&1
  cp /etc/ssl/certs/dovecot.pem /etc/ssl/certs/postfix.pem
  cp /etc/ssl/private/dovecot.key /etc/ssl/private/postfix.key
  chmod 640 /etc/ssl/private/dovecot.key
  chmod 640 /etc/ssl/private/postfix.key
  chgrp ssl-cert /etc/ssl/private/dovecot.key
  chgrp ssl-cert /etc/ssl/private/postfix.key
  echo -e "\e[95mALERT:\e[39m One or more certs didn't exist, created them"
fi


cat > /etc/postfix/main.cf << EOF
# See /usr/share/postfix/main.cf.dist for a commented, more complete version

#Procmail as default mail delivery routine
mailbox_command = /usr/bin/procmail

# Debian specific:  Specifying a file name will cause the first
# line of that file to be used as the name.  The Debian default
# is /etc/mailname.
#myorigin = /etc/mailname

smtpd_banner = \$myhostname ESMTP \$mail_name (Debian/GNU)
biff = no

# appending .domain is the MUA's job.
append_dot_mydomain = no

# Uncomment the next line to generate "delayed mail" warnings
#delay_warning_time = 4h

readme_directory = no

# TLS parameters
smtpd_use_tls=yes
smtpd_tls_session_cache_database = btree:\${data_directory}/smtpd_scache
smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache
smtpd_tls_security_level = may
smtpd_tls_cert_file=/etc/ssl/certs/postfix.pem
smtpd_tls_key_file=/etc/ssl/private/postfix.key
smtpd_tls_loglevel = 1
smtp_tls_loglevel = 1
inet_protocols = ipv4

#Enabling SASL, to send messages outside our domain
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes

# See /usr/share/doc/postfix/TLS_README.gz in the postfix-doc package for
# information on enabling SSL in the smtp client.

smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination

myhostname = mail.$DOMEEN
mydomain = $DOMEEN

#Canonical sender aliases
sender_canonical_maps = hash:/etc/postfix/canonical
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
#What domains to use in outbound mail:
myorigin = /etc/mailname
#What domains to receive mail for:
mydestination = \$mydomain, $HOST.\$mydomain, mail.\$mydomain, localhost.\$mydomain, , localhost
#relayhost = 
#mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mynetworks_style = host
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
EOF
echo -e "\e[92mNOTE:\e[39m /etc/postfix/main.cf is overwritten"

cat > /etc/postfix/master.cf << "EOF"
# ==========================================================================
# service type  private unpriv  chroot  wakeup  maxproc command + args
#               (yes)   (yes)   (yes)   (never) (100)
# ==========================================================================
smtp      inet  n       -       -       -       -       smtpd
#SASL authentication over STARTTLS, over submission port tcp/587
submission inet n       -       -       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_sasl_path=private/auth
#Restrict anonymous submission
  -o smtpd_sasl_security_options=noanonymous
#Only allow SASL authenticated clients
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
#Only allow SASL authenticated relaying
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
#explicit TLS (SMTPS)
smtps     inet  n       -       -       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_sasl_path=private/auth
  -o smtpd_sasl_security_options=noanonymous
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
pickup    unix  n       -       -       60      1       pickup
cleanup   unix  n       -       -       -       0       cleanup
qmgr      unix  n       -       n       300     1       qmgr
tlsmgr    unix  -       -       -       1000?   1       tlsmgr
rewrite   unix  -       -       -       -       -       trivial-rewrite
bounce    unix  -       -       -       -       0       bounce
defer     unix  -       -       -       -       0       bounce
trace     unix  -       -       -       -       0       bounce
verify    unix  -       -       -       -       1       verify
flush     unix  n       -       -       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       -       -       -       smtp
relay     unix  -       -       -       -       -       smtp
showq     unix  n       -       -       -       -       showq
error     unix  -       -       -       -       -       error
retry     unix  -       -       -       -       -       error
discard   unix  -       -       -       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       -       -       -       lmtp
anvil     unix  -       -       -       -       1       anvil
scache    unix  -       -       -       -       1       scache
maildrop  unix  -       n       n       -       -       pipe
  flags=DRhu user=vmail argv=/usr/bin/maildrop -d ${recipient}
uucp      unix  -       n       n       -       -       pipe
  flags=Fqhu user=uucp argv=uux -r -n -z -a$sender - $nexthop!rmail ($recipient)
ifmail    unix  -       n       n       -       -       pipe
  flags=F user=ftn argv=/usr/lib/ifmail/ifmail -r $nexthop ($recipient)
bsmtp     unix  -       n       n       -       -       pipe
  flags=Fq. user=bsmtp argv=/usr/lib/bsmtp/bsmtp -t$nexthop -f$sender $recipient
scalemail-backend unix  - n n - 2 pipe
  flags=R user=scalemail argv=/usr/lib/scalemail/bin/scalemail-store ${nexthop} ${user} ${extension}
mailman   unix  -       n       n       -       -       pipe
  flags=FR user=list argv=/usr/lib/mailman/bin/postfix-to-mailman.py
  ${nexthop} ${user}
EOF
echo -e "\e[92mNOTE:\e[39m /etc/postfix/master.cf is overwritten"

#Create file canonical

touch /etc/postfix/canonical

cat > /etc/postfix/canonical << EOF
@$HOST.$DOMEEN @$DOMEEN
@mail.$DOMEEN  @$DOMEEN
EOF

echo -e "\e[92mNOTE:\e[39m /etc/postfix/canonical is overwritten"

cat > /etc/mailname << EOF
$HOST.$DOMEEN
EOF

echo -e "\e[92mNOTE:\e[39m /etc/postfix/canonical is overwritten"

#Compile the canonical file into binary hash table: -> creates /etc/postfix/canonical.db
postmap /etc/postfix/canonical

#Dovecot
if [ ! -d /var/log/dovecot ] 
then
    mkdir /var/log/dovecot
    chown dovecot:dovecot /var/log/dovecot
    chmod 640 /var/log/dovecot
    echo -e "\e[92mNOTE:\e[39m /var/log/dovecot is created"
fi
echo -e "\e[92mNOTE:\e[39m /var/log/dovecot exists"

#Create conf.d folder if it does not exist
if [ ! -d /etc/dovecot/conf.d ] 
then
    mkdir -p /etc/dovecot/conf.d
fi

cat > /etc/dovecot/conf.d/10-logging.conf << "EOF"
log_path = /var/log/dovecot/dovecot.log
mail_debug = yes
EOF
echo -e "\e[92mNOTE:\e[39m /etc/dovecot/conf.d/10-logging.conf is overwritten"

cat > /etc/dovecot/conf.d/10-ssl.conf << "EOF"
ssl = yes
ssl_cert = </etc/ssl/certs/dovecot.pem
ssl_key = </etc/ssl/private/dovecot.key
EOF
echo -e "\e[92mNOTE:\e[39m /etc/dovecot/conf.d/10-ssl.conf is overwritten"

cat > /etc/dovecot/conf.d/10-auth.conf << "EOF"
#Allows login over SSL/TLS only
disable_plaintext_auth = yes
#LOGIN is typically used only by SMTP servers to let Outlook clients perform SMTP authentication
auth_mechanisms = plain login
!include auth-system.conf.ext
EOF
echo -e "\e[92mNOTE:\e[39m /etc/dovecot/conf.d/10-auth.conf is overwritten"

cat > /etc/dovecot/conf.d/10-mail.conf << "EOF"
mail_location = mbox:~/Mail:INBOX=/var/mail/%u
namespace inbox {
  inbox = yes
}
EOF
echo -e "\e[92mNOTE:\e[39m /etc/dovecot/conf.d/10-mail.conf is overwritten"

cat > /etc/dovecot/conf.d/10-master.conf << "EOF"
service auth {
#Postfix smtp-auth
    unix_listener /var/spool/postfix/private/auth {
     mode = 0666
        user = postfix
        group = postfix
    }
}
EOF
echo -e "\e[92mNOTE:\e[39m /etc/dovecot/conf.d/10-master.conf is overwritten"

cat > /etc/dovecot/dovecot.conf << "EOF"
!include_try /usr/share/dovecot/protocols.d/*.protocol
dict {
  #quota = mysql:/etc/dovecot/dovecot-dict-sql.conf.ext
  #expire = sqlite:/etc/dovecot/dovecot-dict-sql.conf.ext
}
!include conf.d/*.conf
!include_try local.conf
EOF
echo -e "\e[92mNOTE:\e[39m /etc/dovecot/dovecot.conf is overwritten"

#Procmail ja Spamassassin
touch /home/mailuser/.procmailrc
chown mailuser:mailuser /home/mailuser/.procmailrc
chmod 644 /home/mailuser/.procmailrc
cat > /home/mailuser/.procmailrc << "EOF"
# SpamAssassin sample procmailrc
#
# Pipe the mail through spamassassin (replace 'spamassassin' with 'spamc'
# if you use the spamc/spamd combination)
#
# The condition line ensures that only messages smaller than 250 kB
# (250 * 1024 = 256000 bytes) are processed by SpamAssassin. Most spam
# isn't bigger than a few k and working with big messages can bring
# SpamAssassin to its knees.
#
# The lock file ensures that only 1 spamassassin invocation happens
# at 1 time, to keep the load down.
#
:0fw: spamassassin.lock
* < 256000
| spamc

# Mails with a score of 15 or higher are almost certainly spam (with 0.05%
# false positives according to rules/STATISTICS.txt). Let's put them in a
# different mbox. (This one is optional.)
:0:
* ^X-Spam-Level: \*\*\*\*\*\*\*\*\*\*\*\*\*\*\*
mail/almost-certainly-spam

# All mail tagged as spam (eg. with a score higher than the set threshold)
# is moved to "probably-spam".
:0:
* ^X-Spam-Status: Yes
mail/probably-spam

# Work around procmail bug: any output on stderr will cause the "F" in "From"
# to be dropped.  This will re-add it.
:0
* ^^rom[ ]
{
  LOG="*** Dropped F off From_ header! Fixing up. "
  
  :0 fhw
  | sed -e '1s/^/F/'
}
EOF
echo -e "\e[92mNOTE:\e[39m /home/mailuser/.procmailrc is overwritten"

#Creating Mail aliases to forward mail to mailuser
cat > /etc/aliases << EOF
postmaster:    root
root:   mailuser
user:   mailuser
EOF
#Regenerate alias database
newaliases

echo -e "\e[92mNOTE:\e[39m Created aliases for 'mailuser'"

#Restart postfix and set to start postfix after reboot
service postfix restart
update-rc.d postfix enable
service postfix status

#Restart dovecot and set to start dovecot after reboot
service dovecot restart
update-rc.d dovecot enable
service dovecot status

##Restart spamassassin and set to start spamassassin after reboot
service spamassassin restart
update-rc.d spamassassin enable
service spamassassin status

#Show recent logs
tail /var/log/dovecot/dovecot.log
tail /var/log/mail.log
#Test sending and receiving mail to mailuser and user

echo -e "\e[92mDONE\e[39m...Check if there are any errors. Have a nice day"

#!/bin/bash
#Created by Magical Unicorns
#For DNS

export LC_ALL=C

#Enter variables
echo -n "Enter hostname (ex. host89): "
read HOST
echo -n "Enter domain (ex. sander89.yks): "
read DOMEEN
echo -n "Enter IP (ex. 10.10.10.81): "
read IPADDR
echo -n "Enter forwarder (ex. 10.10.10.1 OR your IP): "
read IPFORW
echo -n "Enter site1 name, besides www and webmail (ex. shop): "
read SITE1
echo -n "Enter site2 name, besides www and webmail (ex. scada): "
read SITE2

#Last octet
OCTET=$(echo $IPADDR | cut -d . -f4)
#Reverse IP without last octet
IPREVE=$(echo $IPADDR | awk -F'.' '{print $3,$2,$1}' OFS='.')
#Top-level domain
TOPLE=$(echo $DOMEEN| cut -d . -f2)

echo -e "\e[92mNOTE:\e[39m Check if BIND and dnsutils is installed, installing if not"
apt-get update > /dev/null 2>&1
apt-get install bind9 dnsutils -y
#Entered correct variables? 
echo -n "Is it correct? FQDN [$HOST.$DOMEEN], top-domain [$TOPLE], IP [$IPADDR], reverse IP without last octet [$IPREVE] forwarder [$IPFORW] and sites [$SITE1], [$SITE2]? If not then enter [n]| "
read answer
if echo "$answer" | grep -iq "^n" ;
then
echo "Bye!"
    exit 1
fi

#Backup old files
cp -r /etc/bind /etc/backup_bind
cp /etc/hosts /etc/backup_hosts
cp /etc/resolv.conf /etc/backup_resolv.conf
cp /etc/sysctl.conf /etc/backup_sysctl.conf 
cp /etc/hostname /etc/backup_hostname

#Reverse backu, if everything got fucked
#cp -r /etc/backup_bind /etc/bind
#cp /etc/backup_hosts /etc/hosts
#cp /etc/backup_resolv.conf /etc/resolv.conf 
#cp /etc/backup_sysctl.conf /etc/sysctl.conf
#cp /etc/backup_hostname /etc/hostname

echo -e "\e[92mNOTE:\e[39m Backup of old files completed"

#Write text what is in EOF
#NB! Writes over files!
cat > /etc/bind/named.conf << "EOF"
include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.logging";
include "/etc/bind/named.conf.local";
EOF
echo -e "\e[92mNOTE:\e[39m /etc/bind/named.conf is overwritten"

#/etc/bind/named.conf.local
cat > /etc/bind/named.conf.local << EOF
view local_resolver {
        allow-query { goodclients; };
        match-clients { goodclients; };
        match-destinations { goodclients; };
        include "/etc/bind/named.conf.default-zones";
        recursion yes;

        zone "$DOMEEN" {
                file "/etc/bind/zones/$DOMEEN.zone";
                type master;
        };

        zone "$IPREVE.in-addr.arpa" {
                file "/etc/bind/zones/$IPREVE.in-addr.arpa.zone";        
                type master;
        };

        zone "$TOPLE" {
                type forward;
                forward only;
                forwarders {$IPFORW; };
        };
        
};

view "world_resolver" {
        allow-query { any; };
        recursion yes;
        match-clients { any; };
        match-destinations { any; };    

        zone "$DOMEEN" {
                file "/etc/bind/zones/$DOMEEN.zone";
                type master;
        };

};
EOF
echo -e "\e[92mNOTE:\e[39m /etc/bind/named.conf.local is overwritten"

#/etc/bind/named.conf.options
cat > /etc/bind/named.conf.options << EOF
acl goodclients{
        127.0.0.0/8;
};

options {
        directory "/var/cache/bind";
        dnssec-enable yes;
        dnssec-validation yes;

        auth-nxdomain no;    # conform to RFC1035
        listen-on { 127.0.0.1; $IPADDR;};
        listen-on-v6 { none; };
};
EOF
echo -e "\e[92mNOTE:\e[39m /etc/bind/named.conf.options is overwritten"

#Create folder if it does not exist
if [ ! -d /var/log/bind9/ ] 
then
    mkdir -p /var/log/bind9/
    
fi
chown bind:bind /var/log/bind9/
#/etc/bind/named.conf.logging
cat > /etc/bind/named.conf.logging << EOF
logging {
        channel update_debug {
                file "/var/log/bind9/update_debug.log" versions 3 size 100k;
                severity debug;
                print-severity  yes;
                print-time      yes;
        };
        channel security_info {
                file "/var/log/bind9/security_log.log" versions 1 size 100k;
                severity info;
                print-severity  yes;
                print-time      yes;
        };
        channel bind_log {
                file "/var/log/bind9/bind.log" versions 3 size 1m;
                severity info;
                print-category  yes;
                print-severity  yes;
                print-time      yes;
        };

        category default { bind_log; };
        category lame-servers { null; };
        category update { update_debug; };
        category update-security { update_debug; };
        category security { security_info; };
};
EOF
echo -e "\e[92mNOTE:\e[39m /etc/bind/named.conf.logging is overwritten"

#Create folder if it does not exist
if [ ! -d /etc/bind/zones ] 
then
    mkdir -p /etc/bind/zones
fi

#Zonefile
cat > /etc/bind/zones/$DOMEEN.zone << EOF
\$ORIGIN $DOMEEN.
\$TTL    15M
@       IN      SOA     ns1.$DOMEEN. root.$DOMEEN. (
                     2016042902         ; Serial
                            15M         ; Refresh
                             5M         ; Retry
                           120M         ; Expire
                            600 )       ; Negative Cache TTL
@          IN      NS           ns1
@          IN      A            $IPADDR
ns1        IN      A            $IPADDR
$HOST      IN      A            $IPADDR
@          IN      MX      10   mail.$DOMEEN.
mail       IN      A            $IPADDR
www        IN      CNAME        $HOST
webmail    IN      CNAME        $HOST
$SITE1     IN      CNAME        $HOST
$SITE2     IN      CNAME        $HOST
EOF
echo -e "\e[92mNOTE:\e[39m /etc/bind/zones/$DOMEEN.zone is overwritten"

#Reverse zonefile
cat > /etc/bind/zones/$IPREVE.in-addr.arpa.zone << EOF
\$ORIGIN $IPREVE.in-addr.arpa.
\$TTL    15M
@       IN      SOA     ns1.$DOMEEN. root.$DOMEEN. (
                     2016170401         ; Serial
                            15M         ; Refresh
                             5M         ; Retry
                           120M         ; Expire
                            600 )       ; Negative Cache TTL
            IN      NS      ns1.$DOMEEN.
$OCTET      IN      PTR     $HOST.$DOMEEN.
EOF
echo -e "\e[92mNOTE:\e[39m /etc/bind/zones/$IPREVE.in-addr.arpa.zone is overwritten"

#Disable IPV6
cat > /etc/sysctl.conf << EOF
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.all.disable_ipv6 = 1
EOF
echo -e "\e[92mNOTE:\e[39m /etc/sysctl.conf is overwritten"
sysctl -p /etc/sysctl.conf

#Hostname
cat > /etc/hostname << EOF
$HOST
EOF

#/etc/hosts
cat > /etc/hosts << "EOF"
127.0.0.1       localhost
EOF
echo -e "\e[92mNOTE:\e[39m /etc/hosts is overwritten"

#/etc/resolv.conf
cat > /etc/resolv.conf << EOF
nameserver 127.0.0.1
domain $DOMEEN #Local domain name
search $DOMEEN #Search list for host-name lookup
EOF
echo -e "\e[92mNOTE:\e[39m /etc/resolv.conf is overwritten"

#Conf check
named-checkzone $DOMEEN /etc/bind/zones/$DOMEEN.zone
named-checkzone $IPREVE.in-addr.arpa /etc/bind/zones/$IPREVE.in-addr.arpa.zone
#If conf is correct returns nothing
named-checkconf

#Restart bind9 if named-checkconf returned nothing(0)
if [ $? -eq 0 ]; then
    echo "restarting bind9"
    service bind9 restart
    service bind9 status
    update-rc.d bind9 enable
    update-rc.d ssh enable

    #Check if it works
    echo -e "\e[96mTEST:\e[39m Should work:"
    dig @127.0.0.1 $DOMEEN
    echo -e "\e[96mTEST:\e[39m Should work:"
    dig @$IPADDR $DOMEEN
    echo -e "\e[96mTEST:\e[39m Should work:"
    dig @127.0.0.1 neti.ee
    echo -e "\e[96mTEST:\e[39m Should work:"
    dig @$IPADDR neti.ee
    echo -e "\e[96mTEST:\e[39m Should work:"
    host $IPADDR
else
    echo -e "\e[91mERROR:\e[39m Conf Check Failed (named-checkconf)"
fi

    echo -e "\e[96mLOG:\e[39m Bind Logs"
#Show logs
tail /var/log/bind9/bind.log

echo -e "\e[95mIMPORTANT NOTE:\e[39m Zonefile contains www and webmail CNAME records. Add others! You can find backup file /etc/backup_bind"
echo -e "\e[92mDONE\e[39m...Check if there are any errors. Have a nice day"
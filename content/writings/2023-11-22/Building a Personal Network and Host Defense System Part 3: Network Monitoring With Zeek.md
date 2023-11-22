--- 
title: "Building a Personal Network and Host Defense System Part 3: Network Monitoring With Zeek"
author: ""
date: 2023-11-22T09:55:34+01:00
description: ""
draft: false
disableComments: false
categories: []
series: [] #Taxonomy to list "See Also" Section in Opengraph Templates
tags: []
slug: ""
summary: ""
---
Having built a very high and strong wall, we will now mount sentries on all entrances and exits of our castle. We will use Zeek to achieve this on our machine. 

As always clone the [NHIDPS](https://github.com/knoxknot/nhidps.git) repository and change into the directory. You may skip the succeeding commands for building the golden image if you have already built one from previous walkthrough, otherwise run the commands below to build the golden image.
```shell
# hash the passwords and insert in the preseed file
ROOT_PASSWORD="INSERT_ROOT_PASSWORD_HERE"; USER_PASSWORD="INSERT_USER_PASSWORD_HERE"
echo $ROOT_PASSWORD | mkpasswd -s -m sha-512  # replace passwd/root-password-crypted value
echo $USER_PASSWORD | mkpasswd -s -m sha-512  # replace passwd/user-password-crypted value

# building the system with packer json definition
packer plugins install github.com/hashicorp/virtualbox
ISO_URL="INSERT_ISO_FILEPATH" TMPDIR=./ PACKER_LOG_PATH=packer.log PACKER_LOG=2 packer build -var-file template-vars.json -force template.json
```  

With existing golden image and earlier generated key pair, run the command below to configure the machine for network monitoring.
```shell
vagrant up --provision # start and configure the vm
```  
Log into the machine with your specified credentials and run the following commands to observe traffic logs.
```shell
# check the status of zeek
sudo systemctl status zeek

# visit to a site
for _ in {1..10}; do curl -s https://example.com -o /dev/null; done

# list the log files and view connection log
ls /usr/local/zeek/logs/current  # view the log files generated
'SNIP
capture_loss.log  dns.log  ssl.log  stderr.log  telemetry.log
conn.log  notice.log  stats.log  stdout.log  weird.log 
'
less -sSN /usr/local/zeek/logs/current/conn.log  # view connection logs
```  
![Zeek Installed](/images/nhidps3/zeek01.png "Zeek Installed")
![Zeek Running](/images/nhidps3/zeek02.png "Zeek Running")
![Zeek Connection Log](/images/nhidps3/zeek03.png "Zeek Connection Log") 
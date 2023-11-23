--- 
title: "Building a Personal Network and Host Defense System Part 4: Network Protection With Suricata"
author: ""
date: 2023-11-23T14:26:10+01:00
description: ""
draft: false
disableComments: false
categories: []
series: [] #Taxonomy to list "See Also" Section in Opengraph Templates
tags: []
slug: ""
summary: ""
---
It is inevitable that enemies will approach the castle. Thus we must not only monitor the perimeter of our castle but also actively defend it. Hence we will station Archers to defend our castle. To this on our machine we use Suricata.

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

With existing golden image and earlier generated key pair, run the command below to configure the machine for network protection.
```shell
vagrant up --provision-with ansible # start and configure the vm
```  
Log into the machine with your specified credentials and run the following commands to observe traffic logs.
```shell
# check the status of zeek
sudo systemctl status suricata

# visit to a site
for _ in {1..10}; do curl -s https://example.com -o /dev/null; done

# view network events observed
tail -f /var/log/suricata/eve.json | jq -rc .
# see protection status and alert description
tail -f /var/log/suricata/eve.json | jq -rc .stats.ips
tail -f /var/log/suricata/fast.log 
```  
![Suricata Installed](/images/nhidps4/suricata01.png "Suricata Installed")
![Suricata Running](/images/nhidps4/suricata02.png "Suricata Running")
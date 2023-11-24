--- 
title: "Building a Personal Network and Host Defense System Part 6: Data Ingestion and Visualization With Brim"
author: ""
date: 2023-11-24T06:15:54+01:00
description: ""
draft: false
disableComments: false
categories: []
series: [] #Taxonomy to list "See Also" Section in Opengraph Templates
tags: []
slug: ""
summary: ""
---
Finally the King needs to have a holistic report on the state of the castle. How many enemies approaching the wall were gunned down. The spies and assassins that slipped into the castle that were apprehended. All of these layers of defense would be futile if we are unable to probably make decision from the information gleaned. Thus we will deploy Brim on our machine to ingest all these valueable data and help us make informed decision. For this walkthrough I bumped the virtual machine memory to 3GB.

Again head to the [NHIDPS](https://github.com/knoxknot/nhidps.git) repository, clone it and change into the directory. You may skip the succeeding commands for building the golden image if you have already built one from previous walkthrough, otherwise run the commands below to build the golden image.
```shell
# hash the passwords and insert in the preseed file
ROOT_PASSWORD="INSERT_ROOT_PASSWORD_HERE"; USER_PASSWORD="INSERT_USER_PASSWORD_HERE"
echo $ROOT_PASSWORD | mkpasswd -s -m sha-512  # replace passwd/root-password-crypted value
echo $USER_PASSWORD | mkpasswd -s -m sha-512  # replace passwd/user-password-crypted value

# building the system with packer json definition
packer plugins install github.com/hashicorp/virtualbox
ISO_URL="INSERT_ISO_FILEPATH" TMPDIR=./ PACKER_LOG_PATH=packer.log PACKER_LOG=2 packer build -var-file template-vars.json -force template.json
```  

With existing golden image and earlier generated key pair - you may run the first command if you do not have the key pair generated yet - run the command below to configure the machine for host monitoring.
```shell
ssh-keygen -t ed25519 -b 4096 -f nhidps -C "nhidps keypair" -N ""  # create an ssh key
vagrant up --provision-with ansible # start and configure the vm
```  
Log into the machine with your specified credentials and run the following commands to visualize the data collected.
```shell
# check the status of brim zed
sudo systemctl status zed

# launch brim zui to view the data collected
gtk-launch zui
```  
![Brim Zed Service Running](/images/nhidps6/brim01.png "Brim Zed Service Running")
![Falco Report](/images/nhidps6/brim02.png "Falco Report")
![Suricata Report](/images/nhidps6/brim03.png "Suricata Report")
![Zeek Report](/images/nhidps6/brim04.png "Zeek Report")
--- 
title: "Building a Personal Network and Host Defense System Part 5: Host Monitoring With Falco"
author: ""
date: 2023-11-23T14:52:31+01:00
description: ""
draft: false
disableComments: false
categories: []
series: [] #Taxonomy to list "See Also" Section in Opengraph Templates
tags: []
slug: ""
summary: ""
---
With the borders of our castle monitored and protected, we will deploy guards to observe the activities within the castle so we are able to apprehend spies and enemies who managed to sneak into the castle. For this we will install Falco on our machine to observe and inform us on anomalous activities. 

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
Log into the machine with your specified credentials and run the following commands to observe process calls.
```shell
# check the status of falcco
sudo systemctl status falco-modern-bpf

# search for private keys
find /root/.ssh -type f \( -name "id_rsa" -o -name "*.pem" -o -name "*key" \)

# observe host process calls
tail -f /var/log/falco.json | jq -rc .
```  
![Falco Installed](/images/nhidps5/falco01.png "Falco Installed")
![Falco Running](/images/nhidps5/falco02.png "Falco Running")
![Falco Observed Processes](/images/nhidps5/falco03.png "Falco Observed Processes")
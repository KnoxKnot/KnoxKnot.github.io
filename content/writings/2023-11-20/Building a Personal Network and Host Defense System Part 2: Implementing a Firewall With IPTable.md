--- 
title: "Building a Personal Network and Host Defense System Part 2: Implementing a Firewall With IPTable"
author: ""
date: 2023-11-20T02:14:51+01:00
description: ""
draft: false
disableComments: false
categories: []
series: [] #Taxonomy to list "See Also" Section in Opengraph Templates
tags: []
slug: ""
summary: ""
---
It is not good for our castle to be open to entry from all sides. We will need to build a strong wall and define specific entry and exit points. To do this on our machine we will employ nftables. I will use nftable since it is highly recommended but I have also written the iptables role so you could try your hands on that too. 

As always clone the [NHIDPS](https://github.com/knoxknot/nhidps.git) repository and change into the directory. Then build the golden image with the commands below:
```shell
# hash the passwords and insert in the preseed file
ROOT_PASSWORD="INSERT_ROOT_PASSWORD_HERE"; USER_PASSWORD="INSERT_USER_PASSWORD_HERE"
echo $ROOT_PASSWORD | mkpasswd -s -m sha-512  # replace passwd/root-password-crypted value
echo $USER_PASSWORD | mkpasswd -s -m sha-512  # replace passwd/user-password-crypted value

# building the system with packer json definition
packer plugins install github.com/hashicorp/virtualbox
ISO_URL="INSERT_ISO_FILEPATH" TMPDIR=./ PACKER_LOG_PATH=packer.log PACKER_LOG=2 packer build -var-file template-vars.json -force template.json
```  

After the image is successfully built bring the virtual machine up with vagrant. See the commands below:
```shell
# running the system
ssh-keygen -t ed25519 -b 4096 -f nhidps -C "nhidps keypair" -N ""  # create an ssh key
vagrant up  # start the vm
```
Now log into the machine with the credentials you specified to see nftables installed and initial rules applied.
![NFTables Installed](/images/nhidps2/nftables01.png "NFTables Installed")  
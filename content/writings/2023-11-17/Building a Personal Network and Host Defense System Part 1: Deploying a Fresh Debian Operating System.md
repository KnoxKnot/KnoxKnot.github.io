--- 
title: "Building a Personal Network and Host Defense System Part 1: Deploying a Fresh Debian Operating System"
author: ""
date: 2023-11-17T23:43:36+01:00
description: ""
draft: false
disableComments: false
categories: []
series: [] #Taxonomy to list "See Also" Section in Opengraph Templates
tags: []
slug: ""
summary: ""
---
In previous articles I shared on breaking and remediating vulnerable systems and also discussed on perculiar flaws of network applications. Now, I will like to write a series of articles on monitoring and defending one's personal machine. The audience for this series are technical users, a non-technical user could also learn from it.  

A typical developer executes programs and scripts they entirely do not understand what it actually does. And worse the machines they work with are not properly locked down, they are either installed with binaries developers do not need or have frivolous ports open. I will take the effective and efficient engineer through a series of articles on guarding the perimeter of their castle - Network - and recording every anomalous activities undertaken in the castle - Host.

Clone the [NHIDPS](https://github.com/knoxknot/nhidps.git) repository and change into the directory. Install all requisite software and run commands specified in the README.
```shell
# hash the passwords and insert in the preseed file
ROOT_PASSWORD="INSERT_ROOT_PASSWORD_HERE"; USER_PASSWORD="INSERT_USER_PASSWORD_HERE"
echo $ROOT_PASSWORD | mkpasswd -s -m sha-512  # replace passwd/root-password-crypted value
echo $USER_PASSWORD | mkpasswd -s -m sha-512  # replace passwd/user-password-crypted value

# building the system with packer json definition
packer plugins install github.com/hashicorp/virtualbox
ISO_URL="INSERT_ISO_FILEPATH" TMPDIR=./ PACKER_LOG_PATH=packer.log PACKER_LOG=2 packer build -var-file template-vars.json -force template.json
```

Below are some screenshot of the Debian OS installation process you would encounter:  
![Operating System Installation](/images/nhidps1/debian-install01.png "Operating System Installation")  

![Preseeding the Installation](/images/nhidps1/debian-install02.png "Preseeding the Installation")  

![Installation Completed](/images/nhidps1/debian-install03.png "Installation Completed")

You can now log into the machine with your specified credentials. Note however that packer is still building the image. Do not shutdown the system until the terminal from where you ran the packer show the message
```text
==> Builds finished. The artifacts of successful builds are:
--> virtualbox-iso: 'virtualbox' provider box: box/nhidps.box
--> virtualbox-iso: Created artifact from files: box/nhidps.box, box/checksums/md5.txt, box/checksums/sha256.txt, box/checksums/sha512.txt
```

Let's now bring up the machine by running the vagrant command
```shell
# running the system
ssh-keygen -t ed25519 -b 4096 -f nhidps -C "nhidps keypair" -N ""  # create an ssh key
vagrant up  # start the vm
```
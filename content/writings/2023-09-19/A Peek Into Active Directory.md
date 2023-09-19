--- 
title: "A Peek Into Active Directory"
author: ""
date: 2023-09-19T19:08:08+01:00
description: ""
draft: false
disableComments: false
categories: []
series: [] #Taxonomy to list "See Also" Section in Opengraph Templates
tags: []
slug: ""
summary: ""
---
#### Overview of Active Directory (AD), Domain Name System (DNS) and Dynamic Host Configuration Protocol (DHCP)
Active Directory is simply a database of objects - Users, Groups, and Computers. The cluster of Computers that maintains this database is known as domain controllers. Each object has an attribute and can be structured logically in a hierarchical manner.

A Domain Name System is a hierarchical and distributed system used to translate human-readable domain names such as [www.example.com](https://www.example.com) into the numerical IP addresses that computers use to identify each other on a network. DNS servers are the computers that maintain a database of domain names and their corresponding IP addresses. 

Dynamic Host Configuration Protocol is a network protocol used to automatically assign IP addresses and other network configuration information to devices on a network.

#### Download and Install VMWare Workstation Player, Windows Server 2022 and Windows 11
Download [VMWare Workstation Player](https://customerconnect.vmware.com/en/downloads/details?downloadGroup=WKST-PLAYER-1701&productId=1377&rPId=100675), [Windows Server 2022](https://go.microsoft.com/fwlink/p/?LinkID=2195280&clcid=0x409&culture=en-us&country=US) and [Windows 11](https://software.download.prss.microsoft.com/dbazure/Win11_22H2_EnglishInternational_x64v1.iso?t=836f881d-5972-407f-8af2-1baacc948747&e=1677936096&h=0401a3dca4e95bb0f6e790bb402cd769b08df4d76292b299c4373bb599406335) from their respective websites and follow the instructions below to install.  
**VMWare Installation:** Double Click the downloaded Windows Vmware Workstation Player, Click `Yes` then Click `Next` -> Check `I accept the terms in the License Agreement` and Click `Next` -> Click `Next` -> Click `Next` -> Click `Next` ->  Click `Next` ->  Click `Install` -> Click `Finish`. See a visual of this installation below:

{{< raw >}}
<figure>
  <video controls width="640" height="480" style="display:block; margin:auto;">
    <source src="/videos/ad/vmware-workstation-player-installation.mp4" type="video/mp4">
  </video>
  <figcaption><b>VMWare Installation</b></figcaption>
</figure>
{{< /raw >}}

**Windows Server 2022 Installation:** Double Click the now installed VMWare Workstation Player -> Click `Create a New Virtual Machine` -> Select `I will install the operating system later.` and Click `Next` -> Click `Next` -> Enter a name in `Virtual machine name:` box and navigate to a desired storage location using `Browse...` and Enter a name in `Location:` box then Click `Next` -> Enter a disk size in `Maximum disk size(GB):` box, Select `Store virtual disk as a single file` and Click `Next` -> Click `Customize Hardware`; Click `Printer`, Click `Remove`; Click `Memory` and ramp it upto 4GB; Click `New CD/DVD(SATA)`, on the right pane Select `Use ISO image file`, browse to the location of the downloaded ISO and upload the ISO then Click `Close` -> Click `Finish`. Now with the created VM selected on the left pane Click `Play virtual machine` -> Accept all prompts and Press any key to boot from CD or DVD -> Select desired options from the dropboxes and Click `Next` -> Click `Install now` -> Select `Windows Server 2022 Standard Evaluation(Desktop Experien..` then Click `Next` -> Check `I accept the Microsoft Software License Terms. If an organization is licensing it, I am authorized to bind the organization.` Click `Next` -> Click `Custom: Install Microsoft Server Operating System only (advanced)` -> with the `Drive 0 Unallocated Space` selected Click `Next` -> Enter and confirm a Password for Administrator then Click `Finish` -> Click `Player` on the top Menu bar, Select Send CTRL + ALT + DEL and Enter the administrator password to login.  

{{< raw >}}
<figure>
  <video controls width="640" height="480" style="display:block; margin:auto;">
    <source src="/videos/ad/windows-server-installation.mp4" type="video/mp4">
  </video>
  <figcaption><b>Windows Server 2022 Installation</b></figcaption>
</figure>
{{< /raw >}}

**Windows 11 Installation:** Double Click the now installed VMWare Workstation Player -> Click `Create a New Virtual Machine` -> Select `Installer disc image file (iso)` and browse to the location of the downloaded iso then Click `Next` -> Enter a name in `Virtual machine name:` box and navigate to a desired storage location using `Browse...` and Enter a name in `Location:` box then Click `Next` -> Select `All the files (.vmdk,vmx, etc) for this virtual machine are encrypted`, Enter and confirm the Password in the textbox, and Check `Remember the password on this machine in Credential Manager` then Click `Next` -> Enter a disk size in `Maximum disk size(GB):` box, Select `Store virtual disk as a single file` and Click `Next` -> Click `Customize Hardware`; Click `Printer`, Click `Remove`; Click `Memory` and ramp it upto 4GB; then Click `Close` -> Click `Finish` ->  Accept all prompts and Press any key to boot from CD or DVD -> Click `Next` -> Click `Install now` -> Click `I don't have a product key` -> Select `Windows 11 Pro` and Click `Next`. Now Select your language of choice and Click `Yes` -> Choose your keyboard layout and Click `Yes` -> You may skip `Do you want to add a second keyboard layout?` -> Enter a device name and Click `Next` -> Choose `Set up for work or school` and Click `Next` -> You may sign or create an account to proceed, a quick hack was to enter a wrong credentials multiple times to display an error page and activate the Next Tab, Click `Next` -> Enter a name and Click `Next` ->  Enter a Password and Click `Next` ->  Confirm the Password and Click `Next` -> Give an answer to three `Security questions` and Click `Next` -> Turn on/off the settings you desire and Click `Accept` -> Click `Player` on the top Menu bar, Select Send CTRL + ALT + DEL, and Enter the user password to login.

{{< raw >}}
<figure>
  <video controls width="640" height="480" style="display:block; margin:auto;">
    <source src="/videos/ad/windows11-installation.mp4" type="video/mp4">
  </video>
  <figcaption><b>Windows 11 Installation</b></figcaption>
</figure>
{{< /raw >}}

Power off both machines. Right Click on a machine and Click `Settings...` -> Click `CD/DVD(SATA)`, Click `Remove`, and Click `OK`. Please do same for the Win11 VM.
![Disconnect CD/DVD Media](/images/ad/vmware-disconnect-media.png "Disconnect CD/DVD Media") 
#### Install and Configure Windows Server with AD, DNS and DHCP services
Having installed Windows Server 2022. Login with the credentials. Type 'About PC' on Windows Search Bar and Click on the highlighted result -> Click `Rename this PC`, type your preferred name and Click `Next` -> Click `Restart now`. Re-login and Right Click the Network Icon on the Taskbar and Click `Open Network & Internet settings` -> Click `Change adapter options` -> Right Click on `Ethernet0` and Click `Properties` -> Uncheck `Internet Protocol Version 6 (TCP/IPv6)`, Click `Internet Protocol Version 4 (TCP/IPv4)` and Click `Properties` -> Select `Use the following IP address`, Enter desired settings then Click OK -> Click `Close`. Now open a command prompt and type the following:
```cmd
C:\Users\Administrator> ipconfig /flushdns       :: purge dns resolver cache
C:\Users\Administrator> ipconfig /registerdns    :: re-register dns
C:\Users\Administrator> ipconfig /all            :: show the new network configuration
C:\Users\Administrator> ping 192.168.20.4        :: test the network connection
```
![Configure Static IPv4](/images/ad/configure-static-ipv4.png "Configure Static IPv4") 

**Install AD,DNS,DHCP Services:** On the already open 'Server Manager > Dashboard' Click on `Manage` on the right end of the menu bar. Click `Add Roles and Feature` -> Click `Next` -> Select `Role-based or feature-based installation` and Click `Next` ->  Select `Select a server from the server pool` and Click `Next` -> Check `Active Directory Domain Services` and Click `Add Features` -> Check `DHCP Server` and Click `Add Features` -> Check `DNS Server` and Click `Add Features` -> Now Click `Next` -> Click `Next` -> Click `Next` -> Click `Next` -> Click `Next` -> Click `Install`. After the installation is complete Click `Promote this server to a domain controller` -> Select `Add a new forest` and Enter a Domain name then Click `Next` -> Enter and Confirm the Password then Click `Next` -> Click `Next` -> "The NetBIOS domain name" automatically populates, Click `Next` -> Click `Next` -> Click `Next` -> Click `Install`. The server automatically restarts once installation is complete. Re-login to the server.  
![Active Directory Installation](/images/ad/ad-installation.png "Active Directory Installation")  
**Configure the DNS server Reverse Lookup Zone and Forward Lookup Zone:** On the `Server Manager > Dashboard`, Click `Tools` -> Click `DNS` -> Click the Server Name on the left pane, -> Click `Reverse Lookup Zones` on the right pane and Right Click, Click `New Zone` -> Click `Next` -> Select `Primary zone` and Click `Next` -> Select `To all DNS servers running on domain controllers in this domain` and Click `Next` -> Select `IPv4 Reverse Lookup Zone` and Click `Next` -> Enter the first three octet block of the server IP and Click `Next` -> Select `Allow only secure dynamic updates(recommended for Active Directory)` and Click `Next` then Click `Finish`. Now on the left pane Click `Forward Lookup Zones`, Double Click the domain name on the right pane -> Double Click the server name ->  Check `Update associated pointer(PTR) record` and Click `OK`. Now Right Click the Network Icon on the Taskbar and Click `Open Network & Internet settings` -> Click `Change adapter options` -> Right Click on `Ethernet0` and Click `Properties`  -> Click `Internet Protocol Version 4 (TCP/IPv4)` and Click `Properties` -> on the `Use the following IP address` section change the `Preferred DNS Server` to the Server`s IP then Click `OK` -> Click `Close`. Open a command prompt and run the following command:
```cmd
C:\Users\Administrator> nslookup 192.168.20.4      :: notice the default server is our server`s fully qualified domain name
```
**Configure the DHCP:** On the `Server Manager > Dashboard` Click the flag with the warning icon -> Click `Complete DHCP Configuration` -> Click `Next` -> Select `Use the following user's credentials` then Click `Commit` -> Click `Close`  
![DHCP Configuration](/images/ad/dhcp-configuration.png "DHCP Configuration")  
Now from the `Server Manager > Dashboard` Click `Tools` -> Click `DHCP` -> Double Click on the server's FQDN on the right pane -> Click `IPv4` on the left pane, Right Click and Click `New Scope` -> Click `Next` -> Enter a Name and Description for this DHCP scope and Click `Next` -> Fill up the details, this should match the min host, max host and subnet mask of your network CIDR, then Click `Next`  -> Enter IP range to exclude, Click `Add` and Click `Next` -> Change the lease duration to 6 hours and Click `Next` -> Select `Yes, I want to configure these options now` and Click `Next` -> Enter the `Default Gateway IP`, Click `Add` and Click `Next` -> Click `Next` -> Click `Next` -> Select `Yes, I want to activate this scope now` and Click `Next` -> Click `Finish`. On command prompt run:
```cmd
C:\Users\Administrator> netsh dhcp show server     :: list server details
```
 
{{< raw >}}
<figure>
  <video controls width="640" height="480" style="display:block; margin:auto;">
    <source src="/videos/ad/windows-server-ad-dns-dhcp-configuration.mp4" type="video/mp4">
  </video>
  <figcaption><b>Windows Server AD, DNS, DHCP Configuration</b></figcaption>
</figure>
{{< /raw >}}

#### Join Windows 11 to the Domain
Type 'Network Connections' on Windows Search Bar and Click on the highlighted result. Right Click on `Ethernet0` and Click `Properties` -> Click `Internet Protocol Version 4 (TCP/IPv4)` and Click `Properties` -> Select `Use the following IP address`, Enter network details and Select `Use the following DNS server addresses` and Enter the Server's DNS IP then Click OK -> Click `Close`.  On the command prompt check for connectivity between the hosts.
```cmd
C:\Users\Administrator> ping 192.168.20.5     :: client is reachable from server
C:\Users\bug-hunter> ping 192.168.20.4        :: server is reachable from client
```

To Configure the client to obtain its IP from the DHCP server, shutdown both machines, create a LAN segment from VMWare Workstation Player and add the machines to it: Double Click the downloaded Windows Vmware Workstation Player -> Right Click on Server VM and Click `Settings` -> Click `Network Adapter`, Select `LAN segment`, Click `LAN Segments` -> Click `Add`, Enter a name for the LAN Segment then Click `OK` -> Click the dropdown box and Select the just added segment then Click `OK`. For the Client, Right Click on Client VM and Click `Settings` -> Click `Network Adapter`, Select `LAN segment`, Click the dropdown box and Select the same name of the LAN segment as the server, then Click `OK`. 

Now power on both machines. On the Client machine let's change the network TCP/IPv4 setting to use DHCP. Type 'Network Connections' on Windows Search Bar and Click on the highlighted result. Right Click on `Ethernet0` and Click `Properties` -> Click `Internet Protocol Version 4 (TCP/IPv4)` and Click `Properties` -> Select `Obtain an IP address automatically` also Select `Obtain DNS server address automatically` then Click `OK` -> Click `Close`. Notice the adapter now has the network domain name underneath it. Open command prompt to confirm connectivity:
```cmd
C:\Users\bug-hunter> ipconfig /all          :: DHCP enabled and client IP assigned
C:\Users\bug-hunter> ping 192.168.20.4      :: server is reachable from client
C:\Users\bug-hunter> nslookup 192.168.20.1  :: resolves via DNS server
```

To join a Client Computer to the Domain: Enter 'Device specification' on Windows Search  and Click on it -> Locate `Related links` and Click on `Domain or workgroup` -> Click `Change` -> Select `Domain`, Enter the domain name and Click `OK` -> Enter the domain server Administrator credentials and Click `OK` -> Click `OK` -> Click `OK` -> Click `Close` -> Click `Restart Now`.

{{< raw >}}
<figure>
  <video controls width="640" height="480" style="display:block; margin:auto;">
    <source src="/videos/ad/joining-client-to-domain-server.mp4" type="video/mp4">
  </video>
  <figcaption><b>Joining Client to Domain Server</b></figcaption>
</figure>
{{< /raw >}}

#### Create Organizational Units, Groups and Users on the Domain Server
Now go back to the Domain Server to can see that the Client Computer is now part of the Domain: From the 'Server Manager > Dashboard' Click `Tools` -> Click `Active Directory Users and Computers` -> Double the domain on the right pane -> Double Click `Computers`.

![Confirm Client Joined Domain](/images/ad/verify-client-joined-domain.png "Confirm Client Joined Domain") 

It is important to structure your AD by Organizational Unit instead of creating objects directly in Container. Create a New Organizational Unit: Right Click `Tools` -> Click `Active Directory Users and Computers` -> Right Click the domain name from the left pane -> Click on `New` and Click `Organizational Unit` -> Enter a name  and Click `OK`. Now create groups within this OU: Right Click the OU name -> Click `New` and Click `Group` -> Enter a group name, retain the default settings and Click `OK`. Let's create users within this OU: Right Click the OU name -> Click `New` and Click `User` -> Enter user details and Click `Next` (notice the user details have "User Principal Name(UPN)" type logon) -> Enter and confirm a password for the user, Check/UnCheck desired options then Click `Next` -> Click `Finish`. Assign the user to a group: With the OU name selected on the left pane, Right Click on the user from the left pane -> Click `Add to a group` -> Enter the group name and Click `OK` -> Click `OK`.

Now jumping back to the Client VM let's log on to the domain with the user: Click `Other user` -> Enter the credentials of the user created on the domain server and hit the Enter button. 

{{< raw >}}
<figure>
  <video controls width="640" height="480" style="display:block; margin:auto;">
    <source src="/videos/ad/operating-active-directory.mp4" type="video/mp4">
  </video>
  <figcaption><b>Operating Active Directory</b></figcaption>
</figure>
{{< /raw >}}  

**References**  
- [Network Protocols - ARP, FTP, SMTP, HTTP, SSL, TLS, HTTPS, DNS, DHCP - Networking Fundamentals - Practical Networking](https://www.youtube.com/watch?v=E5bSumTAHZE)
- [Learn Microsoft Active Directory (ADDS) in 30mins - Andy Malone](https://www.youtube.com/watch?v=85-bp7XxWDQ)
- [How to install and configure Active Directory & DNS Services Windows Server 2019 - InfoSec Pat](https://youtu.be/8teMFArShR8)
- [A Complete Guide – How Install Active Directory, DNS and DHCP to Create a Domain Controller - MSFT WebCast](https://www.youtube.com/watch?v=NE2nQlYcwao)
- [Adding Additional Domain Controller to an Existing Domain | Windows Server 2019 - MSFT WebCast](https://youtu.be/sqHa2gN1HsY?t=529)
- [Windows Hot Keys](https://support.microsoft.com/en-us/windows/keyboard-shortcuts-in-windows-dcc61a57-8ff0-cffe-9796-cb9706c75eec)
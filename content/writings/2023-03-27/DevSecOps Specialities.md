--- 
title: "DevSecOps Specialities"
date: 2023-03-27T22:49:28+02:00
author: "Samuel Nwoye"
description: ""
draft: false
disableComments: false
categories: ["fundamentals"]
series: [] #Taxonomy used to list "See Also" Section in Opengraph Templates
tags: ["automation","network","operating system","operations","security"]
slug: ""
summary: ""
---
DevSecOps (Development, Security, and Operations) is a software engineering practice that integrates security at every phase of software development and delivery. This approach fosters collaboration among software engineering professionals to deliver a functional, secure, and reliable application. The ideal DevSecOps team would comprise individuals with one or more mastery of these technology subjects:  
###### Network Fundamentals  
- Networking and Network Communication: How a network works and the devices participating in network communication. Understand concepts like subnetting, network address translation, firewalls, and proxies.  
- Network Protocols: Know different network communication protocols and how they work, e.g. ARP, TCP, UDP, IP, SSH, FTP, ICMP, QUIC, OSPF, TLS, DNS, DHCP, SMTP, SNMP, SSDP, LDAP, HTTP/HTTPS, Telnet, POP, IMAP, NTP, RARP, BGP.

###### Operating System
- Linux Fundamentals: Understand the internal mechanisms of Linux from kernel to userspace and how to operate the system. Have a grasp of Linux utilities and how to debug system issues. Master a shell - bash or zsh - and these utilities: dmesg, top, strace/ltrace.
- Windows Fundamentals: Understand the Windows(Client and Server) OS and how to operate the system. Have a good understanding of CMD and Powershell. Have a general knowledge of windows applications, e.g. Active Directory and Office Suite.

###### Programming Languages  
Have a solid grasp of Python and Go programming. Python because it cuts across several domains - Web, Security and AI. Go because modern networking and infrastructure tools are written in Go. Go is fast becoming the go-to tool for compiling a cross-platform application. Get a basic understanding of C/C++, as it is the mother of all programs that exist out there.  

If you yearn for mastery of Microsoft technologies, you may want to pick up C#. How deep you delve into it depends on your desired goal. If one masters one or two programming languages, understanding a new language becomes a breeze - 🙂 maybe not totally a breeze, but somewhat easier - this comes in handy for security researchers.

###### Virtualization/Containerization  
The world is now making efficient use of the operating system. Thanks to orchestrating different operating systems on top of a main operating system and compartmentalizing several applications to run coherently and concurrently on top of the OS. All that is required is the physical resource to run all your containers within this host operating system. Goodbye to purchasing high-end machines as cloud providers solve that problem.

###### Cloud Platform  
There is no hard rule to this one, master whichever cloud you find the opportunity to operate. Different organizations decide on their choice of cloud providers for many reasons.

###### Automation Technologies  
It is challenging to stand up 50 server instances and configure them with the desired applications. In today's world, effective and efficient (EE) engineers leverage several automation tools to make their life saner. A few must have in your arsenal include:
- Kubernetes: For running and managing your containerized applications.
- Docker: For describing and packaging containerized applications.
- Packer: For describing machine/container templates.
- Terraform: For defining your infrastructure.
- Trivy: For static code analysis and vulnerability assessment.
- Consul: For describing and connecting your networks.
- Vault: For securely distributing secrets and configurations.

###### Software Pipelines  
Any successfully developed software in production is a conglomeration of several components developed by different professionals. The final product served to the end users is born from the glue of these pieces in a software development, security and delivery pipeline. 

This is achieved by stringing different tools with applications like Jenkins, Github Action, Gitlab Pipeline, CircleCI, TravisCI or even the newest in the hood Waypoint. Whichever of these tools you eventually choose for implementing your pipeline, ensure to include security checks like static application security testing(SAST) with trivy, bridgecrew or synk.

###### Observation  
I buy into the DevSecOps philosophy - Collaboration, Automation, Security and Measurement. These tenets have been my own North Star in delivering all infrastructure services. Why must you observe? Because you will know how your application and machines are performing, of any nefarious activity, how many requests your system receives, and even the geographic distribution of the requesters(client) - useful for administrators and executives but may be slightly misleading. Some tools that may help you gain visibility include Prometheus, Loki, Fluentd, Datadog, New Relic, Falco, Grafana, etc.

###### Security  
All hell is let loose if you fail on this. Notice that several sites are now always prompting you with several challenges, reminding you to enable a Two-Factor authentication (2FA) and even taking it a notch to call, text or email you to validate that you are indeed whom you claim you are. This is because the nefarious activities of the bad actors have exponentially increased, and companies want to protect the less tech-savvy from basic attacks. In the end, humans are still always the least barrier to entry into a system.   
  
The EE engineer must understand how web applications work and best practices for developing and operating a web application - 10TOP OWASP highlights web application security best practices. However, it should not end there. Every application on the internet is a living breathing entity. Tools get outdated, libraries are discovered with vulnerabilities, and application functionalities are deprecated. It is only wise for the EE engineer to nurture their applications else they will be susceptible to attacks.  
  
Every organization, therefore, needs to have a security team or at least have security woven into the fabric of its software development and delivery process. Carrying out internal penetration tests and security drills is essential. While this may seem one of the difficult functions for the EE engineer since it requires depth in several areas and undoubtedly appears to be important in keeping your castle from being destroyed, it is inevitable if you must hold the fort.

###### Incident Response/Disaster Recovery  
After all knobs and nuts of security are tightened, and a bad actor manages to gain entrance or even probably cause some harm, what do you do? Well, that is when you should activate your plan B to Z. Before an attack, the team must have defined a standard operating procedure (SOP) which usually varies with organizations.  
  
Some general areas to institute SOP may include events of customer data exfiltration, network/system failures, etc. The EE engineer must understand the architecture of the system they manage, mark out possible failure points or most likely compromisable services within the entire architecture, define mitigations, and describe a remediation strategy. 

---  
>I build secure and reliable infrastructures, hunt for flaws in insecure systems and remediate them to meet compliance. Book a consultation [session](https://calendly.com/samuelnwoye/10min).
 
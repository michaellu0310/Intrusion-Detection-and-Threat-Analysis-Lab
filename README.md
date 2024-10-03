# Intrusion Detection and Threat Analysis Lab
## Introduction
This lab was made from scratch to simulate a real-world network attack focusing on detecting, logging, and analyzing threats in a controlled environment.

The lab will involve creating two virtual machines: one running Kali Linux (acting as the attacker) and the other running Ubuntu (serving as the victim and network analyzer). The Kali Linux machine will utilize a backdoor [Metasploit](https://www.metasploit.com/) method to attempt exploit, while the Ubuntu machine will employ [Snort](https://www.snort.org/) as an IDS/IPS and logging solution, and [Wireshark](https://www.wireshark.org/) as a network analyzer.

Key Skills: IDS/IPS, Network Traffic Analysis, Snort, Metasploit, Wireshark, Kali Linux, Ubuntu, CLI, Logging, VIM, VM IP/Network Configuration, Pentesting

#

## Setup
To start the lab, we'll set up both of the Kali Linux and Ubuntu Linux machines on Oracle VM VirtualBox. Kali Linux is heavily utilized for infosec and I wanted to give it a try for this project. We will also set up Snort for the Ubuntu machine utilizing promiscuous mode, which allows for the device to intercept and read traffic in the network regardless of their destination. We also make sure that we have vim installed on Ubuntu for text editing and Wireshark for analysis at the end.

![1](https://github.com/user-attachments/assets/f60748cc-9b4f-4dbe-b3e6-e83d679c835a)
![2](https://github.com/user-attachments/assets/adc9c8e1-e8b4-4c19-98a9-239ff89b4581)

#

### Configuring Snort to match network settings & disabling rules
Network settings can be found on linux machines using ```ip a s``` or ```ifconfig```. We want to delete existing rules because we want to try creating our own rules for this specific project.
![3](https://github.com/user-attachments/assets/37b4b5c0-a0c7-4238-a674-ac49e38fecfd)
![4](https://github.com/user-attachments/assets/36ad393c-bec8-487a-8ffd-8b023ae27e78)
![5](https://github.com/user-attachments/assets/68782b44-63a2-4679-9e55-faf2574dcf93)

#

### Creating a new rule on Snort local.rules to detect ICMP traffic between both Kali and Ubuntu VMs
Breakdown of ```alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Detected"; sid:100001; rev:1;)```:\
This message will alert on Snort that any ICMP requests coming from any external address with any external port to any of the home network (subnet) with any port will display the message 'ICMP Ping Detected'. Sid and rev are unique identifiers for this alert.
![6](https://github.com/user-attachments/assets/481d1692-6c76-4fa7-9461-7d8fcdbb48de)

#

### Snort detection
On the Ubuntu machine, we will run the command ```sudo snort -q -l /var/log/snort -i enp0s3 -A console -c /etc/snort/snort.conf``` and wait for responses from the Kali Linux pings which should display the following results:
![7](https://github.com/user-attachments/assets/52678d2b-d91b-471b-997a-32697ec1d8f8)
![8](https://github.com/user-attachments/assets/10b80a27-ad0c-4b13-bb1c-263f168ba610)

#

### Snorpy
[Snorpy](http://snorpy.cyb3rs3c.net/) is a simple but powerful tool to help write Snort rules. We are setting up a simple TCP alert rule in Snort for the upcoming Metasploit alert that comes after this portion.
![9](https://github.com/user-attachments/assets/13cf1d0c-0292-492c-adfb-9620a0d93ef9)

#

### Metasploit
We will set up Metasploit, a powerful pentesting tool, on the Kali Linux machine. If we had a Windows machine we would've attempted utilizing eternalblue, however, since we are using an Ubuntu machine for IDS/IPS we are using a backdoor method instead. We make sure that Snort is listening and run the exploit.
![10](https://github.com/user-attachments/assets/8a6fe125-78c1-4e05-8574-3f3f3280399a)
![11](https://github.com/user-attachments/assets/51ce4cf2-30be-47f6-b9ba-84d5b585876b)

#

### Snort Logging & Wireshark Analysis
On a separate instance on the Ubuntu machine we use ```sudo snort -q -l /var/log/snort -i enp0s3 -A fast -c /etc/snort/snort.conf``` for logging so that we can feed this for analysis in Wireshark. Within Wireshark, we see several logs and follow stream for a suspicious looking log for details. In this case we see that there is a failed attempt at logging in and other details related to this log file.
![12](https://github.com/user-attachments/assets/5a45e4c4-c121-4a72-ba2e-b2d62058b550)
![13](https://github.com/user-attachments/assets/e3e8448e-b67e-42e2-984a-50c7d757a572)
![14](https://github.com/user-attachments/assets/f03d4688-6869-4aa0-85e8-5eea14a40024)

### Challenges & Solutions

**Challenge 1:** Kali Linux did not have the proper tools to download anything on terminal such as installing metasploit.\
**Solution 1:** Kali Linux needed to install the debian package to get started for this project.

**Challenge 2:** When running ```sudo snort -T -i enp0s3 -c /etc/snort/snort.conf``` it said ```ERROR: /etc/snort/snort.conf(280) Unknown rule type: et. Fatal Error. Quitting..```\
**Solution 2:** Going back into snort.conf using vim and removing the extra typo lines when trying to exit vim

**Challenge 3:** VMs utilizing same IP so I cannot ping to test snort\
**Solution 3:** In VirtualBox, set each VM network setting to be Host-Only Ethernet Adapter

**Challenge 4:** With the new IP Addresses both VMs refuses to talk to each other\
**Solution 4:** In VirtualBox, create and set NAT Network for both machines

**Challenge 5:** Finding var folder for snort logs\
**Solution 5:** Press CTRL+H in file explorer to show hidden folders

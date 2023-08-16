# Red-Team-Simulation-1
A Red Team engagement that exposed Child and Parent Domain Controllers

### **Initial Access SCOPE of Engagement :**

## **[172.16.25.0/24](http://172.16.25.0/24) [ONLY 172.16.25.1 is out of scope]**

### Objective:

1. The goal of the challenge is to exfiltrate the file "**secret.xml**" placed in one of the end servers, all the steps must be documented in a **PDF report.**
2. You must get the highest (**root/administrator**) level command execution in order to pass the examination

### Executing my .ovpn exam environment

```bash
openvpn CCRTA-Exam-TCP4-4443-exam_operator-config.ovpn
```
## My Attacker IP Address: 172.16.250.4
![Screenshot 2023-07-08 at 9 48 01 AM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/c362d61d-db0d-44ce-a491-354a3e131b86)

# Enumeration

Enumerating the given IP Ranges

```bash
nmap -sn 172.16.25.0/24 > ./Findings/nmap_172-16-25-0_24.txt
```

And resulted me to 3 IP Addresses

![Screenshot 2023-07-08 at 10 02 27 AM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/f4b1128b-60cf-4940-a21a-36e06540e8d6)

### Network Details

| External IP Address | Remarks | Description |
| --- | --- | --- |
| 172.16.25.1 | Out of Scope |  |
| 172.16.25.2 | 22 open ports | Production-Server |
| 172.16.25.3 | 4 open ports (with no port 80), but with RDP port open | child.redteam.corp/Employee-System |

Enumerating 172.16.25.2 using nmap scan, and had 22 open ports

```bash
nmap -A -sV -sT 172.16.25.3 > ./Findings/nmap_172-16-25-3.txt
```
## 172.16.25.2
![Screenshot 2023-07-08 at 10 08 45 AM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/0abb9949-5de9-45a0-a1a8-28b95dab850c)
![Screenshot 2023-07-08 at 10 09 23 AM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/9471722f-34b3-4bc3-bb7a-ecde9ccb7189)
![Screenshot 2023-07-08 at 10 09 51 AM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/d5229108-4ded-454b-8b1b-112133ff6e44)

## 172.16.25.3

```bash
nmap -A -sV -sT 172.16.25.3 > ./Findings/nmap_172-16-25-3.txt
```

We found 4 open ports and validates that this is windows machine where port 3389 
![Screenshot 2023-07-08 at 10 04 54 AM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/7d0f1ee4-c0da-4bac-bfe2-92f8661fc69d)

I will get back to this later, while I proceed on IP 172.16.25.2

## port 80 at 172.16.25.2

since port 80 is open, I look at http://172.16.25.2, a Registration page for Red Team Lab

![Screenshot 2023-06-28 at 9 32 04 AM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/671daaca-c974-4258-a7ae-257fbd4f1307)

I tried the registration but it give us an error 

![Screenshot 2023-06-28 at 10 13 38 AM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/344afbb0-1575-43d3-ae7b-6ee68400c194)

![Screenshot 2023-07-08 at 10 13 21 AM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/91e3e2ad-abd0-440f-9218-5d61302bcc68)

error after the registration

## vsftpd 2.3.4

Since I couldn’t get any information on port 80, I moved to the service running on port 21 which I believed vsftpd 2.3.4 has vulnerability.
![Screenshot 2023-07-08 at 10 14 41 AM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/725b9bde-e9bc-4b4f-b502-c931fad37585)

| Vulnerability | System | CVSS Version 3.x | CVSS version 2.0 |
| --- | --- | --- | --- |
| CVE-2011-2523 vsftpd 2.3.4 | 172.16.25.2 | 9.8 Critical | 10.0 High |

Using metasploit, We look on possible use of the  vsftpd 2.3.4 service vulnerability.

![Screenshot 2023-07-0![Screenshot 2023-07-08 at 12 23 21 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/dd0ebfc7-2a0f-45c7-bb2b-87bf7d892530)

I found an exploit for vsftpd 2.3.4 which is a Backdoor Command Execution and can be used to the target machine. Selecting the module - exploit/unix/ftp/vsftpd_234_backdoor, and the setting up the following:

RHOSTS: 172.16.25.2

verbose: True
![Screenshot 2023-07-08 at 12 32 16 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/85d66a19-cd8e-4bdf-878c-2ca84995d926)
![Screenshot 2023-07-08 at 12 34 13 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/12289f49-0fef-4bfb-b606-8c930d4849ae)

Executing the exploit and a shell session was created, since this is not a stable shell
![Screenshot 2023-07-08 at 12 35 08 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/e90ebfff-f2db-4298-af96-4ab0ca80cef6)

To have a interactive shell, I execute a terminal (tty) spawned via Python

```bash
python -c "import pty;pty.spawn('bin/bash')"
```

I got a root shell under the host-name Production-Server

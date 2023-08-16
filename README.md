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

![Screenshot 2023-07-08 at 12 23 21 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/dd0ebfc7-2a0f-45c7-bb2b-87bf7d892530)

I found an exploit for vsftpd 2.3.4 which is a Backdoor Command Execution and can be used to the target machine. Selecting the module - exploit/unix/ftp/vsftpd_234_backdoor, and the setting up the following:

RHOSTS: 172.16.25.2

verbose: True

![Screenshot 2023-07-08 at 12 32 16 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/85d66a19-cd8e-4bdf-878c-2ca84995d926)
![Screenshot 2023-07-08 at 12 34 13 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/12289f49-0fef-4bfb-b606-8c930d4849ae)

Executing the exploit and a shell session was created, but this is not a interactive shell
![Screenshot 2023-07-08 at 12 35 08 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/e90ebfff-f2db-4298-af96-4ab0ca80cef6)

To have a interactive shell, I execute a terminal (tty) spawned via Python

```bash
python -c "import pty;pty.spawn('bin/bash')"
```

I got a root shell under the host-name Production-Server

## Production-Server
![Screenshot 2023-06-28 at 10 26 54 AM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/97d6cd96-e1cf-40ea-bbd1-7f6b50188946)

we got a root shell of Production-Server

From here I checked the /etc/passwd to check some interesting credentials

```bash
cat /etc/passwd
```
![Screenshot 2023-07-08 at 12 40 06 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/20e0ba04-b946-4db0-b5d4-e728f6129ff4)


I found a a familiar credential

```bash
msfadmin:x:1000:1000:msfadmin,,,:/home/msfadmin:/bin/bash
```

I look around to gather more interesting information. I found another user named “prod-admin”.

![Screenshot 2023-07-08 at 12 46 22 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/70ab05d3-f736-4627-89f7-e0faa4aa9423)


## prod-admin

I navigate to home root directory and found 5 users folders. And look to the prod-admin folder and found a file named “credential.txt”

![Screenshot 2023-07-08 at 12.48.49 PM.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/f820bfd7-0596-4d6d-a482-ec24c7ccd75f/Screenshot_2023-07-08_at_12.48.49_PM.png)

```bash
cd prod-admin
ls
cat credential.txt
```

![Screenshot 2023-07-08 at 12.49.43 PM.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/bdbd9c90-db88-4268-878e-d1684a2d7a1f/Screenshot_2023-07-08_at_12.49.43_PM.png)

2 interesting credentials

| User Name | Password |
| --- | --- |
| support | support@123 |
| prod-admin | Pr0d!@#$% |

First, I try to login using the 1st credential - support:support@123. It doesn’t work

```bash
ssh support@172.16.25.2
```

![Screenshot 2023-07-08 at 12.56.23 PM.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/e81bd488-0d26-48d1-a431-26bcf5bcaaba/Screenshot_2023-07-08_at_12.56.23_PM.png)

Next, I go with trying the 2nd credential - prod-admin:Pr0d!@#$%. It does work

```bash
ssh prod-admin@172.16.25.2
```

![Screenshot 2023-07-08 at 12.59.25 PM.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/addbefde-204a-4444-a000-2a6926ffdbc5/Screenshot_2023-07-08_at_12.59.25_PM.png)

So far this is the summary of what I got from the root directory enumeration of the Production-Server.

| User’s Directory | Remarks |  |
| --- | --- | --- |
| ftp | nothing interesting |  |
| msfadmin | nothing interesting |  |
| prod-admin | found credential.txt | Support User Credential = support:support@123 and Prod-admin Credential = prod-admin:Pr0d!@#$% |
| service | nothing interesting |  |
| user | nothing interesting |  |

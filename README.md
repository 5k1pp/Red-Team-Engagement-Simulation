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

![Screenshot 2023-07-08 at 10.02.27 AM.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/4fd37c2e-ff88-484a-b8b1-532b892fa67c/Screenshot_2023-07-08_at_10.02.27_AM.png)

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

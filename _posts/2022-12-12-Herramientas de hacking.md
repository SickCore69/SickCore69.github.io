---
layout: single  
title: Herramientas de hacking.
excerpt: "Las herramientas de hacking son utilizadas para realizar pruebas de penetración en sistemas y redes para detectar vulnerabilidades y mejorar la ciberseguridad."
date: 2022-12-12  
classes: wide
header:
  teaser: /assets/images/eh.jpg
  teaser_home_page: true
categories:
- Pentesting  
- Ethical Hacking
tags:
- Fuzzing
---

Las herramientas de hacking son utilizadas para detectar y corregir vulnerabilidades antes de que pueden ser explotadas por ciberdelincuentes. Tener una gran variedad de herramientas de hacking te permitirá tener mas alcance al aplicar reconocimiento y explotación de vulnerabilidades ya sea en auditorias o en entornos controlados.<br>

## Nmap.
Es una herramienta utilizada escanear sistemas y redes con el fin de detectar los dispositivos conectados y su configuración asi como los servicios que se estan ejecutando. Tambien puede ser utilizada para detectar vulnerabilidades en los dispositivos encontrados, información sobre el sistema operativo y descubrir puertos abiertos.<br>

Escaneo para verificar si un dispositivo es vulnerable a EternaL Blue.
```
nmap --script "vuln and safe" -p445 <ip-address> -oN smbScan
# Escaneo que lanza todos los scripts pertenecientes a la categoría "vulnerabilidad y seguridad" 
detectando vulnerabilidades y buscando las medidas de seguridad implementadas en el dispositivo en 
el puerto 445 (SMB) y el resultado lo exporta en formato normal al archivo smbScan.
```
<br>
Escaneo por TCP a todo el rango de puertos (65535) que te reporta solo aquellos puertos que tengan status abierto lanzando un TCP-SYN PortScan indicando que quieres lanzar paquetes no mas lentos de 5000 paquetes por segundo y a medida que se vaya realizando el escaneo se te vaya reportando por consola sin que te aplique resolución DNS ni descubrimineto de hosts y el resultado te lo exporta en formato grepable para despues filtrar con expresiones regulares al archivo allPorts. 
```
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn <ip-address> -oG allPorts

# -p- -> Indica el rango de puertos a escanear (-p65535).
# --open -> Te reporta status del puerto ya sea que esta abierto, filtrado o cerrado(--open, --filtered y --close).
# -sS -> Escaneo rápido y discreto que te ayuda a no ser detectado por un firewall ya que solo envía un paquete SYN al sistema y si el puerto esta abierto responderá con un SYN-ACK sino este responderá con un RST cortando la comunicación.
# min-rate 5000 -> Establece la velocidad mínima por segundo de los paquetes tramitados.
# -vvv -> Triple verbose para obtener información detallada acerca del escaneo.
# -n -> Parámetro para deshabilitar la resolución de nombres de dominio.
# -Pn -> Desactivar la detección del estado de host(El estado de host es saber si el sistema o red esta activo mediante el envío de paquetes de ping)
# -oG -> Exportar el resultado del escaneo en formato grep al archivo alPorts.
```
<br>
Escaneo por UDP a los 100 puertos más comunes reportando solo aquellos que tengan status abierto controlando el temporizado del escaneo y a medida que se vaya realizando el escaneo se va reportando por consola sin que te aplique resolución DNS ni descubrimiento de host y el resultado lo exporta al archivo updPorts en formato grepable.
```
nmap -sU --top-ports 100 --open -T5 -v -n -Pn <ip-address> -oG updPorts
# -sU -> Indica que el escaneo será por el protocolo UDP.
# --top-ports -> Establece los puertos más comunes para realizar el escaneo.
# --open -> Te reporta solo aquellos que esten abiertos.
# -T5 -> Establece un tiempo de espera para cada puerto de 5 segundos.
# -v -> Muestra información detallada del escaneo.
# -n -> Deshabilita a la resolución DNS.
# -Pn -> Evita la detección de estado del host.
# -oG -> Exporta el resultado del escaneo al archivo udpPorts.
```
<br>
Tipo de escaneo es utilizado en caso de que haya un firewall que bloquee el escaneo normal por TCP. Este escaneo tambien se realiza por TCP solo que lanza las flags FIN, PSH y URG al sistema o red y si este responde con una flag de RST significa que el puerto puede estar filtrado o cerrado.
```
nmap -p- -sX --min-rate 5000 -vvv -n -Pn <ip-address> -oG xPorts 
```
<br>
Escaneo para ver si un puerto se encuentra abierto.
```
nmap -p445 --open -sS -T5 -v -n <ip-address> 
```
<br>
Escaneo de red sin conexión para encontrar dispositivos conectados a una red lanzando paquetes de ping a todos los dispositivos en la subred especificada(192.168.0.0/24). A este tipo de escaneo se le denomina escaneo de ping.
```
nmap -sn 192.168.0.0/24
# En este caso la subred incluye todas las direcciones IP desde 192.168.0.0 hasta 192.168.0.255.
# La subred(192.168.0.0/16) tambien puede ser de 16 bits que iría desde 192.168.0.0 hasta 192.168.255.255.
```
<br>
Escaneo para enumerar los recursos de un servidor web con nmap para encontrar directorios y archivos realizando solicitudes HTTP en el puerto 80 y asi poder evaluar la seguridad del sitio web.
```
nmap --script http-enum -p80 <ip-address> -oN webContend
```
<br>
En caso de encontrar el directorio cgi-bin puedes utilizar el siguiente escaneo para comprobar si el sitio web es vulnerable a un shellshock attack. El shellshock es una vulnerabilidad en el intérprete de comandos de Bash que te permiter ejecutar comandos en el sistema.
```
nmap --script http-shellshock --script-args url=</cgi-bin/user.sh> -p<port> <ip-address>
# --script-args <nombre_argumento>=<valor_argumento> -> Es para especificar argumentos adicionales para que el script 
# http-shellshock pueda utilizarlos al hacer las peticiones al sitio web.
# url= -> Indica al script que utilice la dirección donde se harán las solicitudes HTTP(/cgi-bin/user.sh).
```
<br><br>
## Hydra.
Es una herramienta utilizada para probar la seguridad de un sistema y encontrar posibles vulnerabilidades. Su objetivo es aplicar fuerza bruta para descifrar posibles usuarios y contraseñas debiles mediante el uso de diccionarios. Hydra puede ser usada en diferentes protocolos(FTP, SSH, HTTPS, SMB, Telnet).
```
hydra -L userlist -P passwordlist <ip-address> <protocol>
# -L -> Es para indicar un diccionario de usuarios.
# -P -> Indica una lista de contraseñas a probar.
# <protocolo> -> Para especificar el protocolo donde será aplicado el ataque de fuerza bruta.
```
![](/assets/images/hydra.webp)
<br><br>
## Shearchsploit.
Es una herramienta de linea de comandos que se utiliza para buscar exploits en la base de datos de  Exploitdb. Esta base de datos contine exploits maliciosos que puedes utilizar para explotar vulnerabilidades en los sistemas informaticos.<br>
Para utilizar el comando searchsploit debes primero instalar la base de datos exploitdb.<br>
`` sudo apt install exploitdb ``
Una vez que hayas realizado el reconocimiento de puertos puedes buscar vulnerabilidades relacionadas con la versión de los servicios mediante palabras clave. Al buscar un exploit te da una breve descripción del script y la versión que afecta.
```
searchsploit ssh user enumeration

 Exploit Title                                                                                |  Path
---------------------------------------------------------------------------------------------- ---------------------------------
OpenSSH 2.3 < 7.7 - Username Enumeration                                                      | linux/remote/45233.py
OpenSSH 2.3 < 7.7 - Username Enumeration (PoC)                                                | linux/remote/45210.py
OpenSSH 7.2p2 - Username Enumeration                                                          | linux/remote/40136.py
OpenSSH < 7.7 - User Enumeration (2)                                                          | linux/remote/45939.py
OpenSSHd 7.2p2 - Username Enumeration                                                         | linux/remote/40113.txt
```
Puedes ver el código del script para ver que hace con más detalle con el parámetro -x seguido de la ruta del script.
```
searchsploit -x linux/remote/45233.py
```
Para hacer uso del script tienes que copiarlo a la ruta actual de trabajo y darle un nombre descriptivo.
```
searchsploit -m linux/remote/45233.py && mv 45233.py userEnumerationSSH.py

userEnumerationSSH.py <ip-address> # Ejecución del script para enumerar usuarios en el protocolo SSH entre la versión 2.3 < 7.7
```

<br><br>
## Whatweb.
Es una herramienta utilizada para recopilar información de un sitio web, con whatweb puedes detectar las tecnologías que están siendo usadas, el software del servidor, el sistema operativo y aplicaciones web. Para instalar la herramienta basta con hacer `` sudo apt install whatweb ``
```
whatweb https://<ip-address>
whatweb http://<nombre del sitio web>
```
<br><br>
## Smbmap.
smbmap sirve para escanear y enumerar recursos compratidos de red en un host SMB(Server Message Block). Tambien puedes descargar archivos y realizar ataques de fuerza bruta a cuentas de usuarios  en un sistema SMB. Smbmap se instala con `` sudo apt install smbmap ``
```
smbmap -H <ip-address> # Enumerar recursos compartidos.
smbmap -H <ip-address> -u 'null' # Enumerar recursos haciendo uso de null session.
smbmap -u <username> -p <password> --download <ruta/del/archivo> <ruta/donde/se/guardara/el/archivo> # Descargar un recurso de sistema
smbmap -u <username> -p <password_list> <ip-address> # Fuerza bruta al protocola SMB.
```
<br><br>
## Smbclient.
Al igual que smbmap, smbclient te permite enumerar los recursos compartidos que existen en un servidor SMB.<br>
Instalar: `` sudo apt install smbclient ``<br>

```
smbclient -L <ip-address> -N # Listar los recursos compartidos de un servidor SMB disponibles para acceso anónimo.
# -L -> Indica que quieres listar recuros.
# -N -> Indica que no se desea proporcionar usuario y contraseña para autenticarse  en el servidor SMB.
```
En caso de que tengas este error al intentar listar los recursos del sistema "error: protocol negotiation failed: NT_STATUS_CONNECTION_DISCONNECTED" agrega esta linea al final del comando `` --option ' client min protocol = NT1 ' ``. Esto asegurará que la comunicaión del servidor SMB sea compatible con la del servidor estableciando el protocolo minimo NT1.
```
smbclient -L <ip-addess> -N --option 'client min protocol = NT1'
```
Comando para conectarse a un recurso compartido.
```
smbclient //<ip-addess>/tmp -N --option 'client min protocol = NT1' 
# tmp es el nombre del recurso al cual se desea conectar, este puede ser sustituido por cualquier recurso disponible.
```
<br><br>
## Impacket-scripts.
Es una biblioteca de scripts escritos en python utilizada para la seguridad informática. Estas herramientas son utilizadas para pruebas de penetración, ataques de red, analizar y extraer información de paquetes de red. Estos son algunos scripts incluidos en impacket-scripts;
- secretsdump.py: Script utilizado para extraer contraseñas de hashes de Active Directory de diferentes fuentes, como archivos NTDS.dit o archivos SYSTEM.
- wmiexec.py: Con este script puedes ejecutar comandos en un sistema remote a través del protocolo WMI(Windows Management Instrumentation).
- smbserver.py: Script para crear un servidor SMB falso en tu equipo local y asi engañar a otros equipos en la red para que se conecten a el. Una vez establecida la conexión puedes capturar credenciales de inicio de sesión y datos sensibles enviados por los equipos.<br>Tambien puedes usar este script para montarte un servicio SMB y transferir archivos entre equipos.


```
secretsdump.py <DC-ip-address> -u <username> -p <password>
wmiexec.py <ip-address> -u <username> -p <password>
smbserver.py 'nombre_del_recurso' 'ruta_del_recurso' -smb2support
# nombre y ruta del recurso son opcionales sino se ponen se utilizan valores predeterminados.
smbserver.py smbFolder $(pwd) -smb2support 
```
<br><br>
## Chisel.
Es utilizado para crear túneles seguros entre dispositivos en una red. Chisel te permite conectarte de forma segura a un servidor remoto a tráves de un puerto no seguro. En el hacking chisel es usado a menudo para hacer port forwarding(enrutamiento de puertos) que consiste en redirigir el tráfico de un puerto a otro de una máquina remota o local.
```

```
<br><br>
## Evil-winrm.
Herramienta usada para conectarte al Administrador Remoto de Windows (Windows Remote Management) y ejecutar comandos.
```
evil-winrm -i <ip-address> -u '<username>' -p '<password>'
```
<br><br>
## Exiftool.
Con exiftool puedes leer o editar los metadatos de archivos de imagen o vídeo, como la fecha y hora de creación, marca y modelo de la cámara asi como los permisos del archivo. Solo ejecutas la herramienta y le pasas el nombre del archivo para que te muestre la información.
```
exiftool image.jpg # Leer los metadatos.
exiftool TAG=VALUE image.jpg # Editar metadatos de un archivo.
# TAG -> Es el nombre del metadato que quieres modificar.
# VALUE -> Es el contenido nuevo que tendra ese metadato.
```
<br><br>
## Crackmapexec.
Herramienta diseñada para escanear y explotar vulnerabilidades en servidores de red y dispositivos. Con crackmapexec puedes conectarte a diferentes servidores (SMB, HTTP, SSH, RDP y mssql). Puedes ver información acerca del equipo, ver si un usuario y contraseña son válidos en el sistema, listar recursos compartidos o probar si un hash pertenece al usuario Administrador.
```
crackmapexec smb -s <ip-address/24> 	# Escaneo de vulnerabilidades a todo segmento de red en el  protocolo SMB.

crackmapexec smb <ip-address> 		
# Ver información acerca del equipo como la versión del sistema operativo, ver el nombre del dominio o si el SMB esta firmado.

crackmapexec smb <ip-address> -u '<username>' -p '<password>'	# Ver si un usuario y contraseña son válidos en el sistema.

crackmapexec smb <ip-address> -u 'null' -p ' ' --shares	
# Listar los recursos compartidos en el sistema haciendo uso de un null session.

crackmapexec smb <ip-address> -u 'Administrator' -H '<hash>'	# Verificar su el hash pertenece al usuario Administrador.
```
<br><br>
## John The Ripper.

<br><br>
## Wpscan.

<br><br>
## Wafw00f.

<br><br>
## Gobuster.

<br><br>
## Wfuzz.

<br><br>
## Node-serialize.

<br><br>
## Gdb.

<br><br>
## Hulk.py
Hacer un ataque DOS.
<br><br>
## Cupp.py
Crear diccionarios de contraseñas con inforamción que le proporciones.
<br><br>
## Cewl.
Crear diccionario de usuarios y contraseñas con la información de un sitio web.

<br><br>
## Tcpdump.
Ponerse en escucha

<br><br>
## Aircrack-ng.
Audotorias wifi

<br><br>
## Steghide.

<br><br>
## Fixgz.
Reparar archivos corruptos.

<br><br>
## Macchanger.

<br><br>
## Rlwrap.

<br><br>
## Davtest.

<br><br>
## Html2text.

<br><br>
## Htmlq.

<br><br>
## Tshark.

<br><br>
## Snmp.

<br><br>
## Onesixtyone.

<br><br>
## Pwdtools.

<br><br>
## Locate.






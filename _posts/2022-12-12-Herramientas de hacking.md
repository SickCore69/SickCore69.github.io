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
smbmap sirve para escanear y enumerar recursos compartidos de red en un host SMB(Server Message Block). Tambien puedes descargar archivos y realizar ataques de fuerza bruta a cuentas de usuarios  en un sistema SMB. Smbmap se instala con `` sudo apt install smbmap ``
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
Es una biblioteca de scripts escritos en python utilizada para la seguridad informática. Estas herramientas son utilizadas para pruebas de penetración, ataques de red, analizar y extraer información de paquetes de red. Estos son algunos scripts incluidos en impacket-scripts.<br>
Instalación: `` sudo apt install impacket-scripts ``
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
Es utilizado para crear túneles seguros entre dispositivos en una red. Chisel te permite conectarte de forma segura a un servidor remoto a tráves de un puerto no seguro. En el hacking chisel es usado a menudo para hacer port forwarding(enrutamiento de puertos) que consiste en redirigir el tráfico de un puerto a otro de una máquina remota o local.<br>
Instalación: `` wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_arm64.gz ``
Hacer uso de chisel para aplicar un RPF (Remote Port Forwarding).
```
./chisel server --reverse -p 1234   

./chisel client <ip-address>:1234 R:80:<ip-address>:80
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

crackmapexec smb <ip-address> -u 'Administrator' -H '<hash>'	# Verificar si el hash pertenece al usuario Administrador.
```
<br><br>
## John The Ripper.
Herramienta utilizada para probar la seguridad de las contraseñas mediante el uso de diccionarios. John the ripper utiliza diferentes tipos de algoritmos para decifrar contraseñas como MD5, SHA1, SHA2, DES, Blowfish y AES.<br>
Instalación: `` sudo apt install john ``<br>
Descifrar un hash.
```
john --wordlist=</ruta/del/diccionario/rockyou.txt> <hash>
```
Descifrar el /etc/shadow.
```
john -w:</ruta/del/diccionario/rockyou.txt> shadow	
```
Fucionar el archivo /etc/passwd y el /etc/shadow en un archivo.txt para posteriormente crackear las contraseñas.
```
unshadow <passwd> <shadow> > password.txt # Fusión de los archivos. 

john -w:rockyou.txt passwords.txt

john --show <archivo.txt> # Muestra las contraseñas obtenidas.
```
```
zip2john archivo.zip > archivo.zip.john		
# Se genera un archivo compatible con john para poder crackear la contraseña con la cual fue cifrado el archivo.zip

zip2john archivo.zip.john	# Ya solo ejecuta el comando para descifrar la contraseña

rar2john archivo.rar
rar2john archivo.rar.john
```
<br><br>
## Wpscan.
Wpscan sirve para escanear sitios web basados en Wordpress y detectar vulnerabilidades y problemas de seguridad como vulnerabilidades de aplicaciones, de plugins y temas, y problemas de configuración.<br>
Instalación: `` sudo apt install wpscan ``<br>
```
wpscan --url https://<ip-address>    # Escaneo para detectar problemas de configuración o vulnerabilidades.
wpscan --url https://<nombre-dominio> --enumerate    # Enumerar usuarios, plugins y temas.
wpscan --url http://<ip-address> -U <username> -P <pasword-list>    # Aplicar fuerza bruta. 
```
<br><br>
## Wafw00f.
Esta herramienta detecta sistemas de proctección de aplicaciones web(Web Aplication Firewall) en una dirección IP o un sitio web para saber si se esta utilizando uno y en todo caso te muestra información detallada del tipo de WAF en uso inclutendo la versión y fabricante.<br>
Instalación: `` sudo apt install wafw00f ``
```
wafw00f https://<ip-address>
```
<br><br>
## Gobuster.
Sirve para detectar archivos, subdominios y directorios ocultos en un sitio web.<br>}
Instalación: `` sudo apt install gobuster ``<br>
```
gobuster dir -t 200 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u https://<ip-address> -k
# dir -> Indica que se desea realizar un escaneo en busca de directorios.
# -t 200 -> Indica los hilos o las tareas que quieres que se ejecuten simultaneamente.
# -w -> Especificar el diccionario.
# -u -> Indicar la dirección IP o el nombre del dominio donde se realizará el escaneo.
# -k -> Es para deshabilitar la verificación de certificados SSL. No se verificará si un certificado SSL es válido o no al reaizar las solicitudes HTTPS. 

gobuster vhost -t 100 -w /usr/share/SecLists/Discovery/DNS/Subdomain-top1million-5000.txt --url https://<ip-address> -k
# Escaneo para detectar subdominios en el sitio web.

gobuster dir -t 150 -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://<ip-address> -x php,html,txt,bak,backup,git,pdf
# Escaneo para encontrar archivos ocultos.
# -x -> Indica que se utlizará una lista de extensiones separadas por coma. Sino se especifica una entensión te mostrará todas las extensiones encontradas.
```
<br><br>
## Wfuzz.
Al igual que gobuster, wfuzz sirve para detectar archivos, subdominios y directorios en un sitio web. Wfuzz envía solicitudes HTTP a un servidor web y variando los parámetros de la solicitud de manera automática. Esto permite a wfuzz probar distintos valores para los parámetros y ver cómo el servidor web responde a ellos, lo que ayuda a detectar posibles vulnerabilidades.<br>
Instalación: `` sudo apt install wfuzz ``
```
wfuzz -c  --hc=404 -t 200 -w diccioanrio.txt https://<ip-address> --ssl-ignore-cert
# --ssl-ignore-cert -> Deshabilita la verificación del certificado SSL
```
```
wfuzz -c -z file,password_list.txt --hs "password=FUZZ" http://dominio.com/login
# -c -> Indica que se debe mostrar el progreso de la ejecución del comando. Esto puede ser útil si estás ejecutando una prueba
que llevará mucho tiempo y quieres tener una idea de cómo va.
# -z -> Indica a wfuzz que debe utilizar un archivo de datos específico como entrada para la prueba. En este caso, se utiliza
el archivo "password_list.txt" como la lista de contraseñas a probar.
# --hs -> Indica a wfuzz que debe incluir una cadena específica en la solicitud que envía al sitio. En este caso se utiliza 
la cadena "password=FUZZ" para indicar que la contraseña de la lista debe reemplazarse en el parámetro "password" del 
formulario de inicio de sesión.

```
<br><br>
## Node-serialize.
node-serialize es una biblioteca de JavaScript diseñada para facilitar la serialización y deserialización de objetos. La serialización es el proceso de convertir un objeto en una representación de cadena de texto, mientras que la deserialización es el proceso de convertir una cadena de texto en un objeto. Esto es útil cuando se necesita guardar un objeto en una base de datos o enviarlo a través de la red.<br>
Instalación: `` npm install nose-serialize ``
<br><br>
## Gdb(GNU Debugger).
Es una herramienta de depuración de código fuente que se utiliza para examinar y depurar programas en diferentes lenguajes de programación. GDB te permite detener la ejecución de un programa en cualquier momento y examinar su estado, incluyendo variables, datos de memoria, establecer puntos de interrupción, evaluar expresiones y hacer seguimiento de la ejecución del programa linea por linea.
<br><br>
## Hulk.py
Hulk.py sirva para realizar pruebas de denegación de servicios(DOS) a un sitio web y asi probar su capacidad ante grandes cantidades de tráfico. Este script envía solicitudes HTTP simultáneamente con el objetivo de sobrecargar el servidor y evaluar el como responde ante la alta carga.<br>
Instalación: `` wget https://github.com/grafov/hulk/blob/master/hulk.py ``
```
python3 hulk.py <url>
```
<br><br>
## Cupp.py
Script de python que se utiliza para crear diccionarios personalizados y poder aplicar fuerza bruta. Tiene una seriede opciones que le permiten especificar el tipo de información que se incluirá, como nombres de usuario, palabras clave y patrones comunes de contraseñas.<br>
Instalación: `` git clone https://github.com/Mebus/cupp ``
```
python3 cupp.py
```
<br><br>
## Cewl (Command Engine World List).
Herramienta para crear un diccionario de palabras a partir de la información disponible en un sitio web. Cewl escanea el sitio web y extrae palabras y frases que se pueden usar como contraseñas o palabras clave para utilizar fuerza bruta.<br>
```
cewl <url> -w <nombre-diccionario.txt>
# -w <archivo.txt> -> Indica el nombre del archivo donde se almacenará la lista de palabras.
# -m <número> -> Especificar el número mínimo de veces que una palabra debe aparecer en un sitio web para ser incluida en la lista.
# -u <username>:<password> -> Permite especificar un usuario y contraseña para autenticarte en un sitio protegido por contraseña
```
<br><br>
## TCPDump.
TCPDump es una herramienta que se utiliza para analizar y capturar tráfico de red. Es una herramienta de depuración y monitoreo de red utilizada por administradores de sistemas y profesionales de seguridad para realizar tareas como:<br>
- Monitorear el tráfico de red en una red local o a través de una interfaz de red específica.
- Depurar problemas de red y detectar problemas de rendimiento.
- Analizar el tráfico de red para detectar posibles ataques o actividad sospechosa.
- Guardar capturas de tráfico de red para su porterior análisis.


Instalación:`` sudo apt install tcpdump ``<br>
Para utilizar TCPDump, debes específicar  una serie de opciones y filtros para controlar que tipo de tráfico de red se captura y cómo se procesa.<br>Estos son algunos parámetros que puedes incluir en un monitoreo:
* -i: Especifica la interfaz de red que se utilizará para capturar el tráfico. Por ejemplo, -i eth0 que capturaría el tráfico en la interfaz de red Ethernet 0.
* -nn: muestra el número de puerto en lugar de los nombres de los servicios.
* -s: Especifica el tamaño de la captura de paquetes. Ejemplo, -s 65535 capturaría paquetes completos de hasta 65535 bytes.
* -c: Especifica el número de paquetes que se deben capturar. -c 100, capturaría los primeros 100 paquetes.
* -w <archivo.txt>: Escribe la captura de paquetes en un archivo en lugar de mostrarlo en pantalla.
* host <ip-address>: Filtra los paquetes que se envían o reciben desde un host. Ejemplo host 192.168.0.1 capturaría los paquetes que se envían desde el host con la dirección IP 192.168.0.1.
* port <port>: Filtra los paquetes que utiliza un puerto. Ejemplo port 80 capturariá los paquetes que utilizan el puerto 80.

```
tcpdump -i <interfaz-de-red>
# Monitoreo de del tráfico de  una red. 
```
```
tcpdump -i tun0 icmp -n
# Escuchar y capturar el tráfico ICMP(Internet Control Message Protocol) en la interfaz de red tun0 sin que se aplique la 
resolución de nombres de host solo mostrando la dirección IP. Este comando es útil para saber si se puede entablar una 
reverse shell.
```
<br><br>
## Aircrack-ng.
Es una suite de herramientas de seguridad utilizada principalmente para la auditoria de seguridad de redes inalambricas y asi poderla proteger ante posibles ataques. Aircrack cuenta con herramientas para escanear redes, atacar redes inhalambricas protegidas por contraseña y recuperar claves de redes.<br>
Estas son algunas de las herramientas que contiene la suite de aircrack-ng:<br>
- airdump-ng: Permite escanear y capturar tráfico inalámbrico en una red.
- airreplay-ng: Permite inyectar paquetes de tráfico en una red inalámbrica. 
- aircrack-ng: Permite recuperar claves de redes inalámbricas protegidas por contraseña.
- airmon-ng: Permite habilitar y deshabilitar el modo monitor en interfaces de red inalámbricas.
- airodump-ng-oui-update: Permite actualizar la base de datos de identidicadores de organizaciones únicas (OUI) utilizados por aircrack-ng.
- packetforge-ng: Permite crear paquetes de tráfico personalizados para inyectarlos en una red inalámbrica.
- wesside-ng: Permite realizar paquetes de fuerza bruta a redes inalámbricas WEP.
- besside-ng: Permite realizar ataques de fuerza bruta a redes inalámbricas WPA/WPA2.
- airdecloak-ng: Permite descifrar tráfico WEP encriptado utilizando técnicas de "cloaking".
- airtun-ng: Permite crear túneles VPN sobre redes inalámbricas.


Instalación: `` sudo apt install aircrack-ng ``
```
airodump-ng <interface>
# Escanear redes inalámbricas disponibles.
```
```
airodump-ng --bssid <BSSID> -c <canal> <interface>
# Capturar tráfico inalámbrico en una red específica.
```
```
aireplay-ng --fakeauth 0 -a <BSSID> -h <mac-address> <interface>
# Inyectar paquetes de tráfico en una red inalámbrica.
```
```
aircrack-ng <capture_file>
# Recuperar claves de redes inalámbricas protegidas por contraseña.

airmon-ng start <interface>
# Habilitar el modo monitor en una interfaz de red inalámbrica.

airmon-ng stop <interface>
# Deshabilitar el modo monitor en una interfaz de red inalámbrica.
```

<br><br>
## Steghide.
Herramienta para ocultar información confidencial y que no pueda ser vista por personas no autorizadas en imagenes, audios y archivos, utilizando una técnica llamada esteganografía que se basa en la modificación de archivos de texto, imagenes, audio. vídeo, código fuente o archivos de datos.<br>Steghide no proporciona una protección de seguridad fuerte, lo que hace posible que la información pueda ser detectada mediante software especializado.<br>
Instalación: `` sudo apt install steghide ``<br>
Ocultar un archivo llamado "secreto.txt" en una imagen llamada "imagen.jpg".
```
steghide embed -ef secreto.txt -cf imagen.jpg
```
Extraer el contenido almacenado detras de una imagen llamda "imagen.jpg".
```
steghide extract -sf imagen.jpg
```
<br><br>
## Fixgz.
Reparar archivos corruptos .gz.

<br><br>
## Macchanger.

<br><br>
## Rlwrap.

<br><br>
## Davtest.
Herramienta que sirve para probar la configuración y la funcionalidad de un servidor WebDAV (Web Distributed Authoring and Versioning). WebDAV es un protocolo que permite la edición y la administración de documentos en un servidor web de manera remota, utilizando HTTP o HTTPS.<br>Davtest envía solicitudes HTTP a un servidor WebDAV y verifica que se pueden realizar operaciones básicas, como subir y descargar archivos, crear y eliminar directorios y verificar que el servodor está configurado de manera adecuada. También se puede utilizar para probar la autenticación y autorización en el servidor WebDAV y para verificar que se está utilizando una conexción segura (HTTPS).<br>
Instalación: `` sudo apt install davtest ``
```
davtest -url https://<url>
```
<br><br>
## Html2text.
Convierte documentos HTML (Hypertext Markup Language) en formato de texto simple sin que se interpreten las etiquetas.<br>
Instalación: `` sudo apt install html2text ``
```
html2text documento.html > documento.txt
```
<br><br>
## Htmlq.

<br><br>
## Tshark.
Analiza y examina el tráfico de red, ademas captura y guarda el tráfico en un archivo para despues poderlo análizar.<br>
Examinar el tráfico de la interfaz de red eth0 y guardar el resultado en un archivo .pcap.
```
tshark -i eth0 -w captura.pcap
# -i -> Indicar la interfaz de red.
# -w -> Especificar el nombre del archivo en que se guardará la captura de tráfico de red.
```
<br><br>
## Onesixtyone.
Es una herramienta de escaneo de red que prueba la seguridad de dispositivos que utilizan el protocolo SNMP (Simple Network Management Protocol). Onesixtyone envía solicitudes SNMP a los dispositivos de red (routers, switches y hubs) y analiza las respuestas para detectar vulnerabilidades y problemas de seguridad.<br>
Onesixtyone se utiliza comúnmente durante el proceso de pruebas de penetración para evaluar la seguridad de los dispositivos de red. También se puede utilizar para detectar dispositivos que tengan contraseñas débiles o que no estén configurados adecuadamente.<br>
Escanear un dispositivo de red que tenga como contraseña "public".
```
onesixtyone -c public <ip-address>
# -c -> Especificar una contraseña.
# public es una contraseña por defecto utilizada en el protocolo SNMP para permitir el acceso a la información.
```
Escanear un rango de direcciones IP.
```
onesixtyone -c <password> 192.168.1.1-254
```
Escanear un archivo que contenga direcciones IP.
```
onesixtyone -c <password> -i <ips.txt>
# -i -> Especificar el nombre del archivo que contiene las direcciones IP.
```
<br><br>
## Pwdtools.

<br><br>
## Locate.
Herramienta de búsqueda de archivos y directorios que utiliza una base de datos que incluye los nuevos archivos que se añaden y elimina las archivos eliminados para realizar busquedas de manera rápida y eficiente. Practicamente localiza la ruta absoluta donde se encuentra almacenado el archivo que estas buscando.<br>
Install: `` sudo apt install locate ``<br>
Buscar el binario python3.
```
locate python3 
/usr/bin/python3
```




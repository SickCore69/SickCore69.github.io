---
layout: single  
title: Herramientas de hacking.
excerpt: "Son herramientas utilizadas para realizar pruebas de penetración en sistemas y redes para detectar vulnerabilidades y mejorar la ciberseguridad."
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

Este tipo de herramientas son utilizadas para detectar y corregir vulnerabilidades antes de que pueden ser explotadas por ciberdelincuentes.<br>Tener una gran variedad de herramientas de hacking te permitirá tener mas alcance al aplicar reconocimiento y explotación de vulnerabilidades ya sea en auditorias o en entornos controlados.<br>

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
-sU -> Indica que el escaneo será por el protocolo UDP.
--top-ports -> Establece los puertos más comunes para realizar el escaneo.
--open -> Te reporta solo aquellos que esten abiertos.
-T5 -> Establece un tiempo de espera para cada puerto de 5 segundos.
-v -> Muestra información detallada del escaneo.
-n -> Deshabilita a la resolución DNS.
-Pn -> Evita la detección de estado del host.
-oG -> Exporta el resultado del escaneo al archivo udpPorts.
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










---
layout: single
title: Scripting.
excerpt: "En esta sección verás algunos scripts de los cuales puedes apoyarte para ver como se realizan ciertos ataques y automatizar tareas."
date: 2023-01-16
classes: wide
header:
  teaser: /assets/images/script.jpeg
  teaser_home_page: true
categories:
- Pentesting
- Ethical Hacking
tags:
- Scripts
---
## hostDiscovery.sh.
Script en bash para ver si se encuentran otras direcciones IP dentro de la misma red y aplicar pivoting.<br>
El script funciona en base al código de estado que se tiene al realizar un ping a una dirección IP.<br>
Secuenciador del 1 al 254 que establece un tiempo de espera de 1 segundo por cada ping realizado a la dirección IP específicada (10.10.0.$i). "$i" es donde se irán sustituyendo las iteraciones el secuenciador. En caso de que el código de estado del ping sea exitoso (echo $? = 0) se imprimirá en pantalla la direccón IP que este activa, de lo contrario no se imprimirá nada y se redirigirán los errores al /dev/null para no mostrarlos en pantalla.
```
#!/bin/bash

function ctrl_c(){
	echo -e "\n\n[!] Saliendo...\n"
	tput cnorm; 		# Recuperar el cursor al hacer ctrl + c.
	exit 1  		# Salir con un código de estado no exitoso.
}

# Ctrl+C
trap ctrl_c INT

tput civis			# Ocultar el cursor durante la ejecución del script.

for i in $(seq 1 254); do 
	timeout 1 bash -c "ping -c 1 10.10.0.$i" &> /dev/null && echo "[+] El host 10.10.0.$i - Está activo." &
done; wait

tput cnorm			# Recuperar el cursor al finálizar el script.
```
<br><br>
## portScan.sh.
Script en bash para escanear todo el rango de puertos y te reporta solo aquellos que esten con status abierto. El script lanza una cadena vacía al /dev/tcp y en base al código de estado te dice si está abierto un puerto.
```
#!/bin/bash

function ctrl_c(){
	echo -e "\n\n[!] Saliendo...\n"
	tput cnorm; exit 1 
}

# Ctrl+C
trap ctrl_c INT 

tput civis

for port in $(seq 1 65535); do
	timeout 1 bash -c "echo '' > /dev/tcp/<ip-address>/$port" 2>/dev/null && echo "[+] El Puerto $port - Abierto" &
done; wait

tput cnorm
```




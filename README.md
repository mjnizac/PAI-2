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
python src/serversocket.py
```

**2. Arrancar el cliente** (en otra terminal):
```
python src/interfaz.py
```

Usuarios disponibles desde el inicio: `admin` / `admin123`, `user1` / `pass1`, `user2` / `pass2`

---

## Demo del ataque Man-in-the-Middle (extra)

Demuestra qué pasa cuando el cliente no verifica el certificado del servidor:

**1.** Arrancar el servidor normalmente (`python src/serversocket.py`)

**2.** Arrancar el proxy atacante (en otra terminal):
```
python src/proxy_atacante.py
```

**3.** Cambiar `PORT = 3443` por `PORT = 3444` en `src/interfaz.py` (línea 10) y arrancar el cliente. El proxy interceptará y modificará los mensajes antes de que lleguen al servidor.

---

## Análisis de tráfico con Wireshark

Las capturas `.pcap` están en `evidencias/`. Para reproducirlas:

1. Abrir `evidencias/captura_tls.pcap` en Wireshark → filtro `tcp.port == 3443` → el payload aparece como **TLSv1.3 Application Data** (cifrado, ilegible)
2. Abrir `evidencias/captura_notls.pcap` en Wireshark → filtro `tcp.port == 3445` → los mensajes aparecen en **texto plano**

Para capturar en vivo: seleccionar la interfaz **"Adapter for loopback traffic capture"** en Wireshark.

---

## Tests y benchmark

```bash
# Tests funcionales (con el servidor arrancado)
python tests/test_funcional.py

# Benchmark TLS vs sin TLS (requiere ambos servidores arrancados)
python src/serversocket.py        # terminal 1 — TLS, puerto 3443
python tests/servidor_notls.py    # terminal 2 — sin TLS, puerto 3445
python tests/benchmark.py         # terminal 3
```

---

## Estructura del proyecto

```
├── src/
│   ├── serversocket.py       Servidor SSL con toda la lógica
│   ├── interfaz.py           Cliente con interfaz gráfica
│   └── proxy_atacante.py     Proxy MitM para la demo del ataque
├── tests/
│   ├── test_funcional.py     Tests automatizados (RF1-RF8, RS1)
│   ├── benchmark.py          Comparativa rendimiento TLS vs sin TLS
│   └── servidor_notls.py     Servidor sin TLS (solo para benchmark)
├── evidencias/
│   ├── evidencias_servidor.log
│   ├── evidencias_tests.log
│   ├── evidencias_benchmark.log
│   └── evidencias_mitm.log
├── bd/
│   ├── usuarios.json         Usuarios registrados (contraseñas hasheadas)
│   ├── salts.json            Salts de cada usuario
│   └── mensajes.json         Historial de mensajes
└── cert.pem / key.pem        Certificado SSL (se genera automáticamente)
```

---

## Seguridad implementada

| Medida | Detalle |
|---|---|
| Canal cifrado | TLS 1.3 con SSL Sockets |
| Contraseñas | SHA-256 + salt aleatorio por usuario |
| Anti-fuerza bruta | Bloqueo de IP tras 4 intentos fallidos (10 min) |
| Sesiones | Token aleatorio criptográfico por sesión |

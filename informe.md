# PAI-2 — VPN SSL Road Warrior
## Seguridad en Sistemas de Información — Universidad de Sevilla

---

## 1. Resumen

El proyecto implementa una VPN SSL de tipo *Road Warrior* que permite a los empleados de una universidad acceder de forma segura al sistema corporativo desde sus propios dispositivos (política BYOD). La solución se ha desarrollado íntegramente en Python utilizando exclusivamente la biblioteca estándar, sin dependencias externas.

### Decisiones técnicas y algorítmicas

**Protocolo de seguridad: TLS 1.3**
Se fuerza TLS 1.3 como versión mínima mediante `ssl.TLSVersion.TLSv1_3` en servidor y cliente, descartando versiones anteriores con vulnerabilidades conocidas (POODLE en SSLv3, BEAST en TLS 1.0, ataques de padding en TLS 1.2). Esta decisión se alinea con las recomendaciones del NIST SP 800-113 (*Guide to SSL VPNs*) y NIST SP 800-46r2 (*Enterprise Telework and BYOD Security*).

**Cipher Suites (TLS 1.3)**
TLS 1.3 limita el conjunto de cipher suites a tres opciones, todas consideradas robustas y sin vulnerabilidades conocidas:
- `TLS_AES_256_GCM_SHA384` — preferida, cifrado autenticado de 256 bits
- `TLS_AES_128_GCM_SHA256` — cifrado autenticado de 128 bits
- `TLS_CHACHA20_POLY1305_SHA256` — alternativa optimizada para hardware sin AES-NI

Se eliminan todas las cipher suites de TLS 1.2 e inferiores, que incluyen algoritmos obsoletos como RC4, 3DES o MD5. La suite activa en cada conexión queda registrada en `evidencias/evidencias_servidor.log` mediante `conn.cipher()`, lo que permite verificar en ejecución qué algoritmo se está usando.

**Almacenamiento seguro de credenciales (RS1)**
Las contraseñas se almacenan como `SHA-256(salt || password)`, con un salt aleatorio de 32 bytes por usuario generado con `os.urandom(32)`. Esto previene ataques de diccionario y rainbow tables incluso si la base de datos queda expuesta.

**Gestión de sesiones (RS1)**
Cada sesión autenticada recibe un token de 64 caracteres hexadecimales generado con `secrets.token_hex(32)` (256 bits de entropía), resistente a predicción o fuerza bruta.

**Protección anti-fuerza bruta (RS1)**
Bloqueo automático por IP tras 4 intentos de login fallidos durante 10 minutos.

**Integridad, confidencialidad y autenticidad de mensajes (RS2)**
Las tres propiedades requeridas por la política de seguridad de la universidad se garantizan mediante el propio canal TLS 1.3:
- *Confidencialidad*: cifrado AES-GCM o ChaCha20-Poly1305
- *Integridad*: MAC integrado en el modo AEAD de TLS 1.3
- *Autenticidad*: handshake TLS con certificado del servidor

**Integridad de la base de datos (RS3)**
Los datos se almacenan en ficheros JSON. La integridad estructural se garantiza mediante serialización controlada (`json.dump`) con acceso exclusivo desde el proceso servidor.

**Concurrencia**
El servidor crea un hilo por conexión (`threading.Thread`), permitiendo atender múltiples clientes de forma simultánea. El benchmark incluido en `tests/benchmark.py` valida el comportamiento con 300 clientes concurrentes.

---

## 2. Manual de despliegue y uso

### Requisitos previos
- Python 3.8 o superior
- OpenSSL instalado y accesible desde la terminal
- (Opcional para análisis de tráfico) RawCap + Wireshark

Verificar disponibilidad:
```bash
python --version
openssl version
```

### Instalación
No requiere dependencias externas. Clonar o descomprimir el proyecto y ejecutar directamente.

### Puesta en funcionamiento

**Paso 1 — Arrancar el servidor:**
```bash
python src/serversocket.py
```
En el primer arranque genera automáticamente `cert.pem` y `key.pem` mediante OpenSSL. El servidor queda escuchando en `localhost:3443`. Los usuarios preexistentes disponibles son `admin/admin123`, `user1/pass1` y `user2/pass2`.

**Paso 2 — Arrancar el cliente (en otra terminal):**
```bash
python src/interfaz.py
```
Se abre la interfaz gráfica Tkinter. Desde ella se puede registrar un nuevo usuario, iniciar sesión y enviar mensajes al servidor.

### Funcionalidades principales

| Acción | Descripción |
|---|---|
| Registro | Crea un nuevo usuario. Rechaza duplicados. |
| Login | Verifica credenciales. Devuelve token de sesión. Bloquea IP tras 4 intentos fallidos. |
| Enviar mensaje | Solo disponible con sesión activa. Máximo 144 caracteres. |
| Logout | Invalida el token de sesión en el servidor. |

### Análisis de tráfico con RawCap y Wireshark

**RawCap** (recomendado en Windows para captura en loopback):

```bash
# Descargar RawCap desde https://www.netresec.com/?page=RawCap
RawCap.exe 127.0.0.1 evidencias/captura_tls.pcap
```

**Wireshark** (análisis del fichero .pcap):
1. Abrir `captura_tls.pcap` en Wireshark
2. Filtro: `tcp.port == 3443`
3. Con TLS activo el payload aparece como `TLSv1.3 Application Data` (cifrado, ilegible)
4. Para comparar, capturar también en puerto 3445 (`tcp.port == 3445`) con el servidor sin TLS: los mensajes aparecerán en texto plano

También se puede capturar directamente en Wireshark seleccionando la interfaz *"Adapter for loopback traffic capture"*.

### Demo del ataque Man-in-the-Middle

**Paso 1 — Arrancar el servidor:** `python src/serversocket.py`

**Paso 2 — Arrancar el proxy atacante (otra terminal):**
```bash
python src/proxy_atacante.py
```

**Paso 3 — Cambiar el puerto del cliente a 3444 en `src/interfaz.py` (línea 10):**
```python
PORT = 3444
```

**Paso 4 — Arrancar el cliente:** `python src/interfaz.py`

El proxy intercepta todo el tráfico SSL. Cuando el cliente envía un mensaje, lo sustituye por `"MENSAJE MANIPULADO POR EL ATACANTE"` antes de reenviarlo al servidor. El ataque es posible porque el cliente tiene `ssl.CERT_NONE` (no verifica el certificado del servidor), lo que permite al proxy presentar su propio certificado falso. Las evidencias quedan en `evidencias/evidencias_mitm.log`.

### Ejecución de tests funcionales

Con el servidor arrancado:
```bash
python tests/test_funcional.py
```
Ejecuta automáticamente todos los flujos (RF1-RF8, RS1) y genera `evidencias/evidencias_tests.log`.

### Ejecución del benchmark (Objetivo 5)

```bash
# Terminal 1
python src/serversocket.py        # TLS, puerto 3443

# Terminal 2
python tests/servidor_notls.py    # sin TLS, puerto 3445

# Terminal 3
python tests/benchmark.py
```
Lanza 300 clientes concurrentes contra cada servidor y genera `evidencias/evidencias_benchmark.log` con la comparativa de latencia y throughput.

---

## 3. Grado de completitud

### Requisitos funcionales

| RF | Descripción | Estado | Referencia en código |
|---|---|---|---|
| RF1 | Registro de usuarios (nombre único + contraseña, sin duplicados, sin modificación posterior) | ✅ Implementado | `src/serversocket.py` acción REGISTRO, `src/interfaz.py` `on_register_click` |
| RF2 | Inicio de sesión (usuario registrado + credenciales) | ✅ Implementado | `src/serversocket.py` acción LOGIN |
| RF3 | Verificar credenciales (validar contra BD, denegar si no coinciden) | ✅ Implementado | `src/serversocket.py` `hashear_contrasena` + comparación en LOGIN |
| RF4 | Cerrar sesión | ✅ Implementado | `src/serversocket.py` acción LOGOUT, `src/interfaz.py` `on_logout_click` |
| RF5 | Gestión de usuarios preexistentes (admin, user1, user2) | ✅ Implementado | `src/serversocket.py` `sembrar_usuarios_iniciales` |
| RF6 | Mensajes (texto, máx. 144 caracteres, solo usuarios autenticados) | ✅ Implementado | `src/serversocket.py` acción MENSAJE, `src/interfaz.py` `mostrar_formulario_mensaje` |
| RF7 | Persistencia de datos (usuarios y mensajes con timestamp) | ✅ Implementado | `bd/usuarios.json`, `bd/mensajes.json`, `bd/salts.json` |
| RF8 | Interfaz de comunicación (sockets seguros + GUI) | ✅ Implementado | `src/serversocket.py` `main()`, `src/interfaz.py` (Tkinter) |

### Requisitos de seguridad

| RS | Descripción | Estado | Referencia en código |
|---|---|---|---|
| RS1 | Credenciales: almacenamiento seguro (SHA-256 + salt), verificación segura, anti-fuerza bruta (bloqueo IP 4 intentos / 10 min) | ✅ Implementado | `src/serversocket.py` `obtener_salt`, `hashear_contrasena`, bloqueo en LOGIN |
| RS2 | Mensajes: integridad + confidencialidad + autenticidad garantizadas por TLS 1.3 (AEAD) | ✅ Implementado | `src/serversocket.py` `main()`, `src/interfaz.py` `conectar_servidor` |
| RS3 | Base de datos: integridad de datos almacenados (serialización JSON controlada) | ✅ Implementado | `src/serversocket.py` `guardar_usuarios`, `guardar_mensajes`, `guardar_salts` |

### Objetivos

| Obj | Descripción | Estado | Evidencia |
|---|---|---|---|
| 1 | Canal seguro TLS para credenciales y mensajes (autenticidad, confidencialidad, integridad) | ✅ Cumplido | `src/serversocket.py` + `src/interfaz.py` |
| 2 | Cipher Suites robustos TLS 1.3 | ✅ Cumplido | Suite logueada en `evidencias/evidencias_servidor.log` por `conn.cipher()` |
| 3 | Herramienta de análisis de tráfico (RawCap + Wireshark) | ✅ Cumplido | Capturas `.pcap` adjuntas en `evidencias/` |
| 4 | Soporte ~300 empleados concurrentes | ✅ Cumplido | `tests/benchmark.py` con 300 hilos — resultados en `evidencias/evidencias_benchmark.log` |
| 5 | Análisis rendimiento TLS vs sin TLS | ✅ Cumplido | Comparativa latencia/throughput en `evidencias/evidencias_benchmark.log` |
| 6 | Ataque Man-in-the-Middle (extra +10%) | ✅ Cumplido | `src/proxy_atacante.py` — evidencias en `evidencias/evidencias_mitm.log` |

---

### Contenido del entregable

```
PAI2-STX.zip
├── src/
│   ├── serversocket.py
│   ├── interfaz.py
│   └── proxy_atacante.py
├── tests/
│   ├── test_funcional.py
│   ├── benchmark.py
│   └── servidor_notls.py
├── evidencias/
│   ├── evidencias_servidor.log
│   ├── evidencias_tests.log
│   ├── evidencias_benchmark.log
│   ├── evidencias_mitm.log
│   ├── captura_tls.pcap
│   └── captura_notls.pcap
├── bd/
│   ├── usuarios.json
│   ├── salts.json
│   └── mensajes.json
├── cert.pem / key.pem
└── PAI2-<Apellido>.pdf
```

---

*Referencias: NIST SP 800-113 — Guide to SSL VPNs (2008) | NIST SP 800-46r2 — Enterprise Telework, Remote Access, and BYOD Security (2016)*

*Entrega: 16 de marzo de 2026 — 23:59h*

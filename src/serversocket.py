import socket
import ssl
import threading
import hashlib
import json
import secrets
import datetime
import os
import logging
import subprocess

BASE_DIR      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE_FILE = os.path.join(BASE_DIR, "bd", "usuarios.json")
MENSAJES_FILE = os.path.join(BASE_DIR, "bd", "mensajes.json")
SALTS_FILE    = os.path.join(BASE_DIR, "bd", "salts.json")
CERTFILE      = os.path.join(BASE_DIR, "cert.pem")
KEYFILE       = os.path.join(BASE_DIR, "key.pem")
LOG_FILE      = os.path.join(BASE_DIR, "evidencias", "evidencias_servidor.log")

os.makedirs(os.path.join(BASE_DIR, "evidencias"), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)

HOST = "localhost"
PORT = 3443

MAX_INTENTOS = 4
LOCKOUT_TIME = 600  # segundos


def generar_cert():
    if not os.path.exists(CERTFILE) or not os.path.exists(KEYFILE):
        logging.info("Generando certificado SSL autofirmado...")
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", KEYFILE, "-out", CERTFILE,
            "-days", "365", "-nodes",
            "-subj", "/CN=localhost"
        ], check=True)
        logging.info("Certificado generado: cert.pem / key.pem")


os.makedirs(os.path.join(BASE_DIR, "bd"), exist_ok=True)

try:
    with open(DATABASE_FILE, "r") as f:
        usuarios = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    usuarios = {}

try:
    with open(MENSAJES_FILE, "r") as f:
        mensajes = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    mensajes = []

try:
    with open(SALTS_FILE, "r") as f:
        salts = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    salts = {}

tokens_activos    = {}  # {token: usuario}
intentos_fallidos = {}  # {ip: (datetime, intentos)}

# RF5 - usuarios preexistentes que deben existir al arrancar
USUARIOS_INICIALES = {
    "admin":  "admin123",
    "user1":  "pass1",
    "user2":  "pass2",
}

def sembrar_usuarios_iniciales():
    if not usuarios:
        for nombre, contrasena in USUARIOS_INICIALES.items():
            usuarios[nombre] = hashear_contrasena(contrasena, nombre)
        guardar_usuarios()
        logging.info("Usuarios iniciales cargados.")


def guardar_usuarios():
    with open(DATABASE_FILE, "w") as f:
        json.dump(usuarios, f, indent=4)

def guardar_salts():
    with open(SALTS_FILE, "w") as f:
        json.dump(salts, f, indent=4)


def guardar_mensajes():
    with open(MENSAJES_FILE, "w") as f:
        json.dump(mensajes, f, indent=4)


# RS1 - SHA-256 + salt aleatorio por usuario
def obtener_salt(usuario):
    if usuario not in salts:
        salts[usuario] = os.urandom(32).hex()
        guardar_salts()
    return salts[usuario]

def hashear_contrasena(contrasena, usuario):
    salt = obtener_salt(usuario)
    return hashlib.sha256((salt + contrasena).encode()).hexdigest()


def generar_token(usuario):
    token = secrets.token_hex(32)
    tokens_activos[token] = usuario
    return token

def verificar_token(token):
    return tokens_activos.get(token)


def manejar_cliente(conn, addr):
    cipher_info = conn.cipher()
    logging.info(f"Nueva conexión desde {addr} | Suite: {cipher_info[0]} | TLS: {cipher_info[1]}")
    try:
        while True:
            datos = conn.recv(4096)
            if not datos:
                break

            mensaje = datos.decode()
            partes  = mensaje.split(":")
            accion  = partes[0]
            logging.info(f"Petición recibida: {accion}")

            # RF1 - Registro de usuarios (sin duplicados, sin modificación posterior)
            if accion == "REGISTRO":
                usuario, contrasena = partes[1], partes[2]
                if usuario in usuarios:
                    conn.send("Usuario ya registrado".encode())
                else:
                    usuarios[usuario] = hashear_contrasena(contrasena, usuario)
                    guardar_usuarios()
                    conn.send("Usuario registrado exitosamente".encode())
                    logging.info(f"Registro exitoso: '{usuario}'")

            # RF2 - Inicio de sesión
            # RF3 - Verificar credenciales / denegar si no coinciden
            # RS1 - Protección anti-fuerza bruta
            elif accion == "LOGIN":
                usuario, contrasena = partes[1], partes[2]
                client_ip = addr[0]

                # RS1 - Bloqueo por IP tras MAX_INTENTOS fallos
                if client_ip in intentos_fallidos:
                    ultimo, intentos = intentos_fallidos[client_ip]
                    if intentos >= MAX_INTENTOS and (datetime.datetime.now() - ultimo).seconds < LOCKOUT_TIME:
                        logging.warning(f"IP bloqueada: {client_ip}")
                        conn.send("Demasiados intentos fallidos. Inténtelo en 10 minutos.".encode())
                        continue

                if usuario in usuarios and hashear_contrasena(contrasena, usuario) == usuarios[usuario]:
                    token = generar_token(usuario)
                    conn.send(f"LOGIN_OK:{token}".encode())
                    intentos_fallidos.pop(client_ip, None)
                    logging.info(f"Login exitoso: '{usuario}'")
                else:
                    intentos = intentos_fallidos.get(client_ip, (None, 0))[1] + 1
                    intentos_fallidos[client_ip] = (datetime.datetime.now(), intentos)
                    logging.warning(f"Login fallido: '{usuario}' desde {client_ip} (intento {intentos})")
                    conn.send(f"Login fallido. Intentos restantes: {MAX_INTENTOS - intentos}".encode())

            # RF4 - Cerrar sesión
            elif accion == "LOGOUT":
                token   = partes[1]
                usuario = verificar_token(token)
                if usuario:
                    tokens_activos.pop(token, None)
                    conn.send("Sesión cerrada correctamente.".encode())
                    logging.info(f"Logout: '{usuario}'")
                else:
                    conn.send("Sesión no válida.".encode())

            # RF6 - Mensajes (solo autenticados, máx. 144 caracteres) + RF7 persistencia
            elif accion == "MENSAJE":
                token = partes[1]
                texto = ":".join(partes[2:])
                usuario = verificar_token(token)
                if not usuario:
                    conn.send("Sesión no válida. Inicia sesión de nuevo.".encode())
                    continue
                if len(texto) > 144:
                    conn.send("Mensaje demasiado largo (máx. 144 caracteres).".encode())
                    continue
                mensajes.append({
                    "usuario":    usuario,
                    "texto":      texto,
                    "timestamp":  datetime.datetime.now().isoformat()
                })
                guardar_mensajes()
                logging.info(f"Mensaje de '{usuario}': {texto}")
                conn.send("Mensaje enviado correctamente.".encode())

    except Exception as e:
        logging.error(f"Error con {addr}: {e}")
    finally:
        conn.close()
        logging.info(f"Cliente desconectado: {addr}")


def main():
    generar_cert()
    sembrar_usuarios_iniciales()

    # RF8 - TLS 1.3 obligatorio
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
    ssl_context.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as servidor:
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        servidor.bind((HOST, PORT))
        servidor.listen()
        servidor.settimeout(1.0)

        with ssl_context.wrap_socket(servidor, server_side=True) as ssl_servidor:
            logging.info(f"Servidor SSL arrancado en {HOST}:{PORT}")
            while True:
                try:
                    conn, addr = ssl_servidor.accept()
                    threading.Thread(target=manejar_cliente, args=(conn, addr), daemon=True).start()
                except (socket.timeout, TimeoutError):
                    pass
                except KeyboardInterrupt:
                    logging.info("Servidor apagado.")
                    break

if __name__ == "__main__":
    main()

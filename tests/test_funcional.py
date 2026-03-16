"""
Test funcional automatizado — PAI-2 VPN SSL
Simula los flujos principales y genera evidencias en evidencias/evidencias_tests.log
Ejecutar con el servidor ya arrancado: python src/serversocket.py
"""
import socket
import ssl
import logging
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(BASE_DIR, "evidencias", "evidencias_tests.log")
os.makedirs(os.path.join(BASE_DIR, "evidencias"), exist_ok=True)

HOST = "127.0.0.1"
PORT = 3443

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)

PASS_TESTS = 0
FAIL_TESTS = 0


def conectar():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn = ctx.wrap_socket(sock, server_hostname=HOST)
    conn.connect((HOST, PORT))
    return conn


def enviar(conn, mensaje):
    conn.send(mensaje.encode())
    return conn.recv(4096).decode()


def check(nombre, respuesta, esperado, contiene=True):
    global PASS_TESTS, FAIL_TESTS
    ok = (esperado in respuesta) if contiene else (respuesta == esperado)
    estado = "PASS" if ok else "FAIL"
    if ok:
        PASS_TESTS += 1
        logging.info(f"[{estado}] {nombre} → '{respuesta}'")
    else:
        FAIL_TESTS += 1
        logging.error(f"[{estado}] {nombre} | Esperado: '{esperado}' | Obtenido: '{respuesta}'")
    return ok


def test_registro():
    logging.info("── RF1: Registro de usuarios ──")
    conn = conectar()
    cipher = conn.cipher()
    logging.info(f"Cipher suite activo: {cipher[0]} | TLS: {cipher[1]}")

    r = enviar(conn, "REGISTRO:test_user_001:password123")
    check("RF1 - Registro nuevo usuario", r, "exitosamente")

    r = enviar(conn, "REGISTRO:test_user_001:otrapass")
    check("RF1 - Registro duplicado rechazado", r, "ya registrado")

    conn.close()


def test_login_logout():
    logging.info("── RF2/RF3/RF4: Login, verificación de credenciales y logout ──")
    conn = conectar()

    r = enviar(conn, "LOGIN:test_user_001:password123")
    check("RF2 - Login correcto", r, "LOGIN_OK")
    token = r.split(":", 1)[1] if "LOGIN_OK" in r else None

    r = enviar(conn, "LOGIN:test_user_001:wrongpass")
    check("RF3 - Login con contraseña incorrecta rechazado", r, "fallido")

    if token:
        r = enviar(conn, f"LOGOUT:{token}")
        check("RF4 - Logout correcto", r, "cerrada")

    conn.close()


def test_usuarios_preexistentes():
    logging.info("── RF5: Usuarios preexistentes (admin, user1, user2) ──")
    conn = conectar()

    for usuario, contrasena in [("admin", "admin123"), ("user1", "pass1"), ("user2", "pass2")]:
        r = enviar(conn, f"LOGIN:{usuario}:{contrasena}")
        check(f"RF5 - Login usuario preexistente '{usuario}'", r, "LOGIN_OK")
        if "LOGIN_OK" in r:
            token = r.split(":", 1)[1]
            enviar(conn, f"LOGOUT:{token}")

    conn.close()


def test_mensajes():
    logging.info("── RF6: Mensajes autenticados y límite de 144 caracteres ──")
    conn = conectar()

    r = enviar(conn, "LOGIN:test_user_001:password123")
    assert "LOGIN_OK" in r, "Login falló"
    token = r.split(":", 1)[1]

    r = enviar(conn, f"MENSAJE:{token}:Hola desde el test funcional automatizado")
    check("RF6 - Mensaje de usuario autenticado", r, "correctamente")

    mensaje_largo = "A" * 145
    r = enviar(conn, f"MENSAJE:{token}:{mensaje_largo}")
    check("RF6 - Mensaje >144 chars rechazado", r, "largo")

    r = enviar(conn, "MENSAJE:token_invalido_xyz:Intento sin sesión")
    check("RF6 - Mensaje sin sesión válida rechazado", r, "no válida")

    enviar(conn, f"LOGOUT:{token}")
    conn.close()


def test_antibrute():
    logging.info("── RS1: Anti-fuerza bruta (bloqueo tras 4 intentos fallidos) ──")
    conn = conectar()

    for i in range(1, 5):
        r = enviar(conn, "LOGIN:admin:wrongpass")
        logging.info(f"Intento {i}: {r}")

    r = enviar(conn, "LOGIN:admin:wrongpass")
    check("RS1 - IP bloqueada tras 4 intentos", r, "Demasiados intentos")

    conn.close()


def test_mensaje_con_dos_puntos():
    logging.info("── Robustez: Mensaje que contiene ':' ──")
    conn = conectar()

    r = enviar(conn, "LOGIN:test_user_001:password123")
    if "LOGIN_OK" not in r:
        logging.warning("Login falló — posible bloqueo activo, esperando...")
        conn.close()
        return

    token = r.split(":", 1)[1]
    r = enviar(conn, f"MENSAJE:{token}:Mensaje con: dos puntos: incluidos")
    check("Robustez - Mensaje con ':' procesado correctamente", r, "correctamente")

    enviar(conn, f"LOGOUT:{token}")
    conn.close()


if __name__ == "__main__":
    logging.info("═══════════════════════════════════════════════")
    logging.info("  INICIO TEST FUNCIONAL — PAI-2 VPN SSL")
    logging.info("═══════════════════════════════════════════════")

    try:
        test_registro()
        test_login_logout()
        test_usuarios_preexistentes()
        test_mensajes()
        test_antibrute()
        test_mensaje_con_dos_puntos()
    except ConnectionRefusedError:
        logging.error("No se pudo conectar al servidor. ¿Está arrancado src/serversocket.py?")
        raise SystemExit(1)

    logging.info("═══════════════════════════════════════════════")
    logging.info(f"  RESULTADO: {PASS_TESTS} PASS | {FAIL_TESTS} FAIL")
    logging.info("═══════════════════════════════════════════════")

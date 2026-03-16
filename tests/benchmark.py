"""
Benchmark de rendimiento — PAI-2 VPN SSL (Objetivo 5)
Compara latencia y throughput con TLS 1.3 vs sin TLS.

Uso:
  1. Terminal 1: python src/serversocket.py      (TLS, puerto 3443)
  2. Terminal 2: python tests/servidor_notls.py  (sin TLS, puerto 3445)
  3. Terminal 3: python tests/benchmark.py
"""
import socket
import ssl
import threading
import time
import statistics
import logging
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(BASE_DIR, "evidencias", "evidencias_benchmark.log")
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

HOST         = "127.0.0.1"
PORT_TLS     = 3443
PORT_NOTLS   = 3445
NUM_CLIENTES = 300   # Objetivo 4: ~300 empleados concurrentes
USUARIO      = "benchmark_user"
PASSWORD     = "benchpass123"


def conectar_tls():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn = ctx.wrap_socket(sock, server_hostname=HOST)
    conn.connect((HOST, PORT_TLS))
    return conn


def conectar_notls():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT_NOTLS))
    return sock


def enviar(conn, msg):
    conn.send(msg.encode())
    return conn.recv(4096).decode()


def ciclo_cliente_tls(resultados, idx, errores):
    try:
        t0 = time.perf_counter()
        conn = conectar_tls()
        enviar(conn, f"LOGIN:{USUARIO}:{PASSWORD}")
        r = enviar(conn, f"LOGIN:{USUARIO}:{PASSWORD}")
        if "LOGIN_OK" in r:
            token = r.split(":", 1)[1]
            enviar(conn, f"MENSAJE:{token}:Mensaje de prueba benchmark {idx}")
            enviar(conn, f"LOGOUT:{token}")
        conn.close()
        resultados.append(time.perf_counter() - t0)
    except Exception as e:
        errores.append(str(e))


def ciclo_cliente_notls(resultados, idx, errores):
    try:
        t0 = time.perf_counter()
        conn = conectar_notls()
        enviar(conn, f"LOGIN:{USUARIO}:{PASSWORD}")
        r = enviar(conn, f"LOGIN:{USUARIO}:{PASSWORD}")
        if "LOGIN_OK" in r:
            token = r.split(":", 1)[1]
            enviar(conn, f"MENSAJE:{token}:Mensaje de prueba benchmark {idx}")
            enviar(conn, f"LOGOUT:{token}")
        conn.close()
        resultados.append(time.perf_counter() - t0)
    except Exception as e:
        errores.append(str(e))


def registrar_usuario_tls():
    try:
        conn = conectar_tls()
        enviar(conn, f"REGISTRO:{USUARIO}:{PASSWORD}")
        conn.close()
    except Exception:
        pass


def registrar_usuario_notls():
    try:
        conn = conectar_notls()
        enviar(conn, f"REGISTRO:{USUARIO}:{PASSWORD}")
        conn.close()
    except Exception:
        pass


def ejecutar_benchmark(nombre, funcion_cliente, n):
    logging.info(f"Iniciando benchmark [{nombre}] con {n} clientes concurrentes...")
    resultados = []
    errores    = []
    threads    = []

    t_inicio = time.perf_counter()
    for i in range(n):
        t = threading.Thread(target=funcion_cliente, args=(resultados, i, errores))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    t_total = time.perf_counter() - t_inicio

    exitosos = len(resultados)
    fallidos = len(errores)

    if exitosos > 0:
        media      = statistics.mean(resultados)
        mediana    = statistics.median(resultados)
        p95        = sorted(resultados)[int(exitosos * 0.95)]
        minimo     = min(resultados)
        maximo     = max(resultados)
        throughput = exitosos / t_total
    else:
        media = mediana = p95 = minimo = maximo = throughput = 0.0

    logging.info(f"── Resultados [{nombre}] ──────────────────────────────")
    logging.info(f"  Clientes totales    : {n}")
    logging.info(f"  Completados (éxito) : {exitosos}")
    logging.info(f"  Fallidos            : {fallidos}")
    logging.info(f"  Tiempo total        : {t_total:.3f} s")
    logging.info(f"  Throughput          : {throughput:.1f} clientes/s")
    logging.info(f"  Latencia media      : {media*1000:.1f} ms")
    logging.info(f"  Latencia mediana    : {mediana*1000:.1f} ms")
    logging.info(f"  Latencia p95        : {p95*1000:.1f} ms")
    logging.info(f"  Latencia mín/máx    : {minimo*1000:.1f} ms / {maximo*1000:.1f} ms")
    if errores:
        logging.warning(f"  Errores muestra     : {errores[:3]}")

    return {
        "nombre": nombre, "n": n, "exitosos": exitosos, "fallidos": fallidos,
        "tiempo_total": t_total, "throughput": throughput,
        "media_ms": media * 1000, "mediana_ms": mediana * 1000,
        "p95_ms": p95 * 1000, "min_ms": minimo * 1000, "max_ms": maximo * 1000
    }


if __name__ == "__main__":
    logging.info("═══════════════════════════════════════════════════════")
    logging.info("  BENCHMARK PAI-2 — TLS 1.3 vs SIN TLS")
    logging.info(f"  Clientes concurrentes: {NUM_CLIENTES}")
    logging.info("═══════════════════════════════════════════════════════")

    logging.info("Registrando usuario de prueba...")
    registrar_usuario_tls()
    registrar_usuario_notls()
    time.sleep(0.5)

    res_tls   = ejecutar_benchmark("CON TLS 1.3",  ciclo_cliente_tls,   NUM_CLIENTES)
    time.sleep(1)
    res_notls = ejecutar_benchmark("SIN TLS",       ciclo_cliente_notls, NUM_CLIENTES)

    logging.info("═══════════════════════════════════════════════════════")
    logging.info("  COMPARATIVA FINAL")
    logging.info("═══════════════════════════════════════════════════════")

    overhead_latencia   = res_tls["media_ms"] - res_notls["media_ms"]
    overhead_throughput = res_notls["throughput"] - res_tls["throughput"]
    pct_latencia        = (overhead_latencia / res_notls["media_ms"] * 100) if res_notls["media_ms"] > 0 else 0
    pct_throughput      = (overhead_throughput / res_notls["throughput"] * 100) if res_notls["throughput"] > 0 else 0

    logging.info(f"  Overhead latencia TLS  : +{overhead_latencia:.1f} ms ({pct_latencia:+.1f}%)")
    logging.info(f"  Overhead throughput    : -{overhead_throughput:.1f} clientes/s ({pct_throughput:+.1f}%)")
    logging.info(f"  Clientes exitosos TLS  : {res_tls['exitosos']}/{NUM_CLIENTES}")
    logging.info(f"  Clientes exitosos noTLS: {res_notls['exitosos']}/{NUM_CLIENTES}")
    logging.info("═══════════════════════════════════════════════════════")
    logging.info(f"  Resultados guardados en {LOG_FILE}")
    logging.info("═══════════════════════════════════════════════════════")
